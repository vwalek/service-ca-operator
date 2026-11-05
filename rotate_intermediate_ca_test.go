// Root-directory, self-contained copy of the service-ca signing-CA rotation
// readable test, so it can be run straight from the repository root:
//
//	go test . -run TestRotateSigningCAReadable -v -count 1
//
// NOTE: the canonical test lives in pkg/operator/rotate_intermediate_ca_test.go
// and calls the operator's real (unexported) rotateSigningCA. That version
// cannot be copied here verbatim: this file is in a different package and the
// root directory is not part of package operator, so it has no access to those
// unexported symbols. Instead, this copy reimplements rotateSigningCA /
// createIntermediateCACert verbatim on top of the *exported*
// github.com/openshift/library-go/pkg/crypto API (resolved from the repo's
// vendor/ directory). Behavior mirrors the operator exactly:
//
//   - bundle              = [newCACert, currentCACertSignedByNewCA]   (service-ca.crt)
//   - intermediateCACert  = newCACertSignedByOldCA                    (serving tls.crt)
package rotatetest

import (
	"bytes"
	gocrypto "crypto"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
)

const (
	minimumTrustDuration       = time.Hour + 15*time.Minute
	signingCertificateLifetime = time.Hour*2 + 30*time.Minute
)

// signingCA mirrors pkg/operator/rotate.go's signingCA struct.
type signingCA struct {
	config             *crypto.TLSCertificateConfig
	bundle             []*x509.Certificate
	intermediateCACert *x509.Certificate
	oldCAExpiry        time.Time
}

// createIntermediateCACert is a verbatim copy of the operator's unexported
// helper (pkg/operator/rotate.go), with util.CreateCertificate inlined to
// x509.CreateCertificate + re-parse.
//
// It builds a cert carrying the TARGET's subject + public key (and the target's
// SubjectKeyId), but signed by the SIGNER's key, with AuthorityKeyId pointing at
// the signer's SubjectKeyId and a fresh serial number.
func createIntermediateCACert(targetCACert, signingCACert *x509.Certificate, signingKey gocrypto.Signer, expiry *time.Time) (*x509.Certificate, error) {
	// Copy the target cert to allow modification.
	template, err := x509.ParseCertificate(targetCACert.Raw)
	if err != nil {
		return nil, fmt.Errorf("failed to copy ca certificate: %v", err)
	}
	// Enable key identity chaining.
	template.AuthorityKeyId = signingCACert.SubjectKeyId

	// Set a new serial number so that the intermediate CA cert is
	// differentiated from the target CA cert.
	serialGenerator := crypto.RandomSerialGenerator{}
	serial, err := serialGenerator.Next(template)
	if err != nil {
		return nil, fmt.Errorf("failed to find next serial number: %v", err)
	}
	template.SerialNumber = big.NewInt(serial)

	// Update the expiry if necessary.
	if expiry != nil {
		template.NotAfter = *expiry
	}

	rawCert, err := x509.CreateCertificate(crand.Reader, template, signingCACert, targetCACert.PublicKey, signingKey)
	if err != nil {
		return nil, fmt.Errorf("error creating intermediate CA certificate: %v", err)
	}
	parsedCerts, err := x509.ParseCertificates(rawCert)
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate: %v", err)
	}
	return parsedCerts[0], nil
}

// rotateSigningCA is a verbatim copy of the operator's unexported method
// (pkg/operator/rotate.go), minus the ConfigurablePKI feature-gate branch (which
// relies on operator-internal types). The legacy path is the default on-cluster
// behavior.
func rotateSigningCA(currentCACert *x509.Certificate, currentKey gocrypto.Signer, minimumTrustDuration, signingCertificateLifetime time.Duration) (*signingCA, error) {
	// Generate a new signing cert (self-signed, reusing the current subject).
	newCAConfig, err := crypto.MakeSelfSignedCAConfigForSubject(currentCACert.Subject, signingCertificateLifetime)
	if err != nil {
		return nil, err
	}
	newCACert := newCAConfig.Certs[0]

	// Ensure the bridge cert's expiry guarantees a minimum trust duration.
	var currentCACertExpiry *time.Time
	minimumExpiry := time.Now().Add(minimumTrustDuration)
	if currentCACert.NotAfter.Before(minimumExpiry) {
		currentCACertExpiry = &minimumExpiry
	}

	newCASigner, ok := newCAConfig.Key.(gocrypto.Signer)
	if !ok {
		return nil, fmt.Errorf("expected crypto.Signer for new CA key, got %T", newCAConfig.Key)
	}

	// Old CA re-signed by the NEW CA -> goes in the bundle (service-ca.crt), so
	// clients with a post-rotation bundle can still trust pre-rotation serving certs.
	currentCACertSignedByNewCA, err := createIntermediateCACert(currentCACert, newCACert, newCASigner, currentCACertExpiry)
	if err != nil {
		return nil, fmt.Errorf("failed to create intermediate certificate signed by new ca: %v", err)
	}

	bundle := []*x509.Certificate{
		newCACert,
		currentCACertSignedByNewCA,
	}

	// New CA re-signed by the OLD CA -> shipped with new serving certs (tls.crt),
	// so clients with a pre-rotation bundle can trust post-rotation serving certs.
	newCACertSignedByOldCA, err := createIntermediateCACert(newCACert, currentCACert, currentKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create intermediate certificate signed by previous ca: %v", err)
	}

	return &signingCA{
		config:             newCAConfig,
		bundle:             bundle,
		intermediateCACert: newCACertSignedByOldCA,
		oldCAExpiry:        currentCACertSignedByNewCA.NotAfter,
	}, nil
}

// colonHex renders a byte slice as colon-separated upper-case hex, e.g.
// "A6:31:...:AD:C0", matching openssl / the bug report notation.
func colonHex(b []byte) string {
	if len(b) == 0 {
		return "<empty>"
	}
	parts := make([]string, len(b))
	for i, bb := range b {
		parts[i] = fmt.Sprintf("%02X", bb)
	}
	return strings.Join(parts, ":")
}

// describeCert returns a readable, openssl-style block describing a cert's
// identity: subject, serial, SKI, AKI, a hash of its public key, validity, and
// whether it is self-signed (SKI == AKI).
func describeCert(label string, c *x509.Certificate) string {
	pubHash := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	selfSigned := bytes.Equal(c.SubjectKeyId, c.AuthorityKeyId)

	var sb strings.Builder
	fmt.Fprintf(&sb, "--- %s ---\n", label)
	fmt.Fprintf(&sb, "Subject:    %s\n", c.Subject.String())
	fmt.Fprintf(&sb, "Serial:     %s\n", c.SerialNumber.Text(16))
	fmt.Fprintf(&sb, "SKI:        %s\n", colonHex(c.SubjectKeyId))
	fmt.Fprintf(&sb, "AKI:        %s\n", colonHex(c.AuthorityKeyId))
	fmt.Fprintf(&sb, "PublicKey:  %s\n", hex.EncodeToString(pubHash[:]))
	fmt.Fprintf(&sb, "NotBefore:  %s\n", c.NotBefore.Format(time.RFC3339))
	fmt.Fprintf(&sb, "NotAfter:   %s\n", c.NotAfter.Format(time.RFC3339))
	fmt.Fprintf(&sb, "SelfSigned: %t\n", selfSigned)
	return sb.String()
}

// TestRotateSigningCAReadable performs a real CA rotation and logs a readable
// breakdown of every certificate in the returned signingCA so the relationships
// can be reviewed by hand. It is a diagnostic / review aid and makes no
// assertions beyond basic shape guards.
func TestRotateSigningCAReadable(t *testing.T) {
	// Pre-rotation (old) CA. A short lifetime (below minimumTrustDuration) makes
	// rotation extend the old CA's trust, exercising the expiry-extension branch.
	oldCAConfig, err := crypto.MakeSelfSignedCAConfig("foo", time.Hour)
	if err != nil {
		t.Fatalf("error generating a new ca: %v", err)
	}
	oldCACert := oldCAConfig.Certs[0]
	oldKey, ok := oldCAConfig.Key.(gocrypto.Signer)
	if !ok {
		t.Fatalf("expected crypto.Signer for old CA key, got %T", oldCAConfig.Key)
	}

	// Rotate the CA.
	newSigningCA, err := rotateSigningCA(oldCACert, oldKey, minimumTrustDuration, signingCertificateLifetime)
	if err != nil {
		t.Fatalf("error rotating signing ca: %v", err)
	}

	// Guard against an unexpected shape so the indexing below cannot panic.
	if len(newSigningCA.bundle) != 2 {
		t.Fatalf("expected bundle to contain 2 certificates, got %d", len(newSigningCA.bundle))
	}

	newCACert := newSigningCA.config.Certs[0]

	t.Log("\n" + describeCert("old CA (pre-rotation) -> signer of newCACertSignedByOldCA", oldCACert))
	t.Log("\n" + describeCert("new CA (config.Certs[0] = newCACert)", newCACert))
	t.Log("\n" + describeCert("bundle[0] (expected: newCACert, self-signed) -> published as service-ca.crt", newSigningCA.bundle[0]))
	t.Log("\n" + describeCert("bundle[1] (currentCACertSignedByNewCA: old key, AKI == new CA SKI) -> published as service-ca.crt", newSigningCA.bundle[1]))
	t.Log("\n" + describeCert("intermediateCACert (newCACertSignedByOldCA: new key, AKI == old CA SKI) -> appended to serving tls.crt", newSigningCA.intermediateCACert))

	t.Logf("oldCAExpiry: %s", newSigningCA.oldCAExpiry.Format(time.RFC3339))
}
