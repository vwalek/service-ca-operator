# Signing CA Rotation — Diagnostic Test

File under test: [rotate_intermediate_ca_test.go](rotate_intermediate_ca_test.go)
Code exercised: `serviceCAOperator.rotateSigningCA` in [pkg/operator/rotate.go](pkg/operator/rotate.go#L116)

## Why this test exists

When the service-serving signing CA is rotated, `rotateSigningCA` does **not** simply
replace one CA with another. To keep both pre-rotation and post-rotation clients and
serving certs trusting each other during the overlap window, it produces several
related certificates:

- **`config.Certs[0]` (`newCACert`)** — the new, self-signed signing CA. Used to sign
  all new serving certs.
- **`bundle[0]`** — the new CA cert itself (self-signed), published in the
  `service-ca.crt` CA bundle.
- **`bundle[1]` (`currentCACertSignedByNewCA`)** — an intermediate that re-issues the
  *old* CA's public key signed by the *new* CA. It lets a client holding the
  post-rotation bundle still trust serving certs that were issued by the old CA. Its
  expiry is floored to guarantee a minimum trust duration.
- **`intermediateCACert` (`newCACertSignedByOldCA`)** — an intermediate that re-issues
  the *new* CA's public key signed by the *old* CA. It is appended to serving cert
  chains (`tls.crt`) so that clients holding the pre-rotation bundle still trust
  serving certs issued by the new CA.

These relationships are subtle and easy to get wrong (which key signed which, which
AKI/SKI should match which, which expiry applies). This test was added as a
**diagnostic / review aid** while investigating a certificate-rotation bug: it performs
a real rotation and logs an openssl-style breakdown (Subject, Serial, SKI, AKI, public
key hash, validity window, self-signed flag) of every certificate the rotation emits,
so the trust relationships can be verified by hand.

It makes **no assertions** — it only logs. It is intentionally separate from the
assertion-based `TestRotateSigningCA` and serves to make the output of a rotation
human-readable during investigation.

## How to run

```bash
go test ./pkg/operator/ -run TestRotateSigningCAReadable -v -count 1
```

The `-v` flag is required to see the logged certificate breakdown; `-count 1` disables
test result caching so the rotation runs fresh each time.

The result is shown below

```bash
=== RUN   TestRotateSigningCAReadable
    rotate_intermediate_ca_test.go:94: 
        --- old CA (pre-rotation, renewed) -> signer of newCACertSignedByOldCA ---
        Subject:    CN=foo
        Serial:     a7e91ce1b69702
        SKI:        DD:78:48:F3:7A:FD:EC:B9:91:8B:F7:1A:FA:F8:CB:52:24:C2:5E:11
        AKI:        DD:78:48:F3:7A:FD:EC:B9:91:8B:F7:1A:FA:F8:CB:52:24:C2:5E:11
        PublicKey:  228778604161518b4b54236515b08963eb4c299cc2a5a5fb4d837dab6fda7bf1
        NotBefore:  2026-11-05T19:36:02Z
        NotAfter:   2026-11-05T20:36:03Z
        SelfSigned: true
        
    rotate_intermediate_ca_test.go:95: 
        --- new CA (config.Certs[0] = newCACert) ---
        Subject:    CN=foo
        Serial:     7d9d744b06302df6
        SKI:        6D:74:C6:1A:82:EC:5E:6E:3E:79:F6:17:E8:F7:7A:32:14:C0:81:B1
        AKI:        6D:74:C6:1A:82:EC:5E:6E:3E:79:F6:17:E8:F7:7A:32:14:C0:81:B1
        PublicKey:  2c46d5c5d2e482c1f69b6602ad068f99c0e6fa7c6ec378f9bf16c86bfa8da879
        NotBefore:  2026-11-05T19:36:02Z
        NotAfter:   2026-11-05T22:06:03Z
        SelfSigned: true
        
    rotate_intermediate_ca_test.go:96: 
        --- bundle[0] (expected: newCACert, self-signed) -> published as service-ca.crt ---
        Subject:    CN=foo
        Serial:     7d9d744b06302df6
        SKI:        6D:74:C6:1A:82:EC:5E:6E:3E:79:F6:17:E8:F7:7A:32:14:C0:81:B1
        AKI:        6D:74:C6:1A:82:EC:5E:6E:3E:79:F6:17:E8:F7:7A:32:14:C0:81:B1
        PublicKey:  2c46d5c5d2e482c1f69b6602ad068f99c0e6fa7c6ec378f9bf16c86bfa8da879
        NotBefore:  2026-11-05T19:36:02Z
        NotAfter:   2026-11-05T22:06:03Z
        SelfSigned: true
        
    rotate_intermediate_ca_test.go:97: 
        --- bundle[1] (currentCACertSignedByNewCA: old key, AKI == new CA SKI) -> published as service-ca.crt ---
        Subject:    CN=foo
        Serial:     72879ae7db64340e
        SKI:        DD:78:48:F3:7A:FD:EC:B9:91:8B:F7:1A:FA:F8:CB:52:24:C2:5E:11
        AKI:        6D:74:C6:1A:82:EC:5E:6E:3E:79:F6:17:E8:F7:7A:32:14:C0:81:B1
        PublicKey:  228778604161518b4b54236515b08963eb4c299cc2a5a5fb4d837dab6fda7bf1
        NotBefore:  2026-11-05T19:36:02Z
        NotAfter:   2026-11-05T20:51:03Z
        SelfSigned: false
        
    rotate_intermediate_ca_test.go:98: 
        --- intermediateCACert (newCACertSignedByOldCA: new key, AKI == old CA SKI) -> appended to serving tls.crt ---
        Subject:    CN=foo
        Serial:     7210c02190f7ff0f
        SKI:        6D:74:C6:1A:82:EC:5E:6E:3E:79:F6:17:E8:F7:7A:32:14:C0:81:B1
        AKI:        DD:78:48:F3:7A:FD:EC:B9:91:8B:F7:1A:FA:F8:CB:52:24:C2:5E:11
        PublicKey:  2c46d5c5d2e482c1f69b6602ad068f99c0e6fa7c6ec378f9bf16c86bfa8da879
        NotBefore:  2026-11-05T19:36:02Z
        NotAfter:   2026-11-05T22:06:03Z
        SelfSigned: false
        
    rotate_intermediate_ca_test.go:100: oldCAExpiry: 2026-11-05T20:51:03Z
--- PASS: TestRotateSigningCAReadable (0.05s)
PASS
ok      github.com/openshift/service-ca-operator/pkg/operator   0.078s
```

From the test above you can see following:

- the newCA is self-signed with public key `2c46d5c5d2...`
- the currentCACertSignedByNewCA is signed by the new CA with public key `228778604161...`

The above is what is saved in the `service-ca.crt` and it is part of the "bundle":

```go
	bundle := []*x509.Certificate{
		newCACert,
		currentCACertSignedByNewCA,
	}

	return &signingCA{
		config:             newCAConfig,
		bundle:             bundle,
		intermediateCACert: newCACertSignedByOldCA,
		oldCAExpiry:        currentCACertSignedByNewCA.NotAfter,
	}, nil
```

- the newCACertSignedByOldCA is new CA signed by the old CA and this is part of the intermediate ca in the signing-key secret and will be part of the service signed TLS cert for the service.


