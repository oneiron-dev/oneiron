# pkix-chain test fixtures

DER fixtures for the use-case wrapper integration tests (`verify_tls_server`
et al.). Each test needs a real two-cert chain because the wrappers run full
RFC 5280 §6.1 path validation before identity binding.

| Fixture | Role | Contents |
|---|---|---|
| `root.der` | trust anchor | P-256 self-signed CA, cA=TRUE, KU=keyCertSign\|cRLSign |
| `leaf-san-www-example.der` | end-entity | EE signed by `root`, EKU=serverAuth, SAN=DNS:www.example.com |
| `leaf-no-san.der` | end-entity | EE signed by `root`, EKU=serverAuth, **no SAN extension** |
| `leaf-san-alice-example.der` | end-entity | EE signed by `root`, EKU=emailProtection, SAN=rfc822Name:alice@example.com |
| `leaf-codesigning.der` | end-entity | EE signed by `root`, EKU=codeSigning, no SAN |
| `leaf-timestamping.der` | end-entity | EE signed by `root`, EKU=timeStamping (critical, sole), KU=digitalSignature only — RFC 3161 §2.3 + §2.1 #10 compliant TSA |
| `leaf-timestamping-not-critical.der` | end-entity | EE signed by `root`, EKU=timeStamping (NOT critical), KU=digitalSignature — RFC 3161 §2.3 negative case |
| `leaf-timestamping-not-sole.der` | end-entity | EE signed by `root`, EKU=timeStamping+codeSigning (critical), KU=digitalSignature — RFC 3161 §2.3 negative case |
| `leaf-timestamping-bad-ku.der` | end-entity | EE signed by `root`, EKU=timeStamping (critical, sole), KU=digitalSignature+keyEncipherment — RFC 3161 §2.1 #10 negative case (PKIX-7cac) |
| `leaf-ocsp-responder.der` | end-entity | EE signed by `root`, EKU=OCSPSigning — RFC 6960 §4.2.2.2 delegated responder |
| `leaf-ocsp-responder-nocheck.der` | end-entity | EE signed by `root`, EKU=OCSPSigning + `id-pkix-ocsp-nocheck` — RFC 6960 §4.2.2.2.1 |
| `root-wrong-issuer.der` | trust anchor (alt) | P-256 self-signed CA with a DIFFERENT subject DN than `root` — used to drive the wrapper-level OCSP-delegation DN-mismatch negative test |
| `root-twin-dn.der` | trust anchor (alt) | P-256 self-signed CA with the SAME subject DN as `root` but a DIFFERENT key — drives the RFC 6960 §4.2.2.2 cryptographic delegation-binding negative test (PKIX-q9hv.3): DN gate passes, signature binding under the twin's SPKI fails |

PKIX-fmtv.11.2 client-auth fixtures (EKU=clientAuth):

| Fixture | Role | Contents |
|---|---|---|
| `leaf-clientauth-dns.der` | end-entity | EKU=clientAuth, SAN dNSName=`client.example.com` |
| `leaf-clientauth-mailbox.der` | end-entity | EKU=clientAuth, SAN rfc822Name=`client@example.com` |

PKIX-fmtv.22 hostname-binding corpus (EKU=serverAuth throughout):

| Fixture | Role | Contents |
|---|---|---|
| `host-exact-foo.der` | end-entity | SAN dNSName=`foo.example.com` |
| `host-wildcard.der` | end-entity | SAN dNSName=`*.example.com` |
| `host-wildcard-partial-label.der` | end-entity | SAN dNSName=`f*o.example.com` |
| `host-wildcard-internal.der` | end-entity | SAN dNSName=`foo.*.example.com` |
| `host-wildcard-tld.der` | end-entity | SAN dNSName=`*.com` (single-label remainder) |
| `host-mixed-case-san.der` | end-entity | SAN dNSName=`FOO.example.com` |
| `host-idn-alabel.der` | end-entity | SAN dNSName=`xn--bcher-kva.example` |
| `host-ipv4.der` | end-entity | SAN iPAddress=`192.0.2.5` |
| `host-ipv6.der` | end-entity | SAN iPAddress=`2001:db8::1` |
| `host-multi-san.der` | end-entity | 3 dNSName entries: `api`, `www`, `*.cdn` @example.com |

PKIX-fmtv.23 mailbox-binding corpus (EKU=emailProtection throughout):

| Fixture | Role | Contents |
|---|---|---|
| `mailbox-rfc822-user-example.der` | end-entity | SAN rfc822Name=`user@example.com` |
| `mailbox-rfc822-user-EXAMPLE.der` | end-entity | SAN rfc822Name=`user@EXAMPLE.com` (domain mixed-case) |
| `mailbox-rfc822-User-example.der` | end-entity | SAN rfc822Name=`User@example.com` (local-part mixed-case) |
| `mailbox-smtputf8-only.der` | end-entity | SAN otherName(SmtpUTF8Mailbox)=`用户@example.com` |
| `mailbox-mixed.der` | end-entity | SAN rfc822Name=`user@example.com` + SmtpUTF8Mailbox=`用户@example.com` |
| `mailbox-multi-rfc822.der` | end-entity | 3 rfc822Name entries: `alpha`, `beta`, `gamma` @example.com |
| `mailbox-dns-only.der` | end-entity | SAN dNSName=`example.com` only — no mailbox entries |
| `mailbox-rfc822-malformed-no-at.der` | end-entity | SAN rfc822Name=`no-at-sign` (valid IA5String, semantically not a mailbox) |
| `mailbox-smtputf8-bad-utf8.der` | end-entity | SAN otherName(SmtpUTF8Mailbox) with malformed UTF-8 value bytes |

Validity 2000-01-01 to 2050-01-01. P-256 ECDSA throughout so the workspace's
default `DefaultVerifier` covers signature checking.

Regenerate with `gen.py`. Uses pyca/cryptography as the external oracle for
DER encoding; the Rust verifier under test never participates in fixture
creation.
