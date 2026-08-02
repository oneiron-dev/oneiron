# pkix-chain

High-level X.509 certificate chain verification.

Combines [`pkix-path`] (RFC 5280 §6 path validation) with
[`pkix-revocation`] (CRL/OCSP checking) into a single ergonomic API.
The starting point for most applications.

## Usage

### Simplest case — no revocation

```rust
use pkix_chain::{verify_chain_default, NoRevocation, TrustAnchor, ValidationPolicy};
use der::Decode as _;
use x509_cert::Certificate;

let chain = vec![
    Certificate::from_der(leaf_der)?,
    Certificate::from_der(intermediate_der)?,
];
let root = Certificate::from_der(root_der)?;
let anchors = vec![TrustAnchor::from_cert(root)];

let policy = ValidationPolicy::new(unix_now());

let result = verify_chain_default(&chain, &anchors, &policy, &NoRevocation)?;
```

### With CRL revocation

```rust
use pkix_chain::{verify_chain_default, CrlChecker, DefaultVerifier};

let checker = CrlChecker::new(crl_der, unix_now(), DefaultVerifier);
let result = verify_chain_default(&chain, &anchors, &policy, &checker)?;
```

### With delta CRL

```rust
use pkix_chain::CrlChecker;

let checker = CrlChecker::with_delta(base_crl_der, delta_crl_der, unix_now(), DefaultVerifier)?;
let result = verify_chain_default(&chain, &anchors, &policy, &checker)?;
```

### With OCSP revocation

```rust
use pkix_chain::{verify_chain_default, OcspChecker, DefaultVerifier};

let checker = OcspChecker::new(ocsp_response_der, unix_now(), DefaultVerifier);
let result = verify_chain_default(&chain, &anchors, &policy, &checker)?;
```

### With a custom signature backend

```rust
use pkix_chain::{verify_chain, NoAiaFetcher};

// Any type implementing pkix_path::SignatureVerifier
let result = verify_chain(&chain, &anchors, &policy, &my_verifier, &NoRevocation, &NoAiaFetcher)?;
```

### TLS server identity (RFC 6125)

`verify_tls_server` composes `verify_chain` with RFC 6125 hostname binding
in a single call. The caller pre-parses the target hostname with
`ServerName::dns_name` (or `ServerName::ip_address`) and passes a
[`Profile`] that supplies the `ValidationPolicy`.

```rust
use pkix_chain::{verify_tls_server, NoRevocation, ServerName};
use pkix_profiles::BasicTlsProfile;

let name = ServerName::dns_name("www.example.com")?;
let result = verify_tls_server(
    &chain,
    &anchors,
    &name,
    &BasicTlsProfile,
    unix_now(),
    &NoRevocation,
)?;
```

Path validation runs before identity binding: a chain that fails
RFC 5280 §6.1 returns `Error::Path(_)`, never `Error::Identity(_)`.

### TLS client authentication identity

`verify_tls_client_dns` and `verify_tls_client_mailbox` compose
`verify_chain` with an *optional* identity binding. Either function
accepts `None` to skip identity binding and validate the path only —
useful for client-auth deployments that read the identity elsewhere
(typically from the Subject DN). When `Some(_)` is supplied, the
binding mirrors `verify_tls_server` or `verify_smime_signer`
respectively. The split between the two functions preserves type
discipline at the call site rather than introducing an `Identity` enum
(PKIX-fmtv.11.2.1).

```rust
use pkix_chain::{verify_tls_client_dns, NoRevocation, ServerName};
use pkix_profiles::Rfc5280Profile;

let name = ServerName::dns_name("client.example.com")?;
let result = verify_tls_client_dns(
    &chain,
    &anchors,
    Some(&name),
    &Rfc5280Profile,
    unix_now(),
    &NoRevocation,
)?;
```

Production callers should supply a profile asserting `id-kp-clientAuth`
EKU, such as [`pkix_profiles::BasicTlsClientProfile`].

### S/MIME signer / recipient identity (RFC 5280 §4.2.1.6 / RFC 8398)

`verify_smime_signer` and `verify_smime_recipient` compose `verify_chain`
with RFC 5280 / RFC 8398 mailbox binding. The caller pre-parses the
mailbox with `MailboxName::parse`. Both wrappers share the same body;
the signer-vs-recipient distinction is encoded in the caller-supplied
`Profile`'s KeyUsage requirement (`digitalSignature` vs `keyEncipherment`).

```rust
use pkix_chain::{verify_smime_signer, MailboxName, NoRevocation};
use pkix_profiles::BasicSmimeProfile;

let mailbox = MailboxName::parse("alice@example.com")?;
let result = verify_smime_signer(
    &chain,
    &anchors,
    &mailbox,
    &BasicSmimeProfile,
    unix_now(),
    &NoRevocation,
)?;
```

### Code-signing identity

`verify_code_signer` is a thin composition of `verify_chain` under a
`Profile` that requires `id-kp-codeSigning`. Code-signing certificates
carry no caller-supplied identity target (no hostname, no mailbox), so
the wrapper does not perform identity binding.

```rust
use pkix_chain::{verify_code_signer, NoRevocation};
use pkix_profiles::BasicCodeSigningProfile;

let result = verify_code_signer(
    &chain,
    &anchors,
    &BasicCodeSigningProfile,
    unix_now(),
    &NoRevocation,
)?;
```

### Time Stamping Authority (RFC 3161)

`verify_time_stamper` composes `verify_chain` with the RFC 3161 §2.3
post-validation rule: the TSA leaf's `ExtendedKeyUsage` extension must
be marked critical and contain only `id-kp-timeStamping`.

```rust
use pkix_chain::{verify_time_stamper, NoRevocation};
use pkix_profiles::BasicTimeStampingProfile;

let result = verify_time_stamper(
    &chain,
    &anchors,
    &BasicTimeStampingProfile,
    unix_now(),
    &NoRevocation,
)?;
```

Violations of the critical-and-sole rule surface as
`Error::ProfileViolation { reason }` after path validation succeeds.

## What this crate does

`verify_chain` runs two sequential checks:

1. **Path validation** — calls `pkix_path::validate_path`, which verifies
   signatures, validity periods, name linkage, BasicConstraints, pathLen,
   KeyUsage, critical extensions, certificate policies, name constraints, and
   duplicate detection per RFC 5280 §6.1.

2. **Revocation checking** — calls `RevocationChecker::check_revocation` for
   each certificate in the validated chain (leaf through the certificate issued
   directly by the trust anchor, excluding the anchor itself).

If either step fails, an `Error` is returned wrapping the underlying error.

## Re-exports

This crate re-exports the full public API of both component crates. You do not
need to add `pkix-path` or `pkix-revocation` directly to your `Cargo.toml`:

```rust
use pkix_chain::{
    // from pkix-path:
    DefaultVerifier, SignatureVerifier, TrustAnchor, ValidatedPath, ValidationPolicy,
    // from pkix-revocation:
    NoRevocation, RevocationChecker,
    CrlChecker,   // requires feature = "crl"
    OcspChecker,  // requires feature = "ocsp"
};
```

## Features

| Feature | Enables |
|---------|---------|
| `crl` | `CrlChecker` (offline CRL validation, with delta CRL support) |
| `ocsp` | `OcspChecker` (offline OCSP validation) |
| `rsa` | RSA-PKCS1v15 backend in `DefaultVerifier` (default on) |
| `p256` | ECDSA P-256 backend in `DefaultVerifier` (default on) |

## `std` only

This crate requires `std`. For `no_std` environments, use `pkix-path` and
`pkix-revocation` directly.

## Standards

- [RFC 5280] — Internet X.509 PKI Certificate and CRL Profile
- [RFC 5280] §5.2.4 — Delta CRLs
- [RFC 6960] — Online Certificate Status Protocol (OCSP)

## License

Apache-2.0 OR MIT
