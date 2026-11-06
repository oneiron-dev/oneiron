//! Independent host-issuer seed format and derivation label.

/// Length of a vault's independent host-issuer seed.
pub const HOST_ISSUER_SEED_BYTES: usize = 32;
/// BLAKE3 context for the host issuer's Ed25519 signing subkey.
pub const HOST_ISSUER_SIGNING_CONTEXT: &str = "oneiron/vault-host-authority-signing/v1";
