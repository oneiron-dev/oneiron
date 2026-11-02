//! The keyed federation scope commitment and its per-grant opening key.
//!
//! The signed pact record carries only the keyed digest, never the key. The
//! 32-byte opening key travels separately, sealed to the peer's live
//! session-ephemeral key, and custody destroys it when the pact is revoked,
//! so the digest left in the record no longer lets anyone test a guess.

use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, OpenKey, OpenPolicy, Purpose, SealKey, SealParams, SuiteId, WrapType,
    seal_with_aad,
};

use super::super::{AuthorityVaultId, invalid_authority};
use crate::error::Result;

/// Domain label feeding the keyed scope digest, before the nonce and scope.
const KEYED_SCOPE_DOMAIN: &[u8] = b"oneiron/federation-scope-commit/keyed/v1";
/// Domain label opening the opening key's extra associated data.
const OPENING_AAD_DOMAIN: &[u8] = b"oneiron/federation-scope-opening/v1";
/// Envelope recipient binding the opening key to its one use.
const OPENING_RECIPIENT: &[u8] = b"oneiron/federation-scope-opening/recipient/v1";
/// Key-id derivation context over the opening key's associated data.
const OPENING_KEY_ID_CONTEXT: &str = "oneiron/federation-scope-opening/key-id/v1";
/// Crypto epoch the opening envelopes are sealed and opened at.
const CRYPTO_EPOCH: u64 = 1;

/// The keyed scope commitment both pact owners sign: keyed BLAKE3 over the
/// domain label, the 16-byte pact nonce, the `u64` big-endian scope length,
/// and the canonical scope bytes.
#[must_use]
pub fn keyed_scope_digest(
    key: &[u8; 32],
    pact_nonce: &[u8; 16],
    canonical_scope: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(KEYED_SCOPE_DOMAIN);
    hasher.update(pact_nonce);
    hasher.update(&(canonical_scope.len() as u64).to_be_bytes());
    hasher.update(canonical_scope);
    *hasher.finalize().as_bytes()
}

/// The pact binding sealed with the opening key: the pact, its epoch, and the
/// sending and receiving vaults. Seal and open bind the same bytes.
#[derive(Clone, Copy)]
pub struct ScopeOpeningAad<'a> {
    /// The shared pact identifier both vaults log.
    pub pact_id: &'a [u8; 32],
    /// The pact consent epoch this opening belongs to.
    pub pact_epoch: u64,
    /// The vault sending the opening key.
    pub from_vault: &'a AuthorityVaultId,
    /// The vault receiving the opening key.
    pub to_vault: &'a AuthorityVaultId,
}

/// The extra associated data binding one opening: the domain label, pact id,
/// epoch, and sending and receiving vaults, all fixed-width.
fn opening_aad_bytes(aad: &ScopeOpeningAad<'_>) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(OPENING_AAD_DOMAIN.len() + 32 + 8 + 32 + 32);
    bytes.extend_from_slice(OPENING_AAD_DOMAIN);
    bytes.extend_from_slice(aad.pact_id);
    bytes.extend_from_slice(&aad.pact_epoch.to_be_bytes());
    bytes.extend_from_slice(aad.from_vault);
    bytes.extend_from_slice(aad.to_vault);
    bytes
}

/// The envelope key id binding one opening: derived over its AAD bytes.
fn opening_key_id(aad_bytes: &[u8]) -> [u8; 32] {
    blake3::derive_key(OPENING_KEY_ID_CONTEXT, aad_bytes)
}

/// Seals the 32-byte per-grant opening key to the peer's session-ephemeral
/// hybrid public key, binding the pact, epoch and both vaults as extra
/// associated data. Returns the envelope bytes.
pub fn seal_scope_opening(
    key: &[u8; 32],
    recipient: &oneiron_crypto::HybridPublicKey,
    aad: &ScopeOpeningAad<'_>,
) -> Result<Vec<u8>> {
    let aad_bytes = opening_aad_bytes(aad);
    let key_id = opening_key_id(&aad_bytes);
    // Reuses Purpose::ErasableKey (26): this is the use that purpose names, an
    // erasable custody key in transit to a live session-ephemeral key, and the
    // key-id, recipient and AAD bindings below keep it from opening as any
    // other erasable-key envelope.
    let params = SealParams {
        suite: SuiteId::XCHACHA20POLY1305_V1,
        purpose: Purpose::ErasableKey,
        epoch: CRYPTO_EPOCH,
        key_id: &key_id,
        recipient: OPENING_RECIPIENT,
        vault_id: aad.to_vault,
    };
    seal_with_aad(
        &params,
        SealKey::Hybrid {
            recipient,
            kem_suite: SuiteId::KEM_X25519_MLKEM1024_V1,
        },
        key,
        &aad_bytes,
        &mut SysRng,
    )
    .map(|envelope| envelope.to_bytes())
    .map_err(|_| invalid_authority())
}

/// Opens a sealed opening key with the session-ephemeral secret, admitting
/// only the one envelope shape [`seal_scope_opening`] writes. The plaintext
/// must be exactly the 32 key bytes; anything else is refused.
pub fn open_scope_opening(
    sealed: &[u8],
    secret: &oneiron_crypto::HybridSecretKey,
    aad: &ScopeOpeningAad<'_>,
) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    let aad_bytes = opening_aad_bytes(aad);
    let key_id = opening_key_id(&aad_bytes);
    let policy = OpenPolicy {
        purpose: Purpose::ErasableKey,
        vault_id: aad.to_vault,
        recipient: OPENING_RECIPIENT,
        key_id: &key_id,
        wraps: &[WrapType::HybridCapsule],
        aead_suites: &[SuiteId::XCHACHA20POLY1305_V1],
        kem_suites: &[SuiteId::KEM_X25519_MLKEM1024_V1],
        min_epoch: CRYPTO_EPOCH,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    };
    let plain = Envelope::parse(sealed)
        .map_err(|_| invalid_authority())?
        .open_with_aad(OpenKey::Hybrid(secret), &policy, &aad_bytes)
        .map_err(|_| invalid_authority())?;
    if plain.len() != 32 {
        return Err(invalid_authority());
    }
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&plain);
    Ok(key)
}
