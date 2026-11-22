//! Core half of `store::home_handoff_custody::seal`: its store-layer items live in `oneiron_store::home_handoff_custody::seal` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::home_handoff_custody::seal::*;

use super::{KeyRef, LiveTarget, SessionBinding, TransitSeal};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, Kek, OpenKey, OpenPolicy, Purpose, SealKey, SealParams, SuiteId,
    WrapType, seal_with_aad,
};
use zeroize::Zeroizing;

/// Seals `plain` under the erasable key `key`, the 32-byte custody secret the
/// key `key_ref` names, binding `aad` (the caller's: vault, incarnation, ref,
/// section, part and order) as extra associated data.
pub(super) fn seal_content(
    key_ref: &KeyRef,
    key: &Zeroizing<[u8; 32]>,
    aad: &[u8],
    plain: &[u8],
) -> Result<Vec<u8>> {
    let params = SealParams {
        suite: AEAD,
        purpose: Purpose::ErasableKey,
        epoch: CRYPTO_EPOCH,
        key_id: key_ref.as_bytes(),
        recipient: CONTENT_RECIPIENT,
        vault_id: key_ref.as_bytes(),
    };
    let kek = Kek::from_bytes_ref(key);
    seal_with_aad(
        &params,
        SealKey::SymmetricKek(&kek),
        plain,
        aad,
        &mut SysRng,
    )
    .map(|envelope| envelope.to_bytes())
    .map_err(|error| seal_refused(&error, "erasable key content"))
}

/// Opens what `seal_content` sealed under the same `key_ref`, `key` and
/// `aad`; any failure (wrong key, wrong ref, wrong aad, damage) is an error.
pub(super) fn open_content(
    key_ref: &KeyRef,
    key: &Zeroizing<[u8; 32]>,
    aad: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let policy = OpenPolicy {
        purpose: Purpose::ErasableKey,
        vault_id: key_ref.as_bytes(),
        recipient: CONTENT_RECIPIENT,
        key_id: key_ref.as_bytes(),
        wraps: &[WrapType::SymmetricKek],
        aead_suites: &[AEAD],
        kem_suites: &[],
        min_epoch: CRYPTO_EPOCH,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    };
    let kek = Kek::from_bytes_ref(key);
    Envelope::parse(sealed)
        .map_err(|error| open_refused(&error, "erasable key content"))?
        .open_with_aad(OpenKey::SymmetricKek(&kek), &policy, aad)
        .map_err(|error| open_refused(&error, "erasable key content"))
}

/// Seals `plain` (a key's 81-byte transit record: purpose | parent 16 |
/// incarnation 32 | secret 32) to `target.ephemeral`, the live session's
/// ephemeral hybrid public key: never a machine's long-lived key. Binds the
/// target machine, the session binding and nonce, and `key_ref`. The home
/// handoff's keys (purpose 1) and the authority overlay's (purpose 5, census
/// L5-22 1a-iii) travel in it, each carrier under a session binding of its
/// own and each receiver admitting only its own purpose.
pub(crate) fn seal_transit(
    target: &LiveTarget,
    key_ref: &[u8; 32],
    plain: &[u8],
) -> Result<TransitSeal> {
    let machine = target.machine.as_bytes();
    let params = SealParams {
        suite: AEAD,
        purpose: Purpose::ErasableKey,
        epoch: CRYPTO_EPOCH,
        key_id: key_ref,
        recipient: machine,
        vault_id: &target.session.binding,
    };
    let aad = transit_aad(
        machine,
        &target.session.binding,
        &target.session.nonce,
        key_ref,
    );
    seal_with_aad(
        &params,
        SealKey::Hybrid {
            recipient: &target.ephemeral,
            kem_suite: KEM,
        },
        plain,
        &aad,
        &mut SysRng,
    )
    .map(|envelope| TransitSeal::from_bytes(envelope.to_bytes()))
    .map_err(|error| seal_refused(&error, "the key in transit"))
}

/// Opens a transit seal on the target with `session`, the session-ephemeral
/// secret matching `target.ephemeral`, checking the same binding from the
/// receiving side: `receiver` (this machine), `binding.binding`,
/// `binding.nonce`, and `key_ref`.
pub(crate) fn open_transit(
    session: &oneiron_crypto::HybridSecretKey,
    receiver: &EntityId,
    binding: &SessionBinding,
    key_ref: &[u8; 32],
    sealed: &TransitSeal,
) -> Result<Zeroizing<Vec<u8>>> {
    let machine = receiver.as_bytes();
    let policy = OpenPolicy {
        purpose: Purpose::ErasableKey,
        vault_id: &binding.binding,
        recipient: machine,
        key_id: key_ref,
        wraps: &[WrapType::HybridCapsule],
        aead_suites: &[AEAD],
        kem_suites: &[KEM],
        min_epoch: CRYPTO_EPOCH,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    };
    let aad = transit_aad(machine, &binding.binding, &binding.nonce, key_ref);
    Envelope::parse(sealed.as_bytes())
        .map_err(|error| open_refused(&error, "the key in transit"))?
        .open_with_aad(OpenKey::Hybrid(session), &policy, &aad)
        .map_err(|error| open_refused(&error, "the key in transit"))
}
