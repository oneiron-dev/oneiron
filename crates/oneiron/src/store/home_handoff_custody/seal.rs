//! Core half of `store::home_handoff_custody::seal`: its store-layer items live in `oneiron_store::home_handoff_custody::seal` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::home_handoff_custody::seal::*;

use super::{KeyRef, LiveTarget, TransitSeal, VerifiedHolder};
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

/// Seals `plain` (the key's 81-byte transit record: purpose 1 | parent 16 |
/// incarnation 32 | secret 32) to `target.ephemeral`, the live session's
/// ephemeral hybrid public key: never a machine's long-lived key. Binds the
/// target machine, the session binding and nonce, and `key_ref`.
pub(super) fn seal_transit(
    target: &LiveTarget,
    key_ref: &KeyRef,
    plain: &[u8],
) -> Result<TransitSeal> {
    let machine = target.machine.as_bytes();
    let params = SealParams {
        suite: AEAD,
        purpose: Purpose::ErasableKey,
        epoch: CRYPTO_EPOCH,
        key_id: key_ref.as_bytes(),
        recipient: machine,
        vault_id: &target.session.binding,
    };
    let aad = transit_aad(
        machine,
        &target.session.binding,
        &target.session.nonce,
        key_ref.as_bytes(),
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
/// receiving side: `holder.target` (this machine), `holder.session.binding`,
/// `holder.session.nonce`, and `key_ref`.
pub(super) fn open_transit(
    session: &oneiron_crypto::HybridSecretKey,
    holder: &VerifiedHolder,
    key_ref: &KeyRef,
    sealed: &TransitSeal,
) -> Result<Zeroizing<Vec<u8>>> {
    let machine = holder.target.as_bytes();
    let policy = OpenPolicy {
        purpose: Purpose::ErasableKey,
        vault_id: &holder.session.binding,
        recipient: machine,
        key_id: key_ref.as_bytes(),
        wraps: &[WrapType::HybridCapsule],
        aead_suites: &[AEAD],
        kem_suites: &[KEM],
        min_epoch: CRYPTO_EPOCH,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    };
    let aad = transit_aad(
        machine,
        &holder.session.binding,
        &holder.session.nonce,
        key_ref.as_bytes(),
    );
    Envelope::parse(sealed.as_bytes())
        .map_err(|error| open_refused(&error, "the key in transit"))?
        .open_with_aad(OpenKey::Hybrid(session), &policy, &aad)
        .map_err(|error| open_refused(&error, "the key in transit"))
}
