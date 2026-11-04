//! Device identity for REDACTION_AUDIT origin attestation (ONE-1140) and this
//! install's machine identity (world privacy P1, P6c).
//!
//! A BASE module (not sync-gated): receipts mint — and are signed — in base
//! delete paths, including the non-sync build. Public rows live in the
//! `sync_state` DB, which is unconditional (the `dt:` precedent — local truth,
//! not sync-only state):
//!
//! - `m:client_id` — this device's stable id (u64 LE, 8 bytes), minted once
//!   per install. Semantics preserved from the sync client (the mint was
//!   relocated here per OD-2 so base receipt paths can reach it; the sync
//!   client re-uses this module). A present-but-malformed row — wrong
//!   length, or an 8-byte row decoding to 0 (the mint loop never produces
//!   0, and 0 collides with Loro's unset peer id, ONE-1155) — fails closed:
//!   silently re-minting would change this device's identity mid-install.
//! - `m:machine_id` — the MACHINE row this install is (16 B). It names the
//!   install's incarnation: every keystore slot of the install is named by it.
//! - `m:device_pk` — 32 B Ed25519 verifying key of the device key, a cache
//!   for verifiers that never load a secret. A present row that does not
//!   match the derived key fails closed (`CorruptedIndex`) — signing with a
//!   key peers no longer hold would silently orphan every new receipt at
//!   their replay doors.
//! - `m:machine_pk` — 32 B Ed25519 verifying key of the machine key (FIX
//!   5472), so a restore that loads no keys still names its serving machine.
//!   Written once while the keys load; a row that does not match the derived
//!   key is `CorruptedIndex`, never written over or minted again.
//!
//! No signing secret is in LMDB (P6c, ruling R2). One 32-byte seed in the
//! install's `DeviceSigning` keystore slot, named by the store's id and the
//! machine id, derives both signing keys: the machine key (settings edits,
//! key records, enrolment, admission seals) and the device key (receipts,
//! detector runs, oversight, outbound bindings). A checkpoint carries
//! neither, and a restore that makes a new machine id gets a new slot.
//!
//! The keystore is never touched inside a write transaction. A door loads
//! the keys first ([`Vault::prepare_install_signing`]) and the handle keeps
//! them; a signer inside a transaction reads that copy only and refuses
//! `KeystoreUnavailable` when there is none.

use ed25519_dalek::SigningKey;

use crate::error::{Error, Result};
use crate::side_table;
use crate::store::install_identity::{DEVICE_PK, MACHINE_ID, MACHINE_PK};
use crate::vault::Vault;

pub(crate) use crate::store::install_identity::{
    DeviceIdentity, InstallSigner, cache_machine_pk, load_or_mint_client_id,
    load_or_mint_client_id_in_txn, load_or_mint_machine_id_in_txn, put_or_check_device_pk_in_txn,
    read_client_id_from, read_client_id_in_txn, read_device_verifying_key_in_txn,
    read_machine_id_in_txn, read_machine_verifying_key_in_store_txn,
    read_machine_verifying_key_in_txn,
};

/// `m:client_id` sync_state row (u64 LE, 8 bytes).
///
/// This module's own accessors go through the typed [`CLIENT_ID`] table below;
/// this raw string stays only for this module's own byte-layout-pinning tests,
/// which deliberately seed malformed rows the typed encoder could never write.
#[cfg(test)]
const KEY_CLIENT_ID: &str = "m:client_id";
/// The retired `m:device_sk` row name, for tests that check it stays absent.
#[cfg(test)]
pub(crate) const KEY_DEVICE_SK: &str = "m:device_sk";
/// `m:device_pk` sync_state row (32 B Ed25519 verifying key).
#[cfg(test)]
pub(crate) const KEY_DEVICE_PK: &str = "m:device_pk";

/// `derive_key` contexts for the two keys of one `DeviceSigning` seed.
const MACHINE_SIGNING_CONTEXT: &str = "oneiron/install-signing/machine/v1";
const DEVICE_SIGNING_CONTEXT: &str = "oneiron/install-signing/device/v1";

pub(crate) trait InstallSignerDerive {
    fn derive(machine: crate::EntityId, seed: &[u8; 32]) -> Self;
}

impl InstallSignerDerive for InstallSigner {
    fn derive(machine: crate::EntityId, seed: &[u8; 32]) -> Self {
        let key = |context: &str| {
            // FIX 6669: derive straight into the guard.
            let derived = crate::world_keys::derive_guarded(context, &[&seed[..]]);
            SigningKey::from_bytes(&derived)
        };
        Self {
            machine,
            machine_key: key(MACHINE_SIGNING_CONTEXT),
            device_key: key(DEVICE_SIGNING_CONTEXT),
        }
    }
}

fn signer_not_loaded() -> Error {
    Error::Secret(crate::error::SecretError::KeystoreUnavailable(
        "this install's signing keys are not loaded; the host installs a keystore",
    ))
}

/// The handle's signer for the machine id in `txn`'s snapshot. Never touches
/// the keystore: with no loaded signer, or one for another machine id, this
/// refuses `KeystoreUnavailable`.
pub(crate) fn loaded_signer_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<std::sync::Arc<InstallSigner>> {
    let machine = read_machine_id_in_txn(vault, txn)?;
    match (machine, vault.loaded_install_signer()) {
        (Some(machine), Some(signer)) if signer.machine == machine => Ok(signer),
        _ => Err(signer_not_loaded()),
    }
}

/// The full device identity (client id + Ed25519 keypair) inside the
/// CALLER's txn (OD-2): the client id is minted when missing, the key is the
/// handle's loaded device key ([`loaded_signer_in_txn`]).
pub(crate) fn ensure_device_identity_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
) -> Result<DeviceIdentity> {
    let client_id = load_or_mint_client_id_in_txn(vault, wtxn)?;
    let signer = loaded_signer_in_txn(vault, wtxn)?;
    put_or_check_device_pk_in_txn(vault, wtxn, &signer.device_key)?;
    Ok(DeviceIdentity {
        client_id,
        signing_key: signer.device_key.clone(),
    })
}

/// This install's machine id and machine key in the caller's snapshot, from
/// the handle's loaded signer ([`loaded_signer_in_txn`]).
pub(crate) fn machine_signer_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<(crate::EntityId, SigningKey)> {
    let signer = loaded_signer_in_txn(vault, txn)?;
    Ok((signer.machine, signer.machine_key.clone()))
}

/// This install's machine signing key, or `None` before it has a machine id.
/// Never touches the keystore: an install with an id and no loaded signer
/// refuses `KeystoreUnavailable`.
pub(crate) fn read_machine_signing_key_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<SigningKey>> {
    if read_machine_id_in_txn(vault, txn)?.is_none() {
        return Ok(None);
    }
    Ok(Some(loaded_signer_in_txn(vault, txn)?.machine_key.clone()))
}

/// Own-txn wrapper around [`ensure_device_identity_in_txn`]: loads the
/// install's signing keys first, outside the transaction.
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
pub(crate) fn ensure_device_identity(vault: &Vault) -> Result<DeviceIdentity> {
    vault.prepare_install_signing()?;
    let mut identity = None;
    vault.with_write_txn_grouped(|wtxn| {
        identity = Some(ensure_device_identity_in_txn(vault, wtxn)?);
        Ok(())
    })?;
    Ok(identity.expect("closure ran on Ok"))
}

/// An install identity row: a checkpoint image restored directly, which may
/// land on any install, leaves these behind, including its client/peer id.
/// The device and machine keys'
/// public caches go with them, since the new machine's slot holds another
/// seed. The pinned root goes with them too:
/// a new machine trusts no root until a pin door on its own install pins one,
/// so an old image never rolls trust back to an older root, and an image a
/// host made never arrives pinned to the host's.
pub(crate) fn is_machine_identity_row(key: &[u8]) -> bool {
    key == side_table::IDENTITY_CLIENT_ID.prefix
        || key == side_table::IDENTITY_MACHINE_ID.prefix
        || key == side_table::IDENTITY_DEVICE_PK.prefix
        || key == side_table::IDENTITY_MACHINE_PK.prefix
        || crate::authority::is_pinned_root_row(key)
}

/// Forgets this install's client id, machine and pin, so the vault joins as a new
/// one: another live vault keeps the machine it was.
pub(crate) fn drop_machine_identity_in_txn(
    store: &crate::store::Store,
    wtxn: &mut heed::RwTxn<'_>,
) -> Result<()> {
    crate::store::install_identity::drop_client_id_in_txn(store, wtxn)?;
    MACHINE_ID.delete(store, wtxn, &())?;
    DEVICE_PK.delete(store, wtxn, &())?;
    MACHINE_PK.delete(store, wtxn, &())?;
    crate::authority::drop_pinned_root_in_txn(store, wtxn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::VaultConfig;
    use crate::test_util::open_test_vault_with;
    use core::assert_matches;

    fn test_vault() -> (tempfile::TempDir, Vault) {
        let mut cfg = VaultConfig::device();
        cfg.map_size = 16 * 1024 * 1024;
        cfg.dimensions = 4;
        cfg.embedding_model = None;
        open_test_vault_with(cfg)
    }

    /// OD-2 literals: identity rows are `m:client_id` (8 B LE, nonzero),
    /// `m:device_sk` (32 B seed), `m:device_pk` (32 B, seed-derived) — and
    /// the identity is STABLE across re-ensures (a re-mint would orphan
    /// previously signed receipts at peer doors).
    #[test]
    fn device_identity_minted_once_with_pinned_row_layouts() {
        let (_dir, vault) = test_vault();
        let first = ensure_device_identity(&vault).unwrap();

        let rtxn = vault.store.env.read_txn().unwrap();
        let id_row = vault
            .store
            .sync_state
            .get(&rtxn, KEY_CLIENT_ID)
            .unwrap()
            .expect("client id row");
        assert_eq!(id_row.len(), 8, "m:client_id is u64 LE (8 bytes)");
        assert_eq!(u64::from_le_bytes(id_row.as_ref().try_into().unwrap()), {
            assert_ne!(first.client_id, 0);
            first.client_id
        });
        let sk_row = vault
            .store
            .sync_state
            .get(&rtxn, KEY_DEVICE_SK)
            .unwrap()
            .expect("sk row");
        assert_eq!(
            sk_row.as_ref(),
            first.signing_key.as_bytes(),
            "32 B seed row"
        );
        let pk_row = vault
            .store
            .sync_state
            .get(&rtxn, KEY_DEVICE_PK)
            .unwrap()
            .expect("pk row");
        assert_eq!(
            *pk_row,
            first.signing_key.verifying_key().to_bytes(),
            "pk row is the seed-derived verifying key"
        );
        drop(rtxn);

        let second = ensure_device_identity(&vault).unwrap();
        assert_eq!(second.client_id, first.client_id, "stable client id");
        assert_eq!(
            second.signing_key.to_bytes(),
            first.signing_key.to_bytes(),
            "stable signing key"
        );
    }

    /// Fail-closed arms: malformed/zero `m:client_id` and malformed
    /// `m:device_sk`/mismatched `m:device_pk` rows are typed errors — never
    /// silently re-minted (ONE-1155 zero-check composed per OD-2).
    #[test]
    fn malformed_identity_rows_fail_closed() {
        let (_dir, vault) = test_vault();

        vault
            .with_write_txn(|wtxn| {
                vault
                    .store
                    .sync_state
                    .put(wtxn, KEY_CLIENT_ID, &0u64.to_le_bytes())?;
                Ok(())
            })
            .unwrap();
        let Err(err) = ensure_device_identity(&vault) else {
            panic!("expected sync client_id zero corruption");
        };
        assert_matches!(err, Error::CorruptedIndex("sync client_id zero"));

        vault
            .with_write_txn(|wtxn| {
                vault.store.sync_state.put(wtxn, KEY_CLIENT_ID, b"short")?;
                Ok(())
            })
            .unwrap();
        let Err(err) = ensure_device_identity(&vault) else {
            panic!("expected sync client_id row corruption");
        };
        assert_matches!(err, Error::CorruptedIndex("sync client_id row"));

        vault
            .with_write_txn(|wtxn| {
                vault
                    .store
                    .sync_state
                    .put(wtxn, KEY_CLIENT_ID, &7u64.to_le_bytes())?;
                vault
                    .store
                    .sync_state
                    .put(wtxn, KEY_DEVICE_SK, &[1u8; 31])?;
                Ok(())
            })
            .unwrap();
        let Err(err) = ensure_device_identity(&vault) else {
            panic!("expected device signing key row corruption");
        };
        assert_matches!(err, Error::CorruptedIndex("device signing key row"));

        vault
            .with_write_txn(|wtxn| {
                vault
                    .store
                    .sync_state
                    .put(wtxn, KEY_DEVICE_SK, &[1u8; 32])?;
                vault
                    .store
                    .sync_state
                    .put(wtxn, KEY_DEVICE_PK, &[2u8; 32])?;
                Ok(())
            })
            .unwrap();
        let Err(err) = ensure_device_identity(&vault) else {
            panic!("expected device public key row corruption");
        };
        assert_matches!(err, Error::CorruptedIndex("device public key row"));
    }
}
