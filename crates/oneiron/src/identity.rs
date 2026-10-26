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
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::vault::Vault;

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

/// This device's stable client id. Key: `()` (singleton).
const CLIENT_ID: SideTable<(), ClientId, Raw> = SideTable::new(&side_table::IDENTITY_CLIENT_ID);
/// Cached Ed25519 verifying key of the device key. Key: `()`.
const DEVICE_PK: SideTable<(), Vec<u8>, Raw> = SideTable::new(&side_table::IDENTITY_DEVICE_PK);
/// The MACHINE row this install is (16 B entity id). Not the client id: that
/// is a CRDT peer id. A checkpoint image restored directly drops it, so a copy
/// on another install never is this machine. Key: `()`.
const MACHINE_ID: SideTable<(), Vec<u8>, Raw> = SideTable::new(&side_table::IDENTITY_MACHINE_ID);
/// Cached Ed25519 verifying key of the machine key (FIX 5472). Key: `()`.
const MACHINE_PK: SideTable<(), Vec<u8>, Raw> = SideTable::new(&side_table::IDENTITY_MACHINE_PK);

/// `derive_key` contexts for the two keys of one `DeviceSigning` seed.
const MACHINE_SIGNING_CONTEXT: &str = "oneiron/install-signing/machine/v1";
const DEVICE_SIGNING_CONTEXT: &str = "oneiron/install-signing/device/v1";

/// [`CLIENT_ID`]'s value: u64 LE, nonzero (ONE-1155 — 0 collides with Loro's
/// unset peer id). A wrong-length row and an 8-byte zero row are distinct
/// corruption verdicts, both fail-closed rather than silently re-minted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ClientId(u64);

impl RawValue for ClientId {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(self.0.to_le_bytes().to_vec())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(Self(decode_client_id_row(bytes)?))
    }
}

/// This device's attestation identity: the stable client id plus the
/// Ed25519 keypair that signs receipt attestations (OD-2).
pub(crate) struct DeviceIdentity {
    pub(crate) client_id: u64,
    pub(crate) signing_key: SigningKey,
}

/// This install's signing keys for one machine id, derived from the seed in
/// its `DeviceSigning` slot. Held on the vault handle only; no `Debug`.
pub(crate) struct InstallSigner {
    pub(crate) machine: crate::EntityId,
    pub(crate) machine_key: SigningKey,
    pub(crate) device_key: SigningKey,
}

impl InstallSigner {
    pub(crate) fn derive(machine: crate::EntityId, seed: &[u8; 32]) -> Self {
        let key = |context: &str| {
            let derived = zeroize::Zeroizing::new(blake3::derive_key(context, seed));
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

/// Loads `m:client_id` inside the caller's txn, minting it once (u64 LE,
/// nonzero) when absent.
///
/// Fail-closed arms: wrong-length rows and zero-decoding rows (ONE-1155)
/// are `CorruptedIndex`, never silently re-minted.
pub(crate) fn load_or_mint_client_id_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
) -> Result<u64> {
    match CLIENT_ID.get(&vault.store, wtxn, &())? {
        Some(ClientId(id)) => Ok(id),
        None => {
            let minted = mint_client_id(&vault.store.clock)?;
            crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
            CLIENT_ID.put(&vault.store, wtxn, &(), &ClientId(minted))?;
            Ok(minted)
        }
    }
}

/// Reads `m:client_id` in a read transaction when present.
///
/// Missing rows return `Ok(None)` so callers can explicitly decide whether to
/// mint in a write transaction.
pub(crate) fn read_client_id_in_txn(vault: &Vault, rtxn: &heed::RoTxn<'_>) -> Result<Option<u64>> {
    Ok(CLIENT_ID
        .get(&vault.store, rtxn, &())?
        .map(|ClientId(id)| id))
}

/// [`read_client_id_in_txn`] where only the store is at hand: the MACRO
/// election's writer records a home move with it (FIX 6459). Read-only.
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
pub(crate) fn read_client_id_from(
    dbs: &impl side_table::SideTableDbs,
    rtxn: &heed::RoTxn<'_>,
) -> Result<Option<u64>> {
    Ok(CLIENT_ID.get(dbs, rtxn, &())?.map(|ClientId(id)| id))
}

/// Read-mostly own-txn accessor for this device's stable client id.
///
/// Existing identities are loaded under a read transaction; only a missing
/// `m:client_id` escalates to the normal caller-txn mint path.
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
pub(crate) fn load_or_mint_client_id(vault: &Vault) -> Result<u64> {
    let rtxn = vault.store.env.read_txn()?;
    if let Some(client_id) = read_client_id_in_txn(vault, &rtxn)? {
        return Ok(client_id);
    }
    drop(rtxn);

    let mut client_id = None;
    vault.with_write_txn_grouped(|wtxn| {
        client_id = Some(load_or_mint_client_id_in_txn(vault, wtxn)?);
        Ok(())
    })?;
    Ok(client_id.expect("closure ran on Ok"))
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

/// Writes `m:device_pk` for `key` when absent; a present row for another key
/// fails closed.
pub(crate) fn put_or_check_device_pk_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    key: &SigningKey,
) -> Result<()> {
    let derived_pk = key.verifying_key().to_bytes();
    match DEVICE_PK.get(&vault.store, wtxn, &())? {
        Some(raw) if raw == derived_pk => Ok(()),
        // A pk row that disagrees with the key is corruption, not a
        // healable cache miss: receipts signed under EITHER key would
        // be unverifiable against the other at peer replay doors.
        Some(_) => Err(Error::CorruptedIndex("device public key row")),
        None => DEVICE_PK.put(&vault.store, wtxn, &(), &derived_pk.to_vec()),
    }
}

/// This device's verifying key under the caller's transaction, or `None`
/// before the identity is minted. Reads the cached public row only, so a
/// verifier never loads the seed or takes the writer.
pub(crate) fn read_device_verifying_key_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<[u8; 32]>> {
    DEVICE_PK
        .get(&vault.store, txn, &())?
        .map(|raw| {
            <[u8; 32]>::try_from(raw.as_slice())
                .map_err(|_| Error::CorruptedIndex("device public key row"))
        })
        .transpose()
}

/// Keeps the public half of `signer`'s machine key in `m:machine_pk` while
/// `signer`'s machine is this install's (FIX 5472; CALLS "FIX 5472 offline
/// machine identity"), so a restore that loads no keys still names its
/// serving machine. A present row is only read; an absent one is written in a
/// write of its own. Best effort: a row naming another key, or one that does
/// not read, is logged as the corruption it is and left as it is, never
/// written over, and the keys stay loaded as before.
pub(crate) fn cache_machine_pk(vault: &Vault, signer: &InstallSigner) {
    if let Err(error) = put_machine_pk_once(vault, signer) {
        tracing::warn!(
            kind = ?error.kind(),
            "this install's machine public key is not cached; a restore with no keys loaded \
             judges its machine row as before"
        );
    }
}

/// [`cache_machine_pk`]'s read, then its write when the row is absent.
fn put_machine_pk_once(vault: &Vault, signer: &InstallSigner) -> Result<()> {
    let key = signer.machine_key.verifying_key().to_bytes();
    {
        let txn = vault.store.env.read_txn()?;
        match read_machine_verifying_key_in_txn(vault, &txn)? {
            Some(cached) if cached == key => return Ok(()),
            Some(_) => return Err(Error::CorruptedIndex("machine public key row")),
            None => {}
        }
    }
    vault.with_write_txn_grouped(|wtxn| {
        if read_machine_id_in_txn(vault, wtxn)? != Some(signer.machine) {
            return Ok(());
        }
        let derived = key.to_vec();
        match MACHINE_PK.get(&vault.store, wtxn, &())? {
            Some(raw) if raw == derived => Ok(()),
            Some(_) => Err(Error::CorruptedIndex("machine public key row")),
            None => MACHINE_PK.put(&vault.store, wtxn, &(), &derived),
        }
    })
}

/// The cached verifying key of this install's machine key under the
/// caller's transaction, or `None` before its keys first loaded. Reads the
/// public row only, never the keystore; a row of another length is
/// `CorruptedIndex`.
pub(crate) fn read_machine_verifying_key_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<[u8; 32]>> {
    read_machine_verifying_key_in_store_txn(&vault.store, txn)
}

/// [`read_machine_verifying_key_in_txn`] on the store alone, for a store
/// door that has no vault handle: the same public row, never the keystore.
pub(crate) fn read_machine_verifying_key_in_store_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<[u8; 32]>> {
    MACHINE_PK
        .get(store, txn, &())?
        .map(|raw| {
            <[u8; 32]>::try_from(raw.as_slice())
                .map_err(|_| Error::CorruptedIndex("machine public key row"))
        })
        .transpose()
}

/// This install's MACHINE id, minted once inside the caller's txn. The keys
/// for it come from its keystore slot, loaded outside any transaction.
pub(crate) fn load_or_mint_machine_id_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
) -> Result<crate::EntityId> {
    if let Some(id) = read_machine_id_in_txn(vault, wtxn)? {
        return Ok(id);
    }
    let id = vault.store.clock.entity_id()?;
    MACHINE_ID.put(&vault.store, wtxn, &(), &id.as_bytes().to_vec())?;
    Ok(id)
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

/// This install's MACHINE id, or `None` before it asked to join a vault.
pub(crate) fn read_machine_id_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<crate::EntityId>> {
    MACHINE_ID
        .get(&vault.store, txn, &())?
        .map(|raw| {
            <[u8; 16]>::try_from(raw.as_slice())
                .ok()
                .and_then(|bytes| crate::EntityId::from_bytes(bytes).ok())
                .ok_or(Error::CorruptedIndex("machine id row"))
        })
        .transpose()
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

/// A machine identity row: a checkpoint image restored directly, which may
/// land on any install, leaves these behind. The device and machine keys'
/// public caches go with them, since the new machine's slot holds another
/// seed. The pinned root goes with them too:
/// a new machine trusts no root until a pin door on its own install pins one,
/// so an old image never rolls trust back to an older root, and an image a
/// host made never arrives pinned to the host's.
pub(crate) fn is_machine_identity_row(key: &[u8]) -> bool {
    key == side_table::IDENTITY_MACHINE_ID.prefix
        || key == side_table::IDENTITY_DEVICE_PK.prefix
        || key == side_table::IDENTITY_MACHINE_PK.prefix
        || crate::authority::is_pinned_root_row(key)
}

/// Forgets this install's machine and its pin, so the vault joins as a new
/// one: another live vault keeps the machine it was.
pub(crate) fn drop_machine_identity_in_txn(
    store: &crate::store::Store,
    wtxn: &mut heed::RwTxn<'_>,
) -> Result<()> {
    MACHINE_ID.delete(store, wtxn, &())?;
    DEVICE_PK.delete(store, wtxn, &())?;
    MACHINE_PK.delete(store, wtxn, &())?;
    crate::authority::drop_pinned_root_in_txn(store, wtxn)
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

/// Mints a random nonzero u64 from the random tail of a UUID (bytes 8..16
/// of a v7 UUID are the random section — the head is a timestamp).
fn mint_client_id(clock: &crate::ports::StoreClock) -> Result<u64> {
    // The public device id is not a signing key. Keys retain the OS CSPRNG.
    // Take the source's nonzero random tail, preserving its existing wire shape.
    for _ in 0..16 {
        let bytes = clock.ulid()?;
        let tail: [u8; 8] = bytes[8..16].try_into().expect("id tail is 8 bytes");
        let candidate = u64::from_le_bytes(tail);
        if candidate != 0 {
            return Ok(candidate);
        }
    }
    Err(Error::InvariantViolation(
        "id source produced zero device ids",
    ))
}

fn decode_client_id_row(raw: &[u8]) -> Result<u64> {
    let bytes: [u8; 8] = raw
        .try_into()
        .map_err(|_| Error::CorruptedIndex("sync client_id row"))?;
    let decoded = u64::from_le_bytes(bytes);
    if decoded == 0 {
        return Err(Error::CorruptedIndex("sync client_id zero"));
    }
    Ok(decoded)
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
