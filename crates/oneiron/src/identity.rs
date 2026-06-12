//! Device identity for REDACTION_AUDIT origin attestation (ONE-1140).
//!
//! A BASE module (not sync-gated): receipts mint — and are signed — in base
//! delete paths, including the non-sync build. Rows live in the `sync_state`
//! DB, which is unconditional (the `dt:` precedent — local truth, not
//! sync-only state):
//!
//! - `m:client_id` — this device's stable id (u64 LE, 8 bytes), minted once
//!   per install. Semantics preserved from the sync client (the mint was
//!   relocated here per OD-2 so base receipt paths can reach it; the sync
//!   client re-uses this module). A present-but-malformed row — wrong
//!   length, or an 8-byte row decoding to 0 (the mint loop never produces
//!   0, and 0 collides with Loro's unset peer id, ONE-1155) — fails closed:
//!   silently re-minting would change this device's identity mid-install.
//! - `m:device_sk` — 32 B Ed25519 signing-key seed. Stored plaintext:
//!   vault-at-rest trust = data trust (OD-2).
//! - `m:device_pk` — 32 B Ed25519 verifying key, a derived cache of the
//!   seed. A present row that does not match the seed-derived key fails
//!   closed (`CorruptedIndex`) — signing with a key peers no longer hold
//!   would silently orphan every new receipt at their replay doors.
//!
//! Identity is minted lazily inside the CALLER's write transaction (LMDB is
//! single-writer; every receipt-mint path already holds a wtxn), so the
//! first hard delete on a fresh vault self-provisions the keypair in the
//! same txn that writes the receipt.

use ed25519_dalek::SigningKey;

use crate::error::{Error, Result};
use crate::vault::Vault;

/// `m:client_id` sync_state row (u64 LE, 8 bytes).
pub(crate) const KEY_CLIENT_ID: &str = "m:client_id";
/// `m:device_sk` sync_state row (32 B Ed25519 seed).
pub(crate) const KEY_DEVICE_SK: &str = "m:device_sk";
/// `m:device_pk` sync_state row (32 B Ed25519 verifying key).
pub(crate) const KEY_DEVICE_PK: &str = "m:device_pk";

/// This device's attestation identity: the stable client id plus the
/// Ed25519 keypair that signs receipt attestations (OD-2).
pub(crate) struct DeviceIdentity {
    pub(crate) client_id: u64,
    pub(crate) signing_key: SigningKey,
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
    match vault.store.sync_state.get(wtxn, KEY_CLIENT_ID)? {
        Some(raw) if raw.len() == 8 => {
            let decoded = u64::from_le_bytes(raw.try_into().expect("length checked"));
            if decoded == 0 {
                return Err(Error::CorruptedIndex("sync client_id zero"));
            }
            Ok(decoded)
        }
        Some(_) => Err(Error::CorruptedIndex("sync client_id row")),
        None => {
            let minted = mint_client_id();
            vault
                .store
                .sync_state
                .put(wtxn, KEY_CLIENT_ID, &minted.to_le_bytes())?;
            Ok(minted)
        }
    }
}

/// Ensures the full device identity (client id + Ed25519 keypair) exists,
/// minting any missing piece inside the CALLER's txn (OD-2).
pub(crate) fn ensure_device_identity_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
) -> Result<DeviceIdentity> {
    let client_id = load_or_mint_client_id_in_txn(vault, wtxn)?;

    let signing_key = match vault.store.sync_state.get(wtxn, KEY_DEVICE_SK)? {
        Some(raw) => {
            let seed: [u8; 32] = raw
                .try_into()
                .map_err(|_| Error::CorruptedIndex("device signing key row"))?;
            SigningKey::from_bytes(&seed)
        }
        None => {
            let key = SigningKey::generate(&mut rand_core::OsRng);
            vault
                .store
                .sync_state
                .put(wtxn, KEY_DEVICE_SK, key.as_bytes())?;
            key
        }
    };

    let derived_pk = signing_key.verifying_key().to_bytes();
    match vault.store.sync_state.get(wtxn, KEY_DEVICE_PK)? {
        Some(raw) if raw == derived_pk => {}
        Some(_) => {
            // A pk row that disagrees with the seed is corruption, not a
            // healable cache miss: receipts signed under EITHER key would
            // be unverifiable against the other at peer replay doors.
            return Err(Error::CorruptedIndex("device public key row"));
        }
        None => {
            vault
                .store
                .sync_state
                .put(wtxn, KEY_DEVICE_PK, &derived_pk)?;
        }
    }

    Ok(DeviceIdentity {
        client_id,
        signing_key,
    })
}

/// Own-txn wrapper around [`ensure_device_identity_in_txn`].
pub(crate) fn ensure_device_identity(vault: &Vault) -> Result<DeviceIdentity> {
    let mut identity = None;
    vault.with_write_txn(|wtxn| {
        identity = Some(ensure_device_identity_in_txn(vault, wtxn)?);
        Ok(())
    })?;
    Ok(identity.expect("closure ran on Ok"))
}

/// Mints a random nonzero u64 from the random tail of a UUID (bytes 8..16
/// of a v7 UUID are the random section — the head is a timestamp).
fn mint_client_id() -> u64 {
    loop {
        let uuid = uuid::Uuid::now_v7();
        let tail: [u8; 8] = uuid.as_bytes()[8..16]
            .try_into()
            .expect("uuid tail is 8 bytes");
        let candidate = u64::from_le_bytes(tail);
        if candidate != 0 {
            return candidate;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::open_test_vault_with;
    use crate::types::VaultConfig;

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
        assert_eq!(u64::from_le_bytes(id_row.try_into().unwrap()), {
            assert_ne!(first.client_id, 0);
            first.client_id
        });
        let sk_row = vault
            .store
            .sync_state
            .get(&rtxn, KEY_DEVICE_SK)
            .unwrap()
            .expect("sk row");
        assert_eq!(sk_row, first.signing_key.as_bytes(), "32 B seed row");
        let pk_row = vault
            .store
            .sync_state
            .get(&rtxn, KEY_DEVICE_PK)
            .unwrap()
            .expect("pk row");
        assert_eq!(
            pk_row,
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
        assert!(matches!(
            ensure_device_identity(&vault),
            Err(Error::CorruptedIndex("sync client_id zero"))
        ));

        vault
            .with_write_txn(|wtxn| {
                vault.store.sync_state.put(wtxn, KEY_CLIENT_ID, b"short")?;
                Ok(())
            })
            .unwrap();
        assert!(matches!(
            ensure_device_identity(&vault),
            Err(Error::CorruptedIndex("sync client_id row"))
        ));

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
        assert!(matches!(
            ensure_device_identity(&vault),
            Err(Error::CorruptedIndex("device signing key row"))
        ));

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
        assert!(matches!(
            ensure_device_identity(&vault),
            Err(Error::CorruptedIndex("device public key row"))
        ));
    }
}
