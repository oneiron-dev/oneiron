//! Revocation: terminal value death everywhere the vault reaches. The
//! record flips `Revoked`, every lease over its name flips `Revoked` with its
//! T2 file torn down, and a [`RotationKind::Revoked`] receipt lands.

use super::{LEASES, RECEIPTS, RotationKind, RotationReceipt, encode_rotation_receipt_body};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SecretError};
use crate::secret_custody::{
    SecretCustodyRecord, SecretCustodyStatus, put_secret_custody_in_txn,
    read_secret_custody_in_txn, resolve_secret_ref_in_txn,
};
use crate::secret_lease::{
    SecretLeaseStatus, teardown_local_registration_in_txn, write_secret_lease_in_txn,
};
use crate::side_table::HexId;

/// Revokes custody record `id` inside `wtxn`: the record flips `Revoked`, and
/// every lease over its name flips `Revoked` with its T2 file torn down. The
/// revoke door and a synced revocation (OF-422) both land here. Returns the
/// record as revoked.
pub(crate) fn revoke_custody_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    at: u64,
) -> Result<SecretCustodyRecord> {
    let mut rec = read_secret_custody_in_txn(&vault.store, wtxn, id)?
        .ok_or(Error::CorruptedIndex("secret custody record for live name"))?;
    if rec.status != SecretCustodyStatus::Revoked {
        rec.status = SecretCustodyStatus::Revoked;
        put_secret_custody_in_txn(vault, wtxn, id, &rec, at)?;
    }

    // The prefix sweep, collected before mutating: a cursor is not held
    // across the writes that follow it.
    let mut doomed = Vec::new();
    for entry in LEASES.scan(&vault.store, wtxn)? {
        let (_, lease) = entry;
        if lease.secret_ref == rec.name && lease.status != SecretLeaseStatus::Revoked {
            doomed.push(lease);
        }
    }
    for mut lease in doomed {
        lease.status = SecretLeaseStatus::Revoked;
        write_secret_lease_in_txn(&vault.store, wtxn, &lease)?;
        teardown_local_registration_in_txn(&vault.store, wtxn, &lease.lease_id, at)?;
    }
    Ok(rec)
}

impl Vault {
    /// Revokes a secret: terminal value death everywhere the vault reaches.
    ///
    /// The one op that DOES walk the leases, and the reason rotation does
    /// not need to. In one write transaction the record flips `Revoked`,
    /// every lease over that ref flips `Revoked` with its T2 file torn down
    /// (the [`Vault::expire_secret_leases`] sweep shape), and a
    /// [`RotationReceipt`] of kind [`RotationKind::Revoked`] lands.
    ///
    /// Afterwards every door and materialization for the ref fails typed
    /// ([`SecretError::SecretCustodyNotActive`](crate::error::SecretError::SecretCustodyNotActive)), and exhaust tainted by the ref
    /// derives [`ArtifactTaintState::TaintedStale`](super::ArtifactTaintState::TaintedStale) — derived from the dead
    /// record, with no row rewritten anywhere in the exhaust plane.
    ///
    /// The generation does NOT advance: nothing replaced the value. The
    /// receipt's kind is what tells a revoke apart from a no-op.
    ///
    /// Test-only: it writes no signed transition, so a portable record's
    /// revocation would never reach the owner's other machines. Every served
    /// revocation goes through [`Vault::revoke_secret_as_owner`], which
    /// writes the transition in the same transaction (OF-422).
    #[cfg(test)]
    pub(crate) fn revoke_secret(&self, secret_ref: &str, at: u64) -> Result<RotationReceipt> {
        let mut wtxn = self.store.env.write_txn()?;
        let receipt = self.revoke_secret_in_txn(&mut wtxn, secret_ref, at)?;
        wtxn.commit()?;
        Ok(receipt)
    }

    /// A revocation's body, inside the caller's transaction: the record
    /// flips `Revoked`, its leases are revoked, and its receipt lands.
    /// [`Vault::revoke_secret_as_owner`] writes the record's signed
    /// transition beside it.
    pub(crate) fn revoke_secret_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        secret_ref: &str,
        at: u64,
    ) -> Result<RotationReceipt> {
        let id = resolve_secret_ref_in_txn(&self.store, wtxn, secret_ref)?.ok_or_else(|| {
            Error::Secret(SecretError::SecretRefNotFound {
                name: secret_ref.to_owned(),
            })
        })?;
        let rec = revoke_custody_in_txn(self, wtxn, &id, at)?;
        let generation = rec.rotation_generation;

        let receipt = RotationReceipt {
            receipt_id: self.store.clock.entity_id()?,
            secret_ref: rec.name.clone(),
            from_generation: generation,
            to_generation: generation,
            rotated_at: at,
            kind: RotationKind::Revoked,
        };
        RECEIPTS.put(
            &self.store,
            wtxn,
            &HexId(receipt.receipt_id),
            &encode_rotation_receipt_body(&receipt)?,
        )?;
        Ok(receipt)
    }
}
