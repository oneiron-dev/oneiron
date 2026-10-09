//! The owner's rotation door and the one transaction body every rotation shares.
//!
//! Rotation is owner-initiated (ARCH-0069 S6): nothing in the engine rotates a
//! secret on its own. The owner door rechecks the proof inside the transaction
//! that replaces the value, so a request queued behind a revoked slip or a
//! removed owner rotates nothing.

use super::{RECEIPTS, RotationKind, RotationReceipt, encode_rotation_receipt_body};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, GateError, Result, SecretError};
use crate::secret_custody::{
    SecretCustodyStatus, put_secret_custody_in_txn, read_secret_custody_in_txn,
    refuse_bindings_wider_than_live_floor, resolve_secret_ref_in_txn,
};
use crate::side_table::HexId;

impl Vault {
    /// Rotates a secret on the vault owner's behalf: [`Vault::rotate_secret`]
    /// behind the owner proof, rechecked in the committing transaction.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] when the proof belongs to
    /// another vault, its slip or person is no longer live, or the actor is no
    /// longer an owner of this vault; otherwise every error
    /// [`Vault::rotate_secret`] returns.
    pub fn rotate_secret_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        secret_ref: &str,
        new_value: &[u8],
        at: u64,
    ) -> Result<RotationReceipt> {
        let mut wtxn = self.store.env.write_txn()?;
        owner.revalidate_in_txn(self, &wtxn)?;
        if !crate::policy_model::is_live_vault_owner_in_txn(self, &wtxn, &owner.actor())? {
            return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "only the vault owner rotates a secret",
            )));
        }
        let receipt = self.rotate_secret_in_txn(&mut wtxn, secret_ref, new_value, at)?;
        wtxn.commit()?;
        Ok(receipt)
    }

    pub(super) fn rotate_secret_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        secret_ref: &str,
        new_value: &[u8],
        at: u64,
    ) -> Result<RotationReceipt> {
        let id = resolve_secret_ref_in_txn(&self.store, wtxn, secret_ref)?.ok_or_else(|| {
            Error::Secret(SecretError::SecretRefNotFound {
                name: secret_ref.to_owned(),
            })
        })?;
        let mut rec = read_secret_custody_in_txn(&self.store, wtxn, &id)?
            .ok_or(Error::CorruptedIndex("secret custody record for live name"))?;
        if rec.status != SecretCustodyStatus::Active {
            return Err(Error::Secret(SecretError::SecretCustodyNotActive {
                name: rec.name,
            }));
        }

        // Narrow-only, re-checked against the LIVE floor through the body
        // registration enforces: a rotation is a fresh authorization of this
        // record's exposure, not a grandfather clause for the posture it
        // registered under.
        refuse_bindings_wider_than_live_floor(&self.store, wtxn, &rec)?;

        let from_generation = rec.rotation_generation;
        let to_generation = from_generation
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("secret rotation generation"))?;
        rec.rotation_generation = to_generation;
        rec.rotated_at = Some(at);
        // The DEK-plane value write. `value_bytes` is `pub(crate)` precisely
        // so this stays inside the crate's custody plane; the new bytes reach
        // no receipt, log, claim or export from here.
        rec.value_bytes = new_value.to_vec();

        let receipt = RotationReceipt {
            receipt_id: self.store.clock.entity_id()?,
            secret_ref: rec.name.clone(),
            from_generation,
            to_generation,
            rotated_at: at,
            kind: RotationKind::Rotated,
        };
        put_secret_custody_in_txn(self, wtxn, &id, &rec, at)?;
        RECEIPTS.put(
            &self.store,
            wtxn,
            &HexId(receipt.receipt_id),
            &encode_rotation_receipt_body(&receipt)?,
        )?;
        Ok(receipt)
    }
}
