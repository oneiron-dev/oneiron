//! The owner's rotation door and the one transaction body every rotation shares.
//!
//! Rotation is owner-initiated (ARCH-0069 S6): nothing in the engine rotates a
//! secret on its own. The owner door rechecks the proof inside the transaction
//! that replaces the value, so a request queued behind a revoked slip or a
//! removed owner rotates nothing.

use super::{RECEIPTS, RotationKind, RotationReceipt, encode_rotation_receipt_body};
use crate::Vault;
use crate::authority::{ActSurface, CustodyChange};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, GateError, Result, SecretError};
use crate::secret_custody::{
    ActiveChange, CustodyKeptHere, CustodyPlan, Material, SecretCustodyRecord, SecretCustodyStatus,
    SecretCustodyWork, SecretRevoked, SecretRotated, custody_portable, put_secret_custody_in_txn,
    read_secret_custody_meta_in_txn, refuse_bindings_wider_than_live_floor,
    refuse_revoked_use_in_txn, resolve_secret_ref_in_txn,
};
use crate::side_table::HexId;
use zeroize::Zeroize;

impl Vault {
    /// Rotates a secret on the vault owner's behalf, this install the
    /// holder, keeping the permits of the secret's live change
    /// ([`Vault::rotate_secret_with_custody`] with the default plan). Returns
    /// the rotation receipt this install wrote.
    ///
    /// # Errors
    /// Those of [`Vault::rotate_secret_with_custody`], and a rotation this
    /// install did not do in this commit.
    pub fn rotate_secret_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        secret_ref: &str,
        new_value: &[u8],
        at: u64,
    ) -> Result<RotationReceipt> {
        self.rotate_secret_with_custody(
            owner,
            ActSurface::ThisInstall,
            secret_ref,
            new_value,
            &CustodyPlan::default(),
            at,
        )?
        .rotation
        .ok_or_else(|| {
            Error::InvalidConfig(
                "the rotation is recorded for its holder, which has not done it yet".to_owned(),
            )
        })
    }

    /// Rotates a secret on the vault owner's behalf, behind the owner proof,
    /// rechecked in the committing transaction: the vault-side value update
    /// of ARCH-0069 S6 (the module docs). In one write transaction the
    /// record's `rotation_generation` advances by one, `rotated_at` is
    /// stamped, the value is replaced and a [`RotationReceipt`] lands. It
    /// kills no lease and touches no build exhaust. It is the only served
    /// rotation.
    ///
    /// A portable record's rotation is a custody rotate request (WILL L04
    /// row 04): its holder, the one `plan` names or this install, rotates
    /// it and signs the transition to the recipients `plan` permits, or
    /// those of the secret's live change when it names none. When this
    /// install is the holder it does so in this commit; any other holder
    /// gets the new value sealed to its key as the request's protected
    /// input, and the receipt reads awaiting it. A record that stays on its
    /// device, or an install that carries no owner act, rotates here alone,
    /// and the receipt says so. `surface` is audit only.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] when the proof belongs to
    /// another vault, its slip or person is no longer live, or the actor is no
    /// longer an owner of this vault; [`SecretError::SecretRefNotFound`] for a
    /// name custody does not hold; [`SecretError::SecretCustodyNotActive`] for
    /// a record that is not `Active`, or one an admitted revoke ended;
    /// [`SecretError::ManifestWidensFloor`] when its bindings no longer fit
    /// the live custody floor; a holder or recipient that is no live linked
    /// install with an importable key; a refusal of this install as holder;
    /// an install key that fails to load; otherwise the store's errors.
    pub fn rotate_secret_with_custody(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        secret_ref: &str,
        new_value: &[u8],
        plan: &CustodyPlan,
        at: u64,
    ) -> Result<SecretRotated> {
        self.load_install_signing_if_minted()?;
        let mut wtxn = self.store.env.write_txn()?;
        let actor = owner.revalidate_in_txn(self, &wtxn)?;
        if !crate::policy_model::is_live_vault_owner_in_txn(self, &wtxn, &actor)? {
            return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "only the vault owner rotates a secret",
            )));
        }
        let id = resolve_secret_ref_in_txn(&self.store, &wtxn, secret_ref)?.ok_or_else(|| {
            Error::Secret(SecretError::SecretRefNotFound {
                name: secret_ref.to_owned(),
            })
        })?;
        let held = Held(
            read_secret_custody_meta_in_txn(&self.store, &wtxn, &id)?
                .ok_or(Error::CorruptedIndex("secret custody record for live name"))?,
        );
        let rotated = if custody_portable(&held.0) {
            refuse_revoked_use_in_txn(self, &wtxn, &id, held.0.class, &held.0.name)?;
            if held.0.status != SecretCustodyStatus::Active {
                return Err(Error::Secret(SecretError::SecretCustodyNotActive {
                    name: held.0.name.clone(),
                }));
            }
            refuse_bindings_wider_than_live_floor(&self.store, &wtxn, &held.0)?;
            let generation = held
                .0
                .rotation_generation
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("secret rotation generation"))?;
            let recorded = self.record_custody_change_in_txn(
                &mut wtxn,
                actor,
                surface,
                ActiveChange {
                    change: CustodyChange::Rotate,
                    id,
                    generation,
                    plan,
                    material: Material::Value(new_value),
                    sealed: None,
                    seen: None,
                    permits: None,
                },
                at,
            )?;
            // An install that carries no owner act rotates here alone.
            let rotation = if recorded.custody.kept_here.is_some() {
                Some(self.rotate_secret_in_txn(&mut wtxn, secret_ref, new_value, at)?)
            } else {
                recorded.rotation
            };
            SecretRotated {
                rotation,
                custody: recorded.custody,
            }
        } else {
            SecretRotated {
                rotation: Some(self.rotate_secret_in_txn(&mut wtxn, secret_ref, new_value, at)?),
                custody: SecretCustodyWork::kept(CustodyKeptHere::DeviceLocal),
            }
        };
        drop(held);
        wtxn.commit()?;
        self.mirror_custody_change(&rotated.custody);
        Ok(rotated)
    }

    /// Revokes a secret on the vault owner's behalf: terminal value death,
    /// the record and every lease over it revoked with a
    /// [`RotationKind::Revoked`] receipt, behind the owner proof, rechecked in
    /// the committing transaction. It is the only served revocation.
    ///
    /// A portable record's revocation reaches the owner's other machines
    /// with no byte (WILL L04 row 04): in the same transaction this install,
    /// as the carrier of his act decided on `surface` (audit only), records
    /// a custody revoke request naming itself as executor, appends its
    /// enacted result and writes the revoked transition bound to it, and
    /// every replica that folds the request holds the id as terminal. The
    /// returned work receipt says it committed here, never that every
    /// replica holds it (CALLS CUSTODY_COMPLETION); with none recorded, the
    /// custody work says exactly why the revoke stays here (FIX 4994). An
    /// install that cannot carry the act yet, with no live machine profile
    /// or no install key loaded, still revokes here, and its carry is
    /// pending until it can sign (CALLS CUSTODY_REVOKE_PENDING_CARRY, FIX
    /// 4851). The record's value is erased here in the same commit (CALLS
    /// CUSTODY_REVOKE_ERASE).
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] when the proof is no longer
    /// the live owner's; [`SecretError::SecretRefNotFound`] for a name
    /// custody does not hold; an install key that fails to load for a reason
    /// other than keys not available here; otherwise the store's errors.
    pub fn revoke_secret_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        secret_ref: &str,
        at: u64,
    ) -> Result<SecretRevoked> {
        self.load_signing_for_revoke()?;
        let mut wtxn = self.store.env.write_txn()?;
        let actor = owner.revalidate_in_txn(self, &wtxn)?;
        if !crate::policy_model::is_live_vault_owner_in_txn(self, &wtxn, &actor)? {
            return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "only the vault owner revokes a secret",
            )));
        }
        let rotation =
            self.revoke_secret_in_txn(&mut wtxn, secret_ref, super::RevokeCause::Revoked, at)?;
        let custody =
            self.carry_custody_revoke_in_txn(&mut wtxn, actor, surface, secret_ref, at)?;
        wtxn.commit()?;
        self.mirror_custody_change(&custody);
        Ok(SecretRevoked { rotation, custody })
    }

    /// A rotation's body, inside the caller's transaction: the owner door
    /// for a record that stays here, and a custody holder's rotate. A record
    /// an admitted revoke ended refuses, though this install has not
    /// settled it yet.
    pub(crate) fn rotate_secret_in_txn(
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
        let mut rec = Held(
            read_secret_custody_meta_in_txn(&self.store, wtxn, &id)?
                .ok_or(Error::CorruptedIndex("secret custody record for live name"))?,
        );
        let rec = &mut rec.0;
        refuse_revoked_use_in_txn(self, wtxn, &id, rec.class, &rec.name)?;
        if rec.status != SecretCustodyStatus::Active {
            return Err(Error::Secret(SecretError::SecretCustodyNotActive {
                name: rec.name.clone(),
            }));
        }

        // Narrow-only, re-checked against the LIVE floor through the body
        // registration enforces: a rotation is a fresh authorization of this
        // record's exposure, not a grandfather clause for the posture it
        // registered under.
        refuse_bindings_wider_than_live_floor(&self.store, wtxn, rec)?;

        let from_generation = rec.rotation_generation;
        let to_generation = from_generation
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("secret rotation generation"))?;
        rec.rotation_generation = to_generation;
        rec.rotated_at = Some(at);
        // The DEK-plane value write. `value_bytes` is `pub(crate)` precisely
        // so this stays inside the crate's custody plane; the new bytes reach
        // no receipt, log, claim or export from here. The old value is wiped
        // before its buffer is freed.
        wipe(&mut rec.value_bytes);
        rec.value_bytes = new_value.to_vec();

        let receipt = RotationReceipt {
            receipt_id: self.store.clock.entity_id()?,
            secret_ref: rec.name.clone(),
            from_generation,
            to_generation,
            rotated_at: at,
            kind: RotationKind::Rotated,
        };
        put_secret_custody_in_txn(self, wtxn, &id, rec, at)?;
        RECEIPTS.put(
            &self.store,
            wtxn,
            &HexId(receipt.receipt_id),
            &encode_rotation_receipt_body(&receipt)?,
        )?;
        // A key a mask found is answered by its rotation (OF-560's notice).
        crate::secret_custody::settle_found_key_in_txn(
            &self.store,
            wtxn,
            &id,
            crate::secret_custody::FoundKeySettled {
                action: crate::secret_custody::FoundKeyAction::Rotate,
                by: None,
                at,
                receipt: format!("rotation:{}", receipt.receipt_id.to_hex()),
                grant_ref: None,
            },
        )?;
        Ok(receipt)
    }
}

/// The record a rotation reads. It holds the old value and then the new one,
/// and its value is wiped when the rotation is done with it, on every path.
struct Held(SecretCustodyRecord);

impl Drop for Held {
    fn drop(&mut self) {
        wipe(&mut self.0.value_bytes);
    }
}

/// Every value buffer the rotation owns ends here.
fn wipe<B: Zeroize + AsRef<[u8]> + ?Sized>(buffer: &mut B) {
    #[cfg(test)]
    wiped::saw(buffer.as_ref());
    buffer.zeroize();
}

/// The wipe hook's record, so a test can name a buffer by its contents and
/// see that it went through [`wipe`].
#[cfg(test)]
pub(super) mod wiped {
    use std::cell::RefCell;

    thread_local! {
        // Per thread: a rotation wipes on the thread that calls it.
        static SEEN: RefCell<Vec<blake3::Hash>> = const { RefCell::new(Vec::new()) };
    }

    pub(super) fn saw(buffer: &[u8]) {
        SEEN.with_borrow_mut(|seen| seen.push(blake3::hash(buffer)));
    }

    /// How many buffers this thread wiped that held exactly `bytes` just
    /// before the wipe.
    pub(in crate::secret_rotation) fn count(bytes: &[u8]) -> usize {
        let held = blake3::hash(bytes);
        SEEN.with_borrow(|seen| seen.iter().filter(|seen| **seen == held).count())
    }
}
