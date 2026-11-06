//! A membership change no host issuer could sign (FIX 12335, Engine 13:13
//! call A). A role change, removal or leave, and a matured Owner act, apply
//! their effects at once, as before: each Grant they drop is marked
//! withdrawn here and its tombstone staged for sync in their own writer.
//! With a live host issuer that writer also signs each signed-mint Grant's
//! withdrawal and the Owner handover. With none, the same writer keeps one
//! value-free intent under the receipt's id: the vault, the cause, the
//! authenticated person who executed the change, the member whose role
//! moved, the act, the second it was executed at, the exact signed-mint
//! Grants it withdrew and an Owner act's handover. No credential, proof or
//! archive is kept.
//!
//! This install signs the intent as a carrier-signed membership execution
//! record ([`crate::authority::MembershipExecution`]) in the change's own
//! writer when it can carry for the vault, and otherwise on the next pass
//! that can: the moment its install key loads, and the owner work pickup
//! after an authority catch-up and on the served tick. Each intent is
//! carried in a writer of its own, once per receipt, naming only the Grants
//! the fold does not hold withdrawn yet, and cleared only in the writer the
//! fold counted its record in. The person's standing is never judged again:
//! a leave or a removal ends it by design, and the record states a fact
//! already committed. Until the record counts, the receipt and the audit
//! report the change pending, never signed.

use serde::{Deserialize, Serialize};

use super::super::{ChangeRecord, RECEIPT_PREFIX, encode, key};
use crate::authority::{
    AuthorityEntryHash, MembershipExecution, MembershipExecutionCause, MembershipHandover,
};
use crate::error::Result;
use crate::receipt::PendingMembershipExecutionRow;
use crate::side_table::{self, HexId, Named, SideTable};
use crate::{EntityId, Vault};

/// Each membership change whose signed record this install still owes, by
/// its receipt id.
const PENDING_MEMBERSHIP_EXECUTION: SideTable<HexId, PendingMembershipExecution, Named> =
    SideTable::new(&side_table::SHARED_ACT_MEMBERSHIP_PENDING);

/// One membership change whose record is not signed yet. It holds no value,
/// credential or proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PendingMembershipExecution {
    /// The shared vault's federation id.
    vault_id: u64,
    cause: MembershipExecutionCause,
    /// The authenticated PERSON who executed the change.
    person: EntityId,
    /// The member whose role moved.
    member: EntityId,
    /// The shared act the change executed; an Owner act's alone.
    act: Option<String>,
    /// The second the change was executed at: its receipt's.
    executed_at: u64,
    /// The signed-mint Grants the change deleted with no signed withdrawal.
    /// Ascending, unique.
    withdrawn_grants: Vec<EntityId>,
    /// An Owner act's handover, unsigned.
    handover: Option<MembershipHandover>,
}

/// What a membership change's writer could not sign, beside the vault,
/// receipt, person and time it holds.
pub(in crate::federation::shared_act) struct UnsignedExecution {
    pub(in crate::federation::shared_act) cause: MembershipExecutionCause,
    /// The member whose role moved; an Owner act's leaver.
    pub(in crate::federation::shared_act) member: EntityId,
    pub(in crate::federation::shared_act) act: Option<String>,
    /// The signed-mint Grants it deleted with no signed withdrawal, in any
    /// order.
    pub(in crate::federation::shared_act) withdrawn_grants: Vec<EntityId>,
    /// An Owner act's handover, when no issuer signed it.
    pub(in crate::federation::shared_act) handover: Option<MembershipHandover>,
}

impl UnsignedExecution {
    /// Whether nothing is left to sign.
    pub(in crate::federation::shared_act) fn is_empty(&self) -> bool {
        self.withdrawn_grants.is_empty() && self.handover.is_none()
    }
}

/// How one owed intent was carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Carried {
    /// Its record counted: the entry hash.
    Signed(AuthorityEntryHash),
    /// Every Grant it names was withdrawn by a record the fold already
    /// counted, and it hands nothing over: no new record repeats them.
    AlreadyWithdrawn,
}

impl Vault {
    /// Keeps `unsigned`, the half of the change receipted as `receipt` that
    /// no issuer signed, pending in the change's own writer `txn`, then
    /// signs it in a savepoint of `txn` when this install can carry for the
    /// vault now. [`ChangeRecord::Signed`] when the fold counted the record,
    /// [`ChangeRecord::Pending`] when the intent stays owed. A failure past
    /// the intent's write is logged by kind and leaves it owed: the change
    /// stands, as before the record existed.
    ///
    /// # Errors
    /// The intent's own write.
    pub(in crate::federation::shared_act) fn file_membership_execution_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        vault_id: u64,
        receipt: &str,
        person: EntityId,
        executed_at: u64,
        unsigned: UnsignedExecution,
    ) -> Result<ChangeRecord> {
        if unsigned.is_empty() {
            return Ok(ChangeRecord::Unnamed);
        }
        let receipt = EntityId::from_hex(receipt)?;
        let pending = PendingMembershipExecution {
            vault_id,
            cause: unsigned.cause,
            person,
            member: unsigned.member,
            act: unsigned.act,
            executed_at,
            withdrawn_grants: crate::authority::canonical_handover_ids(unsigned.withdrawn_grants),
            handover: unsigned.handover,
        };
        PENDING_MEMBERSHIP_EXECUTION.put(&self.store, txn, &HexId(receipt), &pending)?;
        match self.carry_membership_execution_in_savepoint(txn, receipt) {
            Ok(Some(Carried::Signed(hash))) => Ok(ChangeRecord::Signed(hash)),
            Ok(Some(Carried::AlreadyWithdrawn)) => Ok(ChangeRecord::Unnamed),
            Ok(None) => Ok(ChangeRecord::Pending),
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a membership change's record was not signed in its writer; it stays pending"
                );
                Ok(ChangeRecord::Pending)
            }
        }
    }

    fn carry_membership_execution_in_savepoint(
        &self,
        txn: &mut heed::RwTxn<'_>,
        receipt: EntityId,
    ) -> Result<Option<Carried>> {
        let mut savepoint = self.store.env.nested_write_txn(txn)?;
        let carried = self.carry_membership_execution_in_txn(&mut savepoint, receipt)?;
        if carried.is_some() {
            savepoint.commit()?;
        }
        Ok(carried)
    }

    /// Signs the record of the intent kept under `receipt` in `txn` and
    /// clears the intent there, once the fold counted it: the Grants it
    /// names that the fold does not hold withdrawn yet, and its handover.
    /// An intent whose every Grant a counted record already withdrew, with
    /// no handover, clears with no new record. `None`, with nothing
    /// written, for no intent or an install that cannot carry now.
    fn carry_membership_execution_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        receipt: EntityId,
    ) -> Result<Option<Carried>> {
        let Some(pending) = PENDING_MEMBERSHIP_EXECUTION.get(&self.store, txn, &HexId(receipt))?
        else {
            return Ok(None);
        };
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let withdrawn_grants: Vec<EntityId> = pending
            .withdrawn_grants
            .iter()
            .copied()
            .filter(|grant| !fold.slips.revoked_grants.contains(&grant.to_hex()))
            .collect();
        if withdrawn_grants.is_empty() && pending.handover.is_none() {
            PENDING_MEMBERSHIP_EXECUTION.delete(&self.store, txn, &HexId(receipt))?;
            return Ok(Some(Carried::AlreadyWithdrawn));
        }
        let Some(hash) =
            self.append_membership_execution_in_txn(txn, |machine| MembershipExecution {
                machine,
                shared_vault: pending.vault_id,
                cause: pending.cause,
                person: pending.person,
                member: pending.member,
                act: pending.act.clone(),
                receipt: receipt.to_hex(),
                executed_at: pending.executed_at,
                withdrawn_grants,
                handover: pending.handover.clone(),
            })?
        else {
            return Ok(None);
        };
        PENDING_MEMBERSHIP_EXECUTION.delete(&self.store, txn, &HexId(receipt))?;
        Ok(Some(Carried::Signed(hash)))
    }

    /// Carries every membership record this install still owes, each in a
    /// writer of its own, settling its receipt in the same writer. The
    /// caller loads the install key first. Returns how many it carried.
    ///
    /// # Errors
    /// The first carry that failed; the others are still tried, and each
    /// that failed stays owed.
    fn carry_pending_membership_executions(&self) -> Result<usize> {
        let owed = self.owed_membership_executions()?;
        let mut carried = 0;
        let mut failed = None;
        for receipt in owed {
            let outcome = self.with_write_txn(|txn| {
                let Some(outcome) = self.carry_membership_execution_in_txn(txn, receipt)? else {
                    return Ok(false);
                };
                let entry = match outcome {
                    Carried::Signed(hash) => Some(hash),
                    Carried::AlreadyWithdrawn => None,
                };
                self.settle_receipt_record_in_txn(txn, &receipt.to_hex(), entry)?;
                Ok(true)
            });
            match outcome {
                Ok(true) => carried += 1,
                Ok(false) => {}
                Err(error) => {
                    failed.get_or_insert(error);
                }
            }
        }
        failed.map_or(Ok(carried), Err)
    }

    /// [`Self::carry_pending_membership_executions`] for a pass that goes on
    /// without it, such as the install key's load: a failure is logged by
    /// kind, never with a value.
    pub(crate) fn carry_pending_membership_executions_logged(&self) {
        match self.carry_pending_membership_executions() {
            Ok(carried) if carried > 0 => {
                tracing::debug!(carried, "pending membership records carried");
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "pending membership records were not carried on this install"
                );
            }
        }
    }

    /// The owner work pickup's arm: with a membership record owed, loads
    /// this install's key and carries what it can. Nothing is read from the
    /// keystore while none is owed.
    pub(crate) fn carry_owed_membership_executions(&self) {
        match self.owed_membership_executions() {
            Ok(owed) if owed.is_empty() => return,
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "pending membership records were not read on this install"
                );
                return;
            }
        }
        // A key that loads now carries them as it loads; this pass carries
        // them with a key loaded before.
        self.load_membership_carrier();
        self.carry_pending_membership_executions_logged();
    }

    /// Loads this install's key for a membership change about to run with no
    /// supplied issuer, so its writer can sign the change's record. A key
    /// that does not load leaves the record pending, never refuses the
    /// change.
    pub(in crate::federation::shared_act) fn load_membership_carrier(&self) {
        if let Err(error) = self.load_install_signing_if_minted() {
            tracing::debug!(
                kind = ?error.kind(),
                "this install's key did not load; a membership record waits for it"
            );
        }
    }

    /// The receipt ids whose membership record this install still owes.
    fn owed_membership_executions(&self) -> Result<Vec<EntityId>> {
        let txn = self.store.env.read_txn()?;
        Ok(PENDING_MEMBERSHIP_EXECUTION
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(HexId(receipt), _)| receipt)
            .collect())
    }

    /// The audit's view of every owed membership record, by receipt id.
    pub(crate) fn pending_membership_execution_rows_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Vec<PendingMembershipExecutionRow>> {
        Ok(PENDING_MEMBERSHIP_EXECUTION
            .scan(&self.store, txn)?
            .into_iter()
            .map(|(HexId(receipt), pending)| PendingMembershipExecutionRow {
                receipt: receipt.to_hex(),
                vault_id: pending.vault_id,
                act: pending.act,
                cause: pending.cause.wire().to_owned(),
                person: pending.person.to_hex(),
                member: pending.member.to_hex(),
                executed_at: pending.executed_at,
                withdrawn_grants: pending
                    .withdrawn_grants
                    .iter()
                    .map(EntityId::to_hex)
                    .collect(),
                handover: pending.handover.is_some(),
            })
            .collect())
    }

    /// The stored receipt `receipt_id` once its record counted: no longer
    /// pending, and naming `entry`, the record, when it names none yet. A
    /// receipt this vault no longer holds is left alone.
    fn settle_receipt_record_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        receipt_id: &str,
        entry: Option<AuthorityEntryHash>,
    ) -> Result<()> {
        let Some(mut receipt) = self.shared_act_receipt_in_txn(txn, receipt_id)? else {
            return Ok(());
        };
        receipt.authority_record_pending = false;
        if let Some(entry) = entry
            && receipt.authority_entry.is_none()
        {
            receipt.authority_entry = Some(crate::entity_id::bytes_to_hex_lower(&entry));
        }
        self.store
            .vault_meta
            .put(txn, &key(RECEIPT_PREFIX, &receipt.id), &encode(&receipt)?)?;
        Ok(())
    }

    /// A person's erase, in its own writer (FIX 3520): every owed membership
    /// record that names them, as the person who executed it, the member it
    /// moved or the successor it names, is dropped, so no record is signed
    /// in their name. The change's effects stand. It is the declared actor
    /// scrub of the intent table.
    pub(crate) fn erase_pending_membership_execution_actor_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        if crate::deletion::names_no_actor(self, wtxn, actor)? {
            return Ok(());
        }
        let mut dropped = 0_usize;
        for (receipt, pending) in PENDING_MEMBERSHIP_EXECUTION.scan(&self.store, wtxn)? {
            let names = pending.person == *actor
                || pending.member == *actor
                || pending
                    .handover
                    .as_ref()
                    .is_some_and(|handover| handover.to == Some(*actor));
            if names {
                PENDING_MEMBERSHIP_EXECUTION.delete(&self.store, wtxn, &receipt)?;
                dropped += 1;
            }
        }
        if dropped > 0 {
            tracing::info!(
                dropped,
                "a person's erase dropped the membership records owed in their name (FIX 12335)"
            );
        }
        Ok(())
    }
}
