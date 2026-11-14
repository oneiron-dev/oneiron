//! The owner's "erase history" in a shared vault waits on the vault's
//! `erase` veto window when two or more live Owners hold it (ARCH-0038
//! #archive-delete-erase; Docs Q05). A personal vault, or a shared one with
//! one live Owner, erases at once. The wait is the shared vault's own
//! `erase` act and objection window, never a second veto.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::{DocAuthorization, PurgeReceipt};
use crate::check_in::CheckInDecision;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::federation::PendingAuthorityAct;
use crate::registry::ENTITY_TYPE_NOTE;
use crate::{EdgeActorClass, EntityId, Vault};
use oneiron_contracts::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, MEMORY_CODE_NOT_FOUND, MemoryError,
    MemoryResult,
};

/// The shared vault's act a history erase waits on.
const ERASE_ACT: &str = "erase";

/// An `erase` act's payload when what it erases is a text history.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryErase {
    v: u8,
    history: [u8; 16],
    /// The frontier the erase runs through; `None` takes a NOTE's oldest pin.
    through: Option<Vec<u8>>,
}

/// What the owner's history erase did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextHistoryErase {
    /// A personal vault, or a shared one with one live Owner: erased now.
    Erased(PurgeReceipt),
    /// Two or more live Owners: the vault's `erase` act started and every
    /// other Owner is told. Run it with
    /// [`Vault::execute_completed_text_history_erase`] once its window passes
    /// with no objection.
    Waiting(PendingAuthorityAct),
}

/// The shared vault's id when two or more live Owners hold it, so its
/// history erase waits on the `erase` veto window.
fn veto_vault_in_txn(vault: &Vault, txn: &RoTxn<'_>) -> Result<Option<u64>> {
    let Some(creation) = vault.shared_vault_creation_in_txn(txn)? else {
        return Ok(None);
    };
    let owners = crate::policy_model::owners_in_txn(vault, txn)?;
    Ok((owners.len() >= 2).then_some(creation.vault_id))
}

fn history_plan(act: &PendingAuthorityAct) -> Option<HistoryErase> {
    (act.act == ERASE_ACT)
        .then(|| serde_json::from_slice::<HistoryErase>(&act.payload).ok())
        .flatten()
        .filter(|plan| plan.v == 1)
}

/// Inside the history purge's own writer: with two or more live Owners the
/// purge runs only by claiming a completed `erase` act that names exactly
/// this erase, bound to this purge's `receipt`, so it runs at most once.
pub(crate) fn admit_history_erase_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    through: Option<&[u8]>,
    act: Option<&str>,
    receipt: &EntityId,
) -> Result<()> {
    let Some(act) = act else {
        if veto_vault_in_txn(vault, txn)?.is_some() {
            return Err(Error::InvalidConfig(
                "history erase waits on the erase veto window; start it first".into(),
            ));
        }
        return Ok(());
    };
    let record = vault
        .pending_authority_act_in_txn(txn, act)?
        .ok_or(Error::EntityNotFound)?;
    let plan = history_plan(&record);
    let names_this = plan.is_some_and(|plan| {
        plan.history == *entity.as_bytes() && plan.through.as_deref() == through
    });
    if !names_this {
        return Err(Error::InvalidConfig(
            "this act names another history erase".into(),
        ));
    }
    let receipt = receipt.to_hex();
    vault.claim_completed_authority_act_in_txn(txn, act, receipt.clone(), Some(receipt))
}

impl Vault {
    /// The owner's "erase history", the way the vault's preset rules it. In
    /// a personal vault, or a shared one with one live Owner, it erases now
    /// ([`Self::erase_text_history_as`]). With two or more live Owners it
    /// starts the vault's `erase` act over exactly this range instead; every
    /// other Owner is told at once, and an objection holds it (Docs Q05).
    ///
    /// # Errors
    /// The owner proof no longer holds, or the act cannot start.
    pub fn start_text_history_erase(
        &self,
        owner: &AuthenticatedOwner,
        entity: &EntityId,
        through: Option<&[u8]>,
    ) -> MemoryResult<TextHistoryErase> {
        self.start_text_history_erase_with_check_in(owner, entity, through, None)
            .map(|(erase, _)| erase)
    }

    /// [`Self::start_text_history_erase`], judged by check-in (2k2;
    /// P25-SHAPE Q1 and Q4 = A; the door names the act class `erase`), with
    /// the decision it runs on: the Owner on their own proof, and with
    /// `check_in_ref` an asker's approved check-in for this erase
    /// ([`crate::check_in::text_history_erase_effect_digest`]), which the
    /// Owner applies on their own proof. As the record erase confirm does
    /// (2j), it is spent in a writer of its own, on the Owner's live proof,
    /// before the erase or its act: a refusal after it leaves the approval
    /// spent. A waiting erase's `erase` act records the decision.
    ///
    /// # Errors
    /// As [`Self::start_text_history_erase`]; a `check_in_ref` that names no
    /// approved, unspent check-in for this erase.
    pub fn start_text_history_erase_with_check_in(
        &self,
        owner: &AuthenticatedOwner,
        entity: &EntityId,
        through: Option<&[u8]>,
        check_in_ref: Option<EntityId>,
    ) -> MemoryResult<(TextHistoryErase, CheckInDecision)> {
        let act_class = crate::check_in::ActClass::Erase;
        let decision = match check_in_ref {
            Some(id) => {
                let applied = crate::check_in::AppliedCheckIn {
                    id,
                    verb: "vault.notes.history_purge",
                    effect_digest: crate::check_in::text_history_erase_effect_digest(
                        entity, through,
                    ),
                };
                self.with_write_txn_grouped(|txn| {
                    owner.revalidate_in_txn(self, txn)?;
                    crate::check_in::owner_act_decision_in_txn(self, txn, act_class, Some(&applied))
                })?
            }
            None => crate::check_in::owner_own_proof_decision(act_class),
        };
        let vault_id = {
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            owner.revalidate_in_txn(self, &txn)?;
            veto_vault_in_txn(self, &txn)?
        };
        let Some(vault_id) = vault_id else {
            return self
                .erase_text_history_as(owner, entity, through)
                .map(|receipt| (TextHistoryErase::Erased(receipt), decision));
        };
        // The other Owners object to an exact range, not to "the head then".
        let note = super::pins::entity_type(self, entity)? == Some(ENTITY_TYPE_NOTE);
        let through = match through {
            Some(bytes) => Some(bytes.to_vec()),
            None if note => None,
            None => Some(super::pins::live_frontier_by_owner_kind(self, entity)?),
        };
        let payload = serde_json::to_vec(&HistoryErase {
            v: 1,
            history: *entity.as_bytes(),
            through,
        })
        .map_err(|_| Error::InvariantViolation("history erase act payload"))?;
        let act = self.start_authority_act_recorded(
            owner,
            vault_id,
            ERASE_ACT,
            payload,
            decision.clone(),
        )?;
        Ok((TextHistoryErase::Waiting(act), decision))
    }

    /// Runs the history erase a completed `erase` act names, once: the act
    /// is one `owner` started in this vault, and its window has run out on
    /// the store clock with no live objection. The purge claims the act in
    /// its own writer, so a retry returns that erase's receipt.
    ///
    /// # Errors
    /// No such act, another caller's act, an act that names no history
    /// erase, an open window or an objection, or the purge's own refusal.
    pub fn execute_completed_text_history_erase(
        &self,
        owner: &AuthenticatedOwner,
        act_id: &str,
    ) -> MemoryResult<PurgeReceipt> {
        let (actor, entity, through, done) = {
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            let actor = owner.revalidate_in_txn(self, &txn)?;
            let act = self
                .pending_authority_act_in_txn(&txn, act_id)?
                .ok_or_else(|| {
                    MemoryError::new(
                        MEMORY_CODE_NOT_FOUND,
                        "no such act",
                        &["Use the act id the history erase returned."],
                    )
                })?;
            let vault_id = self
                .shared_vault_creation_in_txn(&txn)?
                .map(|creation| creation.vault_id);
            let plan = history_plan(&act)
                .filter(|_| act.starter == actor.to_hex() && Some(act.vault_id) == vault_id)
                .ok_or_else(|| {
                    MemoryError::new(
                        MEMORY_CODE_FORBIDDEN,
                        "this act is no history erase this caller started in this vault",
                        &["Execute a history erase act you started here."],
                    )
                })?;
            let done = act.execution.as_ref().and_then(|run| run.receipt.clone());
            if done.is_none() && !self.authority_act_completed_in_txn(&txn, &act)? {
                return Err(MemoryError::new(
                    MEMORY_CODE_INVALID_STATE,
                    "this erase's veto window is open or an owner objects",
                    &["Execute it once the window has run out with no objection."],
                ));
            }
            let entity = EntityId::from_bytes(plan.history)?;
            (actor, entity, plan.through, done)
        };
        if let Some(receipt) = done {
            return self
                .entity_text_purge_receipts(&entity)?
                .into_iter()
                .find(|filed| filed.receipt == receipt)
                .ok_or_else(|| Error::CorruptedIndex("history erase receipt").into());
        }
        if super::pins::entity_type(self, &entity)? == Some(ENTITY_TYPE_NOTE) {
            return self
                .memory(actor, EdgeActorClass::Human)
                .purge_note_history_for_act(owner, entity, through.as_deref(), act_id);
        }
        let Some(through) = through else {
            return Err(Error::CorruptedIndex("history erase act frontier").into());
        };
        Ok(self.purge_entity_text_history_for(
            &entity,
            &through,
            &DocAuthorization::Owner(owner),
            self.now_recorded_at(),
            Some(act_id),
        )?)
    }
}
