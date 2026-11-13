//! The shared-act family's actor scrub (SHARED-ACT-FAMILY-ACTOR-ERASE;
//! Engine RULING ROW4-SHARED-ACT-ERASE = B, 13 Nov 21:09, with the lead's
//! condition of the same minute). A hard erase of a person keeps a shared
//! vault's governance scaffold and drops its attribution:
//! - in every execution receipt, erase ask and pending act, each field that
//!   names the person becomes [`ERASED_CALL_IDENTITY`];
//! - in the other members' outcome notices, the change names
//!   [`ERASED_CALL_IDENTITY`] where it named the person;
//! - the person's own outcome, started and matured notices are deleted;
//! - ids, roles, clocks, grants and the other members' parts stay.
//!
//! A record's target id stays as scaffold: the erase ask's record and an
//! erased record's id are no attribution. When that record is the erased
//! person's own row, the erase leaves the id resolving to nothing.
//!
//! A pending act whose starter or plan operand was the person can no longer
//! run: [`Vault::execute_completed_shared_act`] refuses it with
//! [`ERASED_MEMBER_ACT_REFUSAL`] ([`refuse_an_erased_member_act`]).
//! A held erase is no such act: it names its record, and runs.
//!
//! `start_authority_act` checks a built-in act's name, not its plan, so a
//! stored plan may not decode. Such an act cannot run. The scrub reads its
//! plan as text, writes the erased marker over each spelling of the person's
//! hex, and goes on: one malformed act never stops an erase.

use super::{
    AddOwnerPlan, EraseAskStatus, RemoveOwnerPlan, SharedActExecutionReceipt, SharedActKind,
    SharedActOutcome, SharedEraseAsk, SharedVaultChange, TransferOwnershipPlan, decode, encode,
};
use crate::error::{Error, Result};
use crate::federation::PendingAuthorityAct;
use crate::receipt::ERASED_CALL_IDENTITY;
use crate::side_table::{self, Raw, SideTable};
use crate::{EntityId, Vault};

/// Execution receipts. Key: hex32 (receipt id).
const RECEIPTS: SideTable<String, Vec<u8>, Raw> = SideTable::new(&side_table::SHARED_ACT_RECEIPT);
/// Outcome notices. Key: hex32 (recipient) ":" hex32 (receipt id).
const OUTCOMES: SideTable<String, Vec<u8>, Raw> = SideTable::new(&side_table::SHARED_ACT_OUTCOME);
/// Erase asks. Key: hex32 (ask id).
const ERASE_ASKS: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::SHARED_ACT_ERASE_ASK);
/// Pending acts. Key: hex32 (act id).
const PENDING_ACTS: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::SHARED_ACT_RECORD);
/// Started-act notices. Key: hex32 (member) ":" hex32 (act id).
const STARTED_NOTICES: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::SHARED_ACT_EVENT);
/// Matured-act notices. Key: hex32 (owner) ":" hex32 (act id).
const MATURED_NOTICES: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::SHARED_ACT_MATURED);

/// Why a pending act whose starter or operand was erased does not run.
const ERASED_MEMBER_ACT_REFUSAL: &str =
    "this act names a member whose identity was erased; it can no longer run";

/// Whether `field` names `actor`: as written, or by the id it decodes to.
fn names(field: &str, actor: &EntityId) -> bool {
    field == actor.to_hex() || EntityId::from_hex(field).is_ok_and(|id| id == *actor)
}

/// Writes [`ERASED_CALL_IDENTITY`] over `field` when it names `actor`.
/// Returns whether it did.
fn scrub(field: &mut String, actor: &EntityId) -> bool {
    let named = names(field, actor);
    if named {
        ERASED_CALL_IDENTITY.clone_into(field);
    }
    named
}

/// [`scrub`] over an optional field.
fn scrub_optional(field: &mut Option<String>, actor: &EntityId) -> bool {
    field.as_mut().is_some_and(|field| scrub(field, actor))
}

/// Scrubs the people a change names. A record's target id stays.
fn scrub_change(change: &mut SharedVaultChange, actor: &EntityId) -> bool {
    match change {
        SharedVaultChange::VaultDeleted { .. } | SharedVaultChange::RecordErased { .. } => false,
        SharedVaultChange::OwnerAdded { owner } => scrub(owner, actor),
        SharedVaultChange::OwnershipTransferred { from, to, .. }
        | SharedVaultChange::OwnerRecovered { from, to } => {
            let from = scrub(from, actor);
            scrub(to, actor) || from
        }
        SharedVaultChange::OwnerRemoved {
            target, successor, ..
        } => {
            let target = scrub(target, actor);
            scrub_optional(successor, actor) || target
        }
        SharedVaultChange::MemberAdded { member, .. }
        | SharedVaultChange::MemberInvited { member, .. }
        | SharedVaultChange::InvitationAccepted { member, .. }
        | SharedVaultChange::InvitationDeclined { member, .. }
        | SharedVaultChange::InvitationWithdrawn { member, .. }
        | SharedVaultChange::MemberRoleChanged { member, .. }
        | SharedVaultChange::MemberRemoved { member }
        | SharedVaultChange::MemberLeft { member } => scrub(member, actor),
    }
}

fn scrub_receipt(receipt: &mut SharedActExecutionReceipt, actor: &EntityId) -> bool {
    let mut changed = scrub(&mut receipt.actor, actor);
    changed |= scrub_optional(&mut receipt.authorizer, actor);
    changed |= scrub_optional(&mut receipt.proposer, actor);
    changed |= scrub_change(&mut receipt.change, actor);
    if let Some(export) = &mut receipt.export {
        changed |= scrub(&mut export.member, actor);
        for read in &mut export.diary_reads {
            changed |= scrub(&mut read.agent, actor);
        }
    }
    changed
}

fn scrub_erase_ask(ask: &mut SharedEraseAsk, actor: &EntityId) -> bool {
    let mut changed = scrub(&mut ask.asker, actor);
    match &mut ask.status {
        EraseAskStatus::Open => {}
        EraseAskStatus::Erased { by, .. } | EraseAskStatus::Declined { by } => {
            changed |= scrub(by, actor);
        }
    }
    changed
}

/// Writes [`ERASED_CALL_IDENTITY`] over each spelling of `actor`'s hex in a
/// plan that does not decode. Returns whether it did.
fn scrub_plan_text(payload: &mut Vec<u8>, actor: &EntityId) -> bool {
    let hex = actor.to_hex();
    let mut scrubbed = Vec::with_capacity(payload.len());
    let mut rest = payload.as_slice();
    let mut changed = false;
    while let Some((&byte, tail)) = rest.split_first() {
        if let Some((head, after)) = rest.split_at_checked(hex.len())
            && head.eq_ignore_ascii_case(hex.as_bytes())
        {
            scrubbed.extend_from_slice(ERASED_CALL_IDENTITY.as_bytes());
            rest = after;
            changed = true;
        } else {
            scrubbed.push(byte);
            rest = tail;
        }
    }
    if changed {
        *payload = scrubbed;
    }
    changed
}

/// Scrubs a built-in plan's operands through `operands`; a plan that does
/// not decode is scrubbed as text ([`scrub_plan_text`]). Returns whether the
/// payload changed.
fn scrub_plan<P: serde::Serialize + serde::de::DeserializeOwned>(
    payload: &mut Vec<u8>,
    actor: &EntityId,
    operands: impl FnOnce(&mut P) -> bool,
) -> Result<bool> {
    let Ok(mut plan) = decode::<P>(payload.as_slice()) else {
        return Ok(scrub_plan_text(payload, actor));
    };
    if !operands(&mut plan) {
        return Ok(false);
    }
    *payload = encode(&plan)?;
    Ok(true)
}

/// Scrubs a pending act's starter, its objections and its plan's operands.
fn scrub_pending_act(act: &mut PendingAuthorityAct, actor: &EntityId) -> Result<bool> {
    let mut changed = scrub(&mut act.starter, actor);
    if act.objections.iter().any(|id| names(id, actor)) {
        act.objections.retain(|id| !names(id, actor));
        act.objections.insert(ERASED_CALL_IDENTITY.to_owned());
        changed = true;
    }
    changed |= match SharedActKind::parse(&act.act) {
        Some(SharedActKind::AddOwner) => {
            scrub_plan(&mut act.payload, actor, |plan: &mut AddOwnerPlan| {
                scrub(&mut plan.owner, actor)
            })?
        }
        Some(SharedActKind::TransferOwnership) => scrub_plan(
            &mut act.payload,
            actor,
            |plan: &mut TransferOwnershipPlan| {
                let from = scrub(&mut plan.from, actor);
                scrub(&mut plan.to, actor) || from
            },
        )?,
        Some(SharedActKind::RemoveOwner) => {
            scrub_plan(&mut act.payload, actor, |plan: &mut RemoveOwnerPlan| {
                let target = scrub(&mut plan.target, actor);
                scrub_optional(&mut plan.successor, actor) || target
            })?
        }
        // A delete names no one; a held erase names its record, scaffold.
        Some(SharedActKind::DeleteVault | SharedActKind::Erase) | None => false,
    };
    Ok(changed)
}

/// Refuses, with [`ERASED_MEMBER_ACT_REFUSAL`], a pending act whose starter
/// or plan operand is a person a hard erase scrubbed.
pub(super) fn refuse_an_erased_member_act(act: &PendingAuthorityAct) -> Result<()> {
    if names_an_erased_member(act)? {
        return Err(Error::InvalidConfig(ERASED_MEMBER_ACT_REFUSAL.to_owned()));
    }
    Ok(())
}

/// Whether a pending act's starter or plan operand is a person a hard
/// erase scrubbed.
fn names_an_erased_member(act: &PendingAuthorityAct) -> Result<bool> {
    let erased = |field: &str| field == ERASED_CALL_IDENTITY;
    Ok(erased(&act.starter)
        || match SharedActKind::parse(&act.act) {
            Some(SharedActKind::AddOwner) => erased(&decode::<AddOwnerPlan>(&act.payload)?.owner),
            Some(SharedActKind::TransferOwnership) => {
                let plan: TransferOwnershipPlan = decode(&act.payload)?;
                erased(&plan.from) || erased(&plan.to)
            }
            Some(SharedActKind::RemoveOwner) => {
                let plan: RemoveOwnerPlan = decode(&act.payload)?;
                erased(&plan.target) || plan.successor.as_deref().is_some_and(erased)
            }
            Some(SharedActKind::DeleteVault | SharedActKind::Erase) | None => false,
        })
}

/// What a scrub does to one stored row.
enum RowEdit {
    /// The row names no one erased.
    Keep,
    /// The row with the erased marker in each slot that named the person.
    Rewrite(Vec<u8>),
    /// The person's own row.
    Delete,
}

/// Applies `edit` to each row of `table`.
fn rewrite_rows(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    table: &SideTable<String, Vec<u8>, Raw>,
    mut edit: impl FnMut(&[u8]) -> Result<RowEdit>,
) -> Result<()> {
    for (key, raw) in table.scan(&vault.store, txn)? {
        match edit(&raw)? {
            RowEdit::Keep => {}
            RowEdit::Rewrite(row) => table.put(&vault.store, txn, &key, &row)?,
            RowEdit::Delete => {
                table.delete(&vault.store, txn, &key)?;
            }
        }
    }
    Ok(())
}

/// Deletes each row of `table` keyed under `actor`'s hex.
fn delete_own_rows(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    table: &SideTable<String, Vec<u8>, Raw>,
    actor: &EntityId,
) -> Result<()> {
    let own = format!("{}:", actor.to_hex());
    for key in table.scan_keys(&vault.store, txn, own.as_bytes())? {
        table.delete(&vault.store, txn, &key)?;
    }
    Ok(())
}

impl Vault {
    /// The receipt table's actor scrub.
    pub(crate) fn erase_shared_act_receipt_actor_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        if crate::deletion::names_no_actor(self, txn, actor)? {
            return Ok(());
        }
        rewrite_rows(self, txn, &RECEIPTS, |raw| {
            let mut receipt: SharedActExecutionReceipt = decode(raw)?;
            Ok(if scrub_receipt(&mut receipt, actor) {
                RowEdit::Rewrite(encode(&receipt)?)
            } else {
                RowEdit::Keep
            })
        })
    }

    /// The outcome table's actor scrub: the person's own notices go; the
    /// others' notices keep their change, the person's part erased.
    pub(crate) fn erase_shared_act_outcome_actor_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        if crate::deletion::names_no_actor(self, txn, actor)? {
            return Ok(());
        }
        rewrite_rows(self, txn, &OUTCOMES, |raw| {
            let mut outcome: SharedActOutcome = decode(raw)?;
            Ok(if names(&outcome.recipient, actor) {
                RowEdit::Delete
            } else if scrub_change(&mut outcome.change, actor) {
                RowEdit::Rewrite(encode(&outcome)?)
            } else {
                RowEdit::Keep
            })
        })
    }

    /// The erase-ask table's actor scrub: its asker and closer; the record
    /// it targets stays.
    pub(crate) fn erase_shared_erase_ask_actor_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        if crate::deletion::names_no_actor(self, txn, actor)? {
            return Ok(());
        }
        rewrite_rows(self, txn, &ERASE_ASKS, |raw| {
            let mut ask: SharedEraseAsk = decode(raw)?;
            Ok(if scrub_erase_ask(&mut ask, actor) {
                RowEdit::Rewrite(encode(&ask)?)
            } else {
                RowEdit::Keep
            })
        })
    }

    /// The pending-act table's actor scrub: its starter, objections and plan
    /// operands. An act it scrubs can no longer run.
    pub(crate) fn erase_pending_act_actor_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        if crate::deletion::names_no_actor(self, txn, actor)? {
            return Ok(());
        }
        rewrite_rows(self, txn, &PENDING_ACTS, |raw| {
            let mut act: PendingAuthorityAct = decode(raw)?;
            Ok(if scrub_pending_act(&mut act, actor)? {
                RowEdit::Rewrite(encode(&act)?)
            } else {
                RowEdit::Keep
            })
        })
    }

    /// The started-act notice table's actor scrub: the person's own notices
    /// go; no other notice names them.
    pub(crate) fn erase_shared_act_started_notice_actor_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        if crate::deletion::names_no_actor(self, txn, actor)? {
            return Ok(());
        }
        delete_own_rows(self, txn, &STARTED_NOTICES, actor)
    }

    /// The matured-act notice table's actor scrub: the person's own notices
    /// go; no other notice names them.
    pub(crate) fn erase_shared_act_matured_notice_actor_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        if crate::deletion::names_no_actor(self, txn, actor)? {
            return Ok(());
        }
        delete_own_rows(self, txn, &MATURED_NOTICES, actor)
    }
}
