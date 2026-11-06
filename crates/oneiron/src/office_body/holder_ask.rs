//! Holder asks for office proposals (DEC-0006: "The rest wait together as one
//! review bundle, offered to every holder whose power covers them"). When a
//! settlement leaves members waiting, one ask TASK per member artifact goes
//! to every holder of that artifact's office edits, or to the vault's owners
//! when no standing grant names one. A holder's definitive answer lands as
//! that holder for
//! the ask's recorded forks; a hold, an unknown or silence lands nothing
//! (ARCH-0040: "Only a ledger record from a holder surface satisfies
//! approval").
//!
//! Live DOCX/XLSX edits without a grant ask the vault's owners instead
//! (FIX 596): a definitive owner ACCEPT mints the standing
//! `entity.office.edit` grant for the editor on the artifact in the ask's
//! settling transaction; the editor's retry carries the ops and lands
//! through the normal grant check. Nothing auto-applies.

use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::side_table::{self, Named, SideTable};
use crate::task_verb::{
    AskAuthorityScope, ConsultPayloadRef, TaskAskDecision, TaskAskDefault, TaskAskEvidenceReason,
    TaskAskOptionId, TaskAskQuestion, TaskAskResult, TaskAskSettlementReason, TaskAskSource,
    TaskAskSpec, TaskAskStatus, TaskAskTarget, TaskAskWord,
};
use crate::write_envelope::WriteActor;

use super::consent::{PROPOSALS, let_go_in_txn, office_scope, settle_in_txn};

mod live_edit;
use super::support::{loro_kind, open_fork};
use super::{MemberVerdict, ProposalAsk, ProposalSettleRequest, ReviewedFork, SettleVerdict};
pub(super) use live_edit::LIVE_EDIT_GROUPS;
pub(crate) use live_edit::{
    LiveEditAskOutcome, guard_live_edit_word, is_live_edit_ask, may_cut_live_edit,
    resolve_live_edit_holder_ask_in_txn,
};

/// The intent prefix of an office proposal's holder ask; with the proposal
/// and the waiting set's revision it keys one ask, so a repeat replays it.
const ASK_INTENT: &str = "office.proposal.holders";
const REVISION_DOMAIN: &[u8] = b"oneiron.office.proposal_ask.v1";
/// The two choices a holder ask offers (FIX 3107): accept lands the recorded
/// forks, reject discards them, each as the answering holder.
const ACCEPT: &str = "accept";
const REJECT: &str = "reject";
impl Memory<'_> {
    /// Ask each waiting member artifact's holders once per waiting set. Ask
    /// admission refuses only that artifact's ask: the settlement stands,
    /// the refusal is kept on the proposal, and all refusal reasons are
    /// returned for the settle or merge result to say no holder was asked.
    pub(super) fn ask_office_holders(&self, proposal: &EntityId) -> Option<String> {
        if !self.has_task_work_turn() {
            return self.task_work_memory().ask_office_holders(proposal);
        }
        let artifacts = match self.vault().office_body_proposal(proposal) {
            Ok(Some(record)) => record
                .members
                .iter()
                .filter(|member| member.verdict == MemberVerdict::Waiting)
                .map(|member| member.artifact)
                .collect::<BTreeSet<_>>(),
            Ok(None) => return None,
            Err(error) => {
                tracing::warn!(
                    proposal = %proposal.to_hex(),
                    %error,
                    "office proposal holder ask could not read its members"
                );
                return Some(error.to_string());
            }
        };
        let mut reasons = Vec::new();
        for artifact in artifacts {
            let Err(error) = self.raise_office_holder_ask(&artifact, proposal) else {
                continue;
            };
            tracing::warn!(
                proposal = %proposal.to_hex(),
                artifact = %artifact.to_hex(),
                %error,
                "office proposal holder ask refused"
            );
            let reason = error.to_string();
            if let Err(error) = self
                .vault()
                .record_office_proposal_ask_refused(proposal, &artifact, &reason)
            {
                tracing::warn!(
                    proposal = %proposal.to_hex(),
                    artifact = %artifact.to_hex(),
                    %error,
                    "office proposal ask refusal not recorded"
                );
            }
            reasons.push(reason);
        }
        (!reasons.is_empty()).then(|| reasons.join("; "))
    }

    fn raise_office_holder_ask(
        &self,
        artifact: &EntityId,
        proposal: &EntityId,
    ) -> MemoryResult<()> {
        let vault = self.vault();
        let Some(record) = vault.office_body_proposal(proposal)? else {
            return Ok(());
        };
        let forks: Vec<EntityId> = record
            .members
            .iter()
            .filter(|member| {
                member.artifact == *artifact && member.verdict == MemberVerdict::Waiting
            })
            .map(|member| member.fork)
            .collect();
        if record.settlement.is_some() || forks.is_empty() {
            return Ok(());
        }
        let revision = waiting_revision(proposal, artifact, &forks);
        let intent_key = format!(
            "{ASK_INTENT}/{}/{}/{revision}",
            proposal.to_hex(),
            artifact.to_hex()
        );
        for asked in &record.asks {
            if asked.artifact == *artifact
                && asked.forks == forks
                && self.owns_task_ask_intent(
                    crate::task_verb::TaskAskHandle {
                        group_ref: asked.ask,
                    },
                    &intent_key,
                )?
            {
                return Ok(vault.record_office_proposal_ask(proposal, asked.clone())?);
            }
        }
        let (class, envelope) = office_scope(artifact)?;
        let who = {
            let txn = vault
                .store
                .env
                .read_txn()
                .map_err(crate::error::Error::from)?;
            if vault
                .ask_authority_holders_in_txn(&txn, &class, &envelope)?
                .is_empty()
            {
                let owners = crate::policy_model::owners_in_txn(vault, &txn)?;
                if owners.is_empty() {
                    return Err(MemoryError::bad_request(
                        "an office proposal ask has no holder and no vault owner",
                    ));
                }
                TaskAskTarget::People(owners.into_iter().collect())
            } else {
                TaskAskTarget::Authority(AskAuthorityScope { class, envelope })
            }
        };
        let version = vault
            .blob_artifact_head(artifact)?
            .ok_or_else(|| MemoryError::not_found("the office artifact has no version"))?;
        let mut question = TaskAskQuestion::new(ConsultPayloadRef::Claim(version.claim_id));
        question.revision = revision;
        question.options = BTreeMap::from([
            (
                TaskAskOptionId::new(ACCEPT)?,
                "Accept: land these forks as you".to_owned(),
            ),
            (
                TaskAskOptionId::new(REJECT)?,
                "Reject: discard these forks as you".to_owned(),
            ),
        ]);
        question.label = Some(format!(
            "Office proposal {} on artifact {}: {} fork(s) wait for a holder whose authority covers them. Read each with vault.artifacts.body.fork.diff, then accept or reject here, or settle with vault.artifacts.body.proposal.settle; your choice lands as you for its forks, while a hold or silence lands nothing.",
            proposal.to_hex(),
            artifact.to_hex(),
            forks.len()
        ));
        let mut spec = TaskAskSpec::shorthand(Some(who), question, None, TaskAskDefault::Hold);
        spec.intent_key = intent_key;
        let receipt = self.tasks_ask_with_txn_effect(&spec, |txn, group| {
            vault
                .record_office_proposal_ask_in_txn(
                    txn,
                    proposal,
                    ProposalAsk {
                        artifact: *artifact,
                        ask: group,
                        forks: forks.clone(),
                        at: vault.now_recorded_at(),
                    },
                )
                .map_err(MemoryError::from)
        })?;
        // Admission replays do not rerun their transaction effect.
        if receipt.idempotent_replay {
            vault.record_office_proposal_ask(
                proposal,
                ProposalAsk {
                    artifact: *artifact,
                    ask: receipt.handle.group_ref,
                    forks,
                    at: vault.now_recorded_at(),
                },
            )?;
        }
        Ok(())
    }
}

/// One waiting set's revision: the same forks waiting in a proposal ask once;
/// a fork joining or landing makes a new set, asked anew.
fn waiting_revision(proposal: &EntityId, artifact: &EntityId, forks: &[EntityId]) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REVISION_DOMAIN);
    hasher.update(proposal.as_bytes());
    hasher.update(artifact.as_bytes());
    for fork in forks {
        hasher.update(fork.as_bytes());
    }
    let mut head = [0; 8];
    head.copy_from_slice(&hasher.finalize().as_bytes()[..8]);
    u64::from_be_bytes(head).max(1)
}

/// Whether `intent_key` is an office holder ask's (FIX 3107).
fn is_office_holder_ask_intent(intent_key: &str) -> bool {
    intent_key
        .strip_prefix(ASK_INTENT)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Settle the office proposal a holder ask answered (FIX 3107), or let its
/// waiting members go when the ask expired with no answer (FIX 3106), in the
/// ask's settling transaction.
///
/// A definitive first word lands exactly what its holder chose, as that
/// holder, for the ask's recorded forks; a hold, an unknown, a word with no
/// offered option or no answer lands nothing; a deadline cut with no
/// definitive word lets the recorded forks go. A settle that fails warns and
/// leaves the ask answered; the holder can still settle at the proposal door.
/// No-op for every other ask.
pub(crate) fn resolve_holder_ask_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    result: &TaskAskResult,
) -> Result<()> {
    if !is_office_holder_ask_intent(&result.settlement.requested.intent_key) {
        return Ok(());
    }
    // The office half runs in a savepoint: whatever it refuses warns, rolls
    // back only its own writes, and never fails the ask's settlement.
    let mut savepoint = vault.store.env.nested_write_txn(txn)?;
    match land_holder_ask_in_txn(vault, &mut savepoint, result) {
        Ok(()) => savepoint.commit()?,
        Err(error) => tracing::warn!(
            ask = %result.settlement.group_ref.to_hex(),
            %error,
            "office holder ask answer not landed; the ask stays answered"
        ),
    }
    Ok(())
}

/// [`resolve_holder_ask_in_txn`]'s office half, in its savepoint.
fn land_holder_ask_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    result: &TaskAskResult,
) -> Result<()> {
    if let Some((holder, class, verdict)) = definitive_holder_answer(result) {
        return settle_holder_answer_in_txn(
            vault,
            txn,
            &result.settlement.group_ref,
            holder,
            class,
            verdict,
        );
    }
    if result.settlement.reason == TaskAskSettlementReason::Deadline {
        let Some((artifact, _, asked)) =
            proposal_for_holder_ask(vault, txn, &result.settlement.group_ref)?
        else {
            return Ok(());
        };
        for fork in &asked.forks {
            let_go_in_txn(&vault.store, txn, &artifact, fork, result.settlement.at)?;
        }
    }
    Ok(())
}

/// The holder a definitive holder-ask answer lands as, with its writer class
/// and the verdict its word chose (FIX 3107): a counted first word from the
/// holder itself for one of the ask's offered options, not a companion hint,
/// an inform or a hold. `None` for a hold, an unknown, a word with no option
/// or any other option, or no answer.
fn definitive_holder_answer(
    result: &TaskAskResult,
) -> Option<(EntityId, EdgeActorClass, SettleVerdict)> {
    if result.settlement.reason == TaskAskSettlementReason::Stale
        || !result.coverage.met
        || result.fallback.is_some()
    {
        return None;
    }
    let TaskAskDecision::First(answer) = &result.decision else {
        return None;
    };
    let entry = result
        .evidence
        .iter()
        .find(|entry| entry.answer == *answer)?;
    if entry.reason != TaskAskEvidenceReason::Counted || entry.person_ref != answer.actor_ref {
        return None;
    }
    let class = match entry.source {
        TaskAskSource::Human | TaskAskSource::ForeignStated => EdgeActorClass::Human,
        TaskAskSource::Executor => EdgeActorClass::Agent,
        TaskAskSource::Companion | TaskAskSource::Inform => return None,
    };
    let verdict = match entry.word.option.as_ref().map(|option| option.as_str()) {
        Some(ACCEPT) => SettleVerdict::Accept,
        Some(REJECT) => SettleVerdict::Reject,
        _ => return None,
    };
    Some((answer.actor_ref, class, verdict))
}

/// The artifact, proposal and recorded ask for a holder ask group, if held.
fn proposal_for_holder_ask(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    ask: &EntityId,
) -> Result<Option<(EntityId, EntityId, ProposalAsk)>> {
    for (proposal, record) in PROPOSALS.scan(&vault.store, txn)? {
        if let Some(found) = record.asks.iter().find(|held| held.ask == *ask) {
            return Ok(Some((found.artifact, proposal, found.clone())));
        }
    }
    Ok(None)
}

/// Land a holder's definitive answer for its ask's recorded forks that still
/// wait (FIX 3107): the verdict its word chose, pinned by the current live
/// head and fork heads, as the answering holder. A settle that fails warns
/// and leaves the ask answered; the holder can still settle at the proposal
/// door.
fn settle_holder_answer_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    ask: &EntityId,
    holder: EntityId,
    class: EdgeActorClass,
    verdict: SettleVerdict,
) -> Result<()> {
    let Some((artifact, proposal, asked)) = proposal_for_holder_ask(vault, txn, ask)? else {
        return Ok(());
    };
    let Some(record) = PROPOSALS.get(&vault.store, txn, &proposal)? else {
        return Ok(());
    };
    if record.settlement.is_some() {
        return Ok(());
    }
    let waiting: Vec<EntityId> = asked
        .forks
        .iter()
        .filter(|fork| {
            record.members.iter().any(|member| {
                member.artifact == artifact
                    && member.fork == **fork
                    && member.verdict == MemberVerdict::Waiting
            })
        })
        .copied()
        .collect();
    if waiting.is_empty() {
        return Ok(());
    }
    let kind = match loro_kind(&vault.store, txn, &artifact) {
        Ok(kind) => kind,
        Err(error) if matches!(error, Error::InvalidConfig(_) | Error::EntityNotFound) => {
            tracing::warn!(
                proposal = %proposal.to_hex(),
                ask = %ask.to_hex(),
                %error,
                "office holder ask answer not settled"
            );
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let head = match vault.loro_body(txn, &artifact, kind, None) {
        Ok((head, _)) => head,
        Err(error) if matches!(error, Error::InvalidConfig(_) | Error::EntityNotFound) => {
            tracing::warn!(
                proposal = %proposal.to_hex(),
                ask = %ask.to_hex(),
                %error,
                "office holder ask answer not settled"
            );
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let mut pins = Vec::with_capacity(waiting.len());
    for fork in &waiting {
        let (_, doc) = match open_fork(&vault.store, txn, &artifact, fork) {
            Ok(opened) => opened,
            Err(error) if matches!(error, Error::InvalidConfig(_) | Error::EntityNotFound) => {
                tracing::warn!(
                    proposal = %proposal.to_hex(),
                    ask = %ask.to_hex(),
                    fork = %fork.to_hex(),
                    %error,
                    "office holder ask answer not settled"
                );
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        pins.push(ReviewedFork {
            artifact,
            fork: *fork,
            head: head.frontier.clone(),
            fork_head: doc.oplog_frontiers().encode(),
        });
    }
    let request = ProposalSettleRequest {
        verdict,
        scope: None,
        reviewed: &pins,
        reason: None,
    };
    match settle_in_txn(
        vault,
        txn,
        &proposal,
        None,
        &request,
        WriteActor::new(holder, class),
    ) {
        Ok(_) => Ok(()),
        Err(error)
            if matches!(
                error,
                Error::InvalidConfig(_) | Error::EntityNotFound | Error::Refused(_)
            ) =>
        {
            tracing::warn!(
                proposal = %proposal.to_hex(),
                ask = %ask.to_hex(),
                holder = %holder.to_hex(),
                %error,
                "office holder ask answer not settled"
            );
            Ok(())
        }
        Err(error) => Err(error),
    }
}
