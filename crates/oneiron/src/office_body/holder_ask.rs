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

use super::consent::{
    LiveEditAdmission, PROPOSALS, identical_live_edit_grant_active_in_txn, let_go_in_txn,
    live_edit_admission_in_txn, mint_live_edit_grant_in_txn, office_scope, settle_in_txn,
};
use super::support::{loro_kind, open_fork};
use super::{MemberVerdict, ProposalAsk, ProposalSettleRequest, ReviewedFork, SettleVerdict};

/// The intent prefix of an office proposal's holder ask; with the proposal
/// and the waiting set's revision it keys one ask, so a repeat replays it.
const ASK_INTENT: &str = "office.proposal.holders";
const REVISION_DOMAIN: &[u8] = b"oneiron.office.proposal_ask.v1";
/// The two choices a holder ask offers (FIX 3107): accept lands the recorded
/// forks, reject discards them, each as the answering holder.
const ACCEPT: &str = "accept";
const REJECT: &str = "reject";
/// The intent prefix of a live-edit holder ask (FIX 596); with the artifact,
/// the editor and the owner set's revision it keys one ask, so a repeat
/// replays it. Distinct from [`ASK_INTENT`], so the proposal resolver never
/// matches it.
const LIVE_EDIT_ASK_INTENT: &str = "office.live_edit.holders";
const LIVE_EDIT_REVISION_DOMAIN: &[u8] = b"oneiron.office.live_edit_ask.v1";

/// What an owner's answer does to the editor's live edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiveEditAnswer {
    /// Mint the standing grant the editor's retries land under.
    Grant,
    /// Refuse the live edits, typed.
    Refuse,
}

/// The options every live-edit ask carries: stable id, the answer it
/// settles and its label.
const LIVE_EDIT_OPTIONS: [(&str, LiveEditAnswer, &str); 2] = [
    (
        "accept",
        LiveEditAnswer::Grant,
        "Accept: grant these live edits as you",
    ),
    (
        "reject",
        LiveEditAnswer::Refuse,
        "Reject: refuse these live edits as you",
    ),
];

/// One live-edit holder ask's route: the artifact, editor, asked owners and
/// revision its group carries (FIX 596). Written in the ask's admission
/// commit; the guard, the cut and the resolve admit nothing without it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LiveEditRoute {
    pub(super) artifact: EntityId,
    pub(super) editor: EntityId,
    /// The owners asked, sorted; only their words answer.
    pub(super) owners: Vec<EntityId>,
    pub(super) revision: u64,
}

/// `ask group` → the live-edit route it carries (FIX 596).
pub(super) const LIVE_EDIT_GROUPS: SideTable<EntityId, LiveEditRoute, Named> =
    SideTable::new(&side_table::OFFICE_LIVE_EDIT_ASK_GROUP);

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
        let revision = waiting_revision(proposal, artifact, &forks);
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
        spec.intent_key = format!(
            "{ASK_INTENT}/{}/{}/{revision}",
            proposal.to_hex(),
            artifact.to_hex()
        );
        let receipt = self.tasks_ask(&spec)?;
        vault.record_office_proposal_ask(
            proposal,
            ProposalAsk {
                artifact: *artifact,
                ask: receipt.handle.group_ref,
                forks,
                at: vault.now_recorded_at(),
            },
        )?;
        Ok(())
    }

    /// Asks the vault's live owners whether `editor` may edit `artifact`'s
    /// live body (FIX 596): one ask per (artifact, editor, owner set). The
    /// spec is static — artifact and editor hexes but no frontier or op
    /// data — so every retry replays the same group under the replay law.
    /// The route binds in the admission commit, so an ask never exists
    /// without the row its guard reads; a replay backfills it.
    pub(super) fn raise_live_edit_holder_ask(
        &self,
        artifact: &EntityId,
        editor: &EntityId,
    ) -> MemoryResult<crate::task_verb::TaskAskReceipt> {
        if !self.has_task_work_turn() {
            return self
                .task_work_memory()
                .raise_live_edit_holder_ask(artifact, editor);
        }
        let vault = self.vault();
        let mut owners = {
            let txn = vault
                .store
                .env
                .read_txn()
                .map_err(crate::error::Error::from)?;
            crate::policy_model::owners_in_txn(vault, &txn)?
        };
        if owners.is_empty() {
            return Err(MemoryError::bad_request(
                "a live-edit ask has no vault owner to ask",
            ));
        }
        owners.sort();
        let version = vault
            .blob_artifact_head(artifact)?
            .ok_or_else(|| MemoryError::not_found("the office artifact has no version"))?;
        let revision = live_edit_revision(artifact, editor, &owners);
        let route = LiveEditRoute {
            artifact: *artifact,
            editor: *editor,
            owners: owners.clone(),
            revision,
        };
        let mut question = TaskAskQuestion::new(ConsultPayloadRef::Claim(version.claim_id));
        question.revision = revision;
        let mut options = BTreeMap::new();
        for (id, _, label) in LIVE_EDIT_OPTIONS {
            options.insert(TaskAskOptionId::new(id)?, label.to_owned());
        }
        question.options = options;
        question.label = Some(format!(
            "Live edits by {} on artifact {} wait for the vault owner. Accepting mints them a standing entity.office.edit grant on this artifact as you, and they retry the same edit; rejecting refuses it. Read the body with vault.artifacts.body.read first.",
            editor.to_hex(),
            artifact.to_hex(),
        ));
        let mut spec = TaskAskSpec::shorthand(
            Some(TaskAskTarget::People(owners.into_iter().collect())),
            question,
            None,
            TaskAskDefault::Hold,
        );
        spec.intent_key = live_edit_intent_key(&route);
        let receipt = self.tasks_ask_with_txn_effect(&spec, |txn, group| {
            LIVE_EDIT_GROUPS
                .put(&vault.store, txn, &group, &route)
                .map_err(MemoryError::from)
        })?;
        if receipt.idempotent_replay {
            vault.with_write_txn_grouped(|txn| {
                LIVE_EDIT_GROUPS.put(&vault.store, txn, &receipt.handle.group_ref, &route)
            })?;
        }
        Ok(receipt)
    }

    /// Where the live-edit ask `ask` stands (FIX 596): pending while open,
    /// accepted on a definitive owner ACCEPT while its coverage still
    /// holds, rejected on a definitive owner REJECT, lapsed once settled
    /// any other way or once the granted coverage no longer holds.
    pub(super) fn live_edit_ask_outcome(&self, ask: &EntityId) -> MemoryResult<LiveEditAskOutcome> {
        if !self.has_task_work_turn() {
            return self.task_work_memory().live_edit_ask_outcome(ask);
        }
        match self.tasks_ask_status(crate::task_verb::TaskAskHandle { group_ref: *ask })? {
            TaskAskStatus::Pending { .. } | TaskAskStatus::Changed { .. } => {
                Ok(LiveEditAskOutcome::Pending)
            }
            TaskAskStatus::WorldPrivacy(_) => Ok(LiveEditAskOutcome::Lapsed {
                reason: "the owner ask closed without a live-edit answer",
            }),
            TaskAskStatus::Settled(result) => Ok(match live_edit_definitive_answer(&result) {
                Some((_, SettleVerdict::Accept))
                    if live_edit_acceptance_holds(self.vault(), &result)? =>
                {
                    LiveEditAskOutcome::Accepted
                }
                Some((_, SettleVerdict::Accept)) => LiveEditAskOutcome::Lapsed {
                    reason: "the granted coverage no longer holds",
                },
                Some((_, SettleVerdict::Reject)) => LiveEditAskOutcome::Rejected,
                None => LiveEditAskOutcome::Lapsed {
                    reason: "the owner ask lapsed without approval",
                },
            }),
        }
    }
}

/// Where a live-edit owner ask stands (FIX 596).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LiveEditAskOutcome {
    /// Open, held, or awaiting its route: the editor waits and retries.
    Pending,
    /// A definitive owner ACCEPT whose coverage still holds: the editor
    /// retries the same edit, which lands.
    Accepted,
    /// A definitive owner REJECT: the verb refuses, typed.
    Rejected,
    /// Settled any other way — deadline, stale, all-responded, or a word
    /// that is no definitive answer: the verb refuses, typed.
    Lapsed {
        /// Why the settled ask concluded without approval.
        reason: &'static str,
    },
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

/// One live-edit ask's revision (FIX 596): the same artifact, editor and
/// owner set ask once; an owner joining or leaving asks anew. Ops and
/// frontiers stay out by the replay law.
fn live_edit_revision(artifact: &EntityId, editor: &EntityId, owners: &[EntityId]) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LIVE_EDIT_REVISION_DOMAIN);
    hasher.update(artifact.as_bytes());
    hasher.update(editor.as_bytes());
    for owner in owners {
        hasher.update(owner.as_bytes());
    }
    let mut head = [0; 8];
    head.copy_from_slice(&hasher.finalize().as_bytes()[..8]);
    u64::from_be_bytes(head).max(1)
}

/// Whether `intent_key` addresses a live-edit holder ask (FIX 596): the
/// cheap gate shared word admission checks before calling
/// [`guard_live_edit_word`]. The prefix admits nothing by itself: a routed
/// ask is one its group index names.
pub(crate) fn is_live_edit_ask(intent_key: &str) -> bool {
    intent_key
        .strip_prefix(LIVE_EDIT_ASK_INTENT)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// The intent key the route `route` names, rebuilt from its canonical
/// fields; the raise writes it, the route index re-parses it.
fn live_edit_intent_key(route: &LiveEditRoute) -> String {
    format!(
        "{LIVE_EDIT_ASK_INTENT}/{}/{}/{}",
        route.artifact.to_hex(),
        route.editor.to_hex(),
        route.revision,
    )
}

/// The answer `option` settles, when a live-edit ask offers it.
fn offered_live_edit_answer(option: &TaskAskOptionId) -> Option<LiveEditAnswer> {
    LIVE_EDIT_OPTIONS
        .iter()
        .find(|(id, _, _)| *id == option.as_str())
        .map(|(_, answer, _)| *answer)
}

/// The route an ask group carries, when the raise bound it; `None` for
/// every other ask. The rebuilt intent must equal the requested one, so a
/// crafted key names nothing; a bound group whose route does not name it
/// back fails closed.
fn live_edit_routed_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    id: EntityId,
    intent_key: &str,
) -> Result<Option<LiveEditRoute>> {
    if !is_live_edit_ask(intent_key) {
        return Ok(None);
    }
    let Some(route) = LIVE_EDIT_GROUPS.get(&vault.store, txn, &id)? else {
        return Ok(None);
    };
    if live_edit_intent_key(&route) != intent_key {
        return Err(ask_invalid());
    }
    Ok(Some(route))
}

/// Whether the route `route` names still waits (FIX 596): the artifact
/// still has a live office body, the editor still needs coverage, and a
/// routed owner is still live.
fn live_edit_route_pending_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    route: &LiveEditRoute,
) -> Result<bool> {
    match loro_kind(&vault.store, txn, &route.artifact) {
        Ok(_) => {}
        Err(error) if matches!(error, Error::InvalidConfig(_) | Error::EntityNotFound) => {
            return Ok(false);
        }
        Err(error) => return Err(error),
    }
    if live_edit_admission_in_txn(vault, txn, &route.artifact, &route.editor)?
        != LiveEditAdmission::NeedsAsk
    {
        return Ok(false);
    }
    for owner in &route.owners {
        if crate::policy_model::is_live_vault_owner_in_txn(vault, txn, owner)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The malformed-word refusal shared ask admission answers with.
fn ask_invalid() -> Error {
    Error::Record(crate::error::RecordError::InvalidTaskBody("tasks.ask.fact"))
}

fn owner_not_authenticated(reason: &'static str) -> Error {
    Error::Gate(GateError::ConsentOwnerNotAuthenticated(reason))
}

/// Refuses a word on a live-edit ask unless it is the asked owner's own act
/// on a route that still waits (FIX 596); any other ask passes untouched.
/// Runs in shared word admission, before the word is recorded, so an
/// unauthorized word can never occupy First and strand the owner's later
/// tap. `owns_revision` is the admission node's check, computed by the
/// caller that holds the ask group.
#[expect(
    clippy::too_many_arguments,
    reason = "one admission check over the word, its writer and the owner proof"
)]
pub(crate) fn guard_live_edit_word(
    vault: &Vault,
    txn: &RoTxn<'_>,
    id: EntityId,
    intent_key: &str,
    source: TaskAskSource,
    actor: EntityId,
    word: &TaskAskWord,
    owner: Option<&crate::consent::AuthenticatedOwner>,
    owns_revision: bool,
) -> Result<()> {
    let Some(route) = live_edit_routed_in(vault, txn, id, intent_key)? else {
        return Ok(());
    };
    // The owner's own tap, never a word given for them or a soft confirm.
    if word.companion_for.is_some() || word.inform_for.is_some() || word.confirmation.is_some() {
        return Err(ask_invalid());
    }
    // A definitive answer names one option the ask offered, while the route
    // still waits.
    if word
        .option
        .as_ref()
        .and_then(offered_live_edit_answer)
        .is_none()
        || !live_edit_route_pending_in_txn(vault, txn, &route)?
    {
        return Err(ask_invalid());
    }
    // Only the admission node settles the ask, so a word anywhere else
    // could never settle under the proof that admitted it.
    if !owns_revision {
        return Err(owner_not_authenticated(
            "a live-edit answer is given on the node that admitted the ask",
        ));
    }
    let Some(owner) = owner else {
        return Err(owner_not_authenticated(
            "a live-edit answer needs the owner's own authenticated word",
        ));
    };
    let proven = owner.revalidate_in_txn(vault, txn)?;
    if source != TaskAskSource::Human || proven != actor || !route.owners.contains(&proven) {
        return Err(owner_not_authenticated(
            "a live-edit answer is the asked owner's own word",
        ));
    }
    if !crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &proven)? {
        return Err(owner_not_authenticated(
            "a live-edit answer is a live vault owner's word",
        ));
    }
    Ok(())
}

/// Whether settlement may cut the ask `id` for `reason` with `decision`
/// under `owner` (FIX 596). A live-edit ask's first word settles its route
/// only under the live proof of the asked owner who gave it — for either
/// option, so a REJECT still cuts while minting nothing; without that
/// proof the ask stays open, and only its deadline or staleness closes it,
/// on the hold default.
pub(crate) fn may_cut_live_edit(
    vault: &Vault,
    txn: &RoTxn<'_>,
    id: EntityId,
    intent_key: &str,
    reason: TaskAskSettlementReason,
    decision: &TaskAskDecision,
    owner: Option<&crate::consent::AuthenticatedOwner>,
) -> Result<bool> {
    if matches!(
        reason,
        TaskAskSettlementReason::Deadline | TaskAskSettlementReason::Stale
    ) {
        return Ok(true);
    }
    let Some(route) = live_edit_routed_in(vault, txn, id, intent_key)? else {
        return Ok(true);
    };
    let TaskAskDecision::First(answer) = decision else {
        return Ok(true);
    };
    match owner {
        Some(owner) => {
            let proven = owner.revalidate_in_txn(vault, txn)?;
            Ok(proven == answer.actor_ref && route.owners.contains(&proven))
        }
        None => Ok(false),
    }
}

/// Whether a settled ACCEPT still covers its editor (FIX 596): the route
/// the group carries, re-parsed, with coverage still holding. A revoked
/// grant refuses, typed, instead of looping "retry" against a spent ask.
fn live_edit_acceptance_holds(vault: &Vault, result: &TaskAskResult) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    let Some(route) = live_edit_routed_in(
        vault,
        &txn,
        result.settlement.group_ref,
        &result.settlement.requested.intent_key,
    )?
    else {
        return Ok(false);
    };
    Ok(
        live_edit_admission_in_txn(vault, &txn, &route.artifact, &route.editor)?
            != LiveEditAdmission::NeedsAsk,
    )
}

/// The holder a definitive live-edit answer settles as, with the verdict
/// its word chose (FIX 596): a counted first Human word for one of the
/// ask's offered options, not a companion hint, an inform, a hold, or a
/// bearer word. `None` for anything else, including no answer.
fn live_edit_definitive_answer(result: &TaskAskResult) -> Option<(EntityId, SettleVerdict)> {
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
    if entry.reason != TaskAskEvidenceReason::Counted
        || entry.person_ref != answer.actor_ref
        || entry.source != TaskAskSource::Human
    {
        return None;
    }
    let verdict = match entry
        .word
        .option
        .as_ref()
        .and_then(offered_live_edit_answer)
    {
        Some(LiveEditAnswer::Grant) => SettleVerdict::Accept,
        Some(LiveEditAnswer::Refuse) => SettleVerdict::Reject,
        None => return None,
    };
    Some((answer.actor_ref, verdict))
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

/// Mints the standing grant a live-edit ask's definitive owner ACCEPT chose
/// (FIX 596), in the ask's settling transaction, before the settlement is
/// stored.
///
/// It acts only on a definitive cut of a live-edit ask: a counted Human
/// word selected First, coverage met, no fallback, not stale, live owner
/// proof naming that word's actor and an asked owner, the ask's offered
/// ACCEPT, and the route still waiting. Then it mints the standing
/// `entity.office.edit` grant for the route's editor on the route's
/// artifact; the mint and its receipt land atomically with the settlement,
/// and the existing waiter path carries the retry. A rejection, a lapse,
/// an Unknown, No or Conflict, or a cut without the answering owner's live
/// proof mints nothing, lands nothing and records no grant use; a mint
/// failure fails the settlement for a later retry.
pub(crate) fn resolve_live_edit_holder_ask_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    result: &TaskAskResult,
    owner: Option<&crate::consent::AuthenticatedOwner>,
) -> Result<()> {
    let id = result.settlement.group_ref;
    let Some(route) = live_edit_routed_in(vault, txn, id, &result.settlement.requested.intent_key)?
    else {
        return Ok(());
    };
    let (TaskAskDecision::First(answer), Some(owner)) = (&result.decision, owner) else {
        return Ok(());
    };
    if !result.coverage.met
        || result.fallback.is_some()
        || result.settlement.reason == TaskAskSettlementReason::Stale
    {
        return Ok(());
    }
    let proven = owner.revalidate_in_txn(vault, txn)?;
    if proven != answer.actor_ref || !route.owners.contains(&proven) {
        return Ok(());
    }
    let Some(selected) = result.evidence.iter().find(|entry| {
        entry.answer == *answer
            && entry.reason == TaskAskEvidenceReason::Counted
            && entry.source == TaskAskSource::Human
    }) else {
        return Ok(());
    };
    let Some(choice) = selected
        .word
        .option
        .as_ref()
        .and_then(offered_live_edit_answer)
    else {
        return Ok(());
    };
    if choice != LiveEditAnswer::Grant {
        return Ok(());
    }
    if !live_edit_route_pending_in_txn(vault, txn, &route)? {
        return Ok(());
    }
    // The accepting owner inside the opener lineage mints nothing: the
    // covering checks would filter the grant anyway. A live edit's opener
    // is its editor, so this is the owner answering their own ask.
    if proven == route.editor {
        return Ok(());
    }
    if identical_live_edit_grant_active_in_txn(vault, txn, &route.artifact, &route.editor)? {
        return Ok(());
    }
    mint_live_edit_grant_in_txn(vault, txn, owner, &route.artifact, &route.editor)?;
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
