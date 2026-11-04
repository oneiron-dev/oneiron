//! Live DOCX/XLSX edit holder asks and ACCEPT grant minting (FIX 596).

use std::collections::BTreeMap;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::side_table::{self, Named, SideTable};
use crate::task_verb::{
    ConsultPayloadRef, TaskAskDecision, TaskAskDefault, TaskAskEvidenceReason, TaskAskOptionId,
    TaskAskQuestion, TaskAskResult, TaskAskSettlementReason, TaskAskSource, TaskAskSpec,
    TaskAskStatus, TaskAskTarget, TaskAskWord,
};

use super::super::consent::{
    LiveEditAdmission, identical_live_edit_grant_active_in_txn, live_edit_admission_in_txn,
    mint_live_edit_grant_in_txn,
};
use super::super::support::loro_kind;
use super::SettleVerdict;

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
pub(crate) struct LiveEditRoute {
    pub(crate) artifact: EntityId,
    pub(crate) editor: EntityId,
    /// The owners asked, sorted; only their words answer.
    pub(crate) owners: Vec<EntityId>,
    pub(crate) revision: u64,
}

/// `ask group` → the live-edit route it carries (FIX 596).
pub(crate) const LIVE_EDIT_GROUPS: SideTable<EntityId, LiveEditRoute, Named> =
    SideTable::new(&side_table::OFFICE_LIVE_EDIT_ASK_GROUP);

impl Memory<'_> {
    /// Asks the vault's live owners whether `editor` may edit `artifact`'s
    /// live body (FIX 596): one ask per (artifact, editor, owner set). The
    /// spec is static — artifact and editor hexes but no frontier or op
    /// data — so every retry replays the same group under the replay law.
    /// The route binds in the admission commit, so an ask never exists
    /// without the row its guard reads; a replay backfills it.
    pub(crate) fn raise_live_edit_holder_ask(
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
    pub(crate) fn live_edit_ask_outcome(&self, ask: &EntityId) -> MemoryResult<LiveEditAskOutcome> {
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
