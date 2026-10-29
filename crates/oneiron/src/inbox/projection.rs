//! Read-side inbox grouping projection, member classification, and dial surfacing.

use sha2::{Digest, Sha256};

use crate::Vault;
use crate::attempt_queue::AttemptQueue;
use crate::calendar::outcome::{DueOutcomeCheckIn, check_in_is_still_due};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    PREDICATE_CONFLICT_OPEN,
};
use crate::context_board::PREDICATE_PLUGIN_SECTION_INSTALL;
use crate::dreamer_runner::decode_dreamer_attempt_payload;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::gate::GateReasonCode;
use crate::store::{GateDecisionRecord, PendingGateConsentRecord};

use super::model::{
    INBOX_REASON_CHECKER_PREFIX, INBOX_RUN_BRIEF_INTENT_KEY, INBOX_SUBCLUSTER_MIN_MEMBERS,
    InboxCheckInException, InboxExceptionClass, InboxGroup, InboxGroupMember, InboxGroupPage,
    InboxPointerRow, InboxQuery, InboxReviewDial, InboxSubCluster, VERB_CLASS_CONFLICT,
    VERB_CLASS_NEW_CLAIM, VERB_CLASS_UPDATE,
};
use super::root_group::{RunGroups, root_group_card};

impl Vault {
    /// Projects one page of open dreamer-run groups, surfaced under the
    /// persisted dial: complete root groups in the tray's order, at most
    /// `query.limit` visible ones, resuming after `query.after` (FIX 9873).
    pub fn inbox_groups(&self, query: InboxQuery) -> Result<InboxGroupPage> {
        let dial = self.inbox_review_dial()?;
        super::traversal::inbox_group_page(self, query, dial)
    }

    /// Projects the still-unanswered meeting-outcome check-ins for the wakes the
    /// host has delivered as due (CAL-07).
    ///
    /// A sibling of the dreamer-run projection, not a member of it: a calendar
    /// check-in has no run, no pending-consent row, and no consent binding, so
    /// it carries no bulk verb and never enters a group. What it shares is the
    /// exception-class vocabulary.
    ///
    /// Each due wake is rechecked against current claim state
    /// ([`check_in_is_still_due`]) — an outcome that arrived during the grace
    /// window suppresses the row. At most one row per EVENT: a second wake for
    /// an EVENT already surfaced is dropped, so a retried or duplicated host
    /// delivery cannot double-ask.
    ///
    /// # Errors
    ///
    /// Storage errors, and claim-body errors from reading an outcome head.
    pub fn inbox_meeting_outcome_check_ins(
        &self,
        due: &[DueOutcomeCheckIn],
    ) -> Result<Vec<InboxCheckInException>> {
        let mut rows: Vec<InboxCheckInException> = Vec::new();
        for check_in in due {
            let event_ref = check_in.event_ref.to_hex();
            if rows.iter().any(|row| row.event_ref == event_ref) {
                continue;
            }
            if !check_in_is_still_due(self, check_in)? {
                continue;
            }
            rows.push(InboxCheckInException {
                event_ref,
                wake_id: check_in.wake_id.clone(),
                scheduled_start_utc: check_in.scheduled_start_utc,
                exception_class: InboxExceptionClass::MeetingOutcomeCheckIn,
            });
        }
        Ok(rows)
    }
}

/// Semantic claim hash for cross-run duplicate collapse. The consent
/// binding (`diff_handle`) hashes the exact stored body, whose evidence
/// carries the writing actor and run provenance — so re-proposals of the
/// same fact by a later run would never match it. This hash keeps the claim
/// identity (predicate, subject, value, world, scope, validity) and drops
/// the per-write stamps.
pub(crate) fn inbox_claim_hash(body: &ClaimBody) -> Result<[u8; 32]> {
    let mut normalized = body.clone();
    normalized.approval = ClaimApprovalStatus::Proposed;
    normalized.lifecycle = ClaimLifecycleStatus::Active;
    normalized.set_confidence(1.0, None);
    normalized.salience = None;
    normalized.evidence = None;
    normalized.source = None;
    normalized.stale = false;
    let encoded = crate::claim::encode_claim_body(&normalized)?;
    let mut hasher = Sha256::new();
    hasher.update(b"oneiron.inbox.claim_hash.v1");
    hasher.update(&encoded);
    Ok(hasher.finalize().into())
}

#[derive(Clone)]
pub(super) struct OpenMember {
    pub(super) pending: PendingGateConsentRecord,
    pub(super) decision: GateDecisionRecord,
    pub(super) body: ClaimBody,
    pub(super) run_id: String,
}

pub(super) fn open_dreamer_members_from_pending(
    vault: &Vault,
    pending_records: Vec<PendingGateConsentRecord>,
) -> Result<Vec<OpenMember>> {
    let mut rows = Vec::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        for pending in pending_records {
            let Some(run_id) = pending.dreamer_run_id.clone() else {
                continue;
            };
            let Some(decision) = vault
                .store
                .gate_decision_in_txn(&rtxn, pending.decision_id)?
            else {
                return Err(Error::CorruptedIndex("pending gate consent"));
            };
            rows.push((pending, decision, run_id));
        }
    }

    let mut members = Vec::with_capacity(rows.len());
    for (pending, decision, run_id) in rows {
        let claim_id = EntityId::from_bytes(pending.claim_id)
            .map_err(|_| Error::CorruptedIndex("pending gate consent"))?;
        let Some(body) = vault.get_claim(&claim_id)? else {
            return Err(Error::CorruptedIndex("pending gate consent"));
        };
        members.push(OpenMember {
            pending,
            decision,
            body,
            run_id,
        });
    }
    Ok(members)
}

/// Resolves the OF-193 group identity for one stamped run id: the run-tree
/// ROOT attempt id plus the Dreamer-authored intent from the root's run brief.
/// Only Dreamer attempt rows can anchor a run tree — other attempt kinds may share
/// a run id and must never be mistaken for the root. When the run's rows
/// are all branches (a child branch carrying its own run id), the parent
/// links climb to the root; runs without any Dreamer rows keep the stamped
/// run id as their key.
pub(super) fn resolve_run_identity(
    vault: &Vault,
    run_id: &str,
) -> Result<(String, Option<String>)> {
    let queue = AttemptQueue::new(vault);
    let Some(root_id) = queue.dreamer_run_root_id(run_id)? else {
        return Ok((run_id.to_owned(), None));
    };
    let Some(root) = queue.get(root_id)? else {
        return Err(Error::CorruptedIndex("attempt run index"));
    };
    let payload = decode_dreamer_attempt_payload(&root.payload)
        .map_err(|_| Error::CorruptedIndex("attempt run index"))?;
    Ok((
        bytes_to_hex_lower(root_id.as_bytes()),
        run_brief_intent(&payload.input),
    ))
}

fn run_brief_intent(input: &rmpv::Value) -> Option<String> {
    let rmpv::Value::Map(entries) = input else {
        return None;
    };
    entries.iter().find_map(|(key, value)| {
        if key.as_str() != Some(INBOX_RUN_BRIEF_INTENT_KEY) {
            return None;
        }
        let intent = value.as_str()?.trim();
        (!intent.is_empty()).then(|| intent.to_owned())
    })
}

pub(super) fn classify_member(
    vault: &Vault,
    member: &OpenMember,
) -> Result<(Vec<InboxExceptionClass>, &'static str)> {
    let mut classes = Vec::new();
    if member
        .pending
        .reason_codes
        .iter()
        .any(|code| code.starts_with(INBOX_REASON_CHECKER_PREFIX))
    {
        classes.push(InboxExceptionClass::CheckerHedge);
    }
    if member
        .pending
        .reason_codes
        .iter()
        .any(|code| code == GateReasonCode::PendingCriticalityFloor.as_str())
    {
        classes.push(InboxExceptionClass::ManifestCritical);
    }
    // ONE-1707: the install predicate classifies additively. The row keeps
    // whatever verb class it would otherwise have had (a first install is a
    // `new_claim`), so the existing bundle verbs keep working on it unchanged.
    if member.body.predicate == PREDICATE_PLUGIN_SECTION_INSTALL {
        classes.push(InboxExceptionClass::PluginInstall);
    }

    let verb_class = if member.body.predicate == PREDICATE_CONFLICT_OPEN
        || member
            .pending
            .reason_codes
            .iter()
            .any(|code| code == "gate.pending.contradiction_closure")
    {
        classes.push(InboxExceptionClass::Conflict);
        VERB_CLASS_CONFLICT
    } else {
        match would_supersede_active_truth(vault, member)? {
            Some(supersedes_user_stated) => {
                if supersedes_user_stated {
                    classes.push(InboxExceptionClass::SupersedesUserStated);
                }
                VERB_CLASS_UPDATE
            }
            None => VERB_CLASS_NEW_CLAIM,
        }
    };
    classes.sort_unstable();
    classes.dedup();
    Ok((classes, verb_class))
}

/// Detects whether approving this proposal would supersede existing active
/// truth on the same subject + predicate (OF-060 supersession surfacing).
/// Returns `Some(true)` when the existing truth is user_stated — the
/// exception class the dial can never hide behind auto-approve.
fn would_supersede_active_truth(vault: &Vault, member: &OpenMember) -> Result<Option<bool>> {
    let ClaimSubject::Entity(subject) = member.body.subject else {
        return Ok(None);
    };
    let member_id = EntityId::from_bytes(member.pending.claim_id)
        .map_err(|_| Error::CorruptedIndex("pending gate consent"))?;
    let mut supersedes_any = false;
    let mut supersedes_user_stated = false;
    for claim_id in vault.claims_for_subject(&subject)? {
        if claim_id == member_id {
            continue;
        }
        let Some(existing) = vault.get_claim(&claim_id)? else {
            continue;
        };
        // Stale rows are excluded from read-path truth, so approving over
        // one is not a supersession of anything current.
        if existing.predicate != member.body.predicate
            || existing.lifecycle != ClaimLifecycleStatus::Active
            || existing.stale
            || matches!(
                existing.approval,
                ClaimApprovalStatus::Proposed | ClaimApprovalStatus::Rejected
            )
        {
            continue;
        }
        supersedes_any = true;
        if existing.source == Some(ClaimSource::UserStated) {
            supersedes_user_stated = true;
        }
    }
    Ok(supersedes_any.then_some(supersedes_user_stated))
}

/// The dial rule, stated exactly.
///
/// `ApproveAll` is spelled as an explicit match over the non-waivable classes
/// rather than a single `contains`: manifest-critical and plugin-install rows
/// both REQUIRE an owner decision, and listing them here is what stops a
/// future class from being waived by accident.
pub(super) fn member_surfaces(dial: InboxReviewDial, classes: &[InboxExceptionClass]) -> bool {
    match dial {
        InboxReviewDial::ReviewEverything => true,
        InboxReviewDial::ExceptionsOnly => !classes.is_empty(),
        InboxReviewDial::ApproveAll => classes.iter().any(|class| {
            matches!(
                class,
                InboxExceptionClass::ManifestCritical | InboxExceptionClass::PluginInstall
            )
        }),
    }
}

pub(super) fn sub_cluster_key(body: &ClaimBody) -> String {
    match body.subject {
        ClaimSubject::Entity(subject) => format!("entity:{}", subject.to_hex()),
        ClaimSubject::Edge { .. } => {
            let theme = body.predicate.split('.').next().unwrap_or("misc");
            format!("theme:{theme}")
        }
    }
}

fn group_headline(
    intent: Option<&str>,
    new_claims: usize,
    updates: usize,
    conflicts: usize,
) -> String {
    let mut parts = Vec::new();
    if new_claims > 0 {
        parts.push(format!(
            "{new_claims} new claim{}",
            if new_claims == 1 { "" } else { "s" }
        ));
    }
    if updates > 0 {
        parts.push(format!(
            "{updates} update{}",
            if updates == 1 { "" } else { "s" }
        ));
    }
    if conflicts > 0 {
        parts.push(format!(
            "{conflicts} conflict{}",
            if conflicts == 1 { "" } else { "s" }
        ));
    }
    let counts = if parts.is_empty() {
        "no open proposals".to_owned()
    } else {
        parts.join(", ")
    };
    match intent {
        Some(intent) => format!("{intent}: {counts}"),
        None => format!("Dreamer run: {counts}"),
    }
}

pub(super) struct GroupDraft {
    pub(super) group_key: String,
    pub(super) run_id: String,
    pub(super) intent: Option<String>,
    pub(super) created_at: u64,
    pub(super) members: Vec<MemberDraft>,
    pub(super) pointer_rows: Vec<InboxPointerRow>,
}

pub(super) struct MemberDraft {
    pub(super) member: InboxGroupMember,
    pub(super) surfaced: bool,
    pub(super) cluster_key: String,
}

pub(super) fn finish_group_draft(draft: GroupDraft) -> Option<InboxGroup> {
    let new_claim_count = draft
        .members
        .iter()
        .filter(|row| row.member.verb_class == VERB_CLASS_NEW_CLAIM)
        .count();
    let update_count = draft
        .members
        .iter()
        .filter(|row| row.member.verb_class == VERB_CLASS_UPDATE)
        .count();
    let conflict_count = draft
        .members
        .iter()
        .filter(|row| row.member.verb_class == VERB_CLASS_CONFLICT)
        .count();
    let open_count = draft.members.len();
    let surfaced_drafts: Vec<MemberDraft> = draft
        .members
        .into_iter()
        .filter(|row| row.surfaced)
        .collect();
    if surfaced_drafts.is_empty() && draft.pointer_rows.is_empty() {
        return None;
    }

    let sub_clusters = if surfaced_drafts.len() >= INBOX_SUBCLUSTER_MIN_MEMBERS {
        let mut clusters: Vec<InboxSubCluster> = Vec::new();
        for row in &surfaced_drafts {
            match clusters
                .iter_mut()
                .find(|cluster| cluster.key == row.cluster_key)
            {
                Some(cluster) => cluster.member_claim_ids.push(row.member.claim_id.clone()),
                None => clusters.push(InboxSubCluster {
                    key: row.cluster_key.clone(),
                    member_claim_ids: vec![row.member.claim_id.clone()],
                }),
            }
        }
        clusters
    } else {
        Vec::new()
    };

    let surfaced: Vec<InboxGroupMember> =
        surfaced_drafts.into_iter().map(|row| row.member).collect();
    let held_member_count = open_count - surfaced.len();
    Some(InboxGroup {
        headline: group_headline(
            draft.intent.as_deref(),
            new_claim_count,
            update_count,
            conflict_count,
        ),
        group_key: draft.group_key,
        run_id: draft.run_id,
        created_at: draft.created_at,
        members: surfaced,
        held_member_count,
        pointer_rows: draft.pointer_rows,
        sub_clusters,
        new_claim_count,
        update_count,
        conflict_count,
    })
}

/// Resolves one named group through the RCPT-1 sidecars, complete (FIX
/// 9871): a canonical root door hydrates every pending row the root-group
/// index holds for that root, whichever run stamped it. A literal run id
/// remains a supported alias: it names its run's root group, read the same
/// way. Cross-run duplicate collapse is reconstructed only for the target
/// group through the semantic-hash sidecar, never by reopening the full
/// pending table.
pub(super) fn explicit_inbox_group(
    vault: &Vault,
    group_ref: &str,
    now: u64,
) -> Result<Option<InboxGroup>> {
    let mut runs = RunGroups::new(vault);
    let mut group_key = group_ref.to_owned();
    let mut pending = vault.store.pending_gate_consents_for_group_key(group_ref)?;
    if pending.is_empty() {
        let raw_run_pending = vault.store.pending_gate_consents_for_run(group_ref)?;
        if raw_run_pending.is_empty() {
            return Ok(None);
        }
        group_key = runs.identity(group_ref)?.0.clone();
        pending = vault.store.pending_gate_consents_for_group_key(&group_key)?;
        if pending.is_empty() {
            pending = raw_run_pending;
        }
    }
    root_group_card(
        vault,
        &mut runs,
        &group_key,
        pending,
        now,
        InboxReviewDial::ReviewEverything,
    )
}
