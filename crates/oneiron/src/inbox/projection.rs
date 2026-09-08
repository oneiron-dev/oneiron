//! Read-side inbox grouping projection, member classification, and dial surfacing.

use std::collections::HashMap;

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
use crate::receipt::{ReceiptView, gate_decision_receipt, hex_lower};
use crate::store::{GateDecisionRecord, PendingGateConsentRecord};

use super::model::{
    INBOX_PENDING_SCAN_LIMIT, INBOX_REASON_CHECKER_PREFIX, INBOX_RUN_BRIEF_INTENT_KEY,
    INBOX_SUBCLUSTER_MIN_MEMBERS, InboxCheckInException, InboxExceptionClass, InboxGroup,
    InboxGroupMember, InboxPointerRow, InboxQuery, InboxReviewDial, InboxSubCluster,
    VERB_CLASS_CONFLICT, VERB_CLASS_NEW_CLAIM, VERB_CLASS_UPDATE,
};

impl Vault {
    /// Projects open dreamer-run groups, surfaced under the persisted dial.
    pub fn inbox_groups(&self, query: InboxQuery) -> Result<Vec<InboxGroup>> {
        let dial = self.inbox_review_dial()?;
        inbox_groups_projection(self, query, dial, INBOX_PENDING_SCAN_LIMIT)
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
    normalized.confidence = 1.0;
    normalized.salience = None;
    normalized.evidence = None;
    normalized.source = None;
    normalized.stale = false;
    let encoded = crate::claim::encode_claim_body(&normalized)?;
    let mut hasher = Sha256::new();
    hasher.update(b"oneiron.inbox.claim_hash.v0");
    hasher.update(&encoded);
    Ok(hasher.finalize().into())
}

#[derive(Clone)]
struct OpenMember {
    pending: PendingGateConsentRecord,
    decision: GateDecisionRecord,
    body: ClaimBody,
    run_id: String,
}

fn open_dreamer_members(vault: &Vault, scan_limit: usize) -> Result<Vec<OpenMember>> {
    let pending = {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .pending_gate_consents_in_txn(&rtxn, scan_limit)?
    };
    open_dreamer_members_from_pending(vault, pending)
}

fn open_dreamer_members_for_run(vault: &Vault, run_id: &str) -> Result<Vec<OpenMember>> {
    open_dreamer_members_from_pending(vault, vault.store.pending_gate_consents_for_run(run_id)?)
}

fn open_dreamer_members_from_pending(
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
fn resolve_run_identity(vault: &Vault, run_id: &str) -> Result<(String, Option<String>)> {
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

fn classify_member(
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

    let verb_class = if member.body.predicate == PREDICATE_CONFLICT_OPEN {
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
fn member_surfaces(dial: InboxReviewDial, classes: &[InboxExceptionClass]) -> bool {
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

fn sub_cluster_key(body: &ClaimBody) -> String {
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

struct GroupDraft {
    group_key: String,
    run_id: String,
    intent: Option<String>,
    created_at: u64,
    members: Vec<MemberDraft>,
    pointer_rows: Vec<InboxPointerRow>,
}

struct MemberDraft {
    member: InboxGroupMember,
    surfaced: bool,
    cluster_key: String,
}

pub(super) fn inbox_groups_projection(
    vault: &Vault,
    query: InboxQuery,
    dial: InboxReviewDial,
    scan_limit: usize,
) -> Result<Vec<InboxGroup>> {
    if query.limit == 0 {
        return Ok(Vec::new());
    }

    let open_members = open_dreamer_members(vault, scan_limit)?;
    let mut drafts: Vec<GroupDraft> = Vec::new();
    let mut group_index_by_run: HashMap<String, usize> = HashMap::new();
    // Same-claim-hash collapse: earliest open row per content hash wins.
    let mut owner_by_hash: HashMap<[u8; 32], (usize, usize)> = HashMap::new();

    for member in open_members {
        let group_index = match group_index_by_run.get(&member.run_id) {
            Some(index) => *index,
            None => {
                let (group_key, intent) = resolve_run_identity(vault, &member.run_id)?;
                drafts.push(GroupDraft {
                    group_key,
                    run_id: member.run_id.clone(),
                    intent,
                    created_at: member.pending.created_at,
                    members: Vec::new(),
                    pointer_rows: Vec::new(),
                });
                group_index_by_run.insert(member.run_id.clone(), drafts.len() - 1);
                drafts.len() - 1
            }
        };

        let claim_id_hex = hex_lower(&member.pending.claim_id);
        let claim_hash = inbox_claim_hash(&member.body)?;
        let duplicate_owner = owner_by_hash
            .get(&claim_hash)
            .copied()
            .filter(|(owner_group, _)| *owner_group != group_index);
        if let Some((owner_group, owner_member)) = duplicate_owner {
            // The duplicate's own exception classes must survive the
            // collapse: the dial can never hide a manifest-critical or
            // checker-held row behind a pointer.
            let (duplicate_classes, _) = classify_member(vault, &member)?;
            let owner_key = drafts[owner_group].group_key.clone();
            let owner_row = &mut drafts[owner_group].members[owner_member];
            owner_row
                .member
                .duplicate_claim_ids
                .push(claim_id_hex.clone());
            if !duplicate_classes.is_empty() {
                owner_row.member.exception_classes.extend(duplicate_classes);
                owner_row.member.exception_classes.sort_unstable();
                owner_row.member.exception_classes.dedup();
                owner_row.surfaced = member_surfaces(dial, &owner_row.member.exception_classes);
            }
            let duplicate_of_claim_id = owner_row.member.claim_id.clone();
            drafts[group_index].pointer_rows.push(InboxPointerRow {
                claim_id: claim_id_hex,
                duplicate_of_claim_id,
                duplicate_of_group_key: owner_key,
            });
            continue;
        }

        let (classes, verb_class) = classify_member(vault, &member)?;
        let surfaced = member_surfaces(dial, &classes);
        let row = InboxGroupMember {
            claim_id: claim_id_hex,
            created_at: member.pending.created_at,
            age_secs: query.now.saturating_sub(member.pending.created_at),
            hold_reasons: member.pending.reason_codes.clone(),
            exception_classes: classes,
            verb_class: verb_class.to_owned(),
            duplicate_claim_ids: Vec::new(),
            receipt_view: ReceiptView::new(gate_decision_receipt(&member.decision)),
        };
        let member_index = drafts[group_index].members.len();
        // Same-group repeats keep the earliest entry so later runs still
        // collapse onto the first occurrence.
        owner_by_hash
            .entry(claim_hash)
            .or_insert((group_index, member_index));
        drafts[group_index].members.push(MemberDraft {
            member: row,
            surfaced,
            cluster_key: sub_cluster_key(&member.body),
        });
    }

    let mut groups = Vec::new();
    for draft in drafts {
        if let Some(group) = finish_group_draft(draft) {
            groups.push(group);
            if groups.len() == query.limit {
                break;
            }
        }
    }
    Ok(groups)
}

fn finish_group_draft(draft: GroupDraft) -> Option<InboxGroup> {
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

/// Resolves one named group through the RCPT-1 sidecars.  A canonical root
/// door first selects its earliest raw stamped run (matching the former scan
/// projection); a literal run id remains a supported alias.  Cross-run
/// duplicate collapse is reconstructed only for the target group through the
/// semantic-hash sidecar, never by reopening the full pending table.
pub(super) fn explicit_inbox_group(
    vault: &Vault,
    group_ref: &str,
    now: u64,
) -> Result<Option<InboxGroup>> {
    let group_pending = vault.store.pending_gate_consents_for_group_key(group_ref)?;
    let run_id = if let Some(first) = group_pending.first() {
        first
            .dreamer_run_id
            .clone()
            .ok_or(Error::CorruptedIndex("pending gate consent group index"))?
    } else {
        let raw_run_pending = vault.store.pending_gate_consents_for_run(group_ref)?;
        if raw_run_pending.is_empty() {
            return Ok(None);
        }
        group_ref.to_owned()
    };
    let members = open_dreamer_members_for_run(vault, &run_id)?;
    let Some(first_member) = members.first() else {
        return Ok(None);
    };
    let (group_key, intent) = resolve_run_identity(vault, &run_id)?;
    let mut draft = GroupDraft {
        group_key,
        run_id: run_id.clone(),
        intent,
        created_at: first_member.pending.created_at,
        members: Vec::new(),
        pointer_rows: Vec::new(),
    };
    let mut duplicate_members_by_hash: HashMap<[u8; 32], Vec<OpenMember>> = HashMap::new();

    for member in members {
        let claim_hash = inbox_claim_hash(&member.body)?;
        if let std::collections::hash_map::Entry::Vacant(entry) =
            duplicate_members_by_hash.entry(claim_hash)
        {
            let pending = vault
                .store
                .pending_gate_consents_for_semantic_claim_hash(&claim_hash)?;
            entry.insert(open_dreamer_members_from_pending(vault, pending)?);
        }
        let duplicate_members = duplicate_members_by_hash
            .get(&claim_hash)
            .expect("inserted above");
        // A same-id proposal rewrite can leave its old semantic-hash sidecar
        // behind. Browse already keeps the pending row visible; the indexed
        // door treats this current member as its own singleton rather than
        // calling the stale sidecar corruption.
        let duplicate_members = if duplicate_members.is_empty() {
            vec![member.clone()]
        } else {
            duplicate_members.clone()
        };
        let earliest = duplicate_members
            .first()
            .expect("the current member supplies the stale-sidecar fallback");
        let claim_id_hex = hex_lower(&member.pending.claim_id);
        if earliest.run_id != run_id {
            let (duplicate_of_group_key, _) = resolve_run_identity(vault, &earliest.run_id)?;
            draft.pointer_rows.push(InboxPointerRow {
                claim_id: claim_id_hex,
                duplicate_of_claim_id: hex_lower(&earliest.pending.claim_id),
                duplicate_of_group_key,
            });
            continue;
        }

        let (mut classes, verb_class) = classify_member(vault, &member)?;
        let mut duplicate_claim_ids = Vec::new();
        if earliest.pending.claim_id == member.pending.claim_id {
            for duplicate in duplicate_members
                .iter()
                .filter(|duplicate| duplicate.run_id != run_id)
            {
                let (duplicate_classes, _) = classify_member(vault, duplicate)?;
                duplicate_claim_ids.push(hex_lower(&duplicate.pending.claim_id));
                classes.extend(duplicate_classes);
            }
            classes.sort_unstable();
            classes.dedup();
        }
        let surfaced = member_surfaces(InboxReviewDial::ReviewEverything, &classes);
        draft.members.push(MemberDraft {
            member: InboxGroupMember {
                claim_id: claim_id_hex,
                created_at: member.pending.created_at,
                age_secs: now.saturating_sub(member.pending.created_at),
                hold_reasons: member.pending.reason_codes.clone(),
                exception_classes: classes,
                verb_class: verb_class.to_owned(),
                duplicate_claim_ids,
                receipt_view: ReceiptView::new(gate_decision_receipt(&member.decision)),
            },
            surfaced,
            cluster_key: sub_cluster_key(&member.body),
        });
    }
    Ok(finish_group_draft(draft))
}
