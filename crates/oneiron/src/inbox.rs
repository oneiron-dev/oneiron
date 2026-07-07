//! OF-234 / ONE-1545: Dreamer-run inbox grouping + auto-approve exception queue.
//!
//! The inbox is an EXCEPTION QUEUE, never a review queue: gated Dreamer
//! proposals are grouped by the run that produced them (group key = the
//! run-tree ROOT id, OF-193), and only exception rows surface by default.
//! Which pending items exist at all stays gate law
//! (`PolicyApprovalCeiling{Auto,Proposed}`, gate.rs); this module only
//! projects, classifies, and resolves what already landed pending:
//!
//! * grouping is a projection over the pending-consent tray — nothing here
//!   mints grouping state;
//! * bulk verbs (accept-all / reject-all / review-each) are B2 RS6 bundle
//!   consent at run × verb-class: per-item receipts plus ONE bundle receipt
//!   carrying the run id, whose RS3 door reopens the group;
//! * gap-decay stays PER-ITEM (`Vault::let_go_pending_ask`) — a lapsing
//!   member never drops its siblings, and the group closes only when every
//!   member is resolved;
//! * cross-run same-claim-hash duplicates collapse into the EARLIEST open
//!   group; the later group shows a pointer row;
//! * the settings dial (approve-all ↔ exceptions-only ↔ review-everything)
//!   adjusts SURFACING only. Manifest-critical rows surface under every dial
//!   position — the dial cannot waive them. Auto-redemption of non-surfaced
//!   rows awaits the ONE-1183-D2 auto_checker knob; until it lands, hidden
//!   rows stay consentable (bundle verbs, tray) and gap-decay per item, so
//!   receipts remain the always-on audit trail.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    PREDICATE_CONFLICT_OPEN,
};
use crate::dreamer_runner::{DREAMER_RUNNER_JOB_KIND, decode_dreamer_job_payload};
use crate::error::{Error, Result};
use crate::gate::GateReasonCode;
use crate::job_queue::{JobQueue, job_record_order};
use crate::receipt::{ReceiptRecord, ReceiptView, gate_decision_receipt, hex_lower};
use crate::store::{
    GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord, PendingGateConsentRecord,
};
use crate::types::{ENTITY_TYPE_CLAIM, EntityId, TimeRange, bytes_to_hex_lower};

/// Upper bound on pending-consent rows visited per projection pass.
pub const INBOX_PENDING_SCAN_LIMIT: usize = 10_000;

/// Upper bound on decision-ledger rows visited when reopening a group.
const INBOX_REOPEN_DECISION_SCAN_LIMIT: usize = 10_000;

/// Sub-clusters by entity/theme are emitted only when a run surfaces at
/// least this many members ("when the run emits many items").
pub const INBOX_SUBCLUSTER_MIN_MEMBERS: usize = 6;

/// Reason-code prefix stamped by the ONE-1183-D2 auto_checker when an
/// Auto-eligible write is held on a low-confidence/hedged verdict. The gate
/// does not stamp these yet; the classifier is ready for the knob.
pub const INBOX_REASON_CHECKER_PREFIX: &str = "gate.pending.checker";

/// RS3 door prefix carried by inbox bundle receipts.
pub const INBOX_GROUP_DOOR_PREFIX: &str = "dreamer_run:";

const INBOX_BUNDLE_REF_PREFIX: &str = "bundle:";
const INBOX_REASON_BUNDLE_ACCEPT: &str = "gate.consent.bundle_accept";
const INBOX_REASON_BUNDLE_REJECT: &str = "gate.consent.bundle_reject";
const INBOX_BUNDLE_ACTOR_CLASS: &str = "owner";
const INBOX_BUNDLE_CONTENT_KIND: &str = "inbox_bundle";
const INBOX_REVIEW_DIAL_KEY: &[u8] = b"settings:inbox:v1:review_dial";
const INBOX_RUN_BRIEF_INTENT_KEY: &str = "intent";

const VERB_CLASS_NEW_CLAIM: &str = "new_claim";
const VERB_CLASS_UPDATE: &str = "update";
const VERB_CLASS_CONFLICT: &str = "conflict";

/// OF-234 settings dial over inbox surfacing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InboxReviewDial {
    /// Everything rides auto except manifest-critical rows, which the dial
    /// can never waive.
    ApproveAll,
    /// Default: only exception rows surface (checker hedge, manifest
    /// critical, supersede-of-user_stated, conflicts).
    #[default]
    ExceptionsOnly,
    /// Every open member surfaces.
    ReviewEverything,
}

impl InboxReviewDial {
    /// Returns the stable on-disk token for this dial position.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApproveAll => "approve_all",
            Self::ExceptionsOnly => "exceptions_only",
            Self::ReviewEverything => "review_everything",
        }
    }

    /// Parses a stable dial token.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "approve_all" => Some(Self::ApproveAll),
            "exceptions_only" => Some(Self::ExceptionsOnly),
            "review_everything" => Some(Self::ReviewEverything),
            _ => None,
        }
    }
}

/// Why a pending member surfaces in the exception queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InboxExceptionClass {
    /// The auto_checker held this write on a low-confidence/hedged verdict.
    CheckerHedge,
    /// The predicate class is manifest-critical (most-restrictive-wins).
    ManifestCritical,
    /// Approving would supersede user_stated truth.
    SupersedesUserStated,
    /// The proposal is an OF-060 conflict row (`core.conflict.open`).
    Conflict,
}

/// B2 RS6 bulk verbs over one dreamer-run group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InboxBulkVerb {
    AcceptAll,
    RejectAll,
    ReviewEach,
}

impl InboxBulkVerb {
    /// Returns the stable verb token used in bundle reason codes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AcceptAll => "accept_all",
            Self::RejectAll => "reject_all",
            Self::ReviewEach => "review_each",
        }
    }

    const fn bundle_outcome(self) -> &'static str {
        match self {
            Self::AcceptAll => "bundle_accepted",
            Self::RejectAll => "bundle_rejected",
            Self::ReviewEach => "bundle_review_each",
        }
    }
}

/// Query for the inbox group projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxQuery {
    pub now: u64,
    /// Maximum number of groups returned.
    pub limit: usize,
}

impl InboxQuery {
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            now: crate::unix_seconds_now(),
            limit,
        }
    }

    #[must_use]
    pub const fn at(now: u64, limit: usize) -> Self {
        Self { now, limit }
    }
}

/// One dreamer-run group card over open pending proposals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxGroup {
    /// Group key: the run-tree ROOT job id (OF-193) when the run resolves in
    /// the job queue, otherwise the provenance-stamped run id.
    pub group_key: String,
    /// The provenance-stamped dreamer run id.
    pub run_id: String,
    /// Dreamer-authored headline from the run brief's stated intent plus the
    /// run's item counts.
    pub headline: String,
    /// Earliest open member's created_at.
    pub created_at: u64,
    /// Members surfaced under the active dial.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<InboxGroupMember>,
    /// Open members the dial is currently holding out of the queue.
    pub held_member_count: usize,
    /// Pointer rows for members collapsed into an earlier group.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pointer_rows: Vec<InboxPointerRow>,
    /// Entity/theme sub-clusters, present only for many-item runs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sub_clusters: Vec<InboxSubCluster>,
    pub new_claim_count: usize,
    pub update_count: usize,
    pub conflict_count: usize,
}

/// One open proposal inside a group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxGroupMember {
    pub claim_id: String,
    pub created_at: u64,
    pub age_secs: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hold_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exception_classes: Vec<InboxExceptionClass>,
    /// `new_claim` | `update` | `conflict` — the bundle-consent verb class.
    pub verb_class: String,
    /// Same-claim-hash duplicates from later runs collapsed onto this row.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub duplicate_claim_ids: Vec<String>,
    pub receipt_view: ReceiptView,
}

/// Pointer row shown by the LATER group when a duplicate collapsed into an
/// earlier one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxPointerRow {
    /// The later run's duplicate claim.
    pub claim_id: String,
    /// The member row it collapsed onto.
    pub duplicate_of_claim_id: String,
    /// The earlier open group holding that row.
    pub duplicate_of_group_key: String,
}

/// Entity/theme sub-cluster over surfaced members.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxSubCluster {
    /// `entity:<subject id>` or `theme:<predicate layer>`.
    pub key: String,
    pub member_claim_ids: Vec<String>,
}

/// Outcome of one bulk verb over a group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxBundleResolution {
    pub group_key: String,
    pub verb: InboxBulkVerb,
    /// Bundle reference carried by every receipt this resolution emitted.
    pub bundle_ref: String,
    /// The ONE bundle receipt carrying the run id (RS3 door).
    pub bundle_receipt: ReceiptRecord,
    /// Per-item resolution receipts (empty for review-each).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub item_receipts: Vec<ReceiptRecord>,
    /// Claim ids expanded for per-item review (review-each only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub review_items: Vec<String>,
}

/// RS3 door result: the group behind a bundle receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxGroupReopen {
    pub group_key: String,
    /// Still-open remainder of the group, surfaced dial-independently.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_group: Option<InboxGroup>,
    /// Bundle + per-item receipts emitted for this group's bundles.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolution_receipts: Vec<ReceiptRecord>,
}

impl Vault {
    /// Reads the persisted inbox review dial (default: exceptions-only).
    pub fn inbox_review_dial(&self) -> Result<InboxReviewDial> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.vault_meta.get(&rtxn, INBOX_REVIEW_DIAL_KEY)? else {
            return Ok(InboxReviewDial::default());
        };
        let token =
            std::str::from_utf8(raw).map_err(|_| Error::CorruptedIndex("inbox review dial"))?;
        InboxReviewDial::parse(token).ok_or(Error::CorruptedIndex("inbox review dial"))
    }

    /// Persists the inbox review dial position.
    pub fn set_inbox_review_dial(&self, dial: InboxReviewDial) -> Result<()> {
        self.with_write_txn(|wtxn| {
            self.store
                .vault_meta
                .put(wtxn, INBOX_REVIEW_DIAL_KEY, dial.as_str().as_bytes())?;
            Ok(())
        })
    }

    /// Projects open dreamer-run groups, surfaced under the persisted dial.
    pub fn inbox_groups(&self, query: InboxQuery) -> Result<Vec<InboxGroup>> {
        let dial = self.inbox_review_dial()?;
        inbox_groups_projection(self, query, dial)
    }

    /// Applies one bulk verb to a group at the current time, covering every
    /// verb class.
    pub fn resolve_inbox_group(
        &self,
        group_key: &str,
        verb: InboxBulkVerb,
    ) -> Result<InboxBundleResolution> {
        self.resolve_inbox_group_at(group_key, verb, None, crate::unix_seconds_now())
    }

    /// Applies one bulk verb to a group: B2 RS6 bundle consent at
    /// run × verb-class. Accept/reject resolve every targeted member — and
    /// the cross-run duplicates collapsed onto it, each verified against its
    /// own consent binding — with per-item receipts plus ONE bundle receipt
    /// carrying the run id; review-each expands the members without mutating
    /// them. `verb_class` narrows the bundle to `new_claim` / `update` /
    /// `conflict` rows.
    pub fn resolve_inbox_group_at(
        &self,
        group_key: &str,
        verb: InboxBulkVerb,
        verb_class: Option<&str>,
        now: u64,
    ) -> Result<InboxBundleResolution> {
        let groups = inbox_groups_projection(
            self,
            InboxQuery::at(now, INBOX_PENDING_SCAN_LIMIT),
            InboxReviewDial::ReviewEverything,
        )?;
        let group = groups
            .into_iter()
            .find(|group| group.group_key == group_key || group.run_id == group_key)
            .ok_or(Error::EntityNotFound)?;

        let mut targets = Vec::new();
        for member in &group.members {
            if let Some(verb_class) = verb_class
                && member.verb_class != verb_class
            {
                continue;
            }
            targets.push(member.claim_id.clone());
            targets.extend(member.duplicate_claim_ids.iter().cloned());
        }
        if targets.is_empty() {
            return Err(Error::EntityNotFound);
        }

        let bundle_ref = bundle_ref_for_group(&group.group_key);
        let (bundle_record, item_records) = self.with_write_txn(|wtxn| {
            let mut item_records = Vec::new();
            let mut basis: Vec<GateDecisionRecord> = Vec::new();
            for claim_id in &targets {
                let id = EntityId::from_hex(claim_id)
                    .map_err(|_| Error::CorruptedIndex("pending gate consent"))?;
                match verb {
                    InboxBulkVerb::AcceptAll => {
                        if let Some(record) =
                            accept_member_in_txn(self, wtxn, &id, &bundle_ref, now)?
                        {
                            item_records.push(record);
                        }
                    }
                    InboxBulkVerb::RejectAll => {
                        if let Some(record) = self.store.close_pending_gate_consent_in_txn(
                            wtxn,
                            &id,
                            now,
                            "rejected",
                            vec![INBOX_REASON_BUNDLE_REJECT.to_owned()],
                            Some(bundle_ref.clone()),
                        )? {
                            item_records.push(record);
                        }
                    }
                    InboxBulkVerb::ReviewEach => {
                        // No mutation: the bundle receipt still needs the
                        // policy floor the members were gated under.
                        if let Some(pending) = self.store.pending_gate_consent_in_txn(wtxn, &id)?
                            && let Some(original) =
                                self.store.gate_decision_in_txn(wtxn, pending.decision_id)?
                        {
                            basis.push(original);
                        }
                    }
                }
            }
            let bundle_basis = if item_records.is_empty() {
                &basis
            } else {
                &item_records
            };
            let bundle_record = append_bundle_decision_in_txn(
                self,
                wtxn,
                &bundle_ref,
                verb,
                verb_class,
                bundle_basis,
                now,
            )?;
            Ok((bundle_record, item_records))
        })?;

        let review_items = if verb == InboxBulkVerb::ReviewEach {
            targets
        } else {
            Vec::new()
        };
        Ok(InboxBundleResolution {
            group_key: group.group_key,
            verb,
            bundle_ref,
            bundle_receipt: gate_decision_receipt(&bundle_record),
            item_receipts: item_records.iter().map(gate_decision_receipt).collect(),
            review_items,
        })
    }

    /// RS3 door: reopens the group behind a bundle receipt reference
    /// (`bundle:dreamer_run:<key>` or `dreamer_run:<key>`), returning the
    /// still-open remainder plus every receipt its bundles emitted.
    pub fn reopen_inbox_group(&self, door_ref: &str) -> Result<InboxGroupReopen> {
        self.reopen_inbox_group_at(door_ref, crate::unix_seconds_now())
    }

    /// Testable variant of [`Vault::reopen_inbox_group`] with an explicit
    /// event time.
    pub fn reopen_inbox_group_at(&self, door_ref: &str, now: u64) -> Result<InboxGroupReopen> {
        let inner = door_ref
            .strip_prefix(INBOX_BUNDLE_REF_PREFIX)
            .unwrap_or(door_ref);
        let group_key = inner.strip_prefix(INBOX_GROUP_DOOR_PREFIX).ok_or_else(|| {
            Error::InvalidConfig("inbox door ref must reference a dreamer run".into())
        })?;
        let bundle_ref = bundle_ref_for_group(group_key);

        let open_group = inbox_groups_projection(
            self,
            InboxQuery::at(now, INBOX_PENDING_SCAN_LIMIT),
            InboxReviewDial::ReviewEverything,
        )?
        .into_iter()
        .find(|group| group.group_key == group_key || group.run_id == group_key);

        let resolution_receipts = self
            .store
            .gate_decisions(INBOX_REOPEN_DECISION_SCAN_LIMIT)?
            .iter()
            .filter(|record| record.grant_ref.as_deref() == Some(bundle_ref.as_str()))
            .map(gate_decision_receipt)
            .collect();

        Ok(InboxGroupReopen {
            group_key: group_key.to_owned(),
            open_group,
            resolution_receipts,
        })
    }
}

fn bundle_ref_for_group(group_key: &str) -> String {
    format!("{INBOX_BUNDLE_REF_PREFIX}{INBOX_GROUP_DOOR_PREFIX}{group_key}")
}

/// Semantic claim hash for cross-run duplicate collapse. The consent
/// binding (`diff_handle`) hashes the exact stored body, whose evidence
/// carries the writing actor and run provenance — so re-proposals of the
/// same fact by a later run would never match it. This hash keeps the claim
/// identity (predicate, subject, value, world, scope, validity) and drops
/// the per-write stamps.
fn inbox_claim_hash(body: &ClaimBody) -> Result<Vec<u8>> {
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
    Ok(hasher.finalize().to_vec())
}

struct OpenMember {
    pending: PendingGateConsentRecord,
    decision: GateDecisionRecord,
    body: ClaimBody,
    run_id: String,
}

fn open_dreamer_members(vault: &Vault) -> Result<Vec<OpenMember>> {
    let mut rows = Vec::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        for pending in vault
            .store
            .pending_gate_consents_in_txn(&rtxn, INBOX_PENDING_SCAN_LIMIT)?
        {
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
/// ROOT job id plus the Dreamer-authored intent from the root's run brief.
/// Runs without queue rows keep the stamped run id as their key.
fn resolve_run_identity(vault: &Vault, run_id: &str) -> Result<(String, Option<String>)> {
    let queue = JobQueue::new(vault);
    let mut records = queue.list_run(run_id)?;
    records.sort_by(job_record_order);
    for record in &records {
        let payload = if record.kind == DREAMER_RUNNER_JOB_KIND {
            decode_dreamer_job_payload(&record.payload).ok()
        } else {
            None
        };
        let is_root = payload
            .as_ref()
            .is_none_or(|payload| payload.parent_job.is_none());
        if !is_root {
            continue;
        }
        let intent = payload.as_ref().and_then(|payload| {
            let rmpv::Value::Map(entries) = &payload.input else {
                return None;
            };
            entries.iter().find_map(|(key, value)| {
                if key.as_str() != Some(INBOX_RUN_BRIEF_INTENT_KEY) {
                    return None;
                }
                let intent = value.as_str()?.trim();
                (!intent.is_empty()).then(|| intent.to_owned())
            })
        });
        return Ok((bytes_to_hex_lower(record.id.as_bytes()), intent));
    }
    Ok((run_id.to_owned(), None))
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
        if existing.predicate != member.body.predicate
            || existing.lifecycle != ClaimLifecycleStatus::Active
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

fn member_surfaces(dial: InboxReviewDial, classes: &[InboxExceptionClass]) -> bool {
    match dial {
        InboxReviewDial::ReviewEverything => true,
        InboxReviewDial::ExceptionsOnly => !classes.is_empty(),
        InboxReviewDial::ApproveAll => classes.contains(&InboxExceptionClass::ManifestCritical),
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

fn inbox_groups_projection(
    vault: &Vault,
    query: InboxQuery,
    dial: InboxReviewDial,
) -> Result<Vec<InboxGroup>> {
    if query.limit == 0 {
        return Ok(Vec::new());
    }

    let open_members = open_dreamer_members(vault)?;
    let mut drafts: Vec<GroupDraft> = Vec::new();
    // Same-claim-hash collapse: earliest open row per content hash wins.
    let mut seen_hashes: Vec<(Vec<u8>, usize, usize)> = Vec::new();

    for member in open_members {
        let group_index = match drafts
            .iter()
            .position(|draft| draft.run_id == member.run_id)
        {
            Some(index) => index,
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
                drafts.len() - 1
            }
        };

        let claim_id_hex = hex_lower(&member.pending.claim_id);
        let claim_hash = inbox_claim_hash(&member.body)?;
        let duplicate_owner = seen_hashes
            .iter()
            .find_map(|(hash, owner_group, owner_member)| {
                (*hash == claim_hash && *owner_group != group_index)
                    .then_some((*owner_group, *owner_member))
            });
        if let Some((owner_group, owner_member)) = duplicate_owner {
            let owner_key = drafts[owner_group].group_key.clone();
            let owner_row = &mut drafts[owner_group].members[owner_member];
            owner_row
                .member
                .duplicate_claim_ids
                .push(claim_id_hex.clone());
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
        seen_hashes.push((claim_hash, group_index, member_index));
        drafts[group_index].members.push(MemberDraft {
            member: row,
            surfaced,
            cluster_key: sub_cluster_key(&member.body),
        });
    }

    let mut groups = Vec::new();
    for draft in drafts {
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
            continue;
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
        groups.push(InboxGroup {
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
        });
        if groups.len() == query.limit {
            break;
        }
    }
    Ok(groups)
}

/// Redeems bundle consent on one member: verifies the content-addressed
/// binding (stale on content or policy-floor drift), flips the stored claim
/// to Approved through the one claim door (`apply_ops`), and emits the
/// per-item resolution receipt.
fn accept_member_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    bundle_ref: &str,
    now: u64,
) -> Result<Option<GateDecisionRecord>> {
    let Some(pending) = vault.store.pending_gate_consent_in_txn(wtxn, id)? else {
        return Ok(None);
    };
    let Some(original) = vault
        .store
        .gate_decision_in_txn(wtxn, pending.decision_id)?
    else {
        return Err(Error::CorruptedIndex("pending gate consent"));
    };
    let Some(raw) = vault.store.entities.get(wtxn, id.as_bytes())? else {
        return Err(Error::CorruptedIndex("pending gate consent"));
    };
    let header = EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return Err(Error::InvalidClaimBody("entity is not a type-0 CLAIM"));
    }
    let mut body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;

    let (diff_handle, read_frontier_hash) =
        crate::gate::claim_consent_binding_parts(&vault.store, wtxn, &body)?;
    if diff_handle != pending.diff_handle || read_frontier_hash != pending.read_frontier_hash {
        return Err(Error::GateConsentStale { claim_id: *id });
    }

    if body.approval != ClaimApprovalStatus::Approved {
        body.approval = ClaimApprovalStatus::Approved;
        let data = crate::claim::encode_claim_body(&body)?;
        apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            wtxn,
            vec![BatchOp::Put {
                id: *id,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: TimeRange {
                    start: header.occurred_start,
                    end: header.occurred_end,
                },
                learned_at: header.learned_at,
                data,
                allow_maintenance: false,
                allow_reserved_predicate: false,
            }],
            vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
    }

    // The gated rewrite may already have redeemed and removed the tray row;
    // the delete is idempotent either way.
    vault.store.delete_pending_gate_consent_in_txn(wtxn, id)?;
    let record = GateDecisionRecord {
        version: GATE_DECISION_LEDGER_VERSION,
        decision_id: GateDecisionId::now(),
        created_at: now,
        outcome: "approved".to_owned(),
        reason_codes: vec![INBOX_REASON_BUNDLE_ACCEPT.to_owned()],
        receipt_reasons: Vec::new(),
        system_notices: Vec::new(),
        actor_class: original.actor_class,
        actor_ref: original.actor_ref,
        content_kind: original.content_kind,
        policy_manifest_version: original.policy_manifest_version,
        claim_id: Some(pending.claim_id),
        grant_ref: Some(bundle_ref.to_owned()),
        diff_handle: pending.diff_handle,
        read_frontier_hash: pending.read_frontier_hash,
    };
    vault.store.append_gate_decision_in_txn(wtxn, &record)?;
    Ok(Some(record))
}

fn append_bundle_decision_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    bundle_ref: &str,
    verb: InboxBulkVerb,
    verb_class: Option<&str>,
    basis: &[GateDecisionRecord],
    now: u64,
) -> Result<GateDecisionRecord> {
    let mut hasher = Sha256::new();
    hasher.update(b"oneiron.inbox.bundle.v0");
    hasher.update(bundle_ref.as_bytes());
    hasher.update(verb.as_str().as_bytes());
    for record in basis {
        if let Some(claim_id) = record.claim_id {
            hasher.update(claim_id);
        }
    }

    // The decision ledger pins reason codes to the `gate.` namespace.
    let mut reason_codes = vec![format!("gate.consent.bundle.{}", verb.as_str())];
    if let Some(verb_class) = verb_class {
        reason_codes.push(format!("gate.consent.bundle.verb_class.{verb_class}"));
    }

    let record = GateDecisionRecord {
        version: GATE_DECISION_LEDGER_VERSION,
        decision_id: GateDecisionId::now(),
        created_at: now,
        outcome: verb.bundle_outcome().to_owned(),
        reason_codes,
        receipt_reasons: Vec::new(),
        system_notices: Vec::new(),
        actor_class: INBOX_BUNDLE_ACTOR_CLASS.to_owned(),
        actor_ref: None,
        content_kind: INBOX_BUNDLE_CONTENT_KIND.to_owned(),
        policy_manifest_version: basis.first().map_or_else(
            || "unversioned".to_owned(),
            |record| record.policy_manifest_version.clone(),
        ),
        claim_id: None,
        grant_ref: Some(bundle_ref.to_owned()),
        diff_handle: hasher.finalize().to_vec(),
        read_frontier_hash: basis
            .first()
            .map_or([0; 32], |record| record.read_frontier_hash),
    };
    vault.store.append_gate_decision_in_txn(wtxn, &record)?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use rmpv::Value;

    use super::*;
    use crate::dreamer_runner::{DreamerRunnerStore, EnqueueDreamerJob, EnqueueDreamerJobOutcome};
    use crate::job_queue::JobId;
    use crate::receipt::ReceiptQuery;
    use crate::store::GateDecisionId;
    use crate::types::{
        ENTITY_TYPE_PERSON, EdgeActorClass, VaultConfig, WriteActor, WriteEnvelope, WriteProvenance,
    };

    const REASON_CEILING: &str = "gate.pending.actor_ceiling";
    const REASON_CRITICAL: &str = "gate.pending.criticality_floor";
    const REASON_CHECKER: &str = "gate.pending.checker_low_confidence";

    fn temp_vault() -> (tempfile::TempDir, Vault) {
        crate::test_util::open_test_vault_with(VaultConfig::default())
    }

    fn entity(seed: u8) -> EntityId {
        EntityId::from_bytes([seed; 16]).expect("entity id")
    }

    fn time(ts: u64) -> TimeRange {
        TimeRange { start: ts, end: ts }
    }

    fn dreamer_envelope(actor: EntityId, run_id: &str) -> WriteEnvelope {
        WriteEnvelope::new(
            WriteActor::new(actor, EdgeActorClass::Agent),
            ClaimSource::Generated,
            WriteProvenance::new(Value::Map(vec![
                (Value::from("runner"), Value::from(DREAMER_RUNNER_JOB_KIND)),
                (Value::from("run_id"), Value::from(run_id)),
            ]))
            .expect("provenance"),
            ClaimApprovalStatus::Proposed,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "fixture keeps each proposal's identity explicit at call sites"
    )]
    fn write_dreamer_proposal(
        vault: &Vault,
        claim_id: EntityId,
        actor: EntityId,
        subject: EntityId,
        predicate: &str,
        value: &str,
        run_id: &str,
        created_at: u64,
        reasons: &[&str],
    ) -> Result<()> {
        vault.put_entity(&actor, ENTITY_TYPE_PERSON, time(1), 1, b"dreamer actor")?;
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, time(1), 1, b"subject")?;
        let envelope = dreamer_envelope(actor, run_id);
        let candidate = crate::types::ClaimCandidate::new(
            predicate,
            ClaimSubject::Entity(subject),
            Value::from(value),
            0.9,
        );
        vault
            .batch()
            .claim_candidate(
                &claim_id,
                candidate,
                &envelope,
                time(created_at),
                created_at,
            )
            .commit()?;
        add_pending_row(vault, claim_id, actor, created_at, reasons, run_id)
    }

    fn add_pending_row(
        vault: &Vault,
        claim_id: EntityId,
        actor: EntityId,
        created_at: u64,
        reasons: &[&str],
        run_id: &str,
    ) -> Result<()> {
        let body = vault.get_claim(&claim_id)?.expect("proposal stored");
        let (diff_handle, read_frontier_hash) = {
            let rtxn = vault.store.env.read_txn()?;
            crate::gate::claim_consent_binding_parts(&vault.store, &rtxn, &body)?
        };
        let reason_codes: Vec<String> = reasons.iter().map(|code| (*code).to_owned()).collect();
        let decision = GateDecisionRecord {
            version: 0,
            decision_id: GateDecisionId::now(),
            created_at,
            outcome: "pending".to_owned(),
            reason_codes: reason_codes.clone(),
            receipt_reasons: Vec::new(),
            system_notices: Vec::new(),
            actor_class: "agent".to_owned(),
            actor_ref: Some(actor.to_hex()),
            content_kind: "claim".to_owned(),
            policy_manifest_version: "v0".to_owned(),
            claim_id: Some(*claim_id.as_bytes()),
            grant_ref: None,
            diff_handle: diff_handle.clone(),
            read_frontier_hash,
        };
        let pending = PendingGateConsentRecord {
            version: 0,
            claim_id: *claim_id.as_bytes(),
            decision_id: decision.decision_id,
            created_at,
            diff_handle,
            read_frontier_hash,
            reason_codes,
            dreamer_run_id: Some(run_id.to_owned()),
        };
        vault.with_write_txn(|wtxn| {
            vault.store.append_gate_decision_in_txn(wtxn, &decision)?;
            vault.store.put_pending_gate_consent_in_txn(wtxn, &pending)
        })
    }

    fn enqueue_dreamer_job(
        vault: &Vault,
        job_type: &str,
        parent_job: Option<JobId>,
        input: Value,
        run_id: &str,
        now: u64,
    ) -> Result<JobId> {
        let runner = DreamerRunnerStore::new(vault);
        match runner.enqueue(EnqueueDreamerJob {
            job_type: job_type.to_owned(),
            input,
            parent_job,
            dedupe_key: None,
            run_id: Some(run_id.to_owned()),
            now,
        })? {
            EnqueueDreamerJobOutcome::Enqueued(status)
            | EnqueueDreamerJobOutcome::Existing(status) => Ok(status.job.id),
        }
    }

    #[test]
    fn review_dial_defaults_to_exceptions_only_and_round_trips() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        assert_eq!(vault.inbox_review_dial()?, InboxReviewDial::ExceptionsOnly);

        vault.set_inbox_review_dial(InboxReviewDial::ApproveAll)?;
        assert_eq!(vault.inbox_review_dial()?, InboxReviewDial::ApproveAll);

        vault.set_inbox_review_dial(InboxReviewDial::ReviewEverything)?;
        assert_eq!(
            vault.inbox_review_dial()?,
            InboxReviewDial::ReviewEverything
        );

        assert!(matches!(
            vault.reopen_inbox_group("claim:not-a-run"),
            Err(Error::InvalidConfig(_))
        ));
        Ok(())
    }

    #[test]
    fn inbox_group_key_is_the_run_tree_root_id() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let run_id = "run-antevon-week";
        let root = enqueue_dreamer_job(
            &vault,
            "orchestrator",
            None,
            Value::Map(vec![(
                Value::from("intent"),
                Value::from("Your Antevon week"),
            )]),
            run_id,
            10,
        )?;
        let branch = enqueue_dreamer_job(
            &vault,
            "entity-sweep",
            Some(root),
            Value::from("branch input"),
            run_id,
            20,
        )?;

        write_dreamer_proposal(
            &vault,
            entity(0xA1),
            entity(0xB1),
            entity(0xC1),
            "profile.diet",
            "vegan",
            run_id,
            30,
            &[REASON_CEILING],
        )?;
        write_dreamer_proposal(
            &vault,
            entity(0xA2),
            entity(0xB2),
            entity(0xC2),
            "profile.hobby",
            "chess",
            run_id,
            40,
            &[REASON_CEILING],
        )?;

        vault.set_inbox_review_dial(InboxReviewDial::ReviewEverything)?;
        let groups = vault.inbox_groups(InboxQuery::at(100, 10))?;
        assert_eq!(groups.len(), 1);
        let group = &groups[0];
        assert_eq!(group.group_key, bytes_to_hex_lower(root.as_bytes()));
        assert_ne!(group.group_key, bytes_to_hex_lower(branch.as_bytes()));
        assert_eq!(group.run_id, run_id);
        assert_eq!(group.headline, "Your Antevon week: 2 new claims");
        assert_eq!(group.created_at, 30);
        assert_eq!(group.members.len(), 2);
        assert_eq!(group.members[0].claim_id, entity(0xA1).to_hex());
        assert_eq!(group.members[0].age_secs, 70);
        assert_eq!(group.members[0].verb_class, "new_claim");
        assert_eq!(group.held_member_count, 0);
        assert!(group.sub_clusters.is_empty());
        Ok(())
    }

    #[test]
    fn bundle_receipt_reopens_group_after_accept_all() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let run_id = "run-b";
        let first = entity(0xA1);
        let second = entity(0xA2);
        write_dreamer_proposal(
            &vault,
            first,
            entity(0xB1),
            entity(0xC1),
            "profile.diet",
            "vegan",
            run_id,
            10,
            &[REASON_CEILING],
        )?;
        write_dreamer_proposal(
            &vault,
            second,
            entity(0xB2),
            entity(0xC2),
            "profile.hobby",
            "chess",
            run_id,
            20,
            &[REASON_CEILING],
        )?;

        assert!(matches!(
            vault.resolve_inbox_group_at("run-missing", InboxBulkVerb::AcceptAll, None, 30),
            Err(Error::EntityNotFound)
        ));

        let review = vault.resolve_inbox_group_at(run_id, InboxBulkVerb::ReviewEach, None, 40)?;
        assert_eq!(review.bundle_receipt.outcome, "bundle_review_each");
        assert_eq!(review.review_items.len(), 2);
        assert!(review.item_receipts.is_empty());
        assert_eq!(vault.store.pending_gate_consents(10)?.len(), 2);

        let resolution =
            vault.resolve_inbox_group_at(run_id, InboxBulkVerb::AcceptAll, None, 50)?;
        assert_eq!(resolution.group_key, run_id);
        assert_eq!(resolution.bundle_ref, "bundle:dreamer_run:run-b");
        assert_eq!(resolution.bundle_receipt.outcome, "bundle_accepted");
        assert_eq!(
            resolution.bundle_receipt.trigger_ref.as_deref(),
            Some("dreamer_run:run-b")
        );
        assert_eq!(
            resolution
                .bundle_receipt
                .fields
                .get("bundle_ref")
                .map(String::as_str),
            Some("bundle:dreamer_run:run-b")
        );
        assert_eq!(resolution.item_receipts.len(), 2);
        for receipt in &resolution.item_receipts {
            assert_eq!(receipt.outcome, "approved");
            assert!(
                receipt
                    .policy_trace
                    .contains(&"gate.consent.bundle_accept".to_owned())
            );
        }

        assert_eq!(
            vault.get_claim(&first)?.expect("accepted claim").approval,
            ClaimApprovalStatus::Approved
        );
        assert_eq!(
            vault.get_claim(&second)?.expect("accepted claim").approval,
            ClaimApprovalStatus::Approved
        );
        assert!(vault.store.pending_gate_consents(10)?.is_empty());
        vault.set_inbox_review_dial(InboxReviewDial::ReviewEverything)?;
        assert!(vault.inbox_groups(InboxQuery::at(60, 10))?.is_empty());

        let approved = vault.receipts(ReceiptQuery::new(10).with_outcome("approved"))?;
        assert_eq!(approved.len(), 2);

        let reopened = vault.reopen_inbox_group_at("bundle:dreamer_run:run-b", 70)?;
        assert_eq!(reopened.group_key, run_id);
        assert!(reopened.open_group.is_none());
        let outcomes: Vec<&str> = reopened
            .resolution_receipts
            .iter()
            .map(|receipt| receipt.outcome.as_str())
            .collect();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == "approved")
                .count(),
            2
        );
        assert!(outcomes.contains(&"bundle_accepted"));
        assert!(outcomes.contains(&"bundle_review_each"));
        Ok(())
    }

    #[test]
    fn reject_all_emits_per_item_receipts_and_keeps_proposal_history() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let run_id = "run-reject";
        let first = entity(0xA1);
        let second = entity(0xA2);
        write_dreamer_proposal(
            &vault,
            first,
            entity(0xB1),
            entity(0xC1),
            "profile.diet",
            "vegan",
            run_id,
            10,
            &[REASON_CEILING],
        )?;
        write_dreamer_proposal(
            &vault,
            second,
            entity(0xB2),
            entity(0xC2),
            "profile.hobby",
            "chess",
            run_id,
            20,
            &[REASON_CEILING],
        )?;

        let resolution =
            vault.resolve_inbox_group_at(run_id, InboxBulkVerb::RejectAll, None, 50)?;
        assert_eq!(resolution.bundle_receipt.outcome, "bundle_rejected");
        assert_eq!(resolution.item_receipts.len(), 2);
        for receipt in &resolution.item_receipts {
            assert_eq!(receipt.outcome, "rejected");
            assert!(
                receipt
                    .policy_trace
                    .contains(&"gate.consent.bundle_reject".to_owned())
            );
        }

        // Rejection resolves consent but never silently deletes the proposal.
        assert_eq!(
            vault
                .get_claim(&first)?
                .expect("rejected proposal")
                .approval,
            ClaimApprovalStatus::Proposed
        );
        assert!(vault.store.pending_gate_consents(10)?.is_empty());
        Ok(())
    }

    #[test]
    fn cross_run_same_claim_hash_dups_collapse_into_earliest_open_group() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let subject = entity(0xC1);
        let original = entity(0xA1);
        let duplicate = entity(0xA2);
        let distinct = entity(0xA3);
        write_dreamer_proposal(
            &vault,
            original,
            entity(0xB1),
            subject,
            "profile.diet",
            "vegan",
            "run-early",
            10,
            &[REASON_CEILING],
        )?;
        write_dreamer_proposal(
            &vault,
            duplicate,
            entity(0xB2),
            subject,
            "profile.diet",
            "vegan",
            "run-late",
            20,
            &[REASON_CEILING],
        )?;
        write_dreamer_proposal(
            &vault,
            distinct,
            entity(0xB3),
            entity(0xC2),
            "profile.hobby",
            "chess",
            "run-late",
            30,
            &[REASON_CEILING],
        )?;

        vault.set_inbox_review_dial(InboxReviewDial::ReviewEverything)?;
        let groups = vault.inbox_groups(InboxQuery::at(100, 10))?;
        assert_eq!(groups.len(), 2);

        let early = &groups[0];
        assert_eq!(early.run_id, "run-early");
        assert_eq!(early.members.len(), 1);
        assert_eq!(early.members[0].claim_id, original.to_hex());
        assert_eq!(
            early.members[0].duplicate_claim_ids,
            vec![duplicate.to_hex()]
        );
        assert!(early.pointer_rows.is_empty());

        let late = &groups[1];
        assert_eq!(late.run_id, "run-late");
        assert_eq!(late.members.len(), 1);
        assert_eq!(late.members[0].claim_id, distinct.to_hex());
        assert_eq!(late.pointer_rows.len(), 1);
        assert_eq!(late.pointer_rows[0].claim_id, duplicate.to_hex());
        assert_eq!(
            late.pointer_rows[0].duplicate_of_claim_id,
            original.to_hex()
        );
        assert_eq!(late.pointer_rows[0].duplicate_of_group_key, early.group_key);

        // Accepting the earliest group covers the collapsed duplicate's
        // pending row too — each row redeems against its own binding.
        let resolution =
            vault.resolve_inbox_group_at("run-early", InboxBulkVerb::AcceptAll, None, 50)?;
        assert_eq!(resolution.item_receipts.len(), 2);
        assert_eq!(
            vault
                .get_claim(&duplicate)?
                .expect("duplicate claim")
                .approval,
            ClaimApprovalStatus::Approved
        );

        let groups = vault.inbox_groups(InboxQuery::at(60, 10))?;
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].run_id, "run-late");
        assert_eq!(groups[0].members.len(), 1);
        assert!(groups[0].pointer_rows.is_empty());
        Ok(())
    }

    #[test]
    fn approve_all_dial_still_surfaces_manifest_critical() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let run_id = "run-dial";
        let critical = entity(0xA1);
        let plain = entity(0xA2);
        let hedged = entity(0xA3);
        write_dreamer_proposal(
            &vault,
            critical,
            entity(0xB1),
            entity(0xC1),
            "profile.diet",
            "vegan",
            run_id,
            10,
            &[REASON_CRITICAL],
        )?;
        write_dreamer_proposal(
            &vault,
            plain,
            entity(0xB2),
            entity(0xC2),
            "profile.hobby",
            "chess",
            run_id,
            20,
            &[REASON_CEILING],
        )?;
        write_dreamer_proposal(
            &vault,
            hedged,
            entity(0xB3),
            entity(0xC3),
            "profile.city",
            "osaka",
            run_id,
            30,
            &[REASON_CHECKER],
        )?;

        // Default dial: exceptions-only surfaces critical + checker hedge.
        let groups = vault.inbox_groups(InboxQuery::at(100, 10))?;
        assert_eq!(groups.len(), 1);
        let surfaced: Vec<&str> = groups[0]
            .members
            .iter()
            .map(|member| member.claim_id.as_str())
            .collect();
        assert_eq!(
            surfaced,
            vec![critical.to_hex().as_str(), hedged.to_hex().as_str()]
        );
        assert_eq!(groups[0].held_member_count, 1);
        assert!(
            groups[0].members[0]
                .exception_classes
                .contains(&InboxExceptionClass::ManifestCritical)
        );
        assert!(
            groups[0].members[1]
                .exception_classes
                .contains(&InboxExceptionClass::CheckerHedge)
        );

        // approve-all cannot waive manifest-critical rows.
        vault.set_inbox_review_dial(InboxReviewDial::ApproveAll)?;
        let groups = vault.inbox_groups(InboxQuery::at(100, 10))?;
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].members.len(), 1);
        assert_eq!(groups[0].members[0].claim_id, critical.to_hex());
        assert_eq!(groups[0].held_member_count, 2);

        vault.set_inbox_review_dial(InboxReviewDial::ReviewEverything)?;
        assert_eq!(
            vault.inbox_groups(InboxQuery::at(100, 10))?[0]
                .members
                .len(),
            3
        );
        Ok(())
    }

    #[test]
    fn per_item_lapse_never_drops_siblings() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let run_id = "run-lapse";
        let lapsing = entity(0xA1);
        let sibling = entity(0xA2);
        write_dreamer_proposal(
            &vault,
            lapsing,
            entity(0xB1),
            entity(0xC1),
            "profile.diet",
            "vegan",
            run_id,
            10,
            &[REASON_CEILING],
        )?;
        write_dreamer_proposal(
            &vault,
            sibling,
            entity(0xB2),
            entity(0xC2),
            "profile.hobby",
            "chess",
            run_id,
            20,
            &[REASON_CEILING],
        )?;
        vault.set_inbox_review_dial(InboxReviewDial::ReviewEverything)?;

        let lapse = vault
            .let_go_pending_ask_at(&lapsing, 99)?
            .expect("lapse emits a receipt");
        assert_eq!(lapse.outcome, "let_go");

        let groups = vault.inbox_groups(InboxQuery::at(100, 10))?;
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].members.len(), 1);
        assert_eq!(groups[0].members[0].claim_id, sibling.to_hex());
        assert_eq!(groups[0].held_member_count, 0);

        // The group closes only once every member is resolved.
        vault
            .let_go_pending_ask_at(&sibling, 120)?
            .expect("second lapse emits a receipt");
        assert!(vault.inbox_groups(InboxQuery::at(130, 10))?.is_empty());
        Ok(())
    }

    #[test]
    fn supersede_of_user_stated_and_conflict_rows_surface_as_exceptions() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let run_id = "run-d";
        let subject = entity(0xC1);
        let owner = entity(0xB0);
        vault.put_entity(&owner, ENTITY_TYPE_PERSON, time(1), 1, b"owner")?;
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, time(1), 1, b"subject")?;

        // Existing user_stated truth on the same subject + predicate.
        let truth = entity(0xA0);
        let envelope = WriteEnvelope::new(
            WriteActor::new(owner, EdgeActorClass::Human),
            ClaimSource::UserStated,
            WriteProvenance::new(Value::from("user said so")).expect("provenance"),
            ClaimApprovalStatus::Approved,
        );
        let candidate = crate::types::ClaimCandidate::new(
            "profile.diet",
            ClaimSubject::Entity(subject),
            Value::from("vegan"),
            1.0,
        );
        vault
            .batch()
            .claim_candidate(&truth, candidate, &envelope, time(5), 5)
            .commit()?;

        let update = entity(0xA1);
        write_dreamer_proposal(
            &vault,
            update,
            entity(0xB1),
            subject,
            "profile.diet",
            "keto",
            run_id,
            10,
            &[REASON_CEILING],
        )?;
        let conflict = entity(0xA2);
        write_dreamer_proposal(
            &vault,
            conflict,
            entity(0xB2),
            subject,
            PREDICATE_CONFLICT_OPEN,
            "diet conflict",
            run_id,
            20,
            &[REASON_CEILING],
        )?;
        let plain = entity(0xA3);
        write_dreamer_proposal(
            &vault,
            plain,
            entity(0xB3),
            entity(0xC3),
            "profile.hobby",
            "chess",
            run_id,
            30,
            &[REASON_CEILING],
        )?;

        // Default exceptions-only dial: the supersede-of-user_stated row and
        // the conflict row surface; the plain new claim rides auto.
        let groups = vault.inbox_groups(InboxQuery::at(100, 10))?;
        assert_eq!(groups.len(), 1);
        let group = &groups[0];
        assert_eq!(group.members.len(), 2);
        assert_eq!(group.held_member_count, 1);
        assert_eq!(group.new_claim_count, 1);
        assert_eq!(group.update_count, 1);
        assert_eq!(group.conflict_count, 1);
        assert_eq!(
            group.headline,
            "Dreamer run: 1 new claim, 1 update, 1 conflict"
        );

        let update_row = &group.members[0];
        assert_eq!(update_row.claim_id, update.to_hex());
        assert_eq!(update_row.verb_class, "update");
        assert!(
            update_row
                .exception_classes
                .contains(&InboxExceptionClass::SupersedesUserStated)
        );
        let conflict_row = &group.members[1];
        assert_eq!(conflict_row.claim_id, conflict.to_hex());
        assert_eq!(conflict_row.verb_class, "conflict");
        assert!(
            conflict_row
                .exception_classes
                .contains(&InboxExceptionClass::Conflict)
        );

        // Bundle consent scopes to run x verb-class.
        let resolution =
            vault.resolve_inbox_group_at(run_id, InboxBulkVerb::RejectAll, Some("conflict"), 99)?;
        assert_eq!(resolution.item_receipts.len(), 1);
        assert_eq!(
            resolution.item_receipts[0].trigger_ref.as_deref(),
            Some(format!("claim:{}", conflict.to_hex()).as_str())
        );
        assert!(
            resolution
                .bundle_receipt
                .policy_trace
                .contains(&"gate.consent.bundle.verb_class.conflict".to_owned())
        );
        assert_eq!(vault.store.pending_gate_consents(10)?.len(), 2);
        Ok(())
    }

    #[test]
    fn many_item_runs_sub_cluster_by_entity() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let run_id = "run-many";
        let first_subject = entity(0xC1);
        let second_subject = entity(0xC2);
        let values = ["a", "b", "c"];
        for (index, value) in values.iter().enumerate() {
            let offset = u8::try_from(index).expect("small index");
            write_dreamer_proposal(
                &vault,
                entity(0xA1 + offset),
                entity(0xB1 + offset),
                first_subject,
                "profile.note",
                value,
                run_id,
                10 + u64::from(offset),
                &[REASON_CEILING],
            )?;
            write_dreamer_proposal(
                &vault,
                entity(0xD1 + offset),
                entity(0xE1 + offset),
                second_subject,
                "profile.note",
                value,
                run_id,
                20 + u64::from(offset),
                &[REASON_CEILING],
            )?;
        }

        vault.set_inbox_review_dial(InboxReviewDial::ReviewEverything)?;
        let groups = vault.inbox_groups(InboxQuery::at(100, 10))?;
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].members.len(), 6);
        assert_eq!(groups[0].sub_clusters.len(), 2);
        let first_cluster = &groups[0].sub_clusters[0];
        assert_eq!(
            first_cluster.key,
            format!("entity:{}", first_subject.to_hex())
        );
        assert_eq!(first_cluster.member_claim_ids.len(), 3);
        let second_cluster = &groups[0].sub_clusters[1];
        assert_eq!(
            second_cluster.key,
            format!("entity:{}", second_subject.to_hex())
        );
        assert_eq!(second_cluster.member_claim_ids.len(), 3);
        Ok(())
    }
}
