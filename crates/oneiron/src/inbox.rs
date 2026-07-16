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
//!   group; the later group shows a pointer row, and a duplicate's exception
//!   classes propagate to the owning row so the dial can never hide them;
//! * the settings dial (approve-all ↔ exceptions-only ↔ review-everything)
//!   adjusts SURFACING only. Manifest-critical rows surface under every dial
//!   position — the dial cannot waive them. Auto-redemption of non-surfaced
//!   rows awaits the ONE-1183-D2 auto_checker knob; until it lands, hidden
//!   rows stay consentable (bundle verbs, tray) and gap-decay per item, so
//!   receipts remain the always-on audit trail.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::attempt_queue::AttemptQueue;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    PREDICATE_CONFLICT_OPEN,
};
#[cfg(test)]
use crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use crate::dreamer_runner::decode_dreamer_attempt_payload;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::gate::GateReasonCode;
use crate::receipt::{ReceiptRecord, ReceiptView, gate_decision_receipt, hex_lower};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::{
    GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord, PendingGateConsentRecord,
};
use crate::temporal::TimeRange;

/// Upper bound on pending-consent rows visited per browse projection pass.
pub const INBOX_PENDING_SCAN_LIMIT: usize = 10_000;

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
    /// Group key: the run-tree ROOT attempt id (OF-193) when the run resolves in
    /// the attempt queue, otherwise the provenance-stamped run id.
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
            std::str::from_utf8(&raw).map_err(|_| Error::CorruptedIndex("inbox review dial"))?;
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
        inbox_groups_projection(self, query, dial, INBOX_PENDING_SCAN_LIMIT)
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
        let group = explicit_inbox_group(self, group_key, now)?.ok_or(Error::EntityNotFound)?;

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

        let open_group = explicit_inbox_group(self, group_key, now)?;

        let resolution_receipts = self
            .store
            .gate_decisions_for_grant_ref(&bundle_ref)?
            .iter()
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
fn explicit_inbox_group(vault: &Vault, group_ref: &str, now: u64) -> Result<Option<InboxGroup>> {
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
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
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
                hub_sync_imported: false,
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
mod tests;
