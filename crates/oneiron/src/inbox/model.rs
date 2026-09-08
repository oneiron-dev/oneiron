//! Public inbox DTOs, surfacing-dial/exception-class/bulk-verb enums, and inbox constants.

use serde::{Deserialize, Serialize};

use crate::edit_distance::delta::AmendmentDelta;
use crate::receipt::{ReceiptRecord, ReceiptView};

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

pub(super) const INBOX_BUNDLE_REF_PREFIX: &str = "bundle:";

pub(super) const INBOX_REASON_BUNDLE_ACCEPT: &str = "gate.consent.bundle_accept";

pub(super) const INBOX_REASON_BUNDLE_REJECT: &str = "gate.consent.bundle_reject";

/// ED-01 (ONE-1757) approve-with-edit: the decider approved an edited body.
pub(super) const INBOX_REASON_AMEND_ACCEPT: &str = "gate.consent.amend_accept";

/// Stamped when the approval landed but its Δ could not be measured — the
/// telemetry gap is receipted rather than hidden, and never blocks.
pub(super) const INBOX_REASON_AMEND_DELTA_UNCAPTURED: &str = "gate.consent.amend.delta_uncaptured";

pub(super) const INBOX_BUNDLE_ACTOR_CLASS: &str = "owner";

pub(super) const INBOX_BUNDLE_CONTENT_KIND: &str = "inbox_bundle";

pub(super) const INBOX_REVIEW_DIAL_KEY: &[u8] = b"settings:inbox:v1:review_dial";

pub(super) const INBOX_RUN_BRIEF_INTENT_KEY: &str = "intent";

pub(super) const VERB_CLASS_NEW_CLAIM: &str = "new_claim";

pub(super) const VERB_CLASS_UPDATE: &str = "update";

pub(super) const VERB_CLASS_CONFLICT: &str = "conflict";

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

/// Why a row surfaces in the exception queue.
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
    /// A meeting-class EVENT's post-end check-in is still unanswered (CAL-07).
    /// The only class not produced by the dreamer-run classifier.
    MeetingOutcomeCheckIn,
    /// The proposal is a plugin-section install (ONE-1707), whether the
    /// Dreamer suggested it or conversation initiated it.
    ///
    /// A PROJECTION rule, never a second approval mechanism: accept/reject
    /// still runs through `resolve_inbox_group[_at]` on the same bound
    /// pending-consent row. Installing a pack is always consent-required, so
    /// this class joins `ManifestCritical` as one the dial cannot waive.
    PluginInstall,
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

    pub(super) const fn bundle_outcome(self) -> &'static str {
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

/// One unanswered meeting-outcome check-in (CAL-07).
///
/// Derived, never stored: the row exists exactly while the EVENT is
/// meeting-class and carries no live `calendar.event_outcome` claim. An owner
/// answer or newly arrived machine evidence records that claim, and the row
/// stops projecting on the next pass — there is no retraction to remember.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxCheckInException {
    /// The EVENT the check-in asks about.
    pub event_ref: String,
    /// The host wake whose due delivery surfaced this row.
    pub wake_id: String,
    /// The EVENT's scheduled start, for the card the host renders.
    pub scheduled_start_utc: u64,
    /// Always [`InboxExceptionClass::MeetingOutcomeCheckIn`]; carried so this
    /// row folds into the same class filters the dreamer-run queue uses.
    pub exception_class: InboxExceptionClass,
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

/// Outcome of one approve-with-edit (ED-01, ONE-1757).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InboxAmendedApproval {
    pub claim_id: String,
    /// The `approved_amended` resolution receipt, Δ slot already filled.
    pub receipt: ReceiptRecord,
    /// The measured Δ. `None` means capture failed — the approval still
    /// landed, and the receipt carries the marker saying so.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta: Option<AmendmentDelta>,
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
