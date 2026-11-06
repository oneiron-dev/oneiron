//! Public inbox DTOs, surfacing-dial/exception-class/bulk-verb enums, and inbox constants.

use serde::{Deserialize, Serialize};

use crate::side_table::codec::CodecError;
use crate::side_table::codec::RawValue;
use oneiron_base::error::Error;

/// Sub-clusters by entity/theme are emitted only when a run surfaces at
/// least this many members ("when the run emits many items").
pub const INBOX_SUBCLUSTER_MIN_MEMBERS: usize = 6;

/// Reason-code prefix stamped by the ONE-1183-D2 auto_checker when an
/// Auto-eligible write is held on a low-confidence/hedged verdict. The gate
/// does not stamp these yet; the classifier is ready for the knob.
pub const INBOX_REASON_CHECKER_PREFIX: &str = "gate.pending.checker";

/// RS3 door prefix carried by inbox bundle receipts.
pub const INBOX_GROUP_DOOR_PREFIX: &str = "dreamer_run:";

pub const INBOX_BUNDLE_REF_PREFIX: &str = "bundle:";

pub const INBOX_REASON_BUNDLE_ACCEPT: &str = "gate.consent.bundle_accept";

pub const INBOX_REASON_BUNDLE_REJECT: &str = "gate.consent.bundle_reject";

/// ED-01 (ONE-1757) approve-with-edit: the decider approved an edited body.
pub const INBOX_REASON_AMEND_ACCEPT: &str = "gate.consent.amend_accept";

/// Stamped when the approval landed but its Δ could not be measured — the
/// telemetry gap is receipted rather than hidden, and never blocks.
pub const INBOX_REASON_AMEND_DELTA_UNCAPTURED: &str = "gate.consent.amend.delta_uncaptured";

pub const INBOX_BUNDLE_ACTOR_CLASS: &str = "owner";

pub const INBOX_BUNDLE_CONTENT_KIND: &str = "inbox_bundle";

pub const INBOX_RUN_BRIEF_INTENT_KEY: &str = "intent";

pub const VERB_CLASS_NEW_CLAIM: &str = "new_claim";

pub const VERB_CLASS_UPDATE: &str = "update";

pub const VERB_CLASS_CONFLICT: &str = "conflict";

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

impl RawValue for InboxReviewDial {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(self.as_str().as_bytes().to_vec())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let token =
            std::str::from_utf8(bytes).map_err(|_| Error::CorruptedIndex("inbox review dial"))?;
        Self::parse(token).ok_or_else(|| Error::CorruptedIndex("inbox review dial").into())
    }
}

/// Why a row surfaces in the exception queue.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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

    pub const fn bundle_outcome(self) -> &'static str {
        match self {
            Self::AcceptAll => "bundle_accepted",
            Self::RejectAll => "bundle_rejected",
            Self::ReviewEach => "bundle_review_each",
        }
    }
}

/// Pointer row shown by the LATER group when a duplicate collapsed into an
/// earlier one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InboxPointerRow {
    /// The later run's duplicate claim.
    pub claim_id: String,
    /// The member row it collapsed onto.
    pub duplicate_of_claim_id: String,
    /// The earlier open group holding that row.
    pub duplicate_of_group_key: String,
}

/// Entity/theme sub-cluster over surfaced members.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
