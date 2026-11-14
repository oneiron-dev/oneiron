//! Moved from `crates/oneiron/src/verbs/courtesy_delete.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::deletion::coop_delivery::types::CooperativeDeletionDispositionKind;
use serde::Deserialize;
use serde::Serialize;

/// `vault.courtesy_delete.send`'s input: the ended pact, the worlds to ask
/// about, and the former peer's host.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CourtesyDeleteSendRequest {
    /// The ended pact, as 64 hex.
    pub pact: String,
    /// The worlds to ask about, as 32 hex; none asks about all the pact
    /// delivered.
    #[serde(default)]
    pub worlds: Vec<String>,
    /// Content up to this pact epoch; by default, the epoch the pact ended at.
    #[serde(default)]
    pub epoch_cutoff: Option<u64>,
    /// The former peer's host origin, `https://host[:port]`.
    pub peer: String,
    /// The ask already signed by the key the peer pinned, base64, when that
    /// key is not this host's. `worlds` and `epoch_cutoff` are then the ask's.
    #[serde(default)]
    pub signed: Option<String>,
}

/// One ask this vault sent, as its outbox holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CourtesyDeleteSent {
    /// The ask's request id, as 32 hex.
    pub request: String,
    /// Every page's request id of the paged selection, in queue order; the
    /// first is `request` (FIX 11802).
    pub pages: Vec<String>,
    /// The ended pact, as 64 hex.
    pub pact: String,
    pub recipient: String,
    /// Its delivery status.
    pub status: String,
    /// RFC 3339.
    pub created: String,
    /// RFC 3339.
    pub updated: String,
}

/// `vault.courtesy_delete.answer`'s input: the owner's choice on one ask a
/// former peer sent.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CourtesyDeleteAnswerRequest {
    /// The pact the ask came under, as 64 hex.
    pub pact: String,
    /// The ask's request id, as 32 hex.
    pub request: String,
    /// `delete`, `redact`, `restrict_pending_review`, `retain_under_basis`,
    /// `legal_hold` or `decline`.
    #[schemars(with = "String")]
    pub choice: CooperativeDeletionDispositionKind,
    /// A short snake_case reason code, for any choice but delete.
    #[serde(default)]
    pub reason_code: Option<String>,
    /// When a choice other than delete comes up for review, unix seconds.
    #[serde(default)]
    pub review_at: Option<u64>,
    /// Under a delete choice, the records to hard-delete, as 32 hex.
    #[serde(default)]
    pub delete: Vec<String>,
    /// Under a legal hold choice, the records to hold, as 32 hex.
    #[serde(default)]
    pub hold: Vec<String>,
    /// Required only for `retain_under_basis`: records, basis and retention-class codes.
    #[serde(default)]
    pub retention: Option<CourtesyDeleteRetention>,
    /// Under `restrict_pending_review`, copies to place or refresh, as 32 hex.
    /// Prior restrictions remain until explicitly lifted below.
    #[serde(default)]
    pub restrict: Vec<String>,
    /// The owner attests the requester was already told outside the engine
    /// BEFORE lifting these copies under this ask. Not engine-delivery proof.
    #[serde(default)]
    pub restriction_notice_given: Vec<String>,
    /// Under Redact, exact value-map keys on ordinary CLAIM copies.
    /// Local history only; not a peer/export erasure promise.
    #[serde(default)]
    pub redact: Vec<CourtesyDeleteClaimValueRedaction>,
    /// The requester's host origin, to send the answer back; without it the
    /// answer stays on this side.
    #[serde(default)]
    pub reply_to: Option<String>,
}

/// One covered CLAIM copy and literal value-map keys selected for removal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CourtesyDeleteClaimValueRedaction {
    pub record: String,
    pub value_fields: Vec<String>,
}

/// One local field/history action, not peer/export erasure proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CourtesyDeleteLocalRedaction {
    pub record: String,
    pub value_fields: Vec<String>,
    pub changed_history_rows: usize,
    pub revisions: Vec<CourtesyDeleteRedactionRevision>,
    pub applied_by: String,
    /// RFC 3339, the time of this local action only.
    pub applied: String,
}

/// The exact old/new causal binding, never a re-signature of old content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CourtesyDeleteRedactionRevision {
    pub previous_revision: String,
    pub revision: String,
    pub body_changed: bool,
    pub short_hash_changed: bool,
}

/// A retain-under-basis choice's selection and recorded policy codes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CourtesyDeleteRetention {
    /// Selected records as 32 hex; the answer lists only covered copies still here.
    pub records: Vec<String>,
    /// The owner's concise recorded basis, not a free-text allegation.
    pub basis_code: String,
    /// A caller-defined class code, not an engine-chosen number of days.
    pub retention_class: String,
}

/// One world an incoming ask names, with its stale stamp when the pact's
/// end already stopped its refresh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CourtesyDeleteAskedWorld {
    pub world: String,
    pub stale: Option<String>,
    pub stale_epoch: Option<u64>,
}

/// One customer hold a courtesy answer placed, as its row reads now (FIX
/// 2924).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CourtesyDeleteHold {
    /// The hold, as 32 hex.
    pub hold: String,
    /// `standing`, `lifted`, or `unknown` once its row is gone.
    pub status: String,
    /// The records it names now, or named when lifted, as 32 hex; empty
    /// when unknown.
    pub records: Vec<String>,
    /// RFC 3339, once lifted.
    pub lifted: Option<String>,
}

/// One record of a delete choice, with what became of it (FIX 2926).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CourtesyDeleteRecordProgress {
    /// The record, as 32 hex.
    pub record: String,
    /// `pending` (not removed yet), `removed`, or `missing` (nothing here).
    pub state: String,
}

/// The owner's recorded choice on an incoming ask.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CourtesyDeleteChoice {
    #[schemars(with = "String")]
    pub choice: CooperativeDeletionDispositionKind,
    pub reason_code: Option<String>,
    /// RFC 3339.
    pub review: Option<String>,
    /// The records a delete choice removed.
    pub deleted: Vec<String>,
    /// RFC 3339.
    pub recorded: String,
    /// The customer hold a legal hold choice placed or kept (FIX 2924).
    pub holds: Vec<CourtesyDeleteHold>,
    /// Selected records left out of the hold, retention or restriction:
    /// non-copies, or (for retention/restriction) no longer stored here.
    pub excluded: Vec<String>,
    /// Each record of a delete choice, in order, and what became of it: one
    /// still pending was not removed (FIX 2926).
    pub progress: Vec<CourtesyDeleteRecordProgress>,
    /// Copies actually retained here, and the owner's recorded basis and class.
    pub retention: Option<CourtesyDeleteRetention>,
    /// Copies this answer placed or refreshed under storage-only restriction.
    pub restricted: Vec<String>,
    pub local_redactions: Vec<CourtesyDeleteLocalRedaction>,
}

/// One active, user-selected storage-only restriction under this ask.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CourtesyDeleteRestriction {
    pub record: String,
    /// RFC 3339.
    pub since: String,
    pub reason_code: String,
    /// RFC 3339; this date does not automatically lift the restriction.
    pub review: String,
}

/// The owner attests prior external notice; this is NOT engine delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CourtesyDeleteRestrictionLift {
    pub records: Vec<String>,
    pub attested_by: String,
    /// RFC 3339; time of the in-engine attestation, not a claimed delivery time.
    pub attested: String,
}

/// One ask a former peer sent, filed for the owner's review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CourtesyDeleteIncoming {
    pub request: String,
    pub pact: String,
    /// The pact's state in this vault's log, when it still has one.
    pub pact_status: Option<String>,
    pub requester: String,
    /// The worlds named; empty asks about everything the pact delivered.
    pub worlds: Vec<CourtesyDeleteAskedWorld>,
    pub epoch_cutoff: u64,
    /// The records this vault still holds that the ask covers: delivered by
    /// the pact at or before the cutoff, in a named world, or in any world
    /// when none is named (FIX 321). The owner picks from them; nothing is
    /// deleted on receipt.
    pub candidates: Vec<String>,
    /// RFC 3339.
    pub requested: String,
    /// RFC 3339.
    pub received: String,
    pub answer: Option<CourtesyDeleteChoice>,
    /// The answer's delivery status, once one is sent back.
    pub reply_status: Option<String>,
    /// Every customer hold an answer to this ask placed or kept, an earlier
    /// choice's included (FIX 2924).
    pub holds: Vec<CourtesyDeleteHold>,
    /// All still-active restrictions from this ask, including earlier choices.
    pub restrictions: Vec<CourtesyDeleteRestriction>,
    /// Explicit owner attestations of prior external notice, never delivery proof.
    pub restriction_lifts: Vec<CourtesyDeleteRestrictionLift>,
    /// Earlier local actions remain recorded after a later menu choice.
    pub local_redactions: Vec<CourtesyDeleteLocalRedaction>,
}
