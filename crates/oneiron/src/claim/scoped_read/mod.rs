//! The policy-gated read lane: [`ScopedReadActorKey`], [`ScopedRead`], and the
//! admission/filtering surface that layers `crate::gate` scoped-read grants on
//! top of the claim surfaceability gate.

mod lifecycle;

use std::collections::HashSet;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};

use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::context_pack::ContextEntity;
use crate::edge::{EdgeConfirmationStatus, EdgeInfo, EdgeKind};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gate::{PolicyManifestResolution, ResolvedRetrievalFilter, RetrievalFilter};
use crate::pipeline::ScoredEntity;
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityRecord, EntityStoreRead, PortRows};
use crate::registry::ENTITY_TYPE_CLAIM;

mod claim_admission;
mod context_pack_filter;
mod diagnostic_reads;
mod facet_gate;
mod graph_reads;
mod loop_decision_read;
mod named_reads;
mod note_visibility;
mod pinned_reads;
mod point_reads;
mod reactions;
mod receipt;
mod retrieval_visibility;
mod served_forms;
mod versions;
mod weave_digest;
pub(crate) use weave_digest::invalidate_weave_digest_source_in_txn;
pub use weave_digest::{
    StoredWeaveDigest, WEAVE_DIGEST_NOTIFICATION_PRODUCER,
    WEAVE_DIGEST_SETTINGS_NOTIFICATION_PRODUCER, WeaveDigestCadence, WeaveDigestFeedback,
    WeaveDigestReader, WeaveDigestSchedule, WeaveDigestSettingAnswer, WeaveDigestSettingChange,
    WeaveDigestSettingChangeStatus, WeaveDigestSettingUndo, WeaveDigestSettings,
    WeaveDigestSettingsDrafter, WeaveScheduleHold,
};
mod weave_correction;
mod weave_lens;
pub use weave_lens::{
    WEAVE_LENS_CORRECTIONS_AXIS, WEAVE_LENS_PLAN_REPAIRS, WEAVE_LENS_READ_RATE_AXIS,
    WEAVE_LIVE_LENS_REREADS, WEAVE_REPORT_SKILL_NAME, WeaveLensPlan, WeaveLensPlanLine,
    WeaveLensPlanSection, WeaveLensRefusal, WeaveLensRender, WeaveLiveLens, weave_report_skill_id,
};
pub(crate) use weave_lens::{
    weave_lens_answer_plan, weave_lens_attempt_input, weave_lens_attempt_period,
    weave_lens_model_input, weave_lens_plan_schema, weave_lens_repair_text,
};
mod weave_report;
mod weave_serve;
mod weave_trigger;
pub(crate) use claim_admission::ClaimReadStatus;
pub use named_reads::NamedSlot;
pub use point_reads::{PointRead, ReadRow, ReadTarget};
pub use receipt::{ReadScope, ScopedReadReceipt, ScopedReadResult};
pub use weave_correction::{WeaveItemCorrection, WeaveItemTarget, WeaveLinkCorrection};
pub use weave_report::{
    WeaveItem, WeaveReader, WeaveReport, WeaveSection, WeaveSectionKind, WeaveSectionSpec,
};
pub use weave_serve::sieve_audit::{WeaveSieveDiscoveryView, WeaveSieveFindingView};
pub use weave_serve::{
    WeaveDigestFramed, WeaveDigestRequest, WeaveDigestView, WeaveItemCorrectionView, WeaveItemView,
    WeaveLinkCorrectionView, WeaveReaderKind, WeaveReaderRef, WeaveReportRequest, WeaveReportView,
    WeaveScheduleView, WeaveSectionInput, WeaveSectionView, WeaveSieveScoreView,
    WeaveWrongItemRequest, WeaveWrongLinkRequest,
};
pub use weave_trigger::WeaveDigestRendered;

mod access_gate;
pub(crate) use access_gate::{RelationshipRead, claim_access_axes, relationship_read};
mod actor_key;
mod agent_grants;
mod guest_bound;
mod owner_authority;
mod records_cover;
pub use actor_key::{CallerLocality, ScopedReadActorKey};
#[cfg(feature = "sync")]
mod residence;
#[cfg(feature = "sync")]
mod residence_page;
#[cfg(feature = "sync")]
mod selected_search;
pub(crate) use actor_key::{RoomTerms, RoomTurnCeiling, TurnTerms, meet_clearance};
#[cfg(feature = "sync")]
pub use residence::ResidenceReadContext;

/// Actor-keyed read lane for the core read surface.
///
/// All methods preserve the existing claim surface admission gate and
/// then layer policy scoped-grant matching for type-0 CLAIM entities.
pub struct ScopedRead<'a> {
    vault: &'a crate::vault::Vault,
    actor_key: ScopedReadActorKey,
    audience: Option<Vec<EntityId>>,
    /// Peers whose own read each served row must pass; see
    /// `ScopedRead::with_peer_reads`.
    peer_reads: Vec<ScopedReadActorKey>,
    audience_cache: Mutex<crate::conversation::AudienceCache>,
    /// A bound room turn's ceiling once a serving snapshot narrowed it; until
    /// then the key's own. See `ScopedRead::room_ceiling_in`.
    room_ceiling: Mutex<Option<Arc<RoomTurnCeiling>>>,
    room_ceilings_built: AtomicUsize,
    /// Session composition (ONE-1728 §7). `None` on the canonical handle,
    /// which therefore reads base only exactly as before; `Some` when the
    /// read was opened through a live session handle, in which case entity
    /// reads compose overlay ∪ base. Every policy/admission predicate above
    /// this field is unchanged — the union widens what is VISIBLE, never what
    /// is permitted.
    session_view: Option<&'a crate::store::SessionStoreView<'a>>,
    claim_status: ClaimReadStatus,
    recall_authority: Mutex<Option<crate::authority::AuthorityFold>>,
    /// Set only on a member's read a personal room ceiling conjoins (see
    /// `ScopedRead::peers_read_raw_in`): that member stands in each private
    /// thread under the CURRENT rule, whether it is in the thread now, never
    /// per turn (FIX 5545).
    room_peer: bool,
    /// Set only on a question's own locally built reader
    /// (`ScopedRead::with_own_owner_authority`, FIX 7461): a row its own
    /// admission and its reader's own Grants refuse is judged again, whole,
    /// under that reader's live owner authority.
    own_owner_authority: bool,
    /// The artifacts whose own version rows a records caveat naming them
    /// covers, for the records check alone (FIX 8245;
    /// `ScopedRead::with_artifact_records_cover`). Empty unless a typed
    /// artifact door opts in.
    records_cover: records_cover::ArtifactRecordsCover,
}

mod admission;
mod edge_admission;
pub(crate) use admission::ScopedDiaryCandidates;
mod retrieval_loop;
mod search;
mod visibility;

#[cfg(test)]
mod slip_tests;
#[cfg(test)]
mod tests;
