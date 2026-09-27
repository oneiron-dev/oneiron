//! The policy-gated read lane: [`ScopedReadActorKey`], [`ScopedRead`], and the
//! admission/filtering surface that layers `crate::gate` scoped-read grants on
//! top of the claim surfaceability gate.

mod lifecycle;

use std::{collections::HashSet, sync::Mutex};

use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::context_pack::{ContextEntity, ContextPack, EmptyContext, EmptyReason};
use crate::edge::{EdgeConfirmationStatus, EdgeInfo, EdgeKind};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gate::{PolicyManifestResolution, ResolvedRetrievalFilter, RetrievalFilter};
use crate::pipeline::ScoredEntity;
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityRecord, EntityStoreRead, PortRows};
use crate::registry::ENTITY_TYPE_CLAIM;

mod graph_reads;
mod note_visibility;
mod pinned_reads;
mod point_reads;
mod receipt;
mod retrieval_visibility;
mod versions;
mod weave_correction;
mod weave_report;
pub use receipt::{ReadScope, ScopedReadReceipt, ScopedReadResult};
pub use weave_correction::WeaveLinkCorrection;
pub use weave_report::{
    WeaveItem, WeaveReader, WeaveReport, WeaveSection, WeaveSectionKind, WeaveSectionSpec,
};

mod access_gate;
mod actor_key;
pub use actor_key::ScopedReadActorKey;

/// Actor-keyed read lane for the core read surface.
///
/// All methods preserve the existing claim surface admission gate and
/// then layer policy scoped-grant matching for type-0 CLAIM entities.
pub struct ScopedRead<'a> {
    vault: &'a crate::vault::Vault,
    actor_key: ScopedReadActorKey,
    audience: Option<Vec<EntityId>>,
    audience_cache: Mutex<crate::conversation::AudienceCache>,
    /// Session composition (ONE-1728 §7). `None` on the canonical handle,
    /// which therefore reads base only exactly as before; `Some` when the
    /// read was opened through a live session handle, in which case entity
    /// reads compose overlay ∪ base. Every policy/admission predicate above
    /// this field is unchanged — the union widens what is VISIBLE, never what
    /// is permitted.
    session_view: Option<&'a crate::store::SessionStoreView<'a>>,
}

mod admission;
mod context_filter;
mod diagnostics;
mod search;
mod visibility;

#[cfg(test)]
mod slip_tests;
