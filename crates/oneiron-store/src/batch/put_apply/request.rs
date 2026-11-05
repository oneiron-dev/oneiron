//! The one typed request `apply_put` takes: the row, the options that govern
//! how it is admitted, and the borrowed context it is judged against.

use crate::batch::builder::ops::BatchOp;
use crate::gate_decision::types::GateDecisionId;
use crate::write_envelope::ClaimCandidate;
use crate::write_envelope::WriteEnvelope;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::temporal::TimeRange;

/// The row as queued: its id, type byte, timestamps and body.
pub struct PutRow<'a> {
    pub id: EntityId,
    pub entity_type: u8,
    pub occurred: TimeRange,
    pub learned_at: u64,
    pub data: &'a [u8],
}

/// Which admit bands the put opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Replication {
    /// Sync replay of a row a peer already authored: skips the local claim
    /// gate and the local-only birth laws, and (ONE-1141) deindexes the
    /// loser's BM25F postings on a body-changing overwrite in the same
    /// transaction (ARCH-0031 amendment).
    pub replicated: bool,
    /// The D17 reserved `edge.*` predicate namespace on a CLAIM body.
    pub reserved_predicate: bool,
}

/// The ONE-1736 hub-sync SKILL import inlet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HubImport {
    /// The body is an imported SKILL the hub-sync policy door accepted.
    pub sync_imported: bool,
}

/// How the claim gate treats a pending consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsentHandling {
    /// Persist a consent the gate leaves pending.
    pub persist_pending: bool,
    /// A consent was already pending for this id when the batch began, so
    /// this put may resolve it.
    pub can_resolve_pending: bool,
}

impl Default for ConsentHandling {
    fn default() -> Self {
        Self {
            persist_pending: true,
            can_resolve_pending: false,
        }
    }
}

/// How the put's body relates to the text index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TextIndexing {
    /// A later text op in the same batch covers this id, so a local
    /// body-changing overwrite leaves deindexing to it.
    pub later_text_op_covers: bool,
}
