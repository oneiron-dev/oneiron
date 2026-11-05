//! FIX 6220: a world-, facet- or record-scoped credential sends its own
//! e-sign notices (`vault.esign.notices.dispatch`) for a signing document
//! its own read lane reaches, and for no other.
//!
//! An unrestricted caller (no bound credential, or one bounded by the whole
//! vault, the only caller the row admitted before) keeps the door's
//! full-vault path exactly: the same verified-actor writer and the same
//! send. A narrowed caller is judged on the signing document by the lane
//! every read verb reads under (its record allowlist, world placement, facet
//! and audience rules, the owner's facet exemption, live grants and the
//! credential's liveness): once before the door lists, recovers or claims a
//! notice, and again in each snapshot that writes. Its recoveries, claims and
//! lease returns go through the document artifact's own content writer (the
//! actor's Grant at the document's position, never a whole-vault one), and
//! its send queues the delivery only while the lane still reaches the
//! document. A document the lane does not reach answers as one that is no
//! signing document.
//!
//! The housekeeping notice worker (FIX 6219, `notice_unattended`) runs the
//! same door path with no caller: as the notices' recorded principal, its
//! recorded send act and standing judged again in each of those snapshots.
use crate::write_envelope::claim_body::lexical_query_hint::ScopedRead;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MemoryResult;

/// The record a narrowed credential's scope is judged on for a staged notice
/// (CALLS `FIX 6220 scoped notice dispatch`, accepted by the Engine 10-20):
/// the signing document the notice stages for. Not the notice queue as a
/// whole, and not the recipient the notice goes to.
#[derive(Clone, Copy)]
enum NoticeScopeTarget {
    SigningDocument,
}

pub const NOTICE_SCOPE_TARGET: NoticeScopeTarget = NoticeScopeTarget::SigningDocument;

impl NoticeScopeTarget {
    /// The record judged for the notices of `document`.
    pub const fn record(self, document: EntityId) -> EntityId {
        match self {
            Self::SigningDocument => document,
        }
    }
}
