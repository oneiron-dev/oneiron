//! Moved from `crates/oneiron/src/store/checkpoint_payload/rows/class.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The owner getters, each beside its own store's codecs (KS7-2a), with the tag a bundle's binding
/// names it by; a tag is never reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Getter {
    /// Entity rows by kind, and edges.
    Entities,
    /// NOTE heads, forks, receipts, bundles, pins and titles.
    Note,
    /// Entity documents: heads, forks, pins, receipts and the document rows.
    EntityDoc,
    /// Typed bodies, their forks and receipts.
    TypedBody,
    /// Entity revisions and their staged index and phonetic inputs.
    EntityRevision,
    /// The text index's source text.
    TextSource,
    /// The phonetic index's source codes.
    PhoneticSource,
    /// Body descriptors and their digest holders; KS-2 carries the bytes.
    ProvenanceBody,
    /// Row births and the born-from index.
    ProvenanceBirth,
    /// Code documents.
    CodeDocument,
    /// Code revisions, proposals and promotions.
    CodeRevision,
    /// Codebase snapshots and their indexes.
    Codebase,
    /// Office bodies: heads, forks, exports and proposals.
    OfficeBody,
    /// Blob artifact heads and versions.
    BlobArtifact,
    /// Outbound calls' frozen input.
    OutboundCall,
    /// Independent owners of blocked step captures.
    BlockedSourceOwner,
    /// Media vectors, device provenance and refusals, by source document.
    EmbedMedia,
    /// Workflow leaves' retained tool transcripts and settled meters.
    WorkflowTool,
    /// Source-audience bindings, carried policy sets and holds, by row.
    SourceAudience,
}

impl Getter {
    /// Every getter: a capture calls each once, in this order.
    pub const ALL: &[Self] = &[
        Self::Entities,
        Self::Note,
        Self::EntityDoc,
        Self::TypedBody,
        Self::EntityRevision,
        Self::TextSource,
        Self::PhoneticSource,
        Self::ProvenanceBody,
        Self::ProvenanceBirth,
        Self::CodeDocument,
        Self::CodeRevision,
        Self::Codebase,
        Self::OfficeBody,
        Self::BlobArtifact,
        Self::OutboundCall,
        Self::BlockedSourceOwner,
        Self::EmbedMedia,
        Self::WorkflowTool,
        Self::SourceAudience,
    ];

    pub const fn tag(self) -> u8 {
        match self {
            Self::Entities => 1,
            Self::Note => 2,
            Self::EntityDoc => 3,
            Self::TypedBody => 4,
            Self::EntityRevision => 5,
            Self::TextSource => 6,
            Self::PhoneticSource => 7,
            Self::ProvenanceBody => 8,
            Self::ProvenanceBirth => 9,
            Self::CodeDocument => 10,
            Self::CodeRevision => 11,
            Self::Codebase => 12,
            Self::OfficeBody => 13,
            Self::BlobArtifact => 14,
            Self::OutboundCall => 15,
            Self::BlockedSourceOwner => 16,
            Self::EmbedMedia => 17,
            Self::WorkflowTool => 18,
            Self::SourceAudience => 19,
        }
    }
}

/// The mixed sync carriers KS7-3's port splits, with the tag a bundle's
/// binding names each by; a tag is never reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Carrier {
    /// A sync window's document snapshot.
    WindowSnapshot,
    /// A window's pending CRDT update.
    WindowUpdate,
    /// A thin-residence item's opened blob or document.
    ResidenceItem,
    /// An unacknowledged local text-document edit.
    PendingEdit,
    /// A pending NOTE-operation request.
    PendingNoteOperation,
    /// The sync queue's update carriers and quarantine.
    SyncQueue,
}

impl Carrier {
    pub const fn tag(self) -> u8 {
        match self {
            Self::WindowSnapshot => 1,
            Self::WindowUpdate => 2,
            Self::ResidenceItem => 3,
            Self::PendingEdit => 4,
            Self::PendingNoteOperation => 5,
            Self::SyncQueue => 6,
        }
    }
}
