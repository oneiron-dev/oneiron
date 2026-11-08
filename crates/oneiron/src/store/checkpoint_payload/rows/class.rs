//! Where a payload family's rows go in a checkpoint (KS7-2b): its one [`Class`], with the owner
//! getters, custody clients and mixed sync carriers a class names. A side table's row declares its
//! family's class (`[family: ..]`); recovery's payload registry reads it there and classes the
//! manifest databases and entity kinds itself. These types sit below recovery, with the rows they
//! place, so a table's row names them without naming recovery; recovery's checkpoint payload
//! dispatches each getter to its store's capture and restore.

use serde::{Deserialize, Serialize};

use super::OtherClient;
use crate::store::CustodyKind;

/// Where a family's rows go: its one class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Class {
    /// An owner getter reads the family and places each row.
    Owner(Getter),
    /// Ids, counts, digests, markers and pins with no payload of their own.
    Structure,
    /// Another custody client's rows, handed to it as they stand.
    Other(Client),
    /// A mixed sync carrier, which KS7-3's port splits.
    Mixed(Carrier),
    /// Not compartmented: under the vault-wide seal, named on the receipt.
    Unclassified,
    /// Runtime or derived rows, which no image takes.
    NotImaged,
}

/// The custody client another family's rows belong to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Client {
    /// One the getters dispatch to as well (KS-2, KS-2B, KS-5, KS-6).
    Dispatch(OtherClient),
    /// Rows already sealed under that kind's own keys, which stay live in
    /// custody: KS-1's claim-bound gate decisions.
    Sealed(CustodyKind),
}

/// The owner getters, each beside its own store's codecs (KS7-2a), with the tag a bundle's binding
/// names it by; a tag is never reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Getter {
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
    pub(crate) const ALL: &[Self] = &[
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

    pub(crate) const fn tag(self) -> u8 {
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
pub(crate) enum Carrier {
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
    pub(crate) const fn tag(self) -> u8 {
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
