// Copyright (c) 2026 Stemma. Licensed under Apache-2.0.
// Oneiron fork: selected stateless engine components; see ../PROVENANCE.md.
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RevisionInfo {
    /// The original wire `w:id` this revision imported with (or the id minted
    /// for a wire-`w:id="0"` carrier / an authoring transaction). This is a
    /// per-element OOXML annotation, NOT a document-wide address: Word reuses
    /// `w:id` across unrelated elements, so it is NOT unique. It survives ONLY
    /// as the round-trip/serialization pairing key and as the seed floor for
    /// `runtime::max_revision_id` → the annotation counter. NEVER address a
    /// revision by this value; use [`RevisionInfo::identity`].
    pub revision_id: u32,
    pub author: Option<String>,
    pub date: Option<String>,
    /// Identifier of the `apply_edit` call that created this revision.
    /// Generated server-side when the call is received and stamped on every
    /// new RevisionInfo the call produces, so all tracked changes from a
    /// single LLM rewrite (or any single apply) share a stable group id.
    /// Pre-existing tracked changes (loaded from import) have `None`.
    ///
    /// NOTE: no `#[serde(skip_serializing_if)]` here — bincode serializes by
    /// position, not by name, so any "skip" attribute desyncs the reader from
    /// the writer. The field must always be present in the binary form.
    #[serde(default)]
    pub apply_op_id: Option<String>,
    /// ENGINE-MINTED revision identity (RFC-0004 §H7). Unique within a
    /// `Document` instance and STABLE across projections within that instance's
    /// lineage: a still-pending revision keeps this value through partial
    /// resolution and re-projection, because it rides forward structurally on
    /// the cloned `RevisionInfo` rather than being re-derived. Imported
    /// identities are deterministically derived from the canonical revision
    /// record, so an unchanged revision also keeps this value across save and
    /// reopen even when serialization replaces its raw `w:id`. This — NOT
    /// `revision_id` — is the address `Resolution::Selective`, `enumerate_
    /// revisions`, `resolvable_revision_ids`, and the cascade set use. All the
    /// carriers of one user intention share ONE identity: a MOVE's source
    /// content + source pilcrow + destination clone(s) carry the move group's
    /// identity, so selecting it resolves the whole move atomically and the
    /// group enumerates as one record.
    ///
    /// `0` is the pre-identity sentinel: a snapshot serialized before H7, or a
    /// carrier not yet passed through the import mint walk, decodes as `0` and
    /// is not individually addressable until (re-)minted. Appended LAST for the
    /// bincode-positional reason above.
    #[serde(default)]
    pub identity: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct StackedRevision {
    pub inserted: RevisionInfo,
    pub deleted: RevisionInfo,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub enum TrackingStatus {
    #[default]
    Normal,
    Inserted(RevisionInfo),
    Deleted(RevisionInfo),
    /// Text inserted by one revision and then deleted by another, BOTH still
    /// pending — "a deletion remembers what it deletes". The
    /// four origin rules define its resolutions:
    ///   accept the insertion → `Deleted(deleted)` (the deletion now targets
    ///     base text); reject the insertion → dropped (the nested deletion
    ///     goes with it — the Word cascade);
    ///   accept the deletion → dropped; reject the deletion →
    ///     `Inserted(inserted)`.
    /// Accept-all and reject-all therefore BOTH drop it; only mixed
    /// resolutions distinguish it from a plain insertion of the kept text.
    /// Boxed: the enum's size is its largest variant, and this state is rare
    /// per document while `Normal` segments are cloned constantly (same
    /// rationale as `InlineNode`'s boxed payloads).
    ///
    /// NOTE: appended LAST — bincode snapshot blobs encode variant indices.
    InsertedThenDeleted(Box<StackedRevision>),
}

