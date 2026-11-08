//! The masked copy every sync peer gets of a marked repo item (FIX 7608
//! slice 4; ruling A3: sync always carries the masked copy, owner-linked
//! devices included, while the human owner door stays exact on every
//! device).
//!
//! A copy only replaces bytes. The canonical rows, windows, documents and
//! queues on this device stay exactly as stored; what leaves it is derived
//! from them at release, and what arrives on a copy is translated back to
//! its source before anything canonical changes. The two roles never meet
//! in one store:
//!
//! - **Source and copy are bound, never conflated.** A marked snapshot
//!   ASSET's copy has its own id ([`RepoSyncProjectionId`]), derived from
//!   the source id alone: the alias is injective and outlives a re-mask, so
//!   an edit a peer made on an older copy still resolves to its source and
//!   is diffed against the current copy (never imported as a new row). The
//!   copy's bytes are named by its stamp, not its id. Any other row whose
//!   body is a marked blob's whole bytes keeps its id and carries the copy's
//!   bytes in place. Edges, tombstones and side-map keys follow the alias.
//! - **One read per pass.** The marks, each copy, its spans and its stamp
//!   are read once ([`SyncSecretProjection::read_in_txn`]) through slice 3's
//!   `RepoIndexMarks`; nothing here detects, masks or diffs on its own. A
//!   copy whose stored bytes, holding and spans read the same as at the last
//!   pass is taken again rather than made again (the shared copy cache, FIX 10599).
//! - **A copy's generation is its stamp, not a version vector.** The
//!   generation a release carries ([`SyncSecretProjection::generation`])
//!   commits to every copy it projects; a peer, cache or queue item bound to
//!   another generation gets a replacement, even when its version vector is
//!   equal (GAP 2 of the s4 soundness read).
//! - **Structure is kept only where it provably holds.** A map register's
//!   value may change length inside its one operation unit, so a window's
//!   map history keeps its operation ids with each value and key aliased
//!   ([`history`]). A text or list payload whose unit count a mask may change
//!   never takes that path: it ships as its separate copy lineage.
//! - **Incoming copy edits are translated, never imported raw.** A copy key
//!   resolves to its source, a copy row to the stored bytes, and a changed
//!   body goes through the shipped visible diff; only its ruled
//!   `projection_edit_conflict` / `sealed_file_edited` results hold, each
//!   kept as a held record and never applied (FIX 10598).
//!
//! The source -> copy map is derived, never stored: its rules are
//! [`SyncSecretProjection::SCHEMA`] (CALL 4-I, ruling (e)), its lifetime is
//! its source's, with no TTL or cap, and no peer learns a source id from
//! it. A masked lookup's store error propagates; nothing falls back to the
//! stored bytes (Engine 10-22 05:5x).
#![allow(
    dead_code,
    reason = "FIX 7608 slice 4, part 1: the release and inbound adapters call these when they activate together"
)]

mod documents;
mod frames;
mod held;
mod history;
mod reauthor;
mod release;
mod rows;

pub(crate) use crate::origin::secret_projection::selector_release::{
    BlobCopy, CopyRow, GENERATION_CONTEXT, ItemCopy, RepoSyncProjectionId, SyncSecretProjection,
};

pub(crate) use documents::device::{
    CopyReply, CopyStream, acknowledge_home_copy, copy_stream_in_txn, import_home_copy,
    release_device_copy, request_vector,
};
pub use documents::settlement::RepoCopyEditReview;
pub(crate) use documents::settlement::{
    begin_repo_copy_settlement_in_txn, finish_repo_copy_settlement_in_txn,
    review_repo_copy_edit_in_txn,
};
pub(crate) use documents::{
    IndexCopies, document_copy_in_txn, document_text_would_project_in_txn, import_document_copy,
    stored_item_in_txn, with_copy_generation_in_txn,
};
pub use documents::{
    RepoCopyAliases, repo_document_copy_id, repo_document_copy_vector, repo_document_lineage_edit,
    repo_document_source,
};
pub(crate) use history::ProjectedHistory;
pub use release::{
    RepoSyncAdmission, RepoSyncLandings, admit_repo_sync_frame, prepare_repo_sync_frame,
    prepare_repo_sync_frame_for_home, repo_copy_generation, repo_sync_frame_as_admitted,
};
pub(crate) use release::{released_item_blob, released_update};
pub(crate) use rows::InboundRow;
