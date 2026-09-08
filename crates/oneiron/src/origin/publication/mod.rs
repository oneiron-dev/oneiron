//! The origin publication protocol (ARCH-0068 RA2–RA5, ONE-1910).
//!
//! One publication couples ONE typed LEDGER claim to ONE compare-and-swap git
//! ref advance under one crash-consistent protocol. Nothing else in this crate
//! may advance a served ref, and nothing else may decide what the origin
//! advertises.
//!
//! # Visibility is a derived proof, never a flag
//!
//! [`Vault::published_origin_refs`] is the ONLY advertisement projection. A ref
//! appears there while — and only while — a `Published` journal row's live ref
//! still equals its `new_oid` and all required Git and LFS objects remain
//! readable. There is no "visible" boolean anybody could set by hand. The
//! objects are proved before the ref moves and rechecked by the projection;
//! missing bytes or a live-ref mismatch hide the row without granting raw refs
//! any advertisement authority.
//!
//! # Single writer, by CAS and nothing else
//!
//! Every ref advance goes through [`crate::git_wire::GitWire::update_ref_cas`]
//! against the exact value the publication was decided against. A rejected
//! compare-and-swap ([`GitWireRejection::RefMoved`]) is a durable `Conflicted`
//! record and is NEVER retried — retrying is precisely how a second writer
//! would silently overwrite the first. That makes split-brain impossible
//! without any coordination service (RA2).
//!
//! # Physical roots and logical owners (RA4)
//!
//! An object is pinned by ONE physical keep-ref — the landed
//! [`GIT_WIRE_KEEP_REF_PREFIX`]`object/<oid>` shape, written only through
//! GitWire — and by as many LOGICAL owner rows as there are reasons to keep it
//! ([`OriginKeepRefKind`]). The physical root is deleted only when the owner
//! count reaches zero, so a publication releasing its own pin can never
//! unpin an object a change index, a conflict tree, a recovery or a snapshot
//! still needs.
//!
//! # The crash windows
//!
//! Objects and LFS bytes stage BEFORE the LMDB critical section. Three windows
//! exist and each has exactly one durable disposition, all reached through the
//! same code path [`Vault::reconcile_origin_publications`] drives:
//!
//! | Window | Observation | Disposition |
//! |---|---|---|
//! | after `Prepared`, before CAS | live ref == `expected_old_oid` and every object present | [`OriginCensusDisposition::RetriedAndPublished`] |
//! | after `Prepared`, before CAS | anything else | `MarkedFailed` / `MarkedConflicted`, ref unmoved |
//! | after CAS, before finalize | live ref == `new_oid` | `FinalizedPublished`, ref NOT moved again |
//! | after finalize, before cleanup | `Published` + live-ref proof | owner dropped; `NoChange` |
//!
//! An interrupted cleanup is a SAFE LEAK: a keep-ref with no owner keeps bytes
//! alive and costs one ref, and the next census removes it. Losing a root that
//! something still references would not be recoverable, so the protocol always
//! errs toward the leak.
//!
//! # Where the transaction boundary really is
//!
//! T1 commits Prepared plus the CAS intent before the public-ref effect.
//! GitWire then commits its own intent and runs CAS, outside publication's
//! transactions. After an Applied/Replayed outcome and a fresh live-ref proof,
//! T2 atomically writes the claim, Published and the visible-ref row. T2 reads
//! its journal row inside the transaction: terminal states always win.
//!
//! Pinning, runner, census and retirement share GitWire's re-entrant repository
//! coordinator. It is acquired BEFORE any LMDB writer. No GitWire call, Vault
//! read or subprocess runs inside T1 or T2. Keeping this coordinator across
//! pinning and zero-owner retirement prevents deletion beneath a new owner.
//!
//! # One authority for "did the ref move"
//!
//! This module never decides a compare-and-swap for itself. It hands the
//! decided-against value to [`GitWire::update_ref_cas`] and reads the verdict
//! back, because GitWire already owns the journal, the roll-forward of an
//! interrupted effect, the whole-graph object proof and the replay of a
//! terminal record. A second implementation of that decision here would be a
//! second thing to keep in agreement with the repository, and the two would
//! disagree exactly when it mattered.

// The state machine still names its admission predicates through the path it
// used as a flat module (`super::smart_http::...`, where `super` was `origin`).
// Import the sibling here so those paths resolve unchanged one level down.
use super::smart_http;
mod publication_codec;
mod publication_journal;
mod publication_machine;
mod publication_protocol;
#[cfg(test)]
mod publication_tests_a;
#[cfg(test)]
mod publication_tests_b;
mod publication_types;

pub use self::publication_codec::{
    origin_keep_ref_name, origin_publication_claim_id, origin_publication_id,
    origin_publication_intent_claim, origin_published_commit_id,
};
pub use self::publication_types::{
    ORIGIN_CAS_INTENT_KEY_PREFIX, ORIGIN_KEEP_OWNER_KEY_PREFIX, ORIGIN_PUBLICATION_CLAIM_ID_DOMAIN,
    ORIGIN_PUBLICATION_COMMIT_ID_DOMAIN, ORIGIN_PUBLICATION_ID_DOMAIN,
    ORIGIN_PUBLICATION_INTENT_PREDICATE, ORIGIN_PUBLICATION_MAX_FAILURE_BYTES,
    ORIGIN_PUBLICATION_MAX_REQUIRED_OBJECTS, ORIGIN_PUBLICATION_MAX_ROWS,
    ORIGIN_PUBLICATION_PREDICATE, ORIGIN_PUBLICATION_RECORD_KEY_PREFIX,
    ORIGIN_PUBLICATION_SCHEMA_VERSION, ORIGIN_PUBLICATION_VALUE_KEYS,
    ORIGIN_VISIBLE_REF_KEY_PREFIX, OriginCensusDisposition, OriginCensusReport, OriginKeepRefKind,
    OriginPublicationReceipt, OriginPublicationRecord, OriginPublicationRequest,
    OriginPublicationStatus,
};
