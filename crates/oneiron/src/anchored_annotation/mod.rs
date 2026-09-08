//! ARTL-2 (OF-368 D2/D3/D4): anchored-comment threads over versioned blob
//! artifacts, plus thread → task-brief conversion.
//!
//! # Type-byte decision (OF-368 open question #4)
//!
//! Anchored-comment threads ride the **existing CLAIM band (type byte 0)** as
//! predicate-typed claims. They do NOT get their own StructuralKind type byte.
//!
//! Reasoning: OF-368 D3 rules that "comment threads are claims … CRDT-synced
//! like any claim". A CLAIM already carries every axis a thread needs —
//! author provenance (the `WriteEnvelope` actor + `ClaimSource`), an approval
//! axis, a lifecycle axis (`Active`/`Superseded`/`Retracted`), a world/scope
//! filter, and automatic Loro CRDT replication (CLAIM is not on any sync
//! skip-list). Minting a fresh entity-type byte would fork all of that and
//! re-implement serialization, sync mirroring, provenance, and consent for no
//! gain — exactly what "the viewer is disposable, memory is not" warns against.
//! It also matches two live precedents: the ARTL-1 `blob.version` LEDGER event
//! is a predicate-typed CLAIM (not a new byte), and the OF-367 context-receipt
//! field-set (ONE-1544) rode the existing receipt spine rather than minting a
//! new `receipt_kind`. So this unit registers three predicates in the CLAIM
//! band instead of a type byte.
//!
//! # Model
//!
//! A thread is identified by a `thread_id` ([`EntityId`]). All of a thread's
//! claims take the blob artifact entity as their `subj` (the same subject the
//! `blob.version` claim uses), so every thread + comment + brief for a workbook
//! is reachable through one `claims_for_subject(artifact_id)` sweep — the read
//! path a viewer overlay and a post-restart reload both use.
//!
//! * [`ANNOTATION_THREAD_PREDICATE`] — the thread **head**: anchor (locator +
//!   the version it resolves against), lifecycle state (open/resolved), origin
//!   version, and drift status. Mutable state is modeled by **superseding** the
//!   head with a new head claim, so exactly one head per thread stays `Active`.
//! * [`ANNOTATION_COMMENT_PREDICATE`] — one **append-only** comment. Comments
//!   are never superseded; author provenance rides both the comment value and
//!   the claim envelope.
//! * [`ANNOTATION_BRIEF_PREDICATE`] — the durable record that a thread was
//!   assigned into a task-brief (D4). The assignment is engine memory, never
//!   viewer-local.
//!
//! # Re-anchoring (D2 / D5 replay hook)
//!
//! On a new artifact version the anchors re-map by replaying the edit-manifest
//! ([`replay_locator`]). A non-mappable anchor is marked **DRIFTED** and pins to
//! its original version rather than lying about position. The op vocabulary
//! ([`ReanchorOp`]) is a MINIMAL local representation — see its docs for the
//! ARTL-3 reconciliation seam.
mod codec;
mod model;
mod reanchor;
mod threads;

pub(crate) use self::codec::{decode_locator, encode_locator};
pub use self::model::{
    A1Range, ANNOTATION_BRIEF_PREDICATE, ANNOTATION_COMMENT_PREDICATE,
    ANNOTATION_COMMENT_TEXT_MAX_BYTES, ANNOTATION_LOCATOR_RANGE_MAX_BYTES,
    ANNOTATION_LOCATOR_TEXT_MAX_BYTES, ANNOTATION_THREAD_PREDICATE, Anchor, AnnotationComment,
    AnnotationThread, DriftMarker, Locator, ReanchorOp, ReanchorOutcome, ReanchorSummary,
    TaskBrief, ThreadState,
};
pub use self::reanchor::replay_locator;

#[cfg(test)]
mod tests;

#[cfg(test)]
use self::codec::*;
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::claim::{ClaimApprovalStatus, ClaimSubject};
#[cfg(test)]
use crate::edge::EdgeActorClass;
#[cfg(test)]
use crate::edit_roundtrip::{AnchorEffect, Axis, StructuralShift};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::registry::ENTITY_TYPE_TASK;
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use crate::write_envelope::{ClaimCandidate, WriteActor};
#[cfg(test)]
use rmpv::Value;
