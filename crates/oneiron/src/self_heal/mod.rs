//! GATE-14 layer 1 (ONE-1394): deterministic detectors and the typed
//! `DiagnosticEvent` maintenance entity.
//!
//! A failure this engine notices about itself is NOT a log line. It is a
//! `DiagnosticEvent`: a closed, canonical MessagePack record at entity byte 69
//! (`DIAGNOSTIC`, Maintenance/System) carrying engine-authored actor / source /
//! criticality metadata, the invariant inputs the verdict was computed from
//! (`expected`, `actual`, `delta`), a content-addressed replay coordinate,
//! evidence refs, bitemporal validity, and exactly ONE explicitly typed escaped
//! leaf for untrusted detail. That is what makes a failure addressable,
//! provenance-carrying and re-derivable by the later healer, instead of a
//! string somebody has to parse back into meaning.
//!
//! # Determinism is the contract
//!
//! [`run_deterministic_detectors`] takes a bounded [`DiagnosticWorkingSet`]
//! whose order is PINNED at `(observed_at, source_ref, payload_digest)`
//! ascending. Detectors read that slice and return drafts; they never re-sort
//! it, and a working set presented out of order is REJECTED rather than quietly
//! sorted — sorting here would hide a non-deterministic scoped read behind a
//! deterministic-looking result, which is the exact failure this layer exists
//! to make visible. Drafts are canonicalized, encoded, keyed by a stable id
//! derived from `(detector_id, canonical body)`, sorted by that id, and
//! deduplicated. The same ordered input and detector set therefore produces
//! byte-identical bodies, identical ids, identical ordering, and identical
//! dedup on every run.
//!
//! # Scope
//!
//! Detection remains T1-only: its sole write is a DIAGNOSTIC entity through
//! [`DiagnosticEvent`]'s maintenance-band door. ONE-1395 adds a separate,
//! propose-only [`Healer`] contract and per-member [`RepairBundle`] review.
//! Healers receive no vault or executor; the engine stamps invocation authority
//! before their output exists and recomputes consent from current repair policy.
//! T2 classifiers, T3 judges and automatic repair remain absent. The narrow BM25
//! deindex self-heal is untouched. Receipts and retrieval telemetry remain
//! READ-ONLY detector inputs; no parallel log stack is introduced.

pub use crate::registry::ENTITY_TYPE_DIAGNOSTIC;

mod admission;
pub(crate) use admission::validate_diagnostic_event_admission;
mod consent_detector;
pub use consent_detector::ConsentDeniedDetector;

mod detector_runner;
mod diagnostic_codec;
mod event;
mod invariant_canonical;
mod untrusted_text;

mod repair;

pub(crate) use repair::validate_repair_proposal;
pub use repair::{
    Healer, HealerInvocationStamp, RepairActor, RepairBundle, RepairConsentRoute,
    RepairCriticality, RepairOperation, RepairProposal, ReviewedRepair,
};
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use repair::{RegisteredHealer, run_healer_proposals};

pub use self::detector_runner::{diagnostic_event_id, run_deterministic_detectors};
pub(crate) use self::diagnostic_codec::validate_diagnostic_event_body_bytes;
pub use self::diagnostic_codec::{decode_diagnostic_event_body, encode_diagnostic_event_body};
pub use self::event::{
    DIAGNOSTIC_BODY_KEYS, DIAGNOSTIC_SCHEMA_VERSION, DeterministicDetector, DiagnosticCriticality,
    DiagnosticEvent, DiagnosticEventClass, DiagnosticObservation, DiagnosticReplayCoordinate,
    DiagnosticSourceKind, DiagnosticWorkingSet,
};

// Private re-exports so the pre-existing children keep their `super::{...}`
// and `super::super::{...}` paths unchanged. These names keep the visibility
// they had as private items of the flat module.
use self::detector_runner::validate_working_set;
use self::diagnostic_codec::{validate_ref, validate_token};
use self::event::{MAX_EVENTS_PER_RUN, MAX_EVIDENCE_REFS, invalid_diagnostic};

#[cfg(test)]
mod production_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod text_tests;

// The flat self_heal.rs module used to provide these names to the test modules
// through `use super::*`: every self-heal-internal item the tests name bare,
// and the crate/std imports the tests relied on. After the directory split
// the seam re-imports both so the tests resolve exactly as they did before.
#[cfg(test)]
use self::{diagnostic_codec::*, event::*};
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::batch::{BatchOp, apply_ops};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use rmpv::{Integer, Value};
#[cfg(test)]
use std::collections::BTreeMap;
#[cfg(test)]
use std::io::Cursor;
