//! Engine feedback channel: bundle wire contract, consent, dispatch, export.
//!
//! A person who hits a bug, a papercut, a confusing surface, or wants a
//! feature can hand the engine a *feedback bundle*: a small, stable,
//! deployment-independent record of what the engine looked like when the
//! problem happened. This module owns the whole in-vault half of that story
//! and nothing beyond it.
//!
//! # What ships here
//!
//! - [`FeedbackBundle`], the frozen wire contract, encoded as named
//!   MessagePack under the token [`FEEDBACK_BUNDLE_ENCODING`].
//! - The typed local verb family: [`FEEDBACK_SEND_VERB`], [`FEEDBACK_VERBS`],
//!   [`FeedbackVerb`]. The family is local to this module by design — feedback
//!   is not an agent-visible board verb and joins no shared verb allowlist.
//! - In-vault redaction ([`FeedbackRedactor`]) and preview
//!   ([`prepare_feedback_preview`]).
//! - Per-bundle, per-destination consent over the existing
//!   [`ConsentAskCard`] surface ([`feedback_approval_card`],
//!   [`validate_feedback_approval`]).
//! - An ordinary outbound send through
//!   [`Vault::dispatch_outbound_intent`](crate::Vault::dispatch_outbound_intent)
//!   ([`send_feedback`]) and an air-gapped export
//!   ([`export_feedback_bundle`]).
//!
//! # What does NOT ship here
//!
//! No collector endpoint, no issue-tracker transport, no cloud routing, no
//! receiving vault entities, no deduplication or classification, no triage
//! proposals, no digest review. The bundle bytes are the input contract those
//! future systems will consume; they are deliberately built and frozen first.
//!
//! The [`FeedbackRedactor`] seam is exposed informationally so a later
//! entity-recognition redactor can be dropped in behind it. No model, no
//! weights, and no model runtime ship in this module —
//! [`PassThroughFeedbackRedactor`] is the only implementation here, and it
//! redacts nothing.
//!
//! # Wire stability
//!
//! [`FeedbackBundle`] serializes exactly six top-level keys, in this order:
//! `category`, `engine_version`, `platform`, `config`, `healer_diagnosis`,
//! `user_note`. Absent optional values serialize as MessagePack nil; they are
//! never omitted, so the key set is identical for every bundle ever produced.
//! Every struct denies unknown fields, unordered collections are ordered maps
//! and sets, decoding rejects trailing bytes, and the encoder is always the
//! *named* MessagePack encoder. A reader written against v1 bytes today keeps
//! working; a v2 shape would take a new encoding token, not a new key.
//!
//! # Trust boundary
//!
//! [`validate_feedback_approval`] consumes a [`ConsentActionEvaluation`] as
//! HOST-TRUSTED FIELD INPUT. It is not authentication. The host authenticated
//! the owner when it evaluated the consent action; this module only checks
//! that the evaluation it was handed describes an approve-once decision on the
//! exact component id derived from this bundle and this destination. A host
//! that fabricates an evaluation is already inside its own trust boundary —
//! the same boundary the persona-snapshot export consent sits behind.
//!
//! # Consent scope
//!
//! One approval authorizes exactly one bundle to exactly one destination,
//! exactly once. The approval card is minted with an EMPTY escalator list, so
//! its only actions are approve-once and decline: there is no "always allow
//! feedback", no standing grant, and no widening. A stale bundle digest or a
//! different destination fails with [`FeedbackError::StalePreviewDigest`]
//! before any contract resolution, gate evaluation, transport call, or write.
//!
//! # Secret hygiene
//!
//! [`FeedbackConfigSnapshot`] is a whitelist projection of
//! [`VaultConfig`]: it copies a fixed list of
//! non-secret tuning scalars and copies nothing else. Dictionary search roots,
//! filesystem locations, environment values, connector credentials, custody
//! references, payload bodies, hostnames, and account identifiers are all
//! absent by construction, because the projection names every field it
//! carries. This module never reads the environment, the filesystem, a socket,
//! or a subprocess; the only sink it writes to is one the caller supplies.

mod bundle;
mod consent;
mod dispatch;
mod error;

pub use self::bundle::{
    FEEDBACK_APPROVE_ONCE_ACTION, FEEDBACK_BUNDLE_ENCODING, FEEDBACK_BUNDLE_KEYS,
    FEEDBACK_DAG_MAX_HOPS, FEEDBACK_EMBEDDING_MODEL_MAX_BYTES, FEEDBACK_ENGINE_VERSION_MAX_BYTES,
    FEEDBACK_MAX_SUBJECT_REFS, FEEDBACK_MECHANISM_MAX_BYTES, FEEDBACK_REF_MAX_BYTES,
    FEEDBACK_SEND_VERB, FEEDBACK_USER_NOTE_MAX_BYTES, FEEDBACK_VERBS, FeedbackBundle,
    FeedbackCategory, FeedbackConfigSnapshot, FeedbackDagHop, FeedbackHealerDiagnosis,
    FeedbackHnswSnapshot, FeedbackPlatform, FeedbackVerb, decode_feedback_bundle,
    encode_feedback_bundle, feedback_bundle_digest,
};
pub use self::consent::{
    FEEDBACK_APPROVAL_COMPONENT_PREFIX, FEEDBACK_CONTENT_REF_PREFIX, FEEDBACK_LOGICAL_SEND_PREFIX,
    FeedbackApproval, FeedbackApprovalScope, FeedbackPreview, FeedbackRedactionError,
    FeedbackRedactor, FeedbackSendRoute, PassThroughFeedbackRedactor, feedback_approval_card,
    feedback_approval_component_id, feedback_approval_disclosure, feedback_content_ref,
    feedback_logical_send_ref, prepare_feedback_preview, validate_feedback_approval,
};
pub use self::dispatch::{
    FEEDBACK_RECEIPT_FIELD_APPROVAL_RECEIPT_REF, FEEDBACK_RECEIPT_FIELD_BUNDLE_DIGEST,
    FEEDBACK_RECEIPT_FIELD_BUNDLE_ENCODING, FEEDBACK_RECEIPT_FIELD_VERB, FeedbackExportOutcome,
    FeedbackSendContext, FeedbackSendOutcome, FeedbackTransport, FeedbackTransportRequest,
    export_feedback_bundle, feedback_dispatch_request, send_feedback,
};
pub use self::error::FeedbackError;

#[cfg(test)]
mod tests;

// The flat feedback.rs module used to provide these names to the sibling test
// module through `use super::*`: its own private crate/std import header.
// After the directory split the seam re-imports them so `tests.rs` resolves
// exactly as it did before. (Every feedback-internal item the tests name bare
// is re-exported above, so no `use self::{...}` glob is needed.)
#[cfg(test)]
use crate::config::VaultConfig;
#[cfg(test)]
use crate::genui::{ConsentActionDecision, ConsentActionEvaluation};
#[cfg(test)]
use crate::outbound::{
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundExecutionOutcome,
};
#[cfg(test)]
use std::collections::{BTreeMap, BTreeSet};
