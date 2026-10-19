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
//!   MessagePack under the token [`FEEDBACK_BUNDLE_ENCODING`], or under
//!   [`FEEDBACK_BUNDLE_ENCODING_V2`] when it carries a [`FeedbackProposal`].
//! - The typed local verb family: [`FEEDBACK_SEND_VERB`], [`FEEDBACK_VERBS`],
//!   [`FeedbackVerb`]. The family is local to this module by design — feedback
//!   remains separate from the universal agent-visible [`REPORT_VERB`] verb.
//! - Free problem/proposal reports, durable ISSUE identity, maker routing and
//!   entity-local review through [`ReportRequest`] and [`ReportIssue`].
//! - A redaction seam ([`FeedbackRedactor`]) and preview
//!   ([`prepare_feedback_preview`]), and the engine text filter it runs free
//!   text through ([`TextFilter`], [`apply_recognised_spans`],
//!   [`FilteredFeedback`]).
//! - The "Learn from my conversations" egress check ([`eligible`]) and the
//!   two doors that hand conversation text toward training the models
//!   Oneiron ships: [`share_for_publisher_training`], over a sink its caller
//!   supplies, and the publisher training outbox
//!   ([`Vault::offer_conversation_training`](crate::Vault::offer_conversation_training)),
//!   which publishes only what a release lets through.
//! - Per-bundle, per-destination consent over the existing
//!   [`ConsentAskCard`](crate::genui::ConsentAskCard) surface ([`feedback_approval_card`],
//!   [`validate_feedback_approval`]).
//! - An ordinary outbound send through
//!   [`Vault::dispatch_outbound_intent`](crate::Vault::dispatch_outbound_intent)
//!   ([`send_feedback`]) and an air-gapped export
//!   ([`export_feedback_bundle`]).
//!
//! # What does NOT ship here
//!
//! Collector, issue-tracker and cloud transports live in the server host, not
//! in this module. [`intake`] stores received bundles, deduplicates reports and
//! exposes review items. Triage prompts and digest policy remain agent-authored;
//! they are not engine policy. The bundle bytes stay the transport contract.
//!
//! The [`FeedbackRedactor`] seam takes [`FilteredFeedback`], which runs every
//! free text a bundle carries through an in-vault [`TextFilter`] the host
//! supplies (the server's Oneironer tagger) and refuses the bundle when that
//! filter cannot run. No model, no weights, and no model runtime ship in this
//! module. [`UnredactedFeedback`] leaves the bundle as built. Telemetry and
//! crash reports never carry world text (owner ruling 2026-10-14), so the
//! engine attaches none to a bundle; text in one is a note the owner wrote and
//! approved.
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
//! working; a new shape takes a new encoding token, not a new v1 key.
//!
//! A proposal is that new shape: [`FEEDBACK_BUNDLE_ENCODING_V2`] serializes
//! the six v1 keys in v1 order, then `proposal` (`problem`, `fix`). The token
//! travels beside the bytes ([`FeedbackPreview::encoding`], the transport
//! request, the receipt and the export), each token digests under its own
//! domain, and [`decode_feedback_bundle_as`] refuses an unknown token and any
//! bytes whose shape disagrees with their token.
//!
//! # Trust boundary
//!
//! [`validate_feedback_approval`] consumes a [`ConsentActionEvaluation`](crate::genui::ConsentActionEvaluation) as
//! HOST-TRUSTED FIELD INPUT. It is not authentication. The host authenticated
//! the owner when it evaluated the consent action; this module only checks
//! that the evaluation it was handed describes an approve-once decision on the
//! exact component id derived from this bundle, this destination and the
//! principal the evaluation names as its approver. A host
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
//! [`VaultConfig`](crate::VaultConfig): it copies a fixed list of
//! non-secret tuning scalars and copies nothing else. Dictionary search roots,
//! filesystem locations, environment values, connector credentials, custody
//! references, payload bodies, hostnames, and account identifiers are all
//! absent by construction, because the projection names every field it
//! carries. This module never reads the environment, the filesystem, a socket,
//! or a subprocess; the only sink it writes to is one the caller supplies.

mod bundle;
mod consent;
mod conversation_training;
mod dispatch;
mod error;
mod inbox;
pub mod intake;
mod redaction;
mod report;

pub use self::bundle::{
    FEEDBACK_APPROVE_ONCE_ACTION, FEEDBACK_BUNDLE_ENCODING, FEEDBACK_BUNDLE_ENCODING_V2,
    FEEDBACK_BUNDLE_KEYS, FEEDBACK_DAG_MAX_HOPS, FEEDBACK_EMBEDDING_MODEL_MAX_BYTES,
    FEEDBACK_ENGINE_VERSION_MAX_BYTES, FEEDBACK_MAX_SUBJECT_REFS, FEEDBACK_PROPOSAL_MAX_BYTES,
    FEEDBACK_REF_MAX_BYTES, FEEDBACK_SEND_VERB, FEEDBACK_USER_NOTE_MAX_BYTES, FEEDBACK_VERBS,
    FeedbackBundle, FeedbackCategory, FeedbackConfigSnapshot, FeedbackDagHop, FeedbackEncoding,
    FeedbackHealerDiagnosis, FeedbackHnswSnapshot, FeedbackPlatform, FeedbackProposal,
    FeedbackVerb, decode_feedback_bundle, decode_feedback_bundle_as, encode_feedback_bundle,
    feedback_bundle_digest, feedback_bundle_digest_as,
};
pub use self::consent::{
    FEEDBACK_APPROVAL_COMPONENT_PREFIX, FEEDBACK_CONTENT_REF_PREFIX, FEEDBACK_LOGICAL_SEND_PREFIX,
    FeedbackApproval, FeedbackApprovalScope, FeedbackPreview, FeedbackRedactionError,
    FeedbackRedactor, FeedbackSendRoute, UnredactedFeedback, feedback_approval_card,
    feedback_approval_component_id, feedback_approval_disclosure, feedback_content_ref,
    feedback_logical_send_ref, prepare_feedback_preview, validate_feedback_approval,
};
pub use self::conversation_training::{
    ConversationSource, ConversationText, ConversationTrainingChoice, Eligibility,
    IntakeReceiptKey, IntakeRecipient, NO_PUBLISHER_TRAINING_INTAKE, NoChoicesYet,
    PersonTrainingControl, PersonTrainingReceipts, PersonTrainingSubmission,
    PublisherTrainingLifecycle, PublisherTrainingSink, ReceiptCursor, ReceivedTrainingReceipt,
    ReleaseDecision, SealedTrainingOffer, ShareOutcome, ShareWithheld, SignedTrainingControl,
    TrainingControlId, TrainingCustody, TrainingOfferPass, TrainingQueued, TrainingReceiptPage,
    TrainingReceiptsCursor, TrainingSubmissionId, TrainingUnavailable, TrainingUpkeep,
    TrainingUsedRun, TrainingWithheld, Withheld, eligible, share_for_publisher_training,
};
pub use self::dispatch::{
    FEEDBACK_RECEIPT_FIELD_APPROVAL_RECEIPT_REF, FEEDBACK_RECEIPT_FIELD_BUNDLE_DIGEST,
    FEEDBACK_RECEIPT_FIELD_BUNDLE_ENCODING, FEEDBACK_RECEIPT_FIELD_VERB, FeedbackExportOutcome,
    FeedbackSendContext, FeedbackSendOutcome, FeedbackTransport, FeedbackTransportRequest,
    export_feedback_bundle, feedback_dispatch_request, send_feedback,
};
pub use self::error::FeedbackError;
pub use self::inbox::{FeedbackInboxNote, FeedbackInboxVia};
pub use self::redaction::{
    FilteredFeedback, FilteredText, TextFilter, TextFilterError, TextFilterIdentity,
    apply_recognised_spans,
};
pub use self::report::{
    IssueCategory, REPORT_VERB, ReportDisclosure, ReportDisclosureChoice, ReportIssue, ReportKind,
    ReportReceipt, ReportRequest, ReportReview, ReportRoute, ReportRoutedPayload, ReportSignature,
    ReportStatus,
};

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
