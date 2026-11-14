//! Moved from `crates/oneiron/src/feedback/triage.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::feedback::triage::github::GithubIssueKind;
pub use crate::feedback::triage::github::GithubIssueRevision;
pub use crate::feedback::triage::work::FeedbackTriagePin;
pub use crate::feedback::triage::work::FeedbackTriageSpan;
pub use oneiron_verb_wire::feedback::triage::FEEDBACK_TRIAGE_INBOX_SOURCE;
pub use oneiron_verb_wire::feedback::triage::FeedbackTriageBinding;
pub use oneiron_verb_wire::feedback::triage::FeedbackTriageContinuation;
pub use oneiron_verb_wire::feedback::triage::FeedbackTriageResult;
pub use oneiron_verb_wire::feedback::triage::github::GithubSweepContinuation;
pub use oneiron_verb_wire::feedback::triage::owner::FeedbackTriageBindingRequest;
pub use oneiron_verb_wire::feedback::triage::owner::FeedbackTriageErased;
pub use oneiron_verb_wire::feedback::triage::owner::FeedbackTriageProgress;
pub use oneiron_verb_wire::feedback::triage::owner::FeedbackTriageRun;
pub use oneiron_verb_wire::feedback::triage::owner::FeedbackTriageRunRequest;
pub use oneiron_verb_wire::feedback::triage::owner::FeedbackTriageStatusRequest;
pub use oneiron_verb_wire::feedback::triage::source::FeedbackTriageSourceError;
pub use oneiron_verb_wire::feedback::triage::source::FeedbackTriageSourceErrorKind;
use serde::Deserialize;
use serde::Serialize;

/// The domain a handoff row's key is taken under.
pub const HANDOFF_DOMAIN: &[u8] = b"oneiron:feedback-triage:handoff:v1";
pub mod github;
pub mod work;
