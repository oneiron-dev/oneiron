//! Auto-check seam: candidate types, fail-closed verdicts, the bounded host wrapper, and the request contract.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::Value as JsonValue;

use super::model_id::dynamic_model_id;
use super::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, DeterministicFallback, LlmMessage,
    LlmMessageRole, LlmRequest, ModelId, ModelLocality, ModelTierRef, ResponseFormat,
    TierPrecedence,
};
use crate::claim::ClaimSource;
use crate::entity_id::bytes_to_hex_lower;
use crate::write_envelope::SourceLineage;

// ---------------------------------------------------------------------------
// Auto-check seam (ONE-1296).
//
// The engine owns exactly three things here: the synchronous `AutoChecker`
// trait a host implements, the bounded wrapper that keeps a host answer from
// becoming an engine liveness problem, and the request contract an auto check
// is entitled to make. It owns no model choice, no prompt tuning and no
// verdict policy — the write gate reads only Allow / Hold / Unavailable.
// ---------------------------------------------------------------------------

/// Wall-clock bound one auto-check consult may take before the write gate
/// stops waiting for it.
///
/// A checker that has not answered by then is [`AutoCheckOutcome::Unavailable`]
/// and the write falls to Proposed. The bound is the engine's, not the host's:
/// a claim write must not be able to block on a host process at all.
pub const AUTO_CHECKER_DEADLINE_MS: u64 = 1_500;

/// Longest claim-value prefix an auto-check candidate carries.
///
/// The checker is shown a PREVIEW, never the whole value: this seam is a
/// second opinion on a candidate, not a disclosure channel.
pub const AUTO_CHECK_VALUE_PREVIEW_BYTES: usize = 512;

/// Most `Hold` reasons one verdict may put on the receipt.
pub(super) const AUTO_CHECK_MAX_HOLD_REASONS: usize = 8;

/// Longest single `Hold` reason one verdict may put on the receipt.
pub(super) const AUTO_CHECK_HOLD_REASON_MAX_BYTES: usize = 256;

/// The tier an auto check asks for by PURPOSE default: the cheap one. The
/// per-call and vault-policy slots stay empty so a vault that pins its own
/// tier still wins through [`TierPrecedence::resolved`].
pub(super) const AUTO_CHECK_PURPOSE_DEFAULT_TIER: &str = "cheap";

/// The floor under the purpose default, used only if a caller clears it.
const AUTO_CHECK_GLOBAL_DEFAULT_TIER: &str = "standard";

/// What a `Durable` auto check falls back to when no model answers: the same
/// fail-closed verdict every other failure mode produces.
const AUTO_CHECK_DETERMINISTIC_FALLBACK: &str = "fail_closed_to_proposed";

/// One candidate write presented to a host checker, borrowed from the write
/// door's own state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoCheckCandidate<'a> {
    pub predicate: &'a str,
    pub value_preview: &'a str,
    /// The claim's declared source, independent of its history.
    pub source: ClaimSource,
    /// Source classes in the write's history, or `None` without an envelope.
    /// Restricted members can trigger this consult even for a benign declaration.
    pub lineage: Option<&'a SourceLineage>,
    pub actor_class: &'a str,
    pub sensitivity_band: Option<u8>,
}

/// [`AutoCheckCandidate`] with every borrow resolved.
///
/// [`BoundedAutoChecker`] hands this — not the borrowed form — to the host, so
/// the host's answer can outlive the gate's deadline without the gate having
/// to keep anything alive for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoCheckCandidateOwned {
    pub predicate: String,
    pub value_preview: String,
    /// The claim's declared source, independent of its history.
    pub source: ClaimSource,
    /// Source classes in the write's history, or `None` without an envelope.
    pub lineage: Option<SourceLineage>,
    pub actor_class: String,
    pub sensitivity_band: Option<u8>,
}

impl AutoCheckCandidateOwned {
    /// Borrows this candidate back into the shape the trait takes.
    #[must_use]
    pub fn borrowed(&self) -> AutoCheckCandidate<'_> {
        AutoCheckCandidate {
            predicate: &self.predicate,
            value_preview: &self.value_preview,
            source: self.source,
            lineage: self.lineage.as_ref(),
            actor_class: &self.actor_class,
            sensitivity_band: self.sensitivity_band,
        }
    }
}

impl From<&AutoCheckCandidate<'_>> for AutoCheckCandidateOwned {
    fn from(candidate: &AutoCheckCandidate<'_>) -> Self {
        Self {
            predicate: candidate.predicate.to_owned(),
            value_preview: candidate.value_preview.to_owned(),
            source: candidate.source,
            lineage: candidate.lineage.cloned(),
            actor_class: candidate.actor_class.to_owned(),
            sensitivity_band: candidate.sensitivity_band,
        }
    }
}

/// A host checker's verdict on one candidate.
///
/// There is no error arm on purpose: a host maps its own failures — budget
/// denial, fatal model error, unparseable answer — onto
/// [`Self::Unavailable`], and the gate treats that exactly like a hold that
/// could not name its reasons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoCheckOutcome {
    Allow,
    Hold { reasons: Vec<String> },
    Unavailable,
}

impl AutoCheckOutcome {
    /// Fail-closed normalization every consumer of a host verdict applies.
    ///
    /// A `Hold` that names no surviving reason is a MALFORMED verdict, not a
    /// quiet hold: the receipt would carry a refusal nothing could explain, so
    /// it becomes [`Self::Unavailable`]. Reasons are trimmed, blank-dropped,
    /// truncated to `AUTO_CHECK_HOLD_REASON_MAX_BYTES` and capped at
    /// `AUTO_CHECK_MAX_HOLD_REASONS`, so a host cannot write an unbounded
    /// gate-decision receipt.
    #[must_use]
    pub fn normalized(self) -> Self {
        let Self::Hold { reasons } = self else {
            return self;
        };
        let reasons: Vec<String> = reasons
            .iter()
            .filter_map(|reason| {
                let trimmed = reason.trim();
                (!trimmed.is_empty()).then(|| {
                    truncate_on_char_boundary(trimmed, AUTO_CHECK_HOLD_REASON_MAX_BYTES).to_owned()
                })
            })
            .take(AUTO_CHECK_MAX_HOLD_REASONS)
            .collect();
        if reasons.is_empty() {
            Self::Unavailable
        } else {
            Self::Hold { reasons }
        }
    }
}

/// The host-implemented auto-check seam.
///
/// Synchronous by design: the write gate runs inside an LMDB write
/// transaction, which is not a place to hold an async runtime open. Bound an
/// implementation with [`BoundedAutoChecker`] before injecting it.
pub trait AutoChecker: Send + Sync + 'static {
    fn check(&self, candidate: &AutoCheckCandidate<'_>) -> AutoCheckOutcome;
}

/// The wrapper that makes an arbitrary host checker safe to call from the
/// write gate.
///
/// Each wrapper owns one worker and admits only one outstanding consult.
/// Clones share that worker and its capacity. A timeout stops the caller's wait,
/// but capacity stays occupied until the host call actually ends. Further
/// consults fail closed immediately while occupied; blocked hosts are never
/// joined and cannot cause this wrapper to accumulate workers or queued calls.
///
/// Candidates are owned off the gate's stack. Timeout, panic, spawn failure,
/// occupied capacity, and malformed verdicts become [`AutoCheckOutcome::Unavailable`].
#[derive(Clone)]
pub struct BoundedAutoChecker {
    sender: Option<mpsc::SyncSender<AutoCheckJob>>,
    pub(super) occupied: Arc<AtomicBool>,
}

struct AutoCheckJob {
    candidate: AutoCheckCandidateOwned,
    reply: mpsc::SyncSender<AutoCheckOutcome>,
}

impl BoundedAutoChecker {
    #[must_use]
    pub fn new(inner: Arc<dyn AutoChecker>) -> Self {
        let (sender, receiver) = mpsc::sync_channel::<AutoCheckJob>(1);
        let occupied = Arc::new(AtomicBool::new(false));
        let worker_occupied = Arc::clone(&occupied);
        // One persistent worker, not one detached thread per consult. Dropping
        // the last wrapper closes the channel; an idle worker then exits. A
        // blocked host keeps only this worker, without delaying wrapper drop.
        let worker = std::thread::Builder::new()
            .name("oneiron-auto-check".to_owned())
            .spawn(move || {
                while let Ok(job) = receiver.recv() {
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        inner.check(&job.candidate.borrowed()).normalized()
                    }))
                    .unwrap_or(AutoCheckOutcome::Unavailable);
                    drop(job.candidate);
                    // Only the worker releases an admitted call's capacity,
                    // after the host has returned or unwound, never on timeout.
                    worker_occupied.store(false, Ordering::Release);
                    // Capacity one; never wait for a caller that has timed out.
                    let _ = job.reply.try_send(outcome);
                }
            });
        Self {
            sender: worker.ok().map(|_| sender),
            occupied,
        }
    }
}

impl fmt::Debug for BoundedAutoChecker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundedAutoChecker").finish_non_exhaustive()
    }
}

impl AutoChecker for BoundedAutoChecker {
    fn check(&self, candidate: &AutoCheckCandidate<'_>) -> AutoCheckOutcome {
        let Some(sender) = &self.sender else {
            return AutoCheckOutcome::Unavailable;
        };
        if self
            .occupied
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return AutoCheckOutcome::Unavailable;
        }
        let (reply, receiver) = mpsc::sync_channel(1);
        let job = AutoCheckJob {
            candidate: AutoCheckCandidateOwned::from(candidate),
            reply,
        };
        if sender.try_send(job).is_err() {
            // No worker accepted this call, so there is no live host to await.
            self.occupied.store(false, Ordering::Release);
            return AutoCheckOutcome::Unavailable;
        }
        receiver
            .recv_timeout(Duration::from_millis(AUTO_CHECKER_DEADLINE_MS))
            .unwrap_or(AutoCheckOutcome::Unavailable)
    }
}

/// The host request one auto-check consult is entitled to make.
///
/// OF-037 is the CURRENT ruling and supersedes the older BestEffort line: an
/// auto check is a [`CallClass::Durable`] [`CallPurpose::AutoCheck`] call
/// answering in a JSON schema on the purpose-default cheap tier. `BestEffort`
/// is stale canon and must not come back — a check whose answer decides
/// whether a write self-approves is memoizable, replayable work with a
/// deterministic fallback, which is exactly what `Durable` means. Failing the
/// call still fails closed to Proposed; the class says how the call is made,
/// not how a failure is read.
///
/// `checker_ref` is the manifest's OPAQUE selector. The host resolves it and
/// injects the matching checker; the engine encodes it as the model identity
/// without choosing a model. `system_prompt` is supplied by the host, including
/// any instructions for interpreting candidate data. The engine owns the typed
/// response schema and call contract, not natural-language prompt policy.
#[must_use]
pub fn auto_check_llm_request(
    checker_ref: &str,
    candidate: &AutoCheckCandidate<'_>,
    system_prompt: &str,
) -> LlmRequest {
    LlmRequest {
        model: auto_check_model_id(checker_ref),
        envelope: CallEnvelope {
            purpose: CallPurpose::AutoCheck,
            class: CallClass::Durable {
                fallback: DeterministicFallback {
                    name: AUTO_CHECK_DETERMINISTIC_FALLBACK.to_owned(),
                    config: None,
                },
            },
            tier: TierPrecedence {
                per_call: None,
                vault_policy: None,
                purpose_default: Some(ModelTierRef(AUTO_CHECK_PURPOSE_DEFAULT_TIER.to_owned())),
                global_default: ModelTierRef(AUTO_CHECK_GLOBAL_DEFAULT_TIER.to_owned()),
            },
            response_format: ResponseFormat::Json {
                schema: auto_check_verdict_schema(),
            },
            // The host resolves `checker_ref` and knows where its checker
            // runs; the engine states the conservative default rather than
            // guessing a locality it cannot verify.
            locality: ModelLocality::ThirdParty,
        },
        messages: vec![
            LlmMessage {
                role: LlmMessageRole::System,
                content: vec![ContentPart::Text {
                    text: system_prompt.to_owned(),
                }],
            },
            LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text {
                    text: auto_check_candidate_text(candidate),
                }],
            },
        ],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
    }
}

fn auto_check_model_id(checker_ref: &str) -> ModelId {
    dynamic_model_id(
        "auto-check",
        // Hex encodes the ORIGINAL UTF-8 bytes injectively. The fixed prefix
        // keeps even the empty ref nonempty; no sanitization or normalization
        // can alias distinct host selectors in pins or durable request keys.
        format!("ref-{}", bytes_to_hex_lower(checker_ref.as_bytes())),
        "configured",
    )
}

pub(super) fn auto_check_verdict_schema() -> JsonValue {
    serde_json::json!({
        "type": "object",
        "properties": {
            "verdict": { "type": "string", "enum": ["allow", "hold"] },
            "reasons": { "type": "array", "items": { "type": "string" } },
        },
        "required": ["verdict"],
        "additionalProperties": false,
    })
}

fn auto_check_candidate_text(candidate: &AutoCheckCandidate<'_>) -> String {
    let lineage = match candidate.lineage {
        Some(lineage) => lineage
            .iter()
            .map(ClaimSource::as_str)
            .collect::<Vec<_>>()
            .join(", "),
        None => "unavailable".to_owned(),
    };
    let sensitivity_band = match candidate.sensitivity_band {
        Some(band) => band.to_string(),
        None => "unstamped".to_owned(),
    };
    format!(
        "predicate: {}\nsource: {}\nlineage: {}\nactor_class: {}\nsensitivity_band: {}\nvalue_preview: {}",
        candidate.predicate,
        candidate.source.as_str(),
        lineage,
        candidate.actor_class,
        sensitivity_band,
        candidate.value_preview,
    )
}

/// Truncates `value` to at most `max_bytes`, never splitting a character.
pub(crate) fn truncate_on_char_boundary(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}
