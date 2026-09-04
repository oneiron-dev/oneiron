//! ONE-1887 failure ladder: classify → bounded retry → healer slot → surface.
//!
//! One engine-owned failure POLICY layer over the landed queue substrate. It
//! classifies a typed, tiered attempt failure, retries only T1-tripwire
//! transients through ONE-1795's fresh-row [`AttemptQueue::retry`], escalates
//! the Nth consecutive transient through the per-scope policy, terminalizes
//! every other class through the existing [`AttemptQueue::fail`], and projects
//! a `self.report_blocked` receipt as a non-triggering Issues entry.
//!
//! What this module deliberately does NOT own: ATTEMPT storage or state
//! variants, retry-row minting, the graceful-cancel/landing protocol,
//! agent-definition/skill/prompt/environment mutation, the ARCH-0066 detector
//! tiers, TASK persistence, and surface rendering.
//!
//! DECLARED DEFERRED (OF-418 open integration edge): the production failure
//! call sites in `dreamer_runner`, `companion`, and `outbound` adopt
//! [`FailureLadder::handle_attempt_failure`] only once OF-418 lands the typed
//! detector evidence substrate. This lane ships and composition-tests the
//! policy and its helpers; it deliberately adds no evidence-less caller.

use std::collections::BTreeSet;
use std::num::NonZeroU16;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::agent_dispatch::{
    AGENT_DISPATCH_ATTEMPT_TYPE, AgentDispatchTarget, AgentDispatcher, DispatchHealer, HealerSlot,
    HealerSlotOutcome, decode_agent_dispatch_input,
};
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, FailAttempt, FailOutcome, RetryAttempt, RetryOutcome,
};
use crate::dreamer_runner::{DREAMER_RUNNER_ATTEMPT_KIND, decode_dreamer_attempt_payload};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_MESSAGE;

/// Consecutive transient failures a scope tolerates before escalating.
pub const DEFAULT_MAX_CONSECUTIVE_TRANSIENTS: NonZeroU16 =
    NonZeroU16::new(3).expect("three is non-zero");

/// Domain separator for the deterministic `case_ref` correlation key.
const FAILURE_CASE_REF_DOMAIN: &[u8] = b"oneiron.failure-case.v1\0";
/// Domain separator for the deterministic `card_ref` correlation key.
const FAILURE_CARD_REF_DOMAIN: &[u8] = b"oneiron.failure-card.v1\0";

/// The canonical three-value routing class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClass {
    Transient,
    Permanent,
    Ambiguous,
}

/// Typed output of the upstream tripwire/classifier stack. This module carries
/// the producer tier but does not implement any detector. Missing evidence is
/// represented as Indeterminate and therefore classifies Ambiguous.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypedFailureVerdict {
    Retryable,
    NonRetryable,
    Indeterminate,
}

/// Which ARCH-0066 detector tier produced the verdict. Only T1 tripwire
/// evidence is trusted enough to spend an automatic retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorTier {
    T1Tripwire,
    T2Classifier,
    T3Judge,
}

/// The typed detector evidence one failure input carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedFailureEvidence {
    /// Lowercase-hex EntityId spelling when evidence exists.
    #[serde(default)]
    pub evidence_ref: Option<String>,
    pub verdict: TypedFailureVerdict,
    #[serde(default)]
    pub tier: Option<DetectorTier>,
    /// Stable typed failure code supplied by the producer. It is persisted as
    /// the queue's human-readable terminal/retry reason, but never parsed to
    /// recover retryability.
    pub stable_reason: String,
}

/// Maps typed detector output onto the routing class, ambiguity-biased.
///
/// `(Retryable, None)` is Ambiguous even though validated production input
/// cannot reach that combination: the bias must hold for direct/unit use too.
#[must_use]
pub const fn classify_failure(evidence: &TypedFailureEvidence) -> FailureClass {
    match (evidence.verdict, evidence.tier) {
        (TypedFailureVerdict::Retryable, Some(DetectorTier::T1Tripwire)) => FailureClass::Transient,
        (
            TypedFailureVerdict::Retryable,
            Some(DetectorTier::T2Classifier | DetectorTier::T3Judge) | None,
        )
        | (TypedFailureVerdict::Indeterminate, _) => FailureClass::Ambiguous,
        (TypedFailureVerdict::NonRetryable, _) => FailureClass::Permanent,
    }
}

/// What the Nth consecutive transient failure selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureEscalationMode {
    /// Route to the healer slot; Reserved is a valid explicit result until the
    /// configured ARCH-0066 healer exists.
    Auto,
    Human,
}

/// The agent-side scope a policy binds to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureScope {
    /// Lowercase-hex EntityId spelling.
    pub agent_ref: String,
    #[serde(default)]
    pub skill_ref: Option<String>,
}

/// Caller-supplied policy. Persistence and lookup are not in this ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureScopePolicy {
    pub scope: FailureScope,
    pub max_consecutive_transients: NonZeroU16,
    pub escalation_mode: FailureEscalationMode,
    pub healer_slot: HealerSlot,
}

impl FailureScopePolicy {
    /// The default policy: N=3, Auto escalation, reserved healer slot.
    #[must_use]
    pub const fn auto(scope: FailureScope) -> Self {
        Self {
            scope,
            max_consecutive_transients: DEFAULT_MAX_CONSECUTIVE_TRANSIENTS,
            escalation_mode: FailureEscalationMode::Auto,
            healer_slot: HealerSlot::Reserved,
        }
    }
}

/// Reference-only projection of ONE-1686's durable `report_blocked` receipt.
///
/// The category/detail stay owned by and decoded through ONE-1686. This lane
/// deliberately does not duplicate that four-category enum or its receipt
/// codec, so the ref stays opaque here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedReportRef {
    /// Lowercase-hex EntityId spelling.
    pub receipt_ref: String,
}

/// Internal verification result. Dropped reports remain unit-testable without
/// becoming case/card data.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BlockedReportVerification {
    Verified(BlockedReportRef),
    Dropped { receipt_ref: String },
}

/// Verifies each supplementary report ref against the landed ONE-1686 surface.
///
/// SEAM (ONE-1686): the landed 1686 surface exposes the `self.*` effect
/// vocabulary and its witnessed MESSAGE ceiling, but no `report_blocked`
/// receipt kind or codec. Until one lands there is nothing to import and
/// nothing to re-implement, so verification stays at the structural floor the
/// landed surface does support: the ref must resolve to a LIVE witnessed
/// MESSAGE row. Everything else — an unparseable ref, an absent row, a
/// header-only (soft-deleted) shell, a foreign entity type — is fail-closed
/// [`BlockedReportVerification::Dropped`]. A dropped ref never reaches a case
/// or a card, and no report of either kind decides a failure class.
fn verify_blocked_reports(
    vault: &Vault,
    reports: &[BlockedReportRef],
) -> Result<Vec<BlockedReportVerification>> {
    reports
        .iter()
        .map(|report| verify_blocked_report(vault, report))
        .collect()
}

fn verify_blocked_report(
    vault: &Vault,
    report: &BlockedReportRef,
) -> Result<BlockedReportVerification> {
    let dropped = || BlockedReportVerification::Dropped {
        receipt_ref: report.receipt_ref.clone(),
    };
    let Ok(receipt) = EntityId::from_hex(&report.receipt_ref) else {
        return Ok(dropped());
    };
    let Some(raw) = vault.get_raw(&receipt)? else {
        return Ok(dropped());
    };
    let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw) else {
        return Ok(dropped());
    };
    // A header-only row is the ARCH-0038 soft-delete shell (or an empty body):
    // it parses, but it is not a durable receipt.
    if header.entity_type != ENTITY_TYPE_MESSAGE
        || raw.len() <= crate::batch::ENTITY_METADATA_HEADER_LEN
    {
        return Ok(dropped());
    }
    Ok(BlockedReportVerification::Verified(report.clone()))
}

/// One verified `report_blocked` receipt, projected for the Dreamer Issues job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureIssueEntry {
    pub report: BlockedReportRef,
    pub semi_trusted: bool,
}

/// Verifies and projects a report into Issues.
///
/// This function never calls a queue, dispatcher, landing requester, or human
/// surface: a report is supplementary, semi-trusted evidence and is NEVER
/// sufficient to arm the ladder. An unverifiable ref is refused here rather
/// than projected, so a dropped receipt cannot reach an Issues feed either.
///
/// # Errors
///
/// [`Error::InvalidConfig`] when the ref does not verify.
pub fn ingest_report_blocked(vault: &Vault, report: BlockedReportRef) -> Result<FailureIssueEntry> {
    match verify_blocked_report(vault, &report)? {
        BlockedReportVerification::Verified(report) => Ok(FailureIssueEntry {
            report,
            semi_trusted: true,
        }),
        BlockedReportVerification::Dropped { receipt_ref } => Err(Error::InvalidConfig(format!(
            "blocked report {receipt_ref} does not resolve to a durable report_blocked receipt"
        ))),
    }
}

/// One typed attempt-failure input, raised while the failing row is still the
/// authenticated leased ATTEMPT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleAttemptFailure {
    pub attempt_id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub evidence: TypedFailureEvidence,
    pub blocked_reports: Vec<BlockedReportRef>,
    /// Existing durable checkpoint immediately before the failing work.
    pub pre_fail_checkpoint_ref: EntityId,
    /// Existing referenced MESSAGE thread used by the healer/human Q&A feed.
    pub qa_thread_ref: EntityId,
    /// Existing retry policy chooses this instant. FailureLadder only forwards it.
    pub retry_at: u64,
    pub now: u64,
}

/// A `retry_of` chain that cannot be read as a chain at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetryLineagePathology {
    MissingAncestor { missing_attempt_id: AttemptId },
    Cycle { repeated_attempt_id: AttemptId },
}

/// Where the failing row sits in its `retry_of` chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryOrdinal {
    BelowLimit(NonZeroU16),
    AtLimit(NonZeroU16),
    Pathology(RetryLineagePathology),
}

/// Walks every class through the same bounded lineage proof.
///
/// The current row counts as ordinal one; at most `limit - 1` ancestors are
/// point-read. There is no list/scan and no use of `attempt_count`, which is
/// the per-row lease fence and not a logical retry count. A repeated pointer
/// is checked BEFORE the threshold return — that check needs no read, because
/// the cursor is already loaded and the repeated target is already in `seen` —
/// so a cycle sitting exactly on the threshold node is still a pathology.
/// Pathology deeper than the bound is intentionally undetectable: the
/// bounded-read law outranks completeness.
fn retry_lineage_walk(
    queue: &AttemptQueue<'_>,
    current: &AttemptRecord,
    limit: NonZeroU16,
) -> Result<RetryOrdinal> {
    let mut seen = BTreeSet::new();
    let mut cursor = current.clone();
    let mut ordinal = 1_u16;
    seen.insert(cursor.id);

    loop {
        let next_parent = cursor.retry_of;

        if let Some(parent_id) = next_parent
            && !seen.insert(parent_id)
        {
            return Ok(RetryOrdinal::Pathology(RetryLineagePathology::Cycle {
                repeated_attempt_id: parent_id,
            }));
        }

        if ordinal >= limit.get() {
            return Ok(RetryOrdinal::AtLimit(limit));
        }

        let Some(parent_id) = next_parent else {
            return Ok(RetryOrdinal::BelowLimit(
                NonZeroU16::new(ordinal).expect("ordinal starts at one"),
            ));
        };
        let Some(parent) = queue.get(parent_id)? else {
            return Ok(RetryOrdinal::Pathology(
                RetryLineagePathology::MissingAncestor {
                    missing_attempt_id: parent_id,
                },
            ));
        };
        cursor = parent;
        ordinal = ordinal.saturating_add(1);
    }
}

/// The healer's read-only view of one failure. Its identifiers are context;
/// the healer never writes them back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealerCase {
    /// Lowercase-hex deterministic correlation key; not a resolvable entity ref.
    pub case_ref: String,
    pub scope: FailureScope,
    pub failure_class: FailureClass,
    pub failing_attempt_id: AttemptId,
    #[serde(default)]
    pub task_ref: Option<String>,
    /// Lowercase-hex EntityId spelling.
    pub evidence_ref: String,
    #[serde(default)]
    pub blocked_reports: Vec<BlockedReportRef>,
    /// Lowercase-hex EntityId spelling.
    pub pre_fail_checkpoint_ref: String,
    /// Lowercase-hex EntityId spelling.
    pub qa_thread_ref: String,
    /// Always 0 for permanent/ambiguous by policy; never computed from lineage
    /// for those classes.
    pub consecutive_transients: u16,
}

/// The healer can target only agent-side artifacts. There is deliberately no
/// Task, task payload, or in-place Attempt target variant, so a task-targeted
/// "fix" is unrepresentable rather than merely rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "route", rename_all = "snake_case")]
pub enum HealerRepairRoute {
    SkillEdit {
        agent_ref: String,
        skill_ref: String,
        patch_ref: String,
        diagnosis_ref: String,
    },
    PromptInjectAndForkResume {
        agent_ref: String,
        prompt_ref: String,
        /// The PRE-FAIL checkpoint, never the terminal attempt: a failed row is
        /// never reopened, so a fork resumes from durable state that predates
        /// the failing work.
        checkpoint_ref: String,
        diagnosis_ref: String,
    },
    Environment {
        agent_ref: String,
        environment_ref: String,
        repair_ref: String,
        diagnosis_ref: String,
    },
    EscalateWithDiagnosis {
        agent_ref: String,
        diagnosis_ref: String,
    },
}

/// Everything the human surface needs about one terminalized failure.
#[derive(Debug, Clone, PartialEq)]
pub struct SurfacedFailure {
    pub failed_attempt: AttemptRecord,
    pub failure_class: FailureClass,
    /// Always 0 for permanent/ambiguous by policy; never computed from lineage
    /// for those classes.
    pub consecutive_transients: u16,
    /// Missing only for an Indeterminate verdict.
    pub evidence_ref: Option<EntityId>,
    pub blocked_reports: Vec<BlockedReportRef>,
    pub pre_fail_checkpoint_ref: EntityId,
    pub qa_thread_ref: EntityId,
    pub diagnosis: Option<HealerRepairRoute>,
    pub healer_slot: Option<HealerSlotOutcome>,
    pub pathology: Option<RetryLineagePathology>,
}

/// The typed result of one failure input.
///
/// Every `Healer` value sets `surface.diagnosis = None` and
/// `surface.healer_slot = Some(slot)`; a later healer-authored diagnosis
/// update rides the healer's own propose lane and is outside this ticket.
#[derive(Debug, Clone, PartialEq)]
pub enum FailureLadderOutcome {
    Retried {
        source_attempt_id: AttemptId,
        scheduled_attempt: AttemptRecord,
        /// The failed source row's ordinal: failures so far, including current.
        consecutive_transients: NonZeroU16,
    },
    Healer {
        failed_attempt: AttemptRecord,
        case: HealerCase,
        slot: HealerSlotOutcome,
        surface: SurfacedFailure,
    },
    Human(SurfacedFailure),
}

/// The deterministic `case_ref` correlation key for one failing attempt.
///
/// A correlation key, NOT an entity ref: it resolves through no store, and any
/// party can re-derive it from `failing_attempt_id` without a registry.
#[must_use]
pub fn failure_case_ref(failing_attempt_id: AttemptId) -> String {
    correlation_ref(FAILURE_CASE_REF_DOMAIN, failing_attempt_id)
}

/// The deterministic `card_ref` correlation key for one failing attempt.
///
/// Domain-separated from [`failure_case_ref`], so the two keys for the same
/// failed attempt are stable and distinct.
#[must_use]
pub fn failure_card_ref(failing_attempt_id: AttemptId) -> String {
    correlation_ref(FAILURE_CARD_REF_DOMAIN, failing_attempt_id)
}

fn correlation_ref(domain: &[u8], failing_attempt_id: AttemptId) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(failing_attempt_id.as_bytes());
    bytes_to_hex_lower(&hasher.finalize().as_bytes()[..16])
}

/// The failure-policy entry point over an already-open vault.
pub struct FailureLadder<'a> {
    vault: &'a Vault,
}

/// The per-failure data every routing arm shares once the row is terminal.
struct FailureSurfaceContext {
    evidence_ref: Option<EntityId>,
    blocked_reports: Vec<BlockedReportRef>,
    pre_fail_checkpoint_ref: EntityId,
    qa_thread_ref: EntityId,
}

impl FailureSurfaceContext {
    fn surface(
        &self,
        failed_attempt: AttemptRecord,
        failure_class: FailureClass,
        consecutive_transients: u16,
        pathology: Option<RetryLineagePathology>,
        healer_slot: Option<HealerSlotOutcome>,
    ) -> SurfacedFailure {
        SurfacedFailure {
            failed_attempt,
            failure_class,
            consecutive_transients,
            evidence_ref: self.evidence_ref,
            blocked_reports: self.blocked_reports.clone(),
            pre_fail_checkpoint_ref: self.pre_fail_checkpoint_ref,
            qa_thread_ref: self.qa_thread_ref,
            diagnosis: None,
            healer_slot,
            pathology,
        }
    }
}

/// What a healer-bound arm needs beyond the shared surface context.
struct HealerRouting {
    failure_class: FailureClass,
    consecutive_transients: u16,
    evidence_ref: Option<EntityId>,
}

impl<'a> FailureLadder<'a> {
    /// Opens the failure ladder over an already-open vault.
    #[must_use]
    pub const fn new(vault: &'a Vault) -> Self {
        Self { vault }
    }

    /// Runs the ordered failure protocol for one typed attempt failure.
    ///
    /// Exactly one retry-or-fail transition happens on the failing row: retry
    /// is never called after fail and the source is never failed after a retry
    /// atomically finalized it. An Auto healer dispatch is a separate enqueue
    /// of a DIFFERENT row.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for invalid evidence or a scope that does not
    /// bind the failing row's dispatched agent — both raised BEFORE any
    /// transition; [`Error::InvalidAttemptQueueTransition`] when the row is
    /// absent or when a concurrent failure input already won the single
    /// transition, in which case NOTHING is routed.
    pub fn handle_attempt_failure(
        &self,
        input: HandleAttemptFailure,
        policy: FailureScopePolicy,
    ) -> Result<FailureLadderOutcome> {
        let queue = AttemptQueue::new(self.vault);
        // 0/1/1a. Validate, point-read, and bind the scope before anything can
        // transition. The lease fence itself stays where it already is: inside
        // the queue's own retry/fail transition.
        let evidence_ref = validated_evidence_ref(&input.evidence)?;
        let current = queue
            .get(input.attempt_id)?
            .ok_or(Error::InvalidAttemptQueueTransition {
                action: "failure ladder",
                state: "missing",
            })?;
        require_dispatch_scope(&current, &policy.scope)?;

        // 2/3. Classify, then verify supplementary reports. No report decides
        // the class, and an unverifiable one never reaches a case or card.
        let class = classify_failure(&input.evidence);
        let context = FailureSurfaceContext {
            evidence_ref,
            blocked_reports: verified_blocked_reports(self.vault, &input.blocked_reports)?,
            pre_fail_checkpoint_ref: input.pre_fail_checkpoint_ref,
            qa_thread_ref: input.qa_thread_ref,
        };
        // Both healer-bound classes require typed evidence at step 0, so the
        // healer's required ref is proven present here — BEFORE any transition
        // — and a healer case can never be lost behind an already-failed row.
        if class != FailureClass::Ambiguous {
            require_evidence_ref(evidence_ref)?;
        }

        // 4. Exactly one bounded lineage walk, for every class.
        let walk = retry_lineage_walk(&queue, &current, policy.max_consecutive_transients)?;
        if let RetryOrdinal::Pathology(pathology) = &walk {
            // A pathology outranks every evidence class: the chain this row
            // sits in is unreadable, so the ordinal that would drive a retry
            // cannot be trusted. It surfaces as Ambiguous and never mints a
            // HealerCase.
            let failed_attempt = fail_once(&queue, &input)?;
            return Ok(FailureLadderOutcome::Human(context.surface(
                failed_attempt,
                FailureClass::Ambiguous,
                0,
                Some(pathology.clone()),
                None,
            )));
        }

        match class {
            FailureClass::Transient => self.route_transient(&queue, input, &policy, &context, walk),
            FailureClass::Permanent => {
                // The intact-lineage ordinal is discarded by policy: permanent
                // failures are stamped 0 rather than counted.
                let failed_attempt = fail_once(&queue, &input)?;
                self.route_healer(
                    failed_attempt,
                    &input,
                    &policy,
                    &context,
                    HealerRouting {
                        failure_class: FailureClass::Permanent,
                        consecutive_transients: 0,
                        evidence_ref: context.evidence_ref,
                    },
                )
            }
            FailureClass::Ambiguous => {
                let failed_attempt = fail_once(&queue, &input)?;
                Ok(FailureLadderOutcome::Human(context.surface(
                    failed_attempt,
                    FailureClass::Ambiguous,
                    0,
                    None,
                    None,
                )))
            }
        }
    }

    fn route_transient(
        &self,
        queue: &AttemptQueue<'_>,
        input: HandleAttemptFailure,
        policy: &FailureScopePolicy,
        context: &FailureSurfaceContext,
        walk: RetryOrdinal,
    ) -> Result<FailureLadderOutcome> {
        match walk {
            RetryOrdinal::BelowLimit(ordinal) => retry_once(queue, input, ordinal),
            RetryOrdinal::AtLimit(ordinal) => {
                let failed_attempt = fail_once(queue, &input)?;
                match policy.escalation_mode {
                    FailureEscalationMode::Auto => self.route_healer(
                        failed_attempt,
                        &input,
                        policy,
                        context,
                        HealerRouting {
                            failure_class: FailureClass::Transient,
                            consecutive_transients: ordinal.get(),
                            evidence_ref: context.evidence_ref,
                        },
                    ),
                    FailureEscalationMode::Human => {
                        Ok(FailureLadderOutcome::Human(context.surface(
                            failed_attempt,
                            FailureClass::Transient,
                            ordinal.get(),
                            None,
                            None,
                        )))
                    }
                }
            }
            RetryOrdinal::Pathology(_) => {
                unreachable!("a lineage pathology is routed before the class match")
            }
        }
    }

    fn route_healer(
        &self,
        failed_attempt: AttemptRecord,
        input: &HandleAttemptFailure,
        policy: &FailureScopePolicy,
        context: &FailureSurfaceContext,
        routing: HealerRouting,
    ) -> Result<FailureLadderOutcome> {
        let case = HealerCase {
            case_ref: failure_case_ref(failed_attempt.id),
            scope: policy.scope.clone(),
            failure_class: routing.failure_class,
            failing_attempt_id: failed_attempt.id,
            task_ref: failed_attempt.task_ref.clone(),
            evidence_ref: require_evidence_ref(routing.evidence_ref)?.to_hex(),
            blocked_reports: context.blocked_reports.clone(),
            pre_fail_checkpoint_ref: context.pre_fail_checkpoint_ref.to_hex(),
            qa_thread_ref: context.qa_thread_ref.to_hex(),
            consecutive_transients: routing.consecutive_transients,
        };
        let dispatched = AgentDispatcher::new(self.vault).dispatch_healer_slot(DispatchHealer {
            slot: policy.healer_slot.clone(),
            case: case.clone(),
            run_id: failed_attempt.run_id.clone(),
            now: input.now,
        });
        match dispatched {
            Ok(slot) => {
                let surface = context.surface(
                    failed_attempt.clone(),
                    routing.failure_class,
                    routing.consecutive_transients,
                    None,
                    Some(slot.clone()),
                );
                Ok(FailureLadderOutcome::Healer {
                    failed_attempt,
                    case,
                    slot,
                    surface,
                })
            }
            // The failing row is ALREADY terminal here, so a slot that cannot
            // be dispatched must not leave the case in limbo: the same
            // failed-attempt data goes straight to the human surface, which
            // composes as an explicit reserved healer slot.
            Err(_) => Ok(FailureLadderOutcome::Human(context.surface(
                failed_attempt,
                routing.failure_class,
                routing.consecutive_transients,
                None,
                None,
            ))),
        }
    }
}

/// Step 0: `stable_reason` must be non-empty, and every non-Indeterminate
/// verdict must carry BOTH `evidence_ref` and `tier`. Returns the parsed
/// evidence ref so no later arm re-parses caller text.
fn validated_evidence_ref(evidence: &TypedFailureEvidence) -> Result<Option<EntityId>> {
    if evidence.stable_reason.trim().is_empty() {
        return Err(Error::InvalidConfig(
            "typed failure evidence requires a non-empty stable_reason".to_owned(),
        ));
    }
    let indeterminate = evidence.verdict == TypedFailureVerdict::Indeterminate;
    if !indeterminate && (evidence.evidence_ref.is_none() || evidence.tier.is_none()) {
        return Err(Error::InvalidConfig(
            "a determinate failure verdict requires both evidence_ref and tier".to_owned(),
        ));
    }
    evidence
        .evidence_ref
        .as_deref()
        .map(|hex| {
            EntityId::from_hex(hex).map_err(|_| {
                Error::InvalidConfig(
                    "typed failure evidence_ref must be a hex-encoded EntityId string".to_owned(),
                )
            })
        })
        .transpose()
}

fn require_evidence_ref(evidence_ref: Option<EntityId>) -> Result<EntityId> {
    evidence_ref.ok_or(Error::InvalidConfig(
        "a healer-bound failure class requires typed evidence_ref".to_owned(),
    ))
}

/// Step 1a: the failing row must be an agent-dispatch row whose dispatched
/// target is exactly the policy scope's agent. `pre_fail_checkpoint_ref` and
/// `qa_thread_ref` stay caller-supplied: the trust basis is the lease fence,
/// because the caller is the authenticated executor of exactly this attempt.
fn require_dispatch_scope(record: &AttemptRecord, scope: &FailureScope) -> Result<()> {
    let expected = EntityId::from_hex(&scope.agent_ref).map_err(|_| {
        Error::InvalidConfig(
            "failure scope agent_ref must be a hex-encoded EntityId string".to_owned(),
        )
    })?;
    let Some(dispatched) = dispatched_target_ref(record) else {
        return Err(Error::InvalidConfig(
            "the failing attempt is not an agent dispatch row".to_owned(),
        ));
    };
    if dispatched != expected {
        return Err(Error::InvalidConfig(
            "the failure scope agent does not match the failing row's dispatched agent".to_owned(),
        ));
    }
    Ok(())
}

/// The dispatched AGENT_DEF ref of a queue row, read through the SAME pinned
/// codec the dispatch and landing-successor paths use.
fn dispatched_target_ref(record: &AttemptRecord) -> Option<EntityId> {
    if record.kind != DREAMER_RUNNER_ATTEMPT_KIND {
        return None;
    }
    let payload = decode_dreamer_attempt_payload(&record.payload).ok()?;
    if payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
        return None;
    }
    let AgentDispatchTarget::Custom(target) =
        decode_agent_dispatch_input(&payload.input).ok()?.target;
    Some(target)
}

fn verified_blocked_reports(
    vault: &Vault,
    reports: &[BlockedReportRef],
) -> Result<Vec<BlockedReportRef>> {
    Ok(verify_blocked_reports(vault, reports)?
        .into_iter()
        .filter_map(|verification| match verification {
            BlockedReportVerification::Verified(report) => Some(report),
            BlockedReportVerification::Dropped { .. } => None,
        })
        .collect())
}

/// The single terminal transition. `AlreadyFailed` means a concurrent failure
/// input won it, so the loser routes NOTHING — no healer dispatch, no card, no
/// surface — and returns the existing typed transition error.
fn fail_once(queue: &AttemptQueue<'_>, input: &HandleAttemptFailure) -> Result<AttemptRecord> {
    match queue.fail(FailAttempt {
        id: input.attempt_id,
        lease_owner: input.lease_owner.clone(),
        attempt_count: input.attempt_count,
        reason: input.evidence.stable_reason.clone(),
        now: input.now,
    })? {
        FailOutcome::Failed(record) => Ok(record),
        FailOutcome::AlreadyFailed(_) => Err(Error::InvalidAttemptQueueTransition {
            action: "failure ladder",
            state: "failed",
        }),
    }
}

/// The single retry transition. The schedule is NOT invented here: `retry_at`
/// comes from the caller's existing typed backoff policy and is forwarded to
/// the landed `backoff_until` field, which is the new row's `scheduled_at`.
fn retry_once(
    queue: &AttemptQueue<'_>,
    input: HandleAttemptFailure,
    ordinal: NonZeroU16,
) -> Result<FailureLadderOutcome> {
    let source_attempt_id = input.attempt_id;
    let RetryOutcome::Retried(scheduled_attempt) = queue.retry(RetryAttempt {
        id: source_attempt_id,
        lease_owner: input.lease_owner,
        attempt_count: input.attempt_count,
        backoff_until: input.retry_at,
        last_error: Some(input.evidence.stable_reason),
        now: input.now,
    })?;
    Ok(FailureLadderOutcome::Retried {
        source_attempt_id,
        scheduled_attempt,
        consecutive_transients: ordinal,
    })
}

#[cfg(test)]
mod tests;
