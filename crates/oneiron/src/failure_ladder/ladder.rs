//! FailureLadder entry point, surface context, healer routing, and correlation refs.

use crate::Vault;
use crate::agent_dispatch::{AgentDispatcher, DispatchHealer, HealerSlotOutcome};
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};

use super::blocked_reports::BlockedReportRef;
use super::classify::{FailureClass, classify_failure};
use super::lineage::{
    FailureLadderOutcome, HandleAttemptFailure, HealerCase, RetryLineagePathology, RetryOrdinal,
    SurfacedFailure, retry_lineage_walk,
};
use super::scope::{FailureEscalationMode, FailureScopePolicy};
use super::transitions::{
    fail_once, require_dispatch_scope, require_evidence_ref, retry_once, validated_evidence_ref,
    verified_blocked_reports,
};

/// Domain separator for the deterministic `case_ref` correlation key.
const FAILURE_CASE_REF_DOMAIN: &[u8] = b"oneiron.failure-case.v1\0";

/// Domain separator for the deterministic `card_ref` correlation key.
const FAILURE_CARD_REF_DOMAIN: &[u8] = b"oneiron.failure-card.v1\0";

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
