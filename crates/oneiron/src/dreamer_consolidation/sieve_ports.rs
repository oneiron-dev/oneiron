//! The sieve's and a child extraction's injected ports (OF-498a). An owed
//! sieve rung calls its [`SieveNoveltyPort`] for the rung's typed pack, and a
//! consolidation child calls its [`NeighbourhoodExtractionPort`] for its
//! scoped slices' extraction steps. A host injects its own through
//! `RoleBackends::with_extraction_ports`; the defaults,
//! [`RoleSieveNoveltyPort`] and [`RoleNeighbourhoodExtractionPort`], call the
//! roles the executor resolves exactly as before: extraction for novelty and
//! a child's slices, the verdict role for typing. Every port returns its
//! durable outcomes with each step's request hash and usage, so replay,
//! traps and charges run as they did. No dedicated runtime is required.

use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;

use super::call_labels::CallLabelMap;
use super::executor::extraction::CitationCheck;
use super::executor::{ConsolidationExecutor, Decider, ScopedRead};
use super::extracted_people::MintNamespace;
use super::failure_rules::{FailureRules, Stage};
use super::provenance::KeptDecision;
use super::roles::{DREAMER_EXTRACTION_ROLE, RoleCall};
use crate::dreamer_wake::WakePassDeadline;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::decision::{AskTo, DecisionQuestion, EvidenceVersion};
use crate::llm::manifest::ModelRole;
use crate::llm::{
    BudgetGuard, CallClass, CallEnvelope, CallPurpose, ContentPart, DurableStepContext,
    DurableStepError, DurableStepResult, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse,
    LlmUsage, ModelTierRef, ResponseFormat, Scope, StepOutcome, TierPrecedence,
    call_as_step_checked,
};

/// A port's work: a future on the caller's own async path.
pub type PortFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// The read an owed sieve rung calls for its span: the rung's typed pack.
pub trait SieveNoveltyPort: Send + Sync {
    /// `rung`'s pack, and each generation that finished, whatever came of it.
    fn read<'a>(&'a self, rung: SieveRungCall<'a>) -> PortFuture<'a, SieveRungRead>;
}

/// The extraction a consolidation child calls for its scoped slices.
pub trait NeighbourhoodExtractionPort: Send + Sync {
    /// One durable extraction step per slice of `child`, in slice order,
    /// each with its request hash. Every step runs to its own outcome; a
    /// failed one never cancels a sibling.
    fn extract<'a>(
        &'a self,
        child: NeighbourhoodExtraction<'a>,
    ) -> PortFuture<'a, DurableStepResult<Vec<SliceStep>>>;
}

/// One owed rung's read, as the sieve step hands it to its port.
pub struct SieveRungCall<'a> {
    /// The host's ladder, the Dreamer actor and the guard the pack reads on.
    pub(in crate::dreamer_consolidation) decider: Decider<'a>,
    /// The rung's role, and where its calls go as the executor resolves it.
    pub(in crate::dreamer_consolidation) role: ModelRole,
    pub(in crate::dreamer_consolidation) call: RoleCall<'a>,
    pub(in crate::dreamer_consolidation) step: &'a DurableStepContext<'a>,
    pub(in crate::dreamer_consolidation) pass: &'a WakePassDeadline,
    /// The vault's authored instruction for this rung.
    pub(in crate::dreamer_consolidation) instruction: &'a str,
    /// The span's exact source grants.
    pub(in crate::dreamer_consolidation) scope: &'a Scope,
    /// The body version of each source the span's read pinned, and their ids.
    pub(in crate::dreamer_consolidation) versions: &'a [EvidenceVersion],
    pub(in crate::dreamer_consolidation) evidence: &'a [EntityId],
    /// The work the pack's asks name: the rung's attempt.
    pub(in crate::dreamer_consolidation) correlation: EntityId,
    pub(in crate::dreamer_consolidation) questions: &'a [DecisionQuestion],
    pub(in crate::dreamer_consolidation) state: &'a serde_json::Value,
    pub(in crate::dreamer_consolidation) labels: &'a CallLabelMap,
}

/// What one owed rung's read came to.
pub enum SieveRungOutcome {
    /// Each pack question's kept decision, in pack order.
    Decided(Vec<KeptDecision>),
    /// The durable step suspended the attempt; it parks for resume.
    Trapped,
    /// The rung's role names no locality: nothing went out.
    NoLocality,
    /// The vault refused the rung's request for its role, its authorization
    /// or its reasoning binding: nothing more went out.
    Refused(Error),
}

/// A rung read's outcome, and each generation that finished (its request
/// hash and usage) whatever the outcome.
pub struct SieveRungRead {
    pub outcome: DurableStepResult<SieveRungOutcome>,
    pub steps: Vec<([u8; 32], LlmUsage)>,
}

/// One child's extraction, as the child hands it to its port.
pub struct NeighbourhoodExtraction<'a> {
    pub(in crate::dreamer_consolidation) step: &'a DurableStepContext<'a>,
    pub(in crate::dreamer_consolidation) guard: &'a BudgetGuard,
    /// The extraction role, as the executor resolves it.
    pub(in crate::dreamer_consolidation) call: RoleCall<'a>,
    pub(in crate::dreamer_consolidation) slices: Vec<SliceCall<'a>>,
    /// The namespace the people a reply declares are minted under.
    pub(in crate::dreamer_consolidation) namespace: MintNamespace,
    pub(in crate::dreamer_consolidation) rules: Option<&'a FailureRules>,
    /// Each reply's citations, read against the branch's own pinned text.
    pub(in crate::dreamer_consolidation) citations: Arc<CitationCheck>,
    /// How many slices run together.
    pub(in crate::dreamer_consolidation) width: usize,
}

impl<'a> SieveRungCall<'a> {
    /// The rung's role.
    #[must_use]
    pub const fn role(&self) -> ModelRole {
        self.role
    }

    /// Where the rung's calls go, as the executor resolves its role.
    #[must_use]
    pub const fn call(&self) -> &RoleCall<'a> {
        &self.call
    }

    /// The rung's durable-step context.
    #[must_use]
    pub const fn step(&self) -> &'a DurableStepContext<'a> {
        self.step
    }

    /// The wake pass the rung runs in.
    #[must_use]
    pub const fn pass(&self) -> &'a WakePassDeadline {
        self.pass
    }

    /// The vault's authored instruction for the rung.
    #[must_use]
    pub const fn instruction(&self) -> &'a str {
        self.instruction
    }

    /// The span's exact source grants.
    #[must_use]
    pub const fn scope(&self) -> &'a Scope {
        self.scope
    }

    /// The body version of each source the span's read pinned.
    #[must_use]
    pub const fn versions(&self) -> &'a [EvidenceVersion] {
        self.versions
    }

    /// The span's sources.
    #[must_use]
    pub const fn evidence(&self) -> &'a [EntityId] {
        self.evidence
    }

    /// The work the pack's asks name: the rung's attempt.
    #[must_use]
    pub const fn correlation(&self) -> EntityId {
        self.correlation
    }

    /// The pack's questions.
    #[must_use]
    pub const fn questions(&self) -> &'a [DecisionQuestion] {
        self.questions
    }

    /// The pack's state, as its questions read it.
    #[must_use]
    pub const fn state(&self) -> &'a serde_json::Value {
        self.state
    }
}

impl<'a> NeighbourhoodExtraction<'a> {
    /// The child's durable-step context: every slice's step is its.
    #[must_use]
    pub const fn step(&self) -> &'a DurableStepContext<'a> {
        self.step
    }

    /// The guard every slice's step spends on.
    #[must_use]
    pub const fn guard(&self) -> &'a BudgetGuard {
        self.guard
    }

    /// The extraction role, as the executor resolves it.
    #[must_use]
    pub const fn call(&self) -> &RoleCall<'a> {
        &self.call
    }

    /// How many slices the child has.
    #[must_use]
    pub fn slice_count(&self) -> usize {
        self.slices.len()
    }

    /// Slice `index`'s transcript, labels rendered in.
    #[must_use]
    pub fn slice_transcript(&self, index: usize) -> Option<&'a str> {
        self.slices.get(index).map(|slice| slice.transcript)
    }

    /// Slice `index`'s exact scope.
    #[must_use]
    pub fn slice_scope(&self, index: usize) -> Option<&'a Scope> {
        self.slices.get(index).map(|slice| slice.scope)
    }

    /// How many slices run together.
    #[must_use]
    pub const fn width(&self) -> usize {
        self.width
    }
}

/// One scoped slice of a child: its transcript, labels and exact scope, and
/// the rows its transcript was read from (FIX 6998).
pub(in crate::dreamer_consolidation) struct SliceCall<'a> {
    pub(in crate::dreamer_consolidation) transcript: &'a str,
    pub(in crate::dreamer_consolidation) labels: &'a CallLabelMap,
    pub(in crate::dreamer_consolidation) scope: &'a Scope,
    pub(in crate::dreamer_consolidation) sources: &'a [EntityId],
}

/// One slice's extraction step: its request hash and its outcome.
pub struct SliceStep {
    pub step_hash: [u8; 32],
    pub outcome: DurableStepResult<StepOutcome>,
}

/// The sieve's rungs on the executor's own roles: one generated pack per
/// rung through the host's ladder, as one call.
#[derive(Debug, Clone, Copy, Default)]
pub struct RoleSieveNoveltyPort;

/// A child's slices on the executor's extraction role, each a checked
/// durable step, run side by side up to the child's width.
#[derive(Debug, Clone, Copy, Default)]
pub struct RoleNeighbourhoodExtractionPort;

/// The ports the sieve's rungs and a child's extraction call.
#[derive(Clone)]
pub struct ExtractionPorts {
    sieve: Arc<dyn SieveNoveltyPort>,
    neighbourhood: Arc<dyn NeighbourhoodExtractionPort>,
}

impl Default for ExtractionPorts {
    /// The role defaults: today's resolved roles and backends.
    fn default() -> Self {
        Self {
            sieve: Arc::new(RoleSieveNoveltyPort),
            neighbourhood: Arc::new(RoleNeighbourhoodExtractionPort),
        }
    }
}

impl ExtractionPorts {
    /// `port` for the sieve's rungs.
    #[must_use]
    pub fn with_sieve_novelty(mut self, port: Arc<dyn SieveNoveltyPort>) -> Self {
        self.sieve = port;
        self
    }

    /// `port` for a child's extraction.
    #[must_use]
    pub fn with_neighbourhood_extraction(
        mut self,
        port: Arc<dyn NeighbourhoodExtractionPort>,
    ) -> Self {
        self.neighbourhood = port;
        self
    }

    pub(super) fn sieve_novelty(&self) -> &dyn SieveNoveltyPort {
        self.sieve.as_ref()
    }

    pub(super) fn neighbourhood_extraction(&self) -> &dyn NeighbourhoodExtractionPort {
        self.neighbourhood.as_ref()
    }
}

impl SieveNoveltyPort for RoleSieveNoveltyPort {
    fn read<'a>(&'a self, rung: SieveRungCall<'a>) -> PortFuture<'a, SieveRungRead> {
        Box::pin(read_rung(rung))
    }
}

impl NeighbourhoodExtractionPort for RoleNeighbourhoodExtractionPort {
    fn extract<'a>(
        &'a self,
        child: NeighbourhoodExtraction<'a>,
    ) -> PortFuture<'a, DurableStepResult<Vec<SliceStep>>> {
        Box::pin(extract_slices(child))
    }
}

/// One rung's pack on its own role: the authored instruction its request's
/// prompt, the span's grants its scope, best effort as before. The dial
/// stops at its first rung, so a rung is still one call.
async fn read_rung(rung: SieveRungCall<'_>) -> SieveRungRead {
    let mut steps = Vec::new();
    // A missing locality waits on no owner act: the rung resumes after its
    // retry delay (OF-193a).
    let Some(locality) = rung.call.inference.selected_locality() else {
        return SieveRungRead {
            outcome: Ok(SieveRungOutcome::NoLocality),
            steps,
        };
    };
    let vault = rung.step.vault;
    let refused = AtomicBool::new(false);
    let seal = |request: LlmRequest| -> Result<LlmRequest> {
        let sealed = vault
            .authorize_model_role(rung.role, request, &rung.call.inference)
            .and_then(|request| {
                let mut request = request.into_request();
                super::roles::bind_reasoning(vault, rung.call.backend, &mut request)?;
                Ok(request)
            });
        if sealed.is_err() {
            refused.store(true, Ordering::Relaxed);
        }
        sealed
    };
    let shell = LlmRequest {
        model: rung.call.model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: rung.scope.clone(),
            purpose: CallPurpose::Extraction,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Extraction,
                ModelTierRef("consolidation".into()),
            ),
            response_format: ResponseFormat::Text,
            locality,
            host_keyless: false,
        }
        .with_purpose_defaults(),
        messages: vec![LlmMessage {
            role: LlmMessageRole::System,
            content: vec![ContentPart::Text {
                text: rung.instruction.to_owned(),
            }],
        }],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    };
    // The rung never goes up the role chain: its asks name the owners only.
    let to = AskTo::owner();
    let decided = rung
        .decider
        .decide_scoped(
            ScopedRead {
                step: rung.step,
                pass: rung.pass,
                call: &rung.call,
                shell,
                seal: &seal,
                versions: rung.versions,
                to: &to,
                correlation: rung.correlation,
                evidence: rung.evidence,
                state: rung.state,
                ceiling: rung.decider.decisions.dial.first,
                // The rung's prompt is the vault's instruction and its
                // state is the span, read from exactly its pinned sources.
                sources: Some(rung.evidence.to_vec()),
            },
            rung.questions,
            rung.labels,
            &mut steps,
        )
        .await;
    let outcome = match decided {
        Ok(Some(decisions)) => Ok(SieveRungOutcome::Decided(decisions)),
        Ok(None) => Ok(SieveRungOutcome::Trapped),
        Err(DurableStepError::Engine(error)) if refused.load(Ordering::Relaxed) => {
            Ok(SieveRungOutcome::Refused(error))
        }
        Err(error) => Err(error),
    };
    SieveRungRead { outcome, steps }
}

/// A child's slices on its extraction role: each slice's request with the
/// child's failure rules bound, sealed for the role and checked against its
/// citations, all run side by side up to `width`.
async fn extract_slices(child: NeighbourhoodExtraction<'_>) -> DurableStepResult<Vec<SliceStep>> {
    let vault = child.step.vault;
    let mut requests = Vec::with_capacity(child.slices.len());
    for slice in &child.slices {
        let mut request = ConsolidationExecutor::extraction_request(
            &child.call,
            slice.transcript,
            slice.labels,
            slice.scope,
            &child.namespace,
        )?;
        if let Some(rules) = child.rules {
            rules.bind(Stage::Extraction, &mut request);
        }
        let mut request = vault
            .authorize_model_role(DREAMER_EXTRACTION_ROLE, request, &child.call.inference)?
            .into_request();
        super::roles::bind_reasoning(vault, child.call.backend, &mut request)?;
        requests.push((request.canonical_hash()?, request));
    }
    // Each slice's reply check reads the citations its candidates would
    // carry into verification against the branch's own pinned text: a range
    // verification refuses the whole partition over refuses the reply here,
    // never memoized (FIX 7274).
    let checks: Vec<_> = child
        .slices
        .iter()
        .map(|slice| {
            let citations = Arc::clone(&child.citations);
            let scope = slice.scope.clone();
            let labels = slice.labels.clone();
            move |response: &LlmResponse| citations.check(response, &scope, &labels)
        })
        .collect();
    // Each slice's call sends under exactly the rows its own transcript was
    // read from, never the branch's or a sibling's (FIX 6998).
    let backends: Vec<_> = child
        .slices
        .iter()
        .map(|slice| child.call.call_backend(Some(slice.sources.to_vec())))
        .collect();
    let jobs = requests
        .iter()
        .zip(&checks)
        .zip(&backends)
        .map(|(((_, request), check), backend)| {
            call_as_step_checked(
                child.step,
                backend.get(),
                child.guard,
                request.clone(),
                check,
            )
        })
        .collect();
    let outcomes = ordered_slots(jobs, child.width).await;
    Ok(requests
        .into_iter()
        .zip(outcomes)
        .map(|((step_hash, _), outcome)| SliceStep { step_hash, outcome })
        .collect())
}

/// Poll at most `width` children together. A ready error is just a slot
/// value: every admitted sibling drains, and outputs retain spawn order.
async fn ordered_slots<F: Future>(jobs: Vec<F>, width: usize) -> Vec<F::Output> {
    let count = jobs.len();
    let mut queued = jobs.into_iter().enumerate();
    let mut active: Vec<(usize, Pin<Box<F>>)> = Vec::new();
    let mut slots: Vec<Option<F::Output>> = (0..count).map(|_| None).collect();
    let mut completed = 0;
    poll_fn(|cx| {
        loop {
            while active.len() < width {
                let Some((index, job)) = queued.next() else {
                    break;
                };
                active.push((index, Box::pin(job)));
            }
            let mut progress = false;
            let mut index = 0;
            while index < active.len() {
                match active[index].1.as_mut().poll(cx) {
                    Poll::Ready(value) => {
                        let (slot, _) = active.remove(index);
                        slots[slot] = Some(value);
                        completed += 1;
                        progress = true;
                    }
                    Poll::Pending => index += 1,
                }
            }
            if completed == count {
                return Poll::Ready(());
            }
            if !progress {
                return Poll::Pending;
            }
        }
    })
    .await;
    slots
        .into_iter()
        .map(|slot| slot.expect("completed extraction slot"))
        .collect()
}
