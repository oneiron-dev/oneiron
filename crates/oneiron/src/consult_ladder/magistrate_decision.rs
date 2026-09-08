//! Novelty guard, magistrate evidence and rulings, decision layer, receipts.

use super::{EntityDeltaShape, InterruptionKind, LadderTerminalDisposition};
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;

/// Payload-level Dreamer attempt type for magistrate work, carried under the
/// existing outer `DREAMER_RUNNER_ATTEMPT_KIND` queue kind exactly like
/// `AGENT_DISPATCH_ATTEMPT_TYPE`. No new queue, admission, or lease machinery.
pub const DREAMER_MAGISTRATE_ATTEMPT_TYPE: &str = "dreamer.magistrate";

/// Domain separator for [`EntityDeltaShape::fingerprint`]. Pinned: a
/// fingerprint is compared against previously approved shapes across sessions
/// and replicas.
const DELTA_SHAPE_FINGERPRINT_DOMAIN: &[u8] = b"oneiron.consult_ladder.delta_shape.v1";

/// Structural fingerprint of one delta shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeltaShapeFingerprint(pub [u8; 32]);

impl EntityDeltaShape {
    /// Hashes the STRUCTURE of this shape — operation family, target class,
    /// and the set of normalized paths. Path ORDER is not structure, so the
    /// set is sorted first and two orderings of one shape fingerprint
    /// identically.
    #[must_use]
    pub fn fingerprint(&self) -> DeltaShapeFingerprint {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DELTA_SHAPE_FINGERPRINT_DOMAIN);
        hasher.update(&[self.target_entity_type]);
        hasher.update(self.operation_kind.as_bytes());
        hasher.update(&[0]);
        let mut paths: Vec<&str> = self
            .normalized_paths
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        paths.sort_unstable();
        for path in paths {
            hasher.update(path.as_bytes());
            hasher.update(&[0]);
        }
        DeltaShapeFingerprint(*hasher.finalize().as_bytes())
    }
}

/// The existing OF-399 / DEC-0006 narrow bound: op kind x target class x
/// skill/agent scope, between two named actors, backed by one standing grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraduationScope {
    pub proposer_actor_ref: EntityId,
    pub owning_actor_ref: EntityId,
    pub operation_kind: String,
    pub target_entity_type: u8,
    pub skill_or_agent_ref: Option<EntityId>,
    pub standing_grant_ref: EntityId,
}

impl GraduationScope {
    /// Whether this scope is the SAME bound the shape describes. A lookup
    /// answered under a different operation family or target class answers a
    /// different question.
    #[must_use]
    pub fn covers(&self, shape: &EntityDeltaShape) -> bool {
        self.operation_kind == shape.operation_kind
            && self.target_entity_type == shape.target_entity_type
    }
}

/// The existing OF-399 receipt history, as the narrow read this module needs.
///
/// ONE-1888 invents no threshold policy: the host answers both questions from
/// the standing grants and outcome receipts OF-399 already keeps.
pub trait GraduationLookup {
    /// Whether the exact scope currently holds a live standing grant.
    ///
    /// # Errors
    ///
    /// Any lookup failure is a string the guard treats as UNCERTAIN, which
    /// routes to consult.
    fn scope_is_graduated(&self, scope: &GraduationScope) -> std::result::Result<bool, String>;

    /// Whether this exact shape was already approved inside that exact scope.
    ///
    /// # Errors
    ///
    /// Any lookup failure is a string the guard treats as UNCERTAIN, which
    /// routes to consult.
    fn shape_was_approved(
        &self,
        scope: &GraduationScope,
        fingerprint: DeltaShapeFingerprint,
    ) -> std::result::Result<bool, String>;
}

/// What the novelty guard decided. Exactly one arm skips the owner consult.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoveltyDecision {
    AutoKnownShape { standing_grant_ref: EntityId },
    ConsultNoGrant,
    ConsultNovelShape { fingerprint: DeltaShapeFingerprint },
    ConsultUncertainShape,
}

/// The OF-399 novelty guard: a graduated pair may reuse its standing grant
/// only for a shape it has already been receipted on.
///
/// Every failure direction is CONSULT. An undecodable shape, a scope that
/// covers a different bound, and a lookup error all return an arm that mints
/// the owner-agent consult; graduation never becomes a wildcard bypass.
pub fn novelty_guard<L: GraduationLookup + ?Sized>(
    lookup: &L,
    scope: &GraduationScope,
    shape: &EntityDeltaShape,
) -> NoveltyDecision {
    if !shape.is_decodable() || !scope.covers(shape) {
        return NoveltyDecision::ConsultUncertainShape;
    }
    match lookup.scope_is_graduated(scope) {
        Err(_) => return NoveltyDecision::ConsultUncertainShape,
        Ok(false) => return NoveltyDecision::ConsultNoGrant,
        Ok(true) => {}
    }
    let fingerprint = shape.fingerprint();
    match lookup.shape_was_approved(scope, fingerprint) {
        Err(_) => NoveltyDecision::ConsultUncertainShape,
        Ok(true) => NoveltyDecision::AutoKnownShape {
            standing_grant_ref: scope.standing_grant_ref,
        },
        Ok(false) => NoveltyDecision::ConsultNovelShape { fingerprint },
    }
}

/// How compiled policy classifies the contested operation/state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaseCriticality {
    Normal,
    Critical,
}

/// What the OWNING agent's ordinary consult produced, before any routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerAgentOutcome {
    Approved,
    Rejected,
    Overridden,
    /// Owner agent and proposer remain in unresolved conflict.
    Contested,
    /// A typed invariant failure: missing/ambiguous owner, cyclic counter
    /// lineage, contradictory authority facts, malformed frontier, or a
    /// repeated no-progress loop.
    Pathological,
}

/// Where one owner-agent outcome goes next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LadderRoute {
    /// Settles with no human and no magistrate.
    Terminal(LadderTerminalDisposition),
    /// Normal-class contested: the Dreamer rules.
    DreamerMagistrate,
    /// The ONLY branches that admit a human.
    HumanConsent(InterruptionKind),
}

/// The complete human-entry matrix.
///
/// Ordinary approval, rejection, and override terminalize with no human at
/// all. Only contested-and-critical and pathological cases reach a person, and
/// normal-class contested goes to the Dreamer magistrate first. No other
/// branch exists, so no other branch can ask.
#[must_use]
pub const fn route_owner_agent_outcome(
    outcome: OwnerAgentOutcome,
    criticality: CaseCriticality,
) -> LadderRoute {
    match outcome {
        OwnerAgentOutcome::Approved => LadderRoute::Terminal(LadderTerminalDisposition::Approved),
        OwnerAgentOutcome::Rejected => LadderRoute::Terminal(LadderTerminalDisposition::Rejected),
        OwnerAgentOutcome::Overridden => {
            LadderRoute::Terminal(LadderTerminalDisposition::Overridden)
        }
        OwnerAgentOutcome::Pathological => LadderRoute::HumanConsent(InterruptionKind::Pathology),
        OwnerAgentOutcome::Contested => match criticality {
            CaseCriticality::Normal => LadderRoute::DreamerMagistrate,
            CaseCriticality::Critical => LadderRoute::HumanConsent(InterruptionKind::Critical),
        },
    }
}

/// WHO authored the contested state.
///
/// Derived only from vault claim/provenance envelopes by
/// `task_verb::derive_state_authorship`. It is deliberately absent from
/// [`MagistrateCase`]: a field a caller can set is a field a caller can forge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateAuthorship {
    Dreamer,
    OtherAgent,
    Human,
    System,
}

/// One applicable compiled policy and what it selects. `selected_delta_ref`
/// absent means the policy applies and selects NOTHING — an explicit refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyEvidence {
    pub policy_ref: EntityId,
    pub selected_delta_ref: Option<EntityId>,
}

/// One authority-over-state fact: who holds authoritative ownership of the
/// contested state, and what that owner selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorityEvidence {
    pub authoritative_actor_ref: EntityId,
    pub state_ref: EntityId,
    pub selected_delta_ref: Option<EntityId>,
}

/// One bitemporal fact: when the claim happened, when it was learned, and what
/// it supersedes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TemporalEvidence {
    pub occurred_at: u64,
    pub learned_at: u64,
    pub supersedes_ref: Option<EntityId>,
    pub selected_delta_ref: Option<EntityId>,
}

/// One contested case, assembled from the vault by `task_verb`.
///
/// It carries refs and evidence, never a summary of WHO wrote the state: that
/// is re-derived at decision time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagistrateCase {
    pub task_ref: EntityId,
    pub contested_state_ref: EntityId,
    pub contested_delta_ref: EntityId,
    pub criticality: CaseCriticality,
    pub policy: Vec<PolicyEvidence>,
    pub authority: Vec<AuthorityEvidence>,
    pub temporal: Vec<TemporalEvidence>,
    pub candidate_delta_refs: Vec<EntityId>,
    /// The runner attempt this case is being decided under, when it was
    /// enqueued as one. Absent for a direct in-process decision.
    pub dreamer_attempt_ref: Option<AttemptId>,
    pub now: u64,
}

/// Why the magistrate stood down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MagistrateRecusal {
    DreamerAuthoredState,
}

impl MagistrateRecusal {
    /// Stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DreamerAuthoredState => "dreamer_authored_state",
        }
    }
}

/// What the magistrate decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MagistrateVerdict {
    Rule {
        selected_delta_ref: EntityId,
        rationale_ref: EntityId,
    },
    Reject {
        rationale_ref: EntityId,
    },
    /// A critical case: evidence and a recommendation, but the TASK cannot be
    /// terminalized without a human verdict.
    AdviceOnly {
        recommended_delta_ref: Option<EntityId>,
        rationale_ref: EntityId,
    },
    Recused {
        reason: MagistrateRecusal,
    },
    EscalatePathology {
        rationale_ref: EntityId,
    },
}

impl MagistrateVerdict {
    /// Stable wire token for the variant.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rule { .. } => "rule",
            Self::Reject { .. } => "reject",
            Self::AdviceOnly { .. } => "advice_only",
            Self::Recused { .. } => "recused",
            Self::EscalatePathology { .. } => "escalate_pathology",
        }
    }
}

/// The ladder outcome a magistrate verdict may settle on, or `None` when the
/// magistrate is not permitted to terminalize the TASK at all.
///
/// Advice, recusal, and pathology all return `None`: those cases wait for a
/// human or a non-Dreamer owner. This is the structural half of "maximal
/// epistemic agency, minimal effector agency".
#[must_use]
pub const fn terminal_for_magistrate_verdict(
    verdict: MagistrateVerdict,
) -> Option<LadderTerminalDisposition> {
    match verdict {
        MagistrateVerdict::Rule { .. } => Some(LadderTerminalDisposition::Approved),
        MagistrateVerdict::Reject { .. } => Some(LadderTerminalDisposition::Rejected),
        MagistrateVerdict::AdviceOnly { .. }
        | MagistrateVerdict::Recused { .. }
        | MagistrateVerdict::EscalatePathology { .. } => None,
    }
}

/// Which layer of the strict order actually decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MagistrateDecisionLayer {
    CompiledPolicy,
    AuthorityOverState,
    Temporal,
    AdviceOnly,
    Recused,
    /// No layer decided: the case itself was malformed.
    Pathology,
}

impl MagistrateDecisionLayer {
    /// Stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CompiledPolicy => "compiled_policy",
            Self::AuthorityOverState => "authority_over_state",
            Self::Temporal => "temporal",
            Self::AdviceOnly => "advice_only",
            Self::Recused => "recused",
            Self::Pathology => "pathology",
        }
    }
}

/// The durable record of one magistrate decision: what was considered, what
/// was chosen, under whose run, and how to appeal it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagistrateReceipt {
    pub receipt_ref: EntityId,
    pub task_ref: EntityId,
    pub verdict: MagistrateVerdict,
    pub decisive_layer: MagistrateDecisionLayer,
    pub considered_policy_refs: Vec<EntityId>,
    pub considered_authority_refs: Vec<EntityId>,
    pub considered_temporal_refs: Vec<EntityId>,
    /// The runner attempt that produced the ruling, when it ran as one.
    pub dreamer_attempt_ref: Option<AttemptId>,
    /// The durable object an appeal is filed against — the ruled TASK.
    pub appeal_handle: EntityId,
    /// Structurally true: the magistrate's whole write set is receipt +
    /// supersession + conflict claim, and every one of those is reversible.
    pub reversible: bool,
    pub occurred_at: u64,
}

/// The complete ED training-signal handoff for one overturned ruling. The ED
/// lane may consume it later; this ticket writes it and stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MagistrateOverturnRecord {
    pub original_receipt_ref: EntityId,
    pub overturning_verdict_ref: EntityId,
    pub corrected_delta_ref: Option<EntityId>,
    pub rationale_ref: EntityId,
    pub occurred_at: u64,
}

/// One layer's answer: what it selected (if anything) and the decisive
/// evidence entity that justifies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LayerRuling {
    layer: MagistrateDecisionLayer,
    selected_delta_ref: Option<EntityId>,
    rationale_ref: EntityId,
}

/// The pure decision core.
///
/// Order of operations is load-bearing:
///
/// 1. **recusal** — Dreamer-authored state stands the magistrate down before a
///    single piece of evidence is weighed;
/// 2. **pathology** — a malformed case escalates rather than being ruled on;
/// 3. **compiled policy → authority-over-state → temporal**, strictly and
///    short-circuiting. This is an ORDER, never a weighted score: temporal
///    recency can no more overrule explicit policy than it can overrule
///    authoritative ownership;
/// 4. **criticality** — a critical case turns whatever the layers found into
///    advice, and cannot terminalize the TASK.
#[must_use]
pub(crate) fn decide_magistrate_from_derived_authorship(
    case: &MagistrateCase,
    authorship: StateAuthorship,
) -> MagistrateVerdict {
    if authorship == StateAuthorship::Dreamer {
        return MagistrateVerdict::Recused {
            reason: MagistrateRecusal::DreamerAuthoredState,
        };
    }
    if let Some(pathology) = case_pathology(case) {
        return pathology;
    }
    let ruling = policy_ruling(case)
        .or_else(|| authority_ruling(case))
        .or_else(|| temporal_ruling(case));
    let Some(ruling) = ruling else {
        // No policy, no authority, no temporal fact: the magistrate has
        // nothing to rule ON. That is a typed invariant failure, not a
        // licence to pick.
        return MagistrateVerdict::EscalatePathology {
            rationale_ref: case.contested_state_ref,
        };
    };
    if case.criticality == CaseCriticality::Critical {
        return MagistrateVerdict::AdviceOnly {
            recommended_delta_ref: ruling.selected_delta_ref,
            rationale_ref: ruling.rationale_ref,
        };
    }
    match ruling.selected_delta_ref {
        Some(selected_delta_ref) => MagistrateVerdict::Rule {
            selected_delta_ref,
            rationale_ref: ruling.rationale_ref,
        },
        None => MagistrateVerdict::Reject {
            rationale_ref: ruling.rationale_ref,
        },
    }
}

/// The typed invariant failures a case can carry into the magistrate.
fn case_pathology(case: &MagistrateCase) -> Option<MagistrateVerdict> {
    let escalate = || {
        Some(MagistrateVerdict::EscalatePathology {
            rationale_ref: case.contested_state_ref,
        })
    };
    if case.candidate_delta_refs.is_empty()
        || !case
            .candidate_delta_refs
            .contains(&case.contested_delta_ref)
    {
        return escalate();
    }
    let selections = case
        .policy
        .iter()
        .map(|entry| entry.selected_delta_ref)
        .chain(case.authority.iter().map(|entry| entry.selected_delta_ref))
        .chain(case.temporal.iter().map(|entry| entry.selected_delta_ref));
    for selected in selections.flatten() {
        if !case.candidate_delta_refs.contains(&selected) {
            return escalate();
        }
    }
    None
}

/// Compiled policy decides first. Two applicable policies that select
/// DIFFERENT deltas are contradictory authority facts, not a tie to break.
fn policy_ruling(case: &MagistrateCase) -> Option<LayerRuling> {
    let first = case.policy.first()?;
    if case
        .policy
        .iter()
        .any(|entry| entry.selected_delta_ref != first.selected_delta_ref)
    {
        return None;
    }
    Some(LayerRuling {
        layer: MagistrateDecisionLayer::CompiledPolicy,
        selected_delta_ref: first.selected_delta_ref,
        rationale_ref: first.policy_ref,
    })
}

/// With policy silent, the actor holding authoritative ownership decides.
fn authority_ruling(case: &MagistrateCase) -> Option<LayerRuling> {
    let first = case.authority.first()?;
    if case
        .authority
        .iter()
        .any(|entry| entry.selected_delta_ref != first.selected_delta_ref)
    {
        return None;
    }
    Some(LayerRuling {
        layer: MagistrateDecisionLayer::AuthorityOverState,
        selected_delta_ref: first.selected_delta_ref,
        rationale_ref: first.state_ref,
    })
}

/// Only with both silent does time decide: supersession first, then freshness.
fn temporal_ruling(case: &MagistrateCase) -> Option<LayerRuling> {
    let superseded: Vec<EntityId> = case
        .temporal
        .iter()
        .filter_map(|entry| entry.supersedes_ref)
        .collect();
    let live: Vec<&TemporalEvidence> = case
        .temporal
        .iter()
        .filter(|entry| {
            entry
                .selected_delta_ref
                .is_none_or(|selected| !superseded.contains(&selected))
        })
        .collect();
    let freshest = live
        .iter()
        .map(|entry| (entry.occurred_at, entry.learned_at))
        .max()?;
    let mut tied = live
        .iter()
        .filter(|entry| (entry.occurred_at, entry.learned_at) == freshest);
    let winner = tied.next()?;
    // An exact bitemporal tie between different deltas has no temporal answer.
    if tied.any(|entry| entry.selected_delta_ref != winner.selected_delta_ref) {
        return None;
    }
    Some(LayerRuling {
        layer: MagistrateDecisionLayer::Temporal,
        selected_delta_ref: winner.selected_delta_ref,
        rationale_ref: winner.supersedes_ref.unwrap_or(case.contested_state_ref),
    })
}

/// Which layer a verdict came from, for the receipt.
#[must_use]
pub(crate) fn magistrate_decision_layer(
    case: &MagistrateCase,
    verdict: MagistrateVerdict,
) -> MagistrateDecisionLayer {
    match verdict {
        MagistrateVerdict::Recused { .. } => MagistrateDecisionLayer::Recused,
        MagistrateVerdict::AdviceOnly { .. } => MagistrateDecisionLayer::AdviceOnly,
        MagistrateVerdict::EscalatePathology { .. } => MagistrateDecisionLayer::Pathology,
        MagistrateVerdict::Rule { .. } | MagistrateVerdict::Reject { .. } => policy_ruling(case)
            .or_else(|| authority_ruling(case))
            .or_else(|| temporal_ruling(case))
            .map_or(MagistrateDecisionLayer::Pathology, |ruling| ruling.layer),
    }
}
