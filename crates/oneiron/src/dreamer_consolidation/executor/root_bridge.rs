//! Accepted root judgements enter the normal conflict and sealed-write path.
use super::*;
use crate::dreamer_consolidation::evidence::EvidenceLocator;
use crate::dreamer_consolidation::root_evidence::bridge::RootPayload;
use crate::dreamer_runner::DreamerAdmittedAttempt;

impl ConsolidationExecutor<'_> {
    pub(super) async fn run_root_bridge(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        let payload = RootPayload::decode(&attempt.status.payload.input)?;
        let mut stages = PartitionStages::start(0);
        let turns: BTreeSet<_> = payload
            .children
            .iter()
            .flat_map(|child| &child.evidence)
            .filter(|reference| reference.claim_id.is_none())
            .map(|reference| &reference.source_id)
            .collect();
        let executed = self
            .run_root_candidates(attempt, ctx, &payload, &mut stages)
            .await;
        stages.log(attempt, turns.len(), &executed);
        executed
    }

    async fn run_root_candidates(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
        payload: &RootPayload,
        stages: &mut PartitionStages,
    ) -> Result<DreamerAttemptExecution> {
        let opened = std::time::Instant::now();
        let resources = BranchResources::open_root_pinned(
            ctx.vault,
            self.actor,
            payload,
            attempt.status.attempt.id,
            self.scope.as_ref(),
        );
        stages.branch_ms = super::super::stage_log::ms_since(opened);
        let resources = match resources {
            Err(error) if super::super::residency::waits_on_residency(&error) => {
                return Ok(super::super::residency::residency_deferral(
                    ctx.now_ms,
                    0,
                    Vec::new(),
                ));
            }
            resources => resources?,
        };
        let key = resources.root_bucket()?;
        let candidates = payload
            .children
            .iter()
            .map(|child| {
                let value = json_to_rmpv(&child.judgement.value);
                let identity = ConflictIdentity {
                    subject: key.subject,
                    predicate: child.judgement.predicate.clone(),
                    world: key.world,
                    facet: key.facet,
                    rel: key.rel.clone(),
                    project: key.project,
                    topic: None,
                };
                let mut candidate = ClaimCandidate::new(
                    identity.predicate.clone(),
                    ClaimSubject::Entity(identity.subject),
                    value.clone(),
                    child.judgement.confidence,
                )
                .with_relationships(identity.rel.clone())
                .with_scope(super::super::persistence::identity_scope(&identity)?);
                if let Some(world) = identity.world {
                    candidate = candidate.with_world(world);
                }
                let at = ctx.now_ms / 1_000;
                let proposal = PromotionCandidate {
                    claim_id: deterministic_claim_id(
                        attempt.status.attempt.id,
                        identity.subject,
                        &identity.predicate,
                        &value,
                        identity.world,
                        identity.facet,
                        identity.rel.as_ref(),
                        identity.project,
                        None,
                    )?,
                    candidate,
                    evidence_turn_refs: Vec::new(),
                    provenance_chain: Vec::new(),
                    supersedes: None,
                    evidence_meet: ClaimSource::Generated,
                    occurred: TimeRange { start: at, end: at },
                    learned_at: at,
                    decisions: Vec::new(),
                };
                let refs = child
                    .evidence
                    .iter()
                    .map(|reference| {
                        let source = EntityId::from_hex(&reference.source_id)?;
                        match (&reference.claim_id, reference.byte_range) {
                            (Some(claim), None) => {
                                EvidenceLocator::claim(source, EntityId::from_hex(claim)?)
                            }
                            (None, Some((start, end))) => {
                                EvidenceLocator::turn_range(source, start, end)
                            }
                            _ => Err(invalid_consolidation("invalid root evidence locator")),
                        }
                    })
                    .collect::<Result<Vec<_>>>()?;
                ExtractedCandidate::new(proposal, refs)
            })
            .collect::<Result<Vec<_>>>()?;
        let mut charges = StepChargeTally::default();
        let resolving = std::time::Instant::now();
        let run = self
            .resolve_conflicts(
                candidates,
                &resources,
                ctx,
                (
                    attempt.status.attempt.id,
                    attempt.status.attempt.run_id.clone(),
                ),
                &mut charges,
                stages,
            )
            .await;
        stages.resolve_ms =
            super::super::stage_log::ms_since(resolving).saturating_sub(stages.gap_ms);
        self.settle_partition_run(
            &resources,
            run,
            &[],
            None,
            &[],
            &[],
            ctx,
            &mut charges,
            stages,
        )
        .await
    }
}
