//! Exact resource bounds for a consolidation partition. This is an additional
//! boundary, not read authority: source bytes still pass through ScopedRead,
//! and the promotion sink still owns the write gate and live ceiling.

use std::collections::{BTreeMap, BTreeSet};

use super::conflict::{candidate_facts, deterministic_claim_id, swarm_evidence_content_hash};

mod prior;
mod signals;
mod write;
use super::partition::ConsolidationPartitionKey;
use super::provenance::{ConsolidationSink, PromotionCandidate};
use super::support::invalid_consolidation;
use super::watermark::{TurnBodyFacts, decode_turn_body};
use crate::attempt_queue::AttemptId;
use crate::claim::{ScopedRead, ScopedReadActorKey};
use crate::dreamer_runner::{dreamer_extraction_role_admissible, dreamer_turn_role};
use crate::edge::EdgeKind;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::llm::{Scope, ScopeResource};
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
use crate::write_envelope::WriteActor;
use crate::{Result, Vault};
pub(crate) use write::ConsolidationFence;
pub use write::ScopedConsolidationWrite;

#[derive(Clone)]
struct SourcePin {
    resource: ScopeResource,
    entity_type: u8,
    learned_at: u64,
}

pub(super) struct BranchResources<'a> {
    read: ScopedRead<'a>,
    partition: ConsolidationPartitionKey,
    sources: BTreeMap<EntityId, SourcePin>,
    turns: BTreeSet<EntityId>,
    bucket: ScopeResource,
    output: ScopeResource,
    scope: Scope,
    attempt: AttemptId,
    signals: ScopeResource,
    priors: BTreeMap<EntityId, super::PriorHead>,
    rules: super::routing::PredicateKeyRules,
}

impl<'a> BranchResources<'a> {
    /// Admit the already queued partition, never a model-selected resource set.
    /// The executor checks the queued Dreamer actor before entering this door.
    pub(super) fn open(
        vault: &'a Vault,
        actor: WriteActor,
        partition: ConsolidationPartitionKey,
        turns: &[EntityId],
        attempt: AttemptId,
        requested: Option<&Scope>,
    ) -> Result<Self> {
        let actor_key = ScopedReadActorKey::with_actor_class(
            actor.entity_ref().to_hex(),
            actor.actor_class().gate_actor_class(),
        )
        .ok_or_else(|| invalid_consolidation("invalid consolidation read actor"))?;
        let read = vault.scoped_read(actor_key);
        let bucket = ScopeResource::Bucket {
            key: bytes_to_hex_lower(&partition.partition_hash()),
        };
        // Real sink boundary over the queued TURN slice. Its key is available
        // before enqueue; the future queue id is not permission a parent can
        // guess. Candidate/vector identities remain bound to the actual attempt.
        let output = output_projection(&partition, turns);
        let mut sources = BTreeMap::new();
        let mut readable = BTreeSet::from([bucket.clone()]);
        for id in std::iter::once(&partition.conversation_ref).chain(turns) {
            let (entity_type, learned_at, body) = read_source(&read, id)?;
            if (*id == partition.conversation_ref
                && !matches!(entity_type, ENTITY_TYPE_SESSION | ENTITY_TYPE_CONVERSATION))
                || (*id != partition.conversation_ref && entity_type != ENTITY_TYPE_TURN)
            {
                return Err(invalid_consolidation("invalid branch source type"));
            }
            let resource = document_version(*id, &body);
            readable.insert(resource.clone());
            sources.insert(
                *id,
                SourcePin {
                    resource,
                    entity_type,
                    learned_at,
                },
            );
        }
        // The queued/caller scope is an actual upper bound supplied by the
        // trusted host. It binds TURNs to relationship/project slices through
        // exact versions: neither axis is a TURN or conversation column.
        let mut granted = Scope {
            world: partition.world_ref,
            facet: partition.facet_ref,
            relationship: requested.and_then(|scope| scope.relationship),
            project: requested.and_then(|scope| scope.project),
            readable,
            writable: BTreeSet::from([output.clone()]),
        };
        let signals = signals_projection(&partition, turns);
        granted.readable.insert(signals.clone());
        granted
            .writable
            .insert(super::gap::branch_gap_projection(&partition, &granted));
        // Never replace explicit missing rights with generated defaults. Extra
        // exact documents are the caller's graph/project slice, not source TURNs.
        // A supplied scope is authority, not a request to infer more authority.
        let scope = requested.cloned().unwrap_or(granted);
        let mut resources = Self {
            read,
            partition,
            sources,
            turns: turns.iter().copied().collect(),
            bucket,
            output,
            scope,
            attempt,
            signals,
            priors: BTreeMap::new(),
            rules: vault.consolidation_key_rules()?,
        };
        resources.check_axes(&resources.scope)?;
        resources.source(&resources.scope, &partition.conversation_ref)?;
        // Membership and coordinates are structural admission, not prompt text.
        for turn in turns {
            resources.turn(&resources.scope, turn)?;
        }
        resources.admit_priors()?;
        Ok(resources)
    }

    pub(super) fn key_rules(&self) -> &super::routing::PredicateKeyRules {
        &self.rules
    }

    pub(super) fn scope(&self) -> &Scope {
        &self.scope
    }

    fn check_axes(&self, scope: &Scope) -> Result<()> {
        if !scope.readable.is_subset(&self.scope.readable)
            || !scope.writable.is_subset(&self.scope.writable)
            || scope.world != self.partition.world_ref
            || scope.facet != self.partition.facet_ref
            || scope.relationship != self.scope.relationship
            || scope.project != self.scope.project
        {
            return Err(invalid_consolidation("branch source axes do not match"));
        }
        Ok(())
    }

    fn source(&self, scope: &Scope, id: &EntityId) -> Result<(u64, Vec<u8>)> {
        self.check_axes(scope)?;
        let pin = self
            .sources
            .get(id)
            .ok_or_else(|| invalid_consolidation("unlisted branch document"))?;
        if !scope.allows_read(&self.bucket) || !scope.allows_read(&pin.resource) {
            return Err(invalid_consolidation("branch document read refused"));
        }
        let (entity_type, learned_at, body) = read_source(&self.read, id)?;
        if entity_type != pin.entity_type
            || learned_at != pin.learned_at
            || document_version(*id, &body) != pin.resource
        {
            return Err(invalid_consolidation("branch source revision changed"));
        }
        Ok((learned_at, body))
    }

    pub(super) fn turn(&self, scope: &Scope, id: &EntityId) -> Result<TurnBodyFacts> {
        if !self.turns.contains(id) {
            return Err(invalid_consolidation("unlisted branch turn"));
        }
        let (_, body) = self.source(scope, id)?;
        let (_, conversation) = self.source(scope, &self.partition.conversation_ref)?;
        let facts = decode_turn_body(&body);
        let parent = decode_turn_body(&conversation);
        let edges = self.read.edges_out(id)?;
        if edges.receipt.suppressed_count != 0 {
            return Err(invalid_consolidation("branch turn graph is incomplete"));
        }
        let edges = edges
            .value
            .ok_or_else(|| invalid_consolidation("branch turn is not readable"))?;
        let parents: Vec<_> = edges
            .iter()
            .filter(|edge| edge.kind == EdgeKind::ChildOf)
            .collect();
        if parents.len() != 1
            || parents[0].target != self.partition.conversation_ref
            || facts.world_ref.or(parent.world_ref) != self.partition.world_ref
            || facts.facet_ref.or(parent.facet_ref) != self.partition.facet_ref
            || !dreamer_extraction_role_admissible(dreamer_turn_role(
                facts.speaker.as_deref(),
                &self.read.vault().config.assistant_display_names,
            ))
        {
            return Err(invalid_consolidation("branch turn crossed its partition"));
        }
        Ok(facts)
    }

    pub(super) fn transcript(&self, scope: &Scope, turns: &[EntityId]) -> Result<String> {
        let mut transcript = String::new();
        for id in turns {
            let facts = self.turn(scope, id)?;
            transcript.push_str(&format!(
                "[{} {}] {}\n",
                id.to_hex(),
                facts.speaker.as_deref().unwrap_or("unknown"),
                facts.text.as_deref().unwrap_or_default()
            ));
        }
        Ok(transcript)
    }

    pub(super) fn evidence_time(&self, scope: &Scope, id: &EntityId) -> Result<u64> {
        self.turn(scope, id)?;
        Ok(self.source(scope, id)?.0)
    }

    pub(super) fn require_output(&self, scope: &Scope) -> Result<()> {
        self.check_axes(scope)?;
        if !scope.allows_write(&self.output) {
            return Err(invalid_consolidation("branch projection write refused"));
        }
        Ok(())
    }

    pub(super) fn validate_candidates(
        &self,
        scope: &Scope,
        candidates: &[PromotionCandidate],
    ) -> Result<()> {
        self.require_output(scope)?;
        for candidate in candidates {
            let facts = candidate_facts(&candidate.candidate)?;
            if facts.world != scope.world
                || facts.facet != scope.facet
                || scope.relationship.is_some_and(|rel| facts.rel != Some(rel))
                || candidate.supersedes.is_some()
                || !candidate.provenance_chain.is_empty()
                || candidate.claim_id
                    != deterministic_claim_id(
                        self.attempt,
                        facts.subject,
                        &facts.predicate,
                        &facts.value,
                        facts.world,
                        facts.facet,
                        facts.rel,
                    )
            {
                return Err(invalid_consolidation("candidate crossed its branch scope"));
            }
            for id in &candidate.evidence_turn_refs {
                self.turn(scope, id)?;
            }
        }
        Ok(())
    }

    pub(super) fn upsert_gaps(
        &self,
        scope: &Scope,
        gaps: Vec<super::gap::ReflectionGap>,
        now: u64,
    ) -> Result<super::gap::GapQueueDelta> {
        self.check_axes(scope)?;
        for gap in &gaps {
            for turn in &gap.evidence_turn_refs {
                self.turn(scope, turn)?;
            }
        }
        super::gap::upsert_branch_gap_queue(self.read.vault(), scope, &self.partition, gaps, now)
    }

    pub(super) fn accept(
        &self,
        scope: &Scope,
        sink: &mut dyn ConsolidationSink,
        candidates: Vec<PromotionCandidate>,
    ) -> Result<()> {
        let write = self.prepare_write(scope, candidates)?;
        sink.accept_scoped(write)
    }
}

fn read_source(read: &ScopedRead<'_>, id: &EntityId) -> Result<(u8, u64, Vec<u8>)> {
    // Restrict the type BEFORE asking for bytes, including at the custody door.
    if !matches!(
        read.vault().get_entity_type(id)?,
        Some(ENTITY_TYPE_TURN | ENTITY_TYPE_SESSION | ENTITY_TYPE_CONVERSATION)
    ) {
        return Err(invalid_consolidation(
            "branch source is not a turn or conversation",
        ));
    }
    read.get_entity_parts(id)?
        .ok_or_else(|| invalid_consolidation("branch source is not readable"))
}

pub(super) fn document_version(document: EntityId, body: &[u8]) -> ScopeResource {
    ScopeResource::DocumentVersion {
        document,
        version: format!(
            "blake3:{}",
            bytes_to_hex_lower(&swarm_evidence_content_hash(body))
        ),
    }
}

/// Named mechanical projection for the real queued TURN slice. Its scope
/// supplies axis bounds and exact document pins; queries bind to branch output.
pub(super) fn signals_projection(
    partition: &ConsolidationPartitionKey,
    turns: &[EntityId],
) -> ScopeResource {
    ScopeResource::Projection {
        key: format!("dreamer:signals:v1:{}", branch_key(partition, turns)),
    }
}

pub(super) fn output_projection(
    partition: &ConsolidationPartitionKey,
    turns: &[EntityId],
) -> ScopeResource {
    ScopeResource::Projection {
        key: format!("dreamer:consolidation:v1:{}", branch_key(partition, turns)),
    }
}

fn branch_key(partition: &ConsolidationPartitionKey, turns: &[EntityId]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron:dreamer-branch-resources:v1");
    hasher.update(&partition.partition_hash());
    hasher.update(&(turns.len() as u64).to_be_bytes());
    for turn in turns {
        hasher.update(turn.as_bytes());
    }
    bytes_to_hex_lower(hasher.finalize().as_bytes())
}
