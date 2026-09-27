//! Exact resource bounds for a consolidation partition. This is an additional
//! boundary, not read authority: source bytes still pass through ScopedRead,
//! and the promotion sink still owns the write gate and live ceiling.

use std::collections::{BTreeMap, BTreeSet};

use super::conflict::{
    SwarmEvidenceRef, VerifiedSwarmEvidence, candidate_facts, deterministic_claim_id,
    swarm_evidence_content_hash, turn_trust_class,
};

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
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN,
};
use crate::write_envelope::WriteActor;
use crate::{Result, Vault};
pub(crate) use write::ConsolidationFence;
pub use write::ScopedConsolidationWrite;

/// Source bodies frozen by the Dreamer at ONE ledger snapshot, before the
/// wake starts any writes. The read transaction closes immediately after this
/// bounded projection; a wake never holds an LMDB reader slot across writes.
#[derive(Debug, Default)]
pub struct WakeEvidenceSnapshot {
    sources: BTreeMap<EntityId, (u8, u64, Vec<u8>)>,
    attempts: BTreeSet<[u8; 16]>,
    retry_turns: BTreeMap<[u8; 16], Vec<super::WorkingSetTurn>>,
}

impl WakeEvidenceSnapshot {
    #[cfg(test)]
    pub(crate) fn capture(
        vault: &Vault,
        scope: crate::dreamer_runner::DreamerConsolidationScope,
    ) -> Result<Self> {
        Self::capture_with_grants(vault, scope, None)
    }

    pub(crate) fn capture_with_grants(
        vault: &Vault,
        scope: crate::dreamer_runner::DreamerConsolidationScope,
        caller_scope: Option<&Scope>,
    ) -> Result<Self> {
        use crate::ports::EdgeDirection;
        let txn = vault.store.env.read_txn()?;
        let records = crate::attempt_queue::AttemptQueue::new(vault).list_in_txn(&txn)?;
        let mut ids = BTreeSet::new();
        let mut attempts = BTreeSet::new();
        let mut retries = Vec::new();
        for attempt in records {
            if attempt.kind != scope.attempt_kind() || attempt.state.is_terminal() {
                continue;
            }
            attempts.insert(*attempt.id.as_bytes());
            // A malformed queued row is not a source grant. Its own executor
            // still refuses it, without failing unrelated wake work here.
            let Ok(payload) =
                crate::dreamer_runner::decode_dreamer_attempt_payload(&attempt.payload)
            else {
                continue;
            };
            let Ok((partition, turns, watermark)) =
                super::partition::decode_partition_payload(&payload.input)
            else {
                continue;
            };
            ids.insert(partition.conversation_ref);
            ids.extend(turns.iter().copied());
            if attempt.retry_of.is_some()
                && super::branch_scope::decode_branch_scope(&payload.input)?.is_none()
            {
                // The retry enumerator is bounded by the normal graph query
                // ceiling; unlike a live per-attempt read these ids and bodies
                // now come from this ONE wake revision.
                let peers = vault.filtered_edge_peers(
                    &txn,
                    EdgeDirection::In,
                    &partition.conversation_ref,
                    EdgeKind::ChildOf,
                    Some(ENTITY_TYPE_TURN),
                    "selection retry wake source scan",
                )?;
                ids.extend(peers.iter().copied());
                retries.push((*attempt.id.as_bytes(), partition, turns, watermark, peers));
            }
            // Exact queued claim grants can cite admitted prior CLAIMs.
            if let Some(bound) = super::branch_scope::decode_branch_scope(&payload.input)? {
                for resource in &bound.readable {
                    if let ScopeResource::DocumentVersion { document, .. } = resource
                        && vault.get_entity_type_in_txn(&txn, document)? == Some(ENTITY_TYPE_CLAIM)
                    {
                        ids.insert(*document);
                    }
                }
            }
        }
        // A host-supplied attenuation may carry additional exact prior CLAIM
        // grants not serialized into queued input. Pin them at this SAME txn;
        // BranchResources still admits only the effective exact scope.
        if let Some(bound) = caller_scope {
            for resource in &bound.readable {
                if let ScopeResource::DocumentVersion { document, .. } = resource
                    && vault.get_entity_type_in_txn(&txn, document)? == Some(ENTITY_TYPE_CLAIM)
                {
                    ids.insert(*document);
                }
            }
        }
        if ids.is_empty() {
            return Ok(Self {
                attempts,
                ..Self::default()
            });
        }
        let actor = vault.dreamer_authority()?;
        let key = ScopedReadActorKey::with_actor_class(
            actor.entity_ref().to_hex(),
            actor.actor_class().gate_actor_class(),
        )
        .ok_or_else(|| invalid_consolidation("invalid consolidation read actor"))?;
        let read = vault.scoped_read(key);
        let source_ids: Vec<_> = ids.into_iter().collect();
        let rows = read.get_entities_parts_in_txn(&txn, &source_ids)?;
        let sources: BTreeMap<_, _> = source_ids
            .into_iter()
            .zip(rows)
            .filter_map(|(id, row)| row.map(|body| (id, body)))
            .collect();
        let mut retry_turns = BTreeMap::new();
        for (attempt, partition, original, watermark, peers) in retries {
            let parent = sources
                .get(&partition.conversation_ref)
                .ok_or_else(|| invalid_consolidation("selection retry parent not readable"))?;
            let parent = decode_turn_body(&parent.2);
            let original: BTreeSet<_> = original.into_iter().collect();
            let mut turns = Vec::new();
            for id in peers {
                let Some((kind, learned_at, bytes)) = sources.get(&id) else {
                    continue;
                };
                if *kind != ENTITY_TYPE_TURN {
                    continue;
                }
                let facts = decode_turn_body(bytes);
                let role = dreamer_turn_role(
                    facts.speaker.as_deref(),
                    &vault.config.assistant_display_names,
                );
                if dreamer_extraction_role_admissible(role)
                    && facts.world_ref.or(parent.world_ref) == partition.world_ref
                    && facts.facet_ref.or(parent.facet_ref) == partition.facet_ref
                    && (original.contains(&id) || *learned_at >= watermark)
                {
                    turns.push((*learned_at, id));
                }
            }
            turns.sort_unstable();
            if turns.len() > 1_024
                || !original
                    .iter()
                    .all(|id| turns.iter().any(|(_, got)| got == id))
            {
                return Err(invalid_consolidation(
                    "selection retry source limit or membership changed",
                ));
            }
            retry_turns.insert(
                attempt,
                turns
                    .into_iter()
                    .map(|(learned_at, turn_id)| {
                        let facts = decode_turn_body(&sources[&turn_id].2);
                        super::WorkingSetTurn {
                            turn_id,
                            role: dreamer_turn_role(
                                facts.speaker.as_deref(),
                                &vault.config.assistant_display_names,
                            ),
                            learned_at,
                            conversation: Some(partition.conversation_ref),
                        }
                    })
                    .collect(),
            );
        }
        Ok(Self {
            sources,
            attempts,
            retry_turns,
        })
    }

    /// Only work known at the wake's single revision may execute on it.
    pub(crate) fn contains_attempt(&self, id: AttemptId) -> bool {
        self.attempts.contains(id.as_bytes())
    }

    pub(in crate::dreamer_consolidation) fn retry_turns(
        &self,
        id: AttemptId,
    ) -> Option<&[super::WorkingSetTurn]> {
        self.retry_turns.get(id.as_bytes()).map(Vec::as_slice)
    }

    fn source(&self, id: &EntityId) -> Option<(u8, u64, Vec<u8>)> {
        self.sources.get(id).cloned()
    }
}

#[derive(Clone)]
struct SourcePin {
    resource: ScopeResource,
    entity_type: u8,
    learned_at: u64,
    trust_class: Option<crate::claim::ClaimSource>,
    body: Vec<u8>,
}

pub(super) struct BranchResources<'a> {
    read: ScopedRead<'a>,
    ledger_pin: Option<&'a WakeEvidenceSnapshot>,
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
    #[cfg(test)]
    pub(super) fn open(
        vault: &'a Vault,
        actor: WriteActor,
        partition: ConsolidationPartitionKey,
        turns: &[EntityId],
        attempt: AttemptId,
        requested: Option<&Scope>,
    ) -> Result<Self> {
        Self::open_at_pin(vault, actor, partition, turns, attempt, requested, None)
    }

    pub(super) fn open_at_pin(
        vault: &'a Vault,
        actor: WriteActor,
        partition: ConsolidationPartitionKey,
        turns: &[EntityId],
        attempt: AttemptId,
        requested: Option<&Scope>,
        ledger_pin: Option<&'a WakeEvidenceSnapshot>,
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
        // One LMDB read transaction pins all branch sources at one ledger
        // revision. Later reads and the write fence must match these pins.
        let source_ids: Vec<_> = std::iter::once(partition.conversation_ref)
            .chain(turns.iter().copied())
            .collect();
        let source_rows = if let Some(pin) = ledger_pin {
            source_ids.iter().map(|id| pin.source(id)).collect()
        } else {
            read.get_entities_parts_with_receipt(&source_ids, None)?
                .value
        };
        for (id, row) in source_ids.iter().zip(source_rows) {
            let (entity_type, learned_at, body) =
                row.ok_or_else(|| invalid_consolidation("branch source is not readable"))?;
            if (*id == partition.conversation_ref
                && !matches!(entity_type, ENTITY_TYPE_SESSION | ENTITY_TYPE_CONVERSATION))
                || (*id != partition.conversation_ref && entity_type != ENTITY_TYPE_TURN)
            {
                return Err(invalid_consolidation("invalid branch source type"));
            }
            let resource = document_version(*id, &body);
            readable.insert(resource.clone());
            let trust_class = (entity_type == ENTITY_TYPE_TURN)
                .then(|| {
                    let facts = decode_turn_body(&body);
                    turn_trust_class(
                        dreamer_turn_role(
                            facts.speaker.as_deref(),
                            &vault.config.assistant_display_names,
                        ),
                        false,
                    )
                })
                .flatten();
            sources.insert(
                *id,
                SourcePin {
                    resource,
                    entity_type,
                    learned_at,
                    trust_class,
                    body,
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
            ledger_pin,
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
        let (entity_type, learned_at, body) = if pin.entity_type == ENTITY_TYPE_CLAIM {
            self.prior(*id)?;
            self.read
                .get_entity_parts_with_receipt(id, None)?
                .value
                .ok_or_else(|| invalid_consolidation("admitted prior not readable"))?
        } else {
            read_source(&self.read, id)?
        };
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

    /// Parent-only evidence accounting: one actor-scoped read transaction for
    /// every cited source, then content hash and source classification. Both
    /// the branch pins and the sink's live fence reject revision drift.
    pub(in crate::dreamer_consolidation) fn verify_evidence_refs(
        &self,
        refs: &[SwarmEvidenceRef],
    ) -> Result<Vec<VerifiedSwarmEvidence>> {
        self.check_axes(&self.scope)?;
        let ids: Vec<_> = refs.iter().map(|entry| entry.source_id).collect();
        for entry in refs {
            if let Some(claim) = entry.claim_id {
                if claim != entry.source_id
                    || entry.byte_range.is_some()
                    || !self.priors.contains_key(&claim)
                {
                    return Err(invalid_consolidation("unadmitted branch claim evidence"));
                }
            } else if !self.turns.contains(&entry.source_id) {
                return Err(invalid_consolidation("unlisted branch evidence"));
            }
            let pin = self
                .sources
                .get(&entry.source_id)
                .ok_or_else(|| invalid_consolidation("unlisted branch evidence"))?;
            if !self.scope.allows_read(&self.bucket) || !self.scope.allows_read(&pin.resource) {
                return Err(invalid_consolidation("branch evidence read refused"));
            }
        }
        let source_rows = if let Some(pin) = self.ledger_pin {
            ids.iter().map(|id| pin.source(id)).collect()
        } else {
            self.read.get_entities_parts_with_receipt(&ids, None)?.value
        };
        refs.iter()
            .zip(source_rows)
            .map(|(entry, row)| {
                let (kind, learned_at, body) =
                    row.ok_or_else(|| invalid_consolidation("branch evidence is not readable"))?;
                let pin = &self.sources[&entry.source_id];
                if kind != pin.entity_type
                    || learned_at != pin.learned_at
                    || document_version(entry.source_id, &body) != pin.resource
                {
                    return Err(invalid_consolidation("branch evidence revision changed"));
                }
                let trust_class = if entry.claim_id.is_some() {
                    if kind != crate::registry::ENTITY_TYPE_CLAIM {
                        return Err(invalid_consolidation("branch claim evidence type changed"));
                    }
                    let claim = crate::claim::decode_claim_body(&body, true)?;
                    if !crate::claim::claim_evidence_admissible(&claim) {
                        return Err(invalid_consolidation("generated claim cannot corroborate"));
                    }
                    let source = claim.source.unwrap_or(crate::claim::ClaimSource::Imported);
                    crate::dreamer_consolidation::provenance::source_meet(
                        source,
                        crate::claim::claim_evidence_taint(&claim).unwrap_or(source),
                    )
                } else {
                    if kind != crate::registry::ENTITY_TYPE_TURN {
                        return Err(invalid_consolidation("branch turn evidence type changed"));
                    }
                    let facts = decode_turn_body(&body);
                    let role = dreamer_turn_role(
                        facts.speaker.as_deref(),
                        &self.read.vault().config.assistant_display_names,
                    );
                    turn_trust_class(role, false)
                        .ok_or_else(|| invalid_consolidation("inadmissible branch evidence role"))?
                };
                let bytes = if let Some((start, end)) = entry.byte_range {
                    body.get(start..end)
                        .ok_or_else(|| invalid_consolidation("invalid evidence byte range"))?
                } else {
                    &body
                };
                Ok(VerifiedSwarmEvidence {
                    source_id: entry.source_id,
                    content_hash: swarm_evidence_content_hash(bytes),
                    trust_class,
                })
            })
            .collect()
    }

    pub(super) fn evidence_time(&self, scope: &Scope, id: &EntityId) -> Result<u64> {
        if self.turns.contains(id) {
            self.turn(scope, id)?;
        } else {
            self.prior(*id)?;
        }
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
                        facts.topic.as_deref(),
                    )
            {
                return Err(invalid_consolidation("candidate crossed its branch scope"));
            }
            let locators = super::conflict::candidate_locators(candidate)?;
            let cited: BTreeSet<_> = locators.iter().map(|entry| entry.source_id).collect();
            let projected: BTreeSet<_> = candidate.evidence_turn_refs.iter().copied().collect();
            if cited != projected {
                return Err(invalid_consolidation(
                    "evidence locator projection mismatch",
                ));
            }
            for id in &candidate.evidence_turn_refs {
                if self.turns.contains(id) {
                    self.turn(scope, id)?;
                } else {
                    self.prior(*id)?;
                    self.source(scope, id)?;
                }
            }
            self.verify_evidence_refs(&locators)?;
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
    let crate::claim::ScopedReadResult {
        value,
        receipt: _receipt,
    } = read.get_entity_parts_with_receipt(id, None)?;
    value.ok_or_else(|| invalid_consolidation("branch source is not readable"))
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
