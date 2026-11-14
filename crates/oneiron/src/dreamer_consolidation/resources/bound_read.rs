//! A bound verdict's rebuilt read projection of its queued branch.
//!
//! The projection rebuilds the queued attempt's authoritative scope, listing
//! and prior heads in the caller's one live read transaction, using the same
//! scope assembly, listing code and pin rules as native branch opening. It
//! opens no transaction of its own and performs no write: the listing pin is
//! read, never minted, and the scope is model-request context, never an
//! executable write capability. The caller proves the binding, the live
//! reader scope and every caller-supplied pin before calling, in the same
//! transaction it passes here.

use std::collections::{BTreeMap, BTreeSet};

use super::super::PriorHead;
use super::super::branch::QueuedBranch;
use super::super::branch_scope::{decode_branch_scope, execution_scope_in};
#[cfg(test)]
use super::super::conflict::turn_trust_class;
use super::super::neighbourhood::{
    ListingPin, Neighbourhood, Passage, discover_in, listing_destination,
};
use super::super::routing::PredicateKeyRules;
use super::super::support::invalid_consolidation;
use super::super::turn_text::{TurnText, collect_in};
use super::super::watermark::decode_turn_body;
use super::SourcePin;
use super::document_version;
use super::parts::assemble_branch_scope;
use super::pins::BranchPins;
use super::prior::Standing;
use super::signals::candidate_vector_in_txn;
use super::standing;
use super::stored_project;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::claim::ScopedRead;
use crate::dreamer_runner::{
    decode_dreamer_attempt_payload, dreamer_extraction_role_admissible, dreamer_turn_role,
};
use crate::edge::EdgeKind;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::ports::EdgeDirection;
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN,
};
use crate::settings::ReadDestination;
use crate::write_envelope::ClaimCandidate;
use crate::{Result, Vault};
use oneiron_model::llm::{Scope, ScopeResource};

/// What the bound verdict supplies to rebuild its queued branch's read
/// projection in its one live transaction.
pub(crate) struct BoundBranchInput<'a> {
    /// The queued attempt, as the binding's lease names it. The listing pin
    /// identity is this attempt, so a replay lists what its first run listed.
    pub(crate) attempt: AttemptId,
    /// The queued branch of `attempt`, as the queue payload decodes it in
    /// this same transaction.
    pub(crate) branch: &'a QueuedBranch,
    /// The host's trusted caller attenuation, or `None` where none applies.
    /// Job input never supplies a scope.
    pub(crate) caller: Option<&'a Scope>,
    /// The listing destination override, or `None` for the native direct
    /// destination nobody proved.
    pub(crate) destination: Option<ReadDestination>,
}

/// The queued branch's rebuilt read projection: its authoritative scope, its
/// listing and its admitted prior heads with their pins. The projection is
/// read-only context for one verdict pack; it grants no write.
pub(crate) struct BoundBranchRead {
    /// The branch's authoritative scope: the trusted restriction unchanged
    /// where one resolved, else the granted scope the same assembly builds.
    scope: Scope,
    /// The branch listing the native neighbourhood code rebuilt, its pin
    /// read, never minted.
    neighbourhood: Neighbourhood,
    /// The admitted prior heads, in native id order.
    priors: BTreeMap<EntityId, PriorHead>,
    /// The pinned source rows the projection read, by entity id.
    sources: BTreeMap<EntityId, SourcePin>,
    /// Each queued turn's frozen text, by turn id.
    texts: BTreeMap<EntityId, TurnText>,
    /// The queued attempt, so a candidate vector read recomputes the native
    /// output id it selects under.
    attempt: AttemptId,
    /// The branch signals projection a candidate vector read requires.
    signals: ScopeResource,
    /// The effective predicate key rules, pinned in the passed transaction.
    key_rules: PredicateKeyRules,
    /// The effective cosine nomination threshold, pinned in the passed
    /// transaction.
    cosine_threshold: f64,
}

impl BoundBranchRead {
    /// The branch's authoritative scope: the trusted restriction unchanged
    /// where one resolved, else the granted scope the same assembly builds.
    pub(crate) fn scope(&self) -> &Scope {
        &self.scope
    }

    /// The admitted prior heads, in native id order.
    pub(crate) fn priors(&self) -> &BTreeMap<EntityId, PriorHead> {
        &self.priors
    }

    /// The admitted prior head `id`, when the branch holds it.
    pub(crate) fn prior(&self, id: EntityId) -> Option<&PriorHead> {
        self.priors.get(&id)
    }

    /// The listed claims about `subject` a candidate read under `scope` may
    /// be asked to correct, in native listing order: held as prior heads,
    /// and exactly read- and writable in `scope`. Each row is its id with
    /// its predicate and value as the listing writes them.
    pub(crate) fn correctable(
        &self,
        subject: EntityId,
        scope: &Scope,
    ) -> Vec<(EntityId, String, String)> {
        self.pins()
            .correctable(subject, scope)
            .map(|(claim, predicate, value)| (claim, predicate.to_owned(), value.to_owned()))
            .collect()
    }

    /// The one PROJECT a claim drawn from `refs` may land in, under the same
    /// rule as a branch: the sources' common project within the branch
    /// project, or `None` where they span, lie outside it, or do not decode.
    pub(crate) fn evidence_project(&self, refs: &[EntityId]) -> Result<Option<EntityId>> {
        self.pins().evidence_project(refs)
    }

    /// The branch relationship exposure: `None` is unbound, `Some(empty)` the
    /// explicit empty set, otherwise exactly these relationships.
    pub(crate) fn relationship(&self) -> Option<&BTreeSet<EntityId>> {
        self.scope.relationship.as_ref()
    }

    /// The effective predicate key rules the projection pinned in the passed
    /// transaction: the same side table native assembly reads.
    pub(crate) fn key_rules(&self) -> &PredicateKeyRules {
        &self.key_rules
    }

    /// The effective cosine nomination threshold the projection pinned in
    /// the passed transaction.
    pub(crate) fn cosine_threshold(&self) -> f64 {
        self.cosine_threshold
    }

    /// The stored vector `claim_id` names for the bound `candidate`, read in
    /// the passed transaction under the native candidate vector guards: the
    /// signals grant, the recomputed native output id, and the reviewed
    /// output or actor-readable matching claim rule. `None` is a missing
    /// vector, not an error.
    pub(crate) fn candidate_vector_in_txn(
        &self,
        read: &ScopedRead<'_>,
        txn: &heed::RoTxn<'_>,
        claim_id: EntityId,
        candidate: &ClaimCandidate,
    ) -> Result<Option<Vec<f32>>> {
        candidate_vector_in_txn(
            read,
            txn,
            &self.scope,
            &self.signals,
            self.attempt,
            claim_id,
            candidate,
        )
    }

    /// The native prior-head write check for `id`: the head stands admitted,
    /// its source pin exists, and this scope grants the pinned resource
    /// exact read and write. Routing runs this for every match; read-only
    /// admission never substitutes for it. The check exposes no write
    /// capability.
    pub(crate) fn require_prior_write(&self, id: EntityId) -> Result<()> {
        if !self.priors.contains_key(&id) {
            return Err(invalid_consolidation("unadmitted prior head"));
        }
        let pin = self
            .sources
            .get(&id)
            .ok_or_else(|| invalid_consolidation("missing prior pin"))?;
        if !self.scope.allows_read(&pin.resource) || !self.scope.allows_write(&pin.resource) {
            return Err(invalid_consolidation("prior head exact read/write refused"));
        }
        Ok(())
    }

    /// The projection's pins as one branch view, answering the same
    /// correctable and project rules as native branch pins.
    fn pins(&self) -> BranchPins<'_> {
        BranchPins::for_bound_read(
            &self.sources,
            &self.priors,
            &self.neighbourhood,
            self.scope.project,
            &self.texts,
            &self.scope,
        )
    }
}

/// Rebuild the queued branch's authoritative read projection in the caller's
/// one live transaction. The queue record of `input.attempt` supplies the
/// queued scope and parent behind the existing authority resolution; the
/// branch sources, listing, priors and turn checks all read in `txn` under
/// `read`, the Dreamer actor's live read. Nothing here opens a transaction
/// or writes.
///
/// # Errors
///
/// A missing queue record, an undecodable payload, a broken scope lineage,
/// an unreadable branch source, a source of the wrong type, a scope that
/// does not grant the branch buckets, documents or witness messages, a prior
/// head whose exact version the scope does not grant, or a TURN that fails
/// its part, axes or role checks.
pub(crate) fn project_bound_branch(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    read: &ScopedRead<'_>,
    input: &BoundBranchInput<'_>,
) -> Result<BoundBranchRead> {
    let record = AttemptQueue::new(vault)
        .get_in_txn(txn, input.attempt)?
        .ok_or_else(|| invalid_consolidation("queued branch attempt is missing"))?;
    let payload = decode_dreamer_attempt_payload(&record.payload)?;
    let queued = decode_branch_scope(&payload.input)?;
    let requested = execution_scope_in(
        vault,
        txn,
        input.attempt,
        payload.parent_attempt,
        queued,
        input.caller,
    )?;
    let branch = input.branch;
    let turn_ids = branch.turn_ids();
    let turn_parts = branch.turn_parts();
    let parents: BTreeSet<EntityId> = branch.conversations().collect();
    let buckets: BTreeSet<ScopeResource> = branch
        .partition_keys()
        .map(|key| ScopeResource::Bucket {
            key: bytes_to_hex_lower(&key.partition_hash()),
        })
        .collect();
    let source_ids: Vec<EntityId> = branch
        .conversations()
        .chain(turn_ids.iter().copied())
        .collect();
    let rows = read.get_entities_parts_in_txn(txn, &source_ids)?;
    let mut sources = BTreeMap::new();
    let mut bodies = BTreeMap::new();
    let mut texts = BTreeMap::new();
    let mut readable = buckets.clone();
    for (id, row) in source_ids.iter().zip(rows) {
        let (entity_type, learned_at, body) =
            row.ok_or_else(|| invalid_consolidation("branch source is not readable"))?;
        let parent = parents.contains(id);
        if (parent && !matches!(entity_type, ENTITY_TYPE_SESSION | ENTITY_TYPE_CONVERSATION))
            || (!parent && entity_type != ENTITY_TYPE_TURN)
        {
            return Err(invalid_consolidation("invalid branch source type"));
        }
        let resource = document_version(*id, &body);
        readable.insert(resource.clone());
        let project = stored_project(&vault.store, txn, *id, entity_type, &body)?;
        #[cfg(test)]
        let trust_class = (entity_type == ENTITY_TYPE_TURN)
            .then(|| {
                let facts = decode_turn_body(&body);
                turn_trust_class(
                    dreamer_turn_role(
                        facts.speaker.as_deref(),
                        &vault.config.assistant_display_names,
                    ),
                    facts.imported,
                )
            })
            .flatten();
        if entity_type == ENTITY_TYPE_TURN {
            let mut withheld = 0;
            texts.insert(*id, collect_in(read, txn, id, &body, &mut withheld)?);
        }
        bodies.insert(*id, body);
        sources.insert(
            *id,
            SourcePin {
                resource,
                entity_type,
                learned_at,
                project,
                body_hash: *blake3::hash(&bodies[id]).as_bytes(),
                #[cfg(test)]
                trust_class,
            },
        );
    }
    readable.extend(
        texts
            .values()
            .flat_map(TurnText::versions)
            .map(|(_, version)| version.clone()),
    );
    let mut passage_turns = Vec::with_capacity(turn_ids.len());
    let mut projects = BTreeSet::new();
    for id in &turn_ids {
        let body = bodies
            .get(id)
            .ok_or_else(|| invalid_consolidation("branch source is not readable"))?;
        let pin = sources
            .get(id)
            .ok_or_else(|| invalid_consolidation("unlisted branch document"))?;
        projects.insert(pin.project);
        passage_turns.push((body.as_slice(), texts.get(id).and_then(TurnText::text)));
    }
    let bound = requested.as_ref();
    let project = match (bound.and_then(|scope| scope.project), projects.len()) {
        (Some(project), _) => Some(project),
        (None, 1) => projects.into_iter().next().flatten(),
        _ => None,
    };
    let axes = project.map(|project| Scope {
        world: branch.world_ref,
        facet: branch.facet_ref,
        relationship: bound.and_then(|scope| scope.relationship.clone()),
        project: Some(project),
        ..Scope::default()
    });
    let destination = input
        .destination
        .clone()
        .unwrap_or_else(listing_destination);
    let listing = vault.scoped_read(read.actor_key().clone().for_destination(&destination));
    let passage = Passage {
        turns: &passage_turns,
        axes: axes.as_ref(),
        bound,
        thing: branch.thing.as_ref().and_then(|thing| thing.entity),
        destination,
    };
    let (neighbourhood, _) = discover_in(
        vault,
        txn,
        &listing,
        ListingPin::attempt(input.attempt),
        &passage,
    )?;
    let (scope, context_only, signals) =
        assemble_branch_scope(branch, readable, Some(&neighbourhood), requested.as_ref());
    let documents: BTreeSet<EntityId> = scope
        .readable
        .iter()
        .chain(&scope.writable)
        .filter_map(|resource| match resource {
            ScopeResource::DocumentVersion { document, .. } => Some(*document),
            _ => None,
        })
        .collect();
    let mut priors = BTreeMap::new();
    let candidates: Vec<EntityId> = documents
        .into_iter()
        .filter(|id| !sources.contains_key(id) && !context_only.contains(id))
        .collect();
    let rows = read.get_entities_parts_in_txn(txn, &candidates)?;
    for (id, row) in candidates.into_iter().zip(rows) {
        let Some((kind, learned_at, bytes)) = row else {
            continue;
        };
        if kind != ENTITY_TYPE_CLAIM {
            continue;
        }
        let resource = document_version(id, &bytes);
        if !scope.allows_read(&resource) {
            return Err(invalid_consolidation("prior head exact read refused"));
        }
        if !crate::gate::claim_consolidation_eligible_in_txn(
            &vault.store,
            txn,
            &id,
            crate::gate::ConsolidationReader::ExplicitPrior,
        )? {
            continue;
        }
        let prior = PriorHead {
            claim_id: id,
            body: crate::claim::decode_claim_body(&bytes, true)?,
        };
        // A head awaiting only generation vetting stands when the listing
        // names it; either standing admits it as a prior head here.
        let admitted = match standing(&prior, &scope)? {
            Some(Standing::Prior) => true,
            Some(Standing::Provisional) => neighbourhood.lists(id),
            None => false,
        };
        if !admitted {
            continue;
        }
        sources.insert(
            id,
            SourcePin {
                resource,
                entity_type: kind,
                learned_at,
                project: Some(prior.body.scope_project),
                body_hash: *blake3::hash(&bytes).as_bytes(),
                #[cfg(test)]
                trust_class: Some(crate::dreamer_consolidation::provenance::source_meet(
                    prior.body.source.unwrap_or(crate::ClaimSource::Imported),
                    crate::claim::claim_evidence_taint(&prior.body)
                        .unwrap_or(prior.body.source.unwrap_or(crate::ClaimSource::Imported)),
                )),
            },
        );
        priors.insert(id, prior);
    }
    if scope.world != branch.world_ref || scope.facet != branch.facet_ref {
        return Err(invalid_consolidation("branch source axes do not match"));
    }
    if !buckets.iter().all(|bucket| scope.allows_read(bucket)) {
        return Err(invalid_consolidation("branch document read refused"));
    }
    for parent in &parents {
        let pin = sources
            .get(parent)
            .ok_or_else(|| invalid_consolidation("unlisted branch document"))?;
        if !scope.allows_read(&pin.resource) {
            return Err(invalid_consolidation("branch document read refused"));
        }
    }
    for id in &turn_ids {
        let conversation = turn_parts
            .get(id)
            .copied()
            .ok_or_else(|| invalid_consolidation("unlisted branch turn"))?;
        let pin = sources
            .get(id)
            .ok_or_else(|| invalid_consolidation("unlisted branch document"))?;
        if !scope.allows_read(&pin.resource) {
            return Err(invalid_consolidation("branch document read refused"));
        }
        let text = texts
            .get(id)
            .ok_or_else(|| invalid_consolidation("unlisted branch turn"))?;
        if !text
            .versions()
            .all(|(_, version)| scope.allows_read(version))
        {
            return Err(invalid_consolidation("witnessed turn message read refused"));
        }
        let turn_body = bodies
            .get(id)
            .ok_or_else(|| invalid_consolidation("branch source is not readable"))?;
        let parent_body = bodies
            .get(&conversation)
            .ok_or_else(|| invalid_consolidation("branch source is not readable"))?;
        let facts = decode_turn_body(turn_body);
        let parent_facts = decode_turn_body(parent_body);
        // Membership is the TURN's ChildOf edge alone, read in this same
        // snapshot: withheld targets are peers here too, so an incomplete
        // graph refuses through the same length check with the same outcome.
        let peers =
            vault.filtered_edge_peers(txn, EdgeDirection::Out, id, EdgeKind::ChildOf, None)?;
        if peers.len() != 1
            || peers[0] != conversation
            || facts.world_ref.or(parent_facts.world_ref) != branch.world_ref
            || facts.facet_ref.or(parent_facts.facet_ref) != branch.facet_ref
            || !dreamer_extraction_role_admissible(dreamer_turn_role(
                facts.speaker.as_deref(),
                &vault.config.assistant_display_names,
            ))
        {
            return Err(invalid_consolidation("branch turn crossed its partition"));
        }
    }
    let key_rules = vault.consolidation_key_rules_in_txn(txn)?;
    let cosine_threshold = vault.consolidation_selection_in_txn(txn)?.cosine_threshold;
    Ok(BoundBranchRead {
        scope,
        neighbourhood,
        priors,
        sources,
        texts,
        attempt: input.attempt,
        signals,
        key_rules,
        cosine_threshold,
    })
}
