//! One frozen read revision and exact preparation of queued consolidation work.
//! The read transaction closes before any model call or write.
use super::support::invalid_consolidation;
use super::watermark::decode_turn_body;
use crate::attempt_queue::AttemptId;
use crate::claim::{ScopedReadActorKey, ScopedReadReceipt};
use crate::dreamer_runner::{dreamer_extraction_role_admissible, dreamer_turn_role};
use crate::edge::EdgeKind;
use crate::llm::{Scope, ScopeResource};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_TURN};
use crate::{EntityId, Result, Vault};
use std::collections::{BTreeMap, BTreeSet};

/// One immutable branch contract selected from a single wake revision.
/// Source bytes are shared by the owning `PreparedWake`; only exact version
/// identities and bounded input/scope belong to the individual plan.
#[derive(Debug, Clone)]
pub struct PreparedConsolidationAttempt {
    attempt_id: AttemptId,
    partition: super::ConsolidationPartitionKey,
    turn_ids: Vec<EntityId>,
    scope: Option<Scope>,
    input: rmpv::Value,
    queued_input: rmpv::Value,
    source_versions: BTreeMap<EntityId, ScopeResource>,
    retry_budget: crate::gate::retry_source_policy::ResolvedRetryBudget,
}

impl PreparedConsolidationAttempt {
    pub(crate) fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }
    pub(crate) fn partition(&self) -> super::ConsolidationPartitionKey {
        self.partition
    }
    pub(crate) fn turn_ids(&self) -> &[EntityId] {
        &self.turn_ids
    }
    pub(crate) fn scope(&self) -> Option<&Scope> {
        self.scope.as_ref()
    }
    pub(crate) fn input(&self) -> &rmpv::Value {
        &self.input
    }
    pub(crate) fn matches_queued(&self, input: &rmpv::Value) -> bool {
        &self.queued_input == input
    }
    pub(crate) fn retry_budget(&self) -> crate::gate::retry_source_policy::ResolvedRetryBudget {
        self.retry_budget
    }
    pub(crate) fn version(&self, id: &EntityId) -> Option<&ScopeResource> {
        self.source_versions.get(id)
    }
}

#[derive(Debug, Clone)]
#[expect(
    clippy::large_enum_variant,
    reason = "one plan per admitted attempt, held once per wake"
)]
pub(crate) enum AttemptPreparation {
    Ready(PreparedConsolidationAttempt),
    Refused {
        reason: &'static str,
        scope_error: bool,
    },
}

/// Source bodies frozen by the Dreamer at ONE ledger snapshot, before the
/// wake starts any writes. The read transaction closes immediately after this
/// bounded projection; a wake never holds an LMDB reader slot across writes.
#[derive(Debug, Default)]
pub struct PreparedWake {
    sources: BTreeMap<EntityId, (u8, u64, Vec<u8>)>,
    /// Every prepared TURN's text and the MESSAGEs it was read from, pinned
    /// in the same snapshot as `sources`.
    texts: BTreeMap<EntityId, super::turn_text::TurnText>,
    attempts: BTreeSet<[u8; 16]>,
    preparations: BTreeMap<[u8; 16], AttemptPreparation>,
    /// The receipt of the one scoped read behind `sources`; `None` when the
    /// wake read nothing. Every branch opened on this wake folds it.
    read_receipt: Option<ScopedReadReceipt>,
}

impl PreparedWake {
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
        Self::prepare_matching(vault, scope, caller_scope, None)
    }

    /// Direct execution uses the same one-revision planner but materializes
    /// only its own admitted attempt, not unrelated queued branches.
    pub(crate) fn prepare_one(
        vault: &Vault,
        scope: crate::dreamer_runner::DreamerConsolidationScope,
        caller_scope: Option<&Scope>,
        attempt: AttemptId,
    ) -> Result<Self> {
        Self::prepare_matching(vault, scope, caller_scope, Some(attempt))
    }

    fn prepare_matching(
        vault: &Vault,
        scope: crate::dreamer_runner::DreamerConsolidationScope,
        caller_scope: Option<&Scope>,
        only_attempt: Option<AttemptId>,
    ) -> Result<Self> {
        use crate::ports::EdgeDirection;
        // Witnessed TURN text is read under live relationship grants.
        let txn = super::turn_text::snapshot(vault)?;
        let policy = crate::gate::resolve_policy_manifest(&vault.store, &txn)?;
        let records = crate::attempt_queue::AttemptQueue::new(vault).list_in_txn(&txn)?;
        let mut ids = BTreeSet::new();
        let mut attempts = BTreeSet::new();
        let mut retries = Vec::new();
        let mut preparations = BTreeMap::new();
        for attempt in records {
            if attempt.kind != scope.attempt_kind()
                || attempt.state.is_terminal()
                || only_attempt.is_some_and(|id| id != attempt.id)
            {
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
            let queued_scope = match super::branch_scope::decode_branch_scope(&payload.input) {
                Ok(scope) => scope,
                Err(_) => {
                    preparations.insert(
                        *attempt.id.as_bytes(),
                        AttemptPreparation::Refused {
                            reason: "invalid queued branch scope",
                            scope_error: true,
                        },
                    );
                    continue;
                }
            };
            let effective_scope = match super::branch_scope::execution_scope_in(
                vault,
                &txn,
                attempt.id,
                payload.parent_attempt,
                queued_scope,
                caller_scope,
            ) {
                Ok(scope) => scope,
                Err(_) => {
                    preparations.insert(
                        *attempt.id.as_bytes(),
                        AttemptPreparation::Refused {
                            reason: "invalid retry execution scope",
                            scope_error: true,
                        },
                    );
                    continue;
                }
            };
            let stamp = match vault.dreamer_attempt_authority_in_txn(&txn, attempt.id) {
                Ok(Some(stamp)) => stamp,
                _ => {
                    preparations.insert(
                        *attempt.id.as_bytes(),
                        AttemptPreparation::Refused {
                            reason: "invalid Dreamer attempt actor",
                            scope_error: false,
                        },
                    );
                    continue;
                }
            };
            let budget = policy.retry_budget_for(stamp.actor, effective_scope.as_ref())?;
            let prepared = PreparedConsolidationAttempt {
                attempt_id: attempt.id,
                partition,
                turn_ids: turns.clone(),
                scope: effective_scope.clone(),
                input: payload.input.clone(),
                queued_input: payload.input.clone(),
                source_versions: BTreeMap::new(),
                retry_budget: budget,
            };
            preparations.insert(*attempt.id.as_bytes(), AttemptPreparation::Ready(prepared));
            if attempt.retry_of.is_some() && effective_scope.is_none() {
                let peers = match vault.filtered_edge_peers(
                    &txn,
                    EdgeDirection::In,
                    &partition.conversation_ref,
                    EdgeKind::ChildOf,
                    Some(ENTITY_TYPE_TURN),
                    "selection retry wake source scan",
                ) {
                    Ok(peers) => peers,
                    Err(crate::Error::IndexOverflow(_)) => {
                        preparations.insert(
                            *attempt.id.as_bytes(),
                            AttemptPreparation::Refused {
                                reason: "selection retry graph limit exceeded",
                                scope_error: false,
                            },
                        );
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                ids.extend(peers.iter().copied());
                retries.push((*attempt.id.as_bytes(), partition, turns, watermark, peers));
            }
            if let Some(bound) = effective_scope {
                for resource in bound.readable.iter().chain(&bound.writable) {
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
            for resource in bound.readable.iter().chain(&bound.writable) {
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
                preparations,
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
        // The receipt is resolved in the SAME snapshot and counts every
        // existing row withheld from the Dreamer actor, retry peers and
        // witnessed TURN messages included.
        let mut withheld = 0;
        for (id, row) in source_ids.iter().zip(&rows) {
            if row.is_none() && vault.get_entity_type_in_txn(&txn, id)?.is_some() {
                withheld += 1;
            }
        }
        let sources: BTreeMap<_, _> = source_ids
            .into_iter()
            .zip(rows)
            .filter_map(|(id, row)| row.map(|body| (id, body)))
            .collect();
        // Resolve each prepared retry only against the frozen source pool.

        for (attempt, partition, original, watermark, peers) in retries {
            let Some(parent) = sources.get(&partition.conversation_ref) else {
                preparations.insert(
                    attempt,
                    AttemptPreparation::Refused {
                        reason: "selection retry parent not readable",
                        scope_error: false,
                    },
                );
                continue;
            };
            let parent = decode_turn_body(&parent.2);
            let original: BTreeSet<_> = original.into_iter().collect();
            let mut turns = Vec::new();
            for id in peers {
                let Some((kind, stored, bytes)) = sources.get(&id) else {
                    continue;
                };
                if *kind != ENTITY_TYPE_TURN {
                    continue;
                }
                // Membership and order read the effective selection key, as
                // the scan does; the source pin keeps the row's own learned_at.
                let carrier = super::redirty::carrier_key_in_txn(vault, &txn, scope, &id, *stored)?;
                let (learned_at, key) = carrier.unwrap_or((*stored, id));
                let facts = decode_turn_body(bytes);
                let role = dreamer_turn_role(
                    facts.speaker.as_deref(),
                    &vault.config.assistant_display_names,
                );
                if dreamer_extraction_role_admissible(role)
                    && facts.world_ref.or(parent.world_ref) == partition.world_ref
                    && facts.facet_ref.or(parent.facet_ref) == partition.facet_ref
                    && (original.contains(&id) || learned_at >= watermark)
                {
                    turns.push((learned_at, key, id, carrier.map(|(_, order)| order)));
                }
            }
            turns.sort_unstable();
            let limit = preparations
                .get(&attempt)
                .and_then(|entry| match entry {
                    AttemptPreparation::Ready(plan) => Some(plan.retry_budget().max_sources()),
                    _ => None,
                })
                .ok_or_else(|| invalid_consolidation("prepared retry budget missing"))?;
            if turns.len() > limit
                || !original
                    .iter()
                    .all(|id| turns.iter().any(|(_, _, got, _)| got == id))
            {
                preparations.insert(
                    attempt,
                    AttemptPreparation::Refused {
                        reason: "selection retry source limit or membership changed",
                        scope_error: false,
                    },
                );
                continue;
            }
            let working_set: Vec<super::WorkingSetTurn> = turns
                .into_iter()
                .map(|(learned_at, _, turn_id, carrier)| {
                    let facts = decode_turn_body(&sources[&turn_id].2);
                    super::WorkingSetTurn {
                        turn_id,
                        role: dreamer_turn_role(
                            facts.speaker.as_deref(),
                            &vault.config.assistant_display_names,
                        ),
                        learned_at,
                        carrier,
                        conversation: Some(partition.conversation_ref),
                    }
                })
                .collect();
            if let Some(AttemptPreparation::Ready(plan)) = preparations.get_mut(&attempt) {
                plan.turn_ids = working_set.iter().map(|turn| turn.turn_id).collect();
                plan.input = super::partition::encode_partition_payload(
                    &super::ConsolidationPartitionPlan {
                        key: partition,
                        turns: working_set,
                        watermark_last_learned_at: watermark,
                    },
                );
            }
        }
        // Witnessed TURN text lives on MESSAGE children: pin them in THIS
        // snapshot. A child set that cannot be read refuses only its branches.
        let mut texts = BTreeMap::new();
        let mut refused_texts = BTreeMap::new();
        for outcome in preparations.values() {
            let AttemptPreparation::Ready(plan) = outcome else {
                continue;
            };
            for turn in &plan.turn_ids {
                let Some((ENTITY_TYPE_TURN, _, body)) = sources.get(turn) else {
                    continue;
                };
                if texts.contains_key(turn) || refused_texts.contains_key(turn) {
                    continue;
                }
                match super::turn_text::collect_in(&read, &txn, turn, body, &mut withheld) {
                    Ok(text) => {
                        texts.insert(*turn, text);
                    }
                    Err(crate::Error::InvalidClaimBody(reason)) => {
                        refused_texts.insert(*turn, reason);
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        let read_receipt = read.read_receipt_in(&txn, None, withheld)?;
        for outcome in preparations.values_mut() {
            let AttemptPreparation::Ready(plan) = outcome else {
                continue;
            };
            let mut ids: BTreeSet<_> = std::iter::once(plan.partition.conversation_ref)
                .chain(plan.turn_ids.iter().copied())
                .collect();
            if let Some(scope) = plan.scope.as_ref() {
                for resource in scope.readable.iter().chain(&scope.writable) {
                    if let ScopeResource::DocumentVersion { document, .. } = resource
                        && sources
                            .get(document)
                            .is_some_and(|row| row.0 == ENTITY_TYPE_CLAIM)
                    {
                        ids.insert(*document);
                    }
                }
            }
            if !std::iter::once(&plan.partition.conversation_ref)
                .chain(plan.turn_ids.iter())
                .all(|id| sources.contains_key(id))
            {
                *outcome = AttemptPreparation::Refused {
                    reason: "prepared source not readable",
                    scope_error: false,
                };
                continue;
            }
            if let Some(&reason) = plan.turn_ids.iter().find_map(|id| refused_texts.get(id)) {
                *outcome = AttemptPreparation::Refused {
                    reason,
                    scope_error: false,
                };
                continue;
            }
            plan.source_versions = ids
                .into_iter()
                .filter_map(|id| {
                    sources
                        .get(&id)
                        .map(|row| (id, super::resources::document_version(id, &row.2)))
                })
                .chain(
                    plan.turn_ids
                        .iter()
                        .filter_map(|id| texts.get(id))
                        .flat_map(super::turn_text::TurnText::versions)
                        .map(|(id, version)| (id, version.clone())),
                )
                .collect();
        }
        Ok(Self {
            sources,
            texts,
            attempts,
            preparations,
            read_receipt: Some(read_receipt),
        })
    }

    /// Only work known at the wake's single revision may execute on it.
    pub(crate) fn contains_attempt(&self, id: AttemptId) -> bool {
        self.attempts.contains(id.as_bytes())
    }

    pub(crate) fn preparation(&self, id: AttemptId) -> Option<&AttemptPreparation> {
        self.preparations.get(id.as_bytes())
    }

    #[cfg(test)]
    pub(crate) fn retry_failure(&self, id: AttemptId) -> Option<&'static str> {
        match self.preparation(id) {
            Some(AttemptPreparation::Refused { reason, .. }) => Some(*reason),
            _ => None,
        }
    }

    pub(super) fn source(&self, id: &EntityId) -> Option<(u8, u64, Vec<u8>)> {
        self.sources.get(id).cloned()
    }

    /// The frozen text of each branch TURN; a TURN this wake did not prepare
    /// cannot be read on it.
    pub(super) fn turn_texts(
        &self,
        turns: &[EntityId],
    ) -> Result<BTreeMap<EntityId, super::turn_text::TurnText>> {
        turns
            .iter()
            .map(|id| {
                self.texts
                    .get(id)
                    .map(|text| (*id, text.clone()))
                    .ok_or_else(|| invalid_consolidation("branch turn text was not prepared"))
            })
            .collect()
    }

    /// The receipt of the wake's one scoped read, if it read anything.
    pub(super) fn read_receipt(&self) -> Option<&ScopedReadReceipt> {
        self.read_receipt.as_ref()
    }
}
