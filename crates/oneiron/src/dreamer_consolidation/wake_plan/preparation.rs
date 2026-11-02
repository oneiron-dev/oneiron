//! The two phases of one frozen wake read that touch every queued attempt:
//! collecting each queued attempt's plan, lineage and round, and finishing
//! each ready plan against the sources pinned at the same snapshot.
//! `PreparedWake::read_matching` calls them in order, on one read txn.

use std::collections::{BTreeMap, BTreeSet};

use super::super::turn_text::TurnText;
use super::{
    AttemptPreparation, PreparedConsolidationAttempt, chunk_identity, chunks, held_round_away_in,
    idle, neighbourhood_in, retry, sources,
};
use crate::attempt_queue::{AttemptId, AttemptRecord};
use crate::claim::ScopedRead;
use crate::dreamer_runner::DreamerConsolidationScope;
use crate::edge::EdgeKind;
use crate::gate::PolicyManifestResolution;
use crate::llm::{Scope, ScopeResource};
use crate::ports::EdgeDirection;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_TURN};
use crate::{EntityId, Result, Vault};

/// What a wake reads for: its scope, the caller's attenuation, and the one
/// attempt a direct execution prepares.
pub(super) struct WakeQuery<'a> {
    pub(super) scope: DreamerConsolidationScope,
    pub(super) caller_scope: Option<&'a Scope>,
    pub(super) only_attempt: Option<AttemptId>,
}

/// Every queued attempt the wake prepares, as collected at its snapshot.
pub(super) struct QueuedPreparation {
    pub(super) ids: BTreeSet<EntityId>,
    pub(super) attempts: BTreeSet<[u8; 16]>,
    pub(super) retries: Vec<retry::Retry>,
    pub(super) preparations: BTreeMap<[u8; 16], AttemptPreparation>,
    pub(super) lineage: BTreeMap<[u8; 16], retry::Lineage>,
    pub(super) rounds: BTreeMap<[u8; 16], (String, String)>,
}

/// What the wake froze before it finishes its plans: each TURN's text or
/// refusal, each attempt's lineage and round, and the completed chunks.
pub(super) struct Frozen<'a> {
    pub(super) texts: &'a BTreeMap<EntityId, TurnText>,
    pub(super) refused_texts: &'a BTreeMap<EntityId, &'static str>,
    pub(super) lineage: &'a BTreeMap<[u8; 16], retry::Lineage>,
    pub(super) rounds: &'a BTreeMap<[u8; 16], (String, String)>,
    pub(super) completed: &'a BTreeSet<String>,
}

/// Each queued attempt of the wake's scope, prepared or refused, and every
/// source id its plan reads.
pub(super) fn collect_queued(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query: WakeQuery<'_>,
    records: Vec<AttemptRecord>,
    left: &BTreeSet<[u8; 16]>,
    policy: &PolicyManifestResolution,
    preempt: Option<&super::PreparationPreempt<'_>>,
) -> Result<QueuedPreparation> {
    let WakeQuery {
        scope,
        caller_scope,
        only_attempt,
    } = query;
    let mut ids = BTreeSet::new();
    let mut attempts = BTreeSet::new();
    let mut retries = Vec::new();
    let mut preparations = BTreeMap::new();
    // Each prepared attempt's queue lineage, for the work it owes.
    let mut lineage = BTreeMap::new();
    // Each attempt's projection round, by its kind and dedupe key.
    let mut rounds = BTreeMap::new();
    for attempt in records {
        // A paused, stopped or expired pass stops collecting: what it left
        // waits for the next pass.
        if preempt.is_some_and(|preempt| preempt.preempted()) {
            break;
        }
        if attempt.kind != scope.attempt_kind()
            || attempt.state.is_terminal()
            || only_attempt.is_some_and(|id| id != attempt.id)
            || left.contains(attempt.id.as_bytes())
            || (only_attempt.is_none() && idle(vault, txn, &attempt)?)
        {
            continue;
        }
        attempts.insert(*attempt.id.as_bytes());
        if let Some(dedupe_key) = &attempt.dedupe_key {
            rounds.insert(
                *attempt.id.as_bytes(),
                (attempt.kind.clone(), dedupe_key.clone()),
            );
        }
        // A malformed queued row is not a source grant. Its own executor
        // still refuses it, without failing unrelated wake work here.
        let Ok(payload) = crate::dreamer_runner::decode_dreamer_attempt_payload(&attempt.payload)
        else {
            continue;
        };
        let Ok(branch) = super::super::partition::decode_partition_payload(&payload.input) else {
            continue;
        };
        let turns = branch.turn_ids();
        ids.extend(branch.conversations());
        ids.extend(turns.iter().copied());
        let queued_scope = match super::super::branch_scope::decode_branch_scope(&payload.input) {
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
        let effective_scope = match super::super::branch_scope::execution_scope_in(
            vault,
            txn,
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
        let stamp = match vault.dreamer_attempt_authority_in_txn(txn, attempt.id) {
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
        lineage.insert(
            *attempt.id.as_bytes(),
            retry::Lineage {
                parent: payload.parent_attempt,
                run_id: attempt.run_id.clone(),
                // A sibling's work keeps the attempt that first owed it.
                origin: super::super::partition::decode_branch_origin(&payload.input)
                    .unwrap_or(attempt.id),
            },
        );
        let prepared = PreparedConsolidationAttempt {
            attempt_id: attempt.id,
            branch: branch.clone(),
            turn_ids: turns,
            scope: effective_scope.clone(),
            input: payload.input.clone(),
            queued_input: payload.input.clone(),
            source_versions: BTreeMap::new(),
            retry_budget: budget,
            neighbourhood: Default::default(),
            thing: branch.thing.and_then(|thing| thing.entity),
            sources_truncated: false,
        };
        preparations.insert(*attempt.id.as_bytes(), AttemptPreparation::Ready(prepared));
        // A selection retry: a retried try, or one a deferral requeued as
        // itself (FIX 3863).
        let selection_retry =
            attempt.retry_of.is_some() || crate::dreamer_runner::selection_deferred(&attempt);
        if selection_retry && effective_scope.is_none() {
            // Each part widens over its own conversation's TURNs.
            let mut peers = Vec::with_capacity(branch.parts.len());
            for conversation in branch.conversations() {
                let found = vault.filtered_edge_peers(
                    txn,
                    EdgeDirection::In,
                    &conversation,
                    EdgeKind::ChildOf,
                    Some(ENTITY_TYPE_TURN),
                )?;
                ids.extend(found.iter().copied());
                peers.push(found);
            }
            retries.push(retry::Retry {
                attempt: *attempt.id.as_bytes(),
                branch,
                peers,
            });
        }
        if let Some(bound) = effective_scope {
            for resource in bound.readable.iter().chain(&bound.writable) {
                if let ScopeResource::DocumentVersion { document, .. } = resource
                    && vault.get_entity_type_in_txn(txn, document)? == Some(ENTITY_TYPE_CLAIM)
                {
                    ids.insert(*document);
                }
            }
        }
    }
    Ok(QueuedPreparation {
        ids,
        attempts,
        retries,
        preparations,
        lineage,
        rounds,
    })
}

/// Finishes each ready plan at the wake's snapshot: splits off the parts it
/// cannot read, refuses or defers it, else pins its neighbourhood and source
/// versions; then adds the heads its neighbourhood lists to `sources`.
pub(super) fn finish_preparations(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    read: &ScopedRead<'_>,
    frozen: Frozen<'_>,
    preparations: &mut BTreeMap<[u8; 16], AttemptPreparation>,
    sources: &mut BTreeMap<EntityId, (u8, u64, Vec<u8>)>,
    owed: &mut Vec<chunks::WakePreparationChunks>,
    preempt: Option<&super::PreparationPreempt<'_>>,
) -> Result<()> {
    let Frozen {
        texts,
        refused_texts,
        lineage,
        rounds,
        completed,
    } = frozen;
    let mut known_rows = BTreeMap::new();
    for outcome in preparations.values_mut() {
        // A paused, stopped or expired pass leaves its plans unfinished:
        // the caller drops the partial wake.
        if preempt.is_some_and(|preempt| preempt.preempted()) {
            return Ok(());
        }
        let AttemptPreparation::Ready(plan) = outcome else {
            continue;
        };
        // A part that cannot be read whole splits off, as does one the
        // effective scope does not name (FIX 7728); the rest run.
        let held = lineage.get(plan.attempt_id.as_bytes());
        let pin = chunk_identity::ChunkPin { sources, completed };
        owed.extend(sources::split_unreadable(
            plan,
            sources,
            refused_texts,
            held,
            pin,
        ));
        owed.extend(sources::split_unnamed(plan, held, pin));
        let mut ids: BTreeSet<_> = plan
            .branch
            .conversations()
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
        let missing: Vec<EntityId> = plan
            .branch
            .conversations()
            .chain(plan.turn_ids.iter().copied())
            .filter(|id| !sources.contains_key(id))
            .collect();
        // FIX 3592: a held round stays whole, so a member TURN of it
        // that this replica does not hold waits for its promotion. The
        // whole-TURN refusal of any other round stays.
        let away = !missing.is_empty()
            && held_round_away_in(vault, txn, rounds.get(plan.attempt_id.as_bytes()), &missing)?;
        if !missing.is_empty() && !away {
            *outcome = AttemptPreparation::Refused {
                reason: "prepared source not readable",
                scope_error: false,
            };
            continue;
        }
        // A refusal outranks a wait: only a turn whose tagged MESSAGE is
        // away (OF-534) defers the attempt.
        if let Some(&reason) = plan
            .turn_ids
            .iter()
            .filter_map(|id| refused_texts.get(id))
            .find(|reason| !super::super::turn_text::residency_deferred(reason))
        {
            *outcome = AttemptPreparation::Refused {
                reason,
                scope_error: false,
            };
            continue;
        }
        if away
            || plan
                .turn_ids
                .iter()
                .any(|id| refused_texts.contains_key(id))
        {
            *outcome = AttemptPreparation::ResidencyDeferred;
            continue;
        }
        let (neighbourhood, rows) = neighbourhood_in(vault, txn, read, plan, sources, texts)?;
        known_rows.extend(rows);
        plan.neighbourhood = neighbourhood;
        plan.source_versions = ids
            .into_iter()
            .filter_map(|id| {
                sources
                    .get(&id)
                    .map(|row| (id, super::super::resources::document_version(id, &row.2)))
            })
            .chain(
                plan.neighbourhood
                    .claim_versions()
                    .map(|(id, version)| (id, version.clone())),
            )
            .chain(
                plan.turn_ids
                    .iter()
                    .filter_map(|id| texts.get(id))
                    .flat_map(super::super::turn_text::TurnText::versions)
                    .map(|(id, version)| (id, version.clone())),
            )
            .collect();
    }
    // The heads a neighbourhood lists are read at this snapshot too; the
    // branch admits them as priors from these bytes.
    for (id, row) in known_rows {
        sources.entry(id).or_insert(row);
    }
    Ok(())
}
