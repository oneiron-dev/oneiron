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
use crate::scan_check::{EngineScan, ScanCount};
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
    /// The known entities its turns name, read at the wake's snapshot.
    neighbourhood: super::neighbourhood::Neighbourhood,
    /// A selection retry whose source budget left admissible sources out:
    /// it runs every original and the oldest others that fit; more exist.
    sources_truncated: bool,
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
    pub(crate) fn neighbourhood(&self) -> &super::neighbourhood::Neighbourhood {
        &self.neighbourhood
    }
    pub(crate) fn sources_truncated(&self) -> bool {
        self.sources_truncated
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
    /// A source the attempt reads is away from this replica, not refused (a
    /// window demoted back to thin, OF-534): a planned TURN whose tagged
    /// MESSAGE is away, or a member TURN of a held round (FIX 3592). The
    /// attempt is deferred, queued, and runs whole once a promotion brings
    /// the row back; it is never failed, parked or applied for it.
    ResidencyDeferred,
}

/// How long an attempt [`AttemptPreparation::ResidencyDeferred`] defers waits
/// before a wake prepares it again, in store-clock seconds.
pub(crate) const RESIDENCY_RETRY_SECS: u64 = 900;

/// Whether every source in `missing` is a member TURN of the held projection
/// round an attempt carries that this replica does not hold (FIX 3592).
/// `round` is the attempt's kind and dedupe key.
fn held_round_away_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    round: Option<&(String, String)>,
    missing: &[EntityId],
) -> Result<bool> {
    let Some((kind, dedupe_key)) = round else {
        return Ok(false);
    };
    crate::dreamer_wake::held_round_members_away_in_txn(
        &vault.store,
        txn,
        (kind.as_str(), dedupe_key.as_str()),
        missing,
    )
}

/// The most queued TURNs one wake prepares: one Meso round's worth. A pass
/// admits work from the head of the ready order, so the wake prepares that
/// head and leaves the rest of a larger backlog (a whole history import) to
/// the passes after it, rather than reading all of it before any budget or
/// deadline applies.
const WAKE_PREPARED_TURN_CAP: usize = super::DEFAULT_MESO_ROUND_TURN_CAP;

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
    /// Ready work past the head this wake prepared, for a later pass.
    left: BTreeSet<[u8; 16]>,
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
        let left = if only_attempt.is_some() {
            BTreeSet::new()
        } else {
            left_for_later(&records, scope)
        };
        let mut ids = BTreeSet::new();
        let mut attempts = BTreeSet::new();
        let mut retries = Vec::new();
        let mut preparations = BTreeMap::new();
        // Each attempt's projection round, by its kind and dedupe key.
        let mut rounds = BTreeMap::new();
        for attempt in records {
            if attempt.kind != scope.attempt_kind()
                || attempt.state.is_terminal()
                || only_attempt.is_some_and(|id| id != attempt.id)
                || left.contains(attempt.id.as_bytes())
                || (only_attempt.is_none() && idle(vault, &txn, &attempt)?)
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
                neighbourhood: Default::default(),
                sources_truncated: false,
            };
            preparations.insert(*attempt.id.as_bytes(), AttemptPreparation::Ready(prepared));
            if attempt.retry_of.is_some() && effective_scope.is_none() {
                let peers = vault.filtered_edge_peers(
                    &txn,
                    EdgeDirection::In,
                    &partition.conversation_ref,
                    EdgeKind::ChildOf,
                    Some(ENTITY_TYPE_TURN),
                )?;
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
                left,
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
        let mut sources: BTreeMap<_, _> = source_ids
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
            // Every peer is read: past the conversation's threshold row the
            // retry raises one check and reads on.
            let mut scanned = ScanCount::start(
                &vault.store,
                &txn,
                EngineScan::DreamerRetryPeers,
                partition.conversation_ref.as_bytes(),
            )?;
            let mut turns = Vec::new();
            let admission_time = crate::ports::job_recorded_at_in_txn(&vault.store, &txn)?;
            for id in peers {
                scanned.row();
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
                if *stored <= admission_time
                    && dreamer_extraction_role_admissible(role)
                    && facts.world_ref.or(parent.world_ref) == partition.world_ref
                    && facts.facet_ref.or(parent.facet_ref) == partition.facet_ref
                    && (original.contains(&id) || learned_at >= watermark)
                {
                    turns.push((learned_at, key, id, carrier.map(|(_, order)| order)));
                }
            }
            scanned.finish(vault);
            turns.sort_unstable();
            let limit = preparations
                .get(&attempt)
                .and_then(|entry| match entry {
                    AttemptPreparation::Ready(plan) => Some(plan.retry_budget().max_sources()),
                    _ => None,
                })
                .ok_or_else(|| invalid_consolidation("prepared retry budget missing"))?;
            let missing: Vec<EntityId> = original
                .iter()
                .filter(|id| !turns.iter().any(|(_, _, got, _)| got == *id))
                .copied()
                .collect();
            if !missing.is_empty() {
                // A held round's member away from this replica waits for
                // its promotion; any other change of membership refuses.
                let away = held_round_away_in(vault, &txn, rounds.get(&attempt), &missing)?;
                preparations.insert(
                    attempt,
                    if away {
                        AttemptPreparation::ResidencyDeferred
                    } else {
                        AttemptPreparation::Refused {
                            reason: "selection retry membership changed",
                            scope_error: false,
                        }
                    },
                );
                continue;
            }
            // The source budget truncates, never refuses: every original runs,
            // with the oldest other sources that fit; the newest wait for the
            // ordinary passes, and the plan says more exist.
            let optional = limit.saturating_sub(original.len());
            let mut kept_optional = 0_usize;
            let admissible = turns.len();
            turns.retain(|(_, _, id, _)| {
                original.contains(id) || {
                    kept_optional += 1;
                    kept_optional <= optional
                }
            });
            let sources_truncated = turns.len() < admissible;
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
                plan.sources_truncated = sources_truncated;
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
        let mut known_rows = BTreeMap::new();
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
            let missing: Vec<EntityId> = std::iter::once(&plan.partition.conversation_ref)
                .chain(plan.turn_ids.iter())
                .filter(|id| !sources.contains_key(*id))
                .copied()
                .collect();
            // FIX 3592: a held round stays whole, so a member TURN of it
            // that this replica does not hold waits for its promotion. The
            // whole-TURN refusal of any other round stays.
            let away = !missing.is_empty()
                && held_round_away_in(
                    vault,
                    &txn,
                    rounds.get(plan.attempt_id.as_bytes()),
                    &missing,
                )?;
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
                .find(|reason| !super::turn_text::residency_deferred(reason))
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
            let (neighbourhood, rows) =
                neighbourhood_in(vault, &txn, &read, plan, &sources, &texts)?;
            known_rows.extend(rows);
            plan.neighbourhood = neighbourhood;
            plan.source_versions = ids
                .into_iter()
                .filter_map(|id| {
                    sources
                        .get(&id)
                        .map(|row| (id, super::resources::document_version(id, &row.2)))
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
                        .flat_map(super::turn_text::TurnText::versions)
                        .map(|(id, version)| (id, version.clone())),
                )
                .collect();
        }
        // The heads a neighbourhood lists are read at this snapshot too; the
        // branch admits them as priors from these bytes.
        for (id, row) in known_rows {
            sources.entry(id).or_insert(row);
        }
        Ok(Self {
            sources,
            texts,
            attempts,
            left,
            preparations,
            read_receipt: Some(read_receipt),
        })
    }

    /// Only work known at the wake's single revision may execute on it.
    pub(crate) fn contains_attempt(&self, id: AttemptId) -> bool {
        self.attempts.contains(id.as_bytes())
    }

    /// Ready work this wake left past the head it prepared: a later pass
    /// prepares and runs it.
    pub(crate) fn left_for_later(&self, id: AttemptId) -> bool {
        self.left.contains(id.as_bytes())
    }

    pub(crate) fn preparation(&self, id: AttemptId) -> Option<&AttemptPreparation> {
        self.preparations.get(id.as_bytes())
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

/// The known entities `plan`'s turns name, with the claims the branch may
/// hold as priors. Claims are listed only when the turns share one project,
/// so a listing never mixes projects into one branch's input.
fn neighbourhood_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    read: &crate::claim::ScopedRead<'_>,
    plan: &PreparedConsolidationAttempt,
    sources: &BTreeMap<EntityId, (u8, u64, Vec<u8>)>,
    texts: &BTreeMap<EntityId, super::turn_text::TurnText>,
) -> Result<(
    super::neighbourhood::Neighbourhood,
    super::neighbourhood::ListedRows,
)> {
    let mut turns = Vec::new();
    let mut projects = BTreeSet::new();
    for id in &plan.turn_ids {
        let Some((kind, _, body)) = sources.get(id) else {
            continue;
        };
        projects.insert(super::resources::stored_project(
            &vault.store,
            txn,
            *id,
            *kind,
            body,
        )?);
        turns.push((
            body.as_slice(),
            texts.get(id).and_then(super::turn_text::TurnText::text),
        ));
    }
    let bound = plan.scope.as_ref();
    let project = match (bound.and_then(|scope| scope.project), projects.len()) {
        (Some(project), _) => Some(project),
        (None, 1) => projects.into_iter().next().flatten(),
        _ => None,
    };
    let axes = project.map(|project| Scope {
        world: plan.partition.world_ref,
        facet: plan.partition.facet_ref,
        relationship: bound.and_then(|scope| scope.relationship),
        project: Some(project),
        ..Scope::default()
    });
    let passage = super::neighbourhood::Passage {
        turns: &turns,
        axes: axes.as_ref(),
        bound,
    };
    super::neighbourhood::discover_in(vault, txn, read, plan.attempt_id, &passage)
}

/// An attempt no pass runs before a later write, which a later wake
/// prepares: a paused one, or one parked under its lease until the lease
/// lapses and the queue hands it out again.
fn idle(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: &crate::attempt_queue::AttemptRecord,
) -> Result<bool> {
    Ok(attempt.state == crate::attempt_queue::AttemptState::Paused
        || (attempt.state.is_running()
            && crate::dreamer_runner::DreamerRunnerStore::new(vault)
                .is_parked_in_txn(txn, attempt.id)?))
}

/// The ready work of `scope` past the head one wake prepares, in the order a
/// pass admits it: every attempt from the first whose queued TURNs would take
/// the head past [`WAKE_PREPARED_TURN_CAP`]. The head always holds at least
/// one attempt, however many TURNs it queued.
fn left_for_later(
    records: &[crate::attempt_queue::AttemptRecord],
    scope: crate::dreamer_runner::DreamerConsolidationScope,
) -> BTreeSet<[u8; 16]> {
    let mut ready: Vec<_> = records
        .iter()
        .filter(|record| record.kind == scope.attempt_kind())
        .filter_map(|record| Some((crate::attempt_queue::admission_order(record)?, record)))
        .collect();
    ready.sort_unstable_by_key(|(order, _)| *order);
    let mut head = 0_usize;
    let mut left = BTreeSet::new();
    for (_, record) in ready {
        let queued = crate::dreamer_runner::decode_dreamer_attempt_payload(&record.payload)
            .ok()
            .and_then(|payload| super::partition::decode_partition_payload(&payload.input).ok())
            .map_or(0, |(_, turns, _)| turns.len());
        if !left.is_empty() || (head > 0 && head.saturating_add(queued) > WAKE_PREPARED_TURN_CAP) {
            left.insert(*record.id.as_bytes());
        } else {
            head = head.saturating_add(queued);
        }
    }
    left
}
