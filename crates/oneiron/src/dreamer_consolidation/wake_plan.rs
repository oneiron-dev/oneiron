//! One frozen read revision and exact preparation of queued consolidation work.
//! The read transaction closes before any model call or write.
use super::support::invalid_consolidation;
use crate::attempt_queue::AttemptId;
use crate::claim::{ScopedReadActorKey, ScopedReadReceipt};
use crate::dreamer_wake::{WakeCancellation, WakePassDeadline};
use crate::llm::{Scope, ScopeResource};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_TURN};
use crate::{EntityId, Result, Vault};
use std::collections::{BTreeMap, BTreeSet};

mod chunk_identity;
mod chunks;
mod preparation;
mod retry;
mod sources;
use preparation::{Frozen, QueuedPreparation, WakeQuery, collect_queued, finish_preparations};

/// One immutable branch contract selected from a single wake revision.
/// Source bytes are shared by the owning `PreparedWake`; only exact version
/// identities and bounded input/scope belong to the individual plan.
#[derive(Debug, Clone)]
pub struct PreparedConsolidationAttempt {
    attempt_id: AttemptId,
    /// The branch it runs: every conversation part, as prepared at the
    /// wake's pin (FIX 7524).
    branch: super::branch::QueuedBranch,
    turn_ids: Vec<EntityId>,
    scope: Option<Scope>,
    input: rmpv::Value,
    queued_input: rmpv::Value,
    source_versions: BTreeMap<EntityId, ScopeResource>,
    retry_budget: crate::gate::retry_source_policy::ResolvedRetryBudget,
    /// The known entities its turns name, read at the wake's snapshot.
    neighbourhood: super::neighbourhood::Neighbourhood,
    /// The entity its queued payload names as its thing (FIX 7497).
    thing: Option<EntityId>,
    /// A selection retry whose source budget left admissible sources out:
    /// it runs every original and the oldest others that fit; more exist,
    /// owed as sibling chunks of the same size (`chunks`).
    sources_truncated: bool,
}

impl PreparedConsolidationAttempt {
    pub(crate) fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }
    pub(crate) fn branch(&self) -> &super::branch::QueuedBranch {
        &self.branch
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

/// What a long preparation polls per iteration: the pass's deadline and
/// its cooperative cancellation (a drain's pause or a stop).
pub(super) struct PreparationPreempt<'a> {
    deadline: &'a WakePassDeadline,
    cancel: &'a WakeCancellation,
}

impl PreparationPreempt<'_> {
    /// True when the pass must stop preparing and end at its next boundary:
    /// paused, stopped, or past its ceiling.
    fn preempted(&self) -> bool {
        self.cancel.is_cancelled() || self.deadline.expired()
    }
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
    /// Ready work past the head this wake prepared, for a later pass.
    left: BTreeSet<[u8; 16]>,
    preparations: BTreeMap<[u8; 16], AttemptPreparation>,
    /// The receipt of the one scoped read behind `sources`; `None` when the
    /// wake read nothing. Every branch opened on this wake folds it.
    read_receipt: Option<ScopedReadReceipt>,
    /// Wall ms the preparation took, for each partition's stage line.
    prepared_ms: u64,
}

impl PreparedWake {
    #[cfg(test)]
    pub(crate) fn capture(
        vault: &Vault,
        scope: crate::dreamer_runner::DreamerConsolidationScope,
    ) -> Result<Self> {
        Self::capture_with_grants(vault, scope, None)
    }

    #[cfg(test)]
    pub(crate) fn capture_with_grants(
        vault: &Vault,
        scope: crate::dreamer_runner::DreamerConsolidationScope,
        caller_scope: Option<&Scope>,
    ) -> Result<Self> {
        Self::prepare_matching(vault, scope, caller_scope, None, None)
    }

    /// [`Self::capture_with_grants`] for a driven pass: while the queues are
    /// long, each iteration polls `deadline` and `cancel`, and a paused,
    /// stopped or expired pass prepares nothing — it ends at its next
    /// boundary instead.
    pub(crate) fn capture_for_pass(
        vault: &Vault,
        scope: crate::dreamer_runner::DreamerConsolidationScope,
        caller_scope: Option<&Scope>,
        deadline: &WakePassDeadline,
        cancel: &WakeCancellation,
    ) -> Result<Self> {
        let preempt = PreparationPreempt { deadline, cancel };
        Self::prepare_matching(vault, scope, caller_scope, None, Some(&preempt))
    }

    /// Direct execution uses the same one-revision planner but materializes
    /// only its own admitted attempt, not unrelated queued branches.
    pub(crate) fn prepare_one(
        vault: &Vault,
        scope: crate::dreamer_runner::DreamerConsolidationScope,
        caller_scope: Option<&Scope>,
        attempt: AttemptId,
    ) -> Result<Self> {
        Self::prepare_matching(vault, scope, caller_scope, Some(attempt), None)
    }

    fn prepare_matching(
        vault: &Vault,
        scope: crate::dreamer_runner::DreamerConsolidationScope,
        caller_scope: Option<&Scope>,
        only_attempt: Option<AttemptId>,
        preempt: Option<&PreparationPreempt<'_>>,
    ) -> Result<Self> {
        let started = std::time::Instant::now();
        let (mut wake, owed) =
            Self::read_matching(vault, scope, caller_scope, only_attempt, preempt)?;
        // The read transaction has closed: each retry's overflow is owed in
        // its own commit, before any branch of this wake runs.
        chunks::owe(vault, scope, owed);
        wake.prepared_ms = super::stage_log::ms_since(started);
        Ok(wake)
    }

    fn read_matching(
        vault: &Vault,
        scope: crate::dreamer_runner::DreamerConsolidationScope,
        caller_scope: Option<&Scope>,
        only_attempt: Option<AttemptId>,
        preempt: Option<&PreparationPreempt<'_>>,
    ) -> Result<(Self, Vec<chunks::WakePreparationChunks>)> {
        // A preempted pass prepares nothing: the driver ends it at its next
        // boundary, and the next pass prepares again.
        let preempted = || preempt.is_some_and(|preempt| preempt.preempted());
        let abandoned = || Ok((Self::default(), Vec::new()));
        // Witnessed TURN text is read under live relationship grants.
        let txn = super::turn_text::snapshot(vault)?;
        let policy = crate::gate::resolve_policy_manifest(&vault.store, &txn)?;
        let records = crate::attempt_queue::AttemptQueue::new(vault).list_in_txn(&txn)?;
        if preempted() {
            return abandoned();
        }
        let completed = chunk_identity::completed_chunks(&records, scope.attempt_kind());
        let left = if only_attempt.is_some() {
            BTreeSet::new()
        } else {
            left_for_later(&records, scope)
        };
        let QueuedPreparation {
            mut ids,
            attempts,
            retries,
            mut preparations,
            lineage,
            rounds,
        } = collect_queued(
            vault,
            &txn,
            WakeQuery {
                scope,
                caller_scope,
                only_attempt,
            },
            records,
            &left,
            &policy,
            preempt,
        )?;
        if preempted() {
            return abandoned();
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
            return Ok((
                Self {
                    attempts,
                    left,
                    preparations,
                    ..Self::default()
                },
                Vec::new(),
            ));
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
        let mut owed = retry::Snapshot {
            vault,
            txn: &txn,
            scope,
            sources: &sources,
            completed: &completed,
            rounds: &rounds,
            lineage: &lineage,
        }
        .resolve(&mut preparations, retries)?;
        // Witnessed TURN text lives on MESSAGE children: pin them in THIS
        // snapshot. A child set that cannot be read refuses only its branches.
        let mut texts = BTreeMap::new();
        let mut refused_texts = BTreeMap::new();
        for outcome in preparations.values() {
            if preempted() {
                return abandoned();
            }
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
        finish_preparations(
            vault,
            &txn,
            &read,
            Frozen {
                texts: &texts,
                refused_texts: &refused_texts,
                lineage: &lineage,
                rounds: &rounds,
                completed: &completed,
            },
            &mut preparations,
            &mut sources,
            &mut owed,
            preempt,
        )?;
        if preempted() {
            return abandoned();
        }
        Ok((
            Self {
                sources,
                texts,
                attempts,
                left,
                preparations,
                read_receipt: Some(read_receipt),
                prepared_ms: 0,
            },
            owed,
        ))
    }

    /// Wall ms this wake's frozen preparation took.
    pub(crate) fn prepared_ms(&self) -> u64 {
        self.prepared_ms
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
        world: plan.branch.world_ref,
        facet: plan.branch.facet_ref,
        relationship: bound.and_then(|scope| scope.relationship),
        project: Some(project),
        ..Scope::default()
    });
    let passage = super::neighbourhood::Passage {
        turns: &turns,
        axes: axes.as_ref(),
        bound,
        thing: plan.thing,
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
            .map_or(0, |branch| branch.turn_count());
        if !left.is_empty() || (head > 0 && head.saturating_add(queued) > WAKE_PREPARED_TURN_CAP) {
            left.insert(*record.id.as_bytes());
        } else {
            head = head.saturating_add(queued);
        }
    }
    left
}
