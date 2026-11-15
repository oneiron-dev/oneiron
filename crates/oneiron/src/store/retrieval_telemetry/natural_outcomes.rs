//! Gated retrieval outcomes the engine labels from what the user says next
//! (ARCH-0037 #reward and #contributing-runs; census L9-06). The rulings:
//! PLAN-L9-06 GATE, HIT, CONTRIBUTORS and COST = A (Engine, 14 Nov 03:02)
//! and UNBUILT-03-TURN-LINK = A (Engine, 15 Nov 22:31).
//!
//! A run is labelled only when its turn follows the convention on
//! [`super::RetrievalTurn`]: `episode_id` names the run's CONVERSATION and
//! `turn_id` its TURN. The natural signal is a claim the user stated
//! ([`ClaimSource::UserStated`]) whose evidence TURN is another TURN of that
//! conversation, learned after the run started. It corrects a claim the run
//! served when it supersedes that claim with another subject, predicate or
//! value (`confirmed_fact_hit` false); it confirms the claim when it states
//! the same subject, predicate and value (true). The gate is closed-form and
//! runs no model: 1.0 when the signal names a memory a run served, and no
//! label otherwise, so a right answer over a wrong retrieval rewards nothing.
//! Only the runs of the turn that served the named memory are named, each
//! with the full gate; nothing is split by overlap. A run without the
//! convention gets no label, and nothing is asked of the user.

use std::collections::BTreeMap;

use heed::RoTxn;

use super::run_store::RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT;
use super::types::{RetrievalEndOutcome, RetrievalRunId, RetrievalRunRecord};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::provenance::{EvidenceTurn, claim_evidence_turns_in};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION};
use crate::store::StoreRead;
use crate::{ClaimBody, ClaimSource, ClaimSubject, Vault};

/// The gate a natural signal passes: closed-form, 1.0 when the signal names
/// a memory a run served (PLAN-L9-06 GATE = A).
const NATURAL_OUTCOME_GATE: f32 = 1.0;
/// λ, the shaped reward's cost weight: a shipped prior (PLAN-L9-06 COST = A,
/// the value `store/tests.rs` checks), which the ruler may move later.
const NATURAL_OUTCOME_COST_WEIGHT: f32 = 0.1;
/// The evaluator each natural outcome names in its metadata.
const NATURAL_OUTCOME_EVALUATOR: &str = "engine.natural_outcome.v1";

/// One outcome to write: the turn, the claim the user stated, and whether
/// it confirmed (true) or corrected (false) what the turn's runs served.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct NaturalLabel {
    turn_id: [u8; 16],
    signal: EntityId,
    confirmed: bool,
}

/// A claim the user stated about a served claim, and the TURNs it came from.
struct NaturalSignal {
    claim: EntityId,
    confirmed: bool,
    turns: Vec<EvidenceTurn>,
}

impl Vault {
    /// Labels the runs whose served claims the user later corrected or
    /// confirmed (see the module doc) through the ordinary end-outcome writer,
    /// and returns how many outcomes it wrote. It reads the newest finalized
    /// runs, the window the policy update reads. Each outcome's key names its
    /// signal, so a second pass replaces its labels and never adds to them.
    /// Call it outside any write transaction, before the policy update.
    pub(crate) fn produce_natural_retrieval_outcomes(&self) -> Result<usize> {
        let runs = self.retrieval_runs(RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT)?;
        let labels = self.natural_labels(&runs)?;
        if labels.is_empty() {
            return Ok(0);
        }
        let latency_scale_us = p95_elapsed_us(&runs);
        let written = labels.len();
        for (label, retrieval_run_ids) in labels {
            let kind = if label.confirmed {
                "confirmation"
            } else {
                "correction"
            };
            let signal_ref = label.signal.to_hex();
            self.record_retrieval_end_outcome(RetrievalEndOutcome {
                retrieval_run_ids,
                key: format!("natural.{kind}:{signal_ref}"),
                turn_id: label.turn_id,
                gate_score: NATURAL_OUTCOME_GATE,
                confirmed_fact_hit: label.confirmed,
                latency_scale_us,
                cost_weight: NATURAL_OUTCOME_COST_WEIGHT,
                metadata: BTreeMap::from([
                    ("source".to_owned(), "natural".to_owned()),
                    ("signal_ref".to_owned(), signal_ref),
                    ("evaluator".to_owned(), NATURAL_OUTCOME_EVALUATOR.to_owned()),
                ]),
            })?;
        }
        Ok(written)
    }

    /// The outcomes `runs` earn, each with the runs it names, read in one
    /// snapshot. A run counts only when its turn names a CONVERSATION; a
    /// served claim's signals are read once however many runs served it.
    fn natural_labels(
        &self,
        runs: &[RetrievalRunRecord],
    ) -> Result<BTreeMap<NaturalLabel, Vec<RetrievalRunId>>> {
        let mut labels: BTreeMap<NaturalLabel, Vec<RetrievalRunId>> = BTreeMap::new();
        let txn = self.store.env.read_txn()?;
        let read = self.store.read();
        let mut conversations: BTreeMap<EntityId, bool> = BTreeMap::new();
        let mut signals: BTreeMap<EntityId, Vec<NaturalSignal>> = BTreeMap::new();
        let mut stated_by_subject: BTreeMap<EntityId, Vec<(EntityId, ClaimBody)>> = BTreeMap::new();
        for run in runs {
            let Some(turn) = run.turn else {
                continue;
            };
            let Ok(conversation) = EntityId::from_bytes(turn.episode_id) else {
                continue;
            };
            let names_conversation = match conversations.get(&conversation) {
                Some(known) => *known,
                None => {
                    let known = entity_type_in(&read, &txn, &conversation)?
                        == Some(ENTITY_TYPE_CONVERSATION);
                    conversations.insert(conversation, known);
                    known
                }
            };
            if !names_conversation {
                continue;
            }
            let run_turn = EntityId::from_bytes(turn.turn_id).ok();
            for served in &run.result_ids {
                let Ok(served) = EntityId::from_bytes(*served) else {
                    continue;
                };
                if !signals.contains_key(&served) {
                    let found =
                        self.natural_signals_in(&read, &txn, &served, &mut stated_by_subject)?;
                    signals.insert(served, found);
                }
                for signal in &signals[&served] {
                    let later_in_conversation = signal.turns.iter().any(|evidence| {
                        evidence.conversation == conversation
                            && Some(evidence.turn) != run_turn
                            && evidence.learned_at > run.started_at
                    });
                    if !later_in_conversation {
                        continue;
                    }
                    let named = labels
                        .entry(NaturalLabel {
                            turn_id: turn.turn_id,
                            signal: signal.claim,
                            confirmed: signal.confirmed,
                        })
                        .or_default();
                    if !named.contains(&run.run_id) {
                        named.push(run.run_id);
                    }
                }
            }
        }
        Ok(labels)
    }

    /// The claims the user stated that supersede `served` or state its
    /// subject, predicate and value, each with its evidence TURNs; none for a
    /// served id that is no readable CLAIM. `stated_by_subject` keeps each
    /// subject's user-stated claims, so a subject is read once per pass.
    fn natural_signals_in(
        &self,
        read: &StoreRead<'_>,
        txn: &RoTxn<'_>,
        served: &EntityId,
        stated_by_subject: &mut BTreeMap<EntityId, Vec<(EntityId, ClaimBody)>>,
    ) -> Result<Vec<NaturalSignal>> {
        let Some(served_body) = self.claim_in(read, txn, served)? else {
            return Ok(Vec::new());
        };
        let mut found: BTreeMap<EntityId, (bool, ClaimBody)> = BTreeMap::new();
        for superseder in
            read.port_edge_peers(txn, served, EdgeDirection::In, EdgeKind::Supersedes)?
        {
            let superseder = superseder?;
            if superseder == *served {
                continue;
            }
            if let Some(body) = self.claim_in(read, txn, &superseder)?
                && matches!(body.source, Some(ClaimSource::UserStated))
            {
                let confirmed = states_same_fact(&body, &served_body);
                found.insert(superseder, (confirmed, body));
            }
        }
        if let ClaimSubject::Entity(subject) = served_body.subject {
            if !stated_by_subject.contains_key(&subject) {
                let mut stated = Vec::new();
                for claim in crate::ports::ClaimStore::port_claim_list(self, txn, &subject)? {
                    if let Some(body) = self.claim_in(read, txn, &claim)?
                        && matches!(body.source, Some(ClaimSource::UserStated))
                    {
                        stated.push((claim, body));
                    }
                }
                stated_by_subject.insert(subject, stated);
            }
            for (claim, body) in &stated_by_subject[&subject] {
                if claim != served && states_same_fact(body, &served_body) {
                    found.insert(*claim, (true, body.clone()));
                }
            }
        }
        let mut signals = Vec::with_capacity(found.len());
        for (claim, (confirmed, body)) in found {
            let turns = claim_evidence_turns_in(read, txn, &claim, &body)?;
            if !turns.is_empty() {
                signals.push(NaturalSignal {
                    claim,
                    confirmed,
                    turns,
                });
            }
        }
        Ok(signals)
    }

    /// `id`'s CLAIM body as history reads it: none for a row that is absent,
    /// withdrawn by a deletion, or no CLAIM.
    fn claim_in(
        &self,
        read: &StoreRead<'_>,
        txn: &RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<ClaimBody>> {
        if entity_type_in(read, txn, id)? != Some(ENTITY_TYPE_CLAIM) {
            return Ok(None);
        }
        crate::ports::ClaimStore::port_claim_get(self, txn, id)
    }
}

/// Whether `stated` states the subject, predicate and value of `served`.
fn states_same_fact(stated: &ClaimBody, served: &ClaimBody) -> bool {
    stated.subject == served.subject
        && stated.predicate == served.predicate
        && stated.value == served.value
}

/// `id`'s stored entity type, from its row's first byte, read in place.
fn entity_type_in(read: &StoreRead<'_>, txn: &RoTxn<'_>, id: &EntityId) -> Result<Option<u8>> {
    Ok(read
        .port_entity_with_raw(txn, id, |raw| Ok(raw.first().copied()))?
        .flatten())
}

/// The nearest-rank 95th percentile of the runs' `elapsed_us`, at least 1:
/// the reward's latency scale, so `latency_norm` is a share of the window's
/// p95 (PLAN-L9-06 COST = A; ARCH-0037:224).
fn p95_elapsed_us(runs: &[RetrievalRunRecord]) -> u64 {
    let mut times: Vec<u64> = runs.iter().map(|run| run.elapsed_us).collect();
    if times.is_empty() {
        return 1;
    }
    times.sort_unstable();
    times[(times.len() * 95).div_ceil(100).saturating_sub(1)].max(1)
}
