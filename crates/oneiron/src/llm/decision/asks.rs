//! The person's queue, kept durable: every request the ladder's last rung queues becomes an
//! owner ask that the vault owner role answers. The answer is kept beside its ask, an answer
//! that changed the ladder's is kept for the Coach, and every waiter on the ask wakes.
//!
//! Asks are numbered in arrival order, from 1, so an owner's list pages after the last
//! number it read. Queueing the same open ask again (same question version, principal and
//! evidence) is that ask: a caller that re-runs a decision while its ask is open adds no row.
//! The ask carries what the ladder hands the queue and nothing more; the host renders its
//! own text from the question's.

use std::ops::Bound;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use super::ladder::{HumanDecisionQueue, HumanDecisionRequest, PairedAnswer, ProviderDecision};
use super::types::invalid;
use super::{DecisionAnswer, DecisionQuestion, HumanAskReason, PairedReading, ProviderPin};
use crate::consent::AuthenticatedOwner;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Error, Result, Vault};

/// Every ask, keyed by its arrival number.
const ASKS: SideTable<u64, DecisionAsk, Named> = SideTable::new(&side_table::DECISION_ASK);

/// How far back a new ask looks for the same open ask.
const SAME_ASK_SCAN: usize = 4_096;

/// One ask the ladder queued for the vault owner role.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionAsk {
    /// Arrival number, from 1.
    pub seq: u64,
    /// The ask's own id: the source its person-changed record is bound to.
    #[serde(with = "super::codec::entity")]
    pub id: EntityId,
    /// Vault clock seconds when the ask was queued.
    pub asked_at: u64,
    pub question: DecisionQuestion,
    #[serde(with = "super::codec::entity")]
    pub principal: EntityId,
    #[serde(with = "super::codec::entities")]
    pub evidence: Vec<EntityId>,
    pub reason: HumanAskReason,
    /// The last provider read's answer, when a rung read one before the ask.
    pub prior: Option<AskPrior>,
    pub queue_pin: ProviderPin,
    /// `None` while the ask is open.
    pub answer: Option<AskAnswer>,
}

/// The answer the ladder held when it asked, and the provider that read it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AskPrior {
    pub answer: DecisionAnswer,
    pub probability: Option<f64>,
    pub provider: ProviderPin,
    pub paired: Option<PairedReading>,
    pub person: Option<PairedReading>,
}

/// What the vault owner role answered.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AskAnswer {
    pub answer: DecisionAnswer,
    /// Vault clock seconds when the answer landed.
    pub answered_at: u64,
    /// The owner actor that answered.
    #[serde(with = "super::codec::entity")]
    pub by: EntityId,
    /// Whether the answer changed the ladder's prior (kept for the Coach).
    pub changed: bool,
}

impl DecisionAsk {
    /// The request the ladder queued, rebuilt.
    pub fn request(&self) -> HumanDecisionRequest {
        let unbind = |reading: &PairedReading| PairedAnswer {
            question: reading.question,
            question_version: reading.question_version,
            probability: reading.probability,
        };
        HumanDecisionRequest {
            question: self.question.clone(),
            principal: self.principal,
            evidence: self.evidence.clone(),
            reason: self.reason,
            prior: self.prior.as_ref().map(|prior| ProviderDecision {
                answer: prior.answer.clone(),
                probability: prior.probability,
                paired: prior.paired.as_ref().map(unbind),
                person: prior.person.as_ref().map(unbind),
            }),
            prior_provider: self.prior.as_ref().map(|prior| prior.provider.clone()),
            queue_pin: self.queue_pin.clone(),
        }
    }

    fn is_open_for(&self, request: &HumanDecisionRequest) -> bool {
        self.answer.is_none()
            && self.question.id == request.question.id
            && self.question.version == request.question.version
            && self.principal == request.principal
            && self.evidence == request.evidence
    }
}

impl Vault {
    /// Keeps one ladder ask and returns its arrival number. An open ask for the same
    /// question version, principal and evidence is that ask, and its number is returned.
    pub fn queue_decision_ask(&self, request: &HumanDecisionRequest) -> Result<u64> {
        request.question.validate()?;
        let prior = match (&request.prior, &request.prior_provider) {
            (None, _) => None,
            (Some(prior), Some(provider)) => Some(AskPrior {
                answer: prior.answer.clone(),
                probability: prior.probability,
                provider: provider.clone(),
                paired: prior.paired.map(|reading| reading.bind(provider.clone())),
                person: prior.person.map(|reading| reading.bind(provider.clone())),
            }),
            (Some(_), None) => return Err(invalid("a prior without its provider")),
        };
        let asked_at = self.store.clock.now_recorded_at();
        self.with_write_txn_grouped(|txn| {
            let mut last = None;
            for row in ASKS
                .iter_rev_from(&self.store, txn, &[])?
                .take(SAME_ASK_SCAN)
            {
                let (seq, ask) = row?;
                last.get_or_insert(seq);
                if ask.is_open_for(request) {
                    return Ok(seq);
                }
            }
            let seq = match last {
                None => 1,
                Some(seq) => seq
                    .checked_add(1)
                    .ok_or(Error::IndexOverflow("decision ask sequence"))?,
            };
            let ask = DecisionAsk {
                seq,
                id: EntityId::now(),
                asked_at,
                question: request.question.clone(),
                principal: request.principal,
                evidence: request.evidence.clone(),
                reason: request.reason,
                prior,
                queue_pin: request.queue_pin.clone(),
                answer: None,
            };
            ASKS.put(&self.store, txn, &seq, &ask)?;
            Ok(seq)
        })
    }

    /// Up to `limit` asks after arrival number `after` (from the first when `None`), oldest
    /// first; only the open ones when `open_only`.
    pub fn decision_asks(
        &self,
        after: Option<u64>,
        limit: usize,
        open_only: bool,
    ) -> Result<Vec<DecisionAsk>> {
        let txn = self.store.env.read_txn()?;
        let start = after.map_or(Bound::Unbounded, Bound::Excluded);
        let mut asks = Vec::new();
        for row in ASKS.iter_range(&self.store, &txn, start.as_ref(), Bound::Unbounded)? {
            if asks.len() >= limit {
                break;
            }
            let (seq, ask) = row?;
            if ask.seq != seq {
                return Err(Error::CorruptedIndex("decision ask identity"));
            }
            if !open_only || ask.answer.is_none() {
                asks.push(ask);
            }
        }
        Ok(asks)
    }

    /// One ask by its arrival number.
    pub fn decision_ask(&self, seq: u64) -> Result<Option<DecisionAsk>> {
        let txn = self.store.env.read_txn()?;
        ASKS.get(&self.store, &txn, &seq)
    }

    /// The newest ask for this question version and principal, open or answered: how a
    /// caller whose decision came back with a human ask finds the ask and its answer.
    pub fn latest_decision_ask(
        &self,
        question: &DecisionQuestion,
        principal: EntityId,
    ) -> Result<Option<DecisionAsk>> {
        let txn = self.store.env.read_txn()?;
        for row in ASKS.iter_rev_from(&self.store, &txn, &[])? {
            let (_, ask) = row?;
            if ask.question.id == question.id
                && ask.question.version == question.version
                && ask.principal == principal
            {
                return Ok(Some(ask));
            }
        }
        Ok(None)
    }

    /// The vault owner's answer to one ask. The answer must be one the question's contract
    /// accepts, and never an abstention. An answer that changed the ladder's prior is kept
    /// for the Coach, bound to the ask's id. The same answer again is a no-op; a different
    /// one to an answered ask is refused.
    pub fn answer_decision_ask(
        &self,
        owner: &AuthenticatedOwner,
        seq: u64,
        answer: DecisionAnswer,
    ) -> Result<DecisionAsk> {
        self.recheck_owner(owner)?;
        let by = owner.actor_for_read(self)?;
        let ask = self
            .decision_ask(seq)?
            .ok_or_else(|| invalid("no such decision ask"))?;
        if let Some(held) = &ask.answer {
            return if held.answer == answer {
                Ok(ask)
            } else {
                Err(invalid("decision ask already answered"))
            };
        }
        let changed = ask.request().changed_by(answer.clone())?;
        if let Some(record) = &changed {
            self.record_person_changed_answer(ask.id, record)?;
        }
        let answered_at = self.store.clock.now_recorded_at();
        self.with_write_txn_grouped(|txn| {
            let mut held = ASKS
                .get(&self.store, &*txn, &seq)?
                .ok_or_else(|| invalid("no such decision ask"))?;
            match &held.answer {
                Some(prior) if prior.answer == answer => return Ok(held),
                Some(_) => return Err(invalid("decision ask already answered")),
                None => {}
            }
            held.answer = Some(AskAnswer {
                answer,
                answered_at,
                by,
                changed: changed.is_some(),
            });
            ASKS.put(&self.store, txn, &seq, &held)?;
            Ok(held)
        })
    }
}

/// The ladder's person queue over the vault's asks. Hold one per vault and lend it: an
/// answer given through it wakes every waiter on it.
pub struct DecisionAsks {
    vault: Arc<Vault>,
    /// The arrival number of the last answer given through this queue.
    answered: watch::Sender<u64>,
}

impl DecisionAsks {
    #[must_use]
    pub fn new(vault: Arc<Vault>) -> Self {
        Self {
            vault,
            answered: watch::channel(0).0,
        }
    }

    /// See [`Vault::decision_asks`].
    pub fn page(
        &self,
        after: Option<u64>,
        limit: usize,
        open_only: bool,
    ) -> Result<Vec<DecisionAsk>> {
        self.vault.decision_asks(after, limit, open_only)
    }

    /// See [`Vault::decision_ask`].
    pub fn get(&self, seq: u64) -> Result<Option<DecisionAsk>> {
        self.vault.decision_ask(seq)
    }

    /// See [`Vault::latest_decision_ask`].
    pub fn latest(
        &self,
        question: &DecisionQuestion,
        principal: EntityId,
    ) -> Result<Option<DecisionAsk>> {
        self.vault.latest_decision_ask(question, principal)
    }

    /// Answers one ask (see [`Vault::answer_decision_ask`]) and wakes its waiters.
    pub fn answer(
        &self,
        owner: &AuthenticatedOwner,
        seq: u64,
        answer: DecisionAnswer,
    ) -> Result<DecisionAsk> {
        let ask = self.vault.answer_decision_ask(owner, seq, answer)?;
        self.answered.send_replace(seq);
        Ok(ask)
    }

    /// Waits for the answer to ask `seq`. An ask answered before the wait, or before a
    /// restart, returns at once.
    pub async fn answered(&self, seq: u64) -> Result<AskAnswer> {
        let mut changes = self.answered.subscribe();
        loop {
            let ask = self
                .get(seq)?
                .ok_or_else(|| invalid("no such decision ask"))?;
            if let Some(answer) = ask.answer {
                return Ok(answer);
            }
            // The sender lives in `self`, so it outlives this wait.
            if changes.changed().await.is_err() {
                return Err(invalid("decision asks closed"));
            }
        }
    }
}

impl HumanDecisionQueue for DecisionAsks {
    fn queue(&self, request: HumanDecisionRequest) -> Result<()> {
        self.vault.queue_decision_ask(&request).map(drop)
    }
}
