//! The person's queue, kept durable: every request the ladder's last rung queues becomes an
//! ask put to a role (Q3 by role). The caller binds who it goes to ([`AskTo`]); the vault
//! resolves the first role on its chain with a live holder when it is queued, and the next
//! one when it climbs. A holder of that role answers it, checked again in the snapshot it
//! answers in; the vault owner answers any ask whose chain reaches the owners. The answer is
//! kept beside its ask, an answer that changed the ladder's is kept for the Coach, and every
//! waiter on the ask wakes.
//!
//! Asks are numbered in arrival order, from 1, so an owner's list pages after the last
//! number it read. Queueing the same open ask again (same question version, principal and
//! evidence) is that ask: a caller that re-runs a decision while its ask is open adds no row.
//! The ask carries what the ladder hands the queue and nothing more; the host renders its
//! own text from the question's.

use std::collections::{BTreeSet, VecDeque};
use std::ops::Bound;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use super::ladder::{
    AskAct, AskRole, AskRoleResolver, AskTo, HolderKind, HumanDecisionQueue, HumanDecisionRequest,
    PairedAnswer, ProviderDecision, ResolvedRole, RoleHolder, RoleRank,
};
use super::types::invalid;
use super::{DecisionAnswer, DecisionQuestion, HumanAskReason, PairedReading, ProviderPin};
use crate::consent::AuthenticatedOwner;
use crate::side_table::{self, Named, SideTable};
use crate::write_envelope::WriteActor;
use crate::{EdgeActorClass, EntityId, Error, Result, Vault};

/// Every ask, keyed by its arrival number.
const ASKS: SideTable<u64, DecisionAsk, Named> = SideTable::new(&side_table::DECISION_ASK);

/// How far back a new ask looks for the same open ask.
const SAME_ASK_SCAN: usize = 4_096;

/// The most project boards an ask's chain walks.
const MAX_BOARD_WALK: usize = 64;

/// One ask the ladder queued for a role.
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
    /// Who the ask goes to, as its caller bound it.
    pub to: AskTo,
    /// The role it is at and the live holders it was put to, resolved when it was queued
    /// or last climbed; none while no role up to its ceiling has one.
    pub role: Option<ResolvedRole>,
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

/// What a role's holder answered.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AskAnswer {
    pub answer: DecisionAnswer,
    /// Vault clock seconds when the answer landed.
    pub answered_at: u64,
    /// The actor that answered, authenticated by its door.
    #[serde(with = "super::codec::entity")]
    pub by: EntityId,
    /// The role it answered as, and whether it is a person or a bound agent.
    pub role: AskRole,
    pub kind: HolderKind,
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
            to: self.to.clone(),
        }
    }

    fn is_open_for(&self, request: &HumanDecisionRequest) -> bool {
        self.answer.is_none()
            && self.question.id == request.question.id
            && self.question.version == request.question.version
            && self.principal == request.principal
            && self.evidence == request.evidence
            && self.to == request.to
    }
}

impl Vault {
    /// Keeps one ladder ask, put to the first role on its chain with a live holder, and
    /// returns its arrival number. An open ask for the same question version, principal,
    /// evidence and role is that ask, and its number is returned.
    pub fn queue_decision_ask(&self, request: &HumanDecisionRequest) -> Result<u64> {
        request.question.validate()?;
        request.to.validate()?;
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
            let role = self.next_ask_role_in_txn(txn, &request.to, None)?;
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
                to: request.to.clone(),
                role,
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
        self.scan_decision_asks(after, limit, |ask| !open_only || ask.answer.is_none())
    }

    /// Up to `limit` open asks after arrival number `after`, oldest first, that were put to
    /// `holder`: its actor is among the holders of the role each is at. The holders are the
    /// ones the ask was queued or last climbed to; an answer reads them again.
    pub fn open_decision_asks_for(
        &self,
        holder: EntityId,
        after: Option<u64>,
        limit: usize,
    ) -> Result<Vec<DecisionAsk>> {
        self.scan_decision_asks(after, limit, |ask| {
            ask.answer.is_none()
                && ask
                    .role
                    .as_ref()
                    .is_some_and(|role| role.holders.iter().any(|held| held.actor == holder))
        })
    }

    /// Up to `limit` asks after `after` that `keep` keeps, oldest first.
    fn scan_decision_asks(
        &self,
        after: Option<u64>,
        limit: usize,
        keep: impl Fn(&DecisionAsk) -> bool,
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
            if keep(&ask) {
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

    /// [`Self::decision_ask`] in the caller's snapshot.
    pub(crate) fn decision_ask_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        seq: u64,
    ) -> Result<Option<DecisionAsk>> {
        ASKS.get(&self.store, txn, &seq)
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

    /// The vault owner's answer to one ask whose chain reaches the owners, as the owner role.
    /// Otherwise as [`Self::answer_decision_ask_as`].
    pub fn answer_decision_ask(
        &self,
        owner: &AuthenticatedOwner,
        seq: u64,
        answer: DecisionAnswer,
    ) -> Result<DecisionAsk> {
        self.recheck_owner(owner)?;
        let by = owner.actor_for_read(self)?;
        self.settle_decision_ask(seq, answer, |_, ask| {
            if ask.to.ceiling != RoleRank::Owner {
                return Err(invalid("the decision ask does not reach the owners"));
            }
            Ok((by, AskRole::Owner, HolderKind::Person))
        })
    }

    /// A role holder's answer to one ask: a person or a bound agent, verified as the writer
    /// in each snapshot the answer reads, that holds the ask's role there (its holders are
    /// read again, not taken from the queue). An e-signature or a payment takes only a
    /// person. The answer must be one the question's contract accepts, and never an
    /// abstention. An answer that changed the ladder's prior is kept for the Coach, bound
    /// to the ask's id. The same answer again is a no-op; a different one to an answered
    /// ask is refused.
    pub fn answer_decision_ask_as(
        &self,
        holder: &WriteActor,
        seq: u64,
        answer: DecisionAnswer,
    ) -> Result<DecisionAsk> {
        let kind = holder_kind(holder)?;
        let actor = holder.entity_ref();
        self.settle_decision_ask(seq, answer, |txn, ask| {
            self.verify_write_actor_in_txn(txn, holder)?;
            let role = ask
                .role
                .as_ref()
                .ok_or_else(|| invalid("the decision ask has no role to answer for"))?;
            if !self.holds_ask_role_in_txn(txn, ask, actor, kind)? {
                return Err(invalid("the answerer does not hold the decision ask's role"));
            }
            Ok((actor, role.role.clone(), kind))
        })
    }

    /// Whether `actor`, as `kind`, holds the role `ask` is at now (its holders read again).
    fn holds_ask_role_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        ask: &DecisionAsk,
        actor: EntityId,
        kind: HolderKind,
    ) -> Result<bool> {
        let Some(role) = &ask.role else {
            return Ok(false);
        };
        Ok(self
            .role_holders_in_txn(txn, &role.role, ask.to.act)?
            .iter()
            .any(|held| held.actor == actor && held.kind == kind))
    }

    /// One answer to ask `seq`, authorised by `answerer` (the actor, the role it answers as
    /// and its kind) in the snapshot the ask is read in and again in the one it is written
    /// in.
    fn settle_decision_ask(
        &self,
        seq: u64,
        answer: DecisionAnswer,
        answerer: impl Fn(&heed::RoTxn<'_>, &DecisionAsk) -> Result<(EntityId, AskRole, HolderKind)>,
    ) -> Result<DecisionAsk> {
        let ask = {
            let txn = self.store.env.read_txn()?;
            let ask = ASKS
                .get(&self.store, &txn, &seq)?
                .ok_or_else(|| invalid("no such decision ask"))?;
            answerer(&txn, &ask)?;
            ask
        };
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
            let read: &heed::RoTxn<'_> = txn;
            let (by, role, kind) = answerer(read, &held)?;
            held.answer = Some(AskAnswer {
                answer,
                answered_at,
                by,
                role,
                kind,
                changed: changed.is_some(),
            });
            ASKS.put(&self.store, txn, &seq, &held)?;
            Ok(held)
        })
    }

    /// Moves an open ask to the next role on its chain with a live holder, up to its
    /// ceiling; an unresolved ask resolves from its first role again. None, and the ask
    /// stays where it is, when no such role is left.
    pub fn climb_decision_ask(&self, seq: u64) -> Result<Option<ResolvedRole>> {
        self.climb_decision_ask_with(seq, |_, _| Ok(()))
    }

    /// [`Self::climb_decision_ask`] for an actor, verified as the writer in the snapshot the
    /// ask climbs in: a holder of the role the ask is at now (it passes the ask up), the
    /// principal the ask is for, or a live owner of the vault.
    pub fn climb_decision_ask_as(
        &self,
        by: &WriteActor,
        seq: u64,
    ) -> Result<Option<ResolvedRole>> {
        let actor = by.entity_ref();
        self.climb_decision_ask_with(seq, |txn, ask| {
            self.verify_write_actor_in_txn(txn, by)?;
            if ask.principal == actor
                || self.holds_ask_role_in_txn(txn, ask, actor, holder_kind(by)?)?
                || crate::policy_model::owners_in_txn(self, txn)?.contains(&actor)
            {
                return Ok(());
            }
            Err(invalid(
                "only the ask's role holder, its principal or an owner climbs a decision ask",
            ))
        })
    }

    /// One climb of ask `seq`, admitted by `climber` in the snapshot it climbs in.
    fn climb_decision_ask_with(
        &self,
        seq: u64,
        climber: impl Fn(&heed::RoTxn<'_>, &DecisionAsk) -> Result<()>,
    ) -> Result<Option<ResolvedRole>> {
        self.with_write_txn_grouped(|txn| {
            let mut ask = ASKS
                .get(&self.store, &*txn, &seq)?
                .ok_or_else(|| invalid("no such decision ask"))?;
            let read: &heed::RoTxn<'_> = txn;
            climber(read, &ask)?;
            if ask.answer.is_some() {
                return Err(invalid("decision ask already answered"));
            }
            let next =
                self.next_ask_role_in_txn(&*txn, &ask.to, ask.role.as_ref().map(|at| &at.role))?;
            if let Some(role) = &next {
                ask.role = Some(role.clone());
                ASKS.put(&self.store, txn, &seq, &ask)?;
            }
            Ok(next)
        })
    }

    /// [`AskRoleResolver::next_role`] in the caller's snapshot.
    pub(crate) fn next_ask_role_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        to: &AskTo,
        after: Option<&AskRole>,
    ) -> Result<Option<ResolvedRole>> {
        to.validate()?;
        let chain = self.ask_chain_in_txn(txn, &to.role)?;
        let start = match after {
            None => 0,
            Some(after) => match chain.iter().position(|(role, _)| role == after) {
                Some(at) => at + 1,
                None => return Ok(None),
            },
        };
        for (role, named) in chain.into_iter().skip(start) {
            if role.rank() > to.ceiling {
                break;
            }
            let holders = self.live_holders_in_txn(txn, named, to.act)?;
            if !holders.is_empty() {
                return Ok(Some(ResolvedRole { role, holders }));
            }
        }
        Ok(None)
    }

    /// The live actors holding `role` now who may answer for `act`.
    fn role_holders_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        role: &AskRole,
        act: AskAct,
    ) -> Result<Vec<RoleHolder>> {
        let named = match role {
            AskRole::Responsible { actor, .. } => vec![*actor],
            AskRole::Board { project } => self
                .board_in_txn(txn, *project)?
                .map(|(board, _)| board)
                .unwrap_or_default(),
            AskRole::Owner => crate::policy_model::owners_in_txn(self, txn)?,
        };
        self.live_holders_in_txn(txn, named, act)
    }

    /// The chain an ask climbs from `role`, each role with the actors named to it: a
    /// responsible actor; then the boards of its project, or of the asked board's, and
    /// their parents', breadth first; then the owners.
    fn ask_chain_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        role: &AskRole,
    ) -> Result<Vec<(AskRole, Vec<EntityId>)>> {
        let mut chain = Vec::new();
        let project = match role {
            AskRole::Responsible { actor, project } => {
                chain.push((role.clone(), vec![*actor]));
                *project
            }
            AskRole::Board { project } => Some(*project),
            AskRole::Owner => None,
        };
        let mut queue: VecDeque<EntityId> = project.into_iter().collect();
        let mut seen = BTreeSet::new();
        while let Some(project) = queue.pop_front() {
            if seen.len() >= MAX_BOARD_WALK || !seen.insert(project) {
                continue;
            }
            let Some((board, parents)) = self.board_in_txn(txn, project)? else {
                continue;
            };
            chain.push((AskRole::Board { project }, board));
            queue.extend(parents);
        }
        chain.push((
            AskRole::Owner,
            crate::policy_model::owners_in_txn(self, txn)?,
        ));
        Ok(chain)
    }

    /// A project's effective board and parents.
    fn board_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        project: EntityId,
    ) -> Result<Option<(Vec<EntityId>, Vec<EntityId>)>> {
        Ok(self
            .effective_project_in_txn(txn, project)?
            .map(|(_, effective)| (ids(&effective.board), ids(&effective.parents))))
    }

    /// Of the actors `named` to a role, those who may answer for `act` now: a live person,
    /// or a live bound agent unless the act takes only a person.
    fn live_holders_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        named: Vec<EntityId>,
        act: AskAct,
    ) -> Result<Vec<RoleHolder>> {
        let mut holders: Vec<RoleHolder> = Vec::new();
        for actor in named {
            if holders.iter().any(|held| held.actor == actor) {
                continue;
            }
            let kind = if crate::consent::person_is_live_in_txn(self, txn, &actor)? {
                HolderKind::Person
            } else if !act.person_only()
                && self
                    .verify_write_actor_in_txn(txn, &WriteActor::new(actor, EdgeActorClass::Agent))
                    .is_ok()
            {
                HolderKind::Agent
            } else {
                continue;
            };
            holders.push(RoleHolder { actor, kind });
        }
        Ok(holders)
    }
}

/// Hex entity references, the unreadable ones skipped.
fn ids(hexes: &[String]) -> Vec<EntityId> {
    hexes
        .iter()
        .filter_map(|hex| EntityId::from_hex(hex).ok())
        .collect()
}

impl AskRoleResolver for Vault {
    fn next_role(&self, to: &AskTo, after: Option<&AskRole>) -> Result<Option<ResolvedRole>> {
        let txn = self.store.env.read_txn()?;
        self.next_ask_role_in_txn(&txn, to, after)
    }
}

/// The kind of role holder `actor` writes as: a person or a bound agent.
fn holder_kind(actor: &WriteActor) -> Result<HolderKind> {
    match actor.actor_class() {
        EdgeActorClass::Human => Ok(HolderKind::Person),
        EdgeActorClass::Agent => Ok(HolderKind::Agent),
        EdgeActorClass::System => Err(invalid("a system actor holds no role")),
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

    /// Answers one ask as a holder of its role (see [`Vault::answer_decision_ask_as`]) and
    /// wakes its waiters.
    pub fn answer_as(
        &self,
        holder: &WriteActor,
        seq: u64,
        answer: DecisionAnswer,
    ) -> Result<DecisionAsk> {
        let ask = self.vault.answer_decision_ask_as(holder, seq, answer)?;
        self.answered.send_replace(seq);
        Ok(ask)
    }

    /// See [`Vault::climb_decision_ask`].
    pub fn climb(&self, seq: u64) -> Result<Option<ResolvedRole>> {
        self.vault.climb_decision_ask(seq)
    }

    /// See [`Vault::climb_decision_ask_as`].
    pub fn climb_as(&self, by: &WriteActor, seq: u64) -> Result<Option<ResolvedRole>> {
        self.vault.climb_decision_ask_as(by, seq)
    }

    /// See [`Vault::open_decision_asks_for`].
    pub fn open_for(
        &self,
        holder: EntityId,
        after: Option<u64>,
        limit: usize,
    ) -> Result<Vec<DecisionAsk>> {
        self.vault.open_decision_asks_for(holder, after, limit)
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
