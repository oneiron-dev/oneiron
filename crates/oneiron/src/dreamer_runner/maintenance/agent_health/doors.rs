//! Card reads and doors: period reads, the card view and settlement.
//! Entry: the `Vault` card doors and `Memory::{concern_card, concern_outcome}`.
//! Owns the concern request and view types; the card is in `vocabulary`.

use serde::{Deserialize, Serialize};

use super::{
    AgentHealthCard, AgentHealthLoadedSkill, AgentHealthOutcome, CARDS, ConcernMoveBasis, card_ref,
    loaded, moves, outcomes, parse_card_ref,
};
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::consent::AuthenticatedOwner;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::run_tree::{RunTree, RunTreeAdapter};
use crate::{EntityId, Error, Result, Vault};

/// The first time in `[from, to)` that `card` was opened, updated or
/// settled, if any: the one period test [`Vault::agent_health_cards_between`]
/// and the digest's cadence and assembly share (FIX 1979).
pub(in crate::dreamer_runner::maintenance) fn card_touched_in(
    card: &AgentHealthCard,
    from: u64,
    to: u64,
) -> Option<u64> {
    [Some(card.opened_at), Some(card.updated_at), card.outcome_at]
        .into_iter()
        .flatten()
        .filter(|at| (from..to).contains(at))
        .min()
}

/// Every card in `txn`, concern first and newest first within a tone, as
/// [`Vault::agent_health_cards_between`] orders them: the weave report reads
/// them in its own snapshot (OF-568).
pub(crate) fn agent_health_cards_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<AgentHealthCard>> {
    let mut cards: Vec<AgentHealthCard> = CARDS
        .scan(&vault.store, txn)?
        .into_iter()
        .map(|(_, card)| card)
        .collect();
    cards.sort_by(|left, right| {
        right
            .tone
            .impact()
            .cmp(&left.tone.impact())
            .then(right.updated_at.cmp(&left.updated_at))
    });
    Ok(cards)
}

/// One card by its `health:` handle in `txn`: a saved weave period rechecks
/// the card it carries against the current one (OF-568).
pub(crate) fn agent_health_card_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    card: &str,
) -> Result<Option<AgentHealthCard>> {
    let Some(key) = parse_card_ref(card) else {
        return Ok(None);
    };
    CARDS.get(&vault.store, txn, &key)
}

/// What a card now says: the answer to a settle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConcernCardSummary {
    /// The card's `health:` handle.
    pub card: String,
    /// The agent the card is about, as 32 hex.
    pub agent: String,
    pub signal: String,
    pub tone: String,
    pub outcome: String,
    pub evidence: usize,
}

impl ConcernCardSummary {
    #[must_use]
    pub fn of(card: &AgentHealthCard) -> Self {
        Self {
            card: card.card_ref(),
            agent: card.subject.to_hex(),
            signal: card.signal.as_str().to_owned(),
            tone: card.tone.as_str().to_owned(),
            outcome: card.outcome.as_str().to_owned(),
            evidence: card.evidence.len(),
        }
    }
}

/// The outcome a card's reader sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConcernOutcome {
    Confirmed,
    Dismissed,
    Unresolved,
}

impl From<ConcernOutcome> for AgentHealthOutcome {
    fn from(outcome: ConcernOutcome) -> Self {
        match outcome {
            ConcernOutcome::Confirmed => Self::Confirmed,
            ConcernOutcome::Dismissed => Self::Dismissed,
            ConcernOutcome::Unresolved => Self::Unresolved,
        }
    }
}

/// `self.inbox.concern`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConcernCardRequest {
    /// The card's `health:` handle: the concern row's `payload_ref`.
    pub card: String,
}

/// `self.inbox.concern.outcome`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConcernOutcomeRequest {
    /// The card's `health:` handle: the concern row's `payload_ref`.
    pub card: String,
    pub outcome: ConcernOutcome,
}

/// One card as its reader sees it, with the ARCH-0066 run-tree diagram.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentHealthCardView {
    /// The card's `health:` handle.
    pub card: String,
    pub body: AgentHealthCard,
    /// The run of the card's newest attempt, when it has one.
    pub run_tree: Option<AgentHealthRunTree>,
    /// The skills that attempt's pack loaded, each at the revision it
    /// pinned, with its instructions whole: what a `skill_edit` replaces.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skills: Vec<AgentHealthLoadedSkill>,
    /// The owner's applied prompt continuation of that attempt (FIX 3694),
    /// once one is applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_inject: Option<AgentHealthPromptInject>,
    /// The card's evidence basis: a note or a steer echoes it, and its
    /// receipt records whether the evidence moved since.
    pub basis: ConcernMoveBasis,
}

/// The owner's applied prompt continuation of a card's failed attempt
/// (FIX 3694): the approval it ran under and the successor it enqueued.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentHealthPromptInject {
    /// The approval's id, as 32 hex.
    pub approval: String,
    /// The successor attempt, as 32 hex.
    pub successor: String,
    /// The Coach ask approved, as 32 hex.
    pub ask: String,
    /// The approving owner.
    pub by: EntityId,
    pub at: u64,
    /// The approved prompt is the owner's edit of the Coach's draft.
    pub edited: bool,
}

/// The run a card's attempt is in, with that attempt's node marked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentHealthRunTree {
    pub run_id: String,
    pub tree: RunTree,
    /// The node the card is about: its attempt, as 32 hex.
    pub marked: String,
}

/// Whether `reader` sees and settles `card`: one of its recipients (its
/// leader, its spawner, an owner with a copy) or a live vault owner. The
/// agent a card is about never settles it. A recipient keeps reading a card
/// after its role changes (FIX 8710).
pub(super) fn may_read(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    card: &AgentHealthCard,
    reader: EntityId,
) -> Result<bool> {
    if reader == card.subject {
        return Ok(false);
    }
    Ok(card.recipients.contains(&reader)
        || crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &reader)?)
}

/// Sets a card's outcome. A settled card leaves the inbox until its evidence
/// grows past the watermark set here, but an owner copy stays with each live
/// owner whose own receipt does not cover it (`delivery`, FIX 8709). Both
/// doors reach it through `outcomes::settle_with_review_receipt_in_txn`.
pub(super) fn settle(
    card: &mut AgentHealthCard,
    by: EntityId,
    outcome: AgentHealthOutcome,
    at: u64,
) {
    card.outcome = outcome;
    card.outcome_by = Some(by);
    card.outcome_at = Some(at);
    card.watermark = card.evidence.len();
    card.updated_at = at;
}

pub(super) fn forbidden() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        "only a card's recipient or a vault owner reads or settles a concern card",
        &["Act on the cards your inbox shows: their payload_ref is the card."],
    )
}

fn card_view(
    vault: &Vault,
    key: &([u8; 16], [u8; 1], [u8; 16]),
    card: AgentHealthCard,
) -> Result<AgentHealthCardView> {
    let mut run_tree = None;
    let mut prompt_inject = None;
    if let Some(attempt) = card.attempt {
        let attempt = AttemptId::from_bytes(attempt.as_bytes())?;
        prompt_inject = crate::agent_dispatch::prompt_inject_application(vault, attempt)?;
        if let Some(run_id) = AttemptQueue::new(vault)
            .get(attempt)?
            .and_then(|record| record.run_id)
        {
            run_tree = Some(AgentHealthRunTree {
                tree: RunTreeAdapter::new(vault).read_run(&run_id)?,
                marked: crate::entity_id::bytes_to_hex_lower(attempt.as_bytes()),
                run_id,
            });
        }
    }
    let skills = loaded::run_skills(vault, &card)?;
    let basis = moves::basis(&card);
    Ok(AgentHealthCardView {
        card: card_ref(key),
        body: card,
        run_tree,
        skills,
        prompt_inject,
        basis,
    })
}

impl Vault {
    /// One agent-health card by its `health:` handle.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn agent_health_card(&self, card: &str) -> Result<Option<AgentHealthCard>> {
        let Some(key) = parse_card_ref(card) else {
            return Ok(None);
        };
        let rtxn = self.store.env.read_txn()?;
        CARDS.get(&self.store, &rtxn, &key)
    }

    /// One card with its run-tree diagram, for the owner.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn agent_health_card_view(&self, card: &str) -> Result<Option<AgentHealthCardView>> {
        let Some(key) = parse_card_ref(card) else {
            return Ok(None);
        };
        let stored = {
            let rtxn = self.store.env.read_txn()?;
            CARDS.get(&self.store, &rtxn, &key)?
        };
        stored
            .map(|stored| card_view(self, &key, stored))
            .transpose()
    }

    /// The cards a digest period carries (agent-mind §3.5: a card that does
    /// not go up to the owner's inbox goes into the owner's digest and the
    /// weave report): each card opened, updated or settled in `[from, to)`,
    /// in impact order (concern first), newest first within a tone.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn agent_health_cards_between(&self, from: u64, to: u64) -> Result<Vec<AgentHealthCard>> {
        let rtxn = self.store.env.read_txn()?;
        let mut cards: Vec<AgentHealthCard> = CARDS
            .scan(&self.store, &rtxn)?
            .into_iter()
            .map(|(_, card)| card)
            .filter(|card| card_touched_in(card, from, to).is_some())
            .collect();
        cards.sort_by(|left, right| {
            right
                .tone
                .impact()
                .cmp(&left.tone.impact())
                .then(right.updated_at.cmp(&left.updated_at))
        });
        Ok(cards)
    }

    /// The owner sets a card's outcome: confirmed, dismissed or unresolved,
    /// on an open or a settled card. Its receipt covers this owner's notice
    /// (`delivery`, FIX 8709) until the card's evidence grows. It never
    /// moves the agent's `learning.reliability`: the owner's verdict is an
    /// anchored outcome of the card's evaluator (`outcomes`).
    ///
    /// # Errors
    ///
    /// [`Error::EntityNotFound`] for an unknown card; owner revalidation
    /// errors; storage errors.
    pub fn set_agent_health_outcome(
        &self,
        owner: &AuthenticatedOwner,
        card: &str,
        outcome: AgentHealthOutcome,
    ) -> Result<AgentHealthCard> {
        let key = parse_card_ref(card).ok_or(Error::EntityNotFound)?;
        self.with_write_txn_grouped(|txn| {
            let by = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let mut card = CARDS
                .get(&self.store, txn, &key)?
                .ok_or(Error::EntityNotFound)?;
            let at = self.store.clock.now_recorded_at();
            outcomes::settle_with_review_receipt_in_txn(
                self, txn, &mut card, by, true, outcome, at,
            );
            CARDS.put(&self.store, txn, &key, &card)?;
            // A settled card can arm the digest on its own (FIX 1979).
            crate::batch::queue_proactivity_change(self, txn);
            Ok(card)
        })
    }
}

impl Memory<'_> {
    /// `self.inbox.concern`: one agent-health card with its run-tree diagram,
    /// for one of its recipients or a vault owner.
    pub fn concern_card(&self, input: &ConcernCardRequest) -> MemoryResult<AgentHealthCardView> {
        crate::memory::verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let key = parse_card_ref(&input.card).ok_or_else(|| {
            MemoryError::bad_request("card is a health: handle from a concern row")
        })?;
        let card = {
            let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
            let card = CARDS
                .get(&self.vault().store, &txn, &key)?
                .ok_or_else(|| MemoryError::not_found("no such concern card"))?;
            if !may_read(self.vault(), &txn, &card, self.actor())? {
                return Err(forbidden());
            }
            card
        };
        Ok(card_view(self.vault(), &key, card)?)
    }

    /// `self.inbox.concern.outcome`: a card's recipient (its leader or
    /// spawner) or a vault owner marks it confirmed, dismissed or unresolved,
    /// as the owner's route does. It never moves the agent's
    /// `learning.reliability`. A live owner's verdict is an anchored outcome
    /// of the card's evaluator; a leader's or spawner's carries no label
    /// (`outcomes`).
    pub fn concern_outcome(
        &self,
        input: &ConcernOutcomeRequest,
    ) -> MemoryResult<ConcernCardSummary> {
        let key = parse_card_ref(&input.card).ok_or_else(|| {
            MemoryError::bad_request("card is a health: handle from a concern row")
        })?;
        let at = self.vault().store.clock.now_recorded_at();
        self.with_verified_actor_write_txn(|txn| {
            let mut card = CARDS
                .get(&self.vault().store, txn, &key)?
                .ok_or_else(|| MemoryError::not_found("no such concern card"))?;
            if !may_read(self.vault(), txn, &card, self.actor())? {
                return Err(forbidden());
            }
            let by_owner =
                crate::policy_model::is_live_vault_owner_in_txn(self.vault(), txn, &self.actor())?;
            outcomes::settle_with_review_receipt_in_txn(
                self.vault(),
                txn,
                &mut card,
                self.actor(),
                by_owner,
                input.outcome.into(),
                at,
            );
            CARDS.put(&self.vault().store, txn, &key, &card)?;
            // A settled card can arm the digest on its own (FIX 1979).
            crate::batch::queue_proactivity_change(self.vault(), txn);
            Ok(ConcernCardSummary::of(&card))
        })
    }
}
