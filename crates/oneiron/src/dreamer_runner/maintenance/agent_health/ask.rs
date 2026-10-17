//! Ask the Coach (agent-mind §3.5): a card's reader takes its `ask_coach`
//! move, and a `coach.agent_health_ask` attempt on the `coach.heal` queue
//! answers it. The host Coach reads the card, the agent's TASK and, as the
//! Coach, the agent's sealed pads (never its diary), and its model drafts one
//! proposal: a skill edit, or a prompt to inject before a fork-resume. The
//! answer lands on the card for its reader. Nothing is edited or resumed
//! here, and no judge grades the draft in v1.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::{AgentHealthCard, AgentHealthMove, CARDS, card_ref, may_read, parse_card_ref};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::{
    COACH_HEAL_ATTEMPT_KIND, DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerRunnerStore,
    EnqueueDreamerAttemptOutcome,
};
use crate::memory::{DiaryEntry, DiaryReadOutcome, Memory, MemoryError, MemoryResult};
use crate::{EntityId, Error, Result, Vault};

/// The ask's facet on the `coach.heal` queue: the host Coach leases it.
pub const COACH_AGENT_HEALTH_ASK_FACET: &str = "coach.agent_health_ask";

/// One ask on a card and, once the Coach has answered, its answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentHealthCoachAsk {
    /// The recipient or owner who asked.
    pub asked_by: EntityId,
    pub asked_at: u64,
    /// The card's newest DIAGNOSTIC when asked: one ask per evidence state.
    pub diagnostic: Option<EntityId>,
    /// The `coach.agent_health_ask` attempt that answers, as 32 hex.
    pub attempt: String,
    pub answer: Option<AgentHealthCoachAnswer>,
}

/// What the Coach read and what it proposes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentHealthCoachAnswer {
    pub at: u64,
    pub pads: AgentHealthPadRead,
    /// `None` when no model seat served the Coach or its answer did not parse.
    pub draft: Option<AgentHealthCoachDraft>,
}

/// The Coach's sealed-pad read for one ask. A held or refused read leaves the
/// Coach the card and the TASK alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AgentHealthPadRead {
    /// The pads were read; `read` is the agent's read-log row.
    Read { read: Option<EntityId>, pads: usize },
    /// The agent reviews reads first; `request` waits for its answer.
    PendingReview { request: EntityId },
    /// The agent said no to the Coach's reason.
    Declined { request: EntityId },
    /// The Coach does not read this agent's pads (a companion).
    NotCovered,
    /// The read door refused, with its code.
    Refused { code: String },
}

/// The fix the Coach proposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentHealthCoachRoute {
    /// Edit the skill the agent ran.
    SkillEdit,
    /// Inject a prompt and resume from before the trouble.
    PromptInject,
    /// Neither fits: a person should look.
    Neither,
}

/// One proposal in the Coach's words. The reader decides; nothing applies it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentHealthCoachDraft {
    pub route: AgentHealthCoachRoute,
    /// What the Coach thinks is going on.
    pub diagnosis: String,
    /// The exact skill edit or prompt it proposes.
    pub proposal: String,
}

/// What the host's model reads to answer one ask.
#[derive(Debug, Clone)]
pub struct CoachHealthBrief {
    pub card: AgentHealthCard,
    /// The TASK's label, spec and brief, as text.
    pub task: Option<String>,
    /// The sealed pads the Coach read; empty when the read was held.
    pub pads: Vec<DiaryEntry>,
}

/// The host's model, lent to the Coach for one ask.
pub trait CoachHealthHost {
    /// One draft, or `None` when no seat serves the Coach or its answer does
    /// not parse.
    ///
    /// # Errors
    ///
    /// A failed model call.
    fn draft(&self, brief: &CoachHealthBrief) -> Result<Option<AgentHealthCoachDraft>>;
}

/// A move a card's reader takes through `self.inbox.concern.move`. The other
/// moves have their own verbs: a note is `self.message`, a steer `self.steer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConcernMove {
    AskCoach,
}

/// `self.inbox.concern.move`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConcernMoveRequest {
    /// The card's `health:` handle: the concern row's `payload_ref`.
    pub card: String,
    pub r#move: ConcernMove,
}

/// The card's ask after the move: a new one, or the one already standing
/// for the same evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConcernMoveOutcome {
    /// The card's `health:` handle.
    pub card: String,
    pub ask: AgentHealthCoachAsk,
}

fn hex(id: crate::attempt_queue::AttemptId) -> String {
    crate::entity_id::bytes_to_hex_lower(id.as_bytes())
}

/// Queues the Coach's answer, unless an ask on the same evidence stands: one
/// still waiting, or one the Coach drafted on the card's newest DIAGNOSTIC.
/// An answer with no draft (no seat served the Coach) may be asked again.
fn ask_coach_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &([u8; 16], [u8; 1], [u8; 16]),
    mut card: AgentHealthCard,
    by: EntityId,
    at: u64,
) -> Result<ConcernMoveOutcome> {
    let handle = card_ref(key);
    let newest = card.diagnostics.last().copied();
    if let Some(ask) = card.coach.as_ref().filter(|ask| match &ask.answer {
        None => true,
        Some(answer) => answer.draft.is_some() && ask.diagnostic == newest,
    }) {
        return Ok(ConcernMoveOutcome {
            card: handle,
            ask: ask.clone(),
        });
    }
    let mut dedupe = blake3::Hasher::new();
    dedupe.update(handle.as_bytes());
    dedupe.update(&at.to_le_bytes());
    let outcome = DreamerRunnerStore::new(vault).enqueue_kind_in_txn(
        txn,
        COACH_HEAL_ATTEMPT_KIND,
        DreamerAttemptPayload {
            attempt_type: COACH_AGENT_HEALTH_ASK_FACET.into(),
            input: Value::from(handle.as_str()),
            parent_attempt: None,
        },
        Some(format!(
            "{COACH_AGENT_HEALTH_ASK_FACET}:{}",
            dedupe.finalize().to_hex()
        )),
        None,
        at,
    )?;
    let (EnqueueDreamerAttemptOutcome::Enqueued(status)
    | EnqueueDreamerAttemptOutcome::Existing(status)) = outcome;
    let ask = AgentHealthCoachAsk {
        asked_by: by,
        asked_at: at,
        diagnostic: newest,
        attempt: hex(status.attempt.id),
        answer: None,
    };
    card.coach = Some(ask.clone());
    card.updated_at = at;
    CARDS.put(&vault.store, txn, key, &card)?;
    Ok(ConcernMoveOutcome { card: handle, ask })
}

impl Vault {
    /// The owner asks the Coach about one card. A card whose moves hold no
    /// `ask_coach` refuses.
    ///
    /// # Errors
    ///
    /// [`Error::EntityNotFound`] for an unknown card; [`Error::InvalidConfig`]
    /// for a card with no `ask_coach` move; owner revalidation errors;
    /// storage errors.
    pub fn ask_coach_on_agent_health_card(
        &self,
        owner: &AuthenticatedOwner,
        card: &str,
    ) -> Result<ConcernMoveOutcome> {
        let key = parse_card_ref(card).ok_or(Error::EntityNotFound)?;
        let at = self.store.clock.now_recorded_at();
        self.with_write_txn_grouped(|txn| {
            let by = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let card = CARDS
                .get(&self.store, txn, &key)?
                .ok_or(Error::EntityNotFound)?;
            if !card.moves.contains(&AgentHealthMove::AskCoach) {
                return Err(Error::InvalidConfig(
                    "this concern card proposes no ask_coach move".into(),
                ));
            }
            ask_coach_in_txn(self, txn, &key, card, by, at)
        })
    }

    /// The Coach's answer to one ask, under its leased
    /// `coach.agent_health_ask` attempt: the card, the TASK and the agent's
    /// sealed pads, read as the Coach, go to the host's model, and its draft
    /// lands on the card. An ask a newer one replaced, or one already
    /// answered, is left as it is.
    ///
    /// # Errors
    ///
    /// A malformed attempt; a failed model call, after its draftless answer
    /// lands; storage errors.
    pub fn run_coach_agent_health_ask(
        &self,
        attempt: &DreamerAdmittedAttempt,
        host: &dyn CoachHealthHost,
        now: u64,
    ) -> Result<()> {
        self.require_coach_attempt(attempt, COACH_AGENT_HEALTH_ASK_FACET)?;
        let handle = attempt
            .status
            .payload
            .input
            .as_str()
            .ok_or_else(super::super::invalid)?
            .to_owned();
        let key = parse_card_ref(&handle).ok_or_else(super::super::invalid)?;
        let mine = hex(attempt.status.attempt.id);
        let waiting = |card: &AgentHealthCard| {
            card.coach
                .as_ref()
                .is_some_and(|ask| ask.attempt == mine && ask.answer.is_none())
        };
        let (card, task) = {
            let rtxn = self.store.env.read_txn()?;
            let Some(card) = CARDS.get(&self.store, &rtxn, &key)? else {
                return Ok(());
            };
            if !waiting(&card) {
                return Ok(());
            }
            let task = match card.task {
                Some(task) => crate::task_verb::task_text_in(self, &rtxn, task)?,
                None => None,
            };
            (card, task)
        };
        let coach = self.coach_authority()?;
        let reason = format!(
            "The Coach answers an ask on agent-health card {handle} ({}).",
            card.signal.as_str()
        );
        let (pads, entries) = match self
            .memory(coach.entity_ref(), coach.actor_class())
            .read_agent_sealed_pads(None, card.subject, &reason)
        {
            Ok(DiaryReadOutcome::Granted { read, entries }) => (
                AgentHealthPadRead::Read {
                    read,
                    pads: entries.len(),
                },
                entries,
            ),
            Ok(DiaryReadOutcome::PendingReview { request }) => {
                (AgentHealthPadRead::PendingReview { request }, Vec::new())
            }
            Ok(DiaryReadOutcome::Declined { request }) => {
                (AgentHealthPadRead::Declined { request }, Vec::new())
            }
            Ok(DiaryReadOutcome::NotCovered) => (AgentHealthPadRead::NotCovered, Vec::new()),
            Err(error) => (AgentHealthPadRead::Refused { code: error.code }, Vec::new()),
        };
        // A failed call still lands a draftless answer, so the ask may be
        // asked again, and the attempt fails with the error.
        let drafted = host.draft(&CoachHealthBrief {
            card,
            task,
            pads: entries,
        });
        let draft = drafted.as_ref().ok().cloned().flatten();
        self.with_write_txn_grouped(|txn| {
            let Some(mut card) = CARDS.get(&self.store, txn, &key)? else {
                return Ok(());
            };
            if !waiting(&card) {
                return Ok(());
            }
            if let Some(ask) = card.coach.as_mut() {
                ask.answer = Some(AgentHealthCoachAnswer {
                    at: now,
                    pads,
                    draft,
                });
            }
            card.updated_at = now;
            CARDS.put(&self.store, txn, &key, &card)
        })?;
        drafted.map(|_| ())
    }
}

impl Memory<'_> {
    /// `self.inbox.concern.move`: a card's recipient (its leader or spawner)
    /// or a vault owner takes one of its moves. `ask_coach` queues the
    /// Coach's answer, which lands on the card; asking again on the same
    /// evidence returns the standing ask.
    pub fn concern_move(&self, input: &ConcernMoveRequest) -> MemoryResult<ConcernMoveOutcome> {
        let key = parse_card_ref(&input.card).ok_or_else(|| {
            MemoryError::bad_request("card is a health: handle from a concern row")
        })?;
        let at = self.vault().store.clock.now_recorded_at();
        self.with_verified_actor_write_txn(|txn| {
            let card = CARDS
                .get(&self.vault().store, txn, &key)?
                .ok_or_else(|| MemoryError::not_found("no such concern card"))?;
            if !may_read(self.vault(), txn, &card, self.actor())? {
                return Err(super::forbidden());
            }
            match input.r#move {
                ConcernMove::AskCoach => {
                    if !card.moves.contains(&AgentHealthMove::AskCoach) {
                        return Err(MemoryError::bad_request(
                            "this concern card proposes no ask_coach move",
                        ));
                    }
                    Ok(ask_coach_in_txn(
                        self.vault(),
                        txn,
                        &key,
                        card,
                        self.actor(),
                        at,
                    )?)
                }
            }
        })
    }
}
