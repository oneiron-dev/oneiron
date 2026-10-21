//! Ask the Coach (agent-mind §3.5): a card's reader takes its `ask_coach`
//! move, and a `coach.agent_health_ask` attempt on the `coach.heal` queue
//! answers it. The host Coach reads the card, the skills its run loaded
//! (`loaded.rs`), the brief the review observed as the ask froze it
//! (`brief.rs`), the agent's TASK as it reads now and, as the Coach, the
//! agent's sealed pads (never its diary), and its model drafts one proposal:
//! a whole replacement of one loaded skill's instructions, bound to that
//! revision, or a prompt to inject before a fork-resume. The answer lands on
//! the card for its reader.
//! Nothing is edited or resumed here, and no judge grades the draft in v1:
//! the owner applies a skill edit through `apply.rs`, where the held-out gate
//! rules on it.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::apply::{AgentHealthApplicationState, AgentHealthCoachApplication};
use super::brief::{HealthBriefPin, HealthObservedBrief, observed_brief_in};
use super::loaded::{
    AgentHealthLoadedSkill, AgentHealthSkillTarget, bind_target, run_skills_sourced,
};
use super::{
    AgentHealthCard, AgentHealthMove, CARDS, ConcernMoveOutcome, card_ref, parse_card_ref,
};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::{
    COACH_HEAL_ATTEMPT_KIND, DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerRunnerStore,
    EnqueueDreamerAttemptOutcome,
};
use crate::memory::{DiaryEntry, DiaryReadOutcome};
use crate::skill_optimize::union_source_rows;
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
    /// The brief the card's newest finding observed when asked, frozen for
    /// this ask and its answer: a later review never rewrites what it saw.
    pub observed_brief: Option<HealthBriefPin>,
    pub answer: Option<AgentHealthCoachAnswer>,
    /// The owner's approval of the answer's skill edit, once given, and where
    /// the gate took it.
    #[serde(default)]
    pub application: Option<AgentHealthCoachApplication>,
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
    /// The pads were read; `read` is the agent's read-log row. `pads` counts
    /// the pads the read returned and `pad_ids` names them, in its order
    /// (FIX 5457).
    Read {
        read: Option<EntityId>,
        pads: usize,
        pad_ids: Vec<EntityId>,
    },
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

/// One proposal in the Coach's words. The reader decides; only the owner's
/// approval of exact bytes applies a skill edit (`apply.rs`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentHealthCoachDraft {
    pub route: AgentHealthCoachRoute,
    /// What the Coach thinks is going on.
    pub diagnosis: String,
    /// For a skill edit, the whole replacement instructions of `target`; for
    /// a prompt injection, the exact prompt; else what a person should see.
    pub proposal: String,
    /// The loaded revision a skill edit replaces, as the apply door takes it.
    /// `None` for another route, or when the Coach named no revision the
    /// card's run loaded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<AgentHealthSkillTarget>,
}

/// What the host's model reads to answer one ask.
#[derive(Debug, Clone)]
pub struct CoachHealthBrief {
    pub card: AgentHealthCard,
    /// The skills the card's run loaded, at their pinned revisions, whole.
    pub skills: Vec<AgentHealthLoadedSkill>,
    /// The brief the ask froze, with its text only while it is still the
    /// TASK's current brief. `None` when no typed brief was observed.
    pub observed_brief: Option<HealthObservedBrief>,
    /// The TASK's label, spec and brief as they read now, as text: today's
    /// TASK, never the observed brief.
    pub current_task: Option<String>,
    /// The sealed pads the Coach read; empty when the read was held.
    pub pads: Vec<DiaryEntry>,
    /// The rows the brief was read from (FIX 6997); `None`, unknown, while
    /// the card's numbers name none.
    pub source_rows: Option<Vec<EntityId>>,
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

fn hex(id: crate::attempt_queue::AttemptId) -> String {
    crate::entity_id::bytes_to_hex_lower(id.as_bytes())
}

/// Queues the Coach's answer, unless an ask on the same evidence stands: one
/// still waiting, or one the Coach drafted on the card's newest DIAGNOSTIC.
/// An answer with no draft (no seat served the Coach) may be asked again. An
/// ask whose approved edit waits on the gate stands whatever the evidence, so
/// the approval keeps its candidate.
pub(super) fn ask_coach_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &([u8; 16], [u8; 1], [u8; 16]),
    mut card: AgentHealthCard,
    by: EntityId,
    at: u64,
) -> Result<ConcernMoveOutcome> {
    let handle = card_ref(key);
    let newest = card.diagnostics.last().copied();
    if let Some(ask) = card.coach.as_ref().filter(|ask| {
        let applying = ask
            .application
            .as_ref()
            .is_some_and(|application| application.state == AgentHealthApplicationState::Pending);
        applying
            || match &ask.answer {
                None => true,
                Some(answer) => answer.draft.is_some() && ask.diagnostic == newest,
            }
    }) {
        return Ok(ConcernMoveOutcome::AskCoach {
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
        observed_brief: card.observed_brief.clone(),
        answer: None,
        application: None,
    };
    card.coach = Some(ask.clone());
    card.updated_at = at;
    CARDS.put(&vault.store, txn, key, &card)?;
    // A touched card can arm the digest on its own (FIX 1979).
    crate::batch::queue_proactivity_change(vault, txn);
    Ok(ConcernMoveOutcome::AskCoach { card: handle, ask })
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
    /// `coach.agent_health_ask` attempt: the card, the skills its run loaded,
    /// the TASK and the agent's sealed pads, read as the Coach, go to the
    /// host's model, and its draft lands on the card, a skill edit bound to
    /// the loaded revision it replaces. An ask a newer one replaced, or one
    /// already answered, is left as it is.
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
        let (card, task, observed_brief) = {
            let rtxn = self.store.env.read_txn()?;
            let Some(card) = CARDS.get(&self.store, &rtxn, &key)? else {
                return Ok(());
            };
            if !waiting(&card) {
                return Ok(());
            }
            let task = match card.task {
                Some(task) => crate::task_verb::task_text_with_source_in(self, &rtxn, task)?,
                None => None,
            };
            // The ask's frozen pin, never the card's newer one.
            let frozen = card
                .coach
                .as_ref()
                .and_then(|ask| ask.observed_brief.as_ref());
            let observed_brief = observed_brief_in(self, &rtxn, frozen)?;
            (card, task, observed_brief)
        };
        let (task, task_rows) = match task {
            Some((text, row)) => (Some(text), vec![row]),
            None => (None, Vec::new()),
        };
        let (skills, skill_rows) = run_skills_sourced(self, &card)?;
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
                    pad_ids: entries.iter().map(|pad| pad.id).collect(),
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
        // The card's numbers are review state merged across passes, naming no
        // rows they were counted from: the brief stays unknown until they do
        // (FIX 6997). Its skills, TASK and the pads read are known.
        let card_rows: Option<Vec<EntityId>> = None;
        let pad_rows = entries.iter().map(|pad| pad.id).collect();
        let source_rows =
            union_source_rows([card_rows, Some(skill_rows), Some(task_rows), Some(pad_rows)]);
        // A failed call still lands a draftless answer, so the ask may be
        // asked again, and the attempt fails with the error.
        let brief = CoachHealthBrief {
            card,
            skills,
            observed_brief,
            current_task: task,
            pads: entries,
            source_rows,
        };
        let drafted = host.draft(&brief);
        let draft = drafted
            .as_ref()
            .ok()
            .cloned()
            .flatten()
            .map(|draft| bind_target(draft, &brief.skills));
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
            CARDS.put(&self.store, txn, &key, &card)?;
            // A touched card can arm the digest on its own (FIX 1979).
            crate::batch::queue_proactivity_change(self, txn);
            Ok(())
        })?;
        drafted.map(|_| ())
    }
}
