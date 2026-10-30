//! The owner applies the Coach's `skill_edit` draft on an agent-health card
//! (OF-568, FIX 1849). The Coach only drafts (`ask.rs`); this door is the
//! owner's approval of one exact edit: the card's answered ask, a skill the
//! card's run loaded at the version the owner read, and the whole
//! replacement instructions. The optimizer's exact-target writer lands the
//! edit as a gated candidate under the Coach's ask attempt, the held-out gate
//! scores it, and only an accepting verdict admits the candidate and
//! supersedes the skill, in one transaction. A confirmed outcome or an ask is
//! never an approval.
//!
//! The approval is stored on the ask, so applying it again returns the same
//! candidate. A gate that has not ruled, or deferred, leaves the application
//! pending, and applying again carries it on; so does the Dreamer's scoring
//! pass that puts the candidate to the gate later (FIX 3725). A rejection or
//! a refusal leaves the skill as it was.

use serde::{Deserialize, Serialize};

use super::ask::{AgentHealthCoachAsk, AgentHealthCoachRoute, COACH_AGENT_HEALTH_ASK_FACET};
use super::loaded::RunPack;
use super::{AgentHealthCard, CARDS, card_ref, parse_card_ref};
use crate::attempt_queue::AttemptId;
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::DreamerRunnerStore;
use crate::error::ArtifactError;
use crate::skill::{SkillLifecycle, SkillRecord};
use crate::skill_optimize::{
    PROVENANCE_OPTIMIZE_ATTEMPT_KEY, SkillRepairStamp, propose_skill_repair_in_txn, proven_cycle,
    score_gate_skill_edit, skill_edit_verdict_in_txn, skill_repair_brief, validate_skill_draft,
};
use crate::temporal::TimeRange;
use crate::{EntityId, Error, Result, Vault};

type CardKey = ([u8; 16], [u8; 1], [u8; 16]);

/// `/v1/owner/inbox/concern/apply`'s input: the one edit the owner approves.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConcernApplyRequest {
    /// The card's `health:` handle, the row's `payload_ref`.
    pub card: String,
    /// The Coach ask the owner read: its `attempt`, as 32 hex.
    pub ask: String,
    /// The skill revision the edit replaces, as 32 hex.
    pub skill: String,
    /// That revision's version, as the owner read it.
    pub version: String,
    /// The whole replacement instructions the owner approved.
    pub instructions: String,
}

/// Where an approved edit stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentHealthApplicationState {
    /// The candidate waits on the gate: not yet ruled, deferred, or short of
    /// evidence. Applying again carries it on.
    Pending,
    /// The gate accepted it: the candidate is the skill's active revision.
    Admitted,
    /// The gate rejected or refused it; the skill is as it was.
    Rejected,
}

/// The owner's approval of one ask's skill edit, and where the gate took it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentHealthCoachApplication {
    /// The owner who approved it.
    pub by: EntityId,
    pub at: u64,
    /// The skill revision it replaces, at the version the owner read.
    pub skill: EntityId,
    pub version: String,
    /// The approved instructions' blake3, as hex: applying the same bytes
    /// again is the same application.
    pub instructions: String,
    /// The gated candidate the edit landed as.
    pub candidate: EntityId,
    pub state: AgentHealthApplicationState,
    /// The gate's standing ruling, once it ruled: its row and disposition.
    pub verdict: Option<EntityId>,
    pub disposition: Option<String>,
    pub updated_at: u64,
}

/// The card's application after the owner's call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConcernApplyOutcome {
    /// The card's `health:` handle.
    pub card: String,
    pub application: AgentHealthCoachApplication,
}

fn refused(why: &str) -> Error {
    Error::InvalidConfig(why.into())
}

fn digest(instructions: &str) -> String {
    blake3::hash(instructions.as_bytes()).to_hex().to_string()
}

/// The ask the owner read, still standing, with a `skill_edit` draft.
fn approved_ask<'a>(card: &'a AgentHealthCard, ask: &str) -> Result<&'a AgentHealthCoachAsk> {
    let Some(standing) = card
        .coach
        .as_ref()
        .filter(|standing| standing.attempt == ask)
    else {
        return Err(refused(
            "the Coach's ask on this card moved since you read it",
        ));
    };
    let draft = standing
        .answer
        .as_ref()
        .and_then(|answer| answer.draft.as_ref());
    if draft.is_none_or(|draft| draft.route != AgentHealthCoachRoute::SkillEdit) {
        return Err(refused(
            "the Coach's answer on this card proposes no skill edit",
        ));
    }
    Ok(standing)
}

/// The application standing on the ask for this approval, if any. One that
/// approved other bytes refuses unless the gate rejected it: an ask carries
/// one edit in flight, and an admitted edit is done.
fn standing_for(
    ask: &AgentHealthCoachAsk,
    skill: &EntityId,
    version: &str,
    instructions: &str,
) -> Result<Option<AgentHealthCoachApplication>> {
    match &ask.application {
        Some(standing)
            if standing.skill == *skill
                && standing.version == version
                && standing.instructions == instructions =>
        {
            Ok(Some(standing.clone()))
        }
        Some(standing) if standing.state != AgentHealthApplicationState::Rejected => Err(refused(
            "another skill edit is already pending or applied on this ask",
        )),
        _ => Ok(None),
    }
}

/// Whether the run the card's evidence came from loaded `record`: its
/// attempt's pack manifest names the skill, and a fork is that run's
/// resident's own. A card with no attempt, or a run with no pack, loaded none.
/// The card's `skills` list reads the same pack (`loaded.rs`).
fn run_loaded(vault: &Vault, card: &AgentHealthCard, record: &SkillRecord) -> Result<bool> {
    match RunPack::of(vault, card)? {
        Some(pack) => pack.loaded(record),
        None => Ok(false),
    }
}

impl Vault {
    /// The owner applies the `skill_edit` the Coach drafted on one card, as
    /// they approve it in `approval`. A new approval lands as a gated
    /// candidate; the gate then rules, and an accepting verdict admits the
    /// candidate and supersedes the skill. Applying the same approval again
    /// returns its application, carrying a pending one on.
    ///
    /// # Errors
    ///
    /// [`Error::EntityNotFound`] for an unknown card; [`Error::InvalidConfig`]
    /// when the approval no longer matches the card (another ask, no
    /// `skill_edit` draft, a skill the card's run did not load, a skill that
    /// moved since the owner read it, another edit standing on the ask, a
    /// candidate whose instructions are not the approved ones); the drafting
    /// door's refusals; owner revalidation errors; a gate error that ruled
    /// nothing, after the application stays pending; storage errors.
    pub fn apply_coach_skill_edit_on_agent_health_card(
        &self,
        owner: &AuthenticatedOwner,
        approval: &ConcernApplyRequest,
    ) -> Result<ConcernApplyOutcome> {
        let key = parse_card_ref(&approval.card).ok_or(Error::EntityNotFound)?;
        let skill = EntityId::from_hex(&approval.skill)
            .map_err(|_| refused("skill is a 32-hex entity id"))?;
        let instructions = digest(&approval.instructions);
        let card = self
            .agent_health_card(&approval.card)?
            .ok_or(Error::EntityNotFound)?;
        let ask = approved_ask(&card, &approval.ask)?;
        let application = match standing_for(ask, &skill, &approval.version, &instructions)? {
            Some(standing) if standing.state != AgentHealthApplicationState::Pending => {
                return Ok(ConcernApplyOutcome {
                    card: card_ref(&key),
                    application: standing,
                });
            }
            Some(standing) => standing,
            None => {
                self.land_approved_skill_edit(owner, &key, &card, approval, skill, instructions)?
            }
        };
        self.settle_approved_skill_edit(owner, &key, &approval.ask, &application.candidate)
    }

    /// Lands a new approval as a gated candidate of its skill, stamped with
    /// the Coach's ask attempt, and stores it on the ask as pending.
    fn land_approved_skill_edit(
        &self,
        owner: &AuthenticatedOwner,
        key: &CardKey,
        card: &AgentHealthCard,
        approval: &ConcernApplyRequest,
        skill: EntityId,
        instructions: String,
    ) -> Result<AgentHealthCoachApplication> {
        let record = self
            .get_skill_record(&skill)?
            .ok_or_else(|| refused("no such skill"))?;
        if record.lifecycle_status != SkillLifecycle::Active || record.version != approval.version {
            return Err(refused("the skill moved since you read it"));
        }
        if !run_loaded(self, card, &record)? {
            return Err(refused("the card's run did not load this skill"));
        }
        let now = self.store.clock.now_recorded_at();
        let brief = skill_repair_brief(self, &skill, now)?;
        if brief.version != approval.version {
            return Err(refused("the skill moved since you read it"));
        }
        let rationale = format!(
            "The owner approved the Coach's skill edit on {}.",
            card_ref(key)
        );
        validate_skill_draft(&brief, &approval.instructions, &rationale)?;
        let ask = approved_ask(card, &approval.ask)?;
        let attempt = AttemptId::from_bytes(
            EntityId::from_hex(&ask.attempt)
                .map_err(|_| refused("the Coach's ask names no attempt"))?
                .as_bytes(),
        )?;
        let actor = self.dreamer_actor_for_attempt(attempt)?;
        let cycle = proven_cycle(self, attempt)?;
        let resident = crate::skill::resident_of(&record)?;
        let candidate = self.store.clock.entity_id()?;
        self.with_write_txn_grouped(|txn| {
            let by = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let mut card = CARDS
                .get(&self.store, txn, key)?
                .ok_or(Error::EntityNotFound)?;
            // An apply of the same bytes that landed first is this one.
            let ask = approved_ask(&card, &approval.ask)?;
            if let Some(standing) = standing_for(ask, &skill, &approval.version, &instructions)? {
                return Ok(standing);
            }
            let stamp = SkillRepairStamp {
                actor,
                facet: COACH_AGENT_HEALTH_ASK_FACET,
                attempt,
                cycle: &cycle,
                owner: None,
                resident,
            };
            propose_skill_repair_in_txn(
                self,
                txn,
                &brief,
                &approval.instructions,
                &rationale,
                &stamp,
                &candidate,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )?;
            let application = AgentHealthCoachApplication {
                by,
                at: now,
                skill,
                version: approval.version.clone(),
                instructions,
                candidate,
                state: AgentHealthApplicationState::Pending,
                verdict: None,
                disposition: None,
                updated_at: now,
            };
            if let Some(ask) = card.coach.as_mut() {
                ask.application = Some(application.clone());
            }
            card.updated_at = now;
            CARDS.put(&self.store, txn, key, &card)?;
            // A touched card can arm the digest on its own (FIX 1979).
            crate::batch::queue_proactivity_change(self, txn);
            Ok(application)
        })
    }

    /// Puts a pending application's candidate to the held-out gate, outside
    /// any write transaction, then settles the application on the gate's
    /// standing ruling: an acceptance admits the candidate and supersedes
    /// the skill, a rejection or refusal closes it, anything else leaves it
    /// pending.
    fn settle_approved_skill_edit(
        &self,
        owner: &AuthenticatedOwner,
        key: &CardKey,
        ask: &str,
        candidate: &EntityId,
    ) -> Result<ConcernApplyOutcome> {
        let gated = score_gate_skill_edit(self, candidate);
        let now = self.store.clock.now_recorded_at();
        let settled = self.with_write_txn_grouped(|txn| {
            owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let card = CARDS
                .get(&self.store, txn, key)?
                .ok_or(Error::EntityNotFound)?;
            let Some(standing) = approved_ask(&card, ask)?
                .application
                .clone()
                .filter(|standing| standing.candidate == *candidate)
            else {
                return Err(refused(
                    "the approval on this card moved since you applied it",
                ));
            };
            self.settle_standing_in_txn(txn, key, card, standing, now)
        })?;
        // A gate that failed without ruling (no judge registered, a failed
        // judgment) is the owner's answer; a raced snapshot or missing
        // evidence is only "pending".
        if settled.state == AgentHealthApplicationState::Pending
            && let Err(error) = gated
            && !matches!(error, Error::Artifact(ArtifactError::SkillEditGateRetry(_)))
        {
            return Err(error);
        }
        Ok(ConcernApplyOutcome {
            card: card_ref(key),
            application: settled,
        })
    }

    /// Settles the owner's approved application whose candidate a Dreamer
    /// scoring pass has just put to the gate (FIX 3725): the optimize pass
    /// and the type-tree pass score an open candidate too, and its ruling
    /// settles the application as the owner's own re-apply would: the
    /// approved bytes are checked, an acceptance admits the candidate and
    /// supersedes the skill, a rejection or refusal closes it, anything else
    /// leaves it pending, and a ruling already settled leaves the card
    /// untouched. The approval was the owner's act when it landed; this
    /// carries it out. `None` when no standing application names
    /// `candidate`: another proposal, or a card or ask that moved on.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when the candidate's instructions are not
    /// the approved ones; storage errors.
    pub(crate) fn settle_approved_skill_edit_by_candidate(
        &self,
        candidate: &EntityId,
    ) -> Result<Option<AgentHealthCoachApplication>> {
        let Some((key, ask)) = self.approval_card_of(candidate)? else {
            return Ok(None);
        };
        let now = self.store.clock.now_recorded_at();
        self.with_write_txn_grouped(|txn| {
            let Some(card) = CARDS.get(&self.store, txn, &key)? else {
                return Ok(None);
            };
            let Some(standing) = card
                .coach
                .as_ref()
                .filter(|standing| standing.attempt == ask)
                .and_then(|standing| standing.application.clone())
                .filter(|standing| standing.candidate == *candidate)
            else {
                return Ok(None);
            };
            // A gate that ruled nothing new since the last settle leaves the
            // card as it is.
            let ruling =
                skill_edit_verdict_in_txn(self, txn, candidate)?.map(|verdict| verdict.id);
            if standing.state == AgentHealthApplicationState::Pending && ruling == standing.verdict {
                return Ok(Some(standing));
            }
            self.settle_standing_in_txn(txn, &key, card, standing, now)
                .map(Some)
        })
    }

    /// The card and Coach ask a candidate landed under, from its provenance:
    /// the ask's facet and attempt, and that attempt's input, the card's
    /// handle. `None` for a candidate no Coach ask landed.
    fn approval_card_of(&self, candidate: &EntityId) -> Result<Option<(CardKey, String)>> {
        let Some(record) = self.get_skill_record(candidate)? else {
            return Ok(None);
        };
        let rmpv::Value::Map(fields) = &record.provenance else {
            return Ok(None);
        };
        let field = |name: &str| {
            fields.iter().find_map(|(key, value)| {
                (key.as_str() == Some(name))
                    .then(|| value.as_str())
                    .flatten()
            })
        };
        if field("facet") != Some(COACH_AGENT_HEALTH_ASK_FACET) {
            return Ok(None);
        }
        let Some(ask) = field(PROVENANCE_OPTIMIZE_ATTEMPT_KEY) else {
            return Ok(None);
        };
        let Ok(id) = EntityId::from_hex(ask) else {
            return Ok(None);
        };
        let attempt = AttemptId::from_bytes(id.as_bytes())?;
        let Some(status) = DreamerRunnerStore::new(self).status(attempt)? else {
            return Ok(None);
        };
        if status.payload.attempt_type != COACH_AGENT_HEALTH_ASK_FACET {
            return Ok(None);
        }
        Ok(status
            .payload
            .input
            .as_str()
            .and_then(parse_card_ref)
            .map(|key| (key, ask.to_owned())))
    }

    /// Settles `settled`, the application standing on `card` at `key`, on
    /// the gate's standing ruling, in `txn`; one that is no longer pending
    /// stands as it is. The bytes the gate admits must be the approved ones.
    fn settle_standing_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        key: &CardKey,
        mut card: AgentHealthCard,
        mut settled: AgentHealthCoachApplication,
        now: u64,
    ) -> Result<AgentHealthCoachApplication> {
        if settled.state != AgentHealthApplicationState::Pending {
            return Ok(settled);
        }
        let candidate = settled.candidate;
        let occurred = TimeRange {
            start: now,
            end: now,
        };
        let verdict = skill_edit_verdict_in_txn(self, txn, &candidate)?;
        if let Some(verdict) = &verdict {
            settled.verdict = Some(verdict.id);
            settled.disposition = Some(verdict.disposition.as_str().to_owned());
        }
        match verdict {
            Some(verdict)
                if verdict.disposition.admits() && verdict.displaced_by_revision.is_none() =>
            {
                // The bytes the gate admits are the bytes the owner
                // approved, or the old permission is refused.
                let staged = self.read_skill_record_in_txn(txn, &candidate)?;
                if digest(&staged.desc) != settled.instructions {
                    return Err(refused(
                        "the candidate's instructions are not the ones you approved",
                    ));
                }
                match self.admit_optimized_skill_in_txn(txn, &candidate, occurred, now)? {
                    Some(refusal) => {
                        settled.state = AgentHealthApplicationState::Rejected;
                        settled.verdict = skill_edit_verdict_in_txn(self, txn, &candidate)?
                            .map(|verdict| verdict.id);
                        settled.disposition = Some(refusal.as_str().to_owned());
                    }
                    None => {
                        self.supersede_skill_record_in_txn(
                            txn,
                            &settled.skill,
                            &candidate,
                            occurred,
                            now,
                        )?;
                        settled.state = AgentHealthApplicationState::Admitted;
                    }
                }
            }
            Some(verdict) if verdict.disposition.closes_proposal() => {
                settled.state = AgentHealthApplicationState::Rejected;
            }
            _ => {}
        }
        settled.updated_at = now;
        if let Some(ask) = card.coach.as_mut() {
            ask.application = Some(settled.clone());
        }
        card.updated_at = now;
        CARDS.put(&self.store, txn, key, &card)?;
        // A touched card can arm the digest on its own (FIX 1979).
        crate::batch::queue_proactivity_change(self, txn);
        Ok(settled)
    }
}

impl Vault {
    /// The owner applies the `prompt_inject` the Coach drafted on one card,
    /// as they approve it in `approval` (FIX 3694): the failed attempt the
    /// card names goes on as a new attempt, from a checkpoint of its run,
    /// with the approved prompt: the Coach's proposal, or the owner's own
    /// edit of it, kept beside the draft it edits. The checkpoint is
    /// resolved first, from its own reads; then one write transaction
    /// revalidates the owner, reads the card and its standing ask again,
    /// checks them, and applies the approval
    /// (`agent_dispatch::apply_prompt_inject_in_txn`): the TASK, the
    /// successor and its spend, its continuation, the application and the
    /// card. Applying the same approval again returns the successor it made.
    ///
    /// # Errors
    ///
    /// [`Error::EntityNotFound`] for an unknown card; [`Error::InvalidConfig`]
    /// when the approval no longer matches the card (another ask, no
    /// `prompt_inject` draft, evidence that grew since the ask, an attempt
    /// that moved), for an empty prompt, and for each continuation
    /// refusal, whose message is exactly its code; owner revalidation
    /// errors; the queue's refusals; storage errors.
    pub fn apply_coach_prompt_inject_on_agent_health_card(
        &self,
        owner: &AuthenticatedOwner,
        approval: &crate::agent_dispatch::ConcernPromptInjectRequest,
    ) -> Result<crate::agent_dispatch::ConcernPromptInjectOutcome> {
        let key = parse_card_ref(&approval.card).ok_or(Error::EntityNotFound)?;
        let card = self
            .agent_health_card(&approval.card)?
            .ok_or(Error::EntityNotFound)?;
        Self::prompt_inject_ask(&card, approval)?;
        if approval.prompt.trim().is_empty() {
            return Err(refused("the prompt is empty"));
        }
        let attempt = card
            .attempt
            .ok_or_else(|| refused("this card names no failed attempt"))?;
        let predecessor = AttemptId::from_bytes(attempt.as_bytes())?;
        // The executor's checkpoint reads open snapshots of their own:
        // before the writer, never inside it. The step is theirs to choose.
        let checkpoint = crate::agent_dispatch::continuation_checkpoint(
            self,
            predecessor,
            approval.checkpoint.as_deref(),
        )?;
        let handle = card_ref(&key);
        let now = self.store.clock.now_recorded_at();
        let applied = self.with_write_txn_grouped(|txn| {
            let by = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let mut card = CARDS
                .get(&self.store, txn, &key)?
                .ok_or(Error::EntityNotFound)?;
            // New evidence moves the card to a newer attempt: the checkpoint
            // above is the old one's.
            if card.attempt != Some(attempt) {
                return Err(refused("the card's failed attempt moved since you read it"));
            }
            let (ask, proposal) = Self::prompt_inject_ask(&card, approval)?;
            let bound = crate::agent_dispatch::PromptInjectApproval {
                card: &handle,
                ask: &ask.attempt,
                proposal,
                diagnostic: ask.diagnostic,
                subject: card.subject,
                task: card.task,
                predecessor,
                checkpoint,
                prompt: &approval.prompt,
                by,
                now,
            };
            let applied = crate::agent_dispatch::apply_prompt_inject_in_txn(self, txn, &bound)?;
            if !applied.replayed {
                card.updated_at = now;
                CARDS.put(&self.store, txn, &key, &card)?;
                // A touched card can arm the digest on its own (FIX 1979).
                crate::batch::queue_proactivity_change(self, txn);
            }
            Ok(applied)
        })?;
        // Committed: the successor is claimable, and its TASK live again.
        if !applied.replayed {
            self.store.notify_attempt_observers();
            if let Some(task) = applied.task {
                self.store.notify_task_updates([task]);
            }
        }
        Ok(crate::agent_dispatch::ConcernPromptInjectOutcome {
            card: handle,
            successor: crate::entity_id::bytes_to_hex_lower(applied.successor.as_bytes()),
            approval: applied.approval.to_hex(),
            checkpoint: checkpoint.id()?.to_hex(),
            replayed: applied.replayed,
        })
    }

    /// The ask the owner read, still standing on `card`, with its
    /// `prompt_inject` draft's proposal, asked over the card's evidence as it
    /// stands. The approved prompt may differ from the proposal: the owner's
    /// own edit is their approval, and the draft stays beside it as evidence.
    fn prompt_inject_ask<'a>(
        card: &'a AgentHealthCard,
        approval: &crate::agent_dispatch::ConcernPromptInjectRequest,
    ) -> Result<(&'a AgentHealthCoachAsk, &'a str)> {
        let Some(standing) = card
            .coach
            .as_ref()
            .filter(|standing| standing.attempt == approval.ask)
        else {
            return Err(refused(
                "the Coach's ask on this card moved since you read it",
            ));
        };
        let Some(draft) = standing
            .answer
            .as_ref()
            .and_then(|answer| answer.draft.as_ref())
            .filter(|draft| draft.route == AgentHealthCoachRoute::PromptInject)
        else {
            return Err(refused(
                "the Coach's answer on this card proposes no prompt injection",
            ));
        };
        if standing.diagnostic != card.diagnostics.last().copied() {
            return Err(refused(
                "the card's evidence moved since the Coach was asked",
            ));
        }
        Ok((standing, &draft.proposal))
    }
}
