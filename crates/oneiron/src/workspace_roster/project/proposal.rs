//! The project card a conversation proposes (OF-501, ARCH-0067). A person's
//! on-record turn stages the house mind's one typed question by reference; a
//! yes lets the house mind draft a host-held card on the source message; one
//! authorised tap mints it. No tap, no project: a card writes no project and
//! confers no authority, and the question never runs under the turn's writer.
use super::{ProjectMintReceipt, ROOM_PROJECT, invalid};
use crate::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext, DispatchAgent,
};
use crate::attempt_queue::{
    AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome, CompleteAttempt, EnqueueAttempt,
    FailAttempt,
};
use crate::consent::AuthenticatedOwner;
use crate::context_projection::ContextSpec;
use crate::edge::EdgeActorClass;
use crate::error::GateError;
use crate::genui::{
    ConsentActionRequest, ProjectGoalDraft, ProjectProposalCard, ProjectProposalPicks,
};
use crate::llm::decision::DecisionReceipt;
use crate::memory::{Memory, MemoryResult};
use crate::ports::JobQueue;
use crate::registry::ENTITY_TYPE_AGENT_DEF;
use crate::side_table::{self, Named, Raw, SideTable};
use crate::workspace_roster::OwnerProjectSigner;
use crate::workspace_roster::rooms;
use crate::{EntityId, Error, Result, Vault};
use serde::{Deserialize, Serialize};

/// The attempt kind of one conversation's pending project question.
pub(crate) const PROJECT_DETECTION_KIND: &str = "project.proposal.detect.v1";

/// Host-held project cards. Key: blake3 hash32 of the card id.
const CARDS: SideTable<[u8; 32], ProjectCardRecord, Named> =
    SideTable::new(&side_table::PROJECT_PROPOSAL_CARD);
/// The source message of each card shown in one conversation. Key: id16 (conversation) +
/// blake3 hash32 of the card id.
const CONVERSATION_CARDS: SideTable<(EntityId, [u8; 32]), EntityId, Raw> =
    SideTable::new(&side_table::PROJECT_PROPOSAL_CONVERSATION);
/// A conversation's latest person turn awaiting the project question. Key: id16
/// (conversation).
const PENDING: SideTable<EntityId, ProjectDetectionSource, Named> =
    SideTable::new(&side_table::PROJECT_PROPOSAL_PENDING);
/// The project question's yes, or its ask of a person, on one source message. Key: id16
/// (source message).
const VERDICTS: SideTable<EntityId, ProjectDetectionVerdict, Named> =
    SideTable::new(&side_table::PROJECT_PROPOSAL_VERDICT);

/// Where a project question's source sits: one person's on-record turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProjectDetectionSource {
    pub(crate) conversation: EntityId,
    pub(crate) turn: EntityId,
    pub(crate) message: EntityId,
    /// The person who wrote it: the card's principal, the one who may tap.
    pub(crate) author: EntityId,
    /// The thread the turn is, when the conversation is a project's room.
    pub(crate) thread: Option<EntityId>,
    pub(crate) at: u64,
}

/// What the project question answered on one source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProjectDetectionAnswer {
    /// Yes: the house mind drafts a card.
    Yes,
    /// The ladder asked a person; the source stays pending. A person's yes to
    /// the question is not the mint tap.
    AskedPerson,
}

/// The question's kept answer on one source, with its decision receipt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProjectDetectionVerdict {
    pub(crate) source: ProjectDetectionSource,
    pub(crate) answer: ProjectDetectionAnswer,
    pub(crate) receipt: DecisionReceipt,
    /// The house agent dispatched to draft the card; none when none resolves.
    pub(crate) house: Option<EntityId>,
}

/// Where a host-held card stands. A dismissed card never mints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectCardState {
    Proposed,
    Minted { project: EntityId },
    Dismissed,
}

/// One host-held card: what the drafting agent proposed on its source message,
/// bound to the detection that answered yes there. It is not authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectCardRecord {
    pub card: ProjectProposalCard,
    pub conversation: EntityId,
    /// The source message whose detection verdict and receipt this card answers.
    pub detection: EntityId,
    pub drafted_by: EntityId,
    pub state: ProjectCardState,
    pub at: u64,
}

/// What the drafting agent proposes on one source message. The principal and
/// the thread placement come from the detection, never from the request.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectProposalRequest {
    pub card_id: String,
    pub source_message_ref: String,
    pub goal: ProjectGoalDraft,
    pub picks: ProjectProposalPicks,
}

/// A tap on a host-held card. The host binds the authenticated owner, the
/// actor, the surface and the owner signer; none of them travel here.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectCardConfirmRequest {
    pub card_id: String,
    /// The card action tapped (`mint_project`).
    pub action_id: String,
    pub occurred_at: u64,
}

fn refused(reason: &str) -> Error {
    Error::InvalidConfig(format!("project card: {reason}"))
}

fn card_key(card_id: &str) -> [u8; 32] {
    *blake3::hash(card_id.as_bytes()).as_bytes()
}

fn canonical(reference: &str) -> Result<EntityId> {
    let id = EntityId::from_hex(reference).map_err(|_| invalid())?;
    if id.to_hex() != reference {
        return Err(invalid());
    }
    Ok(id)
}

/// Whether the conversation (in a room, the thread) already shows a card no
/// tap has answered.
fn live_card_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    conversation: EntityId,
    thread: Option<EntityId>,
) -> Result<bool> {
    for row in CONVERSATION_CARDS.iter_from(&vault.store, txn, conversation.as_bytes())? {
        let ((_, key), _) = row?;
        let Some(record) = CARDS.get(&vault.store, txn, &key)? else {
            continue;
        };
        if record.state == ProjectCardState::Proposed
            && thread.is_none_or(|thread| {
                record.card.source_thread_ref.as_deref() == Some(thread.to_hex().as_str())
            })
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn enqueue_detection_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    conversation: EntityId,
    now: u64,
) -> Result<()> {
    // One durable question per conversation: a pending one absorbs the call.
    AttemptQueue::new(vault).port_job_enqueue(
        txn,
        EnqueueAttempt {
            kind: PROJECT_DETECTION_KIND.to_owned(),
            payload: conversation.as_bytes().to_vec(),
            dedupe_key: Some(conversation.to_hex()),
            run_id: None,
            now,
        },
    )?;
    Ok(())
}

/// Stages the house mind's one project question on a person's on-record
/// turn, by reference, in the turn's own write. It runs no model and mints
/// nothing; a question already pending for the conversation takes this turn
/// as its latest source instead of queuing another. The witness passes no
/// `message` or `author` for a turn that is not a person's own words on
/// record. A project's home room is a project already: there only a thread
/// asks, toward its conversion. A conversation showing an unanswered card
/// asks nothing more.
pub(crate) fn stage_project_detection_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    conversation: EntityId,
    turn: EntityId,
    message: Option<EntityId>,
    author: Option<EntityId>,
    now: u64,
) -> Result<()> {
    let (Some(message), Some(author)) = (message, author) else {
        return Ok(());
    };
    let thread = if ROOM_PROJECT.contains(&vault.store, txn, &conversation)? {
        match rooms::TURNS.get(&vault.store, txn, &turn)? {
            // A reply's card converts its whole thread: record the root.
            Some(row) if row.thread_of.is_some() && row.converted_project.is_none() => Some(
                rooms::room_thread_turns_in_txn(vault, txn, conversation, turn)?
                    .and_then(|selection| selection.root)
                    .ok_or_else(invalid)?,
            ),
            _ => return Ok(()),
        }
    } else {
        None
    };
    if live_card_in(vault, txn, conversation, thread)? {
        return Ok(());
    }
    let source = ProjectDetectionSource {
        conversation,
        turn,
        message,
        author,
        thread,
        at: now,
    };
    PENDING.put(&vault.store, txn, &conversation, &source)?;
    enqueue_detection_in_txn(vault, txn, conversation, now)
}

/// One claimed project question: its attempt, its conversation, and the
/// latest source the conversation holds for it.
pub(crate) struct ClaimedProjectDetection {
    pub(crate) attempt: AttemptRecord,
    pub(crate) conversation: EntityId,
    pub(crate) source: Option<ProjectDetectionSource>,
}

/// Leases the oldest queued project question, if any.
pub(crate) fn claim_project_detection(
    vault: &Vault,
    lease_owner: &str,
    now: u64,
) -> Result<Option<ClaimedProjectDetection>> {
    let ClaimOutcome::Claimed(attempt) = AttemptQueue::new(vault).claim_kind(
        PROJECT_DETECTION_KIND,
        ClaimAttempt {
            lease_owner: lease_owner.to_owned(),
            now,
        },
    )?
    else {
        return Ok(None);
    };
    let conversation = EntityId::from_bytes(
        attempt
            .payload
            .as_slice()
            .try_into()
            .map_err(|_| Error::CorruptedIndex("project detection payload"))?,
    )?;
    let txn = vault.store.env.read_txn()?;
    let source = PENDING.get(&vault.store, &txn, &conversation)?;
    Ok(Some(ClaimedProjectDetection {
        attempt,
        conversation,
        source,
    }))
}

/// Settles a claimed question with its kept answer, if any, in one write. A
/// person asked keeps the source pending; a newer person turn that landed
/// while the question ran is asked again.
pub(crate) fn settle_project_detection(
    vault: &Vault,
    claimed: &ClaimedProjectDetection,
    lease_owner: &str,
    verdict: Option<&ProjectDetectionVerdict>,
) -> Result<()> {
    let keep = verdict.is_some_and(|verdict| verdict.answer == ProjectDetectionAnswer::AskedPerson);
    vault.with_write_txn_grouped(|txn| {
        if let Some(verdict) = verdict {
            VERDICTS.put(&vault.store, txn, &verdict.source.message, verdict)?;
        }
        AttemptQueue::new(vault).port_job_complete(
            txn,
            CompleteAttempt {
                id: claimed.attempt.id,
                lease_owner: lease_owner.to_owned(),
                attempt_count: claimed.attempt.attempt_count,
                now: 0,
            },
        )?;
        match PENDING.get(&vault.store, txn, &claimed.conversation)? {
            Some(latest) if Some(latest) == claimed.source => {
                if !keep {
                    PENDING.delete(&vault.store, txn, &claimed.conversation)?;
                }
            }
            Some(latest) => enqueue_detection_in_txn(vault, txn, claimed.conversation, latest.at)?,
            None => {}
        }
        Ok(())
    })
}

/// Ends a claimed question that could not be asked. Its source stays: the
/// conversation's next person turn asks again.
pub(crate) fn fail_project_detection(
    vault: &Vault,
    claimed: &ClaimedProjectDetection,
    lease_owner: &str,
    reason: String,
    now: u64,
) -> Result<()> {
    AttemptQueue::new(vault).fail(FailAttempt {
        id: claimed.attempt.id,
        lease_owner: lease_owner.to_owned(),
        attempt_count: claimed.attempt.attempt_count,
        reason,
        now,
    })?;
    Ok(())
}

/// The house mind: the root project's effective leader, which holds the root
/// house room. `None` when that leader is not an AGENT_DEF.
pub(crate) fn project_house_agent(vault: &Vault) -> Result<Option<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    let Some(root) = super::root_project_in(&vault.store, &txn)? else {
        return Ok(None);
    };
    let Some((_, effective)) = vault.effective_project_in_txn(&txn, root)? else {
        return Ok(None);
    };
    let leader = EntityId::from_hex(&effective.leader).map_err(|_| invalid())?;
    Ok(
        (vault.get_entity_type_in_txn(&txn, &leader)? == Some(ENTITY_TYPE_AGENT_DEF))
            .then_some(leader),
    )
}

fn mark_minted_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8; 32],
    receipt: &ProjectMintReceipt,
) -> Result<()> {
    let mut record = CARDS.get(&vault.store, txn, key)?.ok_or_else(invalid)?;
    if record.state != ProjectCardState::Proposed {
        return Err(refused("the card was already answered"));
    }
    record.state = ProjectCardState::Minted {
        project: EntityId::from_hex(&receipt.project_id).map_err(|_| invalid())?,
    };
    CARDS.put(&vault.store, txn, key, &record)
}

impl Vault {
    /// The project question's kept answer on one source message, if any: the
    /// record a drafting run is checked against (OF-501).
    pub(crate) fn project_detection_verdict_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        message: EntityId,
    ) -> Result<Option<ProjectDetectionVerdict>> {
        VERDICTS.get(&self.store, txn, &message)
    }

    /// One host-held card by its id, if any: the record a goal-intake run is
    /// checked against (OF-501).
    pub(crate) fn project_card_record_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        card_id: &str,
    ) -> Result<Option<ProjectCardRecord>> {
        CARDS.get(&self.store, txn, &card_key(card_id))
    }

    /// One host-held card by its id, if any, in a read of its own: the card
    /// a host's confirm door lists as the source of its answer.
    pub fn project_card(&self, card_id: &str) -> Result<Option<ProjectCardRecord>> {
        let txn = self.store.env.read_txn()?;
        self.project_card_record_in_txn(&txn, card_id)
    }

    /// One authorised tap mints a host-held card's project; the tap is the
    /// Grant move. The card is the host's stored one, never a client's: a
    /// card pinned on a thread in a project's room is born by conversion under
    /// that project, any other at the root, never both. The card turns Minted
    /// in the birth's own write, and an exact retry returns the recorded
    /// receipt. After a fresh birth the card's leader is dispatched to run
    /// the goal-intake interview in the new home room, seeded by the card.
    pub fn confirm_project_card(
        &self,
        card_id: &str,
        tap: &ConsentActionRequest,
        owner: &AuthenticatedOwner,
        signer: &OwnerProjectSigner<'_>,
    ) -> Result<ProjectMintReceipt> {
        let key = card_key(card_id);
        let record = {
            let txn = self.store.env.read_txn()?;
            CARDS.get(&self.store, &txn, &key)?.ok_or_else(invalid)?
        };
        if record.state == ProjectCardState::Dismissed {
            return Err(refused("a dismissed card never mints"));
        }
        let card = &record.card;
        // Only a fresh birth runs its step; an exact retry runs nothing.
        let mut fresh = false;
        let receipt = if card.source_thread_ref.is_some() {
            self.convert_thread_with_card(
                card,
                tap,
                owner,
                signer,
                EntityId::now(),
                tap.occurred_at,
                |txn, receipt| {
                    fresh = true;
                    mark_minted_in_txn(self, txn, &key, receipt)
                },
            )?
            .1
        } else {
            self.mint_card_with(card, tap, owner, signer, |txn, receipt| {
                fresh = true;
                mark_minted_in_txn(self, txn, &key, receipt)
            })?
        };
        if fresh && let Err(error) = self.dispatch_goal_intake(card, &receipt, tap.occurred_at) {
            tracing::warn!(project = %receipt.project_id, %error, "goal-intake interview not dispatched");
        }
        Ok(receipt)
    }

    /// The minted project's leader, as an ordinary attempt with no TASK, runs
    /// the goal-intake skill in the new home room. The brief names references
    /// only: the card is the interview's first turn, read back through
    /// [`Self::project_goal_interview_context`].
    fn dispatch_goal_intake(
        &self,
        card: &ProjectProposalCard,
        receipt: &ProjectMintReceipt,
        now: u64,
    ) -> Result<AgentDispatchOutcome> {
        let project = EntityId::from_hex(&receipt.project_id).map_err(|_| invalid())?;
        let leader = canonical(&card.leader_agent_def_ref)?;
        let home_room = super::home_room_id(project)?;
        let brief = serde_json::json!({
            "goal_intake": {
                "skill": "goal-intake",
                "project": project.to_hex(),
                "home_room": home_room.to_hex(),
                "card": card.card_id,
            }
        });
        AgentDispatcher::new(self).dispatch_with_context(
            DispatchAgent {
                target: AgentDispatchTarget::Custom(leader),
                parent_attempt: None,
                dedupe_key: Some(format!("project-goal-intake:{}", project.to_hex())),
                run_id: Some(format!("project:{}", project.to_hex())),
                now,
            },
            AgentSpawnContext {
                project_ref: Some(project),
                ..AgentSpawnContext::default()
            }
            .with_context_spec(ContextSpec::default().with_briefing(brief.to_string()))
            .with_origin_conversation(home_room),
        )
    }
}

impl Memory<'_> {
    /// The drafting agent's card on a source the project question answered
    /// yes on: only the house agent that yes dispatched may propose it. The
    /// card is stored host-held and idempotently per source message and card
    /// id; it writes no project and confers no authority. The person who
    /// wrote the source is its principal, and a source in a room thread pins
    /// the card there.
    pub fn projects_propose(
        &self,
        input: &ProjectProposalRequest,
    ) -> MemoryResult<ProjectProposalCard> {
        if self.actor_class() != EdgeActorClass::Agent {
            return Err(refused("only the drafting agent proposes a card").into());
        }
        let message = canonical(&input.source_message_ref)?;
        let key = card_key(&input.card_id);
        let vault = self.vault();
        let drafter = self.actor();
        let at = crate::unix_seconds_now();
        self.with_verified_actor_write_txn(|txn| {
            let verdict = VERDICTS
                .get(&vault.store, txn, &message)?
                .ok_or_else(|| refused("no project question answered yes on this message"))?;
            if verdict.answer != ProjectDetectionAnswer::Yes || verdict.house != Some(drafter) {
                return Err(refused("this agent was not asked to draft this card").into());
            }
            let source = verdict.source;
            let mut card = ProjectProposalCard::new(
                input.card_id.clone(),
                source.author.to_hex(),
                message.to_hex(),
                input.goal.clone(),
                input.picks.clone(),
            )?;
            if let Some(thread) = source.thread {
                card = card.on_thread(source.conversation, thread)?;
            }
            if let Some(stored) = CARDS.get(&vault.store, txn, &key)? {
                return if stored.card == card {
                    Ok(stored.card)
                } else {
                    Err(refused("this card id names another card").into())
                };
            }
            if live_card_in(vault, txn, source.conversation, source.thread)? {
                return Err(refused("the conversation already shows an unanswered card").into());
            }
            CARDS.put(
                &vault.store,
                txn,
                &key,
                &ProjectCardRecord {
                    card: card.clone(),
                    conversation: source.conversation,
                    detection: message,
                    drafted_by: drafter,
                    state: ProjectCardState::Proposed,
                    at,
                },
            )?;
            CONVERSATION_CARDS.put(&vault.store, txn, &(source.conversation, key), &message)?;
            Ok(card)
        })
    }

    /// The cards shown in a conversation, each with its state: to the person
    /// each is for, the agent that drafted it, and the members of the room it
    /// sits in. No client surface draws them yet; this is the read they use.
    pub fn projects_proposals(
        &self,
        conversation: EntityId,
    ) -> MemoryResult<Vec<ProjectCardRecord>> {
        let vault = self.vault();
        let actor = self.actor();
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        let mut cards = Vec::new();
        for row in CONVERSATION_CARDS.iter_from(&vault.store, &txn, conversation.as_bytes())? {
            let ((_, key), _) = row?;
            let Some(record) = CARDS.get(&vault.store, &txn, &key)? else {
                continue;
            };
            let member = match record.card.source_room_ref.as_deref() {
                Some(room) => rooms::require_member(vault, &txn, canonical(room)?, actor).is_ok(),
                None => false,
            };
            if member || record.drafted_by == actor || record.card.principal_ref == actor.to_hex() {
                cards.push(record);
            }
        }
        Ok(cards)
    }

    /// The card's person dismisses it: a dismissed card never mints. `false`
    /// when it was dismissed already; a minted card stays minted.
    pub fn projects_dismiss_card(&self, card_id: &str) -> MemoryResult<bool> {
        if self.actor_class() != EdgeActorClass::Human {
            return Err(refused("only the card's person dismisses it").into());
        }
        let key = card_key(card_id);
        let vault = self.vault();
        let actor = self.actor().to_hex();
        self.with_verified_actor_write_txn(|txn| {
            let mut record = CARDS.get(&vault.store, txn, &key)?.ok_or_else(invalid)?;
            if record.card.principal_ref != actor {
                return Err(refused("only the card's person dismisses it").into());
            }
            match record.state {
                ProjectCardState::Dismissed => Ok(false),
                ProjectCardState::Minted { .. } => {
                    Err(refused("a minted card stays minted").into())
                }
                ProjectCardState::Proposed => {
                    record.state = ProjectCardState::Dismissed;
                    CARDS.put(&vault.store, txn, &key, &record)?;
                    Ok(true)
                }
            }
        })
    }

    /// A surface holds neither the owner's authentication nor the host's owner
    /// signer, so it refuses the tap. The host's own door binds both to the
    /// authenticated request and calls [`Vault::confirm_project_card`] with
    /// the host-held card.
    pub fn projects_confirm(
        &self,
        _input: &ProjectCardConfirmRequest,
    ) -> MemoryResult<ProjectMintReceipt> {
        Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
            "a project card tap needs the host's authenticated owner and owner signer",
        ))
        .into())
    }

    /// What the goal-intake interview starts from, for a member of the
    /// project's home room.
    pub fn projects_goal_intake(
        &self,
        project: EntityId,
    ) -> MemoryResult<super::ProjectGoalInterviewContext> {
        let vault = self.vault();
        {
            let txn = vault.store.env.read_txn().map_err(Error::from)?;
            let record = vault
                .visible_project_in_txn(&txn, project)?
                .ok_or_else(invalid)?;
            rooms::require_member(vault, &txn, canonical(&record.home_room)?, self.actor())?;
        }
        Ok(vault.project_goal_interview_context(project)?)
    }
}
