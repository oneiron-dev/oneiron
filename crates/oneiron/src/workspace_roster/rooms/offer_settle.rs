//! Answering an offer card (OF-530): join or not now, from the room's host.
//!
//! The party whose admission a card asks for answers it: the room's owner or
//! a delegated host, the party `rooms.consent` takes the admission part from.
//! The request names only the card, the verb and its replay key; the room,
//! thread, agent, payer and cap are read back from the stored card.
//!
//! Join records the host's yes on the card's join and decides it again. A
//! Hold keeps the card open with the parties still missing, and lands
//! nothing. A Ready join commits, in one write, the receipt proved again for
//! exactly that thread, the agent's participation fact, the card's
//! settlement and the acceptance itself, landed as the agent's own turn
//! through the room's speech door ("accepted, it becomes her turn"). The
//! card stores that turn once: a replay returns it and lands no second one.
//!
//! Not now records the host's no on the join and lands the decline in the
//! agent's private diary, in the same write: no seat, no participation fact,
//! no launch and no spend hold. It settles this card and bars no later ask.
//! A not now always settles: when the agent's standing refuses the diary
//! note, the card settles with no diary entry; any other error fails it.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::offers::{OFFERS, OfferCard, OfferState, StoredOffer, is_offer_id, join_refused};
use super::participation::{JoinCause, record_participation_in_txn};
use crate::edge::EdgeActorClass;
use crate::error::{ClaimError, Error, Result};
use crate::memory::{
    MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult, WitnessAuthor, WitnessMessage,
    WitnessTurn,
};
use crate::workspace_roster::join_door::require_admission_party_in_txn;
use crate::workspace_roster::join_receipt::JOINS;
use crate::workspace_roster::{
    ConsentAnswer, ConsentPart, JoinDecision, JoinOutcome, JoinReceiptRef, JoinSubject,
    require_join_for_branch_in_txn, rooms_consent_in_txn,
};
use crate::{EntityId, Vault, WriteActor};

/// The host's verb on a card.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OfferAnswer {
    Join,
    NotNow,
}

/// An answer to one card. It cannot change the card, its payer, thread or
/// cap: those are read back from the stored card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferAnswerRequest {
    pub offer_id: String,
    pub action: OfferAnswer,
    /// The answerer's idempotency key, 1..=128 printable bytes.
    pub intent_key: String,
}

/// What an answer left: the card's state, the join as last decided, and the
/// turn or diary NOTE it landed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfferSettlement {
    pub offer_id: String,
    pub state: OfferState,
    pub join: Option<JoinOutcome>,
    /// The agent's acceptance turn, when a join landed one. This, not the
    /// verb's wake, is the truth: a wake after a hold or a not now finds no
    /// new turn.
    pub turn_ref: Option<String>,
    /// The agent's private diary NOTE a not now landed in.
    pub diary_ref: Option<String>,
}

/// The host's answer that settled a card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecordedOfferAnswer {
    pub(super) action: OfferAnswer,
    /// The host's actor.
    pub(super) by: EntityId,
    pub(super) intent_key: String,
    /// Unix seconds.
    pub(super) at: u64,
}

/// What one settlement write leaves to do.
pub(super) enum Step {
    /// Everything is written: commit.
    Done(Settled),
    /// The join is Ready: the agent's acceptance lands in this same write.
    Land(Box<Acceptance>),
}

/// A card as one write left it, with the join as last decided.
pub(super) struct Settled {
    pub(super) card: OfferCard,
    pub(super) join: Option<JoinOutcome>,
}

impl Settled {
    /// A stored card as it stands, with its join's receipt.
    pub(super) fn replayed(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        stored: StoredOffer,
    ) -> Result<Self> {
        let join = JOINS
            .get(&vault.store, txn, &stored.card.join_ref)?
            .map(|receipt| JoinOutcome::of(&receipt));
        Ok(Self {
            card: stored.card,
            join,
        })
    }

    fn settlement(self) -> OfferSettlement {
        let (turn_ref, diary_ref) = match &self.card.state {
            OfferState::Joined { turn, .. } => (Some(turn.to_hex()), None),
            OfferState::NotNow { diary_ref } => (None, diary_ref.map(|note| note.to_hex())),
            _ => (None, None),
        };
        OfferSettlement {
            offer_id: self.card.offer_id,
            state: self.card.state,
            join: self.join,
            turn_ref,
            diary_ref,
        }
    }
}

/// The acceptance a Ready join lands: the card it accepts, and the receipt
/// proved again for exactly its room or thread.
pub(super) struct Acceptance {
    card: OfferCard,
    receipt: JoinReceiptRef,
    join: JoinOutcome,
}

impl Acceptance {
    /// A Ready receipt is evidence, never a grant: it is proved again against
    /// live facts, for exactly the card's thread and the scope it spends under.
    pub(super) fn ready_in_txn(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        card: OfferCard,
        join: JoinOutcome,
    ) -> Result<Self> {
        let receipt = require_join_for_branch_in_txn(
            vault,
            txn,
            card.room,
            card.branch,
            &JoinSubject::Agent(card.agent),
            card.spend_scope.as_ref(),
        )?;
        Ok(Self {
            card,
            receipt,
            join,
        })
    }

    /// The agent's own turn: the card's sentence and artifact, placed in its
    /// thread, carrying the offer and the join receipt.
    fn turn(&self, turn: EntityId, at: u64) -> WitnessTurn {
        let mut metadata = serde_json::Map::new();
        if let Some(branch) = self.card.branch {
            metadata.insert("room_reply_to".to_owned(), branch.to_hex().into());
        }
        metadata.insert("room_offer".to_owned(), self.card.offer_id.clone().into());
        metadata.insert(
            "room_join_receipt".to_owned(),
            self.receipt.as_str().to_owned().into(),
        );
        let content = match &self.card.artifact_ref {
            Some(artifact) => format!("{}\n{artifact}", self.card.what),
            None => self.card.what.clone(),
        };
        WitnessTurn {
            conversation_ref: self.card.room.to_hex(),
            turn_ref: Some(turn.to_hex()),
            quote: None,
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: None,
                author: WitnessAuthor::Companion,
                message_type: "text".to_owned(),
                content,
                metadata: Some(serde_json::Value::Object(metadata)),
                is_visible: true,
                order: 0,
            }],
            occurred_at: at,
        }
    }
}

/// A first write that must not commit alone.
enum Pending {
    Failed(MemoryError),
    Land(Box<Acceptance>),
}

impl From<Error> for Pending {
    fn from(error: Error) -> Self {
        Self::Failed(error.into())
    }
}

impl From<MemoryError> for Pending {
    fn from(error: MemoryError) -> Self {
        Self::Failed(error)
    }
}

/// Runs `step` in one write. A step that must land the agent's acceptance
/// commits nothing there: it runs again inside the room speech writer's own
/// write, the one `rooms.speak` lands through, as the agent, so the join,
/// its participation fact, the card's settlement and the turn commit
/// together or not at all.
pub(super) fn run_settlement(
    vault: &Vault,
    step: impl Fn(&mut heed::RwTxn<'_>, u64) -> MemoryResult<Step>,
) -> MemoryResult<Settled> {
    let first = vault.try_with_write_txn_grouped(|txn| {
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        match step(txn, now)? {
            Step::Done(settled) => Ok(settled),
            Step::Land(acceptance) => Err(Pending::Land(acceptance)),
        }
    });
    let planned = match first {
        Ok(settled) => return Ok(settled),
        Err(Pending::Failed(error)) => return Err(error),
        Err(Pending::Land(acceptance)) => acceptance,
    };
    let turn = vault.store.clock.entity_id()?;
    let speech = planned.turn(turn, vault.store.clock.now_recorded_at());
    let mut landed = None;
    // The agent speaks: its speaking role, the room door and its own author
    // ceiling decide the turn. The settlement runs before the door reads it.
    vault
        .memory(planned.card.agent, EdgeActorClass::Agent)
        .witness_with_room_birth(&speech, |txn| {
            let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
            let Step::Land(acceptance) = step(txn, now)? else {
                return Err(MemoryError::new(
                    MEMORY_CODE_INVALID_STATE,
                    "the join changed while the acceptance landed",
                    &["Answer the offer again."],
                ));
            };
            if acceptance.card.offer_id != planned.card.offer_id {
                return Err(Error::InvariantViolation("offer acceptance changed card").into());
            }
            landed = Some(land_in_txn(vault, txn, *acceptance, turn, now)?);
            Ok(())
        })?;
    landed.ok_or_else(|| Error::InvariantViolation("offer acceptance left no settlement").into())
}

/// A Ready acceptance's settlement, written before the speech door reads it:
/// the agent's participation fact, and the card Joined with exactly `turn`,
/// which is what lets the door take the turn without a claim. The turn
/// itself lands next in the same write.
fn land_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    acceptance: Acceptance,
    turn: EntityId,
    now: u64,
) -> Result<Settled> {
    let Acceptance {
        card,
        receipt,
        join,
    } = acceptance;
    record_participation_in_txn(
        vault,
        txn,
        card.room,
        card.branch,
        &JoinSubject::Agent(card.agent),
        &JoinCause::Offer {
            offer_id: card.offer_id.clone(),
        },
        Some(&receipt),
        now,
    )?;
    let mut stored = OFFERS
        .get(&vault.store, txn, &card.offer_id)?
        .ok_or(Error::CorruptedIndex("offer card"))?;
    stored.card.state = OfferState::Joined {
        turn,
        receipt_ref: receipt.as_str().to_owned(),
    };
    OFFERS.put(&vault.store, txn, &card.offer_id, &stored)?;
    Ok(Settled {
        card: stored.card,
        join: Some(join),
    })
}

/// The decline, in the agent's own words, for its private diary.
fn decline_note(card: &OfferCard) -> String {
    let place = card.branch.map_or_else(
        || format!("room {}", card.room.to_hex()),
        |branch| format!("thread {} of room {}", branch.to_hex(), card.room.to_hex()),
    );
    format!(
        "Offer {} in {place}: not now. I offered: {}",
        card.offer_id, card.what
    )
}

/// Lands the decline in the agent's private diary, in a savepoint of the
/// answer's write. The host's not now never waits on the agent's standing: a
/// diary note the agent's content-write standing refuses rolls back alone,
/// and the card settles with no diary entry. Any other error fails the answer.
fn decline_in_diary_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    card: &OfferCard,
    now: u64,
) -> Result<Option<EntityId>> {
    let mut savepoint = vault.store.env.nested_write_txn(txn)?;
    match crate::memory::append_agent_diary_in_txn(
        vault,
        &mut savepoint,
        WriteActor::new(card.agent, EdgeActorClass::Agent),
        decline_note(card),
        now,
    ) {
        Ok(note) => {
            savepoint.commit()?;
            Ok(Some(note))
        }
        Err(Error::Claim(ClaimError::ActorLacksClaimAuthority { .. })) => {
            drop(savepoint);
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

/// Answers `request` as `caller` in the caller's write. `ended` says the
/// card's thread has ended, read before the write from the room's fold; a
/// room-wide card's own time is read here, from the stored card.
fn answer_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    request: &OfferAnswerRequest,
    caller: WriteActor,
    ended: bool,
    now: u64,
) -> MemoryResult<Step> {
    vault.verify_write_actor_in_txn(txn, &caller)?;
    let mut stored = OFFERS
        .get(&vault.store, txn, &request.offer_id)?
        .ok_or_else(|| MemoryError::not_found("no offer card under this offer_id"))?;
    // The party whose admission the card asks for answers it, whatever the
    // join's state.
    require_admission_party_in_txn(vault, txn, stored.card.room, caller)?;
    if let Some(answer) = &stored.answer {
        if answer.action != request.action {
            return Err(MemoryError::bad_request(
                "this offer was already answered the other way",
            ));
        }
        return Ok(Step::Done(Settled::replayed(vault, txn, stored)?));
    }
    // Joined at its mint, replaced or aged out: nothing is left to answer.
    if !matches!(stored.card.state, OfferState::Open { .. }) {
        return Ok(Step::Done(Settled::replayed(vault, txn, stored)?));
    }
    if ended || super::offer_activity::room_offer_expired(&stored.card, now) {
        stored.card.state = OfferState::AgedOut;
        OFFERS.put(&vault.store, txn, &request.offer_id, &stored)?;
        return Ok(Step::Done(Settled::replayed(vault, txn, stored)?));
    }
    // An answer engages the card: one that holds keeps it open from now.
    stored.card.last_engaged_at = stored.card.last_engaged_at.max(now);
    let join = rooms_consent_in_txn(
        vault,
        txn,
        &ConsentAnswer {
            join_ref: stored.card.join_ref.clone(),
            part: ConsentPart::Admission,
            grant: request.action == OfferAnswer::Join,
            spend_scope: None,
        },
        caller,
        now,
    )?;
    let answer = RecordedOfferAnswer {
        action: request.action,
        by: caller.entity_ref(),
        intent_key: request.intent_key.clone(),
        at: now,
    };
    match request.action {
        OfferAnswer::NotNow => {
            let diary_ref = decline_in_diary_in_txn(vault, txn, &stored.card, now)?;
            stored.card.state = OfferState::NotNow { diary_ref };
            stored.answer = Some(answer);
            OFFERS.put(&vault.store, txn, &request.offer_id, &stored)?;
            Ok(Step::Done(Settled {
                card: stored.card,
                join: Some(join),
            }))
        }
        OfferAnswer::Join => match join.decision.state.clone() {
            // The card stays open: the host may answer again once the party
            // fixes its standing.
            JoinDecision::Refuse(refusal) => Err(join_refused(&refusal)),
            JoinDecision::Hold { needs } => {
                stored.card.state = OfferState::Open { needs };
                OFFERS.put(&vault.store, txn, &request.offer_id, &stored)?;
                Ok(Step::Done(Settled {
                    card: stored.card,
                    join: Some(join),
                }))
            }
            JoinDecision::Ready => {
                stored.answer = Some(answer);
                OFFERS.put(&vault.store, txn, &request.offer_id, &stored)?;
                Ok(Step::Land(Box::new(Acceptance::ready_in_txn(
                    vault,
                    txn,
                    stored.card,
                    join,
                )?)))
            }
        },
    }
}

impl Memory<'_> {
    /// Answers an offer card as the room's host: join or not now. See the
    /// module docs.
    pub fn rooms_offer_answer(
        &self,
        request: &OfferAnswerRequest,
    ) -> MemoryResult<OfferSettlement> {
        if !is_offer_id(&request.offer_id) {
            return Err(MemoryError::bad_request(
                "offer_id is the 64-hex id rooms.offer returned",
            ));
        }
        if !super::offers::valid_intent_key(&request.intent_key) {
            return Err(MemoryError::bad_request(
                "an answer's intent_key is 1..=128 printable bytes",
            ));
        }
        let vault = self.vault();
        let caller = WriteActor::new(self.actor(), self.actor_class());
        let card = {
            let txn = vault.store.env.read_txn().map_err(Error::from)?;
            let stored = OFFERS
                .get(&vault.store, &txn, &request.offer_id)?
                .ok_or_else(|| MemoryError::not_found("no offer card under this offer_id"))?;
            require_admission_party_in_txn(vault, &txn, stored.card.room, caller)?;
            stored.card
        };
        // Whether the card's thread has ended, from the room's own fold as
        // the host reads it, before the write.
        let ended = match (&card.state, card.branch) {
            (OfferState::Open { .. }, Some(branch)) => self
                .ended_offer_threads(card.room, &BTreeSet::from([branch]))?
                .contains(&branch),
            _ => false,
        };
        Ok(run_settlement(vault, |txn, now| {
            answer_in_txn(vault, txn, request, caller, ended, now)
        })?
        .settlement())
    }
}
