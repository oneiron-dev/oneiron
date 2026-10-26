//! A card's moves (agent-mind §3.5: "moves, each a proposal that the leader
//! or owner takes"): `ask_coach` (`ask`), and a note or a steer taken through
//! the doors that already carry them. A note is `self.message`'s own door to
//! the PERSON of the agent the card is about, sent as the caller, under that
//! door's authority, comm reach and text rules (ARCH-0079: "Advice. It
//! carries no authority"). A steer is the `steer` door's, the TASK's
//! spawner's or the owner's, on the card's TASK's live run ("A nudge, taken
//! at the child's next safe breakpoint"). Nothing here adds a right: a card's
//! reader takes only what those doors already admit it, and no detector or
//! pass calls this.
//!
//! The control runs first, in its own writes, with no transaction of this
//! module open; its receipt lands on the card after it, in a second write,
//! keyed by actor and retry key. The same key returns the stored receipt and
//! runs nothing again; the same key with other words is refused as a reused
//! signal key is. A receipt records the evidence basis the caller read and
//! the card's own, and whether they differ: it never refuses on that.

use serde::{Deserialize, Serialize};

use super::ask::ask_coach_in_txn;
use super::{
    AgentHealthCard, AgentHealthCoachAsk, AgentHealthMove, CARDS, card_ref, forbidden, may_read,
    parse_card_ref,
};
use crate::claim::{CallerLocality, ClaimReadStatus};
use crate::consent::AuthenticatedOwner;
use crate::context_board::People;
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult, MessagePersonReceipt,
    MessagePersonRequest,
};
use crate::run_tree::RunSignalState;
use crate::task_verb::sdk::{SteerReceipt, SteerRequest, steer_child, steer_child_as_owner};
use crate::{EdgeActorClass, EntityId, Error, Result, Vault};

const BASIS_DOMAIN: &[u8] = b"oneiron.coach.agent_health.move_basis.v1";
const PAYLOAD_DOMAIN: &[u8] = b"oneiron.coach.agent_health.move_payload.v1";
const STEER_KEY_DOMAIN: &[u8] = b"oneiron.coach.agent_health.move_steer_key.v1";

/// A card's key, `(actor, signal, task or zero)`.
type CardKey = ([u8; 16], [u8; 1], [u8; 16]);

/// A move a card's reader takes through `self.inbox.concern.move`, as the
/// owner does through `/v1/owner/inbox/concern/move`. A note's or a steer's
/// `key` is the caller's retry key: the same key returns the first receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConcernMove {
    /// Ask the Coach for a proposal, which lands on the card.
    AskCoach,
    /// Say a note to the card's agent through `self.message`'s door, as the
    /// caller. It carries no authority.
    Note {
        /// The caller's retry key.
        key: String,
        /// The note, as `self.message` takes it.
        text: String,
        /// As `self.message`'s `from_project`: when the sender leads several
        /// projects and sends from no run that names one.
        from_project: Option<String>,
        /// As `self.message`'s `to_project`: when the card's agent leads
        /// several projects.
        to_project: Option<String>,
    },
    /// Steer the live run of the card's TASK through the `steer` door, taken
    /// at its next safe breakpoint.
    Steer {
        /// The caller's retry key.
        key: String,
        /// The nudge, as `steer` takes it.
        instruction: String,
    },
}

/// `self.inbox.concern.move`'s input, and the owner route's body.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConcernMoveRequest {
    /// The card's `health:` handle: the concern row's `payload_ref`.
    pub card: String,
    /// The move taken.
    pub r#move: ConcernMove,
    /// The card's `basis` as the caller read it, echoed: a note's or a
    /// steer's receipt records whether the evidence moved since. It refuses
    /// nothing.
    pub basis: Option<ConcernMoveBasis>,
}

/// A card's typed evidence as one digest: its DIAGNOSTICs and evidence ids,
/// attempt, observed brief, window, number and dial, counter-evidence and
/// causes. A merge that changes them changes it; a move, an ask, an outcome,
/// `updated_at` and the time a review read the brief do not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConcernMoveBasis {
    /// BLAKE3, as 64 hex.
    pub digest: String,
}

/// A move's answer: the card's ask, or the receipt of a note or a steer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConcernMoveOutcome {
    /// The card's ask after `ask_coach`: a new one, or the one already
    /// standing for the same evidence.
    AskCoach {
        /// The card's `health:` handle.
        card: String,
        /// The ask.
        ask: AgentHealthCoachAsk,
    },
    /// A note or a steer that landed, or the receipt its key already holds.
    Applied {
        /// The card's `health:` handle.
        card: String,
        /// The move's receipt, as the card keeps it.
        receipt: ConcernMoveReceipt,
    },
}

/// One note or steer taken through a card, kept on it oldest first. It is
/// no evidence and never reopens the card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConcernMoveReceipt {
    /// Who took the move: the agent door's verified caller, or the actor the
    /// owner's proof names. Never request text.
    pub actor: EntityId,
    /// Its class: `human`, `agent` or `system`.
    pub actor_class: String,
    /// When the receipt landed.
    pub at: u64,
    /// The caller's retry key.
    pub key: String,
    /// BLAKE3 of the move's kind, key and every field it carries, as 64 hex.
    pub payload: String,
    /// The basis the caller echoed, when it did.
    pub observed: Option<ConcernMoveBasis>,
    /// The card's basis when the receipt landed.
    pub current: ConcernMoveBasis,
    /// The caller echoed a basis that is not the current one: recorded,
    /// never refused.
    pub evidence_changed: bool,
    /// The card's TASK.
    pub task: Option<EntityId>,
    /// The agent the card is about.
    pub subject: EntityId,
    /// The card's attempt when the receipt landed.
    pub attempt: Option<EntityId>,
    /// What the move's own door answered.
    pub link: ConcernMoveLink,
}

/// The native receipt a move's door answered, by the move's kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConcernMoveLink {
    /// `self.message`'s receipt: the room and the witness ids. The text stays
    /// in the room.
    Note {
        /// The room, as 32 hex.
        room: String,
        /// The TURN, as 32 hex.
        turn: Option<String>,
        /// The MESSAGEs, as 32 hex.
        messages: Vec<String>,
    },
    /// `steer`'s receipt. A pending signal is not yet taken.
    Steer {
        /// The steered TASK.
        task_ref: String,
        /// The live attempt whose inbox holds the signal, as 32 hex.
        branch: String,
        /// Its run.
        run_id: String,
        /// The signal's key, derived from the actor, the card and the key.
        key: String,
        /// Pending until the run's breakpoint takes it.
        state: RunSignalState,
        /// The steered attempt is not the card's: the TASK's live run moved
        /// on, or the card names no attempt.
        run_differs_from_card_attempt: bool,
    },
}

/// Who takes a note or a steer, and so whose check stands.
#[derive(Clone, Copy)]
enum Taker<'o> {
    /// The agent door's caller: a verified actor that reads the card.
    Agent,
    /// The vault's owner, by a proof each step revalidates.
    Owner(&'o AuthenticatedOwner),
}

/// A note or a steer, borrowed from its request.
#[derive(Clone, Copy)]
enum Control<'a> {
    Note {
        text: &'a str,
        from_project: Option<&'a str>,
        to_project: Option<&'a str>,
    },
    Steer {
        instruction: &'a str,
    },
}

/// What a control's door answered.
enum Landed {
    Note(MessagePersonReceipt),
    Steer(SteerReceipt),
}

/// A landed control, and what its receipt names besides the card.
struct Landing<'a> {
    actor: EntityId,
    actor_class: &'static str,
    key: &'a str,
    payload: &'a str,
    observed: Option<&'a ConcernMoveBasis>,
    landed: Landed,
}

/// One length-prefixed field, so no two field lists hash alike.
fn field(digest: &mut blake3::Hasher, bytes: &[u8]) {
    digest.update(&(bytes.len() as u64).to_le_bytes());
    digest.update(bytes);
}

fn optional_text(digest: &mut blake3::Hasher, text: Option<&str>) {
    match text {
        Some(text) => {
            digest.update(&[1]);
            field(digest, text.as_bytes());
        }
        None => {
            digest.update(&[0]);
        }
    }
}

fn optional_id(digest: &mut blake3::Hasher, id: Option<EntityId>) {
    match id {
        Some(id) => {
            digest.update(&[1]);
            digest.update(id.as_bytes());
        }
        None => {
            digest.update(&[0]);
        }
    }
}

fn ids(digest: &mut blake3::Hasher, ids: &[EntityId]) {
    digest.update(&(ids.len() as u64).to_le_bytes());
    for id in ids {
        digest.update(id.as_bytes());
    }
}

/// The card's evidence basis, as its view shows it and a receipt records it.
pub(super) fn basis(card: &AgentHealthCard) -> ConcernMoveBasis {
    let mut digest = blake3::Hasher::new();
    digest.update(BASIS_DOMAIN);
    ids(&mut digest, &card.diagnostics);
    ids(&mut digest, &card.evidence);
    optional_id(&mut digest, card.attempt);
    match &card.observed_brief {
        // The brief's identity, never the time a review read it.
        Some(pin) => {
            digest.update(&[1]);
            digest.update(pin.task.as_bytes());
            digest.update(&pin.rev.to_le_bytes());
            field(&mut digest, pin.digest.as_bytes());
        }
        None => {
            digest.update(&[0]);
        }
    }
    for number in [card.window_from, card.window_to] {
        digest.update(&number.to_le_bytes());
    }
    for number in [card.measured, card.dial] {
        digest.update(&number.to_le_bytes());
    }
    digest.update(&(card.counter_evidence.len() as u64).to_le_bytes());
    for counter in &card.counter_evidence {
        digest.update(&[*counter as u8]);
    }
    digest.update(&(card.causes.len() as u64).to_le_bytes());
    for cause in &card.causes {
        digest.update(cause.source.as_bytes());
        field(&mut digest, cause.receipt.as_bytes());
        optional_id(&mut digest, cause.skill);
        field(&mut digest, cause.label.as_bytes());
        digest.update(&cause.share.to_bits().to_le_bytes());
        optional_text(&mut digest, cause.judge_revision.as_deref());
        optional_text(&mut digest, cause.displaced_by.as_deref());
    }
    ConcernMoveBasis {
        digest: digest.finalize().to_hex().to_string(),
    }
}

/// A note's or a steer's retry key and control; `None` for `ask_coach`.
fn control_of(r#move: &ConcernMove) -> Option<(&str, Control<'_>)> {
    match r#move {
        ConcernMove::AskCoach => None,
        ConcernMove::Note {
            key,
            text,
            from_project,
            to_project,
        } => Some((
            key.as_str(),
            Control::Note {
                text: text.as_str(),
                from_project: from_project.as_deref(),
                to_project: to_project.as_deref(),
            },
        )),
        ConcernMove::Steer { key, instruction } => Some((
            key.as_str(),
            Control::Steer {
                instruction: instruction.as_str(),
            },
        )),
    }
}

/// BLAKE3 of the move's kind, key and every field it carries, as 64 hex.
fn payload(key: &str, control: Control<'_>) -> String {
    let mut digest = blake3::Hasher::new();
    digest.update(PAYLOAD_DOMAIN);
    match control {
        Control::Note {
            text,
            from_project,
            to_project,
        } => {
            field(&mut digest, b"note");
            field(&mut digest, key.as_bytes());
            field(&mut digest, text.as_bytes());
            optional_text(&mut digest, from_project);
            optional_text(&mut digest, to_project);
        }
        Control::Steer { instruction } => {
            field(&mut digest, b"steer");
            field(&mut digest, key.as_bytes());
            field(&mut digest, instruction.as_bytes());
        }
    }
    digest.finalize().to_hex().to_string()
}

/// The steer signal's key: one per actor, card and retry key, never the
/// caller's own string, so two cards' keys never meet in one run's inbox.
fn steer_key(actor: EntityId, card: &str, key: &str) -> String {
    let mut digest = blake3::Hasher::new();
    digest.update(STEER_KEY_DOMAIN);
    digest.update(actor.as_bytes());
    field(&mut digest, card.as_bytes());
    field(&mut digest, key.as_bytes());
    format!("health-move:{}", digest.finalize().to_hex())
}

/// The receipt `actor` already holds on `card` under `key`: the same words
/// return it, other words are refused as a reused signal key is.
fn taken(
    card: &AgentHealthCard,
    actor: EntityId,
    key: &str,
    payload: &str,
) -> Result<Option<ConcernMoveReceipt>> {
    let Some(stored) = card
        .moves_taken
        .iter()
        .find(|receipt| receipt.actor == actor && receipt.key == key)
    else {
        return Ok(None);
    };
    if stored.payload != payload {
        return Err(Error::InvalidConfig(
            "concern move key reused with different intent".into(),
        ));
    }
    Ok(Some(stored.clone()))
}

/// Now in unix milliseconds, the clock the people roster reads agents at.
fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// `self.message` to the PERSON of the card's agent, as the caller: the
/// person comes from the card, never from the request, and the door reads
/// it again through the caller's own read. A caller whose read does not hold
/// that PERSON is refused here, its handle unnamed (FIX 8537).
fn note(
    memory: &Memory<'_>,
    card: &AgentHealthCard,
    text: &str,
    from_project: Option<&str>,
    to_project: Option<&str>,
) -> MemoryResult<MessagePersonReceipt> {
    let people = People::load(memory.vault(), unix_ms(), &mut |_| Ok(true))?;
    let row = people
        .get(card.subject)
        .ok_or_else(|| MemoryError::not_found("the card's agent is not a person in this vault"))?;
    let readable = memory
        .read_lane(ClaimReadStatus::Surfaceable)?
        .is_entity_readable(&row.person)?;
    if !readable {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "the caller's read does not hold the card's agent, so it cannot message it",
            &[],
        ));
    }
    memory.message_person(&MessagePersonRequest {
        pr: row.handle.clone(),
        text: text.to_owned(),
        mention: None,
        from_project: from_project.map(str::to_owned),
        to_project: to_project.map(str::to_owned),
    })
}

fn link(landed: &Landed, attempt: Option<EntityId>) -> ConcernMoveLink {
    match landed {
        Landed::Note(message) => ConcernMoveLink::Note {
            room: message.room.clone(),
            turn: message.receipt.turn.as_ref().map(|turn| turn.id.clone()),
            messages: message
                .receipt
                .messages
                .iter()
                .map(|message| message.id.clone())
                .collect(),
        },
        Landed::Steer(steer) => ConcernMoveLink::Steer {
            task_ref: steer.task_ref.clone(),
            branch: steer.branch.clone(),
            run_id: steer.run_id.clone(),
            key: steer.key.clone(),
            state: steer.state,
            run_differs_from_card_attempt: attempt
                .is_none_or(|attempt| attempt.to_hex() != steer.branch),
        },
    }
}

/// The receipt, on the card as it reads in the second write. A twin call
/// with the same key that landed first keeps its receipt.
fn record_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    card_key: &CardKey,
    landing: &Landing<'_>,
) -> Result<ConcernMoveOutcome> {
    let mut card = CARDS
        .get(&vault.store, txn, card_key)?
        .ok_or(Error::EntityNotFound)?;
    let receipt = match taken(&card, landing.actor, landing.key, landing.payload)? {
        Some(receipt) => receipt,
        None => {
            let current = basis(&card);
            let receipt = ConcernMoveReceipt {
                actor: landing.actor,
                actor_class: landing.actor_class.to_owned(),
                at: vault.store.clock.now_recorded_at(),
                key: landing.key.to_owned(),
                payload: landing.payload.to_owned(),
                observed: landing.observed.cloned(),
                evidence_changed: landing
                    .observed
                    .is_some_and(|observed| *observed != current),
                current,
                task: card.task,
                subject: card.subject,
                attempt: card.attempt,
                link: link(&landing.landed, card.attempt),
            };
            card.moves_taken.push(receipt.clone());
            card.updated_at = receipt.at;
            CARDS.put(&vault.store, txn, card_key, &card)?;
            // A touched card can arm the digest on its own (FIX 1979).
            crate::batch::queue_proactivity_change(vault, txn);
            receipt
        }
    };
    Ok(ConcernMoveOutcome::Applied {
        card: card_ref(card_key),
        receipt,
    })
}

/// A note or a steer, for both doors: the card and the caller's standing in
/// one read, where a retry returns; the control through its own door, with
/// nothing open here; then the receipt in a second write.
fn take(
    memory: &Memory<'_>,
    taker: Taker<'_>,
    card_key: &CardKey,
    observed: Option<&ConcernMoveBasis>,
    key: &str,
    control: Control<'_>,
) -> MemoryResult<ConcernMoveOutcome> {
    let vault = memory.vault();
    let handle = card_ref(card_key);
    let actor = memory.actor();
    let payload = payload(key, control);
    let card = {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        match taker {
            Taker::Agent => crate::memory::verify_actor_binding_in_txn(
                vault,
                &txn,
                actor,
                memory.actor_class(),
            )?,
            Taker::Owner(owner) => {
                owner.revalidate_in_txn(vault, &txn)?;
            }
        }
        let card = CARDS
            .get(&vault.store, &txn, card_key)?
            .ok_or_else(|| MemoryError::not_found("no such concern card"))?;
        if matches!(taker, Taker::Agent) && !may_read(vault, &txn, &card, actor)? {
            return Err(forbidden());
        }
        if let Some(receipt) = taken(&card, actor, key, &payload)? {
            return Ok(ConcernMoveOutcome::Applied {
                card: handle,
                receipt,
            });
        }
        card
    };
    let landed = match control {
        Control::Note {
            text,
            from_project,
            to_project,
        } => Landed::Note(note(memory, &card, text, from_project, to_project)?),
        Control::Steer { instruction } => {
            let task = card.task.ok_or_else(|| {
                MemoryError::bad_request("this concern card names no task to steer")
            })?;
            let request = SteerRequest {
                task_ref: task.to_hex(),
                instruction: instruction.to_owned(),
                key: steer_key(actor, &handle, key),
            };
            Landed::Steer(match taker {
                Taker::Agent => steer_child(memory, request)?,
                Taker::Owner(owner) => steer_child_as_owner(memory, owner, request)?,
            })
        }
    };
    let landing = Landing {
        actor,
        actor_class: memory.actor_class().gate_actor_class(),
        key,
        payload: &payload,
        observed,
        landed,
    };
    Ok(match taker {
        Taker::Agent => memory.with_verified_actor_write_txn(|txn| {
            Ok(record_in_txn(vault, txn, card_key, &landing)?)
        })?,
        Taker::Owner(owner) => vault.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(vault, txn)?;
            record_in_txn(vault, txn, card_key, &landing)
        })?,
    })
}

impl Vault {
    /// The owner takes one of a card's moves, as `self.inbox.concern.move`
    /// does for a recipient. `ask_coach` is
    /// [`Self::ask_coach_on_agent_health_card`]. A note and a steer run as
    /// the owner's own Human caller at `locality`, as the owner's steer route
    /// builds it: the note through `self.message`'s door, the steer through
    /// the owner's steer, which rechecks the proof. The same key returns the
    /// first receipt.
    ///
    /// # Errors
    ///
    /// A malformed handle or an unknown card; owner revalidation errors; the
    /// note's or the steer's own refusals; a key reused with other words;
    /// storage errors.
    pub fn apply_concern_move(
        &self,
        owner: &AuthenticatedOwner,
        locality: CallerLocality,
        input: &ConcernMoveRequest,
    ) -> MemoryResult<ConcernMoveOutcome> {
        let Some((key, control)) = control_of(&input.r#move) else {
            return Ok(self.ask_coach_on_agent_health_card(owner, &input.card)?);
        };
        let card_key = parse_card_ref(&input.card).ok_or_else(|| {
            MemoryError::bad_request("card is a health: handle from a concern row")
        })?;
        let actor = owner.revalidate(self)?;
        let memory = self.memory(actor, EdgeActorClass::Human).at(locality);
        take(
            &memory,
            Taker::Owner(owner),
            &card_key,
            input.basis.as_ref(),
            key,
            control,
        )
    }
}

impl Memory<'_> {
    /// `self.inbox.concern.move`: a card's recipient (its leader or spawner)
    /// or a vault owner takes one of its moves. `ask_coach` queues the
    /// Coach's answer, which lands on the card; asking again on the same
    /// evidence returns the standing ask. A note goes to the card's agent
    /// through `self.message`'s door and a steer to its TASK's live run
    /// through `steer`'s, each under that door's own rule; its receipt lands
    /// on the card after it, and the same key returns it.
    pub fn concern_move(&self, input: &ConcernMoveRequest) -> MemoryResult<ConcernMoveOutcome> {
        let key = parse_card_ref(&input.card).ok_or_else(|| {
            MemoryError::bad_request("card is a health: handle from a concern row")
        })?;
        if let Some((move_key, control)) = control_of(&input.r#move) {
            return take(
                self,
                Taker::Agent,
                &key,
                input.basis.as_ref(),
                move_key,
                control,
            );
        }
        let at = self.vault().store.clock.now_recorded_at();
        self.with_verified_actor_write_txn(|txn| {
            let card = CARDS
                .get(&self.vault().store, txn, &key)?
                .ok_or_else(|| MemoryError::not_found("no such concern card"))?;
            if !may_read(self.vault(), txn, &card, self.actor())? {
                return Err(forbidden());
            }
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
        })
    }
}
