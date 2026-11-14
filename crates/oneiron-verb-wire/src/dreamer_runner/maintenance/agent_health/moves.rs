//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/agent_health/moves.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::attempt_run_signal::RunSignalState;
use serde::Deserialize;
use serde::Serialize;

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

/// One note or steer taken through a card, kept on it oldest first. It is
/// no evidence and never reopens the card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
