//! Witness DTOs: author enum, message/turn inputs, turn receipt.

use serde::{Deserialize, Serialize};

use crate::gate::{WITNESS_AUTHOR_COMPANION, WITNESS_AUTHOR_SYSTEM, WITNESS_AUTHOR_USER};

/// Who authored one witnessed message (facade vocabulary; the MESSAGE body
/// `author` key stores the snake_case string).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessAuthor {
    /// The vault owner.
    User,
    /// The companion persona.
    Companion,
    /// System/tooling rows; these get NO `AuthoredBy` edge (design §2.1).
    System,
}

impl WitnessAuthor {
    /// Stable string form (`user`/`companion`/`system`).
    ///
    /// The strings are the gate's own author vocabulary (ONE-1686): the
    /// witness ceiling door matches on them, so there is exactly one place
    /// they are spelled.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => WITNESS_AUTHOR_USER,
            Self::Companion => WITNESS_AUTHOR_COMPANION,
            Self::System => WITNESS_AUTHOR_SYSTEM,
        }
    }

    /// Parses the stable string form.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            WITNESS_AUTHOR_USER => Some(Self::User),
            WITNESS_AUTHOR_COMPANION => Some(Self::Companion),
            WITNESS_AUTHOR_SYSTEM => Some(Self::System),
            _ => None,
        }
    }
}

/// One message inside a witnessed turn.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WitnessMessage {
    /// Caller-supplied deterministic 32-hex entity id; `None` ⇒ generated.
    pub id: Option<String>,
    /// Author bucket; `System` rows get no `AuthoredBy` edge.
    pub author: WitnessAuthor,
    /// Message type string (closed set app-side, opaque here).
    pub message_type: String,
    /// Text content; BM25-indexed under the `content` field when non-empty.
    pub content: String,
    /// Opaque metadata, passed through as MessagePack.
    pub metadata: Option<serde_json::Value>,
    /// Visibility flag (default true app-side).
    pub is_visible: bool,
    /// Position of the message within its turn.
    pub order: u32,
}

/// One conversational turn to witness: create-or-get CONVERSATION/TURN plus
/// gated MESSAGE puts, edges, and text indexing in ONE batch (B2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WitnessTurn {
    /// CONVERSATION ref: short-id ref or 32-hex id (create-or-get for hex).
    pub conversation_ref: String,
    /// TURN ref (create-or-get for hex); `None` ⇒ a fresh TURN is created.
    pub turn_ref: Option<String>,
    /// Messages, all attributed to the bound actor unless `System`.
    ///
    /// A TURN is the maximal consecutive run of ONE speaker, so every
    /// non-system message in one call must share an author; `System` rows
    /// interleave freely. Consecutive runs of different speakers are
    /// witnessed as different turns, never as one `turn_ref` re-witnessed
    /// under another author.
    ///
    /// "Freely" is a STRUCTURAL statement, not an authority one (ONE-1686):
    /// a `System` row carries no `AuthoredBy` edge, so writing one requires a
    /// loaded policy with an owner-authored `actor_ceilings` row bound to the
    /// writing actor and resolving to `auto`. Each message's order must be
    /// distinct within the call and, when appending, from the turn's stored
    /// MESSAGE children.
    pub messages: Vec<WitnessMessage>,
    /// Unix seconds; used for both `occurred` and `learned_at` so
    /// migration backfill stays deterministic.
    pub occurred_at: u64,
}

/// Receipt for one witnessed turn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessReceipt {
    /// Short-id ref of the TURN (hex fallback if no short id exists).
    pub turn_short_id: String,
    /// Short-id refs of the written MESSAGE entities, input order.
    pub message_short_ids: Vec<String>,
    /// Facade write ref (`witness:<turn-hex>`). Structural puts produce no
    /// gate decision at base, so this is a write marker, not a
    /// `receipts()`-resolvable gate ref.
    pub receipt_ref: String,
}
