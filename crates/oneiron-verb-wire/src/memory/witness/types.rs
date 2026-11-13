//! Moved from `crates/oneiron/src/memory/witness/types.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::witness_message_body::WITNESS_AUTHOR_COMPANION;
use oneiron_store::witness_message_body::WITNESS_AUTHOR_SYSTEM;
use oneiron_store::witness_message_body::WITNESS_AUTHOR_USER;
use serde::Deserialize;
use serde::Serialize;

/// Who authored one witnessed message (facade vocabulary; the MESSAGE body
/// `author` key stores the snake_case string).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WitnessMessage {
    /// Caller-supplied deterministic 32-hex entity id; `None` ⇒ generated.
    pub id: Option<String>,
    /// Author bucket; `System` rows get no `AuthoredBy` edge.
    pub author: WitnessAuthor,
    /// Message type string (closed set app-side, opaque here).
    pub message_type: String,
    /// Text content; BM25-indexed under the `content` field when non-empty.
    pub content: String,
    /// Ordered model-output parts owned by this MESSAGE. Text readers keep
    /// reading `content`; reasoning never enters their joined text or the
    /// editable document. Absent for text-only writers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parts: Option<Vec<oneiron_model::llm::ContentPart>>,
    /// Opaque metadata, passed through as MessagePack.
    pub metadata: Option<serde_json::Value>,
    /// Visibility flag (default true app-side).
    pub is_visible: bool,
    /// Position of the message within its turn.
    pub order: u32,
    /// This message's quote (OF-460; one per message, FIX 2028): a scalar
    /// span of one MESSAGE in the same room that the speaker's own read
    /// admits under the room's, or the destination thread's, ceiling; a
    /// private thread's MESSAGE only from inside that thread. The witness
    /// proves it in its own write, and this message is its citation: the
    /// engine-issued anchor is kept against this message's id, in its
    /// project room's turn row or, in an ordinary room, in its TURN's first
    /// body, so an ordinary room's quotes are born with their TURN. A
    /// project thread reply or an ordinary room's turn minted with quotes
    /// answers the first quoted message's TURN; a project trunk turn stays
    /// opaque. A stored message's quote is a birth fact, so a retry carries
    /// the same one. Absent ⇒ no quote.
    #[serde(default)]
    pub quote: Option<oneiron_store::conversation_record::QuoteSpan>,
}
