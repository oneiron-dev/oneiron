//! Moved from `crates/oneiron/src/board_verb.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::context_board::stream::events::SubscriptionReceipt;
use crate::context_board::stream::frames::StreamConnectionId;
use oneiron_verb_wire::context_board::stream::events::SubscriptionScope;
use oneiron_verb_wire::context_board::stream::frames::BoardStreamFrame;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// A board verb's answer. It is written as [`BoardVerbOutputWire`], the one
/// shape MCP and code mode read (FIX 2153).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(into = "BoardVerbOutputWire")]
pub enum BoardVerbOutput {
    Expanded { key: String, lines: Vec<String> },
    Frame(BoardStreamFrame),
    Subscription(SubscriptionReceipt),
}

/// [`BoardVerbOutput`] on the wire, tagged by `kind`: an expanded card's key
/// and lines, a frame, or a subscription's connection and active scopes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BoardVerbOutputWire {
    Expanded {
        key: String,
        lines: Vec<String>,
    },
    Frame {
        frame: BoardStreamFrame,
    },
    Subscription {
        connection: StreamConnectionId,
        active: BTreeSet<SubscriptionScope>,
    },
}

impl From<BoardVerbOutput> for BoardVerbOutputWire {
    fn from(output: BoardVerbOutput) -> Self {
        match output {
            BoardVerbOutput::Expanded { key, lines } => Self::Expanded { key, lines },
            BoardVerbOutput::Frame(frame) => Self::Frame { frame },
            BoardVerbOutput::Subscription(receipt) => Self::Subscription {
                connection: receipt.connection,
                active: receipt.active,
            },
        }
    }
}
