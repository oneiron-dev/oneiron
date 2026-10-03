//! The tagger's input for one turn, read from the turn's MESSAGE rows.

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::edge::EdgeKind;
use crate::error::Result;
use crate::memory::extraction::{EncoderInput, EncoderMessage};
use crate::ports::EdgeDirection;
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};

/// What a marker's turn reads as now.
pub(super) enum TurnInput {
    /// The turn is absent, deleted or archived: nothing is owed.
    Gone,
    /// The turn holds no visible text.
    Empty,
    /// The input the tagger reads, and its digest.
    Ready { input: EncoderInput, hash: String },
}

/// The three MESSAGE-body keys the input needs; every other key is ignored.
#[derive(Deserialize)]
struct MessageText {
    #[serde(default)]
    content: String,
    #[serde(default)]
    is_visible: bool,
    #[serde(default)]
    order: u32,
}

/// Reads the turn's visible, non-empty MESSAGE children in message order.
///
/// The text is the hydrated body, so an edited message reads as edited. A
/// body this build cannot decode is skipped, never guessed at.
pub(super) fn turn_input_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
) -> Result<TurnInput> {
    match live_entity_row_in_txn(&vault.store, txn, turn)? {
        LiveEntityRow::Live { entity_type, .. } if entity_type == ENTITY_TYPE_TURN => {}
        _ => return Ok(TurnInput::Gone),
    }
    if vault.archive_tombstone_in_txn(txn, turn)?.is_some() {
        return Ok(TurnInput::Gone);
    }
    let children = vault.filtered_edge_peers(
        txn,
        EdgeDirection::In,
        turn,
        EdgeKind::PartOf,
        Some(ENTITY_TYPE_MESSAGE),
        "tagging input messages",
    )?;
    let mut rows = Vec::new();
    for id in children {
        if vault.archive_tombstone_in_txn(txn, &id)?.is_some() {
            continue;
        }
        let Some(body) = crate::ports::safe_read_text(vault, txn, &id)? else {
            continue;
        };
        let Ok(message) = rmp_serde::from_slice::<MessageText>(&body) else {
            continue;
        };
        if message.is_visible && !message.content.is_empty() {
            rows.push((message.order, id, message.content));
        }
    }
    if rows.is_empty() {
        return Ok(TurnInput::Empty);
    }
    rows.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.as_bytes().cmp(right.1.as_bytes()))
    });
    let input = EncoderInput {
        turn: turn.to_hex(),
        messages: rows
            .into_iter()
            .map(|(_, id, text)| EncoderMessage {
                id: id.to_hex(),
                text,
            })
            .collect(),
    };
    let hash = input_hash(&input);
    Ok(TurnInput::Ready { input, hash })
}

/// The digest `Memory::witness_with_shadow` stamps on its trace, computed the
/// same way, so a shadow trace and a tagging trace of one input agree.
pub(super) fn input_hash(input: &EncoderInput) -> String {
    let mut hash = Sha256::new();
    hash.update(input.turn.as_bytes());
    for message in &input.messages {
        hash.update(message.id.as_bytes());
        hash.update((message.text.len() as u64).to_le_bytes());
        hash.update(message.text.as_bytes());
    }
    format!("{:x}", hash.finalize())
}
