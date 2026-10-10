//! The engine's receipt for one organ call: facts the host computed, plus
//! the organ's bounded notes.

use oneiron_organ_protocol::{Hash32, Locator, Loss, Notes, OrganIdentity, ProtocolVersion};
use serde::{Deserialize, Serialize};

use crate::spec::CallClass;

const MAX_NOTES: usize = 64;
const MAX_NOTE_BYTES: usize = 256;
const MAX_CODE_BYTES: usize = 64;

/// What one call read, made and took. Recall and the Dreamer read it as a
/// typed record; a landing writes it into the version's `made_by` envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallReceipt {
    pub organ: OrganIdentity,
    pub protocol: ProtocolVersion,
    pub verb: String,
    pub schema: u32,
    /// blake3 of the call's args, as MessagePack.
    pub args_digest: Hash32,
    pub inputs: Vec<ReceiptInput>,
    /// blake3 of the base body, as MessagePack.
    pub base_body: Option<Hash32>,
    pub result_body: Option<Hash32>,
    pub outputs: Vec<ReceiptOutput>,
    /// The organ's word, bounded: 64 entries of each kind, 256 bytes each.
    pub notes: Notes,
    pub class: CallClass,
    pub grant: String,
    /// Waiting for the budget and the inputs.
    pub queue_us: u64,
    /// From sending the call to its verified reply.
    pub run_us: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptInput {
    /// The artifact id, hex.
    pub artifact: String,
    pub version: u64,
    pub content_hash: Hash32,
    pub len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptOutput {
    pub name: String,
    pub media_type: String,
    pub content_hash: Hash32,
    pub len: u64,
}

pub(crate) fn bound_text(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// Caps an organ's notes so a hostile organ cannot grow a receipt.
pub(crate) fn bound_notes(notes: Notes) -> Notes {
    Notes {
        touched: notes
            .touched
            .into_iter()
            .filter(|locator| encoded_len(locator) <= MAX_NOTE_BYTES)
            .take(MAX_NOTES)
            .collect(),
        warnings: notes
            .warnings
            .iter()
            .take(MAX_NOTES)
            .map(|warning| bound_text(warning, MAX_NOTE_BYTES))
            .collect(),
        losses: notes
            .losses
            .iter()
            .take(MAX_NOTES)
            .map(|loss| Loss {
                code: bound_text(&loss.code, MAX_CODE_BYTES),
                detail: bound_text(&loss.detail, MAX_NOTE_BYTES),
            })
            .collect(),
    }
}

fn encoded_len(locator: &Locator) -> usize {
    rmp_serde::to_vec_named(locator).map_or(usize::MAX, |bytes| bytes.len())
}

/// blake3 of a value's MessagePack encoding.
pub(crate) fn digest<T: Serialize>(value: &T) -> Hash32 {
    rmp_serde::to_vec_named(value).map_or_else(|_| Hash32([0; 32]), |bytes| Hash32::of(&bytes))
}
