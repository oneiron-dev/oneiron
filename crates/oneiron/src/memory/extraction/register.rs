//! The turns an input carries beside its own, in conversation order
//! (FIX 9520, 10167): earlier context, and for the conversation register
//! every later turn too. Spans still index the input's own messages; a
//! context link names one of these turns by id.

use sha2::{Digest, Sha256};

use super::types::{EncoderInput, EncoderMessage, EncoderTurn, SpeakerRole};

/// The turn `turn` among those `input` carries beside its own: an earlier
/// one, or a later one of its conversation register.
pub(crate) fn register_turn<'a>(input: &'a EncoderInput, turn: &str) -> Option<&'a EncoderTurn> {
    input
        .context
        .iter()
        .chain(&input.following)
        .find(|each| each.turn == turn)
}

/// Folds what only a conversation register carries into an input's digest,
/// after everything a live input folds: its later turns, then their roles.
/// A live input folds nothing here, so it digests as it did before the
/// register existed.
pub(super) fn fold_register(
    hash: &mut Sha256,
    input: &EncoderInput,
    message: impl Fn(&mut Sha256, &EncoderMessage),
) {
    if input.register.is_live() {
        return;
    }
    hash.update(b"\0register");
    hash.update((input.following.len() as u64).to_le_bytes());
    for turn in &input.following {
        hash.update(turn.turn.as_bytes());
        hash.update((turn.messages.len() as u64).to_le_bytes());
        for each in &turn.messages {
            message(hash, each);
        }
    }
    hash.update(b"\0following-speaker");
    for turn in &input.following {
        hash.update(match turn.speaker {
            None => b"-",
            Some(SpeakerRole::User) => b"A",
            Some(SpeakerRole::Companion) => b"B",
        });
    }
}
