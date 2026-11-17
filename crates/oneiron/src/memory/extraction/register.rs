//! The turns an input carries beside its own, in conversation order
//! (FIX 9520, 10167): earlier context, and for the conversation register
//! every later turn too. Spans still index the input's own messages; a
//! context link names one of these turns by id.

use oneiron_contracts::fingerprint::LegacyDigest;

use super::types::{EncoderInput, EncoderMessage, EncoderRegister, EncoderTurn, SpeakerRole};

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
    hash: &mut LegacyDigest,
    input: &EncoderInput,
    message: impl Fn(&mut LegacyDigest, &EncoderMessage),
) {
    if input.register.is_live() {
        return;
    }
    hash.raw(b"\0register").len_u64_le(input.following.len());
    for turn in &input.following {
        hash.raw(turn.turn.as_bytes())
            .len_u64_le(turn.messages.len());
        for each in &turn.messages {
            message(hash, each);
        }
    }
    hash.raw(b"\0following-speaker");
    for turn in &input.following {
        hash.raw(match turn.speaker {
            None => b"-",
            Some(SpeakerRole::User) => b"A",
            Some(SpeakerRole::Companion) => b"B",
        });
    }
    // Where the register stops short (FIX 10705); one read whole folds
    // nothing more, so it digests as it did before the record existed.
    if let EncoderRegister::Conversation(reach) = input.register
        && !reach.is_whole()
    {
        hash.raw(b"\0reach")
            .raw(&[u8::from(reach.earlier_cut), u8::from(reach.later_cut)]);
    }
}
