//! A person's own "Learn from my conversations" choice (FIX 4489, OF-420),
//! and its wire codec.
//!
//! The owner's ruling: real conversation text for training stays off until
//! the PERSON says yes, the yes can be scoped per world, and private worlds
//! are never included. Each person makes the choice for themselves, from any
//! surface where they are authenticated, on any host; it is never an owner
//! act on someone else's behalf, and no Grant action names it, so an agent's
//! act never makes it. The install that served them, a live machine of the
//! vault in any role, signs the choice with its install key; the choice
//! carries their act ([`OwnerAct`], kind `conversation_training`, `owner` and
//! `target` both the acting PERSON) and its `seen` is that person's live
//! choices as the deciding surface showed them, under
//! [`CONVERSATION_TRAINING_REVISION_CONTEXT`]. It is a main-log entry, so
//! every machine the owner admits folds it.
//!
//! The record is shape only: an explicit, non-empty set of worlds, or none
//! for off. Whether each world may be listed (a live WORLD that reads
//! everywhere) is the writer's rule, and the read judges it again on the
//! fold it reads.

use std::collections::BTreeSet;

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

pub const OP_KIND_CONVERSATION_TRAINING: &str = "conversation_training";
const CONVERSATION_TRAINING_KEYS: [&str; 4] = [OP_KEY_KIND, OP_KEY_ACT, "machine", "worlds"];
/// The domain of a conversation training act's `seen`, beside the home
/// pick's ([`HOME_PICK_REVISION_CONTEXT`]): BLAKE3 over it and the person's
/// sorted live choice hashes, in the `PolicyRevision` shape.
pub const CONVERSATION_TRAINING_REVISION_CONTEXT: &[u8] =
    b"oneiron/conversation-training-revision/v1";

/// One person's choice of the worlds whose conversations may train models,
/// signed by the install key of `machine`, a live machine of the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationTrainingSet {
    /// The person's own act: `owner` and `target` both name the acting
    /// PERSON, `by` is their own say-so. Its kind is `conversation_training`.
    pub act: OwnerAct,
    /// The carrier: the machine whose install key signed the choice.
    pub machine: EntityId,
    /// The worlds the person said yes for, never empty. `None` is off: no
    /// conversation of theirs trains anything.
    pub worlds: Option<BTreeSet<EntityId>>,
}

impl ConversationTrainingSet {
    pub fn validate(&self) -> Result<()> {
        // The person's own: no Grant action names it, no ask answers it, and
        // nobody makes it for someone else. An empty list has one encoding,
        // off.
        if self.worlds.as_ref().is_some_and(BTreeSet::is_empty)
            || self.act.act != OwnerActKind::ConversationTraining
            || self.act.by != ActBy::Owner
            || self.act.answer.is_some()
            || self.act.target != self.act.owner
        {
            return Err(invalid_authority());
        }
        Ok(())
    }

    /// The act names its own person as its target.
    pub fn validate_entry(&self, _entry: &AuthorityLogEntry) -> Result<()> {
        self.act
            .validate_carried(OwnerActKind::ConversationTraining, self.act.owner)
    }
}

pub(super) fn conversation_training_value(set: &ConversationTrainingSet) -> Value {
    let worlds = set.worlds.as_ref().map_or(Value::Nil, |worlds| {
        Value::Array(
            worlds
                .iter()
                .map(|world| Value::from(world.to_hex()))
                .collect(),
        )
    });
    Value::Map(vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OP_KIND_CONVERSATION_TRAINING),
        ),
        (
            Value::from(OP_KEY_ACT),
            super::owner_act::owner_act_value(&set.act),
        ),
        (Value::from("machine"), Value::from(set.machine.to_hex())),
        (Value::from("worlds"), worlds),
    ])
}

/// Nil for off, or a non-empty array of canonical world ids, strictly
/// ascending (so each once), judged before any is collected.
pub(super) fn decode_conversation_training(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    validate_keys(entries, &CONVERSATION_TRAINING_KEYS)?;
    let worlds = match required(entries, "worlds")? {
        Value::Nil => None,
        Value::Array(values) if !values.is_empty() => {
            let ids = values
                .iter()
                .map(decode_canonical_id)
                .collect::<Result<Vec<_>>>()?;
            if ids.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(invalid_authority());
            }
            Some(ids.into_iter().collect())
        }
        _ => return Err(invalid_authority()),
    };
    Ok(AuthorityOp::ConversationTrainingSet(
        ConversationTrainingSet {
            act: super::owner_act::decode_owner_act(required(entries, OP_KEY_ACT)?)?,
            machine: decode_canonical_id(required(entries, "machine")?)?,
            worlds,
        },
    ))
}
