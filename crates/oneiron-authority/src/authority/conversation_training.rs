//! A person's own "Learn from my conversations" opt-out (FIX 4489, FIX 5502
//! owner rulings, OF-420), and its wire codec.
//!
//! The owner's rulings (10-19): one setting per vault, set by its admin and
//! off until the admin turns it on ([`ConversationTrainingVaultSet`]); while
//! it is on, everything in the vault counts, people, agents and guests
//! alike, and private worlds never do. The admin may also let people opt
//! out. This is that opt-out: one on/off, "leave my messages out", which any
//! live person of the vault, member or guest, sets for themselves from any
//! surface where they are authenticated, on any host. It is never an act on
//! someone else's behalf, and no Grant action names it, so an agent's act
//! never makes it. It counts only while the vault's setting lets people opt
//! out; otherwise it is kept and ignored.
//!
//! The install that served them, a live machine of the vault in any role,
//! signs it with its install key; it carries their act ([`OwnerAct`], kind
//! `conversation_training`, `owner` and `target` both the acting PERSON) and
//! its `seen` is that person's live choices as the deciding surface showed
//! them, under [`CONVERSATION_TRAINING_REVISION_CONTEXT`]. It is a main-log
//! entry, so every machine the owner admits folds it.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

pub const OP_KIND_CONVERSATION_TRAINING: &str = "conversation_training";
const CONVERSATION_TRAINING_KEYS: [&str; 4] = [OP_KEY_KIND, OP_KEY_ACT, "machine", "leave_out"];
/// The same keys with the person's own proof (row
/// PERSON-TRAINING-CHOICE-PERSON-KEY-PROOF): a row whose person signed one
/// carries exactly these five.
const CONVERSATION_TRAINING_KEYS_WITH_PROOF: [&str; 5] = [
    OP_KEY_KIND,
    OP_KEY_ACT,
    "machine",
    "leave_out",
    "person_proof",
];
/// The person's own proof, exactly these two keys.
const PERSON_PROOF_KEYS: [&str; 2] = ["signature", "slip"];
/// The domain of an opt-out act's `seen`, beside the home pick's
/// ([`HOME_PICK_REVISION_CONTEXT`]): BLAKE3 over it and the person's sorted
/// live choice hashes, in the `PolicyRevision` shape.
pub const CONVERSATION_TRAINING_REVISION_CONTEXT: &[u8] =
    b"oneiron/conversation-training-revision/v1";

/// One person's own choice to leave their messages out of training, signed
/// by the install key of `machine`, a live machine of the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationTrainingSet {
    /// The person's own act: `owner` and `target` both name the acting
    /// PERSON, `by` is their own say-so. Its kind is `conversation_training`.
    pub act: OwnerAct,
    /// The carrier: the machine whose install key signed the choice.
    pub machine: EntityId,
    /// Whether the person's own messages are left out.
    pub leave_out: bool,
    /// The person's own proof (row PERSON-TRAINING-CHOICE-PERSON-KEY-PROOF),
    /// `None` when the person signed none.
    pub person_proof: Option<PersonChoiceProof>,
}

impl ConversationTrainingSet {
    pub fn validate(&self) -> Result<()> {
        // The person's own: no Grant action names it, no ask answers it, and
        // nobody makes it for someone else.
        if self.act.act != OwnerActKind::ConversationTraining
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
    let mut fields = vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OP_KIND_CONVERSATION_TRAINING),
        ),
        (
            Value::from(OP_KEY_ACT),
            super::owner_act::owner_act_value(&set.act),
        ),
        (Value::from("machine"), Value::from(set.machine.to_hex())),
        (Value::from("leave_out"), Value::from(set.leave_out)),
    ];
    // The proof rides only when the person signed one, so a choice without
    // one keeps today's bytes exactly: old rows decode and re-encode
    // unchanged, and the stored-change path is "keep".
    if let Some(proof) = &set.person_proof {
        fields.push((
            Value::from("person_proof"),
            Value::Map(vec![
                (
                    Value::from("signature"),
                    Value::Binary(proof.signature.to_vec()),
                ),
                (Value::from("slip"), binary_value(proof.slip)),
            ]),
        ));
    }
    Value::Map(fields)
}

/// A boolean `leave_out`, and the person's own proof when they signed one:
/// exactly the four keys of today, or the five with `person_proof`.
pub(super) fn decode_conversation_training(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    // `validate_keys` takes exact key sets, so the list is picked by whether
    // a `person_proof` key is present.
    let has_proof = entries
        .iter()
        .any(|(key, _)| key.as_str() == Some("person_proof"));
    if has_proof {
        validate_keys(entries, &CONVERSATION_TRAINING_KEYS_WITH_PROOF)?;
    } else {
        validate_keys(entries, &CONVERSATION_TRAINING_KEYS)?;
    }
    Ok(AuthorityOp::ConversationTrainingSet(
        ConversationTrainingSet {
            act: super::owner_act::decode_owner_act(required(entries, OP_KEY_ACT)?)?,
            machine: decode_canonical_id(required(entries, "machine")?)?,
            leave_out: required(entries, "leave_out")?
                .as_bool()
                .ok_or_else(invalid_authority)?,
            person_proof: if has_proof {
                Some(decode_person_proof(required(entries, "person_proof")?)?)
            } else {
                None
            },
        },
    ))
}

/// The person's own proof: exactly the two keys, exact lengths.
fn decode_person_proof(value: &Value) -> Result<PersonChoiceProof> {
    let inner = map_entries(value)?;
    validate_keys(inner, &PERSON_PROOF_KEYS)?;
    let signature: [u8; 64] = match required(inner, "signature")? {
        Value::Binary(bytes) => bytes
            .as_slice()
            .try_into()
            .map_err(|_| invalid_authority())?,
        _ => return Err(invalid_authority()),
    };
    Ok(PersonChoiceProof {
        slip: decode_hash(required(inner, "slip")?)?,
        signature,
    })
}
