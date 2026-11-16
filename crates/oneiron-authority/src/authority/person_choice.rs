//! A person's own proof of their conversation-training choice (row
//! PERSON-TRAINING-CHOICE-PERSON-KEY-PROOF).
//!
//! A person who is not the vault owner proves their own opt back in with the
//! binding key K of one of their own live human slips. K's secret lives only
//! on their device. The client signs the fixed statement
//! ([`conversation_training_statement`]) before the request; the statement
//! needs no parents, seq or ts. The statement's `seen` is the act's `seen`.
//! The proof rides in the op, and every replica judges it from the entry's
//! parent state alone (`oneiron::authority::person_proof`).

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

/// The domain of a person's own choice statement, NUL-terminated as the
/// statement domains are.
pub const PERSON_CHOICE_DOMAIN: &[u8] = b"oneiron/person-choice/v1\0";

/// The person's own proof: the slip whose binding key signed, and its
/// signature over the statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonChoiceProof {
    /// The person's own live human slip whose binding key signed.
    pub slip: [u8; 32],
    /// That key's strict Ed25519 signature over
    /// [`conversation_training_statement`].
    pub signature: [u8; 64],
}

/// The statement K signs for a conversation-training choice: the domain,
/// then the canonical encoding (the same encoder [`authority_transcript`]
/// uses) of one map with these keys in sorted order: `kind`, `leave_out`,
/// `person`, `seen`, `slip`, `vault_id`. The person rides as their canonical
/// hex string, as the op writes ids; the 32-byte values ride as binaries, as
/// the op codec writes `seen`.
pub fn conversation_training_statement(
    vault_id: &[u8; 32],
    person: EntityId,
    leave_out: bool,
    seen: [u8; 32],
    slip: [u8; 32],
) -> Result<Vec<u8>> {
    let body = encode_value(&Value::Map(vec![
        (Value::from("kind"), Value::from("conversation_training")),
        (Value::from("leave_out"), Value::from(leave_out)),
        (Value::from("person"), Value::from(person.to_hex())),
        (Value::from("seen"), binary_value(seen)),
        (Value::from("slip"), binary_value(slip)),
        (Value::from("vault_id"), binary_value(*vault_id)),
    ]))?;
    let mut statement = Vec::with_capacity(PERSON_CHOICE_DOMAIN.len() + body.len());
    statement.extend_from_slice(PERSON_CHOICE_DOMAIN);
    statement.extend_from_slice(&body);
    Ok(statement)
}
