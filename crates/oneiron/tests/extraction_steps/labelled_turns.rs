//! Shared helpers for lent step tests over words that carry a relationship label: witnessing
//! labelled MESSAGEs, storing relationships, and granting the Dreamer the MESSAGEs of one.
//!
//! The recipe is the one of `tests/extraction_operand_relationship_bound.rs`.

use std::collections::BTreeSet;

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::extraction_inputs::ExtractionConversation;
use oneiron::test_doors::steward::dreamer;
use oneiron::{EdgeActorClass, EntityId, Vault};
use serde_json::Value;

/// Returns a fixture error without hiding its source.
pub(crate) type LabelledTurnsResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Witnesses each `(words, metadata)` pair as one visible user MESSAGE into its own TURN of one
/// fresh conversation, each spoken by a fresh person. A MESSAGE whose metadata is `None`
/// carries no relationship label.
pub(crate) fn witness_labelled_turns(
    vault: &Vault,
    labelled: &[(&str, Option<Value>)],
) -> LabelledTurnsResult<ExtractionConversation> {
    let conversation = EntityId::now();
    let mut turns = Vec::with_capacity(labelled.len());
    let mut messages = Vec::with_capacity(labelled.len());
    for (index, (words, metadata)) in labelled.iter().enumerate() {
        let speaker = EntityId::now();
        vault.put_entity(
            &speaker,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"witness",
        )?;
        let turn = EntityId::now();
        let message = EntityId::now();
        vault
            .memory(speaker, EdgeActorClass::Human)
            .witness(&WitnessTurn {
                conversation_ref: conversation.to_hex(),
                turn_ref: Some(turn.to_hex()),
                thread_audience: None,
                project: None,
                messages: vec![WitnessMessage {
                    id: Some(message.to_hex()),
                    author: WitnessAuthor::User,
                    message_type: "dialogue".to_owned(),
                    content: (*words).to_owned(),
                    parts: None,
                    metadata: metadata.clone(),
                    is_visible: true,
                    order: 0,
                    quote: None,
                }],
                occurred_at: 10 + index as u64,
                assertions: WitnessAssertions::default(),
            })?;
        turns.push(turn);
        messages.push(message);
    }
    Ok(ExtractionConversation {
        conversation,
        turns,
        messages,
    })
}

/// Stores one relationship entity.
pub(crate) fn store_relationship(vault: &Vault) -> LabelledTurnsResult<EntityId> {
    let relationship = EntityId::now();
    vault.put_entity(
        &relationship,
        ENTITY_TYPE_RELATIONSHIP,
        TimeRange { start: 1, end: 1 },
        1,
        b"relationship",
    )?;
    Ok(relationship)
}

/// Grants the Dreamer a live `MessagesRead` grant on `relationship`, so its TURN reader
/// serves the MESSAGEs that carry that label.
pub(crate) fn grant_relationship_messages(
    vault: &Vault,
    relationship: EntityId,
) -> LabelledTurnsResult<()> {
    let actor = dreamer(vault)?;
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    vault.create_access_grant(
        &EntityId::now(),
        &AccessGrant {
            authority_scope,
            principal_ref: actor,
            scope: AccessGrantScope::Messages {
                space_ref: relationship,
            },
            capability: AccessGrantCapability::MessagesRead,
            status: AccessGrantStatus::Active,
            created_at: vault.now_recorded_at(),
            revoked_at: None,
            expires_at: None,
            companion_bounds: None,
        },
    )?;
    Ok(())
}
