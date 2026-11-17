//! The owner's stated intent stands where the MESSAGE its words came from
//! stands: in that MESSAGE's project (FIX INTENT-DISTINCT-PROJECT-WORLD;
//! ONE-1592 P3, ARCH-0022 #task-facet-not-built: "a claim takes the most
//! restrictive exposure of its source turns").
//!
//! The owner says "I'll ..." in a MESSAGE of a TURN the leader-chat door
//! settled into a project P, then states it as his intent at
//! `/v1/owner/intents` ([`oneiron::Vault::record_owner_intent`]), citing that
//! MESSAGE. The intent must be born in P, so a door that reads only the
//! default project (a selector window, a project-bound Grant) does not read
//! the words through it. Before the fix it landed in the default project.
//!
//! The second test quotes a MESSAGE that names no relationship and is not
//! private, which a member reads only through a grant on its conversation
//! (review round 2 of #6971). A CLAIM carries no such grant, so the intent
//! must be private, as the distinct fact an identity answer derives from the
//! same MESSAGE is. Before the fix a member with no grant read the intent.
//!
//! Each `FIXTURE:` assertion checks the setup, never the fix. The last
//! assertion is the check.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test intent_source_position`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::edge::EdgeActorClass;
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::derivation_position::settle_into_project;
use oneiron::test_doors::label_writers::{embedded_owner, open_member_vault};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_authority::federation::{ScopeAxis, ScopeId};

const WORDS: &str = "I'll send the budget to the board on Friday.";

/// Witnesses `words` as the owner's one MESSAGE in a fresh TURN;
/// `(turn, message)`.
fn witness_owner_words(vault: &Vault, owner: EntityId, words: &str) -> (EntityId, EntityId) {
    let turn = EntityId::now();
    let message = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: words.to_owned(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: 10,
            assertions: WitnessAssertions::default(),
        })
        .expect("the owner's turn");
    (turn, message)
}

/// The one project the stored claim `claim` is read at, as every scoped door
/// judges it ([`Vault::record_scope`]), and the project its body is stamped
/// with.
fn claim_projects(vault: &Vault, claim: &EntityId) -> (Option<EntityId>, EntityId) {
    let read = match vault
        .record_scope(claim)
        .expect("record scope read")
        .expect("FIXTURE: the claim has a read position")
        .audience
    {
        ScopeAxis::Some(projects) if projects.len() == 1 => {
            projects.first().map(|ScopeId(project)| *project)
        }
        _ => None,
    };
    let stamped = vault
        .get_claim(claim)
        .expect("claim read")
        .expect("FIXTURE: the claim landed")
        .scope_project;
    (read, stamped)
}

#[test]
fn an_intent_from_a_project_message_stands_in_that_project() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_member_vault(dir.path(), VaultConfig::device(), &[]).expect("fixture vault");
    let (owner, proof) = embedded_owner(&vault).expect("the owner");
    let default_project = oneiron::claim::default_project_id();

    // The same writer over a MESSAGE of the default project: the intent
    // lands there, so an intent elsewhere is placed for its source.
    let (_, open_message) = witness_owner_words(&vault, owner, "I will water the plants.");
    let open_intent = vault
        .record_owner_intent(&proof, "I will water the plants.", None, Some(open_message))
        .expect("an intent citing a default-project MESSAGE");
    assert_eq!(
        claim_projects(&vault, &open_intent),
        (Some(default_project), default_project),
        "FIXTURE: an intent citing a default-project MESSAGE stands in the default project"
    );

    let project = EntityId::now();
    let (turn, message) = witness_owner_words(&vault, owner, WORDS);
    settle_into_project(&vault, &[turn, message], project).expect("the turn settles into P");
    let message_projects = match vault
        .record_scope(&message)
        .expect("record scope read")
        .expect("FIXTURE: the MESSAGE has a read position")
        .audience
    {
        ScopeAxis::Some(projects) => projects,
        _ => BTreeSet::new(),
    };
    assert_eq!(
        message_projects,
        BTreeSet::from([ScopeId(project)]),
        "FIXTURE: the MESSAGE is read in P"
    );

    let intent = vault
        .record_owner_intent(&proof, WORDS, None, Some(message))
        .expect("the owner states his intent");
    let (read, stamped) = claim_projects(&vault, &intent);
    assert_eq!(
        (read, stamped),
        (Some(project), project),
        "LEAK: the intent quoting a MESSAGE of project P is read in {read:?} (stamped {stamped:?}), not P"
    );
}

#[test]
fn an_intent_from_a_message_naming_no_relationship_is_not_read_without_a_grant_on_its_conversation()
{
    let dir = tempfile::tempdir().expect("tempdir");
    let outsider = EntityId::now();
    let vault = open_member_vault(dir.path(), VaultConfig::device(), &[outsider.to_hex()])
        .expect("fixture vault");
    vault
        .put_entity(
            &outsider,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"outsider",
        )
        .expect("a member with no grant on the conversation");
    let (owner, proof) = embedded_owner(&vault).expect("the owner");
    let reads = |id: EntityId| {
        vault
            .memory(outsider, EdgeActorClass::Human)
            .get_entity(&id.to_hex())
            .expect("outsider read")
            .value
            .is_some()
    };

    let (_, message) = witness_owner_words(&vault, owner, WORDS);
    assert!(
        !reads(message),
        "FIXTURE: the member does not read a MESSAGE of a conversation it holds no grant on"
    );
    // The same writer, citing no MESSAGE: the member reads it, so a withheld
    // intent is withheld for its source, not for its shape.
    let open_intent = vault
        .record_owner_intent(&proof, "I will water the plants.", None, None)
        .expect("an intent citing no MESSAGE");
    assert!(
        reads(open_intent),
        "FIXTURE: the member reads an intent citing no MESSAGE"
    );

    let intent = vault
        .record_owner_intent(&proof, WORDS, None, Some(message))
        .expect("the owner states his intent");
    assert!(
        !reads(intent),
        "LEAK: a member with no grant on the conversation reads the intent quoting its MESSAGE"
    );
}
