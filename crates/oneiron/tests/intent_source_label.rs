//! The owner's stated intent keeps the audience of the MESSAGE its words came
//! from (OPUS-LEAKS, lead call G "leaks today").
//!
//! The owner says "I'll ..." in a MESSAGE scoped to a relationship R, then
//! states it as his intent at `/v1/owner/intents`
//! ([`oneiron::Vault::record_owner_intent`]), citing that MESSAGE, as the
//! writer's contract asks ("his exact words ... citing the MESSAGE the words
//! came from"). A member outside R reads neither the MESSAGE nor the intent.
//! The second test gives that member a live grant on R's CLAIMs, not on its
//! MESSAGEs (review round 2 of #6969): the intent quotes the MESSAGE, so the
//! member still reads neither.
//!
//! Each `FIXTURE:` assertion checks the setup, never the leak. The last
//! assertion is the leak check.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test intent_source_label`.
#![cfg(oneiron_test_support)]

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::edge::EdgeActorClass;
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::label_writers::{embedded_owner, open_member_vault};
use oneiron::{EntityId, VaultConfig};
use oneiron_authority::federation::scope_codec::read_preset;

const WORDS: &str = "I'll call the lawyer about the lease tomorrow.";

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

/// Runs the fixture, with the member outside R holding a live grant on R's
/// CLAIMs when `claims_grant`, and returns whether it reads the intent
/// quoting the R MESSAGE (with that intent's `rel`, for the message).
fn outsider_reads_the_intent(claims_grant: bool) -> (bool, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let outsider = EntityId::now();
    let vault = open_member_vault(dir.path(), VaultConfig::device(), &[outsider.to_hex()])
        .expect("fixture vault");
    let relationship = EntityId::now();
    vault
        .put_entity(
            &relationship,
            ENTITY_TYPE_RELATIONSHIP,
            at(1),
            1,
            b"relationship",
        )
        .expect("a relationship");
    vault
        .put_entity(&outsider, ENTITY_TYPE_PERSON, at(1), 1, b"outsider")
        .expect("a member outside the relationship");
    if claims_grant {
        vault
            .create_access_grant(
                &EntityId::now(),
                &AccessGrant {
                    principal_ref: outsider,
                    scope: AccessGrantScope::RelationshipClaims {
                        space_ref: relationship,
                    },
                    capability: AccessGrantCapability::RelationshipClaimsRead,
                    status: AccessGrantStatus::Active,
                    created_at: 1,
                    revoked_at: None,
                    expires_at: None,
                    authority_scope: read_preset(),
                    companion_bounds: None,
                },
            )
            .expect("the outsider's grant on R's CLAIMs");
    }
    let (owner, proof) = embedded_owner(&vault).expect("the owner");

    let message = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: Some(EntityId::now().to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: WORDS.to_owned(),
                parts: None,
                metadata: Some(serde_json::json!({"rel": relationship.to_hex()})),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: 10,
            assertions: WitnessAssertions::default(),
        })
        .expect("the owner's turn");

    // The member's own lane: its grants, as every Memory read verb opens it.
    let reads = |id: EntityId| {
        vault
            .memory(outsider, EdgeActorClass::Human)
            .get_entity(&id.to_hex())
            .expect("outsider read")
            .value
            .is_some()
    };
    assert!(
        !reads(message),
        "FIXTURE: the outsider does not read the R MESSAGE"
    );

    let intent = vault
        .record_owner_intent(&proof, WORDS, None, Some(message))
        .expect("the owner states his intent");
    let body = vault
        .get_claim(&intent)
        .expect("claim read")
        .expect("FIXTURE: the intent landed");
    assert_eq!(
        body.predicate, "profile.intent",
        "FIXTURE: the intent claim"
    );
    // The same writer, citing no MESSAGE: the outsider reads it, so a
    // withheld intent is withheld for its source, not for its shape.
    let open_intent = vault
        .record_owner_intent(&proof, "I will water the plants.", None, None)
        .expect("an intent citing no MESSAGE");
    assert!(
        reads(open_intent),
        "FIXTURE: the outsider reads an intent citing no MESSAGE"
    );

    (reads(intent), format!("{:?}", body.rel))
}

#[test]
fn an_intent_from_a_relationship_message_is_not_read_outside_the_relationship() {
    let (read, rel) = outsider_reads_the_intent(false);
    assert!(
        !read,
        "LEAK: a member outside R reads the intent quoting the R MESSAGE (rel {rel})"
    );
}

/// Review round 2 of #6969: a grant on R's CLAIMs admits a CLAIM scoped to R,
/// never R's MESSAGEs; the intent carries the MESSAGE's words, so it reads
/// only where the MESSAGE does.
#[test]
fn an_intent_from_a_relationship_message_is_not_read_on_a_grant_to_the_relationships_claims() {
    let (read, rel) = outsider_reads_the_intent(true);
    assert!(
        !read,
        "LEAK: a member holding only a grant on R's CLAIMs reads the intent quoting the R MESSAGE (rel {rel})"
    );
}
