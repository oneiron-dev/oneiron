//! A federation selector window carries no relationship row its member does
//! not read (OPUS-LEAKS round 2, FIX-LIST SELECTOR-RELATIONSHIP-LABELS).
//!
//! A member P holds a live Member federation grant whose Scope admits every
//! record, and a `core:read` policy grant, but no grant on a relationship R
//! and no membership in it. The vault holds three rows labelled R: a MESSAGE
//! whose metadata names R, a CLAIM keyed to R, and a PERSON whose
//! `source_audience` names R (the label a provisional confirm writes). P's
//! own read lane reads none of them, and reads an open CLAIM. The test packs
//! the vault's window and exports it through P's selector: the open CLAIM
//! rides it, and the test asserts no R row does.
//!
//! Each `FIXTURE:` assertion checks the setup, never the leak. The `LEAK:`
//! assertions come last.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test selector_relationship_label`.
// `put_selector_test_federation_grant` exists only under `test-hooks`.
#![cfg(all(oneiron_test_support, feature = "test-hooks"))]

use std::collections::BTreeSet;

use oneiron::edge::EdgeActorClass;
use oneiron::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
};
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP};
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::window::reverse_rematerialize;
use oneiron::sync::{
    SyncSelector, SyncSelectorWorld, WindowKey, authorize_sync_selector, filtered_window_doc,
    put_selector_test_federation_grant,
};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::label_writers::{embedded_owner, open_member_vault};
use oneiron::write_envelope::claim_body::{encode_relationship_scope, relationship_scope_of};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    Vault, VaultConfig,
};
use oneiron_authority::federation::scope_codec::read_preset;
use rmpv::Value;

/// The shared vault the federation grant names.
const SHARED_VAULT_ID: u64 = 7;

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

/// A stated CLAIM about `subject` learned at `now`, keyed to `relationship`
/// when one is named.
fn record(vault: &Vault, subject: EntityId, relationship: Option<EntityId>, now: u64) -> EntityId {
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(subject),
        Value::from("a profile fact"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    body.source = Some(ClaimSource::UserStated);
    body.rel = relationship_scope_of(relationship);
    vault.put_claim(&id, &body, at(now), now).expect("a record");
    id
}

#[test]
fn a_selector_window_carries_no_relationship_row_its_member_does_not_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let member = EntityId::now();
    let vault = open_member_vault(dir.path(), VaultConfig::device(), &[member.to_hex()])
        .expect("fixture vault");
    // Every row is learned now, so all of them pack into one window.
    let now = vault.now_recorded_at();
    let relationship = EntityId::now();
    vault
        .put_entity(
            &relationship,
            ENTITY_TYPE_RELATIONSHIP,
            at(now),
            now,
            b"relationship",
        )
        .expect("a relationship");
    vault
        .put_entity(
            &member,
            ENTITY_TYPE_PERSON,
            at(now),
            now,
            &rmp_serde::to_vec_named(&serde_json::json!({ "name": "member" })).expect("body"),
        )
        .expect("a member outside the relationship");
    let (owner, _proof) = embedded_owner(&vault).expect("the owner");

    let scope = FederationGrantScope::vault(SHARED_VAULT_ID);
    let grant_id = EntityId::now();
    let mut grant = FederationGrant::new(
        scope,
        member,
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
    );
    grant.authority_scope = read_preset();
    put_selector_test_federation_grant(&vault, &grant_id, &grant, now)
        .expect("the member's federation grant");
    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
    authorize_sync_selector(&vault, scope, &selector)
        .expect("FIXTURE: the member's selector is authorized");

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
                content: "We moved the date.".to_owned(),
                parts: None,
                metadata: Some(serde_json::json!({ "rel": relationship.to_hex() })),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: now,
            assertions: WitnessAssertions::default(),
        })
        .expect("the owner's R MESSAGE");
    let open_claim = record(&vault, member, None, now);
    let claim = record(&vault, member, Some(relationship), now);
    // The PERSON body a provisional confirm writes for a name said only in R.
    let person = EntityId::now();
    let mut person_body = Vec::new();
    rmpv::encode::write_value(
        &mut person_body,
        &Value::Map(vec![
            (Value::from("name"), Value::from("Ada")),
            (
                Value::from("source_audience"),
                Value::Map(vec![
                    (
                        Value::from("rel"),
                        encode_relationship_scope(
                            relationship_scope_of(Some(relationship)).as_ref(),
                        ),
                    ),
                    (Value::from("private"), Value::Boolean(false)),
                ]),
            ),
        ]),
    )
    .expect("PERSON body");
    vault
        .put_entity(&person, ENTITY_TYPE_PERSON, at(now), now, &person_body)
        .expect("a PERSON named only in R");

    let reads = |id: EntityId| {
        vault
            .memory(member, EdgeActorClass::Human)
            .get_entity(&id.to_hex())
            .expect("member read")
            .value
            .is_some()
    };
    assert!(
        reads(open_claim),
        "FIXTURE: the member reads the open CLAIM"
    );
    assert!(
        !reads(message) && !reads(claim) && !reads(person),
        "FIXTURE: the member reads none of the R MESSAGE, the R CLAIM and the R PERSON"
    );

    let key = WindowKey::from_timestamp(now);
    let source = create_window_doc("selector", &key);
    reverse_rematerialize(&vault, &source, &key).expect("the window pack");
    for id in [open_claim, message, claim, person] {
        assert!(
            source.get_map("entities").get(&id.to_hex()).is_some(),
            "FIXTURE: the packed window holds {}",
            id.to_hex()
        );
    }
    let selected = filtered_window_doc(&vault, &source, &key, scope, &selector)
        .expect("the member's selector window");
    let mut carried = BTreeSet::new();
    selected.get_map("entities").for_each(|key, _| {
        carried.insert(EntityId::from_hex(key).expect("an entity key"));
    });
    assert!(
        carried.contains(&open_claim),
        "FIXTURE: the selector window carries the open CLAIM"
    );

    let leaked: Vec<&str> = [(message, "MESSAGE"), (claim, "CLAIM"), (person, "PERSON")]
        .into_iter()
        .filter(|(id, _)| carried.contains(id))
        .map(|(_, kind)| kind)
        .collect();
    assert!(
        leaked.is_empty(),
        "LEAK: the selector window carries the R {leaked:?} to a member who does not read R"
    );
}
