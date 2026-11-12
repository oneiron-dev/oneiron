//! Engine-stamped observed preferences from cited user TURNs.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test derive_observed_preference`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::session_lifecycle::{
    SessionClosePredicate, SessionEndWake, SessionKey, SessionMintOutcome,
};
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::{
    Claim, Committed, Named, batches_of, commit_claims, define_auto_agent, grant_derive_rows,
    source_version,
};
use oneiron::test_doors::derive_verbs::lease_run;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault};
use rmpv::Value;
use serde_json::json;

struct ObservedPreferenceFixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    agent: EntityId,
    subject: EntityId,
    session_key: SessionKey,
}

fn observed_preference_fixture() -> ObservedPreferenceFixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), "reader").expect("vault");
    let agent = define_auto_agent(&vault).expect("an Auto agent");
    grant_derive_rows(&vault, &[agent]).expect("the agent's policy rows");
    let subject = EntityId::now();
    let now = vault.now_recorded_at();
    vault
        .put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            b"owen",
        )
        .expect("a subject");
    let session_key = vault.local_session_key(subject).expect("a session key");
    ObservedPreferenceFixture {
        _dir: dir,
        vault,
        agent,
        subject,
        session_key,
    }
}

fn witness_preference_turn(
    fixture: &ObservedPreferenceFixture,
    author: WitnessAuthor,
    words: &str,
) -> EntityId {
    let turn = EntityId::now();
    let receipt = fixture
        .vault
        .memory(fixture.subject, EdgeActorClass::Human)
        .with_session(fixture.session_key)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(EntityId::now().to_hex()),
                author,
                message_type: "dialogue".to_owned(),
                content: words.to_owned(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: fixture.vault.now_recorded_at(),
            assertions: WitnessAssertions::default(),
        })
        .expect("a witnessed TURN");
    assert_eq!(receipt.turn_id, turn);
    turn
}

fn preference_evidence(
    fixture: &ObservedPreferenceFixture,
    split_sessions: bool,
    third_author: WitnessAuthor,
) -> Vec<EntityId> {
    let now = fixture.vault.now_recorded_at();
    let SessionMintOutcome::Minted(first_session) = fixture
        .vault
        .mint_session(fixture.session_key, now)
        .expect("the first session opens")
    else {
        panic!("the fixture has no open session");
    };
    let first = witness_preference_turn(fixture, WitnessAuthor::User, "I choose green tea.");
    let second = witness_preference_turn(fixture, WitnessAuthor::User, "Green tea again.");
    if split_sessions {
        fixture
            .vault
            .end_session_with_wake(
                &first_session,
                SessionClosePredicate::Explicit,
                fixture.vault.now_recorded_at(),
                &SessionEndWake::none(first_session, 0),
            )
            .expect("the first session closes")
            .expect("the session was open");
        let SessionMintOutcome::Minted(second_session) = fixture
            .vault
            .mint_session(fixture.session_key, fixture.vault.now_recorded_at())
            .expect("the second session opens")
        else {
            panic!("the first session was closed");
        };
        assert_ne!(first_session, second_session);
    }
    let third = witness_preference_turn(fixture, third_author, "Green tea this time too.");
    vec![first, second, third]
}

fn derive_preference_item(
    fixture: &ObservedPreferenceFixture,
    predicate: &'static str,
    evidence: &[EntityId],
) -> (Committed, EntityId) {
    let committed = commit_claims(
        &fixture.vault,
        fixture.agent,
        EdgeActorClass::Agent,
        "run-observed-preference",
        &[Claim {
            local: "drink",
            predicate,
            subject: Named::Stored(fixture.subject),
            value: json!("green tea"),
            evidence: evidence.iter().copied().map(Named::Stored).collect(),
        }],
    )
    .expect("the batch commits");
    let [item] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    assert!(item.landed, "the claim lands: {:?}", item.reasons);
    assert_eq!(item.approval.as_deref(), Some("auto"));
    let [claim] = item.rows.as_slice() else {
        panic!("one claim row: {:?}", item.rows);
    };
    let claim = *claim;
    (committed, claim)
}

fn standing_stated_preference(fixture: &ObservedPreferenceFixture, answer: &str) -> EntityId {
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        "preference.drink",
        ClaimSubject::Entity(fixture.subject),
        Value::from(answer),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("a stated claim body");
    body.source = Some(ClaimSource::UserStated);
    body.scope_facet = fixture.vault.default_facet().expect("the vault facet");
    let now = fixture.vault.now_recorded_at();
    fixture
        .vault
        .put_claim(
            &id,
            &body,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .expect("a standing stated preference");
    id
}

fn subject_conflict_markers(fixture: &ObservedPreferenceFixture) -> Vec<ClaimBody> {
    fixture
        .vault
        .claims_for_subject(&fixture.subject)
        .expect("the subject's claims")
        .into_iter()
        .map(|id| {
            fixture
                .vault
                .get_claim(&id)
                .expect("read")
                .expect("a claim")
        })
        .filter(|body| body.predicate == "core.conflict.open")
        .collect()
}

fn assert_preference_pair_active(
    fixture: &ObservedPreferenceFixture,
    observed: EntityId,
    stated: EntityId,
) {
    let observed = fixture
        .vault
        .get_claim(&observed)
        .expect("read")
        .expect("the derived claim");
    let stated = fixture
        .vault
        .get_claim(&stated)
        .expect("read")
        .expect("the stated claim");
    assert_eq!(observed.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(stated.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(stated.source, Some(ClaimSource::UserStated));
    assert_eq!(stated.approval, ClaimApprovalStatus::Auto);
    assert_eq!(observed.subject, stated.subject);
    assert_eq!(observed.predicate, stated.predicate);
    assert_eq!(observed.world, stated.world);
    assert_eq!(observed.rel, stated.rel);
    assert_eq!(observed.scope, stated.scope);
    assert_eq!(observed.scope_facet, stated.scope_facet);
    assert_eq!(observed.scope_project, stated.scope_project);
}

#[test]
fn three_user_turns_in_two_sessions_land_an_observed_preference() {
    let fixture = observed_preference_fixture();
    let evidence = preference_evidence(&fixture, true, WitnessAuthor::User);
    let (_, claim) = derive_preference_item(&fixture, "preference.drink", &evidence);
    assert_eq!(
        fixture
            .vault
            .get_claim(&claim)
            .expect("read")
            .expect("the claim")
            .source,
        Some(ClaimSource::Observed)
    );
}

#[test]
fn three_user_turns_in_one_session_land_a_generated_preference() {
    let fixture = observed_preference_fixture();
    let evidence = preference_evidence(&fixture, false, WitnessAuthor::User);
    let (_, claim) = derive_preference_item(&fixture, "preference.drink", &evidence);
    assert_eq!(
        fixture
            .vault
            .get_claim(&claim)
            .expect("read")
            .expect("the claim")
            .source,
        Some(ClaimSource::Generated)
    );
}

#[test]
fn an_assistant_turn_does_not_count_toward_the_bar() {
    let fixture = observed_preference_fixture();
    let evidence = preference_evidence(&fixture, true, WitnessAuthor::Companion);
    let (_, claim) = derive_preference_item(&fixture, "preference.drink", &evidence);
    assert_eq!(
        fixture
            .vault
            .get_claim(&claim)
            .expect("read")
            .expect("the claim")
            .source,
        Some(ClaimSource::Generated)
    );
}

#[test]
fn a_claim_that_is_no_preference_stays_generated() {
    let fixture = observed_preference_fixture();
    let evidence = preference_evidence(&fixture, true, WitnessAuthor::User);
    let (_, claim) = derive_preference_item(&fixture, "profile.drink", &evidence);
    assert_eq!(
        fixture
            .vault
            .get_claim(&claim)
            .expect("read")
            .expect("the claim")
            .source,
        Some(ClaimSource::Generated)
    );
}

#[test]
fn a_preference_item_naming_its_own_source_is_refused() {
    let fixture = observed_preference_fixture();
    let run = lease_run(&fixture.vault, fixture.agent).expect("the agent's live run");
    let evidence = preference_evidence(&fixture, true, WitnessAuthor::User);
    let sources: Vec<_> = evidence
        .iter()
        .map(|id| {
            source_version(&fixture.vault, fixture.agent, EdgeActorClass::Agent, *id)
                .expect("read")
                .expect("the agent reads the TURN")
        })
        .collect();
    let request = json!({
        "items": [{
            "kind": "claim",
            "spec": {
                "local": "drink",
                "predicate": "preference.drink",
                "subject": {"stored": fixture.subject},
                "value": "green tea",
                "confidence": 0.9,
                "evidence": evidence.iter().map(|id| json!({"stored": id})).collect::<Vec<_>>(),
                "source": "observed",
            },
        }],
        "sources": sources,
    });
    let refusal = run
        .commit(&fixture.vault, request)
        .expect_err("a caller cannot set the source");
    assert_eq!(refusal.code, MEMORY_CODE_BAD_REQUEST);
    assert!(
        batches_of(&fixture.vault, fixture.agent)
            .expect("read")
            .is_empty()
    );
    assert!(
        fixture
            .vault
            .claims_for_subject(&fixture.subject)
            .expect("read")
            .is_empty()
    );
}

#[test]
fn an_observed_preference_beside_a_differing_stated_one_opens_one_conflict() {
    let fixture = observed_preference_fixture();
    let stated = standing_stated_preference(&fixture, "black coffee");
    let evidence = preference_evidence(&fixture, true, WitnessAuthor::User);
    let (_, observed) = derive_preference_item(&fixture, "preference.drink", &evidence);
    assert_preference_pair_active(&fixture, observed, stated);
    let markers = subject_conflict_markers(&fixture);
    assert_eq!(markers.len(), 1, "one conflict names the differing pair");
    let marker = &markers[0];
    assert_eq!(marker.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(marker.approval, ClaimApprovalStatus::Proposed);
    let Some(Value::Map(evidence)) = &marker.evidence else {
        panic!("the marker has envelope evidence");
    };
    let candidate_evidence = evidence
        .iter()
        .find(|(key, _)| key.as_str() == Some("candidate_evidence"))
        .map(|(_, value)| value)
        .expect("the marker's candidate evidence");
    assert_eq!(
        candidate_evidence,
        &Value::Map(vec![(
            Value::from("refs"),
            Value::Array(vec![
                Value::Binary(observed.as_bytes().to_vec()),
                Value::Binary(stated.as_bytes().to_vec()),
            ]),
        )])
    );
    assert_eq!(
        fixture
            .vault
            .get_claim(&observed)
            .expect("read")
            .expect("the claim")
            .source,
        Some(ClaimSource::Observed)
    );
}

#[test]
fn an_observed_preference_agreeing_with_the_stated_one_opens_no_conflict() {
    let fixture = observed_preference_fixture();
    let stated = standing_stated_preference(&fixture, "  GREEN   Tea  ");
    let evidence = preference_evidence(&fixture, true, WitnessAuthor::User);
    let (_, observed) = derive_preference_item(&fixture, "preference.drink", &evidence);
    assert_preference_pair_active(&fixture, observed, stated);
    assert!(subject_conflict_markers(&fixture).is_empty());
}
