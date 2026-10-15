//! A native host's proof shows a live person, not whose vault this is, so an
//! owner door asks for both (F18 tier flip, Engine design (a)). A person-tier
//! door takes a non-owner's proof for that person's own rows only.

use super::*;
use crate::error::{Error, GateError};

fn refused<T: std::fmt::Debug>(result: crate::error::Result<T>) -> bool {
    matches!(
        result,
        Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(_)))
    )
}

/// The vault owner's proof, and a live non-owner person's on the same vault.
fn owner_and_person() -> (
    tempfile::TempDir,
    Vault,
    AuthenticatedOwner,
    AuthenticatedOwner,
) {
    let (dir, vault) = open_test_vault_with(embedding_test_config());
    let owner_id = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault
        .authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let person = crate::test_util::non_owner_proof(&vault);
    (dir, vault, owner, person)
}

/// Sample owner doors in consent, dreamer maintenance and the gate: each
/// refuses a live non-owner person's credential-less proof and takes the
/// owner's.
#[test]
fn a_non_owner_persons_proof_opens_no_owner_door() {
    let (_dir, vault, owner, person) = owner_and_person();
    let now = vault.store.clock.now_recorded_at();
    let cadence = crate::dreamer_runner::maintenance::digest::ProactivityCadence {
        period_secs: 100,
        group_by_facet: true,
        urgent_breakthrough: true,
    };
    let doors: [(
        &str,
        &dyn Fn(&AuthenticatedOwner) -> crate::error::Result<()>,
    ); 4] = [
        ("consent: create_standing_grant", &|proof| {
            vault
                .create_standing_grant(proof, action_bound("agent-a", "send", &["channel:email"]))
                .map(drop)
        }),
        ("dreamer maintenance: set_proactivity_cadence", &|proof| {
            vault.set_proactivity_cadence(proof, &cadence)
        }),
        ("gate: grant_dreamer_weave", &|proof| {
            vault.grant_dreamer_weave(proof, now).map(drop)
        }),
        // Sol r1 P1-2: the shared digest reads every pending proposal and
        // moves the vault's one delivery state.
        ("dreamer maintenance: proactivity_digest", &|proof| {
            vault.proactivity_digest(proof, now, None).map(drop)
        }),
    ];
    let mut failures = Vec::new();
    for (door, call) in doors {
        let decisions = vault.store.gate_decisions(1_000).unwrap().len();
        if !refused(call(&person)) {
            failures.push(format!("{door}: took a non-owner person's proof"));
        } else if vault.store.gate_decisions(1_000).unwrap().len() != decisions {
            failures.push(format!("{door}: refused but left a gate decision"));
        }
        if let Err(error) = call(&owner) {
            failures.push(format!("{door}: refused the owner ({:?})", error.kind()));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// The person tier, over doors a person uses on their own behalf: each takes
/// a live non-owner's proof for that person's own rows, keyed by the proof's
/// actor, and a self-scoped read reaches no other reader's row. Positive
/// control: the owner reads that they own the vault.
#[test]
fn every_person_tier_door_takes_a_non_owner_for_their_own_rows_only() {
    use crate::claim::WeaveDigestReader;
    use crate::policy_model::PolicyNotificationMode;
    let (_dir, vault, owner, person) = owner_and_person();
    let actor = person.actor_for_read(&vault).unwrap();
    let owner_id = owner.actor_for_read(&vault).unwrap();
    let digest = ComposedEffect::new(irreversible_send_facts()).digest();
    let doors: [(&str, &dyn Fn() -> crate::error::Result<()>); 6] = [
        ("consent: deny_consent (their own refusal)", &|| match vault
            .deny_consent(&person, digest)?
        {
            ConsentReceipt::Denied { .. } => Ok(()),
            other => panic!("a refusal receipt, got {other:?}"),
        }),
        ("policy: is_live_vault_owner (false, not an error)", &|| {
            assert!(!vault.is_live_vault_owner(&person)?);
            Ok(())
        }),
        (
            "policy: set_policy_notification_mode (their own key)",
            &|| vault.set_policy_notification_mode(&person, PolicyNotificationMode::Digest),
        ),
        (
            "policy: set_policy_notification_digest_interval (their own key)",
            &|| vault.set_policy_notification_digest_interval(&person, Some(60)),
        ),
        (
            "skill optimize: set_judge_digest_minutes (their own budget)",
            &|| crate::skill_optimize::set_judge_digest_minutes(&vault, &person, 5),
        ),
        (
            "weave digest: weave_digest_schedule (their own person schedule)",
            &|| {
                vault
                    .weave_digest_schedule(&person, WeaveDigestReader::Person(actor))
                    .map(drop)
            },
        ),
    ];
    let mut failures = Vec::new();
    for (door, call) in doors {
        if let Err(error) = call() {
            failures.push(format!("{door}: refused ({:?})", error.kind()));
        }
    }
    for (reader, name) in [
        (
            WeaveDigestReader::Owner(owner_id),
            "the owner role's schedule",
        ),
        (
            WeaveDigestReader::Person(owner_id),
            "another person's schedule",
        ),
    ] {
        if !refused(vault.weave_digest_schedule(&person, reader)) {
            failures.push(format!("weave_digest_schedule read {name}"));
        }
    }
    if !vault.is_live_vault_owner(&owner).unwrap() {
        failures.push("the owner reads that they own nothing".to_owned());
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// A roomless off-record stretch binds no person, so only the vault's owner
/// speaks in it (Sol r1 P1-6): a non-owner's proof naming their own actor
/// witnesses nothing there, and the owner's lands.
#[test]
fn a_non_owner_persons_proof_witnesses_nothing_into_a_roomless_stretch() {
    use crate::memory::{MEMORY_CODE_FORBIDDEN, WitnessAuthor, WitnessMessage, WitnessTurn};
    let (_dir, vault, owner, person) = owner_and_person();
    let session = vault
        .off_record_session_vault()
        .enter(
            "sess-roomless-tier",
            crate::off_record::OffRecordBackendClass::Local,
        )
        .expect("a roomless stretch");
    let turn = WitnessTurn {
        conversation_ref: String::new(),
        turn_ref: None,
        messages: vec![WitnessMessage {
            id: None,
            author: WitnessAuthor::User,
            message_type: "utterance".to_owned(),
            content: "roomless fixture".to_owned(),
            metadata: None,
            is_visible: true,
            order: 0,
        }],
        occurred_at: 1000,
    };
    let speak = |proof: &AuthenticatedOwner| {
        let actor = proof.actor_for_read(&vault).expect("a live proof");
        vault
            .memory(actor, crate::edge::EdgeActorClass::Human)
            .witness_into_session_as(proof, &session, &turn, None)
    };
    let refusal = speak(&person).expect_err("a non-owner spoke in a roomless stretch");
    assert_eq!(refusal.code, MEMORY_CODE_FORBIDDEN, "{refusal:?}");
    speak(&owner).expect("the owner speaks in their own stretch");
}
