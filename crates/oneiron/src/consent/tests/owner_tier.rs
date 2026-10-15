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

/// A merge source stops being a live PERSON, so merging the vault owner away
/// would leave a personal vault with no owner: the merge door refuses it and
/// changes nothing. The other way the owner survives the merge and still
/// opens owner doors (Engine ruling Q2).
#[test]
fn a_merge_never_retires_the_vault_owner_and_the_owner_survives_one() {
    use crate::error::SyncError;
    use crate::identity_topology::{
        IdentityOpEvidence, IdentityOpWrite, IdentityTopologyOp, IdentityTopologyRejection,
        MergeOp, SurvivorshipPlan,
    };
    let (_dir, vault, owner, person) = owner_and_person();
    let duplicate = person.actor_for_read(&vault).unwrap();
    let merge = |sources: Vec<crate::EntityId>, survivor: crate::EntityId| {
        vault.apply_identity_topology_op(
            &IdentityTopologyOp::Merge(MergeOp {
                sources,
                survivor,
                evidence: IdentityOpEvidence {
                    refs: Vec::new(),
                    rationale: "a duplicate of the owner".into(),
                },
                survivorship_plan: SurvivorshipPlan::ReadThrough,
            }),
            &IdentityOpWrite::auto(crate::claim::ClaimSource::Inferred).with_actor(
                crate::WriteActor::new(owner.actor(), crate::edge::EdgeActorClass::Human),
            ),
            200,
        )
    };
    let decisions = vault.store.gate_decisions(1_000).unwrap().len();
    let refused = merge(vec![owner.actor()], duplicate);
    assert!(
        matches!(
            refused,
            Err(Error::Sync(SyncError::IdentityTopologyRejected(
                IdentityTopologyRejection::OwnerMergedAway { owner: named }
            ))) if named == owner.actor()
        ),
        "{refused:?}"
    );
    // Nothing changed: the owner still owns the vault and the duplicate is
    // still a live person who owns nothing.
    assert!(vault.is_live_vault_owner(&owner).unwrap());
    assert!(!vault.is_live_vault_owner(&person).unwrap());
    assert_eq!(vault.store.gate_decisions(1_000).unwrap().len(), decisions);
    merge(vec![duplicate], owner.actor()).expect("the owner survives the merge");
    assert!(
        vault.is_live_vault_owner(&person).is_err(),
        "the duplicate was merged away"
    );
    vault
        .create_standing_grant(&owner, action_bound("agent-a", "send", &["channel:email"]))
        .expect("the owner still opens owner doors");
}

/// The owner-retirement rule holds wherever topology history lands, not only
/// at the local merge door (Sol r2 P1-1, P2-1): a split of the owner is
/// refused locally, a peer's merge of the owner is refused at replicated
/// admission, and history that retires the owner folds as a rejection with
/// the owner still active.
#[test]
fn no_split_peer_event_or_replayed_history_retires_the_vault_owner() {
    use crate::claim::{ClaimApprovalStatus, ClaimSource};
    use crate::error::SyncError;
    use crate::identity_topology::{
        IdentityOpEvidence, IdentityOpWrite, IdentityTopologyAction, IdentityTopologyEvent,
        IdentityTopologyOp, IdentityTopologyRejection, MergeOp, ReassignmentMap, SplitOp,
        StoredIdentityOpAction, StoredIdentityOpEvent, SurvivorshipPlan,
        fold_identity_topology_log,
    };
    let (_dir, vault, owner, person) = owner_and_person();
    let owner_id = owner.actor();
    let duplicate = person.actor_for_read(&vault).unwrap();
    let evidence = || IdentityOpEvidence {
        refs: Vec::new(),
        rationale: "fixture".into(),
    };
    let split = IdentityTopologyOp::Split(SplitOp {
        entity: owner_id,
        heads: Vec::new(),
        reassignment: ReassignmentMap::default(),
        evidence: evidence(),
    });
    let refused = vault.apply_identity_topology_op(
        &split,
        &IdentityOpWrite::auto(ClaimSource::Inferred),
        200,
    );
    assert!(
        matches!(
            refused,
            Err(Error::Sync(SyncError::IdentityTopologyRejected(
                IdentityTopologyRejection::OwnerSplitAway { owner: named }
            ))) if named == owner_id
        ),
        "{refused:?}"
    );
    assert!(vault.is_live_vault_owner(&owner).unwrap());

    let peer_merge = StoredIdentityOpEvent {
        seq: 1,
        validated_at_write: false,
        invalidated: false,
        at: 200,
        actor: None,
        source: ClaimSource::Inferred,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: StoredIdentityOpAction::Merge {
            sources: vec![owner_id],
            survivor: duplicate,
        },
    };
    let rtxn = vault.store.env.read_txn().unwrap();
    let admitted = vault.validate_replicated_identity_topology_event_in_txn(&rtxn, &peer_merge);
    drop(rtxn);
    assert!(
        matches!(
            admitted,
            Err(Error::Sync(SyncError::IdentityTopologyRejected(
                IdentityTopologyRejection::OwnerMergedAway { .. }
            )))
        ),
        "{admitted:?}"
    );

    let history = [
        IdentityTopologyEvent {
            event_id: crate::EntityId::now(),
            seq: 1,
            approval: ClaimApprovalStatus::Auto,
            action: IdentityTopologyAction::Apply(IdentityTopologyOp::Merge(MergeOp {
                sources: vec![owner_id],
                survivor: duplicate,
                evidence: evidence(),
                survivorship_plan: SurvivorshipPlan::ReadThrough,
            })),
        },
        IdentityTopologyEvent {
            event_id: crate::EntityId::now(),
            seq: 2,
            approval: ClaimApprovalStatus::Auto,
            action: IdentityTopologyAction::Apply(split),
        },
    ];
    let fold = fold_identity_topology_log(&history);
    assert!(
        !fold.states.contains_key(&owner_id),
        "the owner folds as active"
    );
    assert_eq!(
        fold.rejections
            .iter()
            .map(|(_, rejection)| *rejection)
            .collect::<Vec<_>>(),
        vec![
            IdentityTopologyRejection::OwnerMergedAway { owner: owner_id },
            IdentityTopologyRejection::OwnerSplitAway { owner: owner_id },
        ]
    );
}
