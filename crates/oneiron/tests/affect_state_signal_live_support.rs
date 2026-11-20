//! A state signal (`state.engagement`, `state.goal_velocity`) is an aggregate
//! number, not a quotation of the records it counted (FIX
//! AFFECT-SIGNAL-HEX-REFS-FAIL-LIVE-SUPPORT; Engine AFFECT-SIGNAL-REFS-CITATION
//! = B). Its evidence holds the count it divides by its target and names no
//! record it counted, so the read-time live-support test asks nothing of it:
//! the signals the production refresh writes are served like any Auto Observed
//! claim, and stay served after every record they counted is deleted, as the
//! composite index that carries the same numbers does. A served signal spells
//! no counted TASK or turn id, which a reader of the substrate facet may not
//! read (REVIEW-9816 P1). The composite counts the annotated turns it read
//! and names none, for the same reason
//! (STATE-COMPOSITE-TURN-HEX-OUTSIDE-READER-FACET). It names neither signal
//! either: a reader the composite admits may be refused a signal row by a
//! check of its own, and it refuses a signal outside its facet or narrowed
//! to one principal, whose number it would carry (REVIEW-9905 P1, rounds 1
//! and 2).
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test affect_state_signal_live_support`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::affect::state_index::{ENGAGEMENT, GOAL_VELOCITY, StateIndexEvidence};
use oneiron::authority::{HostSlipIssuer, MachineOwnership, MachineRole};
use oneiron::memory::state_index::StateWindow;
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_POLICY_MANIFEST};
use oneiron::task_verb::TaskCreateSpec;
use oneiron::test_doors::affect_state_signals::{RefreshedStateSignals, refresh_state_signals};
use oneiron::test_doors::derive::claim_has_live_support;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, DeleteReason,
    EdgeActorClass, EntityId, TimeRange, Vad, VadAnnotation, VadAnnotationSource, Vault,
    VaultConfig, WriteActor,
};
use oneiron_keystore::MemoryKeystore;
use rmpv::Value;
use serde_json::json;

/// The pack id of the shipped default policy manifest.
const SHIPPED_POLICY_PACK: &str = "oneiron-default-policy";

/// One day, one expected completion and one expected engaged day: the turn
/// the owner spoke today and the TASK it owns both fall in the window.
const WINDOW: StateWindow = StateWindow {
    window_secs: 86_400,
    expected_goal_completions: 1,
    expected_engaged_days: 1,
};

/// A personal vault rooted under its host, with a device keystore (a delete
/// signs its receipt with this install's key), and its embedded owner PERSON,
/// as `archive_task_authority_facts.rs` builds one.
fn owned_vault() -> (tempfile::TempDir, Vault, EntityId) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open_owned(dir.path(), VaultConfig::default()).expect("owned vault");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let issuer =
        HostSlipIssuer::from_secret(b"affect state signal live support").expect("host issuer");
    vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Owned(MachineOwnership::Yours))
        .expect("serving install profile");
    (dir, vault, owner)
}

/// Declares each `(prefix, exact)` rule normal in the stored default policy,
/// as an owner's rule would: a predicate no rule names takes the criticality
/// floor, so its write pends for the owner instead of landing (as
/// `claim_facet_birth.rs` does).
fn declare_predicates_normal(vault: &Vault, declared: &[(&str, bool)]) {
    let axes = json!({ "criticality": "normal", "sensitivity": "normal" });
    for id in vault
        .entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)
        .expect("policy manifests")
    {
        let Some(bytes) = vault.get(&id).expect("policy manifest read") else {
            continue;
        };
        let mut manifest: serde_json::Value =
            rmp_serde::from_slice(&bytes).expect("policy manifest body");
        if manifest["pack_id"] != SHIPPED_POLICY_PACK {
            continue;
        }
        let rules = manifest
            .as_object_mut()
            .expect("policy manifest map")
            .entry("rules")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .expect("policy rules list");
        for &(prefix, exact) in declared {
            let found = rules.iter().position(|rule| rule["prefix"] == prefix);
            let index = match found {
                Some(index) => index,
                None => {
                    rules.push(json!({ "prefix": prefix }));
                    rules.len() - 1
                }
            };
            rules[index]["axes"] = axes.clone();
            if exact {
                rules[index]["exact"] = json!(true);
            }
        }
        oneiron::test_support::put_policy_manifest_bytes(
            vault,
            id,
            &rmp_serde::to_vec_named(&manifest).expect("policy manifest encode"),
        )
        .expect("policy manifest put");
        return;
    }
    panic!("the vault holds no shipped policy manifest");
}

/// One turn the owner says in `room` now, with a self-reported VAD on it:
/// the turn the engagement signal counts and the affect the index reads.
fn spoken_turn(vault: &Vault, owner: EntityId, room: EntityId) -> EntityId {
    let now = vault.now_recorded_at();
    let turn = vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: None,
            thread_audience: None,
            project: None,
            messages: vec![WitnessMessage {
                id: None,
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: "the garden plan is done".to_owned(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: now,
            assertions: WitnessAssertions::default(),
        })
        .expect("the owner's turn lands")
        .turn_id;
    let annotation = VadAnnotation::new(
        Vad {
            valence: 0.5,
            arousal: 0.6,
            dominance: 0.9,
        },
        VadAnnotationSource::UserSelfReport,
        now,
    )
    .expect("annotation");
    vault
        .annotate_turn_vad(&turn, annotation)
        .expect("the turn is annotated");
    turn
}

/// One TASK the owner creates through the task door and owns: the TASK the
/// goal-velocity signal counts.
fn owned_task(vault: &Vault, owner: EntityId) -> EntityId {
    vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_create(&TaskCreateSpec::new(
            Value::from("plant the spring beds"),
            None,
            Some(owner),
            None,
        ))
        .expect("the owner creates the task")
        .task_ref
        .expect("the TASK creation took effect")
}

/// The value a signal's (or the composite's) evidence holds under `key`, or
/// `None` when the evidence holds no such key.
fn evidence_field(vault: &Vault, signal: &EntityId, key: &str) -> Option<Value> {
    let body = vault
        .get_claim(signal)
        .expect("signal read")
        .expect("the signal is stored");
    let Some(Value::Map(fields)) = body.evidence.as_ref() else {
        panic!("the claim's evidence is a map: {:?}", body.evidence);
    };
    fields
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, value)| value.clone())
}

/// Whether the stored bytes of `row` spell `id`, as its hex text or its 16
/// raw bytes: a door that serves the row's bytes would hand the id on.
fn row_spells_id(vault: &Vault, row: &EntityId, id: &EntityId) -> bool {
    let bytes = vault
        .get(row)
        .expect("row read")
        .expect("the row is stored");
    let hex = id.to_hex();
    [hex.as_bytes(), id.as_bytes().as_slice()]
        .iter()
        .any(|needle| bytes.windows(needle.len()).any(|window| window == *needle))
}

/// The owner speaks one annotated turn and owns one TASK; the production
/// refresh writes both signals and the composite. Each signal has live
/// support, holds its count, spells neither the turn's nor the TASK's id, and
/// keeps live support once the turn and the TASK are both deleted.
/// Red on main: the signals list their counted records under `refs`, which
/// the live-support test reads as a malformed consolidation envelope, so no
/// read door serves either signal.
#[test]
fn a_state_signal_keeps_live_support_after_every_counted_record_is_deleted() {
    let (_dir, vault, owner) = owned_vault();
    declare_predicates_normal(&vault, &[("state.", false)]);
    let room = EntityId::now();
    let turn = spoken_turn(&vault, owner, room);
    let task = owned_task(&vault, owner);

    let RefreshedStateSignals {
        composite,
        goal_velocity,
        engagement,
    } = refresh_state_signals(&vault, &owner, &WINDOW, vault.now_recorded_at())
        .expect("the refresh")
        .expect("an annotated turn the owner spoke and a TASK it owns make the refresh measure");
    for (signal, predicate) in [
        (goal_velocity, "state.goal_velocity"),
        (engagement, "state.engagement"),
    ] {
        assert_eq!(
            vault
                .get_claim(&signal)
                .expect("read")
                .expect("stored")
                .predicate,
            predicate,
            "the composite's evidence ends in the goal-velocity and engagement signals"
        );
    }

    for (signal, name) in [(goal_velocity, "goal velocity"), (engagement, "engagement")] {
        assert_eq!(
            claim_has_live_support(&vault, &signal).expect("read"),
            Some(true),
            "FAILBEFORE AFFECT-SIGNAL-HEX-REFS-FAIL-LIVE-SUPPORT: the {name} signal is an \
             Auto Observed claim the read doors serve"
        );
        assert_eq!(
            evidence_field(&vault, &signal, "refs"),
            None,
            "the {name} signal holds no consolidation-envelope key"
        );
        for (counted, kind) in [(turn, "turn"), (task, "TASK")] {
            assert!(
                !row_spells_id(&vault, &signal, &counted),
                "FAILBEFORE REVIEW-9816-P1: the {name} signal spells the {kind} id it read, \
                 which a reader of the substrate facet may not read"
            );
        }
    }
    assert_eq!(
        evidence_field(&vault, &engagement, "count"),
        Some(Value::from(1_u64)),
        "the engagement signal counts the one day the owner spoke"
    );
    assert_eq!(
        evidence_field(&vault, &goal_velocity, "count"),
        Some(Value::from(0_u64)),
        "the goal-velocity signal counts no completion in the window"
    );
    assert_eq!(
        claim_has_live_support(&vault, &composite).expect("read"),
        Some(true),
        "the composite index is served"
    );

    vault
        .delete_room_record(
            room,
            turn,
            WriteActor::new(owner, EdgeActorClass::Human),
            DeleteReason::UserDelete,
        )
        .expect("the owner deletes the turn");
    assert!(
        vault
            .delete_entity(&task)
            .expect("the owner deletes the task"),
        "the TASK existed"
    );

    for (signal, name) in [(goal_velocity, "goal velocity"), (engagement, "engagement")] {
        assert_eq!(
            claim_has_live_support(&vault, &signal).expect("read"),
            Some(true),
            "the {name} signal stays served after every record it counted is deleted"
        );
    }
    assert_eq!(
        claim_has_live_support(&vault, &composite).expect("read"),
        Some(true),
        "the composite carrying the same numbers stays served too"
    );
}

/// The owner speaks one annotated turn and owns one TASK; the production
/// refresh writes the composite. The composite spells no turn id: the turn
/// sits in its room's facet and the composite in the owner's substrate facet,
/// so a door that serves the composite's bytes to a reader of that facet
/// would hand on the id of a turn the reader may not read. Its evidence
/// counts the one annotated turn and names neither signal claim, which sit in
/// the composite's own facet: a reader the composite admits may be refused a
/// signal row by a check of its own (REVIEW-9905 P1 round 2).
/// Red on main: the composite's evidence is an array of the annotated turn's
/// hex id, then the two signals' ids. Red at #9905's round-1 head
/// 60dda246c995: the evidence counts the turn and names both signals.
#[test]
fn a_composite_index_counts_its_annotated_turns_and_names_none() {
    let (_dir, vault, owner) = owned_vault();
    declare_predicates_normal(&vault, &[("state.", false)]);
    let room = EntityId::now();
    let turn = spoken_turn(&vault, owner, room);
    let _task = owned_task(&vault, owner);

    let RefreshedStateSignals {
        composite,
        goal_velocity,
        engagement,
    } = refresh_state_signals(&vault, &owner, &WINDOW, vault.now_recorded_at())
        .expect("the refresh")
        .expect("an annotated turn the owner spoke and a TASK it owns make the refresh measure");

    assert!(
        !row_spells_id(&vault, &composite, &turn),
        "FAILBEFORE STATE-COMPOSITE-TURN-HEX-OUTSIDE-READER-FACET: the composite spells the \
         id of the turn it read, which a reader of the substrate facet may not read"
    );
    assert_eq!(
        evidence_field(&vault, &composite, "annotated_turns"),
        Some(Value::from(1_u64)),
        "the composite counts the one annotated turn the owner spoke"
    );
    for (signal, predicate) in [
        (goal_velocity, "state.goal_velocity"),
        (engagement, "state.engagement"),
    ] {
        assert!(
            !row_spells_id(&vault, &composite, &signal),
            "FAILBEFORE REVIEW-9905-P1-ROUND-2: the composite spells the id of its {predicate} \
             signal, which a reader the composite admits may be refused"
        );
        let body = vault.get_claim(&signal).expect("read").expect("stored");
        assert_eq!(body.predicate, predicate);
        assert_eq!(
            body.scope_facet,
            vault
                .get_claim(&composite)
                .expect("read")
                .expect("stored")
                .scope_facet,
            "the {predicate} signal sits in the composite's own facet"
        );
    }
    assert_eq!(
        claim_has_live_support(&vault, &composite).expect("read"),
        Some(true),
        "the composite index is served"
    );
}

/// One `predicate` signal claim about `subject` stored in `facet` through the
/// public claim door, which keeps the facet it is given.
fn signal_in_facet(
    vault: &Vault,
    subject: EntityId,
    predicate: &str,
    value: f32,
    facet: EntityId,
) -> EntityId {
    let at = vault.now_recorded_at();
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        Value::F32(value),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("signal claim");
    body.source = Some(ClaimSource::Observed);
    body.scope_facet = facet;
    vault
        .put_claim(&id, &body, TimeRange { start: at, end: at }, at)
        .expect("signal claim put");
    id
}

/// The composite carries both signals' numbers, so a signal claim stored in a
/// facet other than the composite's is refused: a reader of the composite's
/// facet may not read that signal, and must not learn it from the composite.
/// The same derivation with the signal in the composite's own facet is
/// accepted, and names no signal (REVIEW-9905 P1).
/// Red at #9905's first fix f51cfaad91f7: the derivation accepts the signal
/// in the other facet and names it in the composite's evidence.
#[test]
fn a_composite_refuses_a_signal_claim_outside_its_facet() {
    let (_dir, vault, owner) = owned_vault();
    declare_predicates_normal(&vault, &[("state.", false)]);
    let room = EntityId::now();
    let turn = spoken_turn(&vault, owner, room);
    let _task = owned_task(&vault, owner);
    let RefreshedStateSignals { composite, .. } =
        refresh_state_signals(&vault, &owner, &WINDOW, vault.now_recorded_at())
            .expect("the refresh")
            .expect(
                "an annotated turn the owner spoke and a TASK it owns make the refresh measure",
            );
    let own_facet = vault
        .get_claim(&composite)
        .expect("read")
        .expect("stored")
        .scope_facet;
    let other_facet = EntityId::now();
    let at = vault.now_recorded_at();
    vault
        .put_entity(
            &other_facet,
            ENTITY_TYPE_FACET,
            TimeRange { start: at, end: at },
            at,
            b"facet",
        )
        .expect("a second FACET");
    assert_ne!(other_facet, own_facet);

    let engagement = signal_in_facet(&vault, owner, ENGAGEMENT, 0.8, own_facet);
    let foreign = signal_in_facet(&vault, owner, GOAL_VELOCITY, 0.7, other_facet);
    let derived = vault.derive_state_index(
        &owner,
        &StateIndexEvidence {
            vad_turns: vec![turn],
            goal_velocity: foreign,
            engagement,
        },
        vault.now_recorded_at(),
    );
    assert!(
        derived.is_err(),
        "FAILBEFORE REVIEW-9905-P1: the composite accepts a goal-velocity signal stored in \
         another facet and names it to readers of its own: {derived:?}"
    );

    let own = signal_in_facet(&vault, owner, GOAL_VELOCITY, 0.7, own_facet);
    let derived = vault
        .derive_state_index(
            &owner,
            &StateIndexEvidence {
                vad_turns: vec![turn],
                goal_velocity: own,
                engagement,
            },
            vault.now_recorded_at(),
        )
        .expect("the same derivation with the signal in the composite's facet");
    assert!(
        !row_spells_id(&vault, &derived, &own),
        "the composite names no signal, even one in its own facet"
    );
}

/// One `predicate` signal claim about `subject` in `facet`, narrowed to
/// `principal` by its scope, through the public claim door.
fn principal_signal_in_facet(
    vault: &Vault,
    subject: EntityId,
    predicate: &str,
    value: f32,
    facet: EntityId,
    principal: EntityId,
) -> EntityId {
    let at = vault.now_recorded_at();
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        Value::F32(value),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("signal claim");
    body.source = Some(ClaimSource::Observed);
    body.scope_facet = facet;
    body.scope = Some(Value::Map(vec![(
        Value::from("principal"),
        Value::Binary(principal.as_bytes().to_vec()),
    )]));
    vault
        .put_claim(&id, &body, TimeRange { start: at, end: at }, at)
        .expect("a signal claim for one principal");
    id
}

/// The composite has no principal, so it carries no signal narrowed to one:
/// a reader the composite admits, who is not that principal, is refused the
/// signal row and must not learn its number or id from the composite
/// (REVIEW-9905 P1 round 2). The same signal with no principal is accepted.
/// Red at #9905's round-1 head 60dda246c995: the derivation accepts the
/// principal-scoped signal and names it in the composite's evidence.
#[test]
fn a_composite_refuses_a_signal_claim_narrowed_to_one_principal() {
    let (_dir, vault, owner) = owned_vault();
    declare_predicates_normal(&vault, &[("state.", false)]);
    let room = EntityId::now();
    let turn = spoken_turn(&vault, owner, room);
    let _task = owned_task(&vault, owner);
    let RefreshedStateSignals { composite, .. } =
        refresh_state_signals(&vault, &owner, &WINDOW, vault.now_recorded_at())
            .expect("the refresh")
            .expect(
                "an annotated turn the owner spoke and a TASK it owns make the refresh measure",
            );
    let own_facet = vault
        .get_claim(&composite)
        .expect("read")
        .expect("stored")
        .scope_facet;

    let engagement = signal_in_facet(&vault, owner, ENGAGEMENT, 0.8, own_facet);
    let narrowed = principal_signal_in_facet(&vault, owner, GOAL_VELOCITY, 0.7, own_facet, owner);
    let derived = vault.derive_state_index(
        &owner,
        &StateIndexEvidence {
            vad_turns: vec![turn],
            goal_velocity: narrowed,
            engagement,
        },
        vault.now_recorded_at(),
    );
    assert!(
        derived.is_err(),
        "FAILBEFORE REVIEW-9905-P1-ROUND-2: the composite accepts a goal-velocity signal \
         narrowed to one principal and carries it to every reader of its facet: {derived:?}"
    );

    let open = signal_in_facet(&vault, owner, GOAL_VELOCITY, 0.7, own_facet);
    vault
        .derive_state_index(
            &owner,
            &StateIndexEvidence {
                vad_turns: vec![turn],
                goal_velocity: open,
                engagement,
            },
            vault.now_recorded_at(),
        )
        .expect("the same derivation with a signal no principal narrows");
}
