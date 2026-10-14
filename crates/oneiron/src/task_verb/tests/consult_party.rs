//! Task verb tests: a consult's parties and its consent requirement are the
//! facts its doors minted, never a replicated assertion, a raw body rewrite,
//! a deleted or regranted actor, or a restored image.

use super::support::*;
use super::*;
use crate::edge::EdgeKind;
use crate::ports::EdgeStoreRead;
use crate::task_authority::{
    TASK_AUTHORITY_FACT_SCHEMA_VERSION, TASK_AUTHORITY_FACT_SUBKIND, TaskAuthorityFactKind,
    decode_task_authority_fact_body,
};

pub(super) fn working() -> ConsultLadderState {
    ConsultLadderState::Working(WorkingState {
        started_at: LADDER_NOW,
        decision_round: 0,
    })
}

pub(super) fn approve(seed: u8) -> LadderTransition {
    LadderTransition::Finish(LadderTerminalState {
        disposition: LadderTerminalDisposition::Approved,
        result_ref: ladder_id(seed),
        counter_task_ref: None,
        finished_at: LADDER_NOW + 5,
    })
}

/// Rewrites only the consult's state through the public raw TASK door.
fn raw_rewrite_state(vault: &Vault, task_ref: EntityId, state: &ConsultLadderState, at: u64) {
    let mut body = task_verb_body(vault, task_ref)
        .expect("decode consult")
        .expect("consult is typed");
    body.state = Some(project_consult_ladder_state(state));
    vault
        .put_entity(
            &task_ref,
            crate::registry::ENTITY_TYPE_TASK,
            TimeRange { start: at, end: at },
            at,
            &encode_task_verb_body(body),
        )
        .expect("raw TASK rewrite of the state");
}

/// The ConsultAssignee facts a `ScopedTo` edge reaches `task_ref` from.
pub(super) fn party_facts(vault: &Vault, task_ref: EntityId) -> Vec<EntityId> {
    let txn = vault.store.env.read_txn().expect("read txn");
    vault
        .store
        .port_edges(
            &txn,
            &task_ref,
            crate::ports::EdgeDirection::In,
            Some(EdgeKind::ScopedTo),
            None,
        )
        .expect("inbound edges")
        .map(|edge| edge.expect("edge row").target)
        .filter(|fact_ref| {
            vault
                .get_raw_in(&txn, fact_ref)
                .expect("read fact")
                .and_then(|raw| {
                    decode_task_authority_fact_body(
                        &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
                    )
                    .ok()
                })
                .is_some_and(|fact| fact.kind == TaskAuthorityFactKind::ConsultAssignee)
        })
        .collect()
}

/// A well-formed ConsultAssignee fact row naming `named`, as a peer's
/// replicated row arrives: bytes and a `ScopedTo` edge, no minting door.
fn replicate_party_fact(vault: &Vault, task_ref: EntityId, named: EntityId) {
    let body = Value::Map(vec![
        (
            Value::from("role"),
            Value::from(crate::habit::TaskRole::AuthorityFact.role_byte()),
        ),
        (
            Value::from("schema_version"),
            Value::from(TASK_AUTHORITY_FACT_SCHEMA_VERSION),
        ),
        (
            Value::from("subkind"),
            Value::from(TASK_AUTHORITY_FACT_SUBKIND),
        ),
        (Value::from("task_ref"), Value::from(task_ref.to_hex())),
        (
            Value::from("kind"),
            Value::from(TaskAuthorityFactKind::ConsultAssignee.as_byte()),
        ),
        (Value::from("actor_ref"), Value::from(named.to_hex())),
        (Value::from("occurred_at"), Value::from(LADDER_NOW)),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &body).expect("encode fact");
    let fact_ref = EntityId::now();
    vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put_task_fact(&fact_ref, &bytes, LADDER_NOW)
                .edge(&fact_ref, EdgeKind::ScopedTo, &task_ref, 0.7)
                .apply(wtxn)
        })
        .expect("replicate the party fact");
}

/// F24 round 3 (H219): every consult mints its party fact, a
/// Dreamer-addressed one naming its asker alone, so a replicated fact
/// naming anyone else forks it. A fork gives nobody party standing, and the
/// owner proof still reads.
#[test]
fn a_replicated_party_fact_never_moves_a_dreamer_consult() {
    let (_dir, vault) = open_vault();
    let asker = own_agent(&vault);
    let created = vault
        .memory(asker, EdgeActorClass::Agent)
        .tasks_create(
            &consult_spec(
                consult_turn(&vault, 0x7A),
                consult_peer(&vault, 0xE2),
                CONSULT_DEADLINE,
            )
            .with_assignee(TaskAssignee::Dreamer),
        )
        .expect("a Dreamer-addressed consult");
    let task_ref = created.task_ref.expect("consult mints one TASK");
    seed_ladder_state(&vault, task_ref, &working());
    let third = other_actor(&vault);
    replicate_party_fact(&vault, task_ref, third);

    let refused = vault
        .memory(third, EdgeActorClass::Agent)
        .compare_and_set_consult_ladder(task_ref, &working(), approve(0xB1))
        .expect_err("a replicated fact names no party");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN);
    assert!(
        vault
            .memory(asker, EdgeActorClass::Agent)
            .compare_and_set_consult_ladder(task_ref, &working(), approve(0xB2))
            .is_err(),
        "a forked party fact fails closed for the asker too"
    );
    assert_eq!(
        vault
            .task_authority_state(task_ref)
            .expect("the owner proof still reads")
            .map(|state| state.owner_ref),
        Some(asker)
    );
}

/// F24 round 3 (H219): a required consent is the fact its interruption
/// minted. A raw rewrite of the body's flag, or of the whole state back to
/// working, waives nothing.
#[test]
fn a_raw_rewrite_cannot_clear_a_required_consent() {
    let (_dir, vault) = open_vault();
    let (task_ref, _peer, _question) = open_consult(&vault);
    let asker = vault.memory(own_agent(&vault), EdgeActorClass::Agent);
    seed_ladder_state(&vault, task_ref, &working());
    let waiting = InterruptedState {
        kind: InterruptionKind::Critical,
        consent_required: true,
        case_ref: ladder_id(0xF9),
        interrupted_at: LADDER_NOW + 1,
    };
    let unasked = InterruptedState {
        consent_required: false,
        ..waiting
    };
    asker
        .compare_and_set_consult_ladder(task_ref, &working(), LadderTransition::Interrupt(waiting))
        .expect("a party interrupts for a human verdict");

    raw_rewrite_state(
        &vault,
        task_ref,
        &ConsultLadderState::Interrupted(unasked),
        LADDER_NOW + 10,
    );
    let resume = LadderTransition::Resume(WorkingState {
        started_at: LADDER_NOW + 11,
        decision_round: 1,
    });
    assert!(
        asker
            .compare_and_set_consult_ladder(
                task_ref,
                &ConsultLadderState::Interrupted(unasked),
                resume
            )
            .is_err(),
        "a raw rewrite of the flag waives nothing"
    );
    raw_rewrite_state(&vault, task_ref, &working(), LADDER_NOW + 12);
    assert!(
        asker
            .compare_and_set_consult_ladder(
                task_ref,
                &working(),
                LadderTransition::Interrupt(unasked)
            )
            .is_err(),
        "a raw resume waives nothing either"
    );
}

/// F24 round 3 (H219): a deleted party is no party. Its retained facade
/// moves nothing, while the live asker still does.
#[test]
fn a_deleted_party_cannot_move_its_consult() {
    let (_dir, vault) = open_vault();
    let (task_ref, peer, _question) = open_consult(&vault);
    seed_ladder_state(&vault, task_ref, &working());
    let retained = vault.memory(peer, EdgeActorClass::Agent);
    vault
        .delete_entity(&peer)
        .expect("delete the addressed party");

    let refused = retained
        .compare_and_set_consult_ladder(task_ref, &working(), approve(0xB3))
        .expect_err("a deleted party moves nothing");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN);
    vault
        .memory(own_agent(&vault), EdgeActorClass::Agent)
        .compare_and_set_consult_ladder(task_ref, &working(), approve(0xB4))
        .expect("positive control: the live asker moves it");
}

/// F24 round 3 (H219): a restore keeping authority brings back neither a
/// party fact the live vault no longer reaches nor a consent requirement
/// the live vault holds, while one that changes neither goes ahead.
#[test]
fn a_restore_never_brings_back_a_removed_party_or_a_waived_consent() {
    let row = "task owners and cancellations";
    let backups = tempfile::tempdir().expect("backup dir");
    let restore = |vault: &Vault, image: &std::path::Path, name: &str| {
        Vault::restore_checkpoint_keeping_authority(
            image,
            &backups.path().join(name),
            vault.config.clone(),
            vault,
            1_000,
        )
        .map(drop)
    };

    let (_dir, vault) = open_vault();
    let (task_ref, _peer, _question) = open_consult(&vault);
    let image = backups.path().join("addressed");
    vault.snapshot_checkpoint(&image, 100).expect("backup");
    restore(&vault, &image, "unchanged")
        .expect("positive control: a restore that loosens nothing goes ahead");
    let facts = party_facts(&vault, task_ref);
    assert!(!facts.is_empty(), "the consult minted its party fact");
    for fact_ref in facts {
        vault
            .delete_edge(&fact_ref, EdgeKind::ScopedTo, &task_ref)
            .expect("remove the party fact's edge");
    }
    let refused = restore(&vault, &image, "party").expect_err("no removed party comes back");
    assert!(refused.to_string().contains(row), "{refused}");

    let (_consent_dir, consent) = open_vault();
    let (consult, _peer, _question) = open_consult(&consent);
    let asker = consent.memory(own_agent(&consent), EdgeActorClass::Agent);
    seed_ladder_state(&consent, consult, &working());
    let unasked = InterruptedState {
        kind: InterruptionKind::Contested,
        consent_required: false,
        case_ref: ladder_id(0xFA),
        interrupted_at: LADDER_NOW + 1,
    };
    asker
        .compare_and_set_consult_ladder(consult, &working(), LadderTransition::Interrupt(unasked))
        .expect("an interruption that asks for no consent");
    let image = backups.path().join("unasked");
    consent.snapshot_checkpoint(&image, 100).expect("backup");
    restore(&consent, &image, "unasked-unchanged")
        .expect("positive control: a restore that loosens nothing goes ahead");
    asker
        .compare_and_set_consult_ladder(
            consult,
            &ConsultLadderState::Interrupted(unasked),
            LadderTransition::Interrupt(InterruptedState {
                kind: InterruptionKind::Critical,
                consent_required: true,
                interrupted_at: LADDER_NOW + 2,
                ..unasked
            }),
        )
        .expect("the case now asks for a human verdict");
    let refused = restore(&consent, &image, "consent").expect_err("no consent is waived");
    assert!(refused.to_string().contains(row), "{refused}");
}

/// F24 round 3 (H219): a party revoked and regranted since a consult was
/// minted holds a new binding, not the party's: it moves no consult minted
/// before, and moves one minted since.
#[test]
fn a_regranted_party_moves_only_consults_minted_since() {
    let (_dir, vault) = open_vault();
    let asker = own_agent(&vault);
    let writer = crate::WriteActor::new(asker, EdgeActorClass::Agent);
    let revoke = crate::subject_model::tests::authorization::root_owner(&vault, writer, 0xEB)
        .expect("root the vault with the asker bound");
    let regrant = crate::subject_model::tests::authorization::regrant_after(&revoke, writer, 0xEB)
        .expect("sign the regrant");
    let (before, peer, _question) = open_consult(&vault);
    seed_ladder_state(&vault, before, &working());
    let at = TimeRange {
        start: 103,
        end: 103,
    };
    vault
        .put_authority_log_entries(&[(revoke, at, 102), (regrant, at, 103)])
        .expect("revoke, then regrant, the asker");
    let after = vault
        .memory(asker, EdgeActorClass::Agent)
        .tasks_create(&consult_spec(
            consult_turn(&vault, 0x7C),
            peer,
            CONSULT_DEADLINE,
        ))
        .expect("a consult minted since the regrant")
        .task_ref
        .expect("consult mints one TASK");
    seed_ladder_state(&vault, after, &working());
    let facade = vault.memory(asker, EdgeActorClass::Agent);

    assert!(
        facade
            .compare_and_set_consult_ladder(before, &working(), approve(0xB5))
            .is_err(),
        "a regranted asker is not the party of a consult minted before"
    );
    facade
        .compare_and_set_consult_ladder(after, &working(), approve(0xB6))
        .expect("a regranted asker moves a consult minted since");
}
