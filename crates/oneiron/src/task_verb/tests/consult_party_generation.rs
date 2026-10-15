//! Task verb tests: a consult party's binding generation names the bindings
//! it held, so a rebind away and back is a new binding, while replicas that
//! observed one binding differently, and a party bound under two classes,
//! still act as the party.

use super::consult_party::{approve, working};
use super::support::*;
use super::*;
use crate::authority::{
    AuthorityAttestation, AuthorityEntryHash, AuthorityKey, AuthorityLogEntry, AuthorityOp,
    AuthorityTier, DeviceAuthority, ROLE_AGENT, authority_entry_hash,
};
use crate::subject_model::tests::authorization::{regrant_after, root_owner, sign_child};
use crate::task_authority::{
    TaskAuthorityFact, TaskAuthorityFactKind, put_task_authority_fact_in_txn,
};
use ed25519_dalek::SigningKey;

fn key(seed: u8) -> AuthorityKey {
    AuthorityKey::Ed25519(
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
}

fn put_entries(vault: &Vault, entries: &[&AuthorityLogEntry]) {
    let entries: Vec<_> = entries
        .iter()
        .map(|entry| {
            let at = entry.ts;
            ((*entry).clone(), TimeRange { start: at, end: at }, at)
        })
        .collect();
    vault
        .put_authority_log_entries(&entries)
        .expect("append the authority entries");
}

/// The host enrolling an engine agent writer `seed`: an authority entry
/// that changes no actor binding.
fn enroll_agent(seed: u8) -> AuthorityOp {
    AuthorityOp::EnrollDevice {
        device: DeviceAuthority {
            key: key(seed),
            transport_key_binding: [seed; 32],
            attestation: AuthorityAttestation {
                kind: "SoftwareArgon2id".to_owned(),
                evidence: vec![1, 2, 3],
            },
            tier: AuthorityTier::Software,
            roles: ROLE_AGENT,
        },
    }
}

fn new_consult(vault: &Vault, asker: EntityId, peer: EntityId, seed: u8) -> EntityId {
    let task_ref = vault
        .memory(asker, EdgeActorClass::Agent)
        .tasks_create(&consult_spec(
            consult_turn(vault, seed),
            peer,
            CONSULT_DEADLINE,
        ))
        .expect("a consult")
        .task_ref
        .expect("consult mints one TASK");
    seed_ladder_state(vault, task_ref, &working());
    task_ref
}

/// F24 round 4 (H219): a key rebound away from its party and back is a new
/// binding, not the one the consult recorded, though no revoke ever ran:
/// the party moves no consult minted before, and moves one minted since.
#[test]
fn a_party_rebound_away_and_back_moves_only_consults_minted_since() {
    let (_dir, vault) = open_vault();
    let asker = own_agent(&vault);
    let writer = crate::WriteActor::new(asker, EdgeActorClass::Agent);
    let revoke = root_owner(&vault, writer, 0xED).expect("root the vault with the asker bound");
    let peer = consult_peer(&vault, 0xE2);
    let before = new_consult(&vault, asker, peer, 0x7D);
    let rebind = |parent: AuthorityEntryHash, seq, actor_ref, epoch| {
        sign_child(
            revoke.vault_id,
            parent,
            seq,
            AuthorityOp::RebindActor {
                authority_key: key(0xED),
                actor_ref,
                actor_class: writer.actor_class().gate_actor_class().to_owned(),
                epoch,
            },
            0xED,
            &[],
        )
        .expect("sign the rebind")
    };
    let away = rebind(revoke.parent_hashes[0], 2, peer, 2);
    let back = rebind(authority_entry_hash(&away).expect("hash"), 3, asker, 3);
    put_entries(&vault, &[&away, &back]);
    let after = new_consult(&vault, asker, peer, 0x7E);
    let facade = vault.memory(asker, EdgeActorClass::Agent);

    assert!(
        facade
            .compare_and_set_consult_ladder(before, &working(), approve(0xC1))
            .is_err(),
        "a party rebound away and back is not the party of a consult minted before"
    );
    facade
        .compare_and_set_consult_ladder(after, &working(), approve(0xC2))
        .expect("positive control: the rebound party moves a consult minted since");
}

/// F24 round 4 (H219): two replicas that observed the same binding through
/// different authority entries record the same generation, so the party
/// facts both mint for one consult (the open migration on each) still let
/// a regranted party move it.
#[test]
fn replicas_observing_one_binding_record_one_generation() {
    let (_dir, vault) = open_vault();
    let asker = own_agent(&vault);
    let writer = crate::WriteActor::new(asker, EdgeActorClass::Agent);
    let revoke = root_owner(&vault, writer, 0xEE).expect("root the vault with the asker bound");
    let regrant = regrant_after(&revoke, writer, 0xEE).expect("sign the regrant");
    put_entries(&vault, &[&revoke, &regrant]);
    let peer = consult_peer(&vault, 0xE2);
    let task_ref = new_consult(&vault, asker, peer, 0x7F);
    let generation = |actor| {
        let txn = vault.store.env.read_txn().expect("read txn");
        vault
            .actor_binding_generation_in_txn(&txn, actor)
            .expect("generation")
    };
    let recorded = generation(asker);

    // Entries that change none of the parties' bindings, as another replica
    // also observed: an engine agent key, then that key bound and rebound to
    // writers of its own (a two-key roster cosigns every entry).
    let enroll = sign_child(
        regrant.vault_id,
        authority_entry_hash(&regrant).expect("hash"),
        4,
        enroll_agent(0x40),
        0xEE,
        &[],
    )
    .expect("sign the enrollment");
    put_entries(&vault, &[&enroll]);
    let mut parent = authority_entry_hash(&enroll).expect("hash");
    for epoch in 1..32_u8 {
        let (authority_key, actor_class) = (
            key(0x40),
            EdgeActorClass::Agent.gate_actor_class().to_owned(),
        );
        let actor_ref = EntityId::from_bytes([0x40 + epoch; 16]).expect("writer id");
        let epoch = u64::from(epoch);
        let op = if epoch == 1 {
            AuthorityOp::BindActor {
                authority_key,
                actor_ref,
                actor_class,
                epoch,
            }
        } else {
            AuthorityOp::RebindActor {
                authority_key,
                actor_ref,
                actor_class,
                epoch,
            }
        };
        let entry = sign_child(regrant.vault_id, parent, 4 + epoch, op, 0xEE, &[0x40])
            .expect("sign the agent binding");
        parent = authority_entry_hash(&entry).expect("hash");
        put_entries(&vault, &[&entry]);
        if generation(asker) != recorded {
            break;
        }
    }
    let txn = vault.store.env.read_txn().expect("read txn");
    assert!(
        vault
            .authority_fold_readonly_in_txn(&txn)
            .expect("fold")
            .actor_bindings
            .get(&key(0x40))
            .is_some_and(|binding| binding.status == crate::authority::ActorBindingStatus::Active),
        "precondition: the agent key's entries landed"
    );
    drop(txn);
    let (actor_generation, assigned_generation) = (generation(asker), generation(peer));
    vault
        .with_write_txn(|wtxn| {
            put_task_authority_fact_in_txn(
                &vault,
                wtxn,
                TaskAuthorityFact {
                    task_ref,
                    kind: TaskAuthorityFactKind::ConsultAssignee,
                    actor_ref: asker,
                    assigned_ref: Some(peer),
                    actor_generation,
                    assigned_generation,
                    occurred_at: LADDER_NOW,
                },
            )
        })
        .expect("the second replica's migration mints the consult's party fact");

    vault
        .memory(asker, EdgeActorClass::Agent)
        .compare_and_set_consult_ladder(task_ref, &working(), approve(0xC3))
        .expect("the regranted asker still moves the consult both replicas minted");
}

/// F24 round 4 (H219): a person bound under a human key and an agent key
/// asks as the agent; the generation names both bindings, so it moves its
/// consult as the agent, whichever binding sorts first and whatever
/// frontier each was observed at.
#[test]
fn a_party_bound_under_two_classes_moves_its_consult() {
    let (_dir, vault) = open_vault();
    let person = own_agent(&vault);
    let human = crate::WriteActor::new(person, EdgeActorClass::Human);
    let revoke = root_owner(&vault, human, 0xEF).expect("root the vault with the human key");
    let bind = revoke.parent_hashes[0];
    // The agent key sorts after the human key, so a capture of the first
    // binding alone would record the human binding.
    let agent_seed = (0x50..=0xFF)
        .find(|seed| key(*seed) > key(0xEF))
        .expect("an agent key sorting after the human key");
    let enroll = sign_child(
        revoke.vault_id,
        bind,
        2,
        enroll_agent(agent_seed),
        0xEF,
        &[],
    )
    .expect("sign the enrollment");
    let enrolled = authority_entry_hash(&enroll).expect("hash");
    // An agent binding entry (any fresh epoch will do) hashing below one
    // the human binding was already observed at, so the frontier the human
    // key reached last is not one the agent key holds.
    let bind_agent = (1..=64)
        .map(|epoch| {
            sign_child(
                revoke.vault_id,
                enrolled,
                3,
                AuthorityOp::BindActor {
                    authority_key: key(agent_seed),
                    actor_ref: person,
                    actor_class: EdgeActorClass::Agent.gate_actor_class().to_owned(),
                    epoch,
                },
                0xEF,
                &[agent_seed],
            )
            .expect("sign the agent binding")
        })
        .find(|entry| authority_entry_hash(entry).is_ok_and(|hash| hash < bind.max(enrolled)))
        .expect("an agent binding hashing below the human key's last frontier");
    put_entries(&vault, &[&enroll, &bind_agent]);
    let peer = consult_peer(&vault, 0xE2);
    let task_ref = new_consult(&vault, person, peer, 0x80);

    vault
        .memory(person, EdgeActorClass::Agent)
        .compare_and_set_consult_ladder(task_ref, &working(), approve(0xC4))
        .expect("the person moves its consult as the agent it asked as");
}

/// F24 round 5 (H219): a party with no generation recorded (its consult was
/// minted before its first binding) holds its key's first binding, not a
/// later one: rebound away and back, it no longer moves the consult.
#[test]
fn a_party_with_no_recorded_generation_loses_it_to_a_rebind() {
    let (_dir, vault) = open_vault();
    let asker = own_agent(&vault);
    let peer = consult_peer(&vault, 0xE2);
    let unrooted = new_consult(&vault, asker, peer, 0x82);
    let control = new_consult(&vault, asker, peer, 0x83);
    let writer = crate::WriteActor::new(asker, EdgeActorClass::Agent);
    let revoke = root_owner(&vault, writer, 0xEC).expect("root the vault with the asker bound");
    let facade = vault.memory(asker, EdgeActorClass::Agent);
    facade
        .compare_and_set_consult_ladder(control, &working(), approve(0xC5))
        .expect("positive control: the first binding moves an unrooted consult");
    let rebind = |parent: AuthorityEntryHash, seq, actor_ref, epoch| {
        sign_child(
            revoke.vault_id,
            parent,
            seq,
            AuthorityOp::RebindActor {
                authority_key: key(0xEC),
                actor_ref,
                actor_class: writer.actor_class().gate_actor_class().to_owned(),
                epoch,
            },
            0xEC,
            &[],
        )
        .expect("sign the rebind")
    };
    let away = rebind(revoke.parent_hashes[0], 2, peer, 2);
    let back = rebind(authority_entry_hash(&away).expect("hash"), 3, asker, 3);
    put_entries(&vault, &[&away, &back]);

    assert!(
        facade
            .compare_and_set_consult_ladder(unrooted, &working(), approve(0xC6))
            .is_err(),
        "a rebound party is not the first binding the consult admitted"
    );
}

/// F24 round 5 (H219): two facts for one consult's parties whose
/// generations share no binding admit nobody, even in an unrooted vault.
#[test]
fn generations_with_no_binding_in_common_admit_nobody_unrooted() {
    let (_dir, vault) = open_vault();
    let asker = own_agent(&vault);
    let peer = consult_peer(&vault, 0xE2);
    let task_ref = new_consult(&vault, asker, peer, 0x84);
    let control = new_consult(&vault, asker, peer, 0x85);
    let recorded = crate::task_authority::BindingGeneration::from_bindings([[0xAB; 32]]);
    vault
        .with_write_txn(|wtxn| {
            put_task_authority_fact_in_txn(
                &vault,
                wtxn,
                TaskAuthorityFact {
                    task_ref,
                    kind: TaskAuthorityFactKind::ConsultAssignee,
                    actor_ref: asker,
                    assigned_ref: Some(peer),
                    actor_generation: recorded,
                    assigned_generation: None,
                    occurred_at: LADDER_NOW,
                },
            )
        })
        .expect("a replica's fact recording a binding");
    let facade = vault.memory(asker, EdgeActorClass::Agent);

    assert!(
        facade
            .compare_and_set_consult_ladder(task_ref, &working(), approve(0xC7))
            .is_err(),
        "no binding in common admits nobody"
    );
    facade
        .compare_and_set_consult_ladder(control, &working(), approve(0xC8))
        .expect("positive control: an unrooted consult's own fact admits its asker");
}
