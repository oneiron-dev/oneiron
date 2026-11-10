//! The Dreamer reads inside the data axes of its Steward grant
//! (S67-READ-AXES = C, Engine 10 Nov; untangle 6.3b). Its read was held to
//! the grant's `read` verb and its live MACHINE binding only: the policy
//! fold rebuilt its read row over every record kind, and the read guard
//! never looked at the grant's scope. So a grant the owner had narrowed
//! still read every kind.
//!
//! The owner narrows the grant with acts of their own: a Steward holder
//! override that names the Dreamer, then the Dreamer's member role changed
//! to Member and back to Steward on a shared vault. The role change resolves
//! the marked grant row again, under the override. The second test runs
//! those acts; the first writes the row they leave.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test steward_read_data_axes`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::federation::FederationGrantRole as Role;
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::{consolidate_unbound_turn, open_dreamer_vault};
use oneiron::test_doors::steward::{
    GrantMark, STEWARD_READ_VERB, STEWARD_VERBS, class_key_reads, dreamer, grant_mark, owner,
    stand_steward_grant, stand_steward_grant_in_bands, write_dreamer_band_override,
};
use oneiron::{EntityId, Vault};

const READER: &str = "reader";
const SHARED: u64 = 42;

/// The model's reply: one new person, named in T1, and its name.
fn reply() -> String {
    serde_json::json!({
        "persons": [{"id": "new:P1", "name": "Owen", "evidence_turn_refs": ["T1"]}],
        "candidates": [{
            "subject": "new:P1",
            "predicate": "profile.name",
            "value": "Owen",
            "confidence": 0.8,
            "evidence_refs": [{"source": "T1", "quote": "Owen"}],
        }],
    })
    .to_string()
}

/// Rows of three record kinds, each with its kind: the turn one
/// consolidation pass read, the claims it landed, and a person.
fn rows_of_three_kinds(vault: &Vault) -> Vec<(EntityId, u8)> {
    let pass = consolidate_unbound_turn(vault, "call me Owen", None, None, &reply())
        .expect("one consolidation pass");
    let person = EntityId::now();
    vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a person");
    std::iter::once((pass.turn, ENTITY_TYPE_TURN))
        .chain(pass.landed.iter().map(|claim| (*claim, ENTITY_TYPE_CLAIM)))
        .chain(std::iter::once((person, ENTITY_TYPE_PERSON)))
        .collect()
}

/// The rows of `rows` the Dreamer's key reads now.
fn read_now(vault: &Vault, dreamer: EntityId, rows: &[(EntityId, u8)]) -> Vec<(EntityId, u8)> {
    rows.iter()
        .copied()
        .filter(|(row, _)| class_key_reads(vault, dreamer, *row).expect("read"))
        .collect()
}

/// The kind the grant is narrowed to: one the Dreamer reads under its whole
/// grant, a claim before a turn before a person (a claim and a turn always
/// hold a record position). At least one row of another kind is read too.
fn kept_kind(read: &[(EntityId, u8)]) -> u8 {
    let kinds: BTreeSet<u8> = read.iter().map(|(_, kind)| *kind).collect();
    assert!(
        kinds.len() >= 2,
        "under its whole grant the Dreamer reads rows of two kinds at least: {read:?}"
    );
    [ENTITY_TYPE_CLAIM, ENTITY_TYPE_TURN, ENTITY_TYPE_PERSON]
        .into_iter()
        .find(|kind| kinds.contains(kind))
        .expect("a kind it reads")
}

/// Each row the Dreamer read under its whole grant is read now exactly when
/// it is of the kind the grant was narrowed to.
fn assert_reads_the_kept_kind_only(
    vault: &Vault,
    dreamer: EntityId,
    read: &[(EntityId, u8)],
    kept: u8,
) {
    for (row, kind) in read {
        let reads = class_key_reads(vault, dreamer, *row).expect("read");
        if *kind == kept {
            assert!(
                reads,
                "a row of kind {kind}, inside the grant's kinds, is still read"
            );
        } else {
            assert!(
                !reads,
                "a row of kind {kind} is outside the grant's kinds ({kept} alone): not read"
            );
        }
    }
}

#[test]
fn the_dreamer_reads_inside_the_record_kinds_of_its_grant() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("fixture vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    stand_steward_grant(&vault, dreamer, &STEWARD_VERBS).expect("whole grant");
    let rows = rows_of_three_kinds(&vault);
    let read = read_now(&vault, dreamer, &rows);
    let kept = kept_kind(&read);

    stand_steward_grant_in_bands(&vault, dreamer, &STEWARD_VERBS, &[kept])
        .expect("the grant held to one kind");
    assert_reads_the_kept_kind_only(&vault, dreamer, &read, kept);
}

#[test]
fn an_owners_holder_override_and_a_role_round_trip_narrow_the_dreamers_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("fixture vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    // The rows are written while the vault's policy rows let the Dreamer
    // read and land, before any grant is marked.
    let rows = rows_of_three_kinds(&vault);

    // The owner shares the vault; the Dreamer's Steward grant stands on it.
    let owner = owner(&vault).expect("owner proof");
    vault
        .initialize_shared_vault(&owner, SHARED, None, &[], 1)
        .expect("a shared vault");
    let grant = stand_steward_grant(&vault, dreamer, &STEWARD_VERBS).expect("whole grant");
    let read = read_now(&vault, dreamer, &rows);
    let kept = kept_kind(&read);

    // The owner's holder override, then the member-role round trip that
    // resolves the marked grant row again under it.
    write_dreamer_band_override(&vault, SHARED, &[kept]).expect("holder override");
    vault
        .change_shared_member_role(&owner, SHARED, dreamer, Role::Member, None)
        .expect("the owner makes the Dreamer a Member");
    vault
        .change_shared_member_role(&owner, SHARED, dreamer, Role::Steward, None)
        .expect("the owner makes the Dreamer a Steward again");
    let Some(GrantMark::Minted {
        grant: marked,
        verbs,
    }) = grant_mark(&vault, dreamer).expect("mark")
    else {
        panic!("the marker still names a grant");
    };
    assert_eq!(marked, grant, "the role change rewrote the marked row");
    assert!(
        verbs.contains(STEWARD_READ_VERB),
        "the narrowed grant still stands with read: {verbs:?}"
    );

    assert_reads_the_kept_kind_only(&vault, dreamer, &read, kept);
}
