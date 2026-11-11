//! The Dreamer reads inside the data axes of its Steward grant
//! (S67-READ-AXES = C, Engine 10 Nov; untangle 6.3b). Its read was held to
//! the grant's `read` verb and its live MACHINE binding only: the policy
//! fold rebuilt its read row over every record kind, and the read guard
//! never looked at the grant's scope. So a grant row narrowed on a data axis
//! still read every kind.
//!
//! The host's mint leaves every data axis whole. The one owner path that
//! narrowed one went through the membership doors (a Steward holder
//! override, then the Dreamer's member role changed and changed back); those
//! doors no longer reach a base agent's grant
//! (`steward_grant_is_no_membership`). The read holds to the row all the
//! same, so the test writes the narrowed row through a door.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test steward_read_data_axes`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::{consolidate_unbound_turn, open_dreamer_vault};
use oneiron::test_doors::steward::{
    STEWARD_VERBS, class_key_reads, dreamer, stand_steward_grant, stand_steward_grant_in_bands,
};
use oneiron::{EntityId, Vault};

const READER: &str = "reader";

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
