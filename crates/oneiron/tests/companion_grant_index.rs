//! Census L3-28E (ARCH-0044 H424): the companion grant reads (the persona
//! list, the profile admission and the gate's grant lookup) are served from
//! a derived (principal, PERSON) grant index instead of reading every
//! ACCESS_GRANT row. The index changes no answer: through person-wide and
//! facet grants, other principals and persons, a calendar grant, a revoke,
//! a re-grant under a new id, a delete, and a reopen that rebuilds the
//! dropped index, the index serves each read (no fallback) and every read
//! answers as the walk of every grant answers it. An undecodable grant row
//! anywhere makes the reads walk, so they fail closed as before. A persona
//! list the index serves reads only its own grants, so it raises no
//! `AccessGrantRows` check; with the index dropped it walks and raises one.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test companion_grant_index -- --nocapture` (the timing
//! line prints with `--nocapture`).
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Instant;

use oneiron::booking::DisclosureRung;
use oneiron::psych_profile::PsychProfileKey;
use oneiron::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON};
use oneiron::scan_check::EngineScan;
use oneiron::settings::ReadDestination;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::companion_grant_index as doors;
use oneiron::{AccessGrant, EntityId, Vault, VaultConfig};
use serde_json::json;

fn put_person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live PERSON");
    id
}

fn put_facet(vault: &Vault, name: &str) -> EntityId {
    let id = EntityId::now();
    let body = rmp_serde::to_vec_named(&json!({ "name": name })).expect("a facet body");
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_FACET,
            TimeRange { start: 1, end: 1 },
            1,
            &body,
        )
        .expect("a stored FACET");
    id
}

fn grant(
    vault: &Vault,
    principal: EntityId,
    person: EntityId,
    facet: Option<EntityId>,
) -> EntityId {
    let id = EntityId::now();
    vault
        .create_access_grant(
            &id,
            &AccessGrant::companion_profile_read(principal, person, facet, 1),
        )
        .expect("a companion grant");
    id
}

/// One fixture: the principals and PERSONs it asks about, and the facets
/// each read names.
struct Asked {
    pairs: Vec<(EntityId, EntityId)>,
    facets: Vec<Option<EntityId>>,
}

/// Every companion grant read of every asked pair, as text: the gate's
/// lookup at each facet, the persona list, and the profile admission at
/// each facet. An error is part of the answer.
fn answers(vault: &Vault, asked: &Asked) -> Vec<String> {
    let mut out = Vec::new();
    for (principal, person) in &asked.pairs {
        for facet in &asked.facets {
            out.push(format!(
                "lookup {principal:?} {person:?} {facet:?}: {:?}",
                vault.companion_profile_access_grant(principal, person, facet.as_ref())
            ));
            let key = PsychProfileKey {
                person: *person,
                facet: *facet,
                world: None,
            };
            out.push(format!(
                "admission {principal:?} {person:?} {facet:?}: {:?}",
                vault.companion_profile_snapshot_admitted(
                    principal,
                    &key,
                    &ReadDestination::on_device(),
                    None,
                    None,
                )
            ));
        }
        out.push(format!(
            "list {principal:?} {person:?}: {:?}",
            vault.authorized_companion_profile_facets(principal, person)
        ));
    }
    out
}

/// The grants the index names for each asked pair: `None` where a read
/// would walk.
fn indexed(vault: &Vault, asked: &Asked) -> Vec<Option<Vec<EntityId>>> {
    asked
        .pairs
        .iter()
        .map(|(principal, person)| doors::indexed_grants(vault, principal, person).expect("index"))
        .collect()
}

/// The index serves every asked read (no fallback), each read answers as
/// the walk of every grant answers it, and an index rebuilt from the rows
/// gives the same answers.
fn assert_index_answers_as_walk(vault: &Vault, asked: &Asked) {
    assert!(
        indexed(vault, asked).iter().all(Option::is_some),
        "the index serves every read"
    );
    let served = answers(vault, asked);
    doors::drop_index(vault).expect("drop the index");
    assert!(
        indexed(vault, asked).iter().all(Option::is_none),
        "a dropped index serves nothing"
    );
    assert_eq!(
        answers(vault, asked),
        served,
        "the walk gives the index's answers"
    );
    doors::rebuild_index(vault).expect("rebuild the index");
    assert!(indexed(vault, asked).iter().all(Option::is_some));
    assert_eq!(
        answers(vault, asked),
        served,
        "a rebuilt index gives the same answers"
    );
}

#[test]
fn index_answers_as_the_walk_through_grants_revokes_a_delete_and_a_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    assert!(
        doors::index_complete(&vault).expect("flag"),
        "open builds the index"
    );
    let (owen, yuki) = (put_person(&vault), put_person(&vault));
    let (work, home) = (put_facet(&vault, "work"), put_facet(&vault, "home"));
    let (reader, other) = (EntityId::now(), EntityId::now());
    let asked = Asked {
        pairs: vec![(reader, owen), (reader, yuki), (other, owen), (other, yuki)],
        facets: vec![None, Some(work), Some(home)],
    };
    assert_index_answers_as_walk(&vault, &asked);

    // Person-wide and facet grants, another principal, another PERSON, and
    // a calendar grant the index never names.
    let wide = grant(&vault, reader, owen, None);
    let at_work = grant(&vault, reader, owen, Some(work));
    let other_home = grant(&vault, other, owen, Some(home));
    let yuki_wide = grant(&vault, reader, yuki, None);
    vault
        .create_access_grant(
            &EntityId::now(),
            &AccessGrant::calendar_disclosure(reader, EntityId::now(), DisclosureRung::Busy, 1),
        )
        .expect("a calendar grant");
    assert_eq!(
        doors::indexed_grants(&vault, &reader, &owen).expect("index"),
        Some(vec![wide, at_work])
    );
    assert_eq!(
        vault
            .companion_profile_access_grant(&reader, &owen, Some(&work))
            .expect("lookup"),
        Some(wide),
        "the first grant in id order that admits the read"
    );
    assert_eq!(
        vault
            .authorized_companion_profile_facets(&reader, &owen)
            .expect("list"),
        vec![None, Some(work)]
    );
    assert_eq!(
        vault
            .companion_profile_access_grant(&other, &owen, None)
            .expect("lookup"),
        None
    );
    assert_eq!(
        vault
            .companion_profile_access_grant(&other, &owen, Some(&home))
            .expect("lookup"),
        Some(other_home)
    );
    assert_eq!(
        vault
            .companion_profile_access_grant(&reader, &yuki, Some(&home))
            .expect("lookup"),
        Some(yuki_wide)
    );
    assert_index_answers_as_walk(&vault, &asked);

    // A revoke: the facet grant is the first that admits the read.
    vault.revoke_access_grant(&wide, 2).expect("revoke");
    assert_eq!(
        vault
            .companion_profile_access_grant(&reader, &owen, Some(&work))
            .expect("lookup"),
        Some(at_work)
    );
    assert_eq!(
        vault
            .companion_profile_access_grant(&reader, &owen, None)
            .expect("lookup"),
        None
    );
    assert_index_answers_as_walk(&vault, &asked);

    // Renewed access under a new grant id.
    let renewed = grant(&vault, reader, owen, None);
    assert_eq!(
        vault
            .companion_profile_access_grant(&reader, &owen, None)
            .expect("lookup"),
        Some(renewed)
    );
    assert_index_answers_as_walk(&vault, &asked);

    // A delete, landed or refused: either way the index answers as the walk.
    let _ = vault.delete_entity(&at_work);
    assert_index_answers_as_walk(&vault, &asked);

    // A vault older than the index: the reads walk, and the reopen rebuilds
    // the index from the ACCESS_GRANT rows.
    let kept = indexed(&vault, &asked);
    let served = answers(&vault, &asked);
    doors::drop_index(&vault).expect("drop the index");
    assert!(!doors::index_complete(&vault).expect("flag"));
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("reopen");
    assert!(
        doors::index_complete(&vault).expect("flag"),
        "the reopen rebuilds the index"
    );
    assert_eq!(indexed(&vault, &asked), kept);
    assert_eq!(answers(&vault, &asked), served);

    // An undecodable grant row anywhere: every read walks and fails closed
    // once its walk meets the row (the persona list reads every grant; the
    // lookup stops at its first admitting grant, so ask a pair with none),
    // and so after a reopen that rebuilds the dropped index from the rows.
    let fails_closed = |vault: &Vault| {
        assert!(
            indexed(vault, &asked).iter().all(Option::is_none),
            "the reads walk"
        );
        assert!(
            vault
                .companion_profile_access_grant(&other, &yuki, None)
                .is_err()
        );
        assert!(
            vault
                .authorized_companion_profile_facets(&reader, &owen)
                .is_err()
        );
    };
    doors::put_undecodable_grant(&vault, &EntityId::now(), b"not-msgpack").expect("a stored row");
    fails_closed(&vault);
    doors::drop_index(&vault).expect("drop the index");
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("reopen");
    assert!(doors::index_complete(&vault).expect("flag"));
    fails_closed(&vault);
}

#[test]
fn a_persona_list_reads_only_its_own_grants_from_the_index() {
    const PEOPLE: usize = 40;
    const READERS: usize = 50;
    const CALLS: u32 = 50;
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let people: Vec<EntityId> = (0..PEOPLE).map(|_| put_person(&vault)).collect();
    let readers: Vec<EntityId> = (0..READERS).map(|_| EntityId::now()).collect();
    for reader in &readers {
        for person in &people {
            grant(&vault, *reader, *person, None);
        }
    }
    let (reader, person) = (EntityId::now(), people[PEOPLE / 2]);
    let own = grant(&vault, reader, person, None);
    let grants = PEOPLE * READERS + 1;

    let time = |vault: &Vault| {
        let start = Instant::now();
        for _ in 0..CALLS {
            assert_eq!(
                vault
                    .authorized_companion_profile_facets(&reader, &person)
                    .expect("list"),
                vec![None]
            );
        }
        start.elapsed().as_micros() / u128::from(CALLS)
    };
    assert_eq!(
        doors::indexed_grants(&vault, &reader, &person).expect("index"),
        Some(vec![own])
    );
    let indexed_us = time(&vault);
    doors::drop_index(&vault).expect("drop the index");
    let walked_us = time(&vault);
    println!(
        "DIAG companion_grant_index: grants={grants} persona list per call: \
         indexed_us={indexed_us} walked_us={walked_us}"
    );

    // The owner's check: none while the index serves, one once it walks.
    doors::rebuild_index(&vault).expect("rebuild the index");
    let scan = EngineScan::AccessGrantRows;
    let grant_checks = |vault: &Vault| {
        vault
            .scan_checks()
            .expect("checks")
            .iter()
            .filter(|check| check.scan == scan.code())
            .count()
    };
    vault.set_scan_threshold(scan, 2).expect("threshold");
    vault
        .authorized_companion_profile_facets(&reader, &person)
        .expect("list");
    assert_eq!(
        grant_checks(&vault),
        0,
        "the index reads no grant past the pair's own"
    );
    doors::drop_index(&vault).expect("drop the index");
    vault
        .authorized_companion_profile_facets(&reader, &person)
        .expect("list");
    assert_eq!(
        grant_checks(&vault),
        1,
        "the walk reads past its threshold row"
    );
}
