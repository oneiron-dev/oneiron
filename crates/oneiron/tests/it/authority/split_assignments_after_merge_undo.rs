//! Undoing a merge leaves a split of the survivor the assignments a replica
//! derives from the same history (#6924 review P1; ARCH-0055 §3, §4). A merge
//! reads its source's claims through the survivor, so a split of the
//! survivor may assign them. Once the merge is undone they are the source's
//! again. The local undo door and a replica's reconcile must agree.

#![cfg(oneiron_test_support)]

use oneiron::identity_topology::{
    IdentityOpEvidence, IdentityOpOutcome, IdentityOpWrite, IdentityTopologyOp, MergeOp,
    ReassignmentEntry, ReassignmentMap, ReassignmentTarget, SplitOp, SurvivorshipPlan,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    TimeRange, Vault, VaultConfig,
};

const AT: TimeRange = TimeRange {
    start: 100,
    end: 100,
};

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("vault dir");
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    let vault = Vault::open(dir.path(), config).expect("open vault");
    // An identity op is sealed with this install's machine key, which a host
    // loads from its keystore after each open.
    vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault
        .prepare_install_signing()
        .expect("load this install's signing keys");
    (dir, vault)
}

fn id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("fixture id")
}

fn put_person(vault: &Vault, byte: u8) -> EntityId {
    let person = id(byte);
    vault
        .put_entity(&person, ENTITY_TYPE_PERSON, AT, AT.start, b"person fixture")
        .expect("put person");
    person
}

/// A committed claim about `subject`. `profile.` is the prefix the default
/// policy manifest rates `normal`, so the Gate commits it.
fn put_claim(vault: &Vault, byte: u8, subject: EntityId) -> EntityId {
    let claim = id(byte);
    vault
        .put_claim(
            &claim,
            &ClaimBody::new(
                "profile.note",
                ClaimSubject::Entity(subject),
                rmpv::Value::from(format!("fixture {byte:#x}")),
                0.9,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            )
            .expect("claim body"),
            AT,
            AT.start,
        )
        .expect("put claim");
    claim
}

fn write() -> IdentityOpWrite {
    IdentityOpWrite::auto(ClaimSource::Inferred)
}

/// Applies `op` at `now` and answers its ledger event.
fn apply(vault: &Vault, op: &IdentityTopologyOp, now: u64) -> EntityId {
    match vault
        .apply_identity_topology_op(op, &write(), now)
        .expect("apply identity op")
    {
        IdentityOpOutcome::Applied { event, .. } => event,
        other => panic!("expected the op applied, got {other:?}"),
    }
}

fn merge(vault: &Vault, source: EntityId, survivor: EntityId, now: u64) -> EntityId {
    apply(
        vault,
        &IdentityTopologyOp::Merge(MergeOp {
            sources: vec![source],
            survivor,
            evidence: IdentityOpEvidence {
                refs: Vec::new(),
                rationale: "fixture rationale".to_owned(),
            },
            survivorship_plan: SurvivorshipPlan::ReadThrough,
        }),
        now,
    )
}

fn split(vault: &Vault, entity: EntityId, head: EntityId, claims: &[EntityId]) {
    apply(
        vault,
        &IdentityTopologyOp::Split(SplitOp {
            entity,
            heads: vec![head],
            reassignment: ReassignmentMap {
                entries: claims
                    .iter()
                    .map(|&claim| ReassignmentEntry {
                        item: ClaimSubject::Entity(claim),
                        target: ReassignmentTarget::Head(head),
                    })
                    .collect(),
            },
            evidence: IdentityOpEvidence {
                refs: Vec::new(),
                rationale: "fixture rationale".to_owned(),
            },
        }),
        200,
    );
}

fn undo(vault: &Vault, event: EntityId) {
    match vault
        .undo_identity_topology_event(&event, &write(), 300)
        .expect("undo the merge")
    {
        IdentityOpOutcome::Applied { .. } => {}
        other => panic!("expected the undo applied, got {other:?}"),
    }
}

fn assigned_to(vault: &Vault, head: EntityId) -> Vec<EntityId> {
    let mut claims = vault.claims_assigned_to(&head).expect("assigned claims");
    claims.sort();
    claims
}

/// The replica's half: the reconcile a sync ingest runs, over the same ledger.
fn replica_assigned_to(vault: &Vault, head: EntityId) -> Vec<EntityId> {
    oneiron::test_doors::reconcile_identity_topology(vault).expect("reconcile as a replica");
    assigned_to(vault, head)
}

#[test]
fn undoing_a_merge_leaves_the_split_assignments_a_replica_derives() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x61);
    let source = put_person(&vault, 0x62);
    let head = put_person(&vault, 0x63);
    let own = put_claim(&vault, 0x71, survivor);
    let inherited = put_claim(&vault, 0x72, source);
    let merged = merge(&vault, source, survivor, 150);
    split(&vault, survivor, head, &[own, inherited]);
    assert_eq!(assigned_to(&vault, head), vec![own, inherited]);

    undo(&vault, merged);

    let local = assigned_to(&vault, head);
    assert_eq!(
        local,
        vec![own],
        "with the merge undone the source's claim is no longer the survivor's to assign"
    );
    assert_eq!(
        replica_assigned_to(&vault, head),
        local,
        "a replica derives the same assignments from the same history"
    );
}

#[test]
fn undoing_a_merge_under_a_merged_survivor_reaches_the_split_above_it() {
    let (_dir, vault) = open_vault();
    let top = put_person(&vault, 0x61);
    let middle = put_person(&vault, 0x62);
    let source = put_person(&vault, 0x64);
    let head = put_person(&vault, 0x63);
    let own = put_claim(&vault, 0x71, top);
    let inherited = put_claim(&vault, 0x72, source);
    let merged = merge(&vault, source, middle, 150);
    merge(&vault, middle, top, 160);
    split(&vault, top, head, &[own, inherited]);
    assert_eq!(assigned_to(&vault, head), vec![own, inherited]);

    undo(&vault, merged);

    let local = assigned_to(&vault, head);
    assert_eq!(
        local,
        vec![own],
        "the claim read through two merges, one now undone"
    );
    assert_eq!(replica_assigned_to(&vault, head), local);
}

#[test]
fn undoing_an_unrelated_merge_keeps_the_split_assignments() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x61);
    let source = put_person(&vault, 0x62);
    let head = put_person(&vault, 0x63);
    let other_survivor = put_person(&vault, 0x65);
    let other_source = put_person(&vault, 0x66);
    let own = put_claim(&vault, 0x71, survivor);
    let inherited = put_claim(&vault, 0x72, source);
    merge(&vault, source, survivor, 150);
    let unrelated = merge(&vault, other_source, other_survivor, 160);
    split(&vault, survivor, head, &[own, inherited]);

    undo(&vault, unrelated);

    let local = assigned_to(&vault, head);
    assert_eq!(local, vec![own, inherited]);
    assert_eq!(replica_assigned_to(&vault, head), local);
}
