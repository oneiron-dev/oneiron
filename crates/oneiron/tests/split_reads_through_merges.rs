//! A split reads its entity's claims through the merges into it (ARCH-0055 §3
//! and §4; E2E MEMORY-07): a claim a merged source holds keeps its subject,
//! the source, and still belongs to the survivor. The split's map assigns it,
//! and the survivor's remaining claims include it until a split assigns it
//! away. Both readers read the same membership.

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

fn evidence() -> IdentityOpEvidence {
    IdentityOpEvidence {
        refs: Vec::new(),
        rationale: "fixture rationale".to_owned(),
    }
}

fn apply(vault: &Vault, op: &IdentityTopologyOp, now: u64) {
    match vault
        .apply_identity_topology_op(op, &IdentityOpWrite::auto(ClaimSource::Inferred), now)
        .expect("apply identity op")
    {
        IdentityOpOutcome::Applied { .. } => {}
        other => panic!("expected the op applied, got {other:?}"),
    }
}

fn merge(vault: &Vault, source: EntityId, survivor: EntityId) {
    apply(
        vault,
        &IdentityTopologyOp::Merge(MergeOp {
            sources: vec![source],
            survivor,
            evidence: evidence(),
            survivorship_plan: SurvivorshipPlan::ReadThrough,
        }),
        150,
    );
}

fn split(vault: &Vault, entity: EntityId, heads: Vec<EntityId>, map: &[(EntityId, EntityId)]) {
    apply(
        vault,
        &IdentityTopologyOp::Split(SplitOp {
            entity,
            heads,
            reassignment: ReassignmentMap {
                entries: map
                    .iter()
                    .map(|&(claim, head)| ReassignmentEntry {
                        item: ClaimSubject::Entity(claim),
                        target: ReassignmentTarget::Head(head),
                    })
                    .collect(),
            },
            evidence: evidence(),
        }),
        200,
    );
}

fn subject_of(vault: &Vault, claim: EntityId) -> ClaimSubject {
    vault
        .get_claim(&claim)
        .expect("read claim")
        .expect("claim exists")
        .subject
}

#[test]
fn a_split_assigns_a_claim_held_by_a_source_merged_into_it() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x61);
    let source = put_person(&vault, 0x62);
    let north = put_person(&vault, 0x63);
    let south = put_person(&vault, 0x64);
    let own = put_claim(&vault, 0x71, survivor);
    let inherited = put_claim(&vault, 0x72, source);
    merge(&vault, source, survivor);

    split(
        &vault,
        survivor,
        vec![north, south],
        &[(own, north), (inherited, south)],
    );

    assert_eq!(vault.claims_assigned_to(&north).expect("north"), vec![own]);
    assert_eq!(
        vault.claims_assigned_to(&south).expect("south"),
        vec![inherited],
        "the merged source's claim is one of the survivor's, so the map assigns it"
    );
    assert!(
        vault
            .claims_remaining_on_origin(&survivor)
            .expect("remaining")
            .is_empty()
    );
    // The assignment rewrites no subject: the merged source's claim still
    // names the source.
    assert_eq!(subject_of(&vault, inherited), ClaimSubject::Entity(source));
}

#[test]
fn a_claim_held_by_a_merged_source_remains_on_the_survivor_until_assigned() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x61);
    let source = put_person(&vault, 0x62);
    let north = put_person(&vault, 0x63);
    let own = put_claim(&vault, 0x71, survivor);
    let inherited = put_claim(&vault, 0x72, source);
    merge(&vault, source, survivor);

    split(&vault, survivor, vec![north], &[(own, north)]);

    assert_eq!(vault.claims_assigned_to(&north).expect("north"), vec![own]);
    assert_eq!(
        vault
            .claims_remaining_on_origin(&survivor)
            .expect("remaining"),
        vec![inherited],
        "the unassigned claim of the merged source still reads as the survivor's"
    );
}

#[test]
fn a_split_still_drops_a_claim_of_an_unrelated_entity() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0x61);
    let source = put_person(&vault, 0x62);
    let stranger = put_person(&vault, 0x65);
    let north = put_person(&vault, 0x63);
    let inherited = put_claim(&vault, 0x72, source);
    let foreign = put_claim(&vault, 0x73, stranger);
    merge(&vault, source, survivor);

    split(
        &vault,
        survivor,
        vec![north],
        &[(inherited, north), (foreign, north)],
    );

    assert_eq!(
        vault.claims_assigned_to(&north).expect("north"),
        vec![inherited],
        "a claim of an entity never merged into the survivor is not the survivor's to assign"
    );
    assert_eq!(
        vault
            .claims_remaining_on_origin(&stranger)
            .expect("stranger"),
        vec![foreign]
    );
}
