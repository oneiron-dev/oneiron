//! Fix list row WHOLE-VAULT-IMPORT-REFUSES-RESERVED-OWNER-EDGES, identity
//! topology part (OWNEDGES-SHELL-RESTORE = A): a whole-vault archive of a
//! vault where one PERSON was merged into another imports. The archived
//! `merged_into` link stays out, as the type-76 event it follows does: the
//! merged PERSON is back as a separate Active row beside its survivor, and
//! the import receipt counts it.
//!
//! * `owner_restore_brings_the_merged_row_back_separate`: the owner's
//!   restore into a fresh vault.
//! * `actor_import_brings_the_merged_row_back_separate`: through the
//!   actor-taking door.
//! * `actorless_import_again_counts_the_merged_row_again`: the actorless
//!   door, and the same archive again leaves the link out again.
//!
//! Red on the base (#9310's head 5426698e96ff): each test fails at its
//! first import, which refuses the archived `merged_into` edge with
//! `Registry(ReservedEdgeKind("merged_into"))`; the source preconditions
//! pass. The receipt counter is new, so its assertions (`assert_counted`)
//! come with the fix commit, not the tests-only one.
//!
//! Vaults in tempdirs, every step through public doors. The source signs
//! with an in-memory install keystore, as a local merge seals with this
//! install's key. Each destination opens at least one wall-clock second
//! after its source (sleep 1100 ms), as in `whole_vault_restore_seeds.rs`.
//! Run with `cargo test --locked -p oneiron --all-features --test
//! whole_vault_restore_identity_topology_shells`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;
use std::sync::Arc;

use oneiron::batch::export::WholeVaultImportReceipt;
use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeKind;
use oneiron::identity_topology::{
    EntityLifecycleState, IdentityOpEvidence, IdentityOpOutcome, IdentityOpWrite,
    IdentityTopologyOp, MergeOp, SurvivorshipPlan,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::{ClaimSource, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

/// A fresh SEEDED destination whose engine-seed seconds differ from the
/// source's: any 1100 ms interval crosses a second boundary.
fn open_later_vault() -> (tempfile::TempDir, Vault) {
    std::thread::sleep(std::time::Duration::from_millis(1100));
    open_vault()
}

fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof")
}

fn put_person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
            b"person fixture",
        )
        .expect("put the person");
    id
}

/// What the source vault holds: `merged` merged into `survivor`, and its
/// whole-vault archive.
struct Merged {
    archive: Vec<u8>,
    merged: EntityId,
    survivor: EntityId,
}

/// A source vault where one PERSON was merged into another through the
/// local identity-topology door (an auto merge, sealed by this install).
fn merged_archive() -> Merged {
    let (_dir, source) = open_vault();
    source.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    source
        .prepare_install_signing()
        .expect("load this install's signing keys");
    let merged = put_person(&source);
    let survivor = put_person(&source);
    let outcome = source
        .apply_identity_topology_op(
            &IdentityTopologyOp::Merge(MergeOp {
                sources: vec![merged],
                survivor,
                evidence: IdentityOpEvidence {
                    refs: Vec::new(),
                    rationale: "one person under two records".to_owned(),
                },
                survivorship_plan: SurvivorshipPlan::ReadThrough,
            }),
            &IdentityOpWrite::auto(ClaimSource::UserStated),
            200,
        )
        .expect("merge the two PERSONs");
    assert!(
        matches!(outcome, IdentityOpOutcome::Applied { .. }),
        "precondition: the merge applies: {outcome:?}"
    );
    assert!(
        source
            .edge_exists(&merged, EdgeKind::MergedInto, &survivor)
            .expect("read the source merged_into edge"),
        "precondition: the merged PERSON's shell edge names the survivor"
    );
    assert_eq!(
        source
            .entity_lifecycle_state(&merged)
            .expect("source lifecycle"),
        EntityLifecycleState::Merged,
        "precondition: the merged PERSON is a Merged shell"
    );
    let archive = source
        .export_whole_vault(true)
        .expect("whole-vault export")
        .bytes()
        .to_vec();
    Merged {
        archive,
        merged,
        survivor,
    }
}

/// `dest` holds both PERSONs Active, with no `merged_into` link between
/// them.
fn assert_back_separate(dest: &Vault, restored: &Merged) {
    assert!(
        dest.targets(&restored.merged, EdgeKind::MergedInto, None)
            .expect("read the merged PERSON's shell edges")
            .is_empty(),
        "the merged_into link stays in the archive"
    );
    for (row, name) in [(restored.merged, "merged"), (restored.survivor, "survivor")] {
        assert_eq!(
            dest.get_entity_type(&row).expect("read the restored row"),
            Some(ENTITY_TYPE_PERSON),
            "the {name} PERSON is restored"
        );
        assert_eq!(
            dest.entity_lifecycle_state(&row)
                .expect("restored lifecycle"),
            EntityLifecycleState::Active,
            "the {name} PERSON is Active here"
        );
    }
}

/// The import's receipt counts the one merged row back separate.
fn assert_counted(receipt: &WholeVaultImportReceipt) {
    assert_eq!(
        receipt.unrestored_identity_topology_shells, 1,
        "the receipt counts the merged row back separate"
    );
}

#[test]
fn owner_restore_brings_the_merged_row_back_separate() {
    let restored = merged_archive();
    let (_dir, dest) = open_later_vault();
    let owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&restored.archive), &owner)
        .expect("the owner's restore completes");
    assert_back_separate(&dest, &restored);
    assert_counted(&receipt);
}

#[test]
fn actor_import_brings_the_merged_row_back_separate() {
    let restored = merged_archive();
    let (_dir, dest) = open_later_vault();
    let owner = dest.ensure_embedded_owner_actor().expect("embedded owner");
    let receipt = dest
        .import_whole_vault_archive_with_actor(
            &restored.archive,
            &WriteActor::new(owner, EdgeActorClass::Human),
        )
        .expect("the actor import completes");
    assert_back_separate(&dest, &restored);
    assert_counted(&receipt);
}

#[test]
fn actorless_import_again_counts_the_merged_row_again() {
    let restored = merged_archive();
    let (_dir, dest) = open_later_vault();
    let receipt = dest
        .import_whole_vault_archive_from(Cursor::new(&restored.archive))
        .expect("the actorless import completes");
    assert_back_separate(&dest, &restored);
    assert_counted(&receipt);
    let again = dest
        .import_whole_vault_archive_from(Cursor::new(&restored.archive))
        .expect("the same archive again completes");
    assert_back_separate(&dest, &restored);
    assert_counted(&again);
}
