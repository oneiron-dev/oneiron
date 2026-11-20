//! Fix list row RESTORE-KEEPS-MERGES-AND-SPLITS (Engine ANSWER 08:00 17 Nov
//! = B): the owner's restore of a whole-vault archive into a fresh vault
//! brings back each merge and split the source held current. The restore
//! decides each one again here, through this vault's topology door and
//! sealed by this install's key, so the archived type-76 events stay archive
//! data and the restored ones are this vault's own.
//!
//! * `owner_restore_into_a_fresh_vault_brings_merges_and_splits_back`: a
//!   merge, a split into two heads and a zero-head split come back; a merge
//!   the source undid does not.
//! * `owner_restore_into_a_vault_holding_rows_keeps_them_separate`: the
//!   owner's restore into a vault that already holds a row of its own
//!   restores none (as today).
//! * `actor_import_keeps_merges_and_splits_in_the_archive`: the actor door
//!   restores none (as today).
//!
//! Red on main d4c26c681b6: the first test fails at its first lifecycle
//! check (the merged PERSON is back Active); the other two pass and guard
//! the doors this row does not change. The receipt fields and the undo of a
//! restored merge are new, so their assertions come with the fix commit.
//!
//! Vaults in tempdirs, every step through public doors. Source and
//! destination each sign with their own in-memory install keystore. Each
//! destination opens at least one wall-clock second after its source (sleep
//! 1100 ms), as in `whole_vault_restore_seeds.rs`. Run with `cargo test
//! --locked -p oneiron --all-features --test
//! whole_vault_restore_merges_and_splits`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeKind;
use oneiron::identity_topology::{
    EntityLifecycleState, IdentityOpEvidence, IdentityOpOutcome, IdentityOpWrite,
    IdentityTopologyOp, MergeOp, ReassignmentMap, SplitOp, SurvivorshipPlan,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::{ClaimSource, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

/// A vault that signs with its own in-memory install keystore.
fn open_signing_vault() -> (tempfile::TempDir, Vault) {
    let (dir, vault) = open_vault();
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault
        .prepare_install_signing()
        .expect("load this install's signing keys");
    (dir, vault)
}

/// A fresh SEEDED signing destination whose engine-seed seconds differ from
/// the source's: any 1100 ms interval crosses a second boundary.
fn open_later_signing_vault() -> (tempfile::TempDir, Vault) {
    std::thread::sleep(std::time::Duration::from_millis(1100));
    open_signing_vault()
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

fn evidence(rationale: &str) -> IdentityOpEvidence {
    IdentityOpEvidence {
        refs: Vec::new(),
        rationale: rationale.to_owned(),
    }
}

/// Applies `op` on `vault` as an auto decision of this install; its event.
fn apply(vault: &Vault, op: IdentityTopologyOp, now: u64) -> EntityId {
    match vault
        .apply_identity_topology_op(&op, &IdentityOpWrite::auto(ClaimSource::UserStated), now)
        .expect("apply the topology op")
    {
        IdentityOpOutcome::Applied { event, .. } => event,
        other => panic!("precondition: the op applies: {other:?}"),
    }
}

fn merge(source: EntityId, survivor: EntityId) -> IdentityTopologyOp {
    IdentityTopologyOp::Merge(MergeOp {
        sources: vec![source],
        survivor,
        evidence: evidence("one person under two records"),
        survivorship_plan: SurvivorshipPlan::ReadThrough,
    })
}

fn split(entity: EntityId, heads: Vec<EntityId>) -> IdentityTopologyOp {
    IdentityTopologyOp::Split(SplitOp {
        entity,
        heads,
        reassignment: ReassignmentMap::default(),
        evidence: evidence("two people under one record"),
    })
}

/// What the source vault holds, and its whole-vault archive.
struct Topology {
    archive: Vec<u8>,
    /// Merged into `survivor`.
    merged: EntityId,
    survivor: EntityId,
    /// Split into `heads`.
    split: EntityId,
    heads: [EntityId; 2],
    /// Split into no head.
    gone: EntityId,
    /// Merged into `kept` and the merge undone.
    unmerged: EntityId,
    kept: EntityId,
}

impl Topology {
    /// Every PERSON the source holds.
    fn persons(&self) -> [EntityId; 8] {
        [
            self.merged,
            self.survivor,
            self.split,
            self.heads[0],
            self.heads[1],
            self.gone,
            self.unmerged,
            self.kept,
        ]
    }
}

/// A source vault with one current merge, one current split into two heads,
/// one current zero-head split and one undone merge, all through the local
/// identity-topology door (auto decisions sealed by this install).
fn topology_archive() -> Topology {
    let (_dir, source) = open_signing_vault();
    let merged = put_person(&source);
    let survivor = put_person(&source);
    let split_row = put_person(&source);
    let heads = [put_person(&source), put_person(&source)];
    let gone = put_person(&source);
    let unmerged = put_person(&source);
    let kept = put_person(&source);
    apply(&source, merge(merged, survivor), 200);
    apply(&source, split(split_row, heads.to_vec()), 210);
    apply(&source, split(gone, Vec::new()), 220);
    let undone = apply(&source, merge(unmerged, kept), 230);
    let outcome = source
        .undo_identity_topology_event(
            &undone,
            &IdentityOpWrite::auto(ClaimSource::UserStated),
            240,
        )
        .expect("undo the second merge");
    assert!(
        matches!(outcome, IdentityOpOutcome::Applied { .. }),
        "precondition: the undo applies: {outcome:?}"
    );
    for (row, state, name) in [
        (merged, EntityLifecycleState::Merged, "merged"),
        (split_row, EntityLifecycleState::Split, "split"),
        (gone, EntityLifecycleState::Split, "zero-head split"),
        (unmerged, EntityLifecycleState::Active, "unmerged"),
    ] {
        assert_eq!(
            source
                .entity_lifecycle_state(&row)
                .expect("source lifecycle"),
            state,
            "precondition: the {name} PERSON's state at the source"
        );
    }
    let archive = source
        .export_whole_vault(true)
        .expect("whole-vault export")
        .bytes()
        .to_vec();
    Topology {
        archive,
        merged,
        survivor,
        split: split_row,
        heads,
        gone,
        unmerged,
        kept,
    }
}

/// `dest` holds every source PERSON, each in `state_of`'s state.
fn assert_states(
    dest: &Vault,
    restored: &Topology,
    state_of: impl Fn(&EntityId) -> EntityLifecycleState,
) {
    for row in restored.persons() {
        assert_eq!(
            dest.get_entity_type(&row).expect("read the restored row"),
            Some(ENTITY_TYPE_PERSON),
            "PERSON {} is restored",
            row.to_hex()
        );
        assert_eq!(
            dest.entity_lifecycle_state(&row)
                .expect("restored lifecycle"),
            state_of(&row),
            "PERSON {} lifecycle here",
            row.to_hex()
        );
    }
}

/// `dest` holds no shell link between the source PERSONs: every row Active.
fn assert_back_separate(dest: &Vault, restored: &Topology) {
    assert_states(dest, restored, |_| EntityLifecycleState::Active);
    for row in restored.persons() {
        for kind in [EdgeKind::MergedInto, EdgeKind::SplitInto] {
            assert!(
                dest.targets(&row, kind, None)
                    .expect("read the shell edges")
                    .is_empty(),
                "PERSON {} has no {kind:?} link here",
                row.to_hex()
            );
        }
    }
}

#[test]
fn owner_restore_into_a_fresh_vault_brings_merges_and_splits_back() {
    let restored = topology_archive();
    let (_dir, dest) = open_later_signing_vault();
    let owner = owner_proof(&dest);
    dest.import_whole_vault_archive_from_as_owner(Cursor::new(&restored.archive), &owner)
        .expect("the owner's restore completes");
    assert_states(&dest, &restored, |row| {
        if *row == restored.merged {
            EntityLifecycleState::Merged
        } else if *row == restored.split || *row == restored.gone {
            EntityLifecycleState::Split
        } else {
            EntityLifecycleState::Active
        }
    });
    assert!(
        dest.edge_exists(&restored.merged, EdgeKind::MergedInto, &restored.survivor)
            .expect("read the merged_into link"),
        "the restored merge's shell link names the survivor"
    );
    for head in restored.heads {
        assert!(
            dest.edge_exists(&restored.split, EdgeKind::SplitInto, &head)
                .expect("read the split_into link"),
            "the restored split's shell link names head {}",
            head.to_hex()
        );
    }
    for (row, name) in [
        (restored.gone, "zero-head split"),
        (restored.unmerged, "unmerged"),
    ] {
        for kind in [EdgeKind::MergedInto, EdgeKind::SplitInto] {
            assert!(
                dest.targets(&row, kind, None)
                    .expect("read the shell edges")
                    .is_empty(),
                "the {name} PERSON has no {kind:?} link here"
            );
        }
    }
    assert!(
        !dest
            .edge_exists(&restored.unmerged, EdgeKind::MergedInto, &restored.kept)
            .expect("read the undone merge's link"),
        "the merge the source undid stays undone"
    );
}

#[test]
fn owner_restore_into_a_vault_holding_rows_keeps_them_separate() {
    let restored = topology_archive();
    let (_dir, dest) = open_later_signing_vault();
    put_person(&dest);
    let owner = owner_proof(&dest);
    dest.import_whole_vault_archive_from_as_owner(Cursor::new(&restored.archive), &owner)
        .expect("the owner's restore completes");
    assert_back_separate(&dest, &restored);
}

#[test]
fn actor_import_keeps_merges_and_splits_in_the_archive() {
    let restored = topology_archive();
    let (_dir, dest) = open_later_signing_vault();
    let owner = dest.ensure_embedded_owner_actor().expect("embedded owner");
    dest.import_whole_vault_archive_with_actor(
        &restored.archive,
        &WriteActor::new(owner, EdgeActorClass::Human),
    )
    .expect("the actor import completes");
    assert_back_separate(&dest, &restored);
}
