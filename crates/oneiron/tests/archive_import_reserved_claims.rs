//! Whole-vault archive restore of a vault that holds reserved claims
//! (FIX row ARCHIVE-IMPORT-RESERVED-CLAIM-ABORTS).
//!
//! On main the import decodes every claim outside its routed families with
//! the reserved flag off (`decode_import_claim`), so one reserved claim
//! anywhere in the archive aborts the whole restore with `ReservedPredicate`.
//!
//! * `a_fresh_owner_vault_restores_whole_as_its_owner`: the control. A fresh
//!   vault with one ordinary PERSON row holds no reserved claim: a fresh vault
//!   stores no `vault.default_facet` claim (the default facet is the owner's
//!   substrate FACET until the owner sets another one).
//! * `an_archive_with_the_owner_default_facet_restores_whole_as_its_owner`:
//!   the owner sets the vault default facet (`Vault::set_default_facet`
//!   stores a reserved `vault.default_facet` CLAIM about the owner). The
//!   owner's restore into a fresh vault sets the same default facet.
//! * `the_actorless_import_keeps_the_destination_default_facet` and
//!   `an_owner_restore_into_a_used_vault_keeps_its_default_facet`: any other
//!   import keeps the archived default facet as archive data
//!   (`TargetDefaultFacetKept`), and the destination's default facet stays.
//!   The receipt's `destination_omissions` is pinned in
//!   `archive_import_reserved_families.rs`: this file builds on main as well,
//!   so it runs red there.
//! * `an_archive_with_a_board_turn_restores_whole_as_its_owner`: one board
//!   turn (`Vault::record_board_turn`) writes `world_access.*` and
//!   `activated.*` claims; they stay archive data
//!   (`LocalHistoryNotRestored`) and the rest of the vault restores.
//! * `dreamer::a_dreamer_landed_claim_restores_without_its_machine_history`
//!   (needs `--cfg oneiron_test_support`): a claim the Dreamer landed, signed
//!   as a MACHINE, restores without its `machine.*` birth carriers, which
//!   stay archive data (`LocalHistoryNotRestored`).
//!
//! Public doors only, plus `test_doors::consolidation` for the Dreamer;
//! neutral fixtures (`owen`); vaults in tempdirs. Each destination opens at
//! least one wall-clock second after its source (sleep 1100 ms), as in
//! `whole_vault_restore_seeds.rs`. Reasons are compared in their `Debug` form.

use std::collections::BTreeSet;
use std::io::Cursor;

use oneiron::consent::AuthenticatedOwner;
use oneiron::context_board::{BoardSelection, BoardTurn};
use oneiron::registry::{
    ENTITY_TYPE_ASSET_TEXT, ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN,
};
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use rmpv::Value;

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

fn owner_actor(vault: &Vault) -> WriteActor {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    WriteActor::new(owner, EdgeActorClass::Human)
}

fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof")
}

fn map_body(key: &str, text: &str) -> Vec<u8> {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![(Value::from(key), Value::from(text))]),
    )
    .expect("encode map body");
    body
}

fn put_row(vault: &Vault, id: &EntityId, entity_type: u8, body: &[u8]) {
    vault
        .put_entity(
            id,
            entity_type,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
            body,
        )
        .expect("ordinary row");
}

fn put_named(vault: &Vault, id: &EntityId, entity_type: u8, name: &str) {
    put_row(vault, id, entity_type, &map_body("name", name));
}

fn export_whole(vault: &Vault) -> Vec<u8> {
    vault
        .export_whole_vault(true)
        .expect("whole-vault export")
        .bytes()
        .to_vec()
}

/// The manifest's import omissions of `archive`, as (entity id, reason in
/// its `Debug` form).
fn import_omissions(reader: &Vault, archive: &[u8]) -> Vec<(String, String)> {
    reader
        .read_whole_vault_archive(archive)
        .expect("read the archive")
        .manifest
        .import_omissions
        .iter()
        .map(|omission| (omission.entity_id.clone(), format!("{:?}", omission.reason)))
        .collect()
}

/// Restores `archive` into a fresh vault as that vault's bound owner, the
/// door the CLI `import archive` takes when the owner authenticates.
fn restore_into_fresh_vault_as_owner(
    archive: &[u8],
) -> (tempfile::TempDir, Vault, oneiron::Result<()>) {
    let (dir, dest) = open_later_vault();
    let owner = owner_proof(&dest);
    let restored = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(archive), &owner)
        .map(|_| ());
    (dir, dest, restored)
}

/// A source vault whose owner set the `work` FACET as the vault default:
/// returns the vault, its archive and the `work` FACET.
fn source_with_default_facet() -> (tempfile::TempDir, Vault, Vec<u8>, EntityId) {
    let (dir, source) = open_vault();
    let owner = owner_actor(&source);
    let owen = EntityId::now();
    put_named(&source, &owen, ENTITY_TYPE_PERSON, "owen");
    let work = EntityId::now();
    put_named(&source, &work, ENTITY_TYPE_FACET, "work");
    source
        .set_default_facet(work, owner)
        .expect("the owner sets the vault default facet");
    assert_eq!(source.default_facet().expect("default facet"), work);
    let archive = export_whole(&source);
    (dir, source, archive, work)
}

#[test]
fn a_fresh_owner_vault_restores_whole_as_its_owner() {
    let (_source_dir, source) = open_vault();
    let _owner = owner_actor(&source);
    let owen = EntityId::now();
    put_named(&source, &owen, ENTITY_TYPE_PERSON, "owen");
    let archive = export_whole(&source);

    let (_dest_dir, dest, restored) = restore_into_fresh_vault_as_owner(&archive);

    if let Err(error) = restored {
        panic!("a fresh owner vault's whole archive must restore: {error:?}");
    }
    assert_eq!(
        dest.get_entity_type(&owen).expect("read owen"),
        Some(ENTITY_TYPE_PERSON)
    );
}

#[test]
fn an_archive_with_the_owner_default_facet_restores_whole_as_its_owner() {
    let (_source_dir, _source, archive, work) = source_with_default_facet();

    let (_dest_dir, dest, restored) = restore_into_fresh_vault_as_owner(&archive);

    if let Err(error) = restored {
        panic!(
            "the owner's whole archive holding a vault.default_facet claim must restore: {error:?}"
        );
    }
    assert_eq!(
        dest.get_entity_type(&work).expect("read the work facet"),
        Some(ENTITY_TYPE_FACET)
    );
    assert_eq!(
        dest.default_facet().expect("the restored default facet"),
        work,
        "the owner's restore into a fresh vault sets the archived default facet"
    );
}

#[test]
fn the_actorless_import_keeps_the_destination_default_facet() {
    let (_source_dir, _source, archive, work) = source_with_default_facet();
    let (_dest_dir, dest) = open_later_vault();
    let before = dest
        .default_facet()
        .expect("the destination's default facet");

    if let Err(error) = dest.import_whole_vault_archive_from(Cursor::new(&archive)) {
        panic!(
            "an actorless import of an archive holding a vault.default_facet claim must succeed: {error:?}"
        );
    }

    assert_eq!(
        dest.get_entity_type(&work).expect("read the work facet"),
        Some(ENTITY_TYPE_FACET)
    );
    assert_eq!(
        dest.default_facet()
            .expect("the destination's default facet"),
        before,
        "an actorless import never sets the default facet"
    );
    assert_ne!(before, work);
}

#[test]
fn an_owner_restore_into_a_used_vault_keeps_its_default_facet() {
    let (_source_dir, _source, archive, work) = source_with_default_facet();
    let (_dest_dir, dest) = open_later_vault();
    let yuki = EntityId::now();
    put_named(&dest, &yuki, ENTITY_TYPE_PERSON, "yuki");
    let before = dest
        .default_facet()
        .expect("the destination's default facet");
    let owner = owner_proof(&dest);

    if let Err(error) = dest.import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &owner)
    {
        panic!(
            "the owner's import into a used vault of an archive holding a vault.default_facet claim must succeed: {error:?}"
        );
    }

    assert_eq!(
        dest.default_facet()
            .expect("the destination's default facet"),
        before,
        "a used vault keeps its own default facet"
    );
    assert_ne!(before, work);
}

#[test]
fn an_archive_with_a_board_turn_restores_whole_as_its_owner() {
    let (_source_dir, source) = open_vault();
    let _owner = owner_actor(&source);
    let owen = EntityId::now();
    put_named(&source, &owen, ENTITY_TYPE_PERSON, "owen");
    let alpha = EntityId::now();
    put_row(
        &source,
        &alpha,
        ENTITY_TYPE_ASSET_TEXT,
        &map_body("content", "scope alpha"),
    );
    let pinned = EntityId::now();
    put_row(
        &source,
        &pinned,
        ENTITY_TYPE_ASSET_TEXT,
        &map_body("content", "a pinned memory"),
    );
    let turn = EntityId::now();
    put_row(
        &source,
        &turn,
        ENTITY_TYPE_TURN,
        &map_body("content", "first"),
    );
    let board = source
        .record_board_turn(
            &BoardTurn {
                turn,
                owner: owen,
                at: 1,
                selection: BoardSelection {
                    allowed: BTreeSet::from([alpha]),
                    active: BTreeSet::from([alpha]),
                    pinned: BTreeSet::from([pinned]),
                    ..Default::default()
                },
            },
            10,
        )
        .expect("one board turn");
    assert!(
        !board.changed_claims.is_empty(),
        "the board turn wrote its history claims"
    );
    let archive = export_whole(&source);

    let (_dest_dir, dest, restored) = restore_into_fresh_vault_as_owner(&archive);

    if let Err(error) = restored {
        panic!("the owner's whole archive holding board history must restore: {error:?}");
    }
    assert_eq!(
        dest.get_entity_type(&turn).expect("read the turn"),
        Some(ENTITY_TYPE_TURN)
    );
    let omissions = import_omissions(&dest, &archive);
    for claim in &board.changed_claims {
        assert_eq!(
            dest.get_entity_type(claim)
                .expect("read a board history claim"),
            None,
            "board history stays archive data"
        );
        assert!(
            omissions
                .iter()
                .any(|(id, reason)| *id == claim.to_hex() && reason == "LocalHistoryNotRestored"),
            "the manifest names {claim:?} as LocalHistoryNotRestored: {omissions:?}"
        );
    }
}

#[cfg(oneiron_test_support)]
mod dreamer {
    use super::*;
    use oneiron::test_doors::consolidation::{consolidate_unbound_turn, open_dreamer_vault};

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

    #[test]
    fn a_dreamer_landed_claim_restores_without_its_machine_history() {
        let source_dir = tempfile::tempdir().expect("tempdir");
        let source = open_dreamer_vault(source_dir.path(), "reader").expect("the Dreamer's vault");
        let pass = consolidate_unbound_turn(&source, "call me Owen", None, None, &reply())
            .expect("one consolidation pass");
        let [claim] = pass.landed.as_slice() else {
            panic!("one landed claim, found {}", pass.landed.len());
        };
        let archive = export_whole(&source);

        let (_dest_dir, dest, restored) = restore_into_fresh_vault_as_owner(&archive);

        if let Err(error) = restored {
            panic!(
                "the owner's whole archive holding a Dreamer-landed claim must restore: {error:?}"
            );
        }
        let restored_claim = dest
            .get_claim(claim)
            .expect("read the landed claim")
            .expect("the landed claim restores without its machine history");
        assert_eq!(restored_claim.predicate, "profile.name");
        let machine_omissions: Vec<(String, String)> = import_omissions(&dest, &archive)
            .into_iter()
            .filter(|(id, _)| {
                EntityId::from_hex(id)
                    .ok()
                    .and_then(|id| source.get_claim(&id).ok().flatten())
                    .is_some_and(|body| body.predicate.starts_with("machine."))
            })
            .collect();
        assert!(
            !machine_omissions.is_empty(),
            "the Dreamer's signed landing wrote machine history the archive carries"
        );
        assert!(
            machine_omissions
                .iter()
                .all(|(_, reason)| reason == "LocalHistoryNotRestored"),
            "machine history stays archive data: {machine_omissions:?}"
        );
    }
}
