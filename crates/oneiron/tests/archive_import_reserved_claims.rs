//! Whole-vault archive restore of a vault whose owner holds a reserved claim
//! (FIX row ARCHIVE-IMPORT-RESERVED-CLAIM-ABORTS).
//!
//! * `a_fresh_owner_vault_restores_whole_as_its_owner`: a fresh vault with one
//!   ordinary PERSON row holds no reserved claim, so its archive restores. A
//!   fresh vault stores no `vault.default_facet` claim: the default facet is
//!   the owner's substrate FACET until the owner sets another one.
//! * `an_archive_with_the_owner_default_facet_restores_whole_as_its_owner`:
//!   the owner sets the vault default facet (`Vault::set_default_facet`, which
//!   stores a reserved `vault.default_facet` CLAIM about the owner). On main
//!   the restore of that vault's whole archive into a fresh vault aborts with
//!   `ReservedPredicate`: the import decodes every claim outside its routed
//!   families with the reserved flag off (`decode_import_claim`), so the owner
//!   cannot restore their own vault.
//!
//! Public doors only; neutral fixtures (`owen`); vaults in tempdirs. Each
//! destination opens at least one wall-clock second after its source (sleep
//! 1100 ms), as in `whole_vault_restore_seeds.rs`.

use std::io::Cursor;

use oneiron::consent::AuthenticatedOwner;
use oneiron::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON};
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

fn named_body(name: &str) -> Vec<u8> {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![(Value::from("name"), Value::from(name))]),
    )
    .expect("encode named body");
    body
}

fn put_named(vault: &Vault, id: &EntityId, entity_type: u8, name: &str) {
    vault
        .put_entity(
            id,
            entity_type,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
            &named_body(name),
        )
        .expect("ordinary named row");
}

fn export_whole(vault: &Vault) -> Vec<u8> {
    vault
        .export_whole_vault(true)
        .expect("whole-vault export")
        .bytes()
        .to_vec()
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
    let (_source_dir, source) = open_vault();
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

    let (_dest_dir, dest, restored) = restore_into_fresh_vault_as_owner(&archive);

    if let Err(error) = restored {
        panic!(
            "the owner's whole archive holding a vault.default_facet claim must restore: {error:?}"
        );
    }
    assert_eq!(
        dest.get_entity_type(&owen).expect("read owen"),
        Some(ENTITY_TYPE_PERSON)
    );
    assert_eq!(
        dest.get_entity_type(&work).expect("read the work facet"),
        Some(ENTITY_TYPE_FACET)
    );
}
