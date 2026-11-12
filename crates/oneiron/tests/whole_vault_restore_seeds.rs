//! Whole-vault archive restore into a fresh SEEDED vault: engine-seed
//! equivalence.
//!
//! * Unchanged engine seeds (the nine pack SKILLs with wall-clock seed times,
//!   their per-SKILL source carriers, the 14 system-agent subject `ClaimOf`
//!   edges and the pack-carrier `FacetOf` edges) compare apart from their
//!   seed times; the destination keeps its own rows, edges and times.
//! * `LfsCdc` keeps the destination's seed. The root stays as before.
//! * An edited seed still collides. Restoring the archive's edited seed is
//!   FIX row WHOLE-VAULT-RESTORE-EDITED-SEED-COLLISION; the owner restore door
//!   for expression preferences is FIX row
//!   OWNER-CLI-RESTORE-ACTORLESS-REFUSES-EXPRESSIONS.
//!
//! On the base (before seed equivalence):
//! * `unchanged_seeds_restore_into_a_fresh_vault_opened_later` fails: the
//!   import refuses with "import ID collides with different entity data" on
//!   the first pack SKILL whose seed second differs.
//! * `edited_seed_still_collides_through_the_actorless_door` passes: every
//!   pack seed collides there, so it pins only the head's behaviour, where
//!   the edited pack SKILL is the one row that still collides.
//!
//! Public doors only; neutral fixtures (`owen`); vaults in tempdirs. Each
//! destination opens at least one wall-clock second after its source (sleep
//! 1100 ms), so the pack seeds' seconds differ.

use std::collections::BTreeMap;

use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::skill::SkillLifecycle;
use oneiron::{EntityId, Result, TimeRange, Vault, VaultConfig};
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

fn encode(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).expect("encode fixture");
    bytes
}

fn person_body(name: &str) -> Vec<u8> {
    encode(&Value::Map(vec![(Value::from("name"), Value::from(name))]))
}

/// Every SKILL row id with its stored `learned_at`, read through a public
/// whole-vault export (each export row carries the stored header times).
fn skill_learned_times(vault: &Vault) -> Result<Vec<(String, u64)>> {
    let export = vault.export_whole_vault(true)?;
    let document = vault.read_whole_vault_archive(export.bytes())?;
    Ok(document
        .skills
        .iter()
        .map(|bundle| (bundle.entity.id.clone(), bundle.entity.learned_at))
        .collect())
}

/// Unchanged engine seeds restore into a fresh vault opened later: the
/// ordinary row lands and the destination keeps its own pack seed header.
#[test]
fn unchanged_seeds_restore_into_a_fresh_vault_opened_later() -> Result<()> {
    let (_dir, source) = open_vault();
    // One ordinary row through a public door.
    let owen = EntityId::now();
    let body = person_body("owen");
    source.put_entity(
        &owen,
        ENTITY_TYPE_PERSON,
        TimeRange {
            start: 100,
            end: 100,
        },
        100,
        &body,
    )?;
    let (_fresh_dir, fresh) = open_later_vault();
    // A pack SKILL: the same id on both sides with different seed seconds.
    // Bootstrap skills sit at zero in both vaults and no user skill is
    // imported here, so a differing pair can only be a wall-clock pack seed.
    let before: BTreeMap<String, u64> = skill_learned_times(&fresh)?.into_iter().collect();
    let mut pack: Option<(String, u64, u64)> = None;
    for (id, source_learned_at) in skill_learned_times(&source)? {
        if let Some(destination_learned_at) = before.get(&id)
            && *destination_learned_at != source_learned_at
        {
            pack = Some((id, source_learned_at, *destination_learned_at));
            break;
        }
    }
    let (pack_id, source_learned_at, destination_learned_at) =
        pack.expect("a pack SKILL with differing seed seconds");
    let export = source.export_whole_vault(true)?;
    fresh.import_whole_vault_archive(export.bytes())?;
    // The ordinary row lands.
    assert_eq!(
        fresh.get(&owen)?.as_deref(),
        Some(body.as_slice()),
        "the ordinary PERSON lands in the destination"
    );
    // The destination keeps its own pack seed header.
    let after: BTreeMap<String, u64> = skill_learned_times(&fresh)?.into_iter().collect();
    assert_eq!(
        after.get(&pack_id).copied(),
        Some(destination_learned_at),
        "the destination keeps its own pack seed header"
    );
    assert_ne!(
        destination_learned_at, source_learned_at,
        "the two vaults seeded their pack skills in different seconds"
    );
    Ok(())
}

/// An edited seed still collides through the actorless door: the import is
/// refused and the destination's seed row is unchanged.
#[test]
fn edited_seed_still_collides_through_the_actorless_door() -> Result<()> {
    let (_dir, source) = open_vault();
    // The edited census seed: one pack SKILL, lifecycle-flipped through the
    // public typed update door keeping its id. Pack seeds are the SKILL rows
    // with a wall-clock learned_at (bootstrap skills sit at zero). A state
    // flip is not content, so the fork law stays out of the way.
    let export = source.export_whole_vault(true)?;
    let document = source.read_whole_vault_archive(export.bytes())?;
    let mut active_pack = None;
    for bundle in &document.skills {
        if bundle.entity.learned_at == 0 {
            continue;
        }
        let id = EntityId::from_hex(&bundle.entity.id)?;
        if source
            .get_skill_record(&id)?
            .expect("skill record")
            .lifecycle_status
            == SkillLifecycle::Active
        {
            active_pack = Some(id);
            break;
        }
    }
    let edited = active_pack.expect("an active pack SKILL seed");
    let mut record = source.get_skill_record(&edited)?.expect("skill record");
    record.lifecycle_status = SkillLifecycle::Stale;
    source.update_skill_record(
        &edited,
        &record,
        TimeRange {
            start: 100,
            end: 100,
        },
        100,
    )?;
    let (_fresh_dir, fresh) = open_later_vault();
    let before = fresh.get(&edited)?.expect("destination seed row");
    let export = source.export_whole_vault(true)?;
    let error = fresh
        .import_whole_vault_archive(export.bytes())
        .expect_err("an edited seed still collides through the actorless door");
    assert_eq!(
        error.to_string(),
        "invalid config: whole-vault import: import ID collides with different entity data"
    );
    assert_eq!(
        fresh.get(&edited)?.as_deref(),
        Some(before.as_slice()),
        "the failed import leaves the destination seed row unchanged"
    );
    Ok(())
}
