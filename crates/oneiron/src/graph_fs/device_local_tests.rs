//! DEC-0005 on Graph-FS listings: the `/worlds` index (Sol R4 F1), claim
//! runs and capped scans (Sol R5 F4).
use super::*;
use crate::claim::{CallerLocality, ScopedReadActorKey};
use crate::temporal::TimeRange;

/// `/worlds` pages the WORLD index. Off this device a world a device-local
/// flag keeps takes no place on a page and is never the page's cursor,
/// though it closes the index's first full page.
#[test]
fn a_worlds_page_off_this_device_never_names_a_device_local_world() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::config::VaultConfig::default());
    let worlds: Vec<_> = (0..=GRAPH_FS_MAX_PAGE_ENTRIES)
        .map(|_| EntityId::now())
        .collect();
    let at = TimeRange { start: 1, end: 1 };
    for chunk in worlds.chunks(256) {
        chunk
            .iter()
            .fold(vault.batch(), |batch, world| {
                batch.put(world, ENTITY_TYPE_WORLD, at, 1, b"world")
            })
            .commit()?;
    }
    let first = vault.entities_by_type_page(ENTITY_TYPE_WORLD, None, GRAPH_FS_MAX_PAGE_ENTRIES)?;
    let kept = *first.last().expect("a full first page");
    vault.keep_world_on_this_machine_for_test(kept, true)?;

    let reader = vault.scoped_read(
        ScopedReadActorKey::new("reader")
            .expect("actor key")
            .at(CallerLocality::OffDevice),
    );
    let page = reader
        .graph_fs(
            GraphFsOptions::default()
                .with_page_byte_cap(GRAPH_FS_MAX_PAGE_BYTE_CAP)
                .with_max_entries(GRAPH_FS_MAX_PAGE_ENTRIES),
        )
        .readdir("/worlds/", None)?;
    let kept = kept.to_hex();
    assert_ne!(page.next_cursor(), Some(kept.as_str()));
    assert!(
        !page
            .render_bytes()
            .windows(kept.len())
            .any(|window| window == kept.as_bytes())
    );
    Ok(())
}

/// Sol R5 F4: `/claims/by-id` reads the claim index in bounded runs. Off this
/// device a claim a device-local flag keeps never fills a run, so a page of
/// nothing but such claims reads as the end of the listing; on this device
/// the full run still says there may be more.
#[test]
fn a_claim_run_off_this_device_hints_at_no_device_local_claim() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::config::VaultConfig::default());
    let at = TimeRange { start: 1, end: 1 };
    let (world, subject) = (EntityId::now(), EntityId::now());
    vault.put_entity(&world, ENTITY_TYPE_WORLD, at, 1, b"world")?;
    vault.put_entity(
        &subject,
        crate::registry::ENTITY_TYPE_PERSON,
        at,
        1,
        b"person",
    )?;
    // Every claim before these is portable: the run they fill exactly.
    let fetch = vault
        .entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)?
        .len()
        + 2;
    put_claims_in(&vault, world, subject, 1)?;
    vault.keep_world_on_this_machine_for_test(world, true)?;

    let next_cursor = |locality| -> Result<bool> {
        let reader = vault.scoped_read(
            ScopedReadActorKey::new("reader")
                .expect("actor key")
                .at(locality),
        );
        let page = reader
            .graph_fs(GraphFsOptions::default())
            .listdir_claims_by_id_with_fetch("/claims/by-id", None, fetch)?;
        Ok(page.next_cursor().is_some())
    };
    assert!(next_cursor(CallerLocality::OnDevice)?);
    assert!(!next_cursor(CallerLocality::OffDevice)?);
    Ok(())
}

/// Sol R5 F4, its related doors: a capped scan counts each timeline row it
/// passes. Off this device a row a device-local world keeps takes no place
/// in the cap, so a scan the other rows do not fill ends with no
/// continuation, whatever device-local rows follow them; on this device
/// those rows still fill it.
#[test]
fn a_capped_scan_off_this_device_is_never_filled_by_device_local_rows() -> Result<()> {
    use crate::ports::EntityStoreRead as _;
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::config::VaultConfig::default());
    let at = TimeRange { start: 1, end: 1 };
    let subject = EntityId::now();
    vault.put_entity(
        &subject,
        crate::registry::ENTITY_TYPE_PERSON,
        at,
        1,
        b"person",
    )?;
    let world = EntityId::now();
    vault.put_entity(&world, ENTITY_TYPE_WORLD, at, 2, b"world")?;
    vault.keep_world_on_this_machine_for_test(world, true)?;
    // Every row so far but the world's own, which the setting keeps, is
    // portable: the cap they fill exactly. The setting's own authority rows
    // are among them.
    let cap = {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .port_entity_timeline(&rtxn, crate::ports::TimelineQuery::default())?
            .count()
            - 1
    };
    put_claims_in(&vault, world, subject, 2)?;

    let continues = |locality| -> Result<[bool; 2]> {
        let reader = vault.scoped_read(
            ScopedReadActorKey::new("reader")
                .expect("actor key")
                .at(locality),
        );
        let fs = reader.graph_fs(GraphFsOptions::default());
        let days = fs.listdir_claim_days_with_scan_cap("/claims/by-time", None, cap)?;
        let (_, newest, _) = fs.ls_claims_by_time_pushdown_with_scan_cap(None, cap)?;
        Ok([days.next_cursor().is_some(), newest.is_some()])
    };
    assert_eq!(continues(CallerLocality::OnDevice)?, [true, true]);
    assert_eq!(continues(CallerLocality::OffDevice)?, [false, false]);
    Ok(())
}

/// Two claims about `subject` in `world`, learned at `learned_at`.
fn put_claims_in(
    vault: &crate::Vault,
    world: EntityId,
    subject: EntityId,
    learned_at: u64,
) -> Result<()> {
    for _ in 0..2 {
        let mut body = crate::claim::ClaimBody::new(
            "profile.orchid",
            crate::claim::ClaimSubject::Entity(subject),
            rmpv::Value::from("kept"),
            1.0,
            crate::claim::ClaimApprovalStatus::Approved,
            crate::claim::ClaimLifecycleStatus::Active,
        )?;
        body.world = Some(world);
        let at = TimeRange {
            start: learned_at,
            end: learned_at,
        };
        vault.put_claim(&EntityId::now(), &body, at, learned_at)?;
    }
    Ok(())
}
