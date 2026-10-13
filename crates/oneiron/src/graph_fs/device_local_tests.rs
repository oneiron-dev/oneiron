//! DEC-0005 on the Graph-FS `/worlds` index (Sol R4 F1).
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
    vault.set_world_device_only(kept, true)?;

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
