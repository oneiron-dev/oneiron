//! The leave purge over the thin index: a listing (`ri:w:{window}:{item}`) and its by-item twin
//! (`ri:i:{item}:{window}`) take one decision and go in the same pass (review round 2 of #10645).

use crate::EntityId;
use crate::Vault;
use crate::temporal::TimeRange;

const WINDOW: &str = "2026-11";

/// A valid MACHINE id whose 16 raw bytes spell the start of the twin key of `ITEM`'s listing.
const MACHINE: [u8; 16] = *b"ri:i:123456789ab";
const ITEM: &str = "123456789ab000000000000000000000";

fn listing_key(item: &str) -> String {
    format!("ri:w:{WINDOW}:{item}")
}

fn twin_key(item: &str) -> String {
    format!("ri:i:{item}:{WINDOW}")
}

fn plant_pair(vault: &Vault, item: &str) {
    vault
        .with_write_txn_grouped(|txn| {
            vault
                .store
                .sync_state
                .put(txn, &listing_key(item), b"listing")?;
            crate::sync::residence::put_index_by_item_in_txn(&vault.store, txn, WINDOW, item)
        })
        .expect("plant the listing and its twin");
}

fn present(vault: &Vault, key: &str) -> bool {
    vault
        .sync_state_get(key)
        .expect("sync_state read")
        .is_some()
}

/// Runs purge passes of `max_rows` until the purge reports complete, calling `after_pass` after
/// each pass's commit.
fn purge_to_completion(vault: &Vault, max_rows: usize, mut after_pass: impl FnMut(&Vault)) {
    for _ in 0..20_000 {
        let pass = vault
            .with_write_txn_grouped(|txn| {
                crate::store::local_replica::purge_left_shared_env_in_txn(vault, txn, max_rows)
            })
            .expect("purge pass");
        after_pass(vault);
        if pass.complete {
            return;
        }
    }
    panic!("the leave purge did not complete");
}

#[test]
fn a_kept_id_spelling_the_twin_key_keeps_neither_row_of_a_doomed_pair() {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let machine = EntityId::from_bytes(MACHINE).expect("a valid MACHINE id");
    let raw = crate::test_util::entity_record(
        crate::registry::ENTITY_TYPE_MACHINE,
        TimeRange { start: 1, end: 1 },
        1,
        0,
        b"machine",
    );
    vault
        .with_write_txn_grouped(|txn| {
            crate::ports::EntityStoreStaging::port_stage_entity_row(
                &vault.store,
                txn,
                &machine,
                &raw,
            )
        })
        .expect("stage the MACHINE row");
    plant_pair(&vault, ITEM);
    assert!(
        twin_key(ITEM).as_bytes().starts_with(&MACHINE),
        "the twin key carries the kept MACHINE's raw bytes"
    );
    assert!(
        !listing_key(ITEM)
            .as_bytes()
            .windows(16)
            .any(|window| window == MACHINE),
        "the listing key does not"
    );
    purge_to_completion(&vault, 10_000, |_| {});
    assert!(!present(&vault, &listing_key(ITEM)), "the listing went");
    assert!(
        !present(&vault, &twin_key(ITEM)),
        "its twin went with it, though its key spells a kept id"
    );
    let txn = vault.store.env.read_txn().expect("read txn");
    assert!(
        vault
            .store
            .entities
            .get(&txn, machine.as_bytes())
            .expect("entity read")
            .is_some(),
        "the MACHINE row is kept"
    );
}

#[test]
fn a_purge_pass_never_splits_a_listing_from_its_twin() {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let items: Vec<String> = (1..=5_u8).map(|n| format!("{n:032x}")).collect();
    for item in &items {
        plant_pair(&vault, item);
    }
    purge_to_completion(&vault, 1, |vault| {
        for item in &items {
            assert_eq!(
                present(vault, &listing_key(item)),
                present(vault, &twin_key(item)),
                "a pass left {item}'s listing and twin apart"
            );
        }
    });
    for item in &items {
        assert!(
            !present(&vault, &listing_key(item)),
            "{item}'s listing went"
        );
        assert!(!present(&vault, &twin_key(item)), "{item}'s twin went");
    }
}
