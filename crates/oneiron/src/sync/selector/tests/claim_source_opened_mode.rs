//! The device-local resolved residence mode row (M2/M2b/M3/M4).
//!
//! PR1-OPENED-COLD-SOURCE-MODE = A (28 Nov): on an opened device, a source that is absent (no
//! entities() row), unlisted (no thin index listing) and unmarked (no soft-drop marker) counts as
//! standing. The put and the read gate read the stored resolved-mode row (`rs:resolved`), written
//! at each resolution a connection applies; no row reads as not opened. These tests reuse the
//! shared fixture from `claim_source_registration` (`witnessed_claim_on`, `set_mode`,
//! `assert_unregistered`, `raw_of`), the window ingest ladder (`synced_device`), and the
//! production eviction tear, as `claim_source_listing.rs` does. Every readability assertion goes
//! through `Vault::get_claim`. No helper visibility was widened.

use super::{insert_blob, synced_device, test_vault_with_grant};
use crate::{EntityId, Vault};

fn member(seed: u8) -> EntityId {
    crate::test_util::entity(seed)
}

struct ColdPair {
    _dir_a: tempfile::TempDir,
    a: Vault,
    _dir_b: tempfile::TempDir,
    b: Vault,
    claim: EntityId,
    claim_learned_at: u64,
}

/// A witnesses a MESSAGE and promotes a CLAIM citing it; B is a fresh device that holds no
/// MESSAGE row. Unlike `o_setup_inner`, B gets no residence mode here: each test sets its own
/// (or none) before the CLAIM travels, so the stored resolved-mode row reads exactly as arranged.
fn cold_pair(member_seed: u8, witness_seed: u8, content: &str, occurred_at: u64) -> ColdPair {
    use super::claim_source_registration as shared;
    let member_ref = member(member_seed);
    let (_dir_a, vault_a, _) = test_vault_with_grant(member_ref);
    let (_turn, _conv, message, claim, _msg_learned_at, claim_learned_at) =
        shared::witnessed_claim_on(&vault_a, witness_seed, content, occurred_at);
    let (_dir_b, vault_b, _) = test_vault_with_grant(member_ref);
    assert!(
        vault_b.get(&message).expect("read B msg").is_none(),
        "B holds no MESSAGE row"
    );
    ColdPair {
        _dir_a,
        a: vault_a,
        _dir_b,
        b: vault_b,
        claim,
        claim_learned_at,
    }
}

/// Syncs A's CLAIM (only) to B through a window doc in the CLAIM's own learned month, for
/// admitted sync. Answers the window and B's synced doc.
fn sync_claim_to(
    vault_a: &Vault,
    vault_b: &Vault,
    claim: EntityId,
    claim_learned_at: u64,
) -> (crate::sync::WindowKey, loro::LoroDoc) {
    use super::claim_source_registration as shared;
    let claim_window = crate::sync::WindowKey::from_timestamp(claim_learned_at);
    let doc_a = crate::sync::schema::create_window_doc("a", &claim_window);
    insert_blob(&doc_a, claim, &shared::raw_of(vault_a, claim));
    doc_a.commit();
    let doc_b = synced_device(&doc_a, &claim_window, vault_b);
    (claim_window, doc_b)
}

/// B's stored resolved-mode row through the production reader.
fn resolved_opened(vault: &Vault) -> bool {
    let txn = vault.store.env.read_txn().expect("read txn");
    crate::sync::residence::device_residence_opened_in_txn(&vault.store, &txn).expect("opened read")
}

/// The held-CLAIM marker key for `claim` in `window`.
fn held_marker(window: &crate::sync::WindowKey, claim: EntityId) -> String {
    format!("rm:w:{}:{}", window.as_str(), claim.to_hex())
}

/// M2: with no mode row, a cold source CLAIM is held. It proves no row reads as not opened
/// (PR1-OPENED-COLD-SOURCE-MODE = A): B never calls `set_mode`, so no owner choice and no stored
/// row exist, and the CLAIM waits exactly as on a sync-all device.
#[test]
fn with_no_mode_row_a_cold_source_claim_is_held() {
    let s = cold_pair(0x69, 0x12, "m2 cold held", 2_500);
    assert!(!resolved_opened(&s.b), "no row reads as not opened");
    let (claim_window, _doc_b) = sync_claim_to(&s.a, &s.b, s.claim, s.claim_learned_at);
    assert!(
        s.b.get_claim(&s.claim).expect("read B").is_none(),
        "the cold CLAIM is held with no mode row"
    );
    assert_eq!(
        s.b.sync_state_get(&held_marker(&claim_window, s.claim))
            .expect("marker read")
            .as_deref(),
        Some([1u8].as_slice()),
        "the held CLAIM leaves its rm:w: marker"
    );
}

/// M2b: with a sync-all row, a cold source CLAIM is held. It proves `[2]` reads as not opened
/// (PR1-OPENED-COLD-SOURCE-MODE = A): the owner chose sync-all and the production resolution
/// recorded it.
#[test]
fn with_a_sync_all_row_a_cold_source_claim_is_held() {
    use super::claim_source_registration as shared;
    let s = cold_pair(0x6A, 0x12, "m2b all held", 2_600);
    shared::set_mode(&s.b, crate::sync::SyncResidenceMode::All);
    assert!(!resolved_opened(&s.b), "a sync-all row reads as not opened");
    let (claim_window, _doc_b) = sync_claim_to(&s.a, &s.b, s.claim, s.claim_learned_at);
    assert!(
        s.b.get_claim(&s.claim).expect("read B").is_none(),
        "the cold CLAIM is held on a sync-all row"
    );
    assert_eq!(
        s.b.sync_state_get(&held_marker(&claim_window, s.claim))
            .expect("marker read")
            .as_deref(),
        Some([1u8].as_slice()),
        "the held CLAIM leaves its rm:w: marker"
    );
}

/// M3: a switch from opened to sync-all rewrites the row and the next put holds. It proves the
/// row is written at EVERY resolution (PR1-OPENED-COLD-SOURCE-MODE = A): the owner stops being
/// treated as opened at the next one. CLAIM 1 stays readable after the switch: it landed with no
/// registration row, and its cold-citation row falls only to local evidence (a deletion mark or a
/// soft-drop marker), which a switch is not; only the next cold put holds.
#[test]
fn a_switch_from_opened_to_sync_all_rewrites_the_row_and_the_next_put_holds() {
    use super::claim_source_registration as shared;
    let member_ref = member(0x6B);
    let (_dir_a, vault_a, _) = test_vault_with_grant(member_ref);
    let (_dir_b, vault_b, _) = test_vault_with_grant(member_ref);
    shared::set_mode(&vault_b, crate::sync::SyncResidenceMode::Opened);
    assert!(
        resolved_opened(&vault_b),
        "the opened choice resolves and records opened"
    );
    // CLAIM 1 lands readable, unregistered.
    let (_t1, _c1, message1, claim1, _m1, claim1_learned) =
        shared::witnessed_claim_on(&vault_a, 0x12, "m3 first", 2_700);
    assert!(
        vault_b.get(&message1).expect("read B msg").is_none(),
        "B holds no MESSAGE row"
    );
    sync_claim_to(&vault_a, &vault_b, claim1, claim1_learned);
    assert!(
        vault_b.get_claim(&claim1).expect("read B").is_some(),
        "CLAIM 1 lands readable on the opened row"
    );
    shared::assert_unregistered(&vault_b, claim1);
    // The owner switches; the production resolution rewrites the row to sync-all.
    shared::set_mode(&vault_b, crate::sync::SyncResidenceMode::All);
    assert!(
        !resolved_opened(&vault_b),
        "the switch rewrites the row to sync-all"
    );
    assert_eq!(
        vault_b
            .sync_state_get("rs:resolved")
            .expect("row read")
            .as_deref(),
        Some([2u8].as_slice()),
        "the stored row holds exactly [2]"
    );
    // CLAIM 2 (a second witnessed CLAIM on A with a different cold MESSAGE) is held.
    let (_t2, _c2, message2, claim2, _m2, claim2_learned) =
        shared::witnessed_claim_on(&vault_a, 0x40, "m3 second", 2_800);
    assert!(
        vault_b.get(&message2).expect("read B msg").is_none(),
        "B holds no second MESSAGE row"
    );
    let (claim_window2, _doc_b2) = sync_claim_to(&vault_a, &vault_b, claim2, claim2_learned);
    assert!(
        vault_b.get_claim(&claim2).expect("read B").is_none(),
        "CLAIM 2 is held on the sync-all row"
    );
    assert_eq!(
        vault_b
            .sync_state_get(&held_marker(&claim_window2, claim2))
            .expect("marker read")
            .as_deref(),
        Some([1u8].as_slice()),
        "the held CLAIM 2 leaves its rm:w: marker"
    );
    // CLAIM 1 stays readable: its cold-citation row falls only to local evidence.
    assert!(
        vault_b.get_claim(&claim1).expect("read B").is_some(),
        "CLAIM 1 stays readable after the switch: no evidence drops its cold source"
    );
}

/// M4: an own CLAIM after eviction reads on an opened row and hides with no row. It proves the
/// gate counts an absent, unlisted, unmarked source as standing exactly when the stored row says
/// opened (PR1-OPENED-COLD-SOURCE-MODE = A), on one vault whose MESSAGE left through the
/// production eviction tear with no deletion evidence and no listing.
#[test]
fn own_claim_after_eviction_reads_on_an_opened_row_and_hides_with_no_row() {
    use super::claim_source_registration as shared;
    let (_dir_b, vault_b, _) = test_vault_with_grant(member(0x6C));
    let (_turn, _conv, message, claim, _msg_learned, _claim_learned) =
        shared::witnessed_claim_on(&vault_b, 0x12, "m4 own claim", 1_772_480_000);
    assert!(
        vault_b.get_claim(&claim).expect("read B").is_some(),
        "B serves its own CLAIM before the eviction"
    );
    // Evict the MESSAGE through the production tear: the leftover pass of the world-copy
    // discard (`discard_leftover_claims`) shape, window held closed. `release_local_members`
    // takes the local-only row the window document does not carry; the tear writes no deletion
    // evidence, listing, or marker.
    let window =
        crate::sync::residence::residence_window_for_blob(&shared::raw_of(&vault_b, message))
            .expect("MESSAGE residence window");
    vault_b.unload_idle_window(&window).expect("unload");
    let removed = vault_b
        .while_window_closed(&window, || {
            vault_b.with_write_txn_grouped(|txn| {
                crate::store::local_replica::remove_local_members_in_txn(
                    &vault_b.store,
                    txn,
                    &window,
                    &[message],
                    crate::store::local_replica::KeepControls {
                        release_local_members: true,
                        ..Default::default()
                    },
                )
            })
        })
        .expect("window held closed");
    let removed = removed.expect("eviction tear");
    assert!(
        removed.removed.contains(&message),
        "the production tear removed the MESSAGE row"
    );
    assert!(
        vault_b.get(&message).expect("read B msg").is_none(),
        "the MESSAGE row is gone from entities()"
    );
    {
        let txn = vault_b.store.env.read_txn().expect("read txn");
        assert!(
            !crate::ports::source_deleted_or_withdrawn_in_txn(&vault_b.store, &txn, &message)
                .expect("deletion read"),
            "the eviction wrote no deletion evidence"
        );
        assert!(
            crate::sync::residence::index_listing_of_item_in_txn(
                &vault_b.store,
                &txn,
                &message.to_hex()
            )
            .expect("listing read")
            .is_none(),
            "the MESSAGE is unlisted"
        );
        assert!(
            !crate::sync::residence::soft_drop_marker_exists_in_txn(
                &vault_b.store,
                &txn,
                &message.to_hex()
            )
            .expect("marker read"),
            "the MESSAGE is unmarked"
        );
    }
    // No row yet: today's behaviour hides the CLAIM.
    assert!(
        !resolved_opened(&vault_b),
        "no row reads as not opened before the choice"
    );
    assert!(
        vault_b.get_claim(&claim).expect("read B").is_none(),
        "the CLAIM hides with no row (today's behaviour)"
    );
    // The owner chooses opened; the production resolution records it, and the CLAIM reads.
    shared::set_mode(&vault_b, crate::sync::SyncResidenceMode::Opened);
    assert!(
        resolved_opened(&vault_b),
        "the opened choice resolves and records opened"
    );
    assert!(
        vault_b.get_claim(&claim).expect("read B").is_some(),
        "the CLAIM reads once the row says opened"
    );
}
