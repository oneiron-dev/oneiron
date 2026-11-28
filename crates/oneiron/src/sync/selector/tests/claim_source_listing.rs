//! Replicated CLAIM against thin-index-listed MESSAGE sources (O2/O2b/O3, M1).
//!
//! Unit fallback from the claim-source-registration-build brief: the it_sync
//! harness cannot hold a replicated CLAIM (batch `put_replicated` bypasses the
//! own-vault ingest signal, and verified locators need
//! `VerifiedEvidenceSet::verify_whole_in_txn` plus the window ingest ladder,
//! all unreachable outside the crate), so O2/O2b/O3 live here as children of
//! the selector tests beside `claim_source_registration`, reusing its shared
//! fixture (`witnessed_claim_on`, `set_mode`, `plant_listing`, `tombstone_v2`,
//! `assert_registered`, `raw_of`). No hand-crafted locators anywhere.
//!
//! Modes (explicit, via existing `set_device_sync_preference`, no new switch):
//! O2/O2b/O3/M1 run on opened receivers. No case-4b behavior is needed for
//! O2/O2b/O3 (their sources are listed, case 3); M1 is the 4b case, landed
//! under PR1-OPENED-COLD-SOURCE-MODE = A: readable, unregistered.
//!
//! Planting (for the report; every other step drives the real path):
//! - O2/O2b/O3 plant the initial listing + twin exactly as O1 (shared
//!   `plant_listing`); O5 plants nothing before arrival (cold by design).
//! - O2 soft leg: REAL residence soft-drop door (`drop_soft_deleted_thin_copy`)
//!   drops the listing + twin and writes the marker. No planting.
//! - O2 restore leg: hand-plants the fresh S1 rows (`plant_listing`) + clears
//!   the marker through SHARED `delete_soft_drop_marker_in_txn`, exactly what
//!   S1 does beside its restoring put. Reported planting, no live fetch.
//! - O2b: calls the REAL production S1 seam
//!   `mark_index_items_absent_from_page_in_txn` with a simulated page (old =
//!   the planted listing key, fresh = empty: the still-current window's next
//!   page no longer lists the MESSAGE), then deletes both rows explicitly via
//!   the production key/twin shape (the seam marks only). Marking logic +
//!   gate real; the fetch and the loop's deletes are simulated/reported.
//! - O3: past the initial plant, no planting; the hard erase runs the shared
//!   replay primitive `apply_replayed_tombstone_for_sync` (writes real `dt:`;
//!   headerless replay withdraws through the gate only, no walk).
//! - M1: cold arrival, no planting. Asserts the landed 4b behavior: readable,
//!   unheld, unregistered, with its cold-citation row. No `dt:` leg (Q-DT = No).
//! - R1a/R1b (#10654 review r1): the cold-citation row lets the gate hide a
//!   cold-landed CLAIM on a later soft erase of its source, and lands a CLAIM
//!   whose source is soft-dropped at arrival hidden, not held, so a restore
//!   shows it with no replay.
//!
//! Hook-undone behavior (only R-f's added line undone):
//! - O2/O2b/O3: the arrival `assert_registered` fails (nothing registers) and
//!   every post-erase `get_claim(..) == None` fails (the CLAIM stays readable:
//!   `source_withdrawn_in` reads only the dependent's own reverse rows).
//!   Listing/twin/marker/`dt:` asserts stay green (residence paths, not the
//!   hook). O2's restore leg stays green.
//! - M1: its cold-citation row assert fails (no hook, no row); the absence and
//!   readability asserts hold either way on the opened row.

use super::{insert_blob, synced_device, test_vault_with_grant};
use crate::{EntityId, Vault};

fn member(seed: u8) -> EntityId {
    crate::test_util::entity(seed)
}

struct OSetup {
    _dir_b: tempfile::TempDir,
    b: Vault,
    message: EntityId,
    claim: EntityId,
    msg_learned_at: u64,
    claim_learned_at: u64,
    listing_window: crate::sync::WindowKey,
}

/// A on its own vault witnesses a MESSAGE and promotes a CLAIM citing it;
/// B is an opened device that takes the CLAIM (only) through a window doc.
/// When `listed`, B first plants the MESSAGE's thin index listing with A's
/// learned_at (case 3); otherwise B is cold (case 4b, M1). Arrival asserts
/// (readable + registered, or readable + unheld + unregistered for the cold
/// source, PR1-OPENED-COLD-SOURCE-MODE = A) run here.
fn o_setup_inner(
    member_seed: u8,
    witness_seed: u8,
    content: &str,
    occurred_at: u64,
    listed: bool,
) -> OSetup {
    use super::claim_source_registration as shared;
    let member_ref = member(member_seed);
    let (_dir_a, vault_a, _) = test_vault_with_grant(member_ref);
    let (_turn, _conv, message, claim, msg_learned_at, claim_learned_at) =
        shared::witnessed_claim_on(&vault_a, witness_seed, content, occurred_at);
    let (_dir_b, vault_b, _) = test_vault_with_grant(member_ref);
    shared::set_mode(&vault_b, crate::sync::SyncResidenceMode::Opened);
    assert!(
        vault_b.get(&message).expect("read B msg").is_none(),
        "B holds no MESSAGE row"
    );
    // Windows derived from actual header times (the witness may use wall
    // time): the CLAIM travels in its own learned month for admitted sync,
    // the listing lives in the MESSAGE's learned month.
    let claim_window = crate::sync::WindowKey::from_timestamp(claim_learned_at);
    let listing_window = crate::sync::WindowKey::from_timestamp(msg_learned_at);
    if listed {
        shared::plant_listing(&vault_b, listing_window.as_str(), message, msg_learned_at);
    }
    let doc_a = crate::sync::schema::create_window_doc("a", &claim_window);
    insert_blob(&doc_a, claim, &shared::raw_of(&vault_a, claim));
    doc_a.commit();
    let _doc_b = synced_device(&doc_a, &claim_window, &vault_b);
    assert!(
        vault_b.get_claim(&claim).expect("read B").is_some(),
        "the CLAIM arrives readable"
    );
    if listed {
        shared::assert_registered(&vault_b, claim, message, msg_learned_at);
    } else {
        assert_eq!(
            vault_b
                .sync_state_get(&cold_citation_key(claim, message))
                .expect("cold row read")
                .as_deref(),
            Some([1u8].as_slice()),
            "the cold source leaves its cold-citation row for the read gate"
        );
        let held = format!("rm:w:{}:{}", claim_window.as_str(), claim.to_hex());
        assert_eq!(
            vault_b.sync_state_get(&held).expect("held read"),
            None,
            "an opened device never holds a cold CLAIM under rm:w:"
        );
        let txn = vault_b.store.env.read_txn().expect("read txn");
        assert!(
            crate::sync::residence::device_residence_opened_in_txn(&vault_b.store, &txn)
                .expect("resolved-mode read"),
            "B's stored resolved-mode row says opened"
        );
        let sources =
            crate::ports::dependency_sources_in(&vault_b.store, &txn, &claim).expect("dep sources");
        assert!(
            !sources.contains(&message),
            "an opened device registers no cold source: no frontier exists for it"
        );
    }
    OSetup {
        _dir_b,
        b: vault_b,
        message,
        claim,
        msg_learned_at,
        claim_learned_at,
        listing_window,
    }
}

/// The cold-citation row key of `claim` landed without `source` (`ri:k:{claim}:{source}`).
fn cold_citation_key(claim: EntityId, source: EntityId) -> String {
    format!("ri:k:{}:{}", claim.to_hex(), source.to_hex())
}

/// Delete one `ri:w:` row + its `ri:i:` twin: the row-deletion half the S1
/// rewrite and the soft drop share (their loops do these same two writes).
/// Used explicitly wherever the test drives only the marking half.
fn delete_listing_rows_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    window: &str,
    hex: &str,
) -> crate::Result<()> {
    store
        .sync_state
        .delete(txn, &format!("ri:w:{window}:{hex}"))?;
    crate::sync::residence::delete_index_by_item_in_txn(store, txn, window, hex)?;
    Ok(())
}

/// The listing (and its twin) is gone, read through the production reader.
fn assert_listing_absent(vault: &Vault, message: EntityId) {
    let txn = vault.store.env.read_txn().expect("read txn");
    assert!(
        crate::sync::residence::index_listing_of_item_in_txn(&vault.store, &txn, &message.to_hex())
            .expect("listing read")
            .is_none(),
        "the listing (and its twin) is gone"
    );
}

/// The soft-drop marker is present (`present`) or absent, through the SHARED
/// production reader (never a hand-rolled key).
fn assert_marker(vault: &Vault, message: EntityId, present: bool) {
    let txn = vault.store.env.read_txn().expect("read txn");
    assert_eq!(
        crate::sync::residence::soft_drop_marker_exists_in_txn(
            &vault.store,
            &txn,
            &message.to_hex()
        )
        .expect("marker read"),
        present,
        "soft-drop marker present == {present}"
    );
}

// ---------------------------------------------------------------------------
// O2: a soft erase drops the listing and hides the CLAIM (then restores).
// Mode: opened receiver (explicit). Hook-undone: registered + hidden fail.
// ---------------------------------------------------------------------------

#[test]
fn a_soft_erase_drops_the_listing_and_hides_the_claim() {
    use super::claim_source_registration as shared;
    let s = o_setup_inner(0x61, 0x20, "o2 soft hides", 2_100, true);
    // Soft leg. REAL residence soft-drop door: drops the listing + twin and
    // writes the case-5 marker.
    let dropped =
        crate::sync::client::drop_soft_deleted_thin_copy(&s.b, &s.listing_window, s.message)
            .expect("the soft drop applies");
    assert!(dropped, "the soft drop took the planted listing");
    assert_listing_absent(&s.b, s.message);
    assert_marker(&s.b, s.message, true);
    let dt = format!("dt:{}", s.message.to_hex());
    assert_eq!(
        s.b.sync_state_get(&dt).expect("dt read"),
        None,
        "a soft drop writes no delete marker"
    );
    assert!(
        s.b.get_claim(&s.claim).expect("read B").is_none(),
        "the CLAIM hides while its listed source carries the soft-drop marker"
    );
    shared::assert_registered(&s.b, s.claim, s.message, s.msg_learned_at);
    // Restore leg: the next index fetch lists the MESSAGE again. Hand-plant
    // the fresh S1 rows + SHARED marker clear (what S1 does beside its
    // restoring put); reported planting, no live fetch.
    shared::plant_listing(&s.b, s.listing_window.as_str(), s.message, s.msg_learned_at);
    s.b.with_write_txn_grouped(|txn| {
        crate::sync::residence::delete_soft_drop_marker_in_txn(
            &s.b.store,
            txn,
            s.message.to_hex().as_str(),
        )?;
        Ok(())
    })
    .expect("clear the marker on re-list");
    assert_marker(&s.b, s.message, false);
    assert!(
        s.b.get_claim(&s.claim).expect("read B").is_some(),
        "the CLAIM reads again once its source is listed and unmarked"
    );
}

// ---------------------------------------------------------------------------
// O2b: a MESSAGE the home stops listing hides the CLAIM (S1, still current).
// Mode: opened receiver (explicit). REAL S1 seam, simulated page (no fetch).
// Hook-undone: registered + hidden fail.
// ---------------------------------------------------------------------------

#[test]
fn a_message_the_home_stops_listing_hides_the_claim() {
    use super::claim_source_registration as shared;
    let s = o_setup_inner(0x62, 0x30, "o2b unlisted hides", 2_200, true);
    // The still-current window's next page no longer lists the MESSAGE: the
    // REAL production S1 seam, simulated inputs (old = the planted key,
    // fresh = empty).
    let prefix = format!("ri:w:{}:", s.listing_window);
    let old = [format!("ri:w:{}:{}", s.listing_window, s.message.to_hex())];
    let fresh: std::collections::HashSet<&str> = std::collections::HashSet::new();
    s.b.with_write_txn_grouped(|txn| {
        // The seam marks; the S1 loop's row deletes are explicit here.
        crate::sync::residence::mark_index_items_absent_from_page_in_txn(
            &s.b.store, txn, &prefix, &old, &fresh,
        )?;
        delete_listing_rows_in_txn(
            &s.b.store,
            txn,
            s.listing_window.as_str(),
            &s.message.to_hex(),
        )?;
        Ok(())
    })
    .expect("s1 marks the unlisted source");
    assert_listing_absent(&s.b, s.message);
    assert_marker(&s.b, s.message, true);
    let dt = format!("dt:{}", s.message.to_hex());
    assert_eq!(
        s.b.sync_state_get(&dt).expect("dt read"),
        None,
        "an unlisting writes no delete marker"
    );
    assert!(
        s.b.get_claim(&s.claim).expect("read B").is_none(),
        "the CLAIM hides while its source is unlisted-but-current"
    );
    shared::assert_registered(&s.b, s.claim, s.message, s.msg_learned_at);
}

// ---------------------------------------------------------------------------
// O3: a hard erase marks dt: and withdraws the CLAIM (no revive on re-list).
// Mode: opened receiver (explicit). Real hard replay primitive. Hook-undone:
// registered + withdrawn fail; dt: stays green.
// ---------------------------------------------------------------------------

#[test]
fn a_hard_erase_marks_dt_and_withdraws_the_claim() {
    use super::claim_source_registration as shared;
    let s = o_setup_inner(0x66, 0x60, "o3 hard withdraws", 2_300, true);
    let hard = shared::tombstone_v2(
        crate::deletion::TombstoneReason::UserHardDelete,
        s.claim_learned_at + 1_000,
    );
    crate::sync::quarantine::apply_replayed_tombstone_for_sync(&s.b, &s.message, &hard)
        .expect("the hard tombstone applies");
    let dt = format!("dt:{}", s.message.to_hex());
    assert!(
        s.b.sync_state_get(&dt).expect("dt read").is_some(),
        "the hard erase wrote dt: for the listed-not-resident source"
    );
    assert!(
        s.b.get_claim(&s.claim).expect("read B").is_none(),
        "the CLAIM withdraws once dt: names its source"
    );
    shared::assert_registered(&s.b, s.claim, s.message, s.msg_learned_at);
    // Withdrawn, not hidden: re-listing the source does not revive the CLAIM.
    shared::plant_listing(&s.b, s.listing_window.as_str(), s.message, s.msg_learned_at);
    assert!(
        s.b.get_claim(&s.claim).expect("read B").is_none(),
        "a withdrawn CLAIM stays withdrawn after its source is listed again"
    );
}

// ---------------------------------------------------------------------------
// M1: a cold unlisted source on an opened device lands readable, unregistered.
// Mode: opened receiver (explicit, case 4b). PR1-OPENED-COLD-SOURCE-MODE = A
// (28 Nov): no registration row for a cold source, no frontier exists for it.
// No dt: leg: a hard erase of a cold source never reaches an opened device
// (Q-DT = No).
// ---------------------------------------------------------------------------

#[test]
fn a_cold_unlisted_source_on_an_opened_device_lands_readable_unregistered() {
    let s = o_setup_inner(0x64, 0x50, "o5 cold reads", 2_400, false);
    // (Arrival: readable + no rm:w: + no registration row, asserted in setup.)
    assert!(
        s.b.get_claim(&s.claim).expect("read B").is_some(),
        "the cold CLAIM stays readable on the opened device"
    );
}

// ---------------------------------------------------------------------------
// R1a (#10654 review r1, P1 replicated_sources.rs:110): a CLAIM that landed against a cold source
// hides once that source is listed and then soft-erased, and reads again on restore. Mode: opened
// receiver. Undo the cold-citation row (or the gate's cold loop) and the hidden assert fails: the
// CLAIM has no registration row for the gate to judge.
// ---------------------------------------------------------------------------

#[test]
fn a_cold_cited_source_listed_then_soft_erased_hides_the_claim() {
    use super::claim_source_registration as shared;
    let s = o_setup_inner(0x66, 0x52, "r1a cold then soft erased", 2_420, false);
    // A later fetch lists the MESSAGE: the CLAIM still reads.
    shared::plant_listing(&s.b, s.listing_window.as_str(), s.message, s.msg_learned_at);
    assert!(
        s.b.get_claim(&s.claim).expect("read B").is_some(),
        "the CLAIM reads once its source is listed"
    );
    // The home soft-erases it: the REAL soft-drop door drops the listing and writes the marker.
    let dropped =
        crate::sync::client::drop_soft_deleted_thin_copy(&s.b, &s.listing_window, s.message)
            .expect("the soft drop applies");
    assert!(dropped, "the soft drop took the listing");
    assert_marker(&s.b, s.message, true);
    assert!(
        s.b.get_claim(&s.claim).expect("read B").is_none(),
        "the cold-landed CLAIM hides once its source carries the soft-drop marker"
    );
    shared::assert_unregistered(&s.b, s.claim);
    // Restore: the next fetch lists the MESSAGE again and clears the marker.
    shared::plant_listing(&s.b, s.listing_window.as_str(), s.message, s.msg_learned_at);
    s.b.with_write_txn_grouped(|txn| {
        crate::sync::residence::delete_soft_drop_marker_in_txn(
            &s.b.store,
            txn,
            s.message.to_hex().as_str(),
        )?;
        Ok(())
    })
    .expect("clear the marker on re-list");
    assert!(
        s.b.get_claim(&s.claim).expect("read B").is_some(),
        "the CLAIM reads again on restore"
    );
}

// ---------------------------------------------------------------------------
// R1b (#10654 review r1, P1 index.rs:478): a CLAIM whose source carries a soft-drop marker when
// it arrives lands hidden, not held, and reads once a restore lists the source again, with no
// replay of the CLAIM's window. Mode: opened receiver. Before the fix the CLAIM was held under
// rm:w:, and a restore never retried it.
// ---------------------------------------------------------------------------

#[test]
fn a_claim_whose_source_is_soft_dropped_lands_hidden_and_reads_on_restore() {
    use super::claim_source_registration as shared;
    let member_ref = member(0x67);
    let (_dir_a, vault_a, _) = test_vault_with_grant(member_ref);
    let (_turn, _conv, message, claim, msg_learned_at, claim_learned_at) =
        shared::witnessed_claim_on(&vault_a, 0x53, "r1b soft dropped first", 2_430);
    let (_dir_b, vault_b, _) = test_vault_with_grant(member_ref);
    shared::set_mode(&vault_b, crate::sync::SyncResidenceMode::Opened);
    let claim_window = crate::sync::WindowKey::from_timestamp(claim_learned_at);
    let listing_window = crate::sync::WindowKey::from_timestamp(msg_learned_at);
    // The home listed the MESSAGE, then soft-erased it: no listing, marker down.
    shared::plant_listing(&vault_b, listing_window.as_str(), message, msg_learned_at);
    assert!(
        crate::sync::client::drop_soft_deleted_thin_copy(&vault_b, &listing_window, message)
            .expect("the soft drop applies"),
        "the soft drop took the listing"
    );
    assert_marker(&vault_b, message, true);
    // The CLAIM arrives: stored with its cold-citation row, hidden, not held.
    let doc_a = crate::sync::schema::create_window_doc("a", &claim_window);
    insert_blob(&doc_a, claim, &shared::raw_of(&vault_a, claim));
    doc_a.commit();
    let _doc_b = synced_device(&doc_a, &claim_window, &vault_b);
    assert!(
        vault_b.get_claim(&claim).expect("read B").is_none(),
        "the CLAIM hides while its source carries the soft-drop marker"
    );
    let held = format!("rm:w:{}:{}", claim_window.as_str(), claim.to_hex());
    assert_eq!(
        vault_b.sync_state_get(&held).expect("held read"),
        None,
        "the CLAIM is not held under rm:w:"
    );
    assert_eq!(
        vault_b
            .sync_state_get(&cold_citation_key(claim, message))
            .expect("cold row read")
            .as_deref(),
        Some([1u8].as_slice()),
        "the put committed the CLAIM's cold-citation row"
    );
    // Restore: listed again, marker cleared. No replay of the CLAIM's window follows.
    shared::plant_listing(&vault_b, listing_window.as_str(), message, msg_learned_at);
    vault_b
        .with_write_txn_grouped(|txn| {
            crate::sync::residence::delete_soft_drop_marker_in_txn(
                &vault_b.store,
                txn,
                message.to_hex().as_str(),
            )?;
            Ok(())
        })
        .expect("clear the marker on re-list");
    assert!(
        vault_b.get_claim(&claim).expect("read B").is_some(),
        "the CLAIM reads on restore with no replay"
    );
}
