//! Replicated promotion CLAIM source registration (PR1): selector unit tests.
//!
//! T1-T5, F1, O1, O4 from the claim-source-registration-build brief. Each test
//! builds a promotion CLAIM with verified MESSAGE locators on device A (via
//! `VerifiedEvidenceSet::verify_whole_in_txn` + `envelope()`, which calls
//! `encode_consolidation_evidence_with_locators`), replicates it to B (and C)
//! through a Loro window doc, and asserts readability through `Vault::get_claim`
//! plus registration rows through `DependencyIndex::port_dependency_list_by_source`.
//!
//! Modes (explicit, via existing `set_device_sync_preference`, no new switch):
//! T1/T2/T3/T4/T5/F1 run on sync-all receivers; O1/O4 on opened receivers.
//! All times are stable epochs inside window `2026-03` (base 1_772_400_000);
//! MESSAGE `learned_at` is read back from A's stored header (the witness may
//! assign recorded wall time, not `occurred_at`).
//!
//! The fixture stages an unsigned A CLAIM with the real verified evidence
//! envelope. This isolates source registration from MACHINE history transfer.
//! Where a resident MESSAGE is needed on B, the fixture plants A's exact
//! witnessed row; actual MESSAGE replication also needs a verified writer
//! proof and the paired authority log. CLAIM and tombstone ingestion are real.
//!
//! Planting (for the report; every other step drives the real path):
//! - T1: MESSAGE planted; real erase on A (`delete_entity` / purge) + real
//!   Loro v2 tombstone delivery to B; CLAIM via real sync.
//! - T2: MESSAGE planted; its soft tombstone arrives SYNTHETICALLY via Loro
//!   (no erase on A in T2); late CLAIM via real sync lands withdrawn.
//! - T3: MESSAGE row planted then replayed the held CLAIM (no MESSAGE sync);
//!   held `rm:w:` marker + retry are real forward-remat behavior; later erase
//!   is real on A + real tombstone to B.
//! - T4: both MESSAGEs planted; CLAIM via real sync; unrelated erase is real
//!   on A + real tombstone to B. No registration asserts (control).
//! - T5: MESSAGE planted on B only; CLAIM + tombstone B->C via B's real
//!   post-erase mirror (C never gets MESSAGE).
//! - F1: no receiver planting; federated import via `import_from_peer` (Member).
//!   The hook tells it apart via the peer-origin map (exact digests).
//! - O1: plants `ri:w:{window}:{hex}` (rmp_serde WindowIndexEntry, learned_at =
//!   MESSAGE learned_at from A) + `ri:i:` twin via `put_index_by_item_in_txn`.
//! - O4: as O1, then purges both rows directly (S2 stale-window purge shape,
//!   no marker) instead of driving the index refresh. No registration asserts.
//!
//! Hook-undone behavior (only R-f's added line undone):
//! - T1/T2/T3/T5/O1: the B/C `None`/held/registered/stale asserts fail (CLAIM
//!   lands readable, unregistered, unheld, unstaled). T3's held-marker asserts
//!   fail. T1 proves the walk via `stale_in_txn`, not just gate hiding.
//! - T4/F1/O4: stay green (controls with no registration asserts / federated /
//!   no-registration readability).

use super::{import_from_peer, insert_blob, rematerialize, synced_device, test_vault_with_grant};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    ScopedReadActorKey, encode_claim_body,
};
use crate::deletion::TombstoneReason;
use crate::dreamer_consolidation::evidence::VerifiedEvidenceSet;
use crate::edge::EdgeActorClass;
use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use crate::sync::FederationAdmissionRole;
use crate::sync::quarantine::{QuarantineContainer, quarantined_records};
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};

// ---------------------------------------------------------------------------
// Shared fixture (pub(super) for the sibling listing module, if it falls back
// to unit tests; see claim_source_listing.rs).
// ---------------------------------------------------------------------------

/// Provision + shipped policy + test egress, as `dreamer_consolidation/tests.rs`
/// `open_vault` does. Idempotent for our fixtures.
pub(super) fn provision_dreamer(vault: &Vault) {
    crate::test_util::provision_engine_machines(vault);
    crate::test_util::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id().expect("policy id"),
        &crate::gate::default_policy_manifest().expect("policy bytes"),
    )
    .expect("shipped policy");
    let mut policy = vault.purpose_default_table().expect("purpose table");
    policy.extraction_max_locality = crate::ModelLocality::OwnServer;
    policy
        .purposes
        .get_mut(&crate::CallPurpose::Extraction)
        .expect("extraction row")
        .locality = crate::ModelLocality::OwnServer;
    vault.set_purpose_default_table(&policy).expect("egress");
}

/// Witness one User TURN with one MESSAGE and promote one CLAIM citing it.
///
/// Returns `(turn, conversation, message, claim, msg_learned_at, claim_learned_at)`.
/// Both `learned_at` values are read back from A's stored headers (the witness
/// may assign recorded wall time, not `occurred_at`); CLAIM uses distinct
/// `occurred_at + 10` / `learned_at = occurred_at + 100` as its ask.
pub(super) fn witnessed_claim_on(
    vault: &Vault,
    seed: u8,
    content: &str,
    occurred_at: u64,
) -> (EntityId, EntityId, EntityId, EntityId, u64, u64) {
    provision_dreamer(vault);
    let person = EntityId::from_bytes([seed; 16]).expect("person id");
    let conversation = EntityId::from_bytes([seed.wrapping_add(1); 16]).expect("conv id");
    let message = EntityId::from_bytes([seed.wrapping_add(2); 16]).expect("msg id");
    let turn = EntityId::from_bytes([seed.wrapping_add(3); 16]).expect("turn id");
    let claim = EntityId::from_bytes([seed.wrapping_add(4); 16]).expect("claim id");
    let subject = EntityId::from_bytes([seed.wrapping_add(5); 16]).expect("subject id");
    vault
        .put_entity(
            &person,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"witness",
        )
        .expect("witness person");
    vault
        .put_entity(
            &subject,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"subject",
        )
        .expect("subject person");
    let receipt = vault
        .memory(person, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            project: None,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: content.to_owned(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at,
            assertions: Default::default(),
        })
        .expect("witnessed turn");
    assert_eq!(receipt.turn_id, turn, "turn landed under its ref");
    let key = ScopedReadActorKey::for_engine_actor(vault.dreamer_authority().expect("dreamer"))
        .expect("engine read key");
    let read = vault.scoped_read(key);
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let verified = VerifiedEvidenceSet::verify_whole_in_txn(
        vault,
        &read,
        &rtxn,
        &[turn],
        ClaimSource::Generated,
    )
    .expect("whole-turn verify");
    drop(rtxn);
    assert!(
        verified.cited_messages().contains(&message),
        "whole-turn evidence cites the MESSAGE"
    );
    let mut body = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("Owen"),
        0.8,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    )
    .expect("CLAIM body");
    body.source = Some(verified.meet());
    body.evidence = Some(rmpv::Value::Map(vec![(
        rmpv::Value::from("candidate_evidence"),
        verified.envelope(Vec::new()),
    )]));
    body.scope = Some(rmpv::Value::Map(vec![(
        rmpv::Value::from("sensitivity"),
        rmpv::Value::from("public"),
    )]));
    let claim_learned_at = occurred_at + 100;
    let raw = crate::test_util::entity_record(
        crate::registry::ENTITY_TYPE_CLAIM,
        TimeRange {
            start: occurred_at + 10,
            end: occurred_at + 10,
        },
        claim_learned_at,
        0,
        &encode_claim_body(&body).expect("encode CLAIM"),
    );
    vault
        .with_write_txn_grouped(|wtxn| {
            crate::ports::EntityStoreStaging::port_stage_entity_row(
                &vault.store,
                wtxn,
                &claim,
                &raw,
            )?;
            verified.record_message_dependencies_in_txn(vault, wtxn, &claim)
        })
        .expect("stage the fixture CLAIM and A's real MESSAGE registrations");
    assert!(
        vault.get_claim(&claim).expect("read A claim").is_some(),
        "A serves its own CLAIM"
    );
    // Actual header times: the witness may assign recorded wall time, not
    // occurred_at, so read them back for registration asserts.
    let msg_learned_actual = learned_of(&raw_of(vault, message));
    let claim_learned_actual = learned_of(&raw_of(vault, claim));
    (
        turn,
        conversation,
        message,
        claim,
        msg_learned_actual,
        claim_learned_actual,
    )
}

/// Set the receiver's residence mode: the owner's choice, then its resolution, as a
/// connection does. With an owner choice stored and the vault not the elected home, the
/// resolution is the choice, and the production writer records it in the stored resolved-mode row.
pub(super) fn set_mode(vault: &Vault, mode: crate::sync::SyncResidenceMode) {
    crate::sync::residence::set_device_sync_preference(vault, mode).expect("mode choice");
    vault
        .resolve_and_record_device_residence(mode)
        .expect("resolved mode");
}

/// Plant one thin index listing + its by-item twin, exactly as `index.rs`
/// writes them: `ri:w:{window}:{hex}` = rmp_serde `WindowIndexEntry`.
pub(super) fn plant_listing(vault: &Vault, window: &str, message: EntityId, learned_at: u64) {
    vault
        .with_write_txn_grouped(|txn| {
            let hex = message.to_hex();
            let key = format!("ri:w:{window}:{hex}");
            let entry = crate::sync::residence::WindowIndexEntry {
                entity_id: hex.clone(),
                title: None,
                learned_at,
                content_world: crate::sync::residence::ContentWorld::Unknown,
            };
            let bytes = rmp_serde::to_vec_named(&entry).expect("index entry encodes");
            vault.store.sync_state.put(txn, &key, &bytes)?;
            crate::sync::residence::put_index_by_item_in_txn(&vault.store, txn, window, &hex)?;
            Ok(())
        })
        .expect("plant listing");
}

/// A v2 Loro tombstone value: `[wire_byte][deleted_at LE][request 16]`.
pub(super) fn tombstone_v2(reason: TombstoneReason, deleted_at: u64) -> Vec<u8> {
    let mut value = vec![reason.wire_byte()];
    value.extend_from_slice(&deleted_at.to_le_bytes());
    value.extend_from_slice(&[0xAE; 16]);
    value
}

/// Insert a precise soft/hard tombstone into a window doc's `tombstones` map.
/// (The parent `insert_tombstone` writes `b"deleted"`, which decodes HARD
/// fail-closed; this helper covers both reasons explicitly.)
pub(super) fn insert_tombstone_v2(
    doc: &loro::LoroDoc,
    id: EntityId,
    reason: TombstoneReason,
    deleted_at: u64,
) {
    crate::sync::loro_support::map_insert_bytes(
        &doc.get_map("tombstones"),
        &id.to_hex(),
        &tombstone_v2(reason, deleted_at),
    )
    .expect("tombstone insert");
}

/// Plant A's exact MESSAGE carrier for tests that do not exercise enrollment.
fn plant_message_from_a(vault_a: &Vault, vault_b: &Vault, message: EntityId) {
    let raw = raw_of(vault_a, message);
    vault_b
        .with_write_txn_grouped(|txn| {
            crate::ports::EntityStoreStaging::port_stage_entity_row(
                &vault_b.store,
                txn,
                &message,
                &raw,
            )
        })
        .expect("plant MESSAGE");
    assert!(
        vault_b.get(&message).expect("read planted").is_some(),
        "planted MESSAGE reads on B"
    );
}

/// Assert `claim` is registered as derived from `source@frontier` on `vault`.
pub(super) fn assert_registered(vault: &Vault, claim: EntityId, source: EntityId, frontier: u64) {
    use crate::ports::DependencyIndex;
    let txn = vault.store.env.read_txn().expect("read txn");
    let span = crate::ports::SourceSpan {
        document: source,
        frontier,
    };
    let listed = vault
        .store
        .port_dependency_list_by_source(&txn, span)
        .expect("list by source");
    assert!(
        listed.contains(&claim),
        "expected {claim:?} registered under {source:?}@{frontier}, got {listed:?}"
    );
}

/// Assert `claim` carries no dependency registration on `vault`.
pub(super) fn assert_unregistered(vault: &Vault, claim: EntityId) {
    let txn = vault.store.env.read_txn().expect("read txn");
    let sources =
        crate::ports::dependency_sources_in(&vault.store, &txn, &claim).expect("dep sources");
    assert!(
        sources.is_empty(),
        "expected no registration for {claim:?}, got {sources:?}"
    );
}

/// The stored raw (header + body) of `id` on `vault`.
pub(super) fn raw_of(vault: &Vault, id: EntityId) -> Vec<u8> {
    let txn = vault.store.env.read_txn().expect("read txn");
    crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &txn, &id)
        .expect("raw read")
        .unwrap_or_else(|| panic!("no raw for {id:?}"))
}

/// `learned_at` of a stored raw blob.
pub(super) fn learned_of(raw: &[u8]) -> u64 {
    crate::batch::EntityMetadataHeader::parse(raw)
        .expect("header parses")
        .learned_at
}

fn window_key() -> crate::sync::WindowKey {
    crate::sync::WindowKey::new("2026-03")
}

fn member(seed: u8) -> EntityId {
    crate::test_util::entity(seed)
}

// ---------------------------------------------------------------------------
// T1: an erased MESSAGE withdraws the CLAIM on the peer (soft + hard).
// Mode: sync-all receiver (explicit). Hook-undone: B stays readable (fails).
// ---------------------------------------------------------------------------

#[test]
fn an_erased_message_withdraws_the_claim_on_the_peer() {
    for (case, reason, purge) in [
        ("soft", TombstoneReason::UserDelete, false),
        ("hard", TombstoneReason::UserHardDelete, true),
    ] {
        let member_ref = member(0x55);
        let (_dir_a, vault_a, _) = test_vault_with_grant(member_ref);
        let (_dir_b, vault_b, _) = test_vault_with_grant(member_ref);
        set_mode(&vault_b, crate::sync::SyncResidenceMode::All);
        let (_turn, _conv, message, claim, msg_learned, _claim_learned) =
            witnessed_claim_on(&vault_a, 0x12, "call me Owen", 1_772_400_000);
        let key = window_key();
        // MESSAGE planted (local put of A's real witness bytes); CLAIM +
        // tombstone travel real sync. See header.
        plant_message_from_a(&vault_a, &vault_b, message);
        let doc_a = crate::sync::schema::create_window_doc("a", &key);
        insert_blob(&doc_a, claim, &raw_of(&vault_a, claim));
        doc_a.commit();
        let mut doc_b = synced_device(&doc_a, &key, &vault_b);
        assert!(
            vault_b.get_claim(&claim).expect("read B").is_some(),
            "{case}: B serves the CLAIM before the erase"
        );
        assert_registered(&vault_b, claim, message, msg_learned);
        if purge {
            vault_a
                .delete_entity_with_options(
                    &message,
                    crate::deletion::DeleteEntityOptions { purge: true },
                )
                .expect("hard erase on A");
        } else {
            vault_a.delete_entity(&message).expect("soft erase on A");
        }
        assert!(
            vault_a.get_claim(&claim).expect("read A").is_none(),
            "{case}: A withdraws its own CLAIM after the erase"
        );
        insert_tombstone_v2(&doc_a, message, reason, 1_772_401_000);
        doc_a.commit();
        let update = doc_a
            .export(loro::ExportMode::all_updates())
            .expect("export tombstone");
        doc_b.import(&update).expect("B imports tombstone");
        rematerialize(&vault_b, &doc_b, &key);
        assert!(
            vault_b.get_claim(&claim).expect("read B").is_none(),
            "{case}: B withdraws the CLAIM after replaying the erase"
        );
        // The CLAIM row still stands; only its words withdrew through the walk.
        assert!(
            raw_of(&vault_b, claim).len() > crate::batch::ENTITY_METADATA_HEADER_LEN,
            "{case}: B keeps the CLAIM row behind the withdrawal"
        );
        assert_registered(&vault_b, claim, message, msg_learned);
        // Proof of the walk (not just the gate hiding the row): the CLAIM
        // carries the walk's stale mark on B.
        {
            let txn = vault_b.store.env.read_txn().expect("read txn");
            assert!(
                crate::ports::stale_in_txn(&vault_b.store, &txn, &claim).expect("stale read"),
                "{case}: B's walk marked the CLAIM stale"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// T2: a CLAIM arriving after its MESSAGE tombstone lands withdrawn.
// Mode: sync-all receiver (explicit). Hook-undone: CLAIM lands readable (fails).
// ---------------------------------------------------------------------------

#[test]
fn a_claim_arriving_after_its_message_tombstone_lands_withdrawn() {
    let member_ref = member(0x55);
    let (_dir_a, vault_a, _) = test_vault_with_grant(member_ref);
    let (_dir_b, vault_b, _) = test_vault_with_grant(member_ref);
    set_mode(&vault_b, crate::sync::SyncResidenceMode::All);
    let (_turn, _conv, message, claim, _msg_learned, _claim_learned) =
        witnessed_claim_on(&vault_a, 0x12, "call me Owen", 1_772_410_000);
    let key = window_key();
    // B holds the planted MESSAGE, then its soft tombstone arrives
    // synthetically via Loro (no erase on A in T2; see header).
    plant_message_from_a(&vault_a, &vault_b, message);
    assert!(
        vault_b.get(&message).expect("read B msg").is_some(),
        "B holds the MESSAGE before its tombstone"
    );
    let doc_a = crate::sync::schema::create_window_doc("a", &key);
    insert_tombstone_v2(&doc_a, message, TombstoneReason::UserDelete, 1_772_411_000);
    doc_a.commit();
    let mut doc_b = synced_device(&doc_a, &key, &vault_b);
    assert!(
        vault_b.get(&message).expect("read B msg").is_none(),
        "B deleted the MESSAGE before the CLAIM arrives"
    );
    // The CLAIM arrives late, over deletion evidence: it lands withdrawn.
    let doc_claim = crate::sync::schema::create_window_doc("a", &key);
    insert_blob(&doc_claim, claim, &raw_of(&vault_a, claim));
    doc_claim.commit();
    let update = doc_claim
        .export(loro::ExportMode::all_updates())
        .expect("export claim");
    doc_b.import(&update).expect("B imports late CLAIM");
    rematerialize(&vault_b, &doc_b, &key);
    assert!(
        vault_b.get_claim(&claim).expect("read B").is_none(),
        "a CLAIM arriving after its MESSAGE tombstone lands withdrawn"
    );
    assert!(
        raw_of(&vault_b, claim).len() > crate::batch::ENTITY_METADATA_HEADER_LEN,
        "the withdrawn CLAIM row still lands"
    );
    let txn = vault_b.store.env.read_txn().expect("read txn");
    assert!(crate::ports::stale_in_txn(&vault_b.store, &txn, &claim).expect("born stale"));
}

// ---------------------------------------------------------------------------
// T3: a CLAIM arriving before its MESSAGE waits, then registers.
// Mode: sync-all receiver (explicit, case 4a). Hook-undone: CLAIM lands at once
// (no hold, no marker) and the held asserts fail.
// ---------------------------------------------------------------------------

#[test]
fn a_claim_arriving_before_its_message_waits_then_registers() {
    let member_ref = member(0x55);
    let (_dir_a, vault_a, _) = test_vault_with_grant(member_ref);
    let (_dir_b, vault_b, _) = test_vault_with_grant(member_ref);
    set_mode(&vault_b, crate::sync::SyncResidenceMode::All);
    let (_turn, _conv, message, claim, msg_learned, _claim_learned) =
        witnessed_claim_on(&vault_a, 0x12, "call me Owen", 1_772_420_000);
    let key = window_key();
    // The CLAIM arrives first, with no MESSAGE row, listing, or deletion
    // evidence on a sync-all B: it is held pending its source.
    let doc_claim = crate::sync::schema::create_window_doc("a", &key);
    insert_blob(&doc_claim, claim, &raw_of(&vault_a, claim));
    doc_claim.commit();
    let mut doc_b = synced_device(&doc_claim, &key, &vault_b);
    assert!(
        vault_b.get_claim(&claim).expect("read B").is_none(),
        "the early CLAIM installs nothing while held"
    );
    let marker = format!("rm:w:{}:{}", key.as_str(), claim.to_hex());
    assert_eq!(
        vault_b
            .sync_state_get(&marker)
            .expect("marker read")
            .as_deref(),
        Some([1u8].as_slice()),
        "the held CLAIM leaves its rm:w: marker"
    );
    let records = quarantined_records(&vault_b).expect("quarantine read");
    assert!(
        records.iter().any(|(_, record)| {
            record.window_key == key.as_str()
                && record.container == QuarantineContainer::Entities
                && record.reason_code == "ClaimSourcePending"
        }),
        "the held CLAIM leaves a ClaimSourcePending x: row: {records:?}"
    );
    assert_eq!(
        crate::sync::quarantine::pending_remat_windows(&vault_b).expect("pending read"),
        vec![key.as_str().to_string()],
        "the held window stays flagged"
    );
    // Plant the arrived MESSAGE, then retry the held CLAIM through replay.
    plant_message_from_a(&vault_a, &vault_b, message);
    rematerialize(&vault_b, &doc_b, &key);
    assert!(
        vault_b.get(&message).expect("read B msg").is_some(),
        "the MESSAGE lands"
    );
    assert!(
        vault_b.get_claim(&claim).expect("read B").is_some(),
        "the retried CLAIM reads after its MESSAGE lands"
    );
    assert_registered(&vault_b, claim, message, msg_learned);
    assert_eq!(
        vault_b.sync_state_get(&marker).expect("marker read"),
        None,
        "the healing write clears the rm:w: marker"
    );
    assert!(
        crate::sync::quarantine::pending_remat_windows(&vault_b)
            .expect("pending read")
            .is_empty(),
        "no window stays flagged after the heal"
    );
    // A later erase still withdraws the registered CLAIM.
    vault_a.delete_entity(&message).expect("erase on A");
    insert_tombstone_v2(
        &doc_claim,
        message,
        TombstoneReason::UserDelete,
        1_772_421_000,
    );
    doc_claim.commit();
    let update = doc_claim
        .export(loro::ExportMode::all_updates())
        .expect("export tombstone");
    doc_b.import(&update).expect("B imports tombstone");
    rematerialize(&vault_b, &doc_b, &key);
    assert!(
        vault_b.get_claim(&claim).expect("read B").is_none(),
        "the registered CLAIM withdraws after a later erase"
    );
}

// ---------------------------------------------------------------------------
// T4 (control): erasing an unrelated MESSAGE leaves the CLAIM readable.
// Mode: sync-all receiver (explicit). Hook-undone: stays green.
// ---------------------------------------------------------------------------

#[test]
fn erasing_an_unrelated_message_leaves_the_claim_readable() {
    let member_ref = member(0x55);
    let (_dir_a, vault_a, _) = test_vault_with_grant(member_ref);
    let (_dir_b, vault_b, _) = test_vault_with_grant(member_ref);
    set_mode(&vault_b, crate::sync::SyncResidenceMode::All);
    let (_t1, _c1, message_cited, claim, _msg_learned, _) =
        witnessed_claim_on(&vault_a, 0x12, "call me Owen", 1_772_430_000);
    let (_t2, _c2, message_other, _claim_other, _, _) =
        witnessed_claim_on(&vault_a, 0x22, "unrelated words here", 1_772_435_000);
    let key = window_key();
    plant_message_from_a(&vault_a, &vault_b, message_cited);
    plant_message_from_a(&vault_a, &vault_b, message_other);
    let doc_a = crate::sync::schema::create_window_doc("a", &key);
    insert_blob(&doc_a, claim, &raw_of(&vault_a, claim));
    doc_a.commit();
    let mut doc_b = synced_device(&doc_a, &key, &vault_b);
    assert!(
        vault_b.get_claim(&claim).expect("read B").is_some(),
        "B serves the CLAIM before the unrelated erase"
    );
    // No registration assert here: T4 is a control that must stay green with
    // the hook undone (when B holds no rows).
    vault_a.delete_entity(&message_other).expect("erase other");
    insert_tombstone_v2(
        &doc_a,
        message_other,
        TombstoneReason::UserDelete,
        1_772_431_000,
    );
    doc_a.commit();
    let update = doc_a
        .export(loro::ExportMode::all_updates())
        .expect("export tombstone");
    doc_b.import(&update).expect("B imports tombstone");
    rematerialize(&vault_b, &doc_b, &key);
    assert!(
        vault_b.get_claim(&claim).expect("read B").is_some(),
        "erasing an unrelated MESSAGE leaves the CLAIM readable"
    );
    // No registration assert: control stays green with the hook undone.
}

// ---------------------------------------------------------------------------
// T5: a third device never gets the CLAIM readable after the erase.
// Modes: sync-all B and C (explicit). Hook-undone: B stays readable (fails).
// ---------------------------------------------------------------------------

#[test]
fn a_third_device_never_gets_the_claim_readable_after_the_erase() {
    let member_ref = member(0x55);
    let (_dir_a, vault_a, _) = test_vault_with_grant(member_ref);
    let (_dir_b, vault_b, _) = test_vault_with_grant(member_ref);
    let (_dir_c, vault_c, _) = test_vault_with_grant(member_ref);
    set_mode(&vault_b, crate::sync::SyncResidenceMode::All);
    set_mode(&vault_c, crate::sync::SyncResidenceMode::All);
    let (_turn, _conv, message, claim, _msg_learned, _) =
        witnessed_claim_on(&vault_a, 0x12, "call me Owen", 1_772_440_000);
    let key = window_key();
    // MESSAGE planted on B only; C gets CLAIM + tombstone via B's mirror.
    plant_message_from_a(&vault_a, &vault_b, message);
    let doc_a = crate::sync::schema::create_window_doc("a", &key);
    insert_blob(&doc_a, claim, &raw_of(&vault_a, claim));
    doc_a.commit();
    let mut doc_b = synced_device(&doc_a, &key, &vault_b);
    assert!(
        vault_b.get_claim(&claim).expect("read B").is_some(),
        "B serves the CLAIM before the erase"
    );
    vault_a.delete_entity(&message).expect("erase on A");
    insert_tombstone_v2(&doc_a, message, TombstoneReason::UserDelete, 1_772_441_000);
    doc_a.commit();
    let update = doc_a
        .export(loro::ExportMode::all_updates())
        .expect("export tombstone");
    doc_b.import(&update).expect("B imports tombstone");
    rematerialize(&vault_b, &doc_b, &key);
    assert!(
        vault_b.get_claim(&claim).expect("read B").is_none(),
        "B withdraws after the erase"
    );
    // C syncs from B's post-erase mirror (CLAIM carrier + tombstone): the
    // CLAIM lands withdrawn there too and never reads.
    let _doc_c = synced_device(&doc_b, &key, &vault_c);
    assert!(
        vault_c.get_claim(&claim).expect("read C").is_none(),
        "C never gets the CLAIM readable after the erase"
    );
    assert!(
        raw_of(&vault_c, claim).len() > crate::batch::ENTITY_METADATA_HEADER_LEN,
        "C still lands the withdrawn CLAIM row"
    );
}

// ---------------------------------------------------------------------------
// F1 (control): a federated copy keeps today's rule.
// Mode: sync-all receiver (explicit; federated never holds or registers).
// Hook-undone: stays green.
// ---------------------------------------------------------------------------

#[test]
fn a_federated_copy_keeps_todays_rule() {
    let member_ref = member(0x55);
    let (_dir_a, vault_a, _) = test_vault_with_grant(member_ref);
    let (_dir_b, vault_b, grant_b) = test_vault_with_grant(member_ref);
    super::put_imported_source_trust(&vault_b);
    set_mode(&vault_b, crate::sync::SyncResidenceMode::All);
    let (_turn, _conv, _message, claim, _msg_learned, _claim_learned) =
        witnessed_claim_on(&vault_a, 0x12, "call me Owen", 1_772_450_000);
    let key = window_key();
    // A federated CLAIM with no MESSAGE on a sync-all B: unlike T3's own-vault
    // hold, it lands at once, readable and unregistered. The hook tells it
    // apart via the peer-origin map, which now carries exact digests.
    let peer = crate::sync::schema::create_window_doc("federation-peer", &key);
    insert_blob(&peer, claim, &raw_of(&vault_a, claim));
    peer.commit();
    let update = peer
        .export(loro::ExportMode::all_updates())
        .expect("export peer CLAIM");
    let live = crate::sync::schema::create_window_doc("local", &key);
    import_from_peer(
        &vault_b,
        &live,
        &key,
        &update,
        (member_ref, grant_b),
        FederationAdmissionRole::Member,
    );
    assert!(
        vault_b.get_claim(&claim).expect("read B").is_some(),
        "a federated CLAIM lands readable"
    );
    assert_unregistered(&vault_b, claim);
    let marker = format!("rm:w:{}:{}", key.as_str(), claim.to_hex());
    assert_eq!(
        vault_b.sync_state_get(&marker).expect("marker read"),
        None,
        "a federated CLAIM is never held pending its source"
    );
}

// ---------------------------------------------------------------------------
// O1: an index-listed MESSAGE registers the CLAIM (opened device).
// Mode: opened receiver (explicit). Hook-undone: readable stays green, but the
// registration assert fails (no rows without the hook).
// ---------------------------------------------------------------------------

#[test]
fn an_index_listed_message_registers_the_claim() {
    let member_ref = member(0x55);
    let (_dir_a, vault_a, _) = test_vault_with_grant(member_ref);
    let (_dir_b, vault_b, _) = test_vault_with_grant(member_ref);
    set_mode(&vault_b, crate::sync::SyncResidenceMode::Opened);
    let (_turn, _conv, message, claim, msg_learned, _) =
        witnessed_claim_on(&vault_a, 0x12, "call me Owen", 1_772_460_000);
    let wk = window_key();
    // B holds no MESSAGE row, only a thin index listing with A's learned_at.
    assert!(
        vault_b.get(&message).expect("read B msg").is_none(),
        "B holds no MESSAGE row"
    );
    plant_listing(&vault_b, wk.as_str(), message, msg_learned);
    {
        let txn = vault_b.store.env.read_txn().expect("read txn");
        let listing = crate::sync::residence::index_listing_of_item_in_txn(
            &vault_b.store,
            &txn,
            &message.to_hex(),
        )
        .expect("listing read");
        assert_eq!(
            listing.map(|entry| entry.learned_at),
            Some(msg_learned),
            "the planted listing carries A's learned_at"
        );
    }
    let doc_a = crate::sync::schema::create_window_doc("a", &wk);
    insert_blob(&doc_a, claim, &raw_of(&vault_a, claim));
    doc_a.commit();
    let _doc_b = synced_device(&doc_a, &wk, &vault_b);
    assert!(
        vault_b.get_claim(&claim).expect("read B").is_some(),
        "the CLAIM reads on a listing alone"
    );
    assert_registered(&vault_b, claim, message, msg_learned);
    let marker = format!("rm:w:{}:{}", wk.as_str(), claim.to_hex());
    assert_eq!(
        vault_b.sync_state_get(&marker).expect("marker read"),
        None,
        "an opened device never holds a listed CLAIM"
    );
}

// ---------------------------------------------------------------------------
// O4: the CLAIM stays readable when its source window leaves the index.
// Mode: opened receiver (explicit, case 4b). Hook-undone: stays green.
// PR1-OPENED-COLD-SOURCE-MODE = A (28 Nov): the stored resolved-mode row says
// Opened (`set_mode` records it, as a connection does), so the gate counts the
// purged absent, unlisted, unmarked source as standing.
// ---------------------------------------------------------------------------

#[test]
fn the_claim_stays_readable_when_its_source_window_leaves_the_index() {
    let member_ref = member(0x55);
    let (_dir_a, vault_a, _) = test_vault_with_grant(member_ref);
    let (_dir_b, vault_b, _) = test_vault_with_grant(member_ref);
    set_mode(&vault_b, crate::sync::SyncResidenceMode::Opened);
    let (_turn, _conv, message, claim, msg_learned, _) =
        witnessed_claim_on(&vault_a, 0x12, "call me Owen", 1_772_470_000);
    let wk = window_key();
    plant_listing(&vault_b, wk.as_str(), message, msg_learned);
    let doc_a = crate::sync::schema::create_window_doc("a", &wk);
    insert_blob(&doc_a, claim, &raw_of(&vault_a, claim));
    doc_a.commit();
    let _doc_b = synced_device(&doc_a, &wk, &vault_b);
    assert!(
        vault_b.get_claim(&claim).expect("read B").is_some(),
        "the CLAIM reads on a listing alone"
    );
    // No registration assert: O4 stays green with the hook undone.
    // The index refresh purges the listing and its twin with no soft
    // tombstone (S2 stale-window shape): DIRECT row deletes, planted.
    vault_b
        .with_write_txn_grouped(|txn| {
            let hex = message.to_hex();
            vault_b
                .store
                .sync_state
                .delete(txn, &format!("ri:w:{}:{hex}", wk.as_str()))?;
            crate::sync::residence::delete_index_by_item_in_txn(
                &vault_b.store,
                txn,
                wk.as_str(),
                &hex,
            )?;
            Ok(())
        })
        .expect("purge listing");
    {
        let txn = vault_b.store.env.read_txn().expect("read txn");
        assert!(
            crate::sync::residence::index_listing_of_item_in_txn(
                &vault_b.store,
                &txn,
                &message.to_hex(),
            )
            .expect("listing read")
            .is_none(),
            "the listing is gone"
        );
        assert!(
            !crate::sync::residence::soft_drop_marker_exists_in_txn(
                &vault_b.store,
                &txn,
                &message.to_hex(),
            )
            .expect("marker read"),
            "a window leaving the index writes no soft-drop marker"
        );
    }
    assert!(
        vault_b.get_claim(&claim).expect("read B").is_some(),
        "the CLAIM stays readable when its source window leaves the index (4b)"
    );
}
