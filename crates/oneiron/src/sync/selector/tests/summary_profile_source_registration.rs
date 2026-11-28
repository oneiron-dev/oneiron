//! Own-vault scope SUMMARY and PSYCH_PROFILE source registration on replicated window puts.

use super::claim_source_registration as shared;
use super::claim_source_typed_refs::{
    cold_row, cold_twin, deliver, has_row, held, id, plant_row, source_raw, stale, window_key,
};
use super::{import_from_peer, insert_blob, rematerialize, synced_device, test_vault_with_grant};
use crate::deletion::TombstoneReason;
use crate::psych_profile::{
    PsychProfile, PsychProfileConfidence, PsychProfileSource, PsychProfileSourceWords,
    encode_psych_profile_body,
};
use crate::registry::{ENTITY_TYPE_PSYCH_PROFILE, ENTITY_TYPE_SUMMARY};
use crate::scope_summary::{ScopeSummaryBody, SummarySourceMessage, encode_scope_summary_body};
use crate::store::revision_ref::RevisionRef;
use crate::sync::{FederationAdmissionRole, SyncResidenceMode};
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};

const SOURCE_AT: u64 = 1_772_410_000;
const L1: u64 = 1_772_411_000;
const ERASE_AT: u64 = 1_772_412_000;
const L2: u64 = 1_772_413_000;

fn summary_raw(cover: EntityId, message: EntityId) -> Vec<u8> {
    let body = ScopeSummaryBody {
        v: 2,
        scope: None,
        text: "Composed summary".to_owned(),
        actor: crate::store::base_agent::dreamer_actor_id()
            .expect("Dreamer actor id")
            .to_hex(),
        covers: vec![cover],
        minted_at: L1,
        messages: vec![SummarySourceMessage {
            id: message,
            revision: [1; 32],
        }],
        memo: Some([2; 32]),
        notes: Vec::new(),
    };
    crate::test_util::entity_record(
        ENTITY_TYPE_SUMMARY,
        TimeRange { start: L1, end: L1 },
        L1,
        0,
        &encode_scope_summary_body(&body).expect("encode scope SUMMARY"),
    )
}

fn profile_raw(documents: &[EntityId], learned_at: u64) -> Vec<u8> {
    // Keep revision ids distinct from document ids, and stable across versions.
    let sources: Vec<_> = documents
        .iter()
        .map(|&document_ref| PsychProfileSource {
            revision_ref: id(document_ref.as_bytes()[0] ^ 0x80),
            document_ref,
            world_ref: None,
            document_revision: RevisionRef([1; 16]),
            words: PsychProfileSourceWords::Record { content: [2; 32] },
        })
        .collect();
    let profile = PsychProfile::new(
        id(0x70),
        "Compact profile",
        "Profile text",
        "Narrative profile",
        sources.iter().map(|source| source.revision_ref).collect(),
        PsychProfileConfidence::new(0.8, 0.7, 0.6).expect("valid confidence"),
    )
    .expect("profile body")
    .with_sources(sources)
    .expect("profile source words");
    crate::test_util::entity_record(
        ENTITY_TYPE_PSYCH_PROFILE,
        TimeRange {
            start: learned_at,
            end: learned_at,
        },
        learned_at,
        0,
        &encode_psych_profile_body(&profile).expect("encode PSYCH_PROFILE"),
    )
}

fn erase_source(vault: &Vault, doc: &loro::LoroDoc, source: EntityId) {
    deliver(
        vault,
        doc,
        &[],
        &[(source, TombstoneReason::UserHardDelete, ERASE_AT)],
    );
    assert!(
        vault.get(&source).expect("read source").is_none(),
        "B applied the source tombstone"
    );
}

// ---------------------------------------------------------------------------
// SS1: an absent cover and an absent MESSAGE leave the SUMMARY readable without a hold.
// Hook undone: the assertion for the cover's cold row fails.
// ---------------------------------------------------------------------------

#[test]
fn an_absent_summary_source_lands_the_summary_readable_with_its_cold_rows() {
    for mode in [SyncResidenceMode::All, SyncResidenceMode::Opened] {
        let (_dir_b, vault_b, _) = test_vault_with_grant(id(0x55));
        shared::set_mode(&vault_b, mode);
        let (summary, cover, message) = (id(0x21), id(0x22), id(0x23));
        let key = window_key();
        let doc_a = crate::sync::schema::create_window_doc("a", &key);
        insert_blob(&doc_a, summary, &summary_raw(cover, message));
        doc_a.commit();
        let _doc_b = synced_device(&doc_a, &key, &vault_b);

        assert!(
            vault_b.get(&summary).expect("read SUMMARY").is_some(),
            "{mode:?}: the SUMMARY lands readable without its sources"
        );
        for source in [cover, message] {
            assert!(
                has_row(&vault_b, &cold_row(summary, source)),
                "{mode:?}: missing SUMMARY cold row for {source:?}"
            );
            assert!(has_row(&vault_b, &cold_twin(summary, source)));
        }
        assert!(
            !held(&vault_b, summary),
            "{mode:?}: the SUMMARY is not held"
        );
        shared::assert_unregistered(&vault_b, summary);
    }
}

// ---------------------------------------------------------------------------
// SS2: a source tombstone B already holds makes the SUMMARY land stale, not absent from storage.
// Hook undone: the stale assertion fails.
// ---------------------------------------------------------------------------

#[test]
fn a_summary_arriving_after_its_source_tombstone_lands_withdrawn() {
    let (_dir_b, vault_b, _) = test_vault_with_grant(id(0x55));
    shared::set_mode(&vault_b, SyncResidenceMode::All);
    let (summary, source) = (id(0x24), id(0x25));
    plant_row(&vault_b, source, &source_raw(SOURCE_AT));
    let doc_b = crate::sync::schema::create_window_doc("device", &window_key());
    erase_source(&vault_b, &doc_b, source);
    let raw = summary_raw(source, id(0x26));
    deliver(&vault_b, &doc_b, &[(summary, raw.as_slice())], &[]);

    assert!(stale(&vault_b, summary), "the SUMMARY lands marked stale");
    assert!(
        vault_b.get(&summary).expect("read SUMMARY").is_none(),
        "B withholds the withdrawn SUMMARY"
    );
    assert!(
        shared::raw_of(&vault_b, summary).len() > crate::batch::ENTITY_METADATA_HEADER_LEN,
        "the withdrawn SUMMARY row still lands with a body"
    );
    assert!(!held(&vault_b, summary), "deletion evidence never holds");
}

// ---------------------------------------------------------------------------
// SS3: a late source registers at its header, consumes the cold twin, and withdraws the SUMMARY
// when erased. Hook undone: the initial cold twin assertion fails, so no late registration follows.
// ---------------------------------------------------------------------------

#[test]
fn a_summary_source_that_lands_later_is_judged_at_its_landing() {
    let (_dir_b, vault_b, _) = test_vault_with_grant(id(0x55));
    shared::set_mode(&vault_b, SyncResidenceMode::All);
    let (summary, source) = (id(0x27), id(0x28));
    let doc_b = crate::sync::schema::create_window_doc("device", &window_key());
    let raw = summary_raw(source, id(0x29));
    deliver(&vault_b, &doc_b, &[(summary, raw.as_slice())], &[]);
    let row = cold_row(summary, source);
    let twin = cold_twin(summary, source);
    assert!(
        vault_b.get(&summary).expect("read SUMMARY").is_some(),
        "the SUMMARY lands readable before its source"
    );
    assert!(
        has_row(&vault_b, &twin),
        "the SUMMARY carries its cold twin"
    );
    assert!(has_row(&vault_b, &row), "the SUMMARY carries a cold row");
    shared::assert_unregistered(&vault_b, summary);

    let source_row = source_raw(SOURCE_AT);
    deliver(&vault_b, &doc_b, &[(source, source_row.as_slice())], &[]);
    let frontier = shared::learned_of(&shared::raw_of(&vault_b, source));
    shared::assert_registered(&vault_b, summary, source, frontier);
    assert!(!has_row(&vault_b, &twin), "the landing consumes the twin");
    assert!(has_row(&vault_b, &row), "the cold-citation row stays");
    assert!(vault_b.get(&summary).expect("read SUMMARY").is_some());

    erase_source(&vault_b, &doc_b, source);
    assert!(
        stale(&vault_b, summary),
        "the source erase marks the SUMMARY stale"
    );
    assert!(vault_b.get(&summary).expect("read SUMMARY").is_none());
}

// ---------------------------------------------------------------------------
// SS4: a resident source registers at its header and its erase withdraws the SUMMARY.
// Hook undone: assert_registered fails.
// ---------------------------------------------------------------------------

#[test]
fn a_resident_summary_source_registers_and_its_erase_withdraws() {
    let (_dir_b, vault_b, _) = test_vault_with_grant(id(0x55));
    shared::set_mode(&vault_b, SyncResidenceMode::All);
    let (summary, source) = (id(0x2a), id(0x2b));
    let source_row = source_raw(SOURCE_AT);
    plant_row(&vault_b, source, &source_row);
    let doc_b = crate::sync::schema::create_window_doc("device", &window_key());
    let raw = summary_raw(source, id(0x2c));
    deliver(&vault_b, &doc_b, &[(summary, raw.as_slice())], &[]);
    shared::assert_registered(&vault_b, summary, source, shared::learned_of(&source_row));
    assert!(vault_b.get(&summary).expect("read SUMMARY").is_some());

    erase_source(&vault_b, &doc_b, source);
    assert!(
        stale(&vault_b, summary),
        "the source erase marks the SUMMARY stale"
    );
    assert!(vault_b.get(&summary).expect("read SUMMARY").is_none());
}

// ---------------------------------------------------------------------------
// SS5: a peer's SUMMARY lands readable and unregistered, without cold rows.
// Peer tag undone: the assertion that there is no cold row fails.
// ---------------------------------------------------------------------------

#[test]
fn a_federated_summary_keeps_todays_rule() {
    let member_ref = id(0x55);
    let (_dir_b, vault_b, grant_b) = test_vault_with_grant(member_ref);
    super::put_imported_source_trust(&vault_b);
    shared::set_mode(&vault_b, SyncResidenceMode::All);
    let (summary, cover, message) = (id(0x2d), id(0x2e), id(0x2f));
    let key = window_key();
    let peer = crate::sync::schema::create_window_doc("federation-peer", &key);
    insert_blob(&peer, summary, &summary_raw(cover, message));
    peer.commit();
    let update = peer
        .export(loro::ExportMode::all_updates())
        .expect("export peer SUMMARY");
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
        vault_b.get(&summary).expect("read SUMMARY").is_some(),
        "the federated SUMMARY lands readable"
    );
    for source in [cover, message] {
        assert!(
            !has_row(&vault_b, &cold_row(summary, source)),
            "the own-vault hook never writes cold rows for a peer's SUMMARY"
        );
        assert!(!has_row(&vault_b, &cold_twin(summary, source)));
    }
    assert!(!held(&vault_b, summary));
    shared::assert_unregistered(&vault_b, summary);
}

// ---------------------------------------------------------------------------
// PP1: a resident source registers at its header and its erase withdraws the profile.
// Hook undone: assert_registered fails.
// ---------------------------------------------------------------------------

#[test]
fn a_resident_profile_source_registers_and_its_erase_withdraws() {
    let (_dir_b, vault_b, _) = test_vault_with_grant(id(0x55));
    shared::set_mode(&vault_b, SyncResidenceMode::All);
    let (profile, source) = (id(0x31), id(0x32));
    let source_row = source_raw(SOURCE_AT);
    plant_row(&vault_b, source, &source_row);
    let doc_b = crate::sync::schema::create_window_doc("device", &window_key());
    let raw = profile_raw(&[source], L1);
    deliver(&vault_b, &doc_b, &[(profile, raw.as_slice())], &[]);
    shared::assert_registered(&vault_b, profile, source, shared::learned_of(&source_row));
    assert!(vault_b.get(&profile).expect("read profile row").is_some());
    assert!(
        vault_b
            .get_psych_profile(&profile)
            .expect("read profile")
            .is_some()
    );

    erase_source(&vault_b, &doc_b, source);
    assert!(
        stale(&vault_b, profile),
        "the source erase marks the profile stale"
    );
    assert!(vault_b.get(&profile).expect("read profile row").is_none());
    assert!(
        vault_b
            .get_psych_profile(&profile)
            .expect("read profile")
            .is_none()
    );
}

// ---------------------------------------------------------------------------
// PP2: an absent source leaves the profile readable, with a cold row but no hold or registration.
// Hook undone: the profile's cold row assertion fails.
// ---------------------------------------------------------------------------

#[test]
fn an_absent_profile_source_lands_the_profile_readable_with_its_cold_row() {
    for mode in [SyncResidenceMode::All, SyncResidenceMode::Opened] {
        let (_dir_b, vault_b, _) = test_vault_with_grant(id(0x55));
        shared::set_mode(&vault_b, mode);
        let (profile, source) = (id(0x33), id(0x34));
        let key = window_key();
        let doc_a = crate::sync::schema::create_window_doc("a", &key);
        insert_blob(&doc_a, profile, &profile_raw(&[source], L1));
        doc_a.commit();
        let _doc_b = synced_device(&doc_a, &key, &vault_b);

        assert!(vault_b.get(&profile).expect("read profile row").is_some());
        assert!(
            vault_b
                .get_psych_profile(&profile)
                .expect("read profile")
                .is_some(),
            "{mode:?}: the profile lands readable without its source"
        );
        assert!(
            has_row(&vault_b, &cold_row(profile, source)),
            "{mode:?}: the profile carries its cold row"
        );
        assert!(has_row(&vault_b, &cold_twin(profile, source)));
        assert!(
            !held(&vault_b, profile),
            "{mode:?}: the profile is not held"
        );
        shared::assert_unregistered(&vault_b, profile);
    }
}

fn land_and_withdraw_initial_profile(
    vault: &Vault,
    doc: &loro::LoroDoc,
    profile: EntityId,
    s1: EntityId,
    s2: EntityId,
) -> (Vec<u8>, u64) {
    let s1_row = source_raw(SOURCE_AT);
    let s2_row = source_raw(SOURCE_AT + 1);
    plant_row(vault, s1, &s1_row);
    plant_row(vault, s2, &s2_row);
    let raw = profile_raw(&[s1, s2], L1);
    deliver(vault, doc, &[(profile, raw.as_slice())], &[]);
    let s2_frontier = shared::learned_of(&s2_row);
    shared::assert_registered(vault, profile, s1, shared::learned_of(&s1_row));
    shared::assert_registered(vault, profile, s2, s2_frontier);
    erase_source(vault, doc, s1);
    assert!(
        stale(vault, profile),
        "the erase marks the initial profile stale"
    );
    assert!(
        vault
            .get_psych_profile(&profile)
            .expect("read profile")
            .is_none()
    );
    (raw, s2_frontier)
}

fn deliver_profile_replacement(vault: &Vault, doc: &loro::LoroDoc, profile: EntityId, raw: &[u8]) {
    // A replacement must follow the prior map write causally, even when its
    // entity header is older. An unrelated one-op sender could lose the map tie.
    let sender = doc.fork();
    insert_blob(&sender, profile, raw);
    sender.commit();
    let update = sender
        .export(loro::ExportMode::all_updates())
        .expect("export replacement profile");
    doc.import(&update).expect("import replacement profile");
    assert_eq!(
        crate::sync::loro_support::map_get_bytes(&doc.get_map("entities"), &profile.to_hex())
            .as_deref(),
        Some(raw),
        "the replacement carrier is the live window value"
    );
    rematerialize(vault, doc, &window_key());
}

fn assert_only_profile_source(vault: &Vault, profile: EntityId, source: EntityId, frontier: u64) {
    shared::assert_registered(vault, profile, source, frontier);
    let txn = vault.store.env.read_txn().expect("read dependencies");
    let sources = crate::ports::dependency_sources_in(&vault.store, &txn, &profile)
        .expect("profile dependency sources");
    assert_eq!(
        sources,
        vec![source],
        "only the standing source is registered"
    );
}

// ---------------------------------------------------------------------------
// PR1: a newer profile using only its standing source clears the mark and is shown at L2.
// B never completes (regenerated forced false): the "shown" assertion fails.
// ---------------------------------------------------------------------------

#[test]
fn a_profile_derived_again_after_a_source_erase_is_shown_when_its_sources_stand() {
    let (_dir_b, vault_b, _) = test_vault_with_grant(id(0x55));
    shared::set_mode(&vault_b, SyncResidenceMode::All);
    let (profile, s1, s2) = (id(0x35), id(0x36), id(0x37));
    let doc_b = crate::sync::schema::create_window_doc("device", &window_key());
    let (_, s2_frontier) = land_and_withdraw_initial_profile(&vault_b, &doc_b, profile, s1, s2);
    deliver_profile_replacement(&vault_b, &doc_b, profile, &profile_raw(&[s2], L2));

    assert!(
        vault_b
            .get_psych_profile(&profile)
            .expect("read profile")
            .is_some(),
        "shown: B serves the regenerated profile when its sources stand"
    );
    assert!(vault_b.get(&profile).expect("read profile row").is_some());
    assert!(
        !stale(&vault_b, profile),
        "regeneration clears the stale mark"
    );
    assert_eq!(shared::learned_of(&shared::raw_of(&vault_b, profile)), L2);
    assert_only_profile_source(&vault_b, profile, s2, s2_frontier);
}

// ---------------------------------------------------------------------------
// PR2: a newer profile whose new source is already deleted lands at L2 but stays withdrawn.
// Deleted sources ignored (skip S3 without setting withdrawn): the stale assertion fails.
// ---------------------------------------------------------------------------

#[test]
fn a_profile_derived_again_with_a_deleted_source_keeps_its_mark() {
    let (_dir_b, vault_b, _) = test_vault_with_grant(id(0x55));
    shared::set_mode(&vault_b, SyncResidenceMode::All);
    let (profile, s1, s2, s3) = (id(0x38), id(0x39), id(0x3a), id(0x3b));
    let doc_b = crate::sync::schema::create_window_doc("device", &window_key());
    let _ = land_and_withdraw_initial_profile(&vault_b, &doc_b, profile, s1, s2);
    plant_row(&vault_b, s3, &source_raw(SOURCE_AT + 2));
    erase_source(&vault_b, &doc_b, s3);
    deliver_profile_replacement(&vault_b, &doc_b, profile, &profile_raw(&[s2, s3], L2));

    assert_eq!(shared::learned_of(&shared::raw_of(&vault_b, profile)), L2);
    assert!(
        stale(&vault_b, profile),
        "the deleted source keeps the stale mark"
    );
    assert!(vault_b.get(&profile).expect("read profile row").is_none());
    assert!(
        vault_b
            .get_psych_profile(&profile)
            .expect("read profile")
            .is_none()
    );
}

// ---------------------------------------------------------------------------
// PR3: a late L1 carrier leaves the regenerated profile's cleared mark and registration alone.
// Late guard undone: L1's erased S1 marks the profile stale, failing the final stale assertion.
// ---------------------------------------------------------------------------

#[test]
fn an_older_profile_version_arriving_late_leaves_the_mark() {
    let (_dir_b, vault_b, _) = test_vault_with_grant(id(0x55));
    shared::set_mode(&vault_b, SyncResidenceMode::All);
    let (profile, s1, s2) = (id(0x3c), id(0x3d), id(0x3e));
    let doc_b = crate::sync::schema::create_window_doc("device", &window_key());
    let (first, s2_frontier) = land_and_withdraw_initial_profile(&vault_b, &doc_b, profile, s1, s2);
    deliver_profile_replacement(&vault_b, &doc_b, profile, &profile_raw(&[s2], L2));
    assert!(
        vault_b
            .get_psych_profile(&profile)
            .expect("read profile")
            .is_some(),
        "the regenerated profile is shown before L1 arrives again"
    );
    assert!(vault_b.get(&profile).expect("read profile row").is_some());
    assert!(!stale(&vault_b, profile));
    assert_eq!(shared::learned_of(&shared::raw_of(&vault_b, profile)), L2);
    assert_only_profile_source(&vault_b, profile, s2, s2_frontier);

    deliver_profile_replacement(&vault_b, &doc_b, profile, &first);
    assert!(
        !stale(&vault_b, profile),
        "the late L1 carrier does not restore the stale mark"
    );
    assert_only_profile_source(&vault_b, profile, s2, s2_frontier);
}
