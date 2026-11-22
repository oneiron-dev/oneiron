//! A row whose words came from a record a use limit keeps for storage only stays home with that
//! record: the whole-vault export and the owner's full window keep it out, as the owner's own
//! scoped read withholds it (FIX 1496 S8; FIX EGRESS-CARRIES-ROWS-DERIVED-FROM-USE-LIMITED-RECORDS).
//!
//! Both doors asked only a row's own use limit (`use_limit_in_txn`), never the limit of the
//! records its words came from (`scope_summary::word_sources_in`), so a PSYCH_PROFILE of a
//! use-limited CLAIM left in an owner archive or on the owner's devices while the claim itself
//! stayed home.
//!
//! Public doors only; neutral fixtures; vaults in tempdirs.
//!
//! * `a_whole_vault_export_keeps_out_a_profile_of_a_use_limited_claim`: on a hosted vault a
//!   PERSON has two CLAIMs, held and kept, and a PSYCH_PROFILE citing each. A customer hold then
//!   refuses held's privacy erase, which keeps it stored and use-limited. The export carries
//!   neither held nor the profile citing it, and still carries the PERSON, kept and kept's
//!   profile.
//! * `a_profile_of_a_use_limited_claim_leaves_the_owner_window`: a hosted hub's window carries
//!   both profiles. After the keep, the hub's next export takes the held profile's carrier out of
//!   the window under a withholding marker, and a peer that holds nothing of the window lands no
//!   carrier of it; kept's profile rides as before.
//!
//! Both run red at main a1dc3dd3c27, whose doors ask each row's own use limit alone, and green at
//! the fix.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test egress_withholds_rows_derived_from_use_limited_records`.

#![cfg(all(feature = "sync", feature = "test-support", oneiron_test_support))]

#[path = "it_sync/sync_harness/mod.rs"]
mod sync_harness;

use std::collections::BTreeSet;

use loro::{LoroDoc, VersionVector};
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::LegalHoldTarget;
use oneiron::memory::{EraseOptions, EraseReason};
use oneiron::psych_profile::{
    PsychProfile, PsychProfileConfidence, PsychProfileSource, PsychProfileSourceWords,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::store::revision_ref::RevisionRef;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::{self, WindowExport};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EntityId,
    HostingPrivacyPosture, TimeRange, Vault, VaultConfig,
};
use rmpv::Value;

use crate::sync_harness::{TestNode, WINDOW, map_get_bytes, test_config};

const AT: u64 = 100;

/// The text tier of the profile citing the claim the hold keeps.
const HELD_PROFILE_TEXT: &str = "Copied prose from the held claim.";
/// The text tier of the profile citing the claim no limit touches.
const KEPT_PROFILE_TEXT: &str = "Copied prose from the kept claim.";

fn range() -> TimeRange {
    TimeRange { start: AT, end: AT }
}

fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the vault names its embedded owner actor");
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("FIXTURE: owner proof")
}

/// Places a customer hold on `record` and runs its privacy erase, which the hold refuses: the
/// record stays stored and use-limited on this hosted vault.
fn keep_use_limited(vault: &Vault, record: EntityId) {
    let hold = vault
        .place_legal_hold(
            &owner_proof(vault),
            vec![LegalHoldTarget::Record(record)],
            Some("matter-derived-rows".to_owned()),
        )
        .expect("FIXTURE: place the customer hold");
    assert!(hold.stands(), "FIXTURE: the customer hold stands: {hold:?}");
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the vault names its embedded owner actor");
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let preview = memory
        .preview_entity_delete(&record)
        .expect("FIXTURE: preview the privacy erase");
    let outcome = memory
        .confirm_entity_erase(
            &preview,
            EraseOptions {
                reason: EraseReason::GdprDelete,
                also_same_bytes: false,
                veto_starter: None,
            },
        )
        .expect("FIXTURE: the privacy erase runs");
    assert_eq!(
        outcome.first.reason.as_str(),
        "privacy_erase_kept",
        "FIXTURE: the held privacy erase is kept: {outcome:?}"
    );
    assert!(
        vault
            .legal_hold_use_limit(&record)
            .expect("FIXTURE: read the use limit")
            .is_some(),
        "FIXTURE: the kept erase use-limits the record"
    );
}

fn put_person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, range(), AT, b"profiled person")
        .expect("FIXTURE: put the PERSON");
    id
}

fn put_claim(vault: &Vault, subject: EntityId, value: &str) -> EntityId {
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        Value::from(value),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .expect("FIXTURE: claim body");
    body.salience = Some(0.9);
    body.source = Some(oneiron::claim::ClaimSource::UserStated);
    vault
        .put_claim(&id, &body, range(), AT)
        .expect("FIXTURE: put the claim");
    id
}

/// Lands a PSYCH_PROFILE about `person` whose one typed source is `claim`, as profile landing
/// records it (`psych_profile::sources::profile_source_in`): in the body, with no edge to the
/// claim.
fn put_profile_from(vault: &Vault, person: EntityId, claim: EntityId, text: &str) -> EntityId {
    let profile = PsychProfile::new(
        person,
        "compact",
        text,
        "Narrative about the person.",
        vec![claim],
        PsychProfileConfidence::new(0.9, 0.8, 0.7).expect("FIXTURE: profile confidence"),
    )
    .expect("FIXTURE: profile")
    .with_sources(vec![PsychProfileSource {
        revision_ref: claim,
        document_ref: claim,
        world_ref: None,
        document_revision: RevisionRef(*claim.as_bytes()),
        words: PsychProfileSourceWords::Record {
            content: [0x5C; 32],
        },
    }])
    .expect("FIXTURE: profile sources");
    let id = EntityId::now();
    vault
        .put_psych_profile(&id, &profile)
        .expect("FIXTURE: put the profile");
    id
}

/// A PERSON, two CLAIMs about it, held and kept, and a PSYCH_PROFILE citing each.
struct Profiled {
    person: EntityId,
    held: EntityId,
    kept: EntityId,
    held_profile: EntityId,
    kept_profile: EntityId,
}

fn put_profiled(vault: &Vault) -> Profiled {
    let person = put_person(vault);
    let held = put_claim(vault, person, "prefers quiet mornings");
    let kept = put_claim(vault, person, "likes long walks");
    Profiled {
        person,
        held,
        kept,
        held_profile: put_profile_from(vault, person, held, HELD_PROFILE_TEXT),
        kept_profile: put_profile_from(vault, person, kept, KEPT_PROFILE_TEXT),
    }
}

/// A hosted vault with a device keystore, so a held privacy erase keeps its record
/// use-limited.
fn open_hosted_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir for the hosted vault");
    let mut config = VaultConfig::default();
    config.privacy.posture = HostingPrivacyPosture::Hosted;
    let vault = Vault::open_owned(dir.path(), config).expect("open the hosted vault");
    vault.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    (dir, vault)
}

/// The ids of every entity and claim a whole-vault export of `vault` carries.
fn carried_ids(vault: &Vault) -> BTreeSet<String> {
    let archive = vault
        .export_whole_vault(true)
        .expect("whole-vault export")
        .bytes()
        .to_vec();
    let document = vault
        .read_whole_vault_archive(&archive)
        .expect("the archive reads back");
    document
        .evidence_ledger
        .entities
        .iter()
        .chain(document.claims.iter())
        .map(|row| row.id.clone())
        .collect()
}

#[test]
fn a_whole_vault_export_keeps_out_a_profile_of_a_use_limited_claim() {
    let (_dir, vault) = open_hosted_vault();
    let rows = put_profiled(&vault);
    let before = carried_ids(&vault);
    for (what, id) in [
        ("the PERSON", rows.person),
        ("the held claim", rows.held),
        ("the kept claim", rows.kept),
        ("the held claim's profile", rows.held_profile),
        ("the kept claim's profile", rows.kept_profile),
    ] {
        assert!(
            before.contains(&id.to_hex()),
            "FIXTURE: before the hold the export carries {what}"
        );
    }

    keep_use_limited(&vault, rows.held);
    assert!(
        vault
            .get_entity_type(&rows.held_profile)
            .expect("FIXTURE: read the profile's type")
            .is_some(),
        "FIXTURE: the kept erase leaves the profile citing the claim stored"
    );

    let after = carried_ids(&vault);
    assert!(
        !after.contains(&rows.held.to_hex()),
        "FIXTURE: the export keeps the use-limited claim out"
    );
    assert!(
        !after.contains(&rows.held_profile.to_hex()),
        "the export keeps out the profile whose words came from the use-limited claim"
    );
    for (what, id) in [
        ("the PERSON", rows.person),
        ("the kept claim", rows.kept),
        ("the kept claim's profile", rows.kept_profile),
    ] {
        assert!(
            after.contains(&id.to_hex()),
            "the export still carries {what}, which no use limit touches"
        );
    }
}

fn hosted_config() -> VaultConfig {
    let mut config = test_config();
    config.privacy.posture = HostingPrivacyPosture::Hosted;
    config
}

/// Mints this install's machine id, as a paired machine holds one: a withholding marker names
/// the machine that filed it.
fn mint_machine_id(vault: &Vault) {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the vault names its embedded owner actor");
    vault
        .local_session_key(owner)
        .expect("FIXTURE: mint the machine id");
}

/// Puts the stored revision of `id` into the hub's window, as the window carries a row of the
/// vault.
fn carry_in_window(hub: &TestNode, id: &EntityId) {
    let raw = hub
        .vault
        .get_raw(id)
        .expect("FIXTURE: read the stored row")
        .expect("FIXTURE: the row is stored");
    hub.put_entity_in_window(WINDOW, id, &raw);
}

fn carries(doc: &LoroDoc, id: &EntityId) -> bool {
    map_get_bytes(&doc.get_map("entities"), &id.to_hex()).is_some()
}

fn withheld_marker(doc: &LoroDoc, id: &EntityId) -> bool {
    map_get_bytes(
        &doc.get_map("source_audiences"),
        &format!("withheld/{}", id.to_hex()),
    )
    .is_some()
}

/// The window as the hub's export door hands it to a peer that holds nothing of it.
fn export_to_empty_peer(hub: &TestNode) -> LoroDoc {
    let peer = LoroDoc::new();
    match window::export_window_updates_since(
        &hub.vault,
        &WindowKey::new(WINDOW),
        hub.doc(WINDOW),
        &VersionVector::default().encode(),
    )
    .expect("the hub's export door answers")
    {
        WindowExport::Update(update) => {
            peer.import(&update).expect("the peer lands the update");
        }
        WindowExport::Replacement(snapshot) => {
            peer.import(&snapshot)
                .expect("the peer lands the replacement");
        }
    }
    peer
}

#[test]
fn a_profile_of_a_use_limited_claim_leaves_the_owner_window() {
    let mut hub = TestNode::with_config("hub", 2, hosted_config());
    mint_machine_id(&hub.vault);
    hub.open_window(WINDOW);
    let rows = put_profiled(&hub.vault);
    carry_in_window(&hub, &rows.held_profile);
    carry_in_window(&hub, &rows.kept_profile);
    let before = export_to_empty_peer(&hub);
    assert!(
        carries(&before, &rows.held_profile) && carries(&before, &rows.kept_profile),
        "FIXTURE: before the hold the window carries both profiles to a peer"
    );

    keep_use_limited(&hub.vault, rows.held);

    let peer = export_to_empty_peer(&hub);
    assert!(
        !carries(hub.doc(WINDOW), &rows.held_profile),
        "the hub's window no longer carries the profile citing the use-limited claim"
    );
    assert!(
        withheld_marker(hub.doc(WINDOW), &rows.held_profile),
        "the hub's window carries a withholding marker for that profile"
    );
    assert!(
        !carries(&peer, &rows.held_profile),
        "a peer lands no carrier of the profile citing the use-limited claim"
    );
    assert!(
        carries(hub.doc(WINDOW), &rows.kept_profile) && carries(&peer, &rows.kept_profile),
        "the profile of the claim no limit touches rides as before"
    );
}
