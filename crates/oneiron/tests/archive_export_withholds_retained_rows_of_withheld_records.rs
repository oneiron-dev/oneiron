#![cfg(oneiron_test_support)]
//! The whole-vault export withholds a retained side row about a record it keeps out (FIX
//! WHOLE-VAULT-EXPORT-RETAINED-ROWS-OF-WITHHELD-RECORDS).
//!
//! Public doors only; neutral fixtures; vaults in tempdirs.
//!
//! * `a_whole_vault_export_withholds_the_landing_receipt_of_a_use_limited_note`: on a hosted
//!   vault the owner lands a rewrite of each of two NOTEs, so the archive carries two
//!   `NOTE_RECEIPT` rows, each keyed by its receipt's own id and naming its NOTE in its value.
//!   A customer hold then refuses the first NOTE's privacy erase, which keeps it stored and
//!   use-limited: the export carries neither that NOTE nor its receipt, and still carries the
//!   second NOTE's receipt.
//! * `a_whole_vault_export_withholds_a_setting_change_whose_reason_names_a_use_limited_note`:
//!   the owner changes a vault-scope setting twice, each change's reason citing one NOTE by its
//!   hex id, the id an erase of that NOTE finds in a change's reason and drops the change by.
//!   After a customer hold keeps the first NOTE use-limited, the export carries no change citing
//!   it and still carries the change citing the second NOTE (own review P1, 20 Nov).
//! * `a_whole_vault_export_withholds_a_house_link_receipt_naming_a_use_limited_org`: on a
//!   hosted vault rooted under its host, the owner binds the workspace's house to run its org,
//!   which files one `HOUSE_LINK_RECEIPT` keyed by the house and naming the org in its value. A
//!   customer hold then refuses the org's privacy erase: the export carries neither the org nor
//!   the receipt (REVIEW-9739 P1-1).
//!
//! The first test runs red at the base (#9446 head 1adbb2714bf), whose export checks only the
//! rows of three room tables, and green at the fix. The second runs red at 0b834f36c37, whose
//! export reads only a setting change's scope, and green at the fix. The third runs red at
//! ec7407c4e2a, whose export reads only the receipt's house, and green at the fix.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test archive_export_withholds_retained_rows_of_withheld_records`.

#[path = "archive_import_retained_side_rows.rs"]
mod retained_side_rows;

use oneiron::deletion::LegalHoldTarget;
use oneiron::memory::{EraseOptions, EraseReason};
use oneiron::note::{NoteProgramEdit, NoteVerdict};
use oneiron::registry::ENTITY_TYPE_ORG;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::workspace_roster::{DEFAULT_HOUSE_ROLE, WorkCompanionPolicy, WorkspaceRosterPreset};
use oneiron::{
    EdgeActorClass, EntityId, HostingPrivacyPosture, TimeRange, Vault, VaultConfig, WriteActor,
};
use retained_side_rows::{export_whole, owner_proof, retained_rows, rows_for};

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

/// Places a customer hold on `record` and runs its privacy erase, which the hold refuses: the
/// record stays stored and use-limited, and a whole-vault export keeps it out.
fn use_limit(vault: &Vault, record: EntityId) {
    let hold = vault
        .place_legal_hold(
            &owner_proof(vault),
            vec![LegalHoldTarget::Record(record)],
            Some("matter-retained-rows".to_owned()),
        )
        .expect("FIXTURE: place the customer hold");
    assert!(hold.stands(), "FIXTURE: the customer hold stands: {hold:?}");
    let actor = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the vault names its embedded owner actor");
    let memory = vault.memory(actor, EdgeActorClass::Human);
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

/// A NOTE the owner writes with `text` and then rewrites through a switch, which files one
/// landing receipt. Returns the NOTE and the receipt's id.
fn note_with_landing_receipt(vault: &Vault, owner: EntityId, text: &str) -> (EntityId, EntityId) {
    let actor = || WriteActor::new(owner, EdgeActorClass::Human);
    let note = vault
        .create_note("research", text, actor())
        .expect("FIXTURE: the owner writes the NOTE");
    let edit = NoteProgramEdit::Rewrite {
        text: format!("{text} Revised."),
    };
    let fork = vault
        .fork_note(note, &edit, actor())
        .expect("FIXTURE: the owner forks the NOTE");
    let bundle = vault
        .open_note_proposal(&[fork], "revise the notes", actor())
        .expect("FIXTURE: the owner opens the proposal");
    assert!(
        bundle.landed.is_empty(),
        "FIXTURE: a declared rewrite waits for a switch"
    );
    let bundle = vault
        .review_note_proposal(bundle.id, NoteVerdict::Switch, actor())
        .expect("FIXTURE: the owner's switch lands the rewrite");
    assert_eq!(bundle.landed.len(), 1, "FIXTURE: the rewrite lands");
    assert_eq!(
        bundle.landed[0].note, note,
        "FIXTURE: the landing receipt names its NOTE"
    );
    (note, bundle.landed[0].id)
}

/// The `NOTE_RECEIPT` tuples of whole-vault `archive` keyed by `receipt`.
fn receipt_tuples(archive: &[u8], receipt: EntityId) -> usize {
    rows_for(&retained_rows(archive), "NOTE_RECEIPT")
        .iter()
        .filter(|(_, key, _)| key.as_slice() == receipt.as_bytes().as_slice())
        .count()
}

/// Whether whole-vault `archive` carries a record of `id`, read through `reader`.
fn archive_carries(reader: &Vault, archive: &[u8], id: EntityId) -> bool {
    reader
        .read_whole_vault_archive(archive)
        .expect("read the archive")
        .evidence_ledger
        .entities
        .iter()
        .any(|entity| entity.id == id.to_hex())
}

#[test]
fn a_whole_vault_export_withholds_the_landing_receipt_of_a_use_limited_note() {
    let (_dir, vault) = open_hosted_vault();
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the vault names its embedded owner actor");
    let (held_note, held_receipt) = note_with_landing_receipt(&vault, owner, "Field notes.");
    let (free_note, free_receipt) = note_with_landing_receipt(&vault, owner, "Reading list.");
    let before = export_whole(&vault);
    for receipt in [held_receipt, free_receipt] {
        assert_eq!(
            receipt_tuples(&before, receipt),
            1,
            "FIXTURE: before the hold the archive carries each NOTE's landing receipt"
        );
    }

    use_limit(&vault, held_note);
    let archive = export_whole(&vault);
    assert!(
        !archive_carries(&vault, &archive, held_note),
        "FIXTURE: the archive carries no record of the use-limited NOTE"
    );
    assert!(
        archive_carries(&vault, &archive, free_note),
        "FIXTURE: the archive still carries the unrestricted NOTE"
    );
    assert_eq!(
        receipt_tuples(&archive, held_receipt),
        0,
        "LEAK: the archive carries no landing receipt of the use-limited NOTE"
    );
    assert_eq!(
        receipt_tuples(&archive, free_receipt),
        1,
        "the archive still carries the unrestricted NOTE's landing receipt"
    );
}

/// Sets the vault-scope `test.owner_number` to `value` as the owner, with a reason that cites
/// `note` by its hex id. Returns the change's sequence, its `SETTING_CHANGE` key.
fn change_citing(vault: &Vault, value: u64, note: EntityId) -> u64 {
    let outcome = vault
        .set_setting(
            SettingCaller::Owner(&owner_proof(vault)),
            SetSetting {
                why: Some(format!("as agreed in note {}", note.to_hex())),
                ..SetSetting::vault_value("test.owner_number", serde_json::json!(value))
            },
        )
        .expect("FIXTURE: the owner changes the vault setting");
    match outcome {
        SetSettingOutcome::Applied {
            sequence: Some(sequence),
            ..
        } => sequence,
        other => panic!("FIXTURE: the change applies with a sequence: {other:?}"),
    }
}

/// The `SETTING_CHANGE` tuples of whole-vault `archive` keyed by `sequence`.
fn change_tuples(archive: &[u8], sequence: u64) -> usize {
    rows_for(&retained_rows(archive), "SETTING_CHANGE")
        .iter()
        .filter(|(_, key, _)| key.as_slice() == sequence.to_be_bytes().as_slice())
        .count()
}

#[test]
fn a_whole_vault_export_withholds_a_setting_change_whose_reason_names_a_use_limited_note() {
    let (_dir, vault) = open_hosted_vault();
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the vault names its embedded owner actor");
    let actor = || WriteActor::new(owner, EdgeActorClass::Human);
    let held_note = vault
        .create_note("research", "Meeting notes.", actor())
        .expect("FIXTURE: the owner writes the held NOTE");
    let free_note = vault
        .create_note("research", "Shopping list.", actor())
        .expect("FIXTURE: the owner writes the free NOTE");
    let held_change = change_citing(&vault, 9, held_note);
    let free_change = change_citing(&vault, 10, free_note);
    let before = export_whole(&vault);
    for sequence in [held_change, free_change] {
        assert_eq!(
            change_tuples(&before, sequence),
            1,
            "FIXTURE: before the hold the archive carries each setting change"
        );
    }

    use_limit(&vault, held_note);
    let archive = export_whole(&vault);
    assert!(
        !archive_carries(&vault, &archive, held_note),
        "FIXTURE: the archive carries no record of the use-limited NOTE"
    );
    assert_eq!(
        change_tuples(&archive, held_change),
        0,
        "LEAK: the archive carries no setting change whose reason cites the use-limited NOTE"
    );
    assert_eq!(
        change_tuples(&archive, free_change),
        1,
        "the archive still carries the setting change citing the unrestricted NOTE"
    );
}

/// The workspace the house link test stores, and its shared vault: not 7, the own-device
/// residence scope's id.
const WORKSPACE: &str = "retained-rows-house-link-workspace";
const WORKSPACE_VAULT_ID: u64 = 41;

#[test]
fn a_whole_vault_export_withholds_a_house_link_receipt_naming_a_use_limited_org() {
    let (_dir, vault) = open_hosted_vault();
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the vault names its embedded owner actor");
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner)
        .expect("FIXTURE: bind the owner under the host root");
    let proof = owner_proof(&vault);
    let signer = vault
        .owner_project_signer(&issuer)
        .expect("FIXTURE: the owner's project signer");
    let root = vault.root_project().expect("FIXTURE: the root project");
    vault
        .sign_owner_project(&proof, &signer, root)
        .expect("FIXTURE: sign the root once");
    let org = EntityId::from_bytes([0xB3; 16]).expect("FIXTURE: the org id");
    vault
        .put_entity(
            &org,
            ENTITY_TYPE_ORG,
            TimeRange { start: 1, end: 1 },
            1,
            b"retained rows house link org",
        )
        .expect("FIXTURE: store the org");
    vault
        .initialize_shared_vault(
            &proof,
            WORKSPACE_VAULT_ID,
            None,
            &[],
            vault.now_recorded_at(),
        )
        .expect("FIXTURE: create the workspace's shared vault");
    let (house, _) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")
        .expect("FIXTURE: read the seeded agents")
        .expect("FIXTURE: sys.default is seeded on open");
    vault
        .establish_workspace_preset(
            &WorkspaceRosterPreset {
                workspace_ref: WORKSPACE.to_owned(),
                workspace_vault_id: WORKSPACE_VAULT_ID,
                org_ref: org,
                venture_name: "Retained Rows Works".to_owned(),
                house_display_name: None,
                house_actor_ref: house,
                house_identity_ref: None,
            },
            WorkCompanionPolicy::Choose,
            &proof,
        )
        .expect("FIXTURE: store the workspace");
    vault
        .bind_workspace_house_leader(WORKSPACE, DEFAULT_HOUSE_ROLE, &proof, &signer)
        .expect("FIXTURE: the owner binds the house to run its org");
    let receipts = |archive: &[u8]| rows_for(&retained_rows(archive), "HOUSE_LINK_RECEIPT").len();
    assert_eq!(
        receipts(&export_whole(&vault)),
        1,
        "FIXTURE: before the hold the archive carries the bind receipt"
    );

    use_limit(&vault, org);
    let archive = export_whole(&vault);
    assert!(
        !archive_carries(&vault, &archive, org),
        "FIXTURE: the archive carries no record of the use-limited org"
    );
    assert_eq!(
        receipts(&archive),
        0,
        "LEAK: the archive carries no house link receipt naming the use-limited org"
    );
}
