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
//!
//! The test runs red at the base (#9446 head 1adbb2714bf), whose export checks only the rows of
//! three room tables, and green at the fix.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test archive_export_withholds_retained_rows_of_withheld_records`.

#[path = "archive_import_retained_side_rows.rs"]
mod retained_side_rows;

use oneiron::deletion::LegalHoldTarget;
use oneiron::memory::{EraseOptions, EraseReason};
use oneiron::note::{NoteProgramEdit, NoteVerdict};
use oneiron::{EdgeActorClass, EntityId, HostingPrivacyPosture, Vault, VaultConfig, WriteActor};
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
