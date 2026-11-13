#![cfg(oneiron_test_support)]
//! Whole-vault archive retention of side-table rows (SIDE-1, OF-222).
//!
//! The archive carries the rows of the retained side tables as inert copies,
//! declares the omitted tables in the manifest, and restores none of them
//! live. Public doors only; neutral fixtures (`agent-a`); vaults in
//! tempdirs. Each destination opens at least one wall-clock second after its
//! source (sleep 1100 ms), as in `archive_import_maintenance_kinds.rs`.
//!
//! * `whole_vault_archive_retains_rows_and_declares_omitted_tables`: the
//!   source archive holds exactly one retained BACKUP_POLICY row and one
//!   retained CONSENT_STANDING_GRANT row, none for HEALER_OVERSIGHT_RECEIPT,
//!   and the manifest declares 23 omitted tables, the healer table with
//!   three rows.
//! * `each_import_door_retains_the_rows_and_the_next_archive_carries_them`:
//!   the owner, actor and actorless doors all retain without going live,
//!   and each destination's own archive re-carries the tuples byte for byte.
//! * `a_repeat_import_keeps_one_copy_and_a_new_value_keeps_both`: a repeat
//!   import adds no copy; a changed backup value lands beside the old one.
//! * `an_actor_erase_drops_the_retained_copies_that_name_the_actor`: erasing
//!   an actor drops the retained CALL_RECEIPT copy naming that actor and keeps the
//!   backup copy.
//!
//! Count model: minting the standing grant also appends its gate receipt, a
//! plain claim-free GATE_DECISION_LEDGER row the secret scan keeps (ids and
//! code strings only), so the source archive holds three retained rows, not
//! two; the owner import appends its own restore receipt, a live gate row
//! the destination's next export carries beside the retained copies. The
//! brief's two targets are asserted exactly, per table and byte for byte,
//! and the gate rows are accounted separately.
//!
//! On the base this file compiles (it names no new type, field or door) and
//! every test fails red: no `retained_side_row` family and no
//! `side_table_omissions` manifest list exist there.
//! `cargo test --locked -p oneiron --all-features --test archive_import_retained_side_rows`.

use std::io::{Cursor, Read as _};

use oneiron::batch::export::WholeVaultDocument;
use oneiron::consent::{ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, GrantBound};
use oneiron::receipt::{CallOutcome, CallReceiptInput, CallTransport};
use oneiron::settings::backup::BackupPolicy;
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};

/// A source vault opened as the owner's own, as the model's fixture opens it.
fn open_source_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir for the source vault");
    let vault =
        Vault::open_owned(dir.path(), VaultConfig::default()).expect("open the source vault");
    (dir, vault)
}

/// A fresh destination whose engine-seed seconds differ from the source's:
/// any 1100 ms interval crosses a second boundary.
pub(crate) fn open_later_vault() -> (tempfile::TempDir, Vault) {
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let dir = tempfile::tempdir().expect("temp dir for the destination vault");
    let vault =
        Vault::open(dir.path(), VaultConfig::default()).expect("open the destination vault");
    (dir, vault)
}

pub(crate) fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof")
}

fn export_whole(vault: &Vault) -> Vec<u8> {
    vault
        .export_whole_vault(true)
        .expect("whole-vault export")
        .bytes()
        .to_vec()
}

/// Reads `archive` through a scratch vault: `read_whole_vault_archive` is a
/// `Vault` method, and reading validates without writing, so any fresh vault
/// reads.
fn read_archive(archive: &[u8]) -> WholeVaultDocument {
    let dir = tempfile::tempdir().expect("scratch dir to read the archive");
    let reader =
        Vault::open(dir.path(), VaultConfig::default()).expect("scratch vault to read the archive");
    reader
        .read_whole_vault_archive(archive)
        .expect("the archive reads and validates")
}

/// The manifest's side-table omissions of `archive`, as (table, reason in
/// its serialized form, row count). Read from the manifest's JSON, so this
/// compiles on the base, where the list is absent and the test fails red.
fn side_table_omissions(archive: &[u8]) -> Vec<(String, String, u64)> {
    let manifest =
        serde_json::to_value(read_archive(archive).manifest).expect("the manifest serializes");
    manifest
        .get("side_table_omissions")
        .expect("the manifest declares its omitted side tables")
        .as_array()
        .expect("side_table_omissions is a list")
        .iter()
        .map(|entry| {
            (
                entry
                    .get("table")
                    .and_then(|table| table.as_str())
                    .expect("an omission names its table")
                    .to_owned(),
                entry
                    .get("reason")
                    .and_then(|reason| reason.as_str())
                    .expect("an omission names its reason")
                    .to_owned(),
                entry
                    .get("rows")
                    .and_then(|rows| rows.as_u64())
                    .expect("an omission counts its rows"),
            )
        })
        .collect()
}

/// The retained side rows `archive` carries, as (source table, source key
/// suffix, source value), sorted. Byte leaves come from inline hex or from
/// the archive's `files/<blake3>` member, read out of `archive` with `zip`.
/// Family and envelope shapes are read from JSON, so this compiles on the
/// base, where the family is absent and every retention assertion fails red.
fn retained_rows(archive: &[u8]) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let document = read_archive(archive);
    let rows = serde_json::to_value(&document.side_tables).expect("the side tables serialize");
    let mut zip = zip::ZipArchive::new(Cursor::new(archive)).expect("the archive opens as a zip");
    let mut retained = Vec::new();
    for row in rows.as_array().expect("side_tables is an array") {
        if row.get("family").and_then(|family| family.as_str()) != Some("retained_side_row") {
            continue;
        }
        assert_eq!(
            row.get("value")
                .and_then(|value| value.get("form"))
                .and_then(|form| form.as_str()),
            Some("message_pack"),
            "a retained row value is MessagePack: {row}"
        );
        let envelope = row
            .get("value")
            .and_then(|value| value.get("value"))
            .expect("a retained row value holds its tree");
        retained.push(decode_retained_envelope(envelope, &mut zip));
    }
    retained.sort();
    retained
}

/// One retained envelope tree as its (source table, source key, source
/// value): a map with `source_table` text and `source_key`/`source_value`
/// byte leaves, inline hex or an archive file.
fn decode_retained_envelope(
    tree: &serde_json::Value,
    zip: &mut zip::ZipArchive<Cursor<&[u8]>>,
) -> (String, Vec<u8>, Vec<u8>) {
    assert_eq!(
        tree.get("type").and_then(|kind| kind.as_str()),
        Some("map"),
        "a retained envelope is a map: {tree}"
    );
    let mut table = None;
    let mut key = None;
    let mut value = None;
    for pair in tree
        .get("value")
        .and_then(|pairs| pairs.as_array())
        .expect("a map holds pairs")
    {
        let pair = pair.as_array().expect("a map entry is a pair");
        assert_eq!(
            pair.len(),
            2,
            "a map entry is one key and one value: {pair:?}"
        );
        let name = tree_string(&pair[0]).expect("an envelope member name is text");
        match name.as_str() {
            "source_table" => table = Some(tree_string(&pair[1]).expect("source_table is text")),
            "source_key" => key = Some(tree_bytes(&pair[1], zip).expect("source_key are bytes")),
            "source_value" => {
                value = Some(tree_bytes(&pair[1], zip).expect("source_value are bytes"));
            }
            other => panic!("unknown retained envelope member {other}: {tree}"),
        }
    }
    (
        table.expect("a retained envelope names its source table"),
        key.expect("a retained envelope holds its source key"),
        value.expect("a retained envelope holds its source value"),
    )
}

/// The text of a `string` tree leaf.
fn tree_string(tree: &serde_json::Value) -> Option<String> {
    if tree.get("type").and_then(|kind| kind.as_str()) != Some("string") {
        return None;
    }
    tree.get("value")
        .and_then(|value| value.as_str())
        .map(str::to_owned)
}

/// The bytes of a byte tree leaf: inline `binary`/`bytes` hex, a
/// `binary_file`/`bytes_file` archive member, or an empty array (an empty
/// key encodes as no bytes).
fn tree_bytes(
    tree: &serde_json::Value,
    zip: &mut zip::ZipArchive<Cursor<&[u8]>>,
) -> Option<Vec<u8>> {
    match tree.get("type").and_then(|kind| kind.as_str()) {
        Some("binary" | "bytes") => {
            let hex = tree.get("value").and_then(|value| value.as_str())?;
            Some(hex_to_bytes(hex))
        }
        Some("binary_file" | "bytes_file") => {
            let file = tree.get("value")?;
            let blake3 = file.get("blake3").and_then(|hash| hash.as_str())?;
            let name = format!("files/{blake3}");
            let mut member = zip
                .by_name(&name)
                .unwrap_or_else(|error| panic!("the archive holds {name}: {error}"));
            let mut bytes = Vec::new();
            member
                .read_to_end(&mut bytes)
                .unwrap_or_else(|error| panic!("the archive's {name} reads: {error}"));
            Some(bytes)
        }
        Some("array") => {
            let items = tree.get("value").and_then(|value| value.as_array())?;
            if items.is_empty() {
                Some(Vec::new())
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Lowercase hex as bytes.
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len() % 2 == 0, "hex comes in pairs: {hex}");
    hex.as_bytes()
        .chunks(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("hex is lowercase hex: {hex}"),
            };
            digit(pair[0]) << 4 | digit(pair[1])
        })
        .collect()
}

/// A source vault holding one backup choice, one standing grant and three
/// healer oversight rows; `archive` is its whole-vault export.
pub(crate) struct Source {
    pub(crate) vault: Vault,
    pub(crate) grant_ref: String,
    pub(crate) archive: Vec<u8>,
    _dir: tempfile::TempDir,
}

pub(crate) fn source_with_rows() -> Source {
    let (dir, vault) = open_source_vault();
    let owner = owner_proof(&vault);
    let policy = BackupPolicy {
        enabled: true,
        every_hours: 6,
        keep: 3,
    };
    vault
        .set_backup_policy(&owner, policy)
        .expect("the owner stores the backup choice");
    assert_eq!(
        vault.backup_policy().expect("read the backup choice"),
        Some(policy),
        "the source holds the backup row"
    );
    let bound = GrantBound::action(
        ActorBound::new("agent-a").expect("the bound names agent-a"),
        ActionClass::new("send").expect("the bound names send"),
        ActionEnvelope::new(["channel:team".to_owned()]).expect("the bound names channel:team"),
    )
    .expect("the action bound builds");
    vault
        .create_standing_grant(&owner, bound.clone())
        .expect("the owner mints the standing grant");
    let grant_ref = bound.digest().to_hex();
    assert!(
        vault
            .consent_grant(&grant_ref)
            .expect("read the grant")
            .is_some_and(|row| row.is_active()),
        "the source holds the active grant row"
    );
    let oversight = vault
        .emit_healer_oversight(1_700_000_000)
        .expect("the host emits oversight");
    assert_eq!(oversight.len(), 3, "the emitter writes three rows");
    assert_eq!(
        vault
            .healer_oversight_receipts()
            .expect("read the oversight rows")
            .len(),
        3,
        "the source holds three oversight rows"
    );
    let archive = export_whole(&vault);
    Source {
        vault,
        grant_ref,
        archive,
        _dir: dir,
    }
}

/// The retained tuples of `table` in `rows`.
fn rows_for(rows: &[(String, Vec<u8>, Vec<u8>)], table: &str) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    rows.iter()
        .filter(|(name, _, _)| name == table)
        .cloned()
        .collect()
}

#[test]
fn whole_vault_archive_retains_rows_and_declares_omitted_tables() {
    let source = source_with_rows();
    let rows = retained_rows(&source.archive);
    // The brief's two targets: exactly one row each, none for the omitted table.
    let backup = rows_for(&rows, "BACKUP_POLICY");
    assert_eq!(
        backup.len(),
        1,
        "the source archive holds exactly one retained BACKUP_POLICY row: {rows:?}"
    );
    let grants = rows_for(&rows, "CONSENT_STANDING_GRANT");
    assert_eq!(
        grants.len(),
        1,
        "the source archive holds exactly one retained CONSENT_STANDING_GRANT row: {rows:?}"
    );
    assert!(
        rows_for(&rows, "HEALER_OVERSIGHT_RECEIPT").is_empty(),
        "the source archive holds no HEALER_OVERSIGHT_RECEIPT row: {rows:?}"
    );
    // Full count accounting, separately: minting the grant also appends its
    // gate receipt, a plain claim-free GATE_DECISION_LEDGER row the secret
    // scan keeps (ids and code strings only), so the archive holds three
    // retained rows in all. No export-audit row is in this first export: the
    // audit row lands after the snapshot it audits.
    let gate = rows_for(&rows, "GATE_DECISION_LEDGER");
    assert_eq!(
        gate.len(),
        1,
        "the grant's gate receipt travels as one retained GATE_DECISION_LEDGER row: {rows:?}"
    );
    assert_eq!(
        rows.len(),
        3,
        "the source archive holds three retained rows in all: {rows:?}"
    );
    // The manifest declares every omitted table, zero-row tables included.
    let omissions = side_table_omissions(&source.archive);
    assert_eq!(
        omissions.len(),
        23,
        "the manifest declares 23 omitted tables: {omissions:?}"
    );
    let healer = omissions
        .iter()
        .find(|(table, _, _)| table == "HEALER_OVERSIGHT_RECEIPT")
        .expect("the manifest names HEALER_OVERSIGHT_RECEIPT");
    assert_eq!(
        healer.1, "engine_attestation_not_restored",
        "the healer omission names its reason: {omissions:?}"
    );
    assert_eq!(
        healer.2, 3,
        "the healer omission counts three rows: {omissions:?}"
    );
}

#[test]
fn each_import_door_retains_the_rows_and_the_next_archive_carries_them() {
    let source = source_with_rows();
    let source_rows = retained_rows(&source.archive);
    let source_backup = rows_for(&source_rows, "BACKUP_POLICY");
    let source_grants = rows_for(&source_rows, "CONSENT_STANDING_GRANT");
    assert_eq!(
        source_backup.len(),
        1,
        "the source archive holds one backup tuple"
    );
    assert_eq!(
        source_grants.len(),
        1,
        "the source archive holds one grant tuple"
    );

    // The owner door.
    let (_owner_dir, owner_dest) = open_later_vault();
    let dest_owner = owner_proof(&owner_dest);
    owner_dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&source.archive), &dest_owner)
        .expect("the owner import succeeds");
    // The actor door, with a destination-local actor, never one from the archive.
    let (_actor_dir, actor_dest) = open_later_vault();
    let actor = actor_dest
        .ensure_embedded_owner_actor()
        .expect("the destination's embedded owner");
    actor_dest
        .import_whole_vault_archive_from_with_actor(
            Cursor::new(&source.archive),
            &WriteActor::new(actor, EdgeActorClass::Human),
        )
        .expect("the actor import succeeds");
    // The actorless door.
    let (_bare_dir, bare_dest) = open_later_vault();
    bare_dest
        .import_whole_vault_archive_from(Cursor::new(&source.archive))
        .expect("the actorless import succeeds");

    for (door, dest) in [
        ("owner", &owner_dest),
        ("actor", &actor_dest),
        ("actorless", &bare_dest),
    ] {
        assert_eq!(
            dest.backup_policy()
                .expect("read the destination backup choice"),
            None,
            "the {door} import retains the backup row without making it live"
        );
        assert!(
            dest.consent_grant(&source.grant_ref)
                .expect("read the destination grant")
                .is_none(),
            "the {door} import retains the grant row without making it live"
        );
        assert!(
            dest.healer_oversight_receipts()
                .expect("read the destination oversight rows")
                .is_empty(),
            "the {door} import keeps the foreign attestation out of the local ledger"
        );
        let dest_rows = retained_rows(&export_whole(dest));
        // The brief's two tuples, byte for byte.
        assert_eq!(
            rows_for(&dest_rows, "BACKUP_POLICY"),
            source_backup,
            "the {door} destination re-carries the backup tuple byte for byte"
        );
        assert_eq!(
            rows_for(&dest_rows, "CONSENT_STANDING_GRANT"),
            source_grants,
            "the {door} destination re-carries the grant tuple byte for byte"
        );
        // Full count accounting: the owner door writes its own restore
        // receipt, a live gate row its next export carries beside the three
        // retained copies; the other doors write none, so their archive
        // equals the source's tuple for tuple.
        let source_gate = rows_for(&source_rows, "GATE_DECISION_LEDGER");
        let dest_gate = rows_for(&dest_rows, "GATE_DECISION_LEDGER");
        if door == "owner" {
            assert_eq!(
                dest_gate.len(),
                source_gate.len() + 1,
                "the owner destination carries its restore receipt too: {dest_rows:?}"
            );
            for tuple in &source_gate {
                assert!(
                    dest_gate.contains(tuple),
                    "the owner destination re-carries the source gate tuple byte for byte: {tuple:?}"
                );
            }
        } else {
            assert_eq!(
                dest_rows, source_rows,
                "the {door} destination holds exactly the source tuples: {dest_rows:?}"
            );
        }
    }
}

#[test]
fn a_repeat_import_keeps_one_copy_and_a_new_value_keeps_both() {
    let source = source_with_rows();
    let first_rows = retained_rows(&source.archive);
    let first_backup = rows_for(&first_rows, "BACKUP_POLICY");
    assert_eq!(
        first_backup.len(),
        1,
        "the first source archive holds one backup tuple"
    );
    let first_grants = rows_for(&first_rows, "CONSENT_STANDING_GRANT");
    assert_eq!(
        first_grants.len(),
        1,
        "the first source archive holds one grant tuple"
    );

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    dest.import_whole_vault_archive_from_as_owner(Cursor::new(&source.archive), &dest_owner)
        .expect("the first owner import succeeds");
    dest.import_whole_vault_archive_from_as_owner(Cursor::new(&source.archive), &dest_owner)
        .expect("the repeat owner import succeeds");
    let repeat_rows = retained_rows(&export_whole(&dest));
    assert_eq!(
        rows_for(&repeat_rows, "BACKUP_POLICY"),
        first_backup,
        "a repeat import keeps one backup copy: {repeat_rows:?}"
    );
    assert_eq!(
        rows_for(&repeat_rows, "CONSENT_STANDING_GRANT"),
        first_grants,
        "a repeat import keeps one grant copy: {repeat_rows:?}"
    );

    let owner = owner_proof(&source.vault);
    source
        .vault
        .set_backup_policy(
            &owner,
            BackupPolicy {
                enabled: true,
                every_hours: 12,
                keep: 5,
            },
        )
        .expect("the owner stores the second backup choice");
    let second_archive = export_whole(&source.vault);
    let second_rows = retained_rows(&second_archive);
    let second_backup = rows_for(&second_rows, "BACKUP_POLICY");
    assert_eq!(
        second_backup.len(),
        1,
        "the second source archive holds the new backup tuple"
    );
    assert_ne!(second_backup, first_backup, "the two backup values differ");
    dest.import_whole_vault_archive_from_as_owner(Cursor::new(&second_archive), &dest_owner)
        .expect("the second archive imports");
    let both_rows = retained_rows(&export_whole(&dest));
    let both_backup = rows_for(&both_rows, "BACKUP_POLICY");
    assert_eq!(
        both_backup.len(),
        2,
        "the destination keeps both backup values: {both_rows:?}"
    );
    assert!(
        both_backup.contains(&first_backup[0]) && both_backup.contains(&second_backup[0]),
        "the destination keeps the old and the new backup tuple byte for byte: {both_rows:?}"
    );
    assert_eq!(
        rows_for(&both_rows, "CONSENT_STANDING_GRANT"),
        first_grants,
        "the destination still keeps one grant copy: {both_rows:?}"
    );
}

#[test]
fn an_actor_erase_drops_the_retained_copies_that_name_the_actor() {
    let (_source_dir, source) = open_source_vault();
    let owner = owner_proof(&source);
    source
        .set_backup_policy(
            &owner,
            BackupPolicy {
                enabled: true,
                every_hours: 6,
                keep: 3,
            },
        )
        .expect("the owner stores the backup choice");
    // CALL_RECEIPT names its actor as lowercase hex through one public call,
    // with no agent definition or rooted vault needed.
    let x = EntityId::now();
    source
        .record_call_receipt(CallReceiptInput {
            transport: CallTransport::HttpFacade,
            verb: "memory.recall".to_owned(),
            actor_ref: x.to_hex(),
            actor_class: "human".to_owned(),
            credential_ref: None,
            carrier_machine: None,
            outcome: CallOutcome::Ok,
            request_digest: "9f".repeat(32),
            result_digest: Some("8e".repeat(32)),
            inputs: None,
            attempt: None,
            served: Vec::new(),
        })
        .expect("the call receipt lands");
    let archive = export_whole(&source);

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    dest.import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    let before = retained_rows(&export_whole(&dest));
    assert!(
        before.iter().any(|(table, _, _)| table == "CALL_RECEIPT"),
        "the destination archive holds the call receipt as retained: {before:?}"
    );
    assert!(
        before.iter().any(|(table, _, _)| table == "BACKUP_POLICY"),
        "the destination archive holds the backup copy: {before:?}"
    );

    let ran = oneiron::test_doors::inquiry::erase_actor_in_tables_in_order(
        &dest,
        &x,
        &["ARCHIVE_RETAINED_SIDE_ROW"],
    )
    .expect("the erase runs");
    assert_eq!(ran, 1, "the retained table registers an actor scrub");

    let after = retained_rows(&export_whole(&dest));
    assert!(
        after.iter().all(|(table, _, _)| table != "CALL_RECEIPT"),
        "the erase drops the retained copy naming the actor: {after:?}"
    );
    assert!(
        after.iter().any(|(table, _, _)| table == "BACKUP_POLICY"),
        "the erase keeps the backup copy: {after:?}"
    );
}
