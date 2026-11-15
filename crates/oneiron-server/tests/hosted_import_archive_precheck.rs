//! The archive pre-check under a hosted import (ARCH-0027 #archive-precheck:
//! the pass "skips and lists an escaping path or a link"; CROSS-ARCH-0024
//! #onboarding-import 01-05: "The job reports what came in"). A staged
//! export zip is decoded by the hosted job through the same pass as
//! `oneiron import`. `vault.imports.get` lists, in the parse phase, each
//! entry the pass skipped with its reason, in the archive's order, during
//! the job and after it: the first `HOSTED_IMPORT_SKIPS_LISTED`, with a
//! count of them all. A refused archive ends the job Failed with the
//! refusal's text, and nothing lands. An archive with no skip reports none.
//!
//! Stages exports and runs the worker's passes through
//! `oneiron_server::test_doors::hosted_import`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features oneiron/test-support --test hosted_import_archive_precheck`.
#![cfg(all(oneiron_test_support, unix))]

use std::path::Path;

use oneiron::ingest::history::{HOSTED_IMPORT_SKIPS_LISTED, HistorySource, HostedImportId};
use oneiron::memory::MemoryResult;
use oneiron::registry::ENTITY_TYPE_MESSAGE;
use oneiron::task_verb::sdk::invoke;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_server::test_doors::hosted_import::{pass, stage};
use serde_json::{Value, json};

type TestError = Box<dyn std::error::Error>;
type TestResult = Result<(), TestError>;

const GET: &str = "vault.imports.get";

/// The fixture export's messages, landed.
const FIXTURE_MESSAGES: u64 = 6;

/// Unix modes of the entries the tests write.
const REGULAR_FILE: u32 = 0o100_644;
const SYMBOLIC_LINK: u32 = 0o120_777;
const FIFO: u32 = 0o010_644;

fn fixture_export() -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/history/chatgpt/export-1/conversations.json"),
    )
    .expect("test fixture")
}

/// A process-owned vault at `dir`, as `serve` opens it: this process holds
/// its writer lease, so its embedded owner may import and call the owner's
/// verbs. Answers the vault and its owner's PERSON.
fn open_vault(dir: &Path) -> Result<(Vault, EntityId), TestError> {
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_owned(dir, config)?;
    let owner = vault.ensure_embedded_owner_actor()?;
    Ok((vault, owner))
}

/// `vault.imports.get` of hosted import `id`, as the owner calls it.
fn progress(vault: &Vault, owner: EntityId, id: HostedImportId) -> MemoryResult<Value> {
    invoke(
        &vault.memory(owner, EdgeActorClass::Human),
        GET,
        json!({ "import": id.to_hex() }),
    )
}

/// One entry of a hand-written zip: stored, with the unix mode its central
/// directory entry records.
struct RawEntry {
    name: String,
    mode: u32,
    data: Vec<u8>,
}

impl RawEntry {
    fn file(name: impl Into<String>, mode: u32, data: &[u8]) -> Self {
        Self {
            name: name.into(),
            mode,
            data: data.to_vec(),
        }
    }
}

/// A zip written byte by byte, so a test sets what the `zip` writer never
/// writes: a FIFO or a link mode, one name held twice.
fn raw_zip(entries: &[RawEntry]) -> Vec<u8> {
    // Unix (3) made the archive; version 2.0 reads it. Names are UTF-8; the
    // date is 1980-01-01.
    const MADE_BY_UNIX: u16 = (3 << 8) | 20;
    const NEEDED: u16 = 20;
    const UTF8_NAMES: u16 = 1 << 11;
    const DOS_DATE: u16 = 0x21;
    let le16 = |out: &mut Vec<u8>, value: u16| out.extend_from_slice(&value.to_le_bytes());
    let le32 = |out: &mut Vec<u8>, value: u32| out.extend_from_slice(&value.to_le_bytes());
    let crc = |data: &[u8]| {
        let mut crc = flate2::Crc::new();
        crc.update(data);
        crc.sum()
    };
    let len32 = |len: usize| u32::try_from(len).expect("test fixture");
    let len16 = |len: usize| u16::try_from(len).expect("test fixture");
    let mut out = Vec::new();
    let mut offsets: Vec<u32> = Vec::new();
    for entry in entries {
        offsets.push(len32(out.len()));
        out.extend_from_slice(b"PK\x03\x04");
        for field in [NEEDED, UTF8_NAMES, 0, 0, DOS_DATE] {
            le16(&mut out, field);
        }
        le32(&mut out, crc(&entry.data));
        le32(&mut out, len32(entry.data.len()));
        le32(&mut out, len32(entry.data.len()));
        le16(&mut out, len16(entry.name.len()));
        le16(&mut out, 0);
        out.extend_from_slice(entry.name.as_bytes());
        out.extend_from_slice(&entry.data);
    }
    let directory_start = out.len();
    for (entry, offset) in entries.iter().zip(&offsets) {
        out.extend_from_slice(b"PK\x01\x02");
        for field in [MADE_BY_UNIX, NEEDED, UTF8_NAMES, 0, 0, DOS_DATE] {
            le16(&mut out, field);
        }
        le32(&mut out, crc(&entry.data));
        le32(&mut out, len32(entry.data.len()));
        le32(&mut out, len32(entry.data.len()));
        le16(&mut out, len16(entry.name.len()));
        // Extra field, comment, disk, internal attributes.
        for field in [0, 0, 0, 0] {
            le16(&mut out, field);
        }
        le32(&mut out, entry.mode << 16);
        le32(&mut out, *offset);
        out.extend_from_slice(entry.name.as_bytes());
    }
    let directory_len = out.len() - directory_start;
    out.extend_from_slice(b"PK\x05\x06");
    for field in [0, 0, len16(entries.len()), len16(entries.len())] {
        le16(&mut out, field);
    }
    le32(&mut out, len32(directory_len));
    le32(&mut out, len32(directory_start));
    le16(&mut out, 0);
    out
}

/// Stages `entries` as a zipped ChatGPT export in the vault at `vault_dir`,
/// as `oneiron import chatgpt <zip> --hosted` does.
fn stage_zip(
    vault_dir: &Path,
    exports: &Path,
    entries: &[RawEntry],
) -> Result<HostedImportId, TestError> {
    let zip = exports.join("export.zip");
    std::fs::write(&zip, raw_zip(entries))?;
    Ok(stage(vault_dir, HistorySource::Chatgpt, &zip)?)
}

#[test]
fn the_job_lists_each_skipped_entry_in_the_parse_phase_and_the_real_export_lands() -> TestResult {
    let vault_dir = tempfile::tempdir()?;
    let exports = tempfile::tempdir()?;
    let (vault, owner) = open_vault(vault_dir.path())?;
    // The link is shallower than the real export: a pick by depth alone
    // takes it.
    let id = stage_zip(
        vault_dir.path(),
        exports.path(),
        &[
            RawEntry::file("conversations.json", SYMBOLIC_LINK, b"/etc/passwd"),
            RawEntry::file("../outside.json", REGULAR_FILE, b"[]"),
            RawEntry::file("export/pipe", FIFO, b""),
            RawEntry::file("export/conversations.json", REGULAR_FILE, &fixture_export()),
        ],
    )?;
    let listed = json!([
        { "name": "conversations.json", "reason": "symbolic_link" },
        { "name": "../outside.json", "reason": "escaping_path" },
        { "name": "export/pipe", "reason": "special_file" },
    ]);

    // A pass that lands nothing decodes the export: the skips are listed
    // before anything lands.
    pass(&vault, vault_dir.path(), Some(0))?;
    let staged = progress(&vault, owner, id).expect("the owner reads the import's progress");
    assert_eq!(staged["state"], json!("staged"), "{staged}");
    assert_eq!(
        staged["parse"]["skipped_entries"], listed,
        "FAILBEFORE: each skip is listed in the parse phase, in the archive's order: {staged}"
    );
    assert_eq!(staged["parse"]["skipped_entry_count"], json!(3), "{staged}");

    // The rest lands: the list stays in the ended job's progress.
    pass(&vault, vault_dir.path(), None)?;
    let landed = progress(&vault, owner, id).expect("the owner reads");
    assert_eq!(landed["state"], json!("landed"), "{landed}");
    assert_eq!(landed["failure"], Value::Null);
    assert_eq!(
        landed["searchable"]["conversations"], landed["parse"]["conversations"],
        "{landed}"
    );
    assert_eq!(
        vault.count_entities_by_type(ENTITY_TYPE_MESSAGE)?,
        FIXTURE_MESSAGES,
        "the real export lands, never the link's target"
    );
    assert_eq!(landed["parse"]["skipped_entries"], listed, "{landed}");
    assert_eq!(landed["parse"]["skipped_entry_count"], json!(3), "{landed}");
    Ok(())
}

#[test]
fn the_list_keeps_the_archives_first_skips_and_counts_them_all() -> TestResult {
    let vault_dir = tempfile::tempdir()?;
    let exports = tempfile::tempdir()?;
    let (vault, owner) = open_vault(vault_dir.path())?;
    let links = HOSTED_IMPORT_SKIPS_LISTED + 50;
    let mut entries: Vec<RawEntry> = (0..links)
        .map(|link| {
            RawEntry::file(
                format!("export/link-{link:03}"),
                SYMBOLIC_LINK,
                b"/etc/passwd",
            )
        })
        .collect();
    entries.push(RawEntry::file(
        "export/conversations.json",
        REGULAR_FILE,
        &fixture_export(),
    ));
    let id = stage_zip(vault_dir.path(), exports.path(), &entries)?;

    pass(&vault, vault_dir.path(), None)?;
    let landed = progress(&vault, owner, id).expect("the owner reads");
    assert_eq!(landed["state"], json!("landed"), "{landed}");
    assert_eq!(
        vault.count_entities_by_type(ENTITY_TYPE_MESSAGE)?,
        FIXTURE_MESSAGES
    );
    let skipped = landed["parse"]["skipped_entries"]
        .as_array()
        .expect("FAILBEFORE: the parse phase lists the skips");
    let names: Vec<&str> = skipped
        .iter()
        .map(|skip| skip["name"].as_str().expect("a name"))
        .collect();
    let first: Vec<String> = (0..HOSTED_IMPORT_SKIPS_LISTED)
        .map(|link| format!("export/link-{link:03}"))
        .collect();
    assert_eq!(names, first, "the archive's first skips, in its order");
    assert!(
        skipped
            .iter()
            .all(|skip| skip["reason"] == json!("symbolic_link"))
    );
    assert_eq!(
        landed["parse"]["skipped_entry_count"],
        json!(links),
        "the count names every skip, listed or not"
    );
    Ok(())
}

#[test]
fn a_refused_archive_ends_the_job_failed_with_the_refusal_and_lands_nothing() -> TestResult {
    let vault_dir = tempfile::tempdir()?;
    let exports = tempfile::tempdir()?;
    let (vault, owner) = open_vault(vault_dir.path())?;
    let export = fixture_export();
    let id = stage_zip(
        vault_dir.path(),
        exports.path(),
        &[
            RawEntry::file("export/conversations.json", REGULAR_FILE, &export),
            RawEntry::file("export/conversations.json", REGULAR_FILE, b"[]"),
        ],
    )?;

    pass(&vault, vault_dir.path(), None)?;
    let failed = progress(&vault, owner, id).expect("the owner reads");
    assert_eq!(failed["state"], json!("failed"), "{failed}");
    let failure = failed["failure"].as_str().expect("a failure's reason");
    assert!(
        failure.contains("holds two entries named \"export/conversations.json\""),
        "the failure names the refusal: {failure}"
    );
    assert_eq!(failed["searchable"]["conversations"], json!(0), "{failed}");
    assert_eq!(vault.count_entities_by_type(ENTITY_TYPE_MESSAGE)?, 0);
    Ok(())
}

#[test]
fn an_archive_with_no_skip_reports_none() -> TestResult {
    let vault_dir = tempfile::tempdir()?;
    let exports = tempfile::tempdir()?;
    let (vault, owner) = open_vault(vault_dir.path())?;
    let id = stage_zip(
        vault_dir.path(),
        exports.path(),
        &[RawEntry::file(
            "export/conversations.json",
            REGULAR_FILE,
            &fixture_export(),
        )],
    )?;

    pass(&vault, vault_dir.path(), None)?;
    let landed = progress(&vault, owner, id).expect("the owner reads");
    assert_eq!(landed["state"], json!("landed"), "{landed}");
    assert_eq!(
        vault.count_entities_by_type(ENTITY_TYPE_MESSAGE)?,
        FIXTURE_MESSAGES
    );
    let parse = landed["parse"].as_object().expect("a parse phase");
    assert!(
        !parse.contains_key("skipped_entries") && !parse.contains_key("skipped_entry_count"),
        "a parse phase with no skip keeps its old shape: {landed}"
    );
    Ok(())
}
