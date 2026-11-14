//! The archive pre-check under `oneiron import chatgpt <zip>`, through the
//! shipped binary (ARCH-0027 #archive-precheck; CROSS-ARCH-0024
//! #onboarding-import 01-05): before anything of an export zip is read or
//! written, one deterministic pass over its entry list refuses overlapping
//! entries, a name held twice and an entry count past `[import]
//! archive_max_entries`; skips and lists an escaping path, a symbolic link
//! and a special file; checks the picked entry's first bytes against the JSON
//! reader; and stops at the room `[import] storage_cap_bytes` leaves. A
//! refused import lands nothing.
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use oneiron::ingest::archive_precheck::{
    ArchiveBounds, ArchiveRefusal, EntryReader, SkipReason, check_archive,
};
use oneiron::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE};
use oneiron::{Vault, VaultConfig};
use serde_json::Value;

/// The fixture export's messages, landed: two conversations, six messages.
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

/// A fresh vault and the config file `init` wrote for it.
struct Home {
    dir: tempfile::TempDir,
    vault: PathBuf,
    config: PathBuf,
    /// The config as `init` wrote it, before any `[import]` row.
    written: String,
    /// What the vault held before any import: `init` and the first open
    /// write rows of their own (a fresh vault holds one conversation).
    fresh: Held,
}

/// How many messages and conversations a vault holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Held {
    messages: u64,
    conversations: u64,
}

impl Home {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("test fixture");
        let vault = dir.path().join("vault");
        let config = dir.path().join("oneiron.toml");
        let init = Command::new(env!("CARGO_BIN_EXE_oneiron"))
            .args(["init", vault.to_str().expect("test fixture")])
            .args([
                "--config",
                config.to_str().expect("test fixture"),
                "--embedder",
                "none",
            ])
            .output()
            .expect("test fixture");
        assert!(
            init.status.success(),
            "init: {}",
            String::from_utf8_lossy(&init.stderr)
        );
        let written = std::fs::read_to_string(&config).expect("test fixture");
        let fresh = held_in(&vault);
        Self {
            dir,
            vault,
            config,
            written,
            fresh,
        }
    }

    /// Sets the config's `[import]` section to `rows`.
    fn import_rows(&self, rows: &str) {
        std::fs::write(
            &self.config,
            format!("{}\n[import]\n{rows}\n", self.written),
        )
        .expect("test fixture");
    }

    /// Writes `bytes` as `<name>` in the home folder.
    fn zip_file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.dir.path().join(name);
        std::fs::write(&path, bytes).expect("test fixture");
        path
    }

    /// Runs `oneiron import chatgpt <zip>`.
    fn import(&self, zip: &Path) -> Output {
        Command::new(env!("CARGO_BIN_EXE_oneiron"))
            .args(["import", "chatgpt"])
            .arg(zip)
            .arg("--config")
            .arg(&self.config)
            .env_remove("ONEIRON_VAULT_PATH")
            .output()
            .expect("test fixture")
    }

    fn count(&self, entity_type: u8) -> u64 {
        Vault::open_owned(&self.vault, VaultConfig::server())
            .expect("open vault")
            .count_entities_by_type(entity_type)
            .expect("test fixture")
    }

    fn held(&self) -> Held {
        held_in(&self.vault)
    }

    /// What the vault's folder holds on disk: every file below it, through
    /// no link (the bytes the storage cap is measured against).
    fn vault_folder_bytes(&self) -> u64 {
        let mut held = 0;
        let mut pending = vec![self.vault.clone()];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).expect("test fixture") {
                let entry = entry.expect("test fixture");
                let metadata = entry.metadata().expect("test fixture");
                if metadata.is_dir() {
                    pending.push(entry.path());
                } else if metadata.is_file() {
                    held += metadata.len();
                }
            }
        }
        held
    }
}

fn held_in(vault: &Path) -> Held {
    let vault = Vault::open_owned(vault, VaultConfig::server()).expect("open vault");
    let count = |entity_type| {
        vault
            .count_entities_by_type(entity_type)
            .expect("test fixture")
    };
    Held {
        messages: count(ENTITY_TYPE_MESSAGE),
        conversations: count(ENTITY_TYPE_CONVERSATION),
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Asserts the import failed, its stderr names each of `named`, and nothing
/// landed: the vault holds what it held before the import.
fn assert_refused(home: &Home, output: &Output, named: &[&str]) {
    let stderr = stderr(output);
    assert!(
        !output.status.success(),
        "the import must be refused; stdout: {}; stderr: {stderr}",
        String::from_utf8_lossy(&output.stdout)
    );
    for name in named {
        assert!(
            stderr.contains(name),
            "stderr must name {name:?}; it is: {stderr}"
        );
    }
    assert_eq!(home.held(), home.fresh, "nothing landed");
}

/// Asserts the import succeeded and returns its report.
fn assert_landed(output: &Output) -> Value {
    assert!(output.status.success(), "import: {}", stderr(output));
    serde_json::from_slice(&output.stdout).expect("a JSON report on stdout")
}

/// One entry of a hand-written zip: stored, with the unix mode its central
/// directory entry records. `shares` points its central entry at an earlier
/// entry's local header instead of writing one (its `data` must be that
/// entry's).
struct RawEntry {
    name: &'static str,
    mode: u32,
    data: Vec<u8>,
    shares: Option<usize>,
}

impl RawEntry {
    fn file(name: &'static str, mode: u32, data: &[u8]) -> Self {
        Self {
            name,
            mode,
            data: data.to_vec(),
            shares: None,
        }
    }
}

/// A zip written byte by byte, so a test sets what the `zip` writer never
/// writes: a FIFO or a link mode, entries sharing a local header, one name
/// held twice.
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
        if let Some(earlier) = entry.shares {
            offsets.push(offsets[earlier]);
            continue;
        }
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

/// A zip the `zip` writer writes: the fixture export as
/// `export/conversations.json`, then `pads` empty entries.
fn export_zip_with_pads(pads: usize) -> Vec<u8> {
    let stored =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file("export/conversations.json", stored)
        .expect("test fixture");
    zip.write_all(&fixture_export()).expect("test fixture");
    for pad in 0..pads {
        zip.start_file(format!("export/pad/{pad}"), stored)
            .expect("test fixture");
    }
    zip.finish().expect("test fixture").into_inner()
}

#[test]
fn overlapping_zip_entries_are_refused_before_any_write() {
    let home = Home::new();
    let export = fixture_export();
    // Two central entries, one local header: the CVE-2019-13232 shape.
    let zip = home.zip_file(
        "overlap.zip",
        &raw_zip(&[
            RawEntry::file("export/conversations.json", REGULAR_FILE, &export),
            RawEntry {
                shares: Some(0),
                ..RawEntry::file("export/copy.json", REGULAR_FILE, &export)
            },
        ]),
    );
    let output = home.import(&zip);
    assert_refused(
        &home,
        &output,
        &[
            "overlapping entries",
            "export/copy.json",
            "Nothing was imported",
        ],
    );
}

#[test]
fn two_entries_with_one_name_are_refused() {
    let home = Home::new();
    let export = fixture_export();
    let zip = home.zip_file(
        "twice.zip",
        &raw_zip(&[
            RawEntry::file("export/conversations.json", REGULAR_FILE, &export),
            RawEntry::file("export/conversations.json", REGULAR_FILE, b"[]"),
        ]),
    );
    let output = home.import(&zip);
    assert_refused(
        &home,
        &output,
        &["holds two entries named \"export/conversations.json\""],
    );
}

#[test]
fn a_root_link_named_conversations_json_is_skipped_listed_and_the_real_export_lands() {
    let home = Home::new();
    // The link is shallower than the real export: a pick by depth alone
    // takes it.
    let zip = home.zip_file(
        "link.zip",
        &raw_zip(&[
            RawEntry::file("conversations.json", SYMBOLIC_LINK, b"/etc/passwd"),
            RawEntry::file("../outside.json", REGULAR_FILE, b"[]"),
            RawEntry::file("export/pipe", FIFO, b""),
            RawEntry::file("export/conversations.json", REGULAR_FILE, &fixture_export()),
        ]),
    );
    let report = assert_landed(&home.import(&zip));
    assert_eq!(home.count(ENTITY_TYPE_MESSAGE), FIXTURE_MESSAGES);
    let skipped: Vec<(&str, &str)> = report["warnings"]
        .as_array()
        .expect("a warnings list")
        .iter()
        .filter(|warning| warning["warning"] == "archive_entry_skipped")
        .map(|warning| {
            (
                warning["name"].as_str().expect("a name"),
                warning["reason"].as_str().expect("a reason"),
            )
        })
        .collect();
    assert_eq!(
        skipped,
        [
            ("conversations.json", "symbolic_link"),
            ("../outside.json", "escaping_path"),
            ("export/pipe", "special_file"),
        ],
        "each skip is listed, in the archive's order: {report}"
    );
}

#[test]
fn an_archive_past_the_entry_cap_is_refused_naming_the_row_and_one_at_the_cap_lands() {
    let home = Home::new();
    // Past 65,535 entries the end record holds 0xFFFF and the ZIP64 record
    // holds the count: the cap reads the ZIP64 one.
    home.import_rows("archive_max_entries = 65536");
    let past = home.zip_file("past.zip", &export_zip_with_pads(65_536));
    let output = home.import(&past);
    assert_refused(
        &home,
        &output,
        &[
            "declares 65537 entries",
            "`[import] archive_max_entries` (65536)",
        ],
    );

    let at = home.zip_file("at.zip", &export_zip_with_pads(65_535));
    assert_landed(&home.import(&at));
    assert_eq!(home.count(ENTITY_TYPE_MESSAGE), FIXTURE_MESSAGES);
}

#[test]
fn a_conversations_entry_that_is_not_json_is_refused_by_its_magic_bytes() {
    let home = Home::new();
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file(
        "export/conversations.json",
        zip::write::FileOptions::default(),
    )
    .expect("test fixture");
    // A PNG, then 64 MiB of zeros: deflated to a few hundred KB.
    zip.write_all(b"\x89PNG\r\n\x1a\n").expect("test fixture");
    let zeros = vec![0_u8; 1 << 20];
    for _ in 0..64 {
        zip.write_all(&zeros).expect("test fixture");
    }
    let bytes = zip.finish().expect("test fixture").into_inner();
    let output = home.import(&home.zip_file("png.zip", &bytes));
    assert_refused(
        &home,
        &output,
        &["magic bytes", "does not start as JSON input"],
    );
}

#[test]
fn an_export_past_the_storage_cap_stops_and_a_cap_with_room_lands_it() {
    let home = Home::new();
    let zip = home.zip_file("export.zip", &export_zip_with_pads(0));
    // Room for 4 KiB: the 6 KiB export does not fit.
    home.import_rows(&format!(
        "storage_cap_bytes = {}",
        home.vault_folder_bytes() + 4096
    ));
    let output = home.import(&zip);
    assert_refused(
        &home,
        &output,
        &["storage cap", "`[import] storage_cap_bytes`"],
    );

    home.import_rows(&format!(
        "storage_cap_bytes = {}",
        home.vault_folder_bytes() + (1 << 20)
    ));
    assert_landed(&home.import(&zip));
    assert_eq!(home.count(ENTITY_TYPE_MESSAGE), FIXTURE_MESSAGES);
}

#[test]
fn a_plain_export_zip_lands_with_no_skip() {
    let home = Home::new();
    let zip = home.zip_file("export.zip", &export_zip_with_pads(2));
    let report = assert_landed(&home.import(&zip));
    assert_eq!(home.count(ENTITY_TYPE_MESSAGE), FIXTURE_MESSAGES);
    assert!(
        report["warnings"]
            .as_array()
            .expect("a warnings list")
            .iter()
            .all(|warning| warning["warning"] != "archive_entry_skipped"),
        "{report}"
    );
}

#[test]
fn the_pass_keeps_central_directory_order_masks_special_bits_and_bounds_reads() {
    let bytes = raw_zip(&[
        RawEntry::file("b.json", 0o104_755, b"{}"),
        RawEntry::file("a/", 0o040_755, b""),
        RawEntry::file("link", SYMBOLIC_LINK, b"b.json"),
        RawEntry::file("c.json", REGULAR_FILE, b"[1, 2, 3]"),
    ]);
    let bounds = ArchiveBounds { max_entries: 16 };
    let mut archive = check_archive(Cursor::new(bytes.as_slice()), bounds).expect("checked");
    let kept: Vec<(String, Option<u32>, bool)> = archive
        .entries()
        .iter()
        .map(|entry| {
            (
                entry.path.to_string_lossy().into_owned(),
                entry.mode,
                entry.directory,
            )
        })
        .collect();
    assert_eq!(
        kept,
        [
            ("b.json".to_owned(), Some(0o755), false),
            ("a/".to_owned(), Some(0o755), true),
            ("c.json".to_owned(), Some(0o644), false),
        ],
        "central-directory order; set-uid and file-type bits never leave the pass"
    );
    assert_eq!(archive.skipped().len(), 1);
    assert_eq!(archive.skipped()[0].reason, SkipReason::SymbolicLink);
    assert_eq!(
        archive
            .read_entry(2, EntryReader::Json, 64)
            .expect("a JSON entry within its bound"),
        b"[1, 2, 3]"
    );
    assert_eq!(
        archive.read_entry(2, EntryReader::Json, 4),
        Err(ArchiveRefusal::PastBound {
            name: "c.json".to_owned(),
            bound: 4
        })
    );

    let again = check_archive(Cursor::new(bytes.as_slice()), bounds).expect("checked");
    assert_eq!(
        again.entries(),
        archive.entries(),
        "the same bytes, the same pass"
    );
    assert_eq!(again.skipped(), archive.skipped());
}
