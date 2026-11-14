//! The archive pre-check under `vault.mail.sources.import_mbox` for a Google
//! Takeout `.zip` (ARCH-0027 #archive-precheck; CROSS-ARCH-0024
//! #onboarding-import 01-05): before any mbox file of the archive is read,
//! one deterministic pass over its entry list refuses overlapping entries and
//! an entry count past the request's `archive_max_entries`; skips and lists
//! an escaping path, a symbolic link and a special file; and checks each
//! mbox file's first bytes against the mbox reader.
//!
//! Public paths only:
//! `cargo test --locked -p oneiron --all-features --test mail_takeout_archive_precheck`.

use std::error::Error;
use std::fmt::Write as _;
use std::io::{Cursor, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::ingest::archive_precheck::{SkipReason, SkippedEntry};
use oneiron::mail_pack::{
    MailMboxImportReport, MailMboxImportRequest, MailProvider, MailSourceConnectRequest,
    MailSourceKind,
};
use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MemoryError};
use oneiron::secret_custody::{SECRET_CUSTODY_SCHEMA_VERSION, decode_secret_custody_body};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn Error>>;

/// The mailbox's address, and the credential it is connected with.
const ADDRESS: &str = "owner@test.example";
const CUSTODY_REF: &str = "test-mail-cred-takeout";

/// The Gmail ids (`X-GM-MSGID`) of the messages the tests export.
const FIRST: u64 = 1_781_234_567_890_123_456;
const SECOND: u64 = 1_781_234_567_890_123_457;
const OUTSIDE: u64 = 1_781_234_567_890_123_458;

/// Unix modes of the entries the tests write.
const REGULAR_FILE: u32 = 0o100_644;
const SYMBOLIC_LINK: u32 = 0o120_777;
const FIFO: u32 = 0o010_644;

/// The mbox file Takeout names for a whole mailbox.
const TAKEOUT_MBOX: &str = "Takeout/Mail/All mail Including Spam and Trash.mbox";

/// A vault with the mail pack installed and the owner's own Gmail mailbox
/// connected, and a folder for the files a test imports. The vault is
/// declared first, so it closes before its folder is removed.
struct Mailbox {
    vault: Vault,
    owner: EntityId,
    source_ref: String,
    files: tempfile::TempDir,
    _vault_dir: tempfile::TempDir,
}

impl Mailbox {
    fn new() -> Result<Self, Box<dyn Error>> {
        let vault_dir = tempfile::tempdir()?;
        // The pack installs as the embedded owner, whose proof needs the
        // vault's writer lease: open it owned, and start the host as a server
        // does.
        let vault = Vault::open_owned(vault_dir.path(), VaultConfig::default())?;
        let owner = vault.ensure_embedded_owner_actor()?;
        let issuer = HostSlipIssuer::from_secret(b"mail takeout archive precheck test host")?;
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        vault.ensure_host_root_slip(&issuer)?;
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let source_ref = {
            let memory = vault.memory(owner, EdgeActorClass::Human);
            oneiron::mail_pack::install_mail_calendar_pack_embedded(&memory)?;
            register_mail_credential(&vault, CUSTODY_REF)?;
            memory
                .mail_sources_connect(&MailSourceConnectRequest {
                    provider: MailProvider::Google,
                    kind: MailSourceKind::PersonalMailbox,
                    address: ADDRESS.to_owned(),
                    provider_account: ADDRESS.to_owned(),
                    custody_ref: CUSTODY_REF.to_owned(),
                    members: Vec::new(),
                    for_person: None,
                    channel_identity_ref: None,
                    copy: None,
                    on_provider_delete: None,
                    calendar_details: None,
                })?
                .source
                .source_ref
        };
        Ok(Self {
            vault,
            owner,
            source_ref,
            files: tempfile::tempdir()?,
            _vault_dir: vault_dir,
        })
    }

    /// Writes `bytes` as the file `name` on this device.
    fn file(&self, name: &str, bytes: &[u8]) -> Result<PathBuf, Box<dyn Error>> {
        let path = self.files.path().join(name);
        std::fs::write(&path, bytes)?;
        Ok(path)
    }

    /// The import request for the file at `path`, as the owner sends it.
    fn request(&self, path: &Path, archive_max_entries: Option<u64>) -> MailMboxImportRequest {
        MailMboxImportRequest {
            source_ref: self.source_ref.clone(),
            path: path.to_string_lossy().into_owned(),
            messages: None,
            archive_max_entries,
        }
    }

    fn import(&self, request: &MailMboxImportRequest) -> Result<MailMboxImportReport, MemoryError> {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .mail_sources_import_mbox(request)
    }

    /// What a plain mbox of the first and second messages lands now: both,
    /// when nothing of them landed before.
    fn landed_by_a_plain_mbox(&self) -> Result<u64, Box<dyn Error>> {
        let path = self.file("All.mbox", &takeout_mbox(&[FIRST, SECOND]))?;
        let report = self.import(&self.request(&path, None))?;
        assert!(report.done, "{report:?}");
        Ok(report.landed)
    }
}

/// Registers a Gmail credential under `custody_ref`, stored for the owner,
/// as the owner's custody door registers one.
fn register_mail_credential(vault: &Vault, custody_ref: &str) -> TestResult {
    use rmpv::Value;
    let band = |min: u64, max: u64| {
        Value::Map(vec![
            (Value::from("min"), Value::from(min)),
            (Value::from("max"), Value::from(max)),
        ])
    };
    let floor = Value::Map(vec![
        (Value::from("portable"), band(0, 2)),
        (Value::from("device_bound"), band(0, 2)),
        (Value::from("cross_vault"), band(0, 0)),
        (Value::from("rotation_max_age_secs"), Value::Nil),
        (Value::from("env_bindings"), Value::Map(vec![])),
    ]);
    let binding = Value::Map(vec![
        (Value::from("effector"), Value::from("connector:gmail")),
        (Value::from("tier_ceiling"), Value::from(0_u64)),
        (Value::from("scopes"), Value::Array(vec![])),
    ]);
    let body = Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(u64::from(SECRET_CUSTODY_SCHEMA_VERSION)),
        ),
        (Value::from("name"), Value::from(custody_ref)),
        (Value::from("class"), Value::from("custody-portable")),
        (Value::from("device_only"), Value::from(false)),
        (
            Value::from("value_bytes"),
            Value::Binary(b"test-mail-token".to_vec()),
        ),
        (Value::from("status"), Value::from("active")),
        (Value::from("registered_at"), Value::from(1_u64)),
        (Value::from("rotated_at"), Value::Nil),
        (Value::from("rotation_generation"), Value::from(0_u64)),
        (Value::from("bindings"), Value::Array(vec![binding])),
        (Value::from("manifest_ref"), Value::from("")),
        (Value::from("declared_paths"), Value::Array(vec![])),
        (Value::from("policy_floor_snapshot"), floor),
        (Value::from("model_reveal_allowed"), Value::from(true)),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &body)?;
    vault.register_secret(decode_secret_custody_body(&bytes)?)?;
    Ok(())
}

/// A Takeout mbox of one message per Gmail id in `ids`: the separator
/// carries the id as Takeout writes it, the message its thread and labels.
fn takeout_mbox(ids: &[u64]) -> Vec<u8> {
    let mut mbox = String::new();
    for id in ids {
        write!(
            mbox,
            "From {id}@xxx Wed Nov 06 01:02:03 +0000 2024\n\
             X-GM-THRID: {id}\n\
             X-Gmail-Labels: Inbox\n\
             Message-ID: <{id}@test.example>\n\
             From: Alice <alice@test.example>\n\
             To: {ADDRESS}\n\
             Subject: Message {id}\n\
             Date: Wed, 06 Nov 2024 01:02:03 +0000\n\
             \n\
             Message {id}, as Takeout exported it.\n\
             \n"
        )
        .expect("a String takes every write");
    }
    mbox.into_bytes()
}

/// A zip the `zip` writer writes, deflated as Takeout writes it: `entries`
/// as (name, bytes).
fn takeout_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let options = zip::write::FileOptions::default();
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, bytes) in entries {
        zip.start_file(*name, options).expect("test fixture");
        zip.write_all(bytes).expect("test fixture");
    }
    zip.finish().expect("test fixture").into_inner()
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
/// writes: a FIFO or a link mode, entries sharing a local header.
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

/// `refused` is a bad request whose message names each of `named`.
fn assert_refused(refused: &MemoryError, named: &[&str]) {
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST, "{refused:?}");
    for name in named {
        assert!(
            refused.message.contains(name),
            "the refusal names {name:?}: {refused:?}"
        );
    }
}

#[test]
fn a_plain_takeout_zip_lands_its_mbox_with_no_skip() -> TestResult {
    let mailbox = Mailbox::new()?;
    let zip = mailbox.file(
        "takeout.zip",
        &takeout_zip(&[(TAKEOUT_MBOX, &takeout_mbox(&[FIRST, SECOND]))]),
    )?;
    let report = mailbox.import(&mailbox.request(&zip, None))?;
    assert_eq!(report.landed, 2, "both messages land: {report:?}");
    assert!(report.done, "{report:?}");
    assert!(report.skipped_entries.is_empty(), "{report:?}");
    Ok(())
}

#[test]
fn overlapping_mbox_entries_are_refused_before_any_message_lands() -> TestResult {
    let mailbox = Mailbox::new()?;
    let mbox = takeout_mbox(&[FIRST, SECOND]);
    // Two central entries, one local header: the CVE-2019-13232 shape.
    let zip = mailbox.file(
        "overlap.zip",
        &raw_zip(&[
            RawEntry::file("Takeout/Mail/All.mbox", REGULAR_FILE, &mbox),
            RawEntry {
                shares: Some(0),
                ..RawEntry::file("Takeout/Mail/Copy.mbox", REGULAR_FILE, &mbox)
            },
        ]),
    )?;
    let refused = mailbox
        .import(&mailbox.request(&zip, None))
        .expect_err("overlapping entries are refused");
    assert_refused(
        &refused,
        &[
            "overlapping entries",
            "Takeout/Mail/All.mbox",
            "Takeout/Mail/Copy.mbox",
        ],
    );
    assert_eq!(
        mailbox.landed_by_a_plain_mbox()?,
        2,
        "the refused archive landed none of its messages"
    );
    Ok(())
}

#[test]
fn an_mbox_entry_that_is_not_an_mbox_is_refused_by_its_magic_bytes() -> TestResult {
    let mailbox = Mailbox::new()?;
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.resize(4_096, 0);
    let zip = mailbox.file("magic.zip", &takeout_zip(&[(TAKEOUT_MBOX, &png)]))?;
    let refused = mailbox
        .import(&mailbox.request(&zip, None))
        .expect_err("an entry that does not start as an mbox is refused");
    assert_refused(&refused, &["magic bytes", TAKEOUT_MBOX, "mbox reader"]);
    Ok(())
}

#[test]
fn a_link_an_escaping_path_and_a_fifo_are_skipped_listed_and_the_mbox_lands() -> TestResult {
    let mailbox = Mailbox::new()?;
    let zip = mailbox.file(
        "skips.zip",
        &raw_zip(&[
            RawEntry::file("Takeout/Mail/Link.mbox", SYMBOLIC_LINK, b"/etc/passwd"),
            RawEntry::file(
                "../../Outside.mbox",
                REGULAR_FILE,
                &takeout_mbox(&[OUTSIDE]),
            ),
            RawEntry::file("Takeout/Mail/pipe.mbox", FIFO, b""),
            RawEntry::file(
                "Takeout/Mail/All.mbox",
                REGULAR_FILE,
                &takeout_mbox(&[FIRST, SECOND]),
            ),
        ]),
    )?;
    let report = mailbox.import(&mailbox.request(&zip, None))?;
    assert_eq!(
        report.landed, 2,
        "the kept mbox lands, and nothing of a skipped entry: {report:?}"
    );
    assert!(report.done, "{report:?}");
    let skipped = |name: &str, reason| SkippedEntry {
        name: name.to_owned(),
        reason,
    };
    assert_eq!(
        report.skipped_entries,
        [
            skipped("Takeout/Mail/Link.mbox", SkipReason::SymbolicLink),
            skipped("../../Outside.mbox", SkipReason::EscapingPath),
            skipped("Takeout/Mail/pipe.mbox", SkipReason::SpecialFile),
        ],
        "each skip is listed, in the archive's order"
    );
    Ok(())
}

#[test]
fn an_archive_past_archive_max_entries_is_refused_naming_the_field_and_the_field_lifts_it()
-> TestResult {
    let mailbox = Mailbox::new()?;
    let mbox = takeout_mbox(&[FIRST, SECOND]);
    let zip = mailbox.file(
        "entries.zip",
        &takeout_zip(&[
            (TAKEOUT_MBOX, &mbox),
            ("Takeout/archive_browser.html", b""),
            ("Takeout/Mail/user_settings.json", b"{}"),
            ("Takeout/Mail/labels.json", b"[]"),
        ]),
    )?;
    // The field as the verb's wire carries it.
    let capped: MailMboxImportRequest = serde_json::from_value(serde_json::json!({
        "source_ref": mailbox.source_ref,
        "path": zip.to_string_lossy(),
        "archive_max_entries": 3,
    }))?;
    assert_eq!(capped, mailbox.request(&zip, Some(3)));
    let refused = mailbox
        .import(&capped)
        .expect_err("four entries are past a cap of three");
    assert_refused(
        &refused,
        &[
            "declares 4 entries",
            "entry cap of 3",
            "archive_max_entries",
        ],
    );
    assert!(
        refused
            .suggestions
            .iter()
            .any(|suggestion| suggestion.contains("archive_max_entries")),
        "the suggestion names the field: {refused:?}"
    );
    let lifted = mailbox.import(&mailbox.request(&zip, Some(4)))?;
    assert_eq!(
        lifted.landed, 2,
        "a cap the archive meets lands it: {lifted:?}"
    );
    assert!(lifted.done, "{lifted:?}");
    Ok(())
}
