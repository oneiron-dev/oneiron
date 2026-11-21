//! The storage cap under `vault.mail.sources.import_mbox` for a Google
//! Takeout `.zip` (ARCH-0027 #archive-precheck: "An archive that unpacks
//! past the vault's storage cap stops there and reports what came in"). A
//! vault whose host set `VaultConfig::storage_cap_bytes` (a served vault's
//! `[import] storage_cap_bytes`) reads a zipped mbox only up to the room the
//! cap leaves: the call stops before the message the cap cuts, keeps what
//! landed, says `stopped_at_storage_cap`, and a later call goes on from
//! there once the vault holds less. A vault with no cap, and a plain mbox
//! (read in place, not unpacked), never stop so.
//!
//! Public paths only:
//! `cargo test --locked -p oneiron --all-features --test mail_takeout_storage_cap`.

use std::error::Error;
use std::fmt::Write as _;
use std::fs::File;
use std::io::{Cursor, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::ingest::archive_precheck::storage_room;
use oneiron::mail_pack::{
    MailMboxImportReport, MailMboxImportRequest, MailProvider, MailSourceConnectRequest,
    MailSourceKind,
};
use oneiron::memory::MemoryError;
use oneiron::secret_custody::{SECRET_CUSTODY_SCHEMA_VERSION, decode_secret_custody_body};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn Error>>;

/// The mailbox's address, and the credential it is connected with.
const ADDRESS: &str = "owner@test.example";
const CUSTODY_REF: &str = "test-mail-cred-storage-cap";

/// The Gmail id (`X-GM-MSGID`) of the first message the tests export; the
/// others follow it.
const FIRST: u64 = 1_781_234_567_890_123_456;
/// How many messages the tests export.
const MESSAGES: u64 = 6;

/// The storage cap the capped vault opens under: past what a fresh vault's
/// folder holds, so the test sets the room it leaves with a file of its own
/// in the folder.
const CAP: u64 = 1 << 34;
/// The file that stands for what the capped vault already holds.
const HELD_FILE: &str = "storage-cap-test-held";

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
    /// The mailbox in a vault opened under `storage_cap_bytes`.
    fn new(storage_cap_bytes: Option<u64>) -> Result<Self, Box<dyn Error>> {
        let vault_dir = tempfile::tempdir()?;
        let mut config = VaultConfig::default();
        config.storage_cap_bytes = storage_cap_bytes;
        // The pack installs as the embedded owner, whose proof needs the
        // vault's writer lease: open it owned, and start the host as a server
        // does.
        let vault = Vault::open_owned(vault_dir.path(), config)?;
        let owner = vault.ensure_embedded_owner_actor()?;
        let issuer = HostSlipIssuer::from_secret(b"mail takeout storage cap test host")?;
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
    fn request(&self, path: &Path) -> MailMboxImportRequest {
        MailMboxImportRequest {
            source_ref: self.source_ref.clone(),
            path: path.to_string_lossy().into_owned(),
            messages: None,
            archive_max_entries: None,
        }
    }

    fn import(&self, path: &Path) -> Result<MailMboxImportReport, MemoryError> {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .mail_sources_import_mbox(&self.request(path))
    }

    /// Fills the capped vault's folder until the cap leaves it `room` bytes:
    /// a sparse file there stands for what the vault already holds.
    fn leave_room(&self, room: u64) -> TestResult {
        let now = storage_room(Some(CAP), self.vault.path())?.ok_or("a cap leaves a room")?;
        assert!(
            now > room,
            "a fresh vault's folder holds less than the test's cap ({now} bytes of room)"
        );
        File::create(self.vault.path().join(HELD_FILE))?.set_len(now - room)?;
        assert_eq!(
            storage_room(Some(CAP), self.vault.path())?,
            Some(room),
            "the file leaves the room the test asked for"
        );
        Ok(())
    }

    /// Frees what [`Self::leave_room`] filled, as an owner frees space.
    fn free_space(&self) -> TestResult {
        std::fs::remove_file(self.vault.path().join(HELD_FILE))?;
        Ok(())
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

/// The Gmail ids of the messages the tests export.
fn exported_ids() -> Vec<u64> {
    (0..MESSAGES).map(|at| FIRST + at).collect()
}

/// A Takeout `.zip` of one mbox holding every exported message.
fn exported_zip() -> Vec<u8> {
    takeout_zip(&[(TAKEOUT_MBOX, &takeout_mbox(&exported_ids()))])
}

#[test]
fn a_takeout_past_the_storage_cap_stops_and_reports_what_came_in() -> TestResult {
    let mailbox = Mailbox::new(Some(CAP))?;
    let zip = mailbox.file("takeout.zip", &exported_zip())?;
    // Room for one message and half of the next: the first lands, and the
    // cap cuts the second.
    let message_bytes = u64::try_from(takeout_mbox(&[FIRST]).len())?;
    mailbox.leave_room(message_bytes + message_bytes / 2)?;

    let first = mailbox.import(&zip)?;
    assert!(
        first.stopped_at_storage_cap,
        "the call stops at the room the cap leaves: {first:?}"
    );
    assert!(!first.done, "the archive is not read whole: {first:?}");
    assert_eq!(
        first.landed, 1,
        "the message before the cap lands, the one it cuts does not: {first:?}"
    );
    assert_eq!(first.read_total, 1, "{first:?}");

    // The vault holds no less, so a later call lands no more than the room
    // still leaves, and stops again.
    let second = mailbox.import(&zip)?;
    assert!(second.stopped_at_storage_cap, "{second:?}");
    assert!(!second.done, "{second:?}");
    assert!(
        first.landed + second.landed < MESSAGES,
        "the cap still holds the archive back: {second:?}"
    );

    // Once the owner frees space, the next call goes on from where the
    // last stopped and lands the rest, each message once.
    mailbox.free_space()?;
    let rest = mailbox.import(&zip)?;
    assert!(!rest.stopped_at_storage_cap, "{rest:?}");
    assert!(rest.done, "{rest:?}");
    assert_eq!(
        first.landed + second.landed + rest.landed,
        MESSAGES,
        "every message lands once over the three calls: {rest:?}"
    );
    assert_eq!(rest.same, 0, "no message landed twice: {rest:?}");
    assert_eq!(rest.read_total, MESSAGES, "{rest:?}");
    Ok(())
}

#[test]
fn a_takeout_without_a_cap_lands_whole() -> TestResult {
    let mailbox = Mailbox::new(None)?;
    let zip = mailbox.file("takeout.zip", &exported_zip())?;
    let report = mailbox.import(&zip)?;
    assert_eq!(report.landed, MESSAGES, "{report:?}");
    assert!(report.done, "{report:?}");
    assert!(!report.stopped_at_storage_cap, "{report:?}");
    Ok(())
}

#[test]
fn a_plain_mbox_is_read_in_place_and_never_stopped_by_the_cap() -> TestResult {
    let mailbox = Mailbox::new(Some(CAP))?;
    let mbox = mailbox.file("All.mbox", &takeout_mbox(&exported_ids()))?;
    mailbox.leave_room(0)?;
    let report = mailbox.import(&mbox)?;
    assert_eq!(report.landed, MESSAGES, "{report:?}");
    assert!(report.done, "{report:?}");
    assert!(!report.stopped_at_storage_cap, "{report:?}");
    Ok(())
}
