//! The e-sign delivery outbox (OF-415, FIX 3577): the seam that hands each
//! authorized `esign.delivery` intent to the host's sender as a file. The
//! intents are the vault's own. A row reaches that queue only after OF-327
//! let it through: the e-sign command's gate for an invitation, a reminder
//! or a void, the email send's for a promoted notice. This worker adds no
//! authority of its own, sends nothing and mints nothing.
//!
//! It runs only for `--esign-delivery-outbox-dir`. Each tick, under the
//! directory's `.lock`, it reads the sender's acks and settles each one
//! that echoes a current lease, reclaims this kind's expired leases, then
//! claims the ready intents and writes each one's envelope:
//!
//! - `esign-delivery-<key>.json`, where `key` is the lower-hex BLAKE3 of
//!   `esign.delivery\0` and the intent's dedupe key. It carries
//!   `schema_version` 1, `kind`, `channel` ("email"), `dedupe_key`,
//!   `attempt_id` (32 lower-hex), `lease_owner`, `attempt_count`,
//!   `leased_at` and `lease_expires_at` (Unix seconds), `payload_sha256`
//!   (lower-hex, over the payload's bytes as the file holds them) and
//!   `payload`, the queued e-sign notice copied byte for byte.
//! - The sender answers with `esign-delivery-<key>.ack.json`. It carries
//!   `schema_version` 1, the envelope's `dedupe_key`, `attempt_id`,
//!   `lease_owner`, `attempt_count` and `payload_sha256`, a `status` of
//!   "ok" or "failed", and a `reason` (null for ok, a nonempty code for
//!   failed).
//!
//! An ok completes the intent. A failed one is tried again a minute later,
//! with its reason kept. With no ack the lease stands until it expires; then
//! the intent is queued again, and its next claim replaces the envelope. An
//! ack that does not echo the current lease settles nothing. Nothing here
//! fails an intent, so none is ever dropped. Both sides write a file whole:
//! a private temporary sibling, synced, renamed, then the directory synced.
//!
//! No signing link is carried. Invitations and reminders need one, and until
//! the vault keeps custody of it a sender acks those failed
//! (`missing_signing_capability`), so they stay queued.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use oneiron::Vault;
use oneiron::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome,
    CleanupAttemptLeases, CompleteAttempt, RetryAttempt,
};
use oneiron::blob_artifact::esign::EsignNotice;
use rand_core::{OsRng, RngCore as _};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use sha2::{Digest as _, Sha256};

use crate::server::{HousekeepingAdmission, SyncServer};

/// The queue kind the vault keeps authorized e-sign mail under.
const DELIVERY_KIND: &str = "esign.delivery";
/// How often the outbox runs.
const POLL: Duration = Duration::from_secs(15);
/// How long an exported intent waits for its ack before it is queued again.
const LEASE_SECS: u64 = 300;
/// How long an intent its sender failed waits before its next try.
const RETRY_DELAY_SECS: u64 = 60;
/// The lease owner every outbox claim carries.
const LEASE_OWNER: &str = "esign-delivery-outbox";
/// The version of both file shapes.
const SCHEMA_VERSION: u32 = 1;
/// The channel an e-sign intent is delivered on.
const CHANNEL: &str = "email";
const FILE_PREFIX: &str = "esign-delivery-";
const ENVELOPE_SUFFIX: &str = ".json";
const ACK_SUFFIX: &str = ".ack.json";
/// Held for a tick, so two publishers never share the directory.
const LOCK_FILE: &str = ".lock";

/// Starts the outbox on `dir`. Each tick runs only while `admit` gives a
/// guard (a managed vault frozen for reap exports nothing), and holds it to
/// the tick's end, its file writes included.
pub(crate) fn spawn(
    server: Arc<SyncServer>,
    admit: HousekeepingAdmission,
    dir: PathBuf,
) -> tokio::task::JoinHandle<()> {
    let weak = Arc::downgrade(&server);
    drop(server);
    tracing::info!(dir = %dir.display(), "esign delivery outbox runs");
    let outbox = Arc::new(Outbox { dir });
    tokio::spawn(async move {
        let mut every = tokio::time::interval(POLL);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // A stop may have come between a claim and its envelope's write.
        let mut recover = true;
        loop {
            every.tick().await;
            let Some(server) = weak.upgrade() else {
                break;
            };
            let Some(pass) = admit() else {
                continue;
            };
            let outbox = Arc::clone(&outbox);
            let ran = tokio::task::spawn_blocking(move || {
                let _pass = pass;
                outbox.tick(server.vault(), recover)
            })
            .await;
            recover = match ran {
                Ok(Ok(pending)) => pending,
                Ok(Err(error)) => {
                    tracing::warn!(
                        error = %format!("{error:#}"),
                        "esign delivery outbox pass failed; it runs again next tick"
                    );
                    true
                }
                Err(error) => {
                    tracing::warn!(%error, "esign delivery outbox pass stopped");
                    true
                }
            };
        }
    })
}

/// The envelope the vault writes for one lease.
#[derive(Serialize)]
struct Envelope<'a> {
    schema_version: u32,
    kind: &'a str,
    channel: &'a str,
    dedupe_key: &'a str,
    attempt_id: String,
    lease_owner: &'a str,
    attempt_count: u32,
    leased_at: u64,
    lease_expires_at: u64,
    payload_sha256: &'a str,
    payload: &'a RawValue,
}

/// The lease an envelope on disk names.
#[derive(Deserialize)]
struct Fence {
    attempt_id: String,
    attempt_count: u32,
}

/// The sender's answer to one envelope.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ack {
    schema_version: u32,
    dedupe_key: String,
    attempt_id: String,
    lease_owner: String,
    attempt_count: u32,
    payload_sha256: String,
    status: AckStatus,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AckStatus {
    Ok,
    Failed,
}

impl AckStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Failed => "failed",
        }
    }
}

/// What one queued intent exports: its key, its file stem and its frozen
/// payload.
struct Export<'a> {
    dedupe_key: &'a str,
    stem: String,
    payload: &'a RawValue,
    payload_sha256: String,
}

enum FileRole {
    Envelope,
    Ack,
}

struct Outbox {
    dir: PathBuf,
}

impl Outbox {
    /// One tick: acks, reclaim, then envelopes. `Ok(true)` when an envelope
    /// could not be written, so the next tick writes the leases it holds
    /// before it claims more.
    fn tick(&self, vault: &Vault, recover: bool) -> anyhow::Result<bool> {
        let Some(_lock) = self.lock()? else {
            return Ok(recover);
        };
        let queue = AttemptQueue::new(vault);
        // The sender's acks settle their leases first, and the files of
        // intents no longer leased here go.
        self.reconcile(&queue)?;
        // This kind's leases that waited out their ack go back to the queue;
        // no other kind's lease is touched.
        let reclaimed = queue.cleanup_kind_leases(
            DELIVERY_KIND,
            CleanupAttemptLeases {
                now: unix_now(),
                lease_timeout_secs: LEASE_SECS,
            },
        )?;
        if let Some(report) = reclaimed.filter(|report| report.stale_requeued > 0) {
            tracing::info!(
                requeued = report.stale_requeued,
                "esign deliveries no ack answered are queued again"
            );
        }
        if recover && !self.publish_leased(&queue)? {
            return Ok(true);
        }
        Ok(!self.claim_ready(&queue)?)
    }

    /// The directory's lock, or `None` while another publisher holds it.
    fn lock(&self) -> anyhow::Result<Option<File>> {
        ensure_directory(&self.dir)
            .with_context(|| format!("create the outbox {}", self.dir.display()))?;
        let path = self.dir.join(LOCK_FILE);
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let file = options
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?;
        match file.try_lock() {
            Ok(()) => Ok(Some(file)),
            Err(fs::TryLockError::WouldBlock) => {
                tracing::debug!(
                    dir = %self.dir.display(),
                    "another publisher holds the esign delivery outbox; this tick waits"
                );
                Ok(None)
            }
            Err(fs::TryLockError::Error(error)) => {
                Err(anyhow::Error::new(error).context(format!("lock {}", path.display())))
            }
        }
    }

    /// Settles every ack that echoes a current lease and clears the files a
    /// settled or ended lease left.
    fn reconcile(&self, queue: &AttemptQueue<'_>) -> anyhow::Result<()> {
        let (acks, envelopes) = self
            .listing()
            .with_context(|| format!("read the outbox {}", self.dir.display()))?;
        let mut changed = false;
        for stem in &acks {
            match self.settle_ack(queue, stem) {
                Ok(cleared) => changed |= cleared,
                Err(error) => tracing::warn!(
                    error = %format!("{error:#}"),
                    %stem,
                    "esign delivery ack not settled; it is read again next tick"
                ),
            }
        }
        for stem in &envelopes {
            match self.retire_envelope(queue, stem) {
                Ok(cleared) => changed |= cleared,
                Err(error) => tracing::warn!(
                    error = %format!("{error:#}"),
                    %stem,
                    "esign delivery envelope not reconciled; it is read again next tick"
                ),
            }
        }
        if changed {
            sync_dir(&self.dir).with_context(|| format!("sync {}", self.dir.display()))?;
        }
        Ok(())
    }

    /// The stems of the acks and the envelopes in the directory.
    fn listing(&self) -> io::Result<(BTreeSet<String>, BTreeSet<String>)> {
        let mut acks = BTreeSet::new();
        let mut envelopes = BTreeSet::new();
        for entry in fs::read_dir(&self.dir)? {
            let name = entry?.file_name();
            match name.to_str().and_then(parse_name) {
                Some((stem, FileRole::Ack)) => {
                    acks.insert(stem);
                }
                Some((stem, FileRole::Envelope)) => {
                    envelopes.insert(stem);
                }
                None => {}
            }
        }
        Ok((acks, envelopes))
    }

    /// Settles the lease one ack answers, when it echoes that lease, and
    /// clears the files of a try already settled. `Ok(true)` when a file
    /// went.
    fn settle_ack(&self, queue: &AttemptQueue<'_>, stem: &str) -> anyhow::Result<bool> {
        let path = self.ack_path(stem);
        let Some(bytes) = read_if_present(&path)? else {
            return Ok(false);
        };
        let Some((ack, id)) = parse_ack(&bytes) else {
            tracing::warn!(%stem, "esign delivery ack is malformed; it settles nothing");
            return Ok(false);
        };
        // A row this vault does not hold is not this outbox's to judge.
        let Some(row) = queue.get(id)? else {
            return Ok(false);
        };
        if row.kind != DELIVERY_KIND {
            return Ok(false);
        }
        let bound = ack_binds(&ack, &row, stem);
        if row.state == AttemptState::Leased {
            // An older lease's answer, or one that does not echo this lease,
            // leaves it standing.
            if !bound || row.lease_owner.as_deref() != Some(LEASE_OWNER) {
                return Ok(false);
            }
            settle(queue, &row, &ack)?;
            tracing::info!(
                attempt = %ack.attempt_id,
                status = ack.status.as_str(),
                "esign delivery settled by its ack"
            );
        } else if !row.state.is_terminal() {
            // Queued again or paused: its next claim retires this ack.
            return Ok(false);
        }
        // Settled, now or before a stop that left its files: they go only
        // after the commit, the envelope first, and only the ones naming
        // this try. An ack naming a settled try can never settle anything.
        if bound {
            self.remove_envelope_of(stem, &row)?;
        }
        remove_if_unchanged(&path, &bytes)?;
        Ok(true)
    }

    /// Removes an envelope whose lease ended (settled, queued again or
    /// paused), so no sender acts on it. `Ok(true)` when it went.
    fn retire_envelope(&self, queue: &AttemptQueue<'_>, stem: &str) -> anyhow::Result<bool> {
        let path = self.envelope_path(stem);
        let Some(bytes) = read_if_present(&path)? else {
            return Ok(false);
        };
        let Some((fence, id)) = parse_fence(&bytes) else {
            return Ok(false);
        };
        let Some(row) = queue.get(id)? else {
            return Ok(false);
        };
        let current = row.state == AttemptState::Leased
            && row.lease_owner.as_deref() == Some(LEASE_OWNER)
            && row.attempt_count == fence.attempt_count;
        if row.kind != DELIVERY_KIND || current {
            return Ok(false);
        }
        Ok(remove_if_unchanged(&path, &bytes)?)
    }

    /// Removes `stem`'s envelope when it names `row`'s settled lease, not a
    /// later try of the same intent.
    fn remove_envelope_of(&self, stem: &str, row: &AttemptRecord) -> io::Result<()> {
        let path = self.envelope_path(stem);
        let Some(bytes) = read_if_present(&path)? else {
            return Ok(());
        };
        let names_row = parse_fence(&bytes)
            .is_some_and(|(fence, id)| id == row.id && fence.attempt_count == row.attempt_count);
        if names_row {
            remove_if_unchanged(&path, &bytes)?;
        }
        Ok(())
    }

    /// Writes the envelope of every lease this outbox holds, after a stop or
    /// a failed write. `Ok(false)` when one could not be written.
    fn publish_leased(&self, queue: &AttemptQueue<'_>) -> oneiron::Result<bool> {
        let mut whole = true;
        for row in queue.list()? {
            if row.kind == DELIVERY_KIND
                && row.state == AttemptState::Leased
                && row.lease_owner.as_deref() == Some(LEASE_OWNER)
            {
                whole &= self.publish_logged(&row);
            }
        }
        Ok(whole)
    }

    /// Claims every ready intent and writes its envelope. `Ok(false)` when
    /// one could not be written: it stays leased, and claiming stops.
    fn claim_ready(&self, queue: &AttemptQueue<'_>) -> oneiron::Result<bool> {
        loop {
            let claimed = queue.claim_kind(
                DELIVERY_KIND,
                ClaimAttempt {
                    lease_owner: LEASE_OWNER.to_owned(),
                    now: unix_now(),
                },
            )?;
            let ClaimOutcome::Claimed(row) = claimed else {
                return Ok(true);
            };
            if !self.publish_logged(&row) {
                return Ok(false);
            }
        }
    }

    fn publish_logged(&self, row: &AttemptRecord) -> bool {
        match self.publish(row) {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(
                    error = %format!("{error:#}"),
                    attempt = %hex(row.id.as_bytes()),
                    "esign delivery envelope not written; the next tick writes it"
                );
                false
            }
        }
    }

    /// Writes `row`'s envelope for its current lease, unless the file
    /// already holds it. A row that is not an e-sign notice with a dedupe key
    /// is left leased and unexported, never dropped.
    fn publish(&self, row: &AttemptRecord) -> anyhow::Result<()> {
        let Some(export) = export(row) else {
            tracing::warn!(
                attempt = %hex(row.id.as_bytes()),
                "esign delivery is not an e-sign notice with a dedupe key; it stays queued, unexported"
            );
            return Ok(());
        };
        let bytes = envelope_bytes(row, &export)?;
        let path = self.envelope_path(&export.stem);
        if read_if_present(&path)?.as_deref() == Some(bytes.as_slice()) {
            return Ok(());
        }
        // The sender has not seen this lease, so an ack beside it answers an
        // older one.
        remove_if_present(&self.ack_path(&export.stem))?;
        write_atomic(&self.dir, &path, &bytes)
            .with_context(|| format!("write {}", path.display()))?;
        tracing::info!(
            attempt = %hex(row.id.as_bytes()),
            stem = %export.stem,
            "esign delivery written to its outbox"
        );
        Ok(())
    }

    fn envelope_path(&self, stem: &str) -> PathBuf {
        self.dir.join(format!("{stem}{ENVELOPE_SUFFIX}"))
    }

    fn ack_path(&self, stem: &str) -> PathBuf {
        self.dir.join(format!("{stem}{ACK_SUFFIX}"))
    }
}

/// Completes the intent on an ok; on a failed ack, finalizes this try and
/// schedules the next one [`RETRY_DELAY_SECS`] later, keeping the reason.
/// Never a terminal failure.
fn settle(queue: &AttemptQueue<'_>, row: &AttemptRecord, ack: &Ack) -> oneiron::Result<()> {
    let now = unix_now();
    match ack.status {
        AckStatus::Ok => {
            queue.complete(CompleteAttempt {
                id: row.id,
                lease_owner: LEASE_OWNER.to_owned(),
                attempt_count: row.attempt_count,
                now,
            })?;
        }
        AckStatus::Failed => {
            queue.retry(RetryAttempt {
                id: row.id,
                lease_owner: LEASE_OWNER.to_owned(),
                attempt_count: row.attempt_count,
                backoff_until: now.saturating_add(RETRY_DELAY_SECS),
                last_error: ack.reason.clone(),
                now,
            })?;
        }
    }
    Ok(())
}

/// The intent `row` exports, or `None` for a row that is not an e-sign
/// notice with a dedupe key.
fn export(row: &AttemptRecord) -> Option<Export<'_>> {
    let dedupe_key = row.dedupe_key.as_deref()?;
    let text = std::str::from_utf8(&row.payload).ok()?;
    if serde_json::from_str::<EsignNotice>(text).is_err() {
        return None;
    }
    let payload: &RawValue = serde_json::from_str(text).ok()?;
    Some(Export {
        dedupe_key,
        stem: stem_of(dedupe_key),
        payload,
        payload_sha256: hex(&Sha256::digest(payload.get().as_bytes())),
    })
}

fn envelope_bytes(row: &AttemptRecord, export: &Export<'_>) -> serde_json::Result<Vec<u8>> {
    serde_json::to_vec(&Envelope {
        schema_version: SCHEMA_VERSION,
        kind: DELIVERY_KIND,
        channel: CHANNEL,
        dedupe_key: export.dedupe_key,
        attempt_id: hex(row.id.as_bytes()),
        lease_owner: LEASE_OWNER,
        attempt_count: row.attempt_count,
        leased_at: row.updated_at,
        lease_expires_at: row.updated_at.saturating_add(LEASE_SECS),
        payload_sha256: &export.payload_sha256,
        payload: export.payload,
    })
}

/// Whether `ack` echoes `row`'s lease whole: this outbox's owner, the lease
/// generation, the dedupe key its file is named by, and the payload's hash.
fn ack_binds(ack: &Ack, row: &AttemptRecord, stem: &str) -> bool {
    let Some(export) = export(row) else {
        return false;
    };
    ack.lease_owner == LEASE_OWNER
        && ack.attempt_count == row.attempt_count
        && ack.dedupe_key == export.dedupe_key
        && export.stem == stem
        && ack.payload_sha256 == export.payload_sha256
}

/// A well-formed ack and the try it names.
fn parse_ack(bytes: &[u8]) -> Option<(Ack, AttemptId)> {
    let ack: Ack = serde_json::from_slice(bytes).ok()?;
    let id = parse_attempt_id(&ack.attempt_id)?;
    let shaped = ack.schema_version == SCHEMA_VERSION
        && match ack.status {
            AckStatus::Ok => ack.reason.is_none(),
            AckStatus::Failed => ack
                .reason
                .as_deref()
                .is_some_and(|reason| !reason.is_empty()),
        };
    shaped.then_some((ack, id))
}

/// The lease an envelope on disk names.
fn parse_fence(bytes: &[u8]) -> Option<(Fence, AttemptId)> {
    let fence: Fence = serde_json::from_slice(bytes).ok()?;
    let id = parse_attempt_id(&fence.attempt_id)?;
    Some((fence, id))
}

/// The file stem of an intent: the prefix and the lower-hex BLAKE3 of
/// `esign.delivery\0` and its dedupe key.
fn stem_of(dedupe_key: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DELIVERY_KIND.as_bytes());
    hasher.update(&[0]);
    hasher.update(dedupe_key.as_bytes());
    format!("{FILE_PREFIX}{}", hasher.finalize().to_hex())
}

/// The stem and role of an outbox file's name; `None` for any other file
/// (the lock, a temporary, the sender's own).
fn parse_name(name: &str) -> Option<(String, FileRole)> {
    let rest = name.strip_prefix(FILE_PREFIX)?;
    let (key, role) = match rest.strip_suffix(ACK_SUFFIX) {
        Some(key) => (key, FileRole::Ack),
        None => (rest.strip_suffix(ENVELOPE_SUFFIX)?, FileRole::Envelope),
    };
    (key.len() == 64 && is_lower_hex(key)).then(|| (format!("{FILE_PREFIX}{key}"), role))
}

fn parse_attempt_id(text: &str) -> Option<AttemptId> {
    if text.len() != 32 || !is_lower_hex(text) {
        return None;
    }
    let bytes = (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    AttemptId::from_bytes(&bytes).ok()
}

fn is_lower_hex(text: &str) -> bool {
    text.bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn read_if_present(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn remove_if_present(path: &Path) -> io::Result<bool> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Removes `path` while it still holds `bytes`: a file its writer replaced
/// since it was read stays.
fn remove_if_unchanged(path: &Path, bytes: &[u8]) -> io::Result<bool> {
    if read_if_present(path)?.as_deref() != Some(bytes) {
        return Ok(false);
    }
    remove_if_present(path)
}

/// Writes `bytes` to `path` whole: a private temporary sibling, synced,
/// renamed over `path`, then the directory synced.
fn write_atomic(dir: &Path, path: &Path, bytes: &[u8]) -> io::Result<()> {
    let name = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or(FILE_PREFIX);
    let staged = dir.join(format!(".{name}.{:016x}.tmp", OsRng.next_u64()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let written = options
        .open(&staged)
        .and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        })
        .and_then(|()| fs::rename(&staged, path));
    if let Err(error) = written {
        let _ = fs::remove_file(&staged);
        return Err(error);
    }
    sync_dir(dir)
}

/// Syncs the directory's entries. A directory opens as a file only on unix;
/// elsewhere a rename is as durable as the system makes it.
fn sync_dir(dir: &Path) -> io::Result<()> {
    if cfg!(unix) {
        File::open(dir)?.sync_all()
    } else {
        Ok(())
    }
}

fn ensure_directory(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
