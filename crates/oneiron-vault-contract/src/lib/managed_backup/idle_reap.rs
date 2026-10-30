//! The answer to an idle reap's preparation (`prepare_idle_reap`, Engine
//! 10-20 backup shipper row (a), co-signed with LC): the reap freeze's report
//! as `prepare_reap` gives it, and the one backup the vault took or reused
//! before it, or why it has none.
//!
//! A vault runs one preparation attempt, which every call joins until a
//! `reap_abort` drops it. Its backup has [`IDLE_REAP_PREPARATION_SECS`] from
//! the attempt's first call. Past them the attempt answers `failed`, and a
//! backup still being written then is never recorded as covered: the vault
//! reads as changed until a later backup lands. `quiescent` is the vault's
//! writer quiescence as `prepare_reap` reports it, a backup still being
//! written included; a deadline never makes it true.
//!
//! Every answer carries the writes in flight when the attempt froze the
//! vault, by kind (FIX 6902): one at the freeze, the same on every call.
//! An owner write among them answers `writers_busy`; background passes are
//! waited for until the deadline before the vault is judged quiet.
//!
//! Coverage is opaque: a supervisor compares two for equality and never
//! orders their fields.

use serde::{Deserialize, Serialize};

use super::lower_hex_of;
use crate::LedgerReportHead;

/// The one [`IdleReapWire`] schema this crate reads.
pub const IDLE_REAP_SCHEMA_VERSION: u32 = 1;

/// How long an idle preparation's backup has, in seconds, from its attempt's
/// first call. A supervisor's own call waits longer than this.
pub const IDLE_REAP_PREPARATION_SECS: u64 = 30;

/// An attempt id's length in bytes.
const ATTEMPT_ID_LEN: usize = 16;
/// A commitment digest's length in bytes.
const ARTIFACT_ID_LEN: usize = 32;
/// A backup incarnation's length in bytes.
const INCARNATION_LEN: usize = 16;

/// The answer to [`CtlRequest::PrepareIdleReap`](crate::CtlRequest::PrepareIdleReap).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdleReapWire {
    /// [`IDLE_REAP_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Whether the vault is quiescent: frozen, with no admitted write and no
    /// backup in flight, its lease table drained, and no sync session that
    /// could still commit.
    pub quiescent: bool,
    /// The admitted writes in flight when the attempt froze the vault, by
    /// kind: the same on every call that joins it.
    pub in_flight_at_freeze: IdleReapInFlight,
    /// The wake ledger report the freeze holds, as `PrepareReap.ledger`: its
    /// entries and training setting are read with `ledger_page` (FIX 9549),
    /// the same report on every call that joins the attempt.
    pub ledger: LedgerReportHead,
    /// The backup taken or reused before the reap, or why there is none.
    pub backup: IdleBackupWire,
}

/// The admitted writes in flight when an idle reap's preparation froze the
/// vault, counted by kind; each count is a number of admissions, never what
/// they write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdleReapInFlight {
    /// The owner's foreground work: served requests other than reads, a
    /// held MCP socket's receipts, voice calls and live voice sessions,
    /// relay deletes, mutating ctl requests and agent runs. A device sync
    /// run is not counted here: it pauses for the freeze, and `quiescent`
    /// waits for its end (FIX 5127).
    pub owner_write: u64,
    /// Tagging passes.
    pub background_tagging: u64,
    /// Dreamer passes, and the home timer, drafts and fallback timers its
    /// gate admits.
    pub dreamer: u64,
    /// Every other background pass, scheduled backups among them, and
    /// backups before an idle reap still running.
    pub other: u64,
}

/// Where the backup before an idle reap stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdleBackupWire {
    pub state: IdleBackupState,
    /// The preparation attempt, as 32 lowercase hex digits: the same on
    /// every call that joins it.
    pub attempt_id: String,
    /// The backup's commitment digest, as 64 lowercase hex digits: set when
    /// taken or reused, `null` otherwise.
    pub artifact_id: Option<String>,
    /// What the backup covers: set when taken or reused, `null` otherwise.
    pub coverage: Option<BackupCoverageWire>,
    /// Why there is no backup: set when failed, `null` otherwise.
    pub reason: Option<IdleBackupFailure>,
    /// Whether a later attempt may succeed with nothing repaired first:
    /// `false` unless failed.
    pub retryable: bool,
}

/// The state of the backup before an idle reap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdleBackupState {
    /// Still being prepared.
    Pending,
    /// A new backup covers the vault as it stands.
    Taken,
    /// The vault's last backup already covers it as it stands.
    Reused,
    /// No backup covers it: [`IdleBackupWire::reason`] says why.
    Failed,
}

/// What a backup covers, from the vault's backup watermark: its incarnation
/// as 32 lowercase hex digits, and its LMDB transaction id and custody log
/// epoch and sequence, each a u64 as a decimal string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupCoverageWire {
    pub incarnation: String,
    pub db_txn: String,
    pub custody_epoch: String,
    pub custody_seq: String,
}

/// Why no backup covers the vault before an idle reap, in closed names:
/// never a path or an error's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdleBackupFailure {
    /// An owner write or a sync session was in flight when the vault froze:
    /// it is not idle, and no backup was started.
    WritersBusy,
    /// Another backup held the backup lock until the deadline, or was in
    /// flight when the deadline cut short the wait for background passes.
    BackupBusy,
    /// The disk's free-space floor refused the backup's room.
    DiskFloor,
    /// A disk refused a write for want of room.
    DiskFull,
    /// The vault's backup watermark did not read. This build takes a backup
    /// instead, so never sends it.
    WatermarkUnavailable,
    /// The keystore, or the checkpoint signer it holds, did not read.
    SignerUnavailable,
    /// The snapshot failed, and nothing landed.
    SnapshotFailed,
    /// The backup was written and did not land, or what it covered was not
    /// recorded beside it.
    PublishFailed,
    /// The backup's worker stopped without an answer.
    WorkerFailed,
    /// The deadline passed while the backup was being prepared or written,
    /// or while background passes were waited for.
    DeadlineExceeded,
}

impl IdleBackupFailure {
    /// The wire spelling, for a log field.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WritersBusy => "writers_busy",
            Self::BackupBusy => "backup_busy",
            Self::DiskFloor => "disk_floor",
            Self::DiskFull => "disk_full",
            Self::WatermarkUnavailable => "watermark_unavailable",
            Self::SignerUnavailable => "signer_unavailable",
            Self::SnapshotFailed => "snapshot_failed",
            Self::PublishFailed => "publish_failed",
            Self::WorkerFailed => "worker_failed",
            Self::DeadlineExceeded => "deadline_exceeded",
        }
    }

    /// Whether a later attempt may succeed with nothing repaired first:
    /// every reason but a signer that does not read.
    #[must_use]
    pub const fn retryable(self) -> bool {
        !matches!(self, Self::SignerUnavailable)
    }
}

impl IdleReapWire {
    /// Shape check after parsing: the schema, the ledger report's head, and
    /// the backup's fields as its state requires them.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.schema_version == IDLE_REAP_SCHEMA_VERSION,
            "unrecognized idle_reap schema_version"
        );
        self.ledger.validate()?;
        self.backup.validate()
    }
}

impl IdleBackupWire {
    /// Shape check: the attempt id, and per state the fields it sets and
    /// leaves `null`. Taken and reused carry an artifact and its coverage
    /// and no reason; pending carries none of them; failed carries a reason
    /// and no artifact or coverage. Only failed may be retryable.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            lower_hex_of(&self.attempt_id, ATTEMPT_ID_LEN),
            "attempt_id is 32 lowercase hex digits"
        );
        match self.state {
            IdleBackupState::Taken | IdleBackupState::Reused => {
                let (Some(artifact), Some(coverage)) = (&self.artifact_id, &self.coverage) else {
                    anyhow::bail!("a taken or reused backup names its artifact and coverage");
                };
                anyhow::ensure!(
                    lower_hex_of(artifact, ARTIFACT_ID_LEN),
                    "artifact_id is 64 lowercase hex digits"
                );
                coverage.validate()?;
                anyhow::ensure!(
                    self.reason.is_none() && !self.retryable,
                    "a taken or reused backup has no reason and is not retryable"
                );
            }
            IdleBackupState::Pending => anyhow::ensure!(
                self.artifact_id.is_none()
                    && self.coverage.is_none()
                    && self.reason.is_none()
                    && !self.retryable,
                "a pending backup names no artifact, coverage or reason"
            ),
            IdleBackupState::Failed => anyhow::ensure!(
                self.artifact_id.is_none() && self.coverage.is_none() && self.reason.is_some(),
                "a failed backup names a reason and no artifact or coverage"
            ),
        }
        Ok(())
    }
}

impl BackupCoverageWire {
    /// Shape check: the incarnation's hex and each u64's decimal spelling.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            lower_hex_of(&self.incarnation, INCARNATION_LEN),
            "coverage.incarnation is 32 lowercase hex digits"
        );
        anyhow::ensure!(
            [&self.db_txn, &self.custody_epoch, &self.custody_seq]
                .into_iter()
                .all(|text| u64_decimal(text.as_str())),
            "coverage's db_txn, custody_epoch and custody_seq are u64 decimal strings"
        );
        Ok(())
    }
}

/// Whether `text` is a whole number in decimal, with no sign or leading
/// zero, that a u64 holds.
fn u64_decimal(text: &str) -> bool {
    text == "0"
        || (!text.starts_with('0')
            && text.bytes().all(|byte| byte.is_ascii_digit())
            && text.parse::<u64>().is_ok())
}
