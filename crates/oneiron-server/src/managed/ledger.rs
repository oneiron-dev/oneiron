//! Managed wake ledger: entries, revision, and supervisor pushes.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use loro::{LoroValue, ValueOrContainer};
use oneiron::sync::lease::{self, LeaseStatus, ROOT_LEASES_MAP};
use oneiron_vault_contract::{
    Credentials, LedgerAck, LedgerUpdate, MAX_CTL_LINE, Schedule, TokenHex, WakeEntry, now_ts,
    validate_wake_entries,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::Mutex;

use super::args::ManagedError;
use crate::server::SyncServer;

/// Wake-ledger revision, persisted so it survives a restart and comes back as
/// `ledger_rev`.
pub const LEDGER_REV_KEY: &str = "managed:ledger_rev:v1";

/// A failing ledger push is retried exactly once, after this delay, and then
/// left behind. Exit must never block on a dead supervisor.
const LEDGER_RETRY_DELAY: Duration = Duration::from_millis(200);

/// How long one whole push attempt — connect, write, and the supervisor's ack —
/// may take before it is abandoned.
///
/// "Exactly one retry, then proceed" bounds nothing unless an attempt is itself
/// bounded, and none of those three steps is bounded on its own. A supervisor
/// that accepted the connection and then went quiet is indistinguishable from a
/// live one that is about to answer, so this is the width of that doubt: long
/// enough that a loaded-but-live supervisor still gets its ack in, short enough
/// that two attempts and one backoff stay well inside a shutdown grace.
const LEDGER_PUSH_TIMEOUT: Duration = Duration::from_secs(2);

/// Lease expiry is swept on a cadence rather than at an instant, so the wake
/// it asks for is a window of that width, not a point. Waking anywhere inside
/// it does the same work.
const LEASE_WAKE_WINDOW_SECS: u64 = 60;

/// How long a sync session that upgraded but has not spoken yet is assumed to
/// still be there.
///
/// Such a session holds nothing this module can count: it subscribes to the
/// broadcast fan-out only after its protocol hello, and the handler's own
/// hello deadline is what closes it if the hello never comes. This is that
/// deadline with margin, because a freeze would rather delay a reap by a few
/// seconds than report quiescence over a writer it cannot see.
pub(super) const SYNC_UPGRADE_SETTLE_SECS: u64 = 15;

/// Stable ids for the exported wake entries. The supervisor keys on these.
const WAKE_ID_JOB_READY: &str = "job_ready";

const WAKE_ID_SYNC_DEADLINE: &str = "sync_deadline";

/// The vault's wake ledger: what the engine wants to be woken for, and when.
///
/// Two delivery paths over the same entries. The pull path rides the
/// `prepare_reap` reply; the push path is a `ledger_update` on the
/// supervisor's socket, sent when the entries change. The revision persists in
/// the vault so a restart resumes the supervisor's ordering rather than
/// replaying it from zero.
pub struct WakeLedger {
    vault: Arc<oneiron::Vault>,
    vault_name: String,
    hypnos_socket: PathBuf,
    token: TokenHex,
    rev: AtomicU64,
    last_exported: Mutex<Option<Vec<WakeEntry>>>,
}

impl std::fmt::Debug for WakeLedger {
    /// Manual, and deliberately not derived: the spawn token must never reach
    /// a diagnostic. `TokenHex` redacts itself, and this impl keeps that true
    /// even if the field type ever changes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WakeLedger")
            .field("vault_name", &self.vault_name)
            .field("hypnos_socket", &self.hypnos_socket)
            .field("token", &"<redacted>")
            .field("rev", &self.rev.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl WakeLedger {
    /// Loads the persisted revision and binds the ledger to a vault, a
    /// supervisor socket and the spawn token that authenticates pushes.
    pub fn load(
        vault: Arc<oneiron::Vault>,
        vault_name: String,
        hypnos_socket: PathBuf,
        credentials: &Credentials,
    ) -> Result<Self, ManagedError> {
        let rev = read_persisted_rev(&vault)?;
        Ok(Self {
            vault,
            vault_name,
            hypnos_socket,
            token: TokenHex::from_token(&credentials.token),
            rev: AtomicU64::new(rev),
            last_exported: Mutex::new(None),
        })
    }

    pub fn rev(&self) -> u64 {
        self.rev.load(Ordering::SeqCst)
    }

    /// Builds the current wake entries from the engine's own state: the
    /// job-ready head probe and the sync deadline.
    ///
    /// No timer is consulted and none is armed — the engine only reports what
    /// it would want; firing is the supervisor's job.
    pub fn export(&self, server: &SyncServer) -> Result<Vec<WakeEntry>, ManagedError> {
        let mut entries = Vec::new();
        if let Some(entry) = job_ready_head(&self.vault)? {
            entries.push(entry);
        }
        if let Some(entry) = sync_deadline(server) {
            entries.push(entry);
        }
        validate_wake_entries(&entries).map_err(|error| ManagedError::LedgerRefused {
            reason: error.to_string(),
        })?;
        Ok(entries)
    }

    /// Export-at-freeze for the pull path: refreshes the entries and, when
    /// they changed, advances and persists the revision so the `ledger_rev`
    /// the supervisor sees keeps moving forward across restarts.
    pub async fn export_at_freeze(
        &self,
        server: &SyncServer,
    ) -> Result<(u64, Vec<WakeEntry>), ManagedError> {
        let entries = self.export(server)?;
        let mut last = self.last_exported.lock().await;
        if last.as_ref() != Some(&entries) {
            self.advance_rev()?;
            *last = Some(entries.clone());
        }
        Ok((self.rev(), entries))
    }

    /// Push-on-change: sends a `ledger_update` only when the entries actually
    /// moved, so a quiet vault costs the supervisor nothing.
    ///
    /// Returns whether a push was both needed and accepted.
    pub async fn push_if_changed(&self, server: &SyncServer) -> Result<bool, ManagedError> {
        let entries = self.export(server)?;
        let mut last = self.last_exported.lock().await;
        if last.as_ref() == Some(&entries) {
            return Ok(false);
        }
        let rev = self.advance_rev()?;
        let accepted = self.push_with_retry(rev, &entries).await;
        if accepted {
            *last = Some(entries);
        }
        Ok(accepted)
    }

    /// One push attempt: validate, frame, send, await the ack — the whole
    /// attempt under a deadline.
    ///
    /// The deadline covers the attempt rather than the ack alone because all
    /// three of connect, write and read are unbounded against a supervisor that
    /// is connected and silent, and any one of them parking is the same
    /// outcome: this process never comes back. Both callers are on paths that
    /// must not stall — the opening push happens after the ready byte and
    /// before the HTTP serve, and the final one is the last thing before exit —
    /// and `push_with_retry`'s "one retry, then proceed" only bounds them if an
    /// attempt is itself bounded. Timing out is a typed refusal like any other
    /// push failure, so the retry policy above is unchanged by it.
    pub async fn push_once(&self, rev: u64, entries: &[WakeEntry]) -> Result<(), ManagedError> {
        match tokio::time::timeout(LEDGER_PUSH_TIMEOUT, self.push_attempt(rev, entries)).await {
            Ok(result) => result,
            Err(_elapsed) => Err(ManagedError::LedgerAckTimeout {
                after: LEDGER_PUSH_TIMEOUT,
            }),
        }
    }

    /// The attempt itself, with no deadline of its own: [`Self::push_once`] is
    /// the only caller and it is what bounds this.
    async fn push_attempt(&self, rev: u64, entries: &[WakeEntry]) -> Result<(), ManagedError> {
        let update = LedgerUpdate {
            op: "ledger_update".to_owned(),
            vault: self.vault_name.clone(),
            token: self.token.clone(),
            rev,
            entries: entries.to_vec(),
        };
        // Validate before sending, not after: an update this side would refuse
        // to receive is one this side must refuse to emit.
        update
            .validate()
            .map_err(|error| ManagedError::LedgerRefused {
                reason: error.to_string(),
            })?;
        let line = serde_json::to_string(&update).map_err(|error| ManagedError::LedgerRefused {
            reason: error.to_string(),
        })?;
        if line.len() > MAX_CTL_LINE {
            return Err(ManagedError::CtlLineTooLong {
                len: line.len(),
                cap: MAX_CTL_LINE,
            });
        }

        let stream = UnixStream::connect(&self.hypnos_socket).await?;
        let (reader, mut writer) = stream.into_split();
        writer.write_all(line.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;

        let mut reader = BufReader::new(reader.take(MAX_CTL_LINE as u64 + 2));
        let mut ack_line = String::new();
        reader.read_line(&mut ack_line).await?;
        let ack: LedgerAck = serde_json::from_str(ack_line.trim_end_matches(['\r', '\n']))
            .map_err(|error| ManagedError::LedgerRefused {
                reason: error.to_string(),
            })?;
        if ack.ok {
            Ok(())
        } else {
            Err(ManagedError::LedgerRefused {
                reason: ack
                    .error
                    .unwrap_or_else(|| "supervisor rejected the ledger update".to_owned()),
            })
        }
    }

    /// Retry discipline: exactly one retry, after 200 ms, then log and
    /// proceed. Shutdown must never be held open by a supervisor that is not
    /// answering.
    pub async fn push_with_retry(&self, rev: u64, entries: &[WakeEntry]) -> bool {
        match self.push_once(rev, entries).await {
            Ok(()) => return true,
            Err(error) => {
                tracing::warn!(%error, "wake ledger push failed; retrying once");
            }
        }
        tokio::time::sleep(LEDGER_RETRY_DELAY).await;
        match self.push_once(rev, entries).await {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "wake ledger push retry failed; proceeding without the supervisor"
                );
                false
            }
        }
    }

    fn advance_rev(&self) -> Result<u64, ManagedError> {
        let rev = self.rev.fetch_add(1, Ordering::SeqCst).saturating_add(1);
        self.vault
            .sync_state_put(LEDGER_REV_KEY, &rev.to_le_bytes())
            .map_err(|error| ManagedError::VaultMeta(error.to_string()))?;
        Ok(rev)
    }
}

fn read_persisted_rev(vault: &oneiron::Vault) -> Result<u64, ManagedError> {
    let Some(raw) = vault
        .sync_state_get(LEDGER_REV_KEY)
        .map_err(|error| ManagedError::VaultMeta(error.to_string()))?
    else {
        return Ok(0);
    };
    let len = raw.len();
    let bytes: [u8; 8] = raw.try_into().map_err(|_| {
        ManagedError::VaultMeta(format!("`{LEDGER_REV_KEY}` row is {len} bytes, expected 8"))
    })?;
    Ok(u64::from_le_bytes(bytes))
}

/// job_ready head probe: any durable row in the vault's sync queue means there
/// is work waiting, and the head of it is due now.
fn job_ready_head(vault: &Arc<oneiron::Vault>) -> Result<Option<WakeEntry>, ManagedError> {
    let queue = oneiron::sync::SyncQueue::new(Arc::clone(vault))
        .map_err(|error| ManagedError::VaultMeta(error.to_string()))?;
    let empty = queue
        .is_empty()
        .map_err(|error| ManagedError::VaultMeta(error.to_string()))?;
    if empty {
        return Ok(None);
    }
    Ok(Some(WakeEntry {
        id: WAKE_ID_JOB_READY.to_owned(),
        at: Schedule::Exact { at: now_ts() },
        reason_tag: WAKE_ID_JOB_READY.to_owned(),
    }))
}

/// Sync deadline: the earliest active device lease expiry. That is the next
/// moment the engine must be running to do durable work nobody else will do.
fn sync_deadline(server: &SyncServer) -> Option<WakeEntry> {
    let leases = server.root_doc.get_map(ROOT_LEASES_MAP);
    let mut earliest: Option<u64> = None;
    leases.for_each(|_key, value| {
        if let ValueOrContainer::Value(LoroValue::Binary(raw)) = value
            && let Ok(record) = lease::decode_lease_record(&raw)
            && record.status == LeaseStatus::Active
        {
            earliest =
                Some(earliest.map_or(record.expires_at, |seen: u64| seen.min(record.expires_at)));
        }
    });
    earliest.map(|at| WakeEntry {
        id: WAKE_ID_SYNC_DEADLINE.to_owned(),
        at: Schedule::Window {
            start: at,
            end: at.saturating_add(LEASE_WAKE_WINDOW_SECS),
        },
        reason_tag: "lease_expiry".to_owned(),
    })
}
