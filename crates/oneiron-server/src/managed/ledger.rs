//! Managed wake ledger: entries, revision, and supervisor pushes.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use loro::{LoroValue, ValueOrContainer};
use oneiron::sync::lease::{self, LeaseStatus, ROOT_LEASES_MAP};
use oneiron_vault_contract::{
    Credentials, LedgerAck, LedgerPage, LedgerPageRequest, LedgerPulledRequest, LedgerReportHead,
    LedgerUpdate, MAX_CTL_LINE, ManagedTrainingSetting, Schedule, TokenHex, WakeEntry, now_ts,
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

/// How long one step of a push attempt — the connect, or one page's write and
/// the supervisor's ack of it — may take before the attempt is abandoned.
///
/// "Exactly one retry, then proceed" bounds nothing unless an attempt is itself
/// bounded, and none of those steps is bounded on its own. A supervisor that
/// accepted the connection and then went quiet is indistinguishable from a
/// live one that is about to answer, so this is the width of that doubt: long
/// enough that a loaded-but-live supervisor still gets its ack in, short enough
/// that two attempts and one backoff stay well inside a shutdown grace. It
/// bounds each page, never the whole report (FIX 9549): a supervisor that
/// keeps answering takes a report of any size.
const LEDGER_PUSH_TIMEOUT: Duration = Duration::from_secs(2);

/// Lease expiry is swept on a cadence rather than at an instant, so the wake
/// it asks for is a window of that width, not a point. Waking anywhere inside
/// it does the same work.
const LEASE_WAKE_WINDOW_SECS: u64 = 60;

/// How often the running vault reads its schedule again for a move to push
/// (FIX 7746): a lease, the sync queue and a noted deadline move with no
/// signal of their own. Half the lease wake window, so a move reaches the
/// supervisor well inside the window it asks for.
pub(super) const LEDGER_SCHEDULE_POLL: Duration = Duration::from_secs(30);

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

const WAKE_ID_HOUSEKEEPING: &str = "housekeeping";

/// The vault's wake ledger: what the engine wants to be woken for, and when,
/// reported with the vault's live training setting.
///
/// Two delivery paths over the same report ([`LedgerSnapshot`]), both in
/// bounded pages (FIX 9549). The pull path is the report a freeze holds,
/// which the `prepare_reap` reply names and `ledger_page` reads; the push
/// path is a `ledger_update` page sequence on the supervisor's socket, sent
/// when the report changes. The revision persists in the vault so a restart
/// resumes the supervisor's ordering rather than replaying it from zero.
pub struct WakeLedger {
    vault: Arc<oneiron::Vault>,
    vault_name: String,
    hypnos_socket: PathBuf,
    token: TokenHex,
    rev: AtomicU64,
    /// What the supervisor took and what a freeze holds for it. Its lock is
    /// held from reading a report to assigning it a revision, so no older
    /// report ever goes out under a newer revision.
    exported: Mutex<Exported>,
}

/// The reports [`WakeLedger::exported`] keeps.
#[derive(Default)]
struct Exported {
    /// The last report the supervisor took: a push it committed, or a frozen
    /// report it said it holds (`ledger_pulled`).
    taken: Option<LedgerSnapshot>,
    /// The report the last freeze holds for its pull, until `ledger_pulled`
    /// takes it or `reap_abort` drops it (FIX 9549). A closed reply never
    /// drops it.
    frozen: Option<FrozenReport>,
}

/// A report a freeze holds for its pull: its head, which `prepare_reap`
/// names, and what it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenReport {
    pub head: LedgerReportHead,
    pub snapshot: LedgerSnapshot,
}

/// One ledger report: the wake entries and the vault's live training setting
/// (FIX 5575). Compared whole, so a move in either, the setting's revision or
/// who set it alone included, is a new report under a new revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerSnapshot {
    pub entries: Vec<WakeEntry>,
    pub training: ManagedTrainingSetting,
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
            exported: Mutex::new(Exported::default()),
        })
    }

    pub(super) fn verify_widen_action(
        &self,
        action: &oneiron_vault_contract::ManagedWidenAction,
        body: &[u8],
    ) -> bool {
        action.verify(&self.token, &self.vault_name, body)
    }

    pub(super) fn verify_owner_action(
        &self,
        action: &oneiron_vault_contract::ManagedOwnerAction,
        request: &oneiron_vault_contract::ManagedOwnerRequest<'_>,
    ) -> bool {
        action.verify(&self.token, &self.vault_name, request)
    }

    /// Proves this vault's owner signing on the supervisor's `challenge`
    /// (FIX 5260): the spawn token goes to the supervisor socket this ledger
    /// pushes to, and nowhere else. Whether the supervisor acked.
    pub(super) async fn prove_owner_signing(&self, challenge: &str) -> anyhow::Result<bool> {
        super::owner_recovery::prove(
            &self.hypnos_socket,
            &self.vault_name,
            &self.token,
            challenge,
        )
        .await
    }

    /// The transcript `holder_ref`'s owner action covers on this vault, for
    /// a request with `head` whose body is `body_len` bytes, fed in pieces
    /// and checked by `ManagedOwnerAction::verify_transcript`.
    pub(super) fn owner_transcript(
        &self,
        holder_ref: &str,
        head: &oneiron_vault_contract::ManagedOwnerHead<'_>,
        body_len: u64,
    ) -> oneiron_vault_contract::ManagedOwnerTranscript {
        oneiron_vault_contract::ManagedOwnerTranscript::new(
            &self.token,
            &self.vault_name,
            holder_ref,
            head,
            body_len,
        )
    }

    pub fn rev(&self) -> u64 {
        self.rev.load(Ordering::SeqCst)
    }

    /// Builds the current wake entries from the engine's own state: the
    /// job-ready head probe, the sync deadline and the housekeeping deadline.
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
        if let Some(entry) = housekeeping_deadline(&self.vault)? {
            entries.push(entry);
        }
        validate_wake_entries(&entries).map_err(|error| ManagedError::LedgerRefused {
            reason: error.to_string(),
        })?;
        Ok(entries)
    }

    /// The vault's live training setting, as its supervisor keeps it: the
    /// four fields of the vault's own read, never the member-facing line.
    /// `set_by` stays null when the vault does not hold the act's row; it is
    /// never filled with the vault's owner.
    pub fn training(&self) -> Result<ManagedTrainingSetting, ManagedError> {
        let view = self
            .vault
            .conversation_learning_status()
            .map_err(|error| ManagedError::VaultMeta(error.to_string()))?;
        Ok(ManagedTrainingSetting {
            on: view.on,
            allow_opt_out: view.allow_opt_out,
            revision: oneiron_vault_contract::hex(&view.revision.0),
            set_by: view.set_by.as_ref().map(oneiron::EntityId::to_hex),
        })
    }

    /// The report as it stands: [`Self::export`]'s entries and
    /// [`Self::training`].
    pub fn snapshot(&self, server: &SyncServer) -> Result<LedgerSnapshot, ManagedError> {
        Ok(LedgerSnapshot {
            entries: self.export(server)?,
            training: self.training()?,
        })
    }

    /// Export-at-freeze for the pull path: refreshes the report and, when it
    /// changed, advances and persists the revision so the revision the
    /// supervisor sees keeps moving forward across restarts. The report is
    /// held whole for its pages until `ledger_pulled` or `reap_abort`; a
    /// freeze that finds it unchanged holds the same one.
    pub async fn export_at_freeze(
        &self,
        server: &SyncServer,
    ) -> Result<FrozenReport, ManagedError> {
        let mut exported = self.exported.lock().await;
        let snapshot = self.snapshot(server)?;
        if let Some(frozen) = exported
            .frozen
            .as_ref()
            .filter(|frozen| frozen.snapshot == snapshot)
        {
            return Ok(frozen.clone());
        }
        let rev = if exported.taken.as_ref() == Some(&snapshot) {
            self.rev()
        } else {
            self.advance_rev()?
        };
        let frozen = FrozenReport {
            head: LedgerReportHead::of(
                &self.vault_name,
                rev,
                &snapshot.entries,
                &snapshot.training,
            ),
            snapshot,
        };
        exported.frozen = Some(frozen.clone());
        Ok(frozen)
    }

    /// One page of the report the freeze holds (`ledger_page`, FIX 9549),
    /// for a request that carries this vault's name and spawn token and
    /// names that report.
    pub(super) async fn frozen_page(
        &self,
        request: &LedgerPageRequest,
    ) -> Result<LedgerPage, ManagedError> {
        self.authenticate(&request.vault, &request.token)?;
        let exported = self.exported.lock().await;
        let frozen = frozen_named(&exported, request.rev, &request.report_digest)?;
        frozen
            .head
            .page(
                &frozen.snapshot.entries,
                &frozen.snapshot.training,
                request.offset,
            )
            .map_err(|error| ManagedError::CtlRequestRefused {
                reason: error.to_string(),
            })
    }

    /// The supervisor holds the frozen report durably (`ledger_pulled`): it
    /// is the report the supervisor took, and the freeze holds it no longer.
    pub(super) async fn pulled(&self, request: &LedgerPulledRequest) -> Result<(), ManagedError> {
        self.authenticate(&request.vault, &request.token)?;
        let mut exported = self.exported.lock().await;
        frozen_named(&exported, request.rev, &request.report_digest)?;
        exported.taken = exported.frozen.take().map(|frozen| frozen.snapshot);
        Ok(())
    }

    /// Drops the report the freeze holds: the reap was aborted.
    pub(super) async fn drop_frozen(&self) {
        self.exported.lock().await.frozen = None;
    }

    /// Refuses a pull request that does not carry this vault's name and
    /// spawn token.
    fn authenticate(&self, vault: &str, token: &TokenHex) -> Result<(), ManagedError> {
        if vault == self.vault_name && token.ct_eq(&self.token) {
            return Ok(());
        }
        Err(ManagedError::CtlRequestRefused {
            reason: "foreign ledger pull".to_owned(),
        })
    }

    /// Push-on-change: sends a `ledger_update` only when the report actually
    /// moved, so a quiet vault costs the supervisor nothing.
    ///
    /// Returns whether a push was both needed and accepted.
    pub async fn push_if_changed(&self, server: &SyncServer) -> Result<bool, ManagedError> {
        let mut exported = self.exported.lock().await;
        let snapshot = self.snapshot(server)?;
        if exported.taken.as_ref() == Some(&snapshot) {
            return Ok(false);
        }
        self.push_report(&mut exported.taken, snapshot).await
    }

    /// Push-on-change while the vault runs (FIX 7746): sends the whole report
    /// when the training setting or the schedule moved from the last report
    /// the supervisor took, or when it took none. The job-ready head is due
    /// now whenever it is there, so only its presence is a schedule move: its
    /// time is the read's own clock.
    ///
    /// Returns whether a push was both needed and accepted.
    pub async fn push_live_if_changed(&self, server: &SyncServer) -> Result<bool, ManagedError> {
        let mut exported = self.exported.lock().await;
        let snapshot = self.snapshot(server)?;
        if exported
            .taken
            .as_ref()
            .is_some_and(|reported| same_schedule(reported, &snapshot))
        {
            return Ok(false);
        }
        self.push_report(&mut exported.taken, snapshot).await
    }

    /// Advances the revision and pushes `snapshot` under it, with `last`
    /// held. A refused push leaves `last` as it was, so the same change goes
    /// out again on the next send.
    async fn push_report(
        &self,
        last: &mut Option<LedgerSnapshot>,
        snapshot: LedgerSnapshot,
    ) -> Result<bool, ManagedError> {
        let rev = self.advance_rev()?;
        let accepted = self.push_with_retry(rev, &snapshot).await;
        if accepted {
            *last = Some(snapshot);
        }
        Ok(accepted)
    }

    /// One push attempt: the report's pages in order on one connection, each
    /// validated, framed, sent and acked before the next, and the last acked
    /// committed (FIX 9549). The connect and each page's exchange run under
    /// [`LEDGER_PUSH_TIMEOUT`].
    ///
    /// Each step is bounded because connect, write and read are all unbounded
    /// against a supervisor that is connected and silent, and any one of them
    /// parking is the same outcome: this process never comes back. Both
    /// callers are on paths that must not stall — the opening push happens
    /// after the ready byte and before the HTTP serve, and the final one is the
    /// last thing before exit — and `push_with_retry`'s "one retry, then
    /// proceed" only bounds them if an attempt's steps are bounded. The bound
    /// is per page, so a supervisor that keeps answering takes every page.
    /// Timing out is a typed refusal like any other push failure, so the retry
    /// policy above is unchanged by it.
    pub async fn push_once(&self, rev: u64, snapshot: &LedgerSnapshot) -> Result<(), ManagedError> {
        let head =
            LedgerReportHead::of(&self.vault_name, rev, &snapshot.entries, &snapshot.training);
        let stream = bounded(async {
            Ok::<_, ManagedError>(UnixStream::connect(&self.hypnos_socket).await?)
        })
        .await?;
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        for offset in head.offsets() {
            let page = head
                .page(&snapshot.entries, &snapshot.training, offset)
                .map_err(|error| ManagedError::LedgerRefused {
                    reason: error.to_string(),
                })?;
            let last = offset + page.entries.len() as u64 >= head.total;
            let update = LedgerUpdate {
                op: "ledger_update".to_owned(),
                vault: self.vault_name.clone(),
                token: self.token.clone(),
                page,
            };
            let ack = bounded(push_page(&mut reader, &mut writer, &update)).await?;
            // A page's receipt names its report and offset; only the last
            // page's ack may, and must, say the report is committed.
            if ack.report.as_ref() != Some(&head)
                || ack.offset != Some(offset)
                || ack.committed != last
            {
                return Err(ManagedError::LedgerRefused {
                    reason: "the supervisor answered another ledger page".to_owned(),
                });
            }
        }
        Ok(())
    }

    /// Retry discipline: exactly one retry, after 200 ms, then log and
    /// proceed. Shutdown must never be held open by a supervisor that is not
    /// answering.
    pub async fn push_with_retry(&self, rev: u64, snapshot: &LedgerSnapshot) -> bool {
        match self.push_once(rev, snapshot).await {
            Ok(()) => return true,
            Err(_) => {
                tracing::warn!(
                    reason = "ledger_push_failed",
                    "wake ledger push failed; retrying once"
                );
            }
        }
        tokio::time::sleep(LEDGER_RETRY_DELAY).await;
        match self.push_once(rev, snapshot).await {
            Ok(()) => true,
            Err(_) => {
                tracing::warn!(
                    reason = "ledger_push_failed",
                    "wake ledger push retry failed; proceeding without the supervisor"
                );
                false
            }
        }
    }

    /// The next revision, kept as telemetry, which moves no backup
    /// watermark (FIX 6730).
    fn advance_rev(&self) -> Result<u64, ManagedError> {
        let rev = self.rev.fetch_add(1, Ordering::SeqCst).saturating_add(1);
        self.vault
            .sync_state_put_telemetry_batch(&[(LEDGER_REV_KEY, &rev.to_le_bytes())])
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

/// Whether `now` holds the training setting and the schedule `reported`
/// held: the same entries, the job-ready head's time apart.
fn same_schedule(reported: &LedgerSnapshot, now: &LedgerSnapshot) -> bool {
    let schedule = |snapshot: &LedgerSnapshot| -> Vec<WakeEntry> {
        let mut entries = snapshot.entries.clone();
        for entry in &mut entries {
            if entry.id == WAKE_ID_JOB_READY {
                entry.at = Schedule::Exact { at: 0 };
            }
        }
        entries
    };
    reported.training == now.training && schedule(reported) == schedule(now)
}

/// The frozen report `exported` holds when it is the one `rev` and
/// `report_digest` name.
fn frozen_named<'a>(
    exported: &'a Exported,
    rev: u64,
    report_digest: &str,
) -> Result<&'a FrozenReport, ManagedError> {
    exported
        .frozen
        .as_ref()
        .filter(|frozen| frozen.head.rev == rev && frozen.head.report_digest == report_digest)
        .ok_or_else(|| ManagedError::CtlRequestRefused {
            reason: "no frozen ledger report has that revision and digest".to_owned(),
        })
}

/// `step` under [`LEDGER_PUSH_TIMEOUT`]; running past it is a typed refusal.
async fn bounded<T>(
    step: impl std::future::Future<Output = Result<T, ManagedError>>,
) -> Result<T, ManagedError> {
    tokio::time::timeout(LEDGER_PUSH_TIMEOUT, step)
        .await
        .unwrap_or(Err(ManagedError::LedgerAckTimeout {
            after: LEDGER_PUSH_TIMEOUT,
        }))
}

/// One page: validated, framed and sent, then its ack read and checked ok.
async fn push_page(
    reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    update: &LedgerUpdate,
) -> Result<LedgerAck, ManagedError> {
    // Validate before sending, not after: an update this side would refuse
    // to receive is one this side must refuse to emit.
    update
        .validate()
        .map_err(|error| ManagedError::LedgerRefused {
            reason: error.to_string(),
        })?;
    let line = serde_json::to_string(update).map_err(|error| ManagedError::LedgerRefused {
        reason: error.to_string(),
    })?;
    if line.len() > MAX_CTL_LINE {
        return Err(ManagedError::CtlLineTooLong {
            len: line.len(),
            cap: MAX_CTL_LINE,
        });
    }
    writer.write_all(line.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    let mut ack_line = String::new();
    reader
        .take(MAX_CTL_LINE as u64 + 2)
        .read_line(&mut ack_line)
        .await?;
    let ack: LedgerAck =
        serde_json::from_str(ack_line.trim_end_matches(['\r', '\n'])).map_err(|error| {
            ManagedError::LedgerRefused {
                reason: error.to_string(),
            }
        })?;
    if !ack.ok {
        return Err(ManagedError::LedgerRefused {
            reason: ack
                .error
                .unwrap_or_else(|| "supervisor rejected the ledger update".to_owned()),
        });
    }
    Ok(ack)
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

/// Housekeeping deadline: the next moment a retirement the engine owes comes
/// due (a secret lease's expiry, a voice print's retention deadline, a critical
/// confirm's window, a waiting erasure). Exact, because the retirement is due
/// then, not somewhere in a window after it.
fn housekeeping_deadline(vault: &oneiron::Vault) -> Result<Option<WakeEntry>, ManagedError> {
    let at = vault
        .housekeeping_wake_at()
        .map_err(|error| ManagedError::VaultMeta(error.to_string()))?;
    Ok(at.map(|at| WakeEntry {
        id: WAKE_ID_HOUSEKEEPING.to_owned(),
        at: Schedule::Exact { at },
        reason_tag: WAKE_ID_HOUSEKEEPING.to_owned(),
    }))
}
