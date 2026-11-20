//! One owner key change of this hosted vault, reported to its supervisor
//! (Engine ruling 21 Nov 06:00: every owner key change on a hosted vault is
//! reported to the control plane, which emails the account's owner).
//!
//! The report goes to the supervisor socket the wake ledger already pushes
//! to: one `owner_key_change` line with the vault's name, its spawn token,
//! the change's entry hash, kind, key shape and signer-claimed time, on a
//! connection of its own, and one ack line back
//! (`oneiron_vault_contract::OwnerKeyChangeReport`). The supervisor proves
//! the line as it proves a push and forwards the change under the vault's
//! placement.
//!
//! The reporter task beside the ledger report is the only caller, through
//! [`sweep_once`]: it sends every listed change the cursor row does not name
//! yet, oldest first, and refuses nothing itself. So every answer other than
//! `reported: true` is an error here: a refusal, an ack outside the contract
//! (a supervisor built before the op answers a ledger ack), a closed
//! connection or no answer within [`REPORT_TIMEOUT`]. One attempt per call;
//! the sweep sends the change again. Managed boot writes the cursor's
//! baseline ([`baseline_cursor`]) before anything serves.
//!
//! The call is a blocking `std` socket: its connect never waits, and the
//! write and the ack run under one deadline, read in slices of
//! [`READ_SLICE`] so a set stop flag ends it within one slice. It needs no
//! runtime. A self-hosted vault has no supervisor and so no client:
//! `SyncServer::owner_key_change_report` answers `None`.

use std::collections::BTreeSet;
use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use oneiron::Vault;
use oneiron::authority::{
    AUTHORITY_HASH_LEN, AuthorityEntryHash, EnrolledOwnerKeyKind, OwnerKeyChange,
    OwnerKeyChangeKind,
};
use oneiron_vault_contract::{
    MAX_CTL_LINE, OWNER_KEY_CHANGE_OP, OwnerKeyChangeReport, OwnerKeyChangeReportAck, TokenHex,
    owner_key_change_wire_at,
};
use zeroize::Zeroizing;

/// The install-local cursor of the report: the entry hashes this install
/// already reported, 32 bytes each, ascending. Never synced: every replica
/// would mail else.
pub const OWNER_KEY_CHANGE_REPORTED_KEY: &str = "managed:owner_key_change_reported:v1";

/// How long one report's write and the supervisor's ack may take, in all.
/// The supervisor's own call to the control plane ends within 20 s, so a
/// slow control plane still answers inside this. The connect to the local
/// socket never waits: a supervisor whose accept backlog is full fails the
/// report at once, and the next sweep sends it again.
pub const REPORT_TIMEOUT: Duration = Duration::from_secs(30);

/// How long one read of the ack waits before the report looks at its stop
/// flag again: a shutdown waits at most this long for a report in flight.
pub const READ_SLICE: Duration = Duration::from_secs(1);

/// The room reserved for the request line before the token is in it, so no
/// growth of the buffer leaves a copy of the token in freed memory. A report
/// is under 512 bytes: a vault name is at most 63, the token and the entry
/// hash 64 each.
const LINE_ROOM: usize = 512;

/// This vault's reporter of its owner key changes, on the supervisor socket
/// and spawn identity its wake ledger uses.
#[derive(Clone)]
pub struct HypnosOwnerKeyChange {
    socket: PathBuf,
    vault: String,
    token: TokenHex,
    timeout: Duration,
}

impl std::fmt::Debug for HypnosOwnerKeyChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HypnosOwnerKeyChange")
            .field("socket", &self.socket)
            .field("vault", &self.vault)
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl HypnosOwnerKeyChange {
    pub(crate) fn new(socket: PathBuf, vault: String, token: TokenHex) -> Self {
        Self {
            socket,
            vault,
            token,
            timeout: REPORT_TIMEOUT,
        }
    }

    /// The same reporter with a shorter bound, for the integration tests'
    /// supervisor that never answers.
    #[cfg(oneiron_test_support)]
    pub(crate) fn with_timeout(
        socket: PathBuf,
        vault: String,
        token: TokenHex,
        timeout: Duration,
    ) -> Self {
        Self {
            socket,
            vault,
            token,
            timeout,
        }
    }

    /// Reports `change` to the supervisor: its entry hash, kind, key shape
    /// and signer-claimed time. `Ok` only when the supervisor answers that
    /// the change is reported; a set `stop` ends the wait for the answer
    /// within one [`READ_SLICE`], as a failure.
    pub fn report_change(&self, change: &OwnerKeyChange, stop: &AtomicBool) -> oneiron::Result<()> {
        let ack = self.ask(change, stop).map_err(|why| failed(&why))?;
        match (ack.reported, ack.error.as_deref()) {
            (true, None) => Ok(()),
            (false, Some(code)) => Err(failed(&format!("was refused by the supervisor ({code})"))),
            _ => Err(failed("had an answer outside the contract")),
        }
    }

    /// One request and its ack: a connect that never waits, then the write
    /// and the whole answer under one deadline.
    fn ask(
        &self,
        change: &OwnerKeyChange,
        stop: &AtomicBool,
    ) -> Result<OwnerKeyChangeReportAck, String> {
        let deadline = Instant::now() + self.timeout;
        let request = OwnerKeyChangeReport {
            op: OWNER_KEY_CHANGE_OP.to_owned(),
            vault: self.vault.clone(),
            token: self.token.clone(),
            entry: oneiron_hex::encode(&change.entry),
            change: change_name(change.change).to_owned(),
            key: key_shape(change).to_owned(),
            // a claim past the wire's range still reports its change
            at: owner_key_change_wire_at(change.at),
        };
        // A request this side's supervisor would refuse to read is one this
        // side must refuse to send.
        request
            .validate()
            .map_err(|e| format!("was not sent: {e}"))?;
        // The line carries the token, so it is wiped once it is written.
        let mut line = Zeroizing::new(Vec::with_capacity(LINE_ROOM));
        serde_json::to_writer(&mut *line, &request).map_err(|_| "was not encoded".to_owned())?;
        if line.len() >= MAX_CTL_LINE {
            return Err("is over the supervisor's line cap".to_owned());
        }
        line.push(b'\n');

        let stream = connect_at_once(&self.socket)
            .map_err(|_| "did not reach the supervisor socket".to_owned())?;
        stream
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(|_| "could not bound the write".to_owned())?;
        (&stream)
            .write_all(&line)
            .and_then(|()| (&stream).flush())
            .map_err(|_| "was not written to the supervisor".to_owned())?;

        let silent = || {
            format!(
                "had no answer from the supervisor within {:?}",
                self.timeout
            )
        };
        let over_cap = || "had an answer over the supervisor's line cap".to_owned();
        let mut answer = Vec::new();
        let mut chunk = [0_u8; 256];
        let end = loop {
            // the cap is the line's with its newline, as on the request
            if let Some(end) = answer.iter().position(|byte| *byte == b'\n') {
                if end >= MAX_CTL_LINE {
                    return Err(over_cap());
                }
                break end;
            }
            if answer.len() >= MAX_CTL_LINE {
                return Err(over_cap());
            }
            if stop.load(Ordering::Relaxed) {
                return Err("was stopped by the vault's shutdown".to_owned());
            }
            // the deadline is the whole answer's, not each read's
            let left = remaining(deadline).map_err(|_| silent())?;
            stream
                .set_read_timeout(Some(left.min(READ_SLICE)))
                .map_err(|_| "could not bound the read".to_owned())?;
            match (&stream).read(&mut chunk) {
                Ok(0) => return Err("had no whole answer from the supervisor".to_owned()),
                Ok(read) => answer.extend_from_slice(&chunk[..read]),
                // a slice ended: the stop flag and the deadline decide
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::Interrupted
                            | std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => return Err("lost the supervisor's answer".to_owned()),
            }
        };
        let first = answer.get(..end).unwrap_or_default();
        // a JSON object only: a struct also reads from an array, so `[true]`
        // would read as reported
        if first.trim_ascii_start().first() != Some(&b'{') {
            return Err("had an answer outside the contract".to_owned());
        }
        let ack: OwnerKeyChangeReportAck = serde_json::from_slice(first)
            .map_err(|_| "had an answer outside the contract".to_owned())?;
        if !ack.well_formed() {
            return Err("had an answer outside the contract".to_owned());
        }
        Ok(ack)
    }
}

/// A blocking stream to the Unix socket at `path`, connected without
/// waiting. A blocking Unix stream connect waits while the listener's accept
/// backlog is full, and nothing bounds that wait: a send timeout is set only
/// after `UnixStream::connect` returns. Non-blocking, the connect either
/// completes at once or fails (`EAGAIN` on Linux, `ECONNREFUSED` on the
/// BSDs), and the stream turns blocking again for its bounded write and
/// reads.
fn connect_at_once(path: &Path) -> std::io::Result<UnixStream> {
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketType, connect};
    #[cfg(not(target_vendor = "apple"))]
    let socket = rustix::net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )?;
    #[cfg(target_vendor = "apple")]
    let socket = {
        let socket = rustix::net::socket(AddressFamily::UNIX, SocketType::STREAM, None)?;
        rustix::io::fcntl_setfd(&socket, rustix::io::FdFlags::CLOEXEC)?;
        socket
    };
    let stream = UnixStream::from(socket);
    stream.set_nonblocking(true)?;
    connect(&stream, &SocketAddrUnix::new(path)?)?;
    stream.set_nonblocking(false)?;
    Ok(stream)
}

/// The wire name of a change kind.
fn change_name(change: OwnerKeyChangeKind) -> &'static str {
    match change {
        OwnerKeyChangeKind::Enrolled => "enrolled",
        OwnerKeyChangeKind::Confirmed => "confirmed",
        OwnerKeyChangeKind::Removed => "removed",
        OwnerKeyChangeKind::RemovedByEndedKey => "removed_by_ended_key",
        OwnerKeyChangeKind::RemovedInConflict => "removed_in_conflict",
        OwnerKeyChangeKind::BoundByPasskey => "bound_by_passkey",
        OwnerKeyChangeKind::BoundByDeviceKey => "bound_by_device_key",
    }
}

/// The wire shape of the key a change names: a passkey is neither enrolled
/// kind, so it is `None` on the list.
fn key_shape(change: &OwnerKeyChange) -> &'static str {
    match change.kind {
        None => "passkey",
        Some(EnrolledOwnerKeyKind::Device) => "device_key",
        Some(EnrolledOwnerKeyKind::RecoveryAuthority) => "recovery_authority",
    }
}

impl crate::server::SyncServer {
    /// Installs this hosted vault's owner key change reporter; managed
    /// boot's only, once.
    ///
    /// # Errors
    ///
    /// When one is already installed.
    pub(crate) fn configure_owner_key_change_report(
        &self,
        report: HypnosOwnerKeyChange,
    ) -> anyhow::Result<()> {
        self.owner_key_change_report
            .set(report)
            .map_err(|_| anyhow::anyhow!("owner key change report already configured"))
    }

    /// This vault's owner key change reporter: `Some` on a hosted vault once
    /// managed boot installed it, `None` on a self-hosted vault, which has no
    /// supervisor to report to.
    #[must_use]
    pub fn owner_key_change_report(&self) -> Option<&HypnosOwnerKeyChange> {
        self.owner_key_change_report.get()
    }
}

/// What one sweep did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SweepOutcome {
    /// Every waiting change was reported, or none waited.
    Clean,
    /// The sweep stopped short: the list or the cursor would not read, a
    /// report was refused or failed, or the cursor would not write. Nothing
    /// past the stop was sent; the next sweep sends it again.
    StoppedOnFailure,
    /// The stop flag was set: the vault is shutting down. Nothing past the
    /// stop was sent; the next start's sweeps send it.
    Stopped,
}

/// Writes the cursor row's baseline: managed boot's only, before this vault
/// serves anything or any worker starts. With no row, or one that does not
/// decode, the row is written with every current entry and nothing is sent,
/// so a deploy mails no old change and a damaged row mails nothing old. Only
/// boot writes a baseline, so a change that lands once the vault serves is
/// never read as history. A row that does not read is left as it is. A
/// failure logs; with no row written, the sweeps send every listed change,
/// and the control plane mails each entry once.
pub(crate) fn baseline_cursor(vault: &Vault) {
    match vault.sync_state_get(OWNER_KEY_CHANGE_REPORTED_KEY) {
        Ok(Some(raw)) if decode_reported(&raw).is_some() => return,
        Ok(Some(_)) => tracing::warn!(
            reason = "owner_key_change_cursor_rebased",
            "owner key change cursor did not decode; it is written again and nothing is sent"
        ),
        Ok(None) => {}
        Err(error) => {
            tracing::warn!(
                reason = "owner_key_change_cursor_failed",
                %error,
                "owner key change baseline read no cursor"
            );
            return;
        }
    }
    let changes = match vault.owner_key_changes_as_host() {
        Ok(changes) => changes,
        Err(error) => {
            tracing::warn!(
                reason = "owner_key_change_list_failed",
                %error,
                "owner key change baseline read no list"
            );
            return;
        }
    };
    let reported: BTreeSet<AuthorityEntryHash> =
        changes.iter().map(|change| change.entry).collect();
    if let Err(error) = write_reported(vault, &reported) {
        tracing::warn!(
            reason = "owner_key_change_cursor_write_failed",
            %error,
            "owner key change baseline wrote no cursor"
        );
    }
}

/// One report sweep over `vault`: every listed change the cursor row does not
/// name goes to the supervisor, oldest first, and joins the row once its ack
/// says reported; any other answer stops the sweep, and so does a set `stop`.
/// A sweep writes no baseline ([`baseline_cursor`] at boot does): with no
/// row, or one that does not decode, it sends every listed change. Failures
/// log with their reason; never the token.
pub(crate) fn sweep_once(
    vault: &Vault,
    report: &HypnosOwnerKeyChange,
    stop: &AtomicBool,
) -> SweepOutcome {
    let changes = match vault.owner_key_changes_as_host() {
        Ok(changes) => changes,
        Err(error) => {
            tracing::warn!(
                reason = "owner_key_change_list_failed",
                %error,
                "owner key change sweep read no list"
            );
            return SweepOutcome::StoppedOnFailure;
        }
    };
    let raw = match vault.sync_state_get(OWNER_KEY_CHANGE_REPORTED_KEY) {
        Ok(raw) => raw,
        Err(error) => {
            tracing::warn!(
                reason = "owner_key_change_cursor_failed",
                %error,
                "owner key change sweep read no cursor"
            );
            return SweepOutcome::StoppedOnFailure;
        }
    };
    let mut reported = match raw.as_deref().map(decode_reported) {
        Some(Some(reported)) => reported,
        Some(None) => {
            tracing::warn!(
                reason = "owner_key_change_cursor_undecoded",
                "owner key change cursor did not decode; every listed change is sent"
            );
            BTreeSet::new()
        }
        None => BTreeSet::new(),
    };
    let mut pending: Vec<&OwnerKeyChange> = changes
        .iter()
        .filter(|change| !reported.contains(&change.entry))
        .collect();
    pending.sort_by(|a, b| a.at.cmp(&b.at).then_with(|| a.entry.cmp(&b.entry)));
    for change in pending {
        if stop.load(Ordering::Relaxed) {
            return SweepOutcome::Stopped;
        }
        if let Err(error) = report.report_change(change, stop) {
            if stop.load(Ordering::Relaxed) {
                return SweepOutcome::Stopped;
            }
            tracing::warn!(
                reason = "owner_key_change_report_failed",
                %error,
                "owner key change report failed"
            );
            return SweepOutcome::StoppedOnFailure;
        }
        reported.insert(change.entry);
        if let Err(error) = write_reported(vault, &reported) {
            tracing::warn!(
                reason = "owner_key_change_cursor_write_failed",
                %error,
                "owner key change sweep wrote no cursor"
            );
            return SweepOutcome::StoppedOnFailure;
        }
    }
    SweepOutcome::Clean
}

/// The cursor row's reported entry hashes, or `None` when the row does not
/// decode: anything but whole 32-byte hashes, ascending or not.
fn decode_reported(raw: &[u8]) -> Option<BTreeSet<AuthorityEntryHash>> {
    if !raw.len().is_multiple_of(AUTHORITY_HASH_LEN) {
        return None;
    }
    Some(
        raw.chunks_exact(AUTHORITY_HASH_LEN)
            .map(|chunk| {
                let mut hash: AuthorityEntryHash = [0; AUTHORITY_HASH_LEN];
                hash.copy_from_slice(chunk);
                hash
            })
            .collect(),
    )
}

/// Writes the cursor row: the reported entry hashes, 32 bytes each,
/// ascending, as telemetry, which moves no backup watermark.
fn write_reported(vault: &Vault, reported: &BTreeSet<AuthorityEntryHash>) -> oneiron::Result<()> {
    let mut bytes = Vec::with_capacity(reported.len() * AUTHORITY_HASH_LEN);
    for hash in reported {
        bytes.extend_from_slice(hash);
    }
    vault.sync_state_put_telemetry_batch(&[(OWNER_KEY_CHANGE_REPORTED_KEY, bytes.as_slice())])
}

/// The time left before `deadline`, or the error that it has passed.
fn remaining(deadline: Instant) -> Result<Duration, String> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err("ran out of time".to_owned());
    }
    Ok(left)
}

fn failed(what: &str) -> oneiron::Error {
    oneiron::Error::Io(std::io::Error::other(format!(
        "the owner key change report {what}"
    )))
}
