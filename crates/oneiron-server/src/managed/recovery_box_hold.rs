//! The kit-only hold on this hosted vault's recovery box (Fable pass 27 R7;
//! Engine RULING WAYBACK-BOX-HOLD-RELAY = A, 16 Nov 01:02).
//!
//! The box lives on the control plane behind the node's bearer, which this
//! process never holds, so the hold goes to the supervisor socket the wake
//! ledger already pushes to: one `recovery_box_kit_only` line with the
//! vault's name, its spawn token and the choice, on a connection of its own,
//! and one ack line back (`oneiron_vault_contract::RecoveryBoxKitOnly`). The
//! supervisor proves the line as it proves a push and forwards the choice
//! under the vault's placement.
//!
//! The recovery preset switch is the only caller, through the
//! `RecoveryBoxHold` trait beside the preset doors: it asks for the hold
//! before it commits "Nobody but me" and refuses the switch when the hold
//! fails, and lifts the hold after it leaves. So every answer other than
//! `held: true` is an error here: a refusal, an ack outside the contract (a
//! supervisor built before the op answers a ledger ack), a closed connection
//! or no answer within [`HOLD_TIMEOUT`]. One attempt per call; the owner
//! retries the switch.
//!
//! A switch this process's last run did not finish leaves the
//! box-hold-pending marker behind: the boot heal below then resends the
//! hold matching the preset, once, on its own thread, and a switch's hold
//! waits for that heal within the same bound.
//!
//! The call is a blocking `std` socket under one deadline, so it needs no
//! runtime and is safe on a runtime's thread or off one. A self-hosted
//! vault has no supervisor and so no client: `SyncServer::recovery_box_hold`
//! answers `None`.

use std::io::{Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use oneiron_vault_contract::{
    MAX_CTL_LINE, RECOVERY_BOX_KIT_ONLY_OP, RecoveryBoxKitOnly, RecoveryBoxKitOnlyAck, TokenHex,
};
use rustix::net::{AddressFamily, SocketAddrUnix, SocketType, sockopt};
use zeroize::Zeroizing;

/// How long one hold's connect, write and the supervisor's ack may take, in
/// all. The supervisor's own call to the control plane ends within 20 s, so
/// a slow control plane still answers inside this. The connect is answered
/// at once unless the supervisor's accept backlog is full; then it waits
/// within the same bound.
pub const HOLD_TIMEOUT: Duration = Duration::from_secs(30);

/// The room reserved for the request line before the token is in it, so no
/// growth of the buffer leaves a copy of the token in freed memory. A request
/// is under 256 bytes: a vault name is at most 63 and the token 64.
const LINE_ROOM: usize = 512;

/// This vault's caller of its recovery box's kit-only hold, on the
/// supervisor socket and spawn identity its wake ledger uses.
#[derive(Clone)]
pub struct HypnosRecoveryBoxHold {
    socket: PathBuf,
    vault: String,
    token: TokenHex,
    timeout: Duration,
    heal: Arc<HealGate>,
}

impl std::fmt::Debug for HypnosRecoveryBoxHold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HypnosRecoveryBoxHold")
            .field("socket", &self.socket)
            .field("vault", &self.vault)
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// How many boot heal holds are still in flight: the gate is open at none.
/// One gate is shared across the client's clones, so the installed client
/// and the heal's own clone wait and signal on the same gate.
#[derive(Default)]
struct HealGate {
    running: Mutex<usize>,
    ended: Condvar,
}

/// One boot heal's hold on the closed gate. Dropping it releases that hold,
/// so a panic's unwind releases it too; the gate opens when the last one
/// drops.
#[must_use = "the heal gate opens again when this drops"]
pub(crate) struct HealRunning(Arc<HealGate>);

impl Drop for HealRunning {
    fn drop(&mut self) {
        let mut running = self
            .0
            .running
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *running = running.saturating_sub(1);
        if *running == 0 {
            self.0.ended.notify_all();
        }
    }
}

impl HypnosRecoveryBoxHold {
    pub(crate) fn new(socket: PathBuf, vault: String, token: TokenHex) -> Self {
        Self {
            socket,
            vault,
            token,
            timeout: HOLD_TIMEOUT,
            heal: Arc::default(),
        }
    }

    /// The same caller with a shorter bound, for the integration tests'
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
            heal: Arc::default(),
        }
    }

    /// Closes the boot heal's gate: every hold from now on waits for the
    /// heal's answer before it sends. The returned guard releases this
    /// close when it drops; the gate opens once every close is released.
    pub(crate) fn close_heal_gate(&self) -> HealRunning {
        let mut running = self
            .heal
            .running
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *running = running.saturating_add(1);
        drop(running);
        HealRunning(Arc::clone(&self.heal))
    }

    /// Waits for the boot heal's hold to answer, up to `deadline`. Past it
    /// the hold fails with nothing sent.
    fn wait_for_heal(&self, deadline: Instant) -> Result<(), String> {
        let guard = self
            .heal
            .running
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (guard, _) = self
            .heal
            .ended
            .wait_timeout_while(guard, remaining(deadline)?, |running| *running > 0)
            .unwrap_or_else(PoisonError::into_inner);
        if *guard > 0 {
            return Err("waited past its bound for the boot heal's hold".to_owned());
        }
        Ok(())
    }

    /// Asks the supervisor to hold this vault's recovery box kit-only
    /// (`true`: the deposit is withdrawn and every enrol is refused while it
    /// holds) or to lift the hold (`false`). `Ok` only when the supervisor
    /// answers that the choice is held.
    pub fn hold_kit_only(&self, kit_only: bool) -> oneiron::Result<()> {
        let deadline = Instant::now() + self.timeout;
        self.wait_for_heal(deadline).map_err(|why| failed(&why))?;
        let ack = self.ask(kit_only, deadline).map_err(|why| failed(&why))?;
        held(&ack)
    }

    /// One request and its ack: the write and the whole answer under one
    /// deadline.
    fn ask(&self, kit_only: bool, deadline: Instant) -> Result<RecoveryBoxKitOnlyAck, String> {
        let request = RecoveryBoxKitOnly {
            op: RECOVERY_BOX_KIT_ONLY_OP.to_owned(),
            vault: self.vault.clone(),
            token: self.token.clone(),
            kit_only,
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

        let stream = connect(&self.socket, deadline)?;
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
        let mut answer = Vec::new();
        let mut chunk = [0_u8; 256];
        let end = loop {
            if let Some(end) = answer.iter().position(|byte| *byte == b'\n') {
                break end;
            }
            if answer.len() > MAX_CTL_LINE {
                return Err("had an answer over the supervisor's line cap".to_owned());
            }
            // the deadline is the whole answer's, not each read's
            let left = remaining(deadline).map_err(|_| silent())?;
            stream
                .set_read_timeout(Some(left))
                .map_err(|_| "could not bound the read".to_owned())?;
            match (&stream).read(&mut chunk) {
                Ok(0) => return Err("had no whole answer from the supervisor".to_owned()),
                Ok(read) => answer.extend_from_slice(&chunk[..read]),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(silent());
                }
                Err(_) => return Err("lost the supervisor's answer".to_owned()),
            }
        };
        let first = answer.get(..end).unwrap_or_default();
        let ack: RecoveryBoxKitOnlyAck = serde_json::from_slice(first)
            .map_err(|_| "had an answer outside the contract".to_owned())?;
        if !ack.well_formed() {
            return Err("had an answer outside the contract".to_owned());
        }
        Ok(ack)
    }

    /// Sends the hold matching the recovery preset now, once, on its own
    /// thread, when a switch this process's last run did not finish left
    /// the box-hold-pending marker. Admitted as a background pass: a reap
    /// pause or a deleted vault leaves the marker for the next boot. The
    /// gate closes before the thread starts, so a switch's hold from then
    /// on waits for the heal's answer; with no marker nothing is sent, no
    /// thread starts and the gate never closes.
    pub(crate) fn heal_at_boot(
        &self,
        vault: Arc<oneiron::Vault>,
        admit: crate::server::HousekeepingAdmission,
    ) -> Option<std::thread::JoinHandle<()>> {
        let pending = match vault.recovery_box_hold_pending() {
            Ok(None) => return None,
            Ok(Some(pending)) => pending,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "the recovery box hold marker could not be read; no heal runs this boot"
                );
                return None;
            }
        };
        let Some(admitted) = admit() else {
            tracing::info!(
                "the recovery box hold heal waits: the vault is paused and the marker stays for the next boot"
            );
            return None;
        };
        let running = self.close_heal_gate();
        let hold = self.clone();
        match std::thread::Builder::new()
            .name("recovery-box-heal".into())
            .spawn(move || {
                let _admitted = admitted;
                hold.heal(&vault, pending, running);
            }) {
            Ok(handle) => Some(handle),
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "the recovery box hold heal started no thread; the marker stays for the next boot"
                );
                None
            }
        }
    }

    /// The boot heal: the hold matching the preset now, sent once. The gate
    /// opens once the send has its answer, so a switch's hold goes after
    /// it; the clear below compares the attempt it read and needs no gate.
    /// A send that fails keeps the marker for the next boot.
    fn heal(
        &self,
        vault: &oneiron::Vault,
        pending: oneiron::world_keys::RecoveryBoxHoldPending,
        running: HealRunning,
    ) {
        let matched = self.send_matching(vault);
        drop(running);
        match matched {
            Ok(kit_only) => match vault.clear_recovery_box_hold_pending(pending.attempt) {
                Ok(true) => tracing::info!(
                    kit_only,
                    "the recovery box hold matches the recovery preset again"
                ),
                Ok(false) => tracing::info!(
                    "the recovery box hold healed, but a newer switch's marker stays"
                ),
                Err(error) => tracing::warn!(
                    kind = ?error.kind(),
                    "the recovery box hold healed, but clearing its marker did not go through; the next boot resends"
                ),
            },
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                "the recovery box hold may not match the recovery preset; the marker stays and the next boot resends"
            ),
        }
    }

    /// Reads the recovery preset now and sends its hold once, past the
    /// gate: `Ok(kit_only)` when the supervisor answers that it holds.
    fn send_matching(&self, vault: &oneiron::Vault) -> oneiron::Result<bool> {
        let kit_only = vault.recovery_preset()?.is_nobody_but_me();
        let ack = self
            .ask(kit_only, Instant::now() + self.timeout)
            .map_err(|why| failed(&why))?;
        held(&ack)?;
        Ok(kit_only)
    }
}

impl crate::server::SyncServer {
    /// Installs this hosted vault's recovery box hold; managed boot's only,
    /// once.
    ///
    /// # Errors
    ///
    /// When one is already installed.
    pub(crate) fn configure_recovery_box_hold(
        &self,
        hold: HypnosRecoveryBoxHold,
    ) -> anyhow::Result<()> {
        self.recovery_box_hold
            .set(hold)
            .map_err(|_| anyhow::anyhow!("recovery box hold already configured"))
    }

    /// This vault's recovery box hold: `Some` on a hosted vault once managed
    /// boot installed it, `None` on a self-hosted vault, which has no box
    /// (the preset switch then passes `NoRecoveryBox`).
    #[must_use]
    pub fn recovery_box_hold(&self) -> Option<&HypnosRecoveryBoxHold> {
        self.recovery_box_hold.get()
    }
}

/// Connects to the supervisor socket before `deadline`. Linux makes a
/// blocking connect to a Unix stream socket wait while the listener's
/// accept backlog is full, and bounds that wait by the socket's send
/// timeout, so the timeout is set before the connect.
fn connect(socket: &Path, deadline: Instant) -> Result<UnixStream, String> {
    let unreached = |_: rustix::io::Errno| "did not reach the supervisor socket".to_owned();
    let address = SocketAddrUnix::new(socket).map_err(unreached)?;
    let stream = cloexec_socket().map_err(unreached)?;
    sockopt::set_socket_timeout(&stream, sockopt::Timeout::Send, Some(remaining(deadline)?))
        .map_err(|_| "could not bound the connect".to_owned())?;
    rustix::net::connect(&stream, &address).map_err(unreached)?;
    Ok(UnixStream::from(stream))
}

/// A Unix stream socket closed on exec, as `UnixStream::connect` makes one.
#[cfg(not(target_vendor = "apple"))]
fn cloexec_socket() -> rustix::io::Result<OwnedFd> {
    rustix::net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )
}

/// A Unix stream socket closed on exec, as `UnixStream::connect` makes one
/// (Apple's `socket` takes no close-on-exec flag).
#[cfg(target_vendor = "apple")]
fn cloexec_socket() -> rustix::io::Result<OwnedFd> {
    let socket = rustix::net::socket(AddressFamily::UNIX, SocketType::STREAM, None)?;
    rustix::io::fcntl_setfd(&socket, rustix::io::FdFlags::CLOEXEC)?;
    Ok(socket)
}

/// The time left before `deadline`, or the error that it has passed.
fn remaining(deadline: Instant) -> Result<Duration, String> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err("ran out of time".to_owned());
    }
    Ok(left)
}

/// Whether the supervisor's answer holds the choice.
fn held(ack: &RecoveryBoxKitOnlyAck) -> oneiron::Result<()> {
    match (ack.held, ack.error.as_deref()) {
        (true, None) => Ok(()),
        (false, Some(code)) => Err(failed(&format!("was refused by the supervisor ({code})"))),
        _ => Err(failed("had an answer outside the contract")),
    }
}

fn failed(what: &str) -> oneiron::Error {
    oneiron::Error::Io(std::io::Error::other(format!(
        "the recovery box's kit-only hold {what}"
    )))
}
