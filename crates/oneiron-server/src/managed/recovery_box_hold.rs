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
//! The call is a blocking `std` socket under one deadline, so it needs no
//! runtime and is safe on a runtime's thread or off one. A self-hosted
//! vault has no supervisor and so no client: `SyncServer::recovery_box_hold`
//! answers `None`.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use oneiron_vault_contract::{
    MAX_CTL_LINE, RECOVERY_BOX_KIT_ONLY_OP, RecoveryBoxKitOnly, RecoveryBoxKitOnlyAck, TokenHex,
};
use zeroize::Zeroizing;

/// How long one hold (connect, write and the supervisor's ack) may take.
/// The supervisor's own call to the control plane ends within 20 s, so a
/// slow control plane still answers inside this.
pub const HOLD_TIMEOUT: Duration = Duration::from_secs(30);

/// This vault's caller of its recovery box's kit-only hold, on the
/// supervisor socket and spawn identity its wake ledger uses.
#[derive(Clone)]
pub struct HypnosRecoveryBoxHold {
    socket: PathBuf,
    vault: String,
    token: TokenHex,
    timeout: Duration,
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

impl HypnosRecoveryBoxHold {
    pub(crate) fn new(socket: PathBuf, vault: String, token: TokenHex) -> Self {
        Self {
            socket,
            vault,
            token,
            timeout: HOLD_TIMEOUT,
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
        }
    }

    /// Asks the supervisor to hold this vault's recovery box kit-only
    /// (`true`: the deposit is withdrawn and every enrol is refused while it
    /// holds) or to lift the hold (`false`). `Ok` only when the supervisor
    /// answers that the choice is held.
    pub fn hold_kit_only(&self, kit_only: bool) -> oneiron::Result<()> {
        let ack = self.ask(kit_only).map_err(|why| failed(&why))?;
        match (ack.held, ack.error) {
            (true, _) => Ok(()),
            (false, code) => Err(failed(&format!(
                "was refused by the supervisor ({})",
                code.as_deref().unwrap_or("refused")
            ))),
        }
    }

    /// One request and its ack, under one deadline.
    fn ask(&self, kit_only: bool) -> Result<RecoveryBoxKitOnlyAck, String> {
        let deadline = Instant::now() + self.timeout;
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
        let mut line =
            Zeroizing::new(serde_json::to_vec(&request).map_err(|_| "was not encoded".to_owned())?);
        if line.len() >= MAX_CTL_LINE {
            return Err("is over the supervisor's line cap".to_owned());
        }
        line.push(b'\n');

        let stream = UnixStream::connect(&self.socket)
            .map_err(|_| "did not reach the supervisor socket".to_owned())?;
        stream
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(|_| "could not bound the write".to_owned())?;
        (&stream)
            .write_all(&line)
            .and_then(|()| (&stream).flush())
            .map_err(|_| "was not written to the supervisor".to_owned())?;

        let mut reader = BufReader::new((&stream).take(MAX_CTL_LINE as u64 + 1));
        let mut answer = Vec::new();
        loop {
            stream
                .set_read_timeout(Some(remaining(deadline)?))
                .map_err(|_| "could not bound the read".to_owned())?;
            match reader.read_until(b'\n', &mut answer) {
                Ok(0) => break,
                Ok(_) if answer.last() == Some(&b'\n') => break,
                Ok(_) => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(format!(
                        "had no answer from the supervisor within {:?}",
                        self.timeout
                    ));
                }
                Err(_) => return Err("lost the supervisor's answer".to_owned()),
            }
        }
        if answer.last() != Some(&b'\n') || answer.len() > MAX_CTL_LINE {
            return Err("had no whole answer from the supervisor".to_owned());
        }
        let ack: RecoveryBoxKitOnlyAck = serde_json::from_slice(&answer)
            .map_err(|_| "had an answer outside the contract".to_owned())?;
        if !ack.well_formed() {
            return Err("had an answer outside the contract".to_owned());
        }
        Ok(ack)
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
        "the recovery box's kit-only hold {what}"
    )))
}
