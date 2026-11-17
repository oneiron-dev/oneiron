//! FIX 8869: the residence mode follows the committed home. A connection
//! resolves its mode when it is made, and the elected home always runs All.
//! This worker resolves it again each time this machine becomes or stops
//! being the elected home: the topology's first election, a host update, or
//! an election a vault wake brings with no topology feed at all. It resolves
//! from the host's configured mode and the owner's stored choice (`rs:mode`),
//! never from the mode the connection ran, so a machine that loses the home
//! goes back to the owner's choice rather than keep the home's forced All.
//! Only a real change is published; the steady loop then queues what it
//! buffered and renegotiates ([`RENEGOTIATE_AT_ONCE`]).
//!
//! The owner's mode setter never runs here: nothing records All as the
//! owner's choice, and nothing waits for the home. On the way to All the
//! opened read caches go, as an owner's switch to All drops them, since the
//! full windows supersede them. On the way back the held windows and the
//! queue stay; the opened lane's own grant path takes them.
//!
//! L7-47: this machine's full-copy mark follows the same resolution. A
//! refresh that resolves sync opened withdraws the mark before it publishes
//! the mode, the first refresh included, so a lost election that falls back
//! to the owner's stored sync-opened choice withdraws it as an owner's
//! switch does. Every mark written outside a switch resolves the stored mode
//! in its own transaction ([`Vault::declare_full_copy_as_resolved`]).

use std::convert::Infallible;
use std::sync::Arc;

use tokio::sync::mpsc;

use super::SyncConnection;
use crate::Vault;
use crate::authority::AuthorityEntryHash;
use crate::sync::client::{SyncEvent, SyncResidenceMode};

/// CALLS renegotiate at once: a residence-mode change reconnects with the
/// new hello at once, past the outage backoff and `auto_reconnect: false`
/// alike. It is a renegotiation of a live lane, not an outage.
pub(super) const RENEGOTIATE_AT_ONCE: bool = true;

impl SyncConnection {
    /// Resolves the mode at start, then on each wake whose committed home
    /// moved this machine in or out of the home, for the connection's whole
    /// life. A federation lane keeps its configured mode and runs none. Each
    /// change holds the host's admission, a pause waited out (FIX 12036).
    pub(super) async fn run_residence_mode(
        &self,
        events: mpsc::UnboundedSender<SyncEvent>,
    ) -> Infallible {
        if self.config.client_config.federation_peer.is_some() {
            match std::future::pending::<Infallible>().await {}
        }
        let vault = Arc::clone(self.manager.vault());
        let mut wakes = vault.subscribe_proactivity_changes();
        let mut home = None;
        loop {
            match crate::sync::residence::local_is_elected_home(&vault) {
                Ok(is_home) if home != Some(is_home) => {
                    // `follow_home` resolves the mode afresh past a pause.
                    let _change = self.admit_round().await;
                    if let Err(error) = self.follow_home(&vault) {
                        let _ = events.send(SyncEvent::Error(format!(
                            "Residence mode refresh failed: {error}"
                        )));
                    } else {
                        home = Some(is_home);
                    }
                }
                Ok(_) => {}
                Err(error) => {
                    let _ = events.send(SyncEvent::Error(format!(
                        "Residence mode refresh failed: {error}"
                    )));
                }
            }
            if wakes.changed().await.is_err() {
                match std::future::pending::<Infallible>().await {}
            }
        }
    }

    /// Publishes the mode the committed home and the owner's stored choice
    /// resolve to now, when it differs from the one this connection runs.
    /// A change to All publishes first and then drops the opened read
    /// caches, so no reader sees Thin with its caches gone (FIX 11114).
    /// Under sync opened it first withdraws this install's full-copy mark,
    /// changed or not (L7-47). An owner's switch can commit and publish
    /// while the refresh runs, so the refresh resolves once more after it
    /// publishes and repeats until the mode stands: the mode it leaves is
    /// the one the store resolves to, and a refresh that ends on sync opened
    /// withdrew the mark under that resolution.
    fn follow_home(&self, vault: &Vault) -> crate::error::Result<()> {
        let configured = self.config.client_config.residence_mode;
        let mut mode = crate::sync::residence::resolve_residence_mode(vault, configured)?;
        loop {
            // L7-47: a machine that runs sync opened holds no full-copy mark.
            // A lost election is no switch, so the switch's withdrawal never
            // ran (FIX FULL-COPY-MARK-ELECTION-OPENED). A mark that is not
            // withdrawn never fails the refresh.
            if mode == SyncResidenceMode::Opened
                && let Err(error) = vault.declare_full_copy_as_resolved(configured, false)
            {
                tracing::warn!(
                    kind = ?error.kind(),
                    "the full-copy mark was not withdrawn; a later residence refresh withdraws it"
                );
            }
            if mode != *self.mode.borrow() {
                self.mode.send_if_modified(|running| {
                    let changed = *running != mode;
                    *running = mode;
                    changed
                });
                if mode == SyncResidenceMode::All
                    && let Err(error) = crate::sync::residence::prune_thin_items(vault, u64::MAX)
                {
                    tracing::warn!(
                        %error,
                        "residence mode is All with its opened read caches left; the next switch drops them"
                    );
                }
            }
            // A switch that committed after the first resolution: its
            // withdrawal transaction skipped a mark this mode disagrees
            // with, or it published before this refresh did.
            let resolved = crate::sync::residence::resolve_residence_mode(vault, configured)?;
            if resolved == mode {
                return Ok(());
            }
            mode = resolved;
        }
    }
}

impl Vault {
    /// L7-47: the full-copy mark a home session's first round earns once it
    /// completes under sync all: held, written only while the owner's stored
    /// choice and the committed home still resolve to sync all
    /// ([`Self::declare_full_copy_as_resolved`]). The round ran the mode its
    /// connect took; an owner's switch to sync opened that lands during the
    /// round wins (FIX FULL-COPY-MARK-FIRST-ROUND-RACE). `configured` is the
    /// host's configured mode.
    ///
    /// # Errors
    /// As [`Self::declare_full_copy_as_resolved`].
    pub(crate) fn mark_first_round_full_copy(
        &self,
        configured: SyncResidenceMode,
    ) -> crate::error::Result<Option<AuthorityEntryHash>> {
        self.declare_full_copy_as_resolved(configured, true)
    }

    /// Writes this install's full-copy mark saying `held` only when the mode
    /// the owner's stored choice and the committed home resolve to in the
    /// mark's own transaction agrees: held under sync all, withdrawn under
    /// sync opened; else nothing (`Ok(None)`). A switch records the owner's
    /// choice and withdraws the mark in one transaction, and LMDB runs one
    /// write transaction at a time, so a mark written here never lands after
    /// a switch it disagrees with. `configured` is the host's configured
    /// mode. `Ok(Some(hash))` when a mark was written and committed.
    ///
    /// # Errors
    /// As [`Self::declare_full_copy_in_txn`]; storage errors.
    pub(crate) fn declare_full_copy_as_resolved(
        &self,
        configured: SyncResidenceMode,
        held: bool,
    ) -> crate::error::Result<Option<AuthorityEntryHash>> {
        self.load_install_signing_if_minted()?;
        self.with_write_txn_grouped(|txn| {
            let mode = self.resolve_residence_mode_in_txn(txn, configured)?;
            if held != (mode == SyncResidenceMode::All) {
                return Ok(None);
            }
            self.declare_full_copy_in_txn(txn, held)
        })
    }
}
