//! An open sync connection's grant, judged again while it serves (FIX
//! [SYNC-OPEN-SOCKET-OUTLIVES-MESH-REVOKE]; SYNC-REVOKE-CLOSES-OPEN-CONNECTION
//! = A, Engine 27 Nov 16:43). The listener admits a connection on its
//! machine's grant and judges each new stream again, but a stream already
//! open (a keep-alive HTTP/1.1 connection, or the sync socket it upgraded
//! into) asked nothing again, so a machine the owner revoked kept its open
//! socket until it hung up. A revoke is the owner's one defence against a
//! lost or hostile own machine on a trust-blind lane (ARCH-0040:261), so it
//! takes effect at once.
//!
//! Each connection's watch judges the grant by the listener's own grants (a
//! device's pinned home as at admission): once at the start, at each
//! credential revocation notice of the vault, and every
//! [`SYNC_GRANT_RECHECK_EVERY`]. Once the grant no longer holds, or cannot
//! be read (fail closed), it closes the whole connection, every stream with
//! it. No new refusal code: the machine sees its connection close, and its
//! next dial is refused at admission as before.

use std::sync::Arc;
use std::time::Duration;

use oneiron::Vault;
use oneiron_mesh_transport::{MachineGrants, MeshConnection, MeshError, SYNC_ALPN};
use tokio::sync::watch;
use tokio::time::{Instant, Interval, MissedTickBehavior};

/// How often an open sync connection's grant is judged again with no
/// notice. A revoke on this vault sends the credential revocation notice
/// and is judged at once; a pairing that ends at its expiry sends none, nor
/// does a revoke that another process committed to the vault, so those are
/// judged within this period. Minutes or less, as the ruling asks: one
/// grant read per open connection per period.
pub(super) const SYNC_GRANT_RECHECK_EVERY: Duration = Duration::from_secs(60);

/// One open sync connection's grant, judged again while it serves.
pub(super) struct SyncGrantWatch {
    grants: Arc<dyn MachineGrants>,
    revocations: watch::Receiver<u64>,
    recheck: Interval,
    /// Whether it judged the grant once since the connection's admission.
    judged: bool,
}

impl SyncGrantWatch {
    /// Subscribes to `vault`'s revocation notices before its first
    /// judgement, so a revoke committed after the admission is judged too.
    pub(super) fn new(vault: &Vault, grants: Arc<dyn MachineGrants>) -> Self {
        let revocations = vault.subscribe_credential_revocations();
        let mut recheck = tokio::time::interval_at(
            Instant::now() + SYNC_GRANT_RECHECK_EVERY,
            SYNC_GRANT_RECHECK_EVERY,
        );
        recheck.set_missed_tick_behavior(MissedTickBehavior::Delay);
        Self {
            grants,
            revocations,
            recheck,
            judged: false,
        }
    }

    /// Returns once `connection`'s sync grant no longer holds, or cannot be
    /// read, having closed the connection. It judges at once on its first
    /// call, then at each notice and each recheck. Cancel-safe: a
    /// `select!` arm that loses drops it between judgements.
    pub(super) async fn lapsed(&mut self, connection: &dyn MeshConnection) {
        loop {
            if self.judged {
                tokio::select! {
                    biased;
                    changed = self.revocations.changed() => {
                        if changed.is_err() {
                            // The vault's notices ended: the recheck alone
                            // judges it from here.
                            self.recheck.tick().await;
                        }
                    }
                    _ = self.recheck.tick() => {}
                }
            }
            self.judged = true;
            if !self.holds(connection) {
                connection.close();
                return;
            }
        }
    }

    /// Whether the listener's grants still admit `connection`'s machine,
    /// under the endpoint key its handshake proved, on sync. A failed read
    /// is no.
    fn holds(&self, connection: &dyn MeshConnection) -> bool {
        matches!(
            self.grants
                .permits(connection.machine(), connection.endpoint_key(), SYNC_ALPN),
            Ok(true)
        )
    }
}

/// Closes `connection` once its accept loop's accept failed, and hands back
/// `error`. A failed accept ends the connection, not just the loop: a stream
/// the connection already upgraded holds a handle to it, so without the close
/// it would outlive a revoke that the next stream's admission refused before
/// the notice woke the watch (review round 1 of #10600). An accept fails only
/// when the grant is refused or cannot be read, or the connection is already
/// lost, so this never closes a connection whose grant holds.
pub(super) fn close_on_accept_error(
    connection: &dyn MeshConnection,
    error: MeshError,
) -> MeshError {
    connection.close();
    error
}
