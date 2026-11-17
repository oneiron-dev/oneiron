//! The node follows the owner's kit-only choice (Engine RULING
//! WAYBACK-BOX-HOLD-FROM-DEVICE-SWITCH = A, 17 Nov 01:49).
//!
//! A hosted vault's recovery preset switch runs on the owner's device, never
//! here: every door into "Nobody but me" refuses this node's supervisor-held
//! key custody before it holds the box, and the preset is this install's own
//! row, so the node's preset always reads `Standard`. The switch also
//! appends one owner-signed authority fact, kit-only on or off, and that
//! fact replicates. This watch reads the fact as the vault's fold holds it
//! and sends the matching hold through the supervisor relay: at once when
//! the process starts, then at each look ([`KIT_ONLY_LOOK_EVERY`]) while the
//! box has not acknowledged the latest fact in this process. A hold that
//! fails is sent again at the next look, and each hold waits for the boot
//! heal as a switch's does. No authority-apply hook reaches the server (the
//! device client's `SyncEvent::AuthorityCaughtUp` is not the node's), hence
//! the cadence. The box answers a repeated hold with no change and no
//! receipt, so the one resend per start costs nothing.
//!
//! Until a switch writes the fact, the gap is status only: the switch's
//! rotation of the recovery-authority key already leaves the box a revoked
//! key's seed (FIX RECOVERY-BOX-DEAD-RECORD-AFTER-DEVICE-SWITCH).
//!
//! The same cadence reports the vault's recovery wait to the box
//! (WAYBACK-BOX-WAIT-ENGINE-HOLD-ONE-WAIT = A): the box waits it before it
//! releases the recovery-authority seed. The first look reports it, and a
//! later look only when the wait differs from the one the box took in this
//! process, so a changed `recovery.wait` reaches the box within one look and
//! a report the box refused goes again at the next. Like every wait report,
//! it does not wait for the boot heal.

use std::cell::Cell;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use oneiron::world_keys::{RecoveryBoxCanceller, RecoveryBoxHold};
use oneiron_contracts::authority::AuthorityEntryHash;

use super::HypnosRecoveryBoxHold;
use crate::server::HousekeepingAdmission;

/// How often a managed node looks at the owner's kit-only fact again: a
/// cadence, not a deadline.
pub(crate) const KIT_ONLY_LOOK_EVERY: Duration = Duration::from_secs(30);

/// The owner's latest kit-only choice as the vault's fold holds it: what
/// their last recovery preset switch chose, on whichever install it ran, and
/// the authority entry that carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KitOnlyFact {
    /// `true` for "Nobody but me" in either form, `false` for `Standard`.
    pub kit_only: bool,
    /// The authority entry the switch appended.
    pub entry: AuthorityEntryHash,
}

/// Reads the vault's kit-only fact. The watch and the boot heal rely on this
/// contract:
/// - `Ok(None)` only when the fold holds no kit-only act in force: the owner
///   never switched with an owner key's proof, or the live acts never agreed.
///   A failure to read is an `Err`, never `None`: on `None` the boot heal
///   falls back to this install's own preset, which reads `Standard` on a
///   node.
/// - The fact is the act in force that the fold counted as the owner's: one
///   with no owner key's proof (an agent's, a carrier's alone, or one signed
///   by an owner key the fold had revoked) never counts.
/// - `entry` is the hash of that act in force, so the watch sends one hold per
///   fact. The act in force may move back to an earlier act (a conflict
///   settles on the live acts' common choice); the watch then sends that
///   act's hold, as for any fact it has not acknowledged.
pub type KitOnlyFactRead =
    Arc<dyn Fn(&oneiron::Vault) -> oneiron::Result<Option<KitOnlyFact>> + Send + Sync>;

/// The fold's reader of the kit-only fact, which managed boot passes: the
/// preset switch's act in force ([`oneiron::Vault::recovery_box_kit_only_fact`]).
/// A vault that was already kit-only before the switch wrote the fact gets
/// its first fact at its next switch (FIX
/// RECOVERY-BOX-DEAD-RECORD-AFTER-DEVICE-SWITCH covers that gap).
pub(crate) fn fold_kit_only_fact() -> KitOnlyFactRead {
    Arc::new(
        |vault: &oneiron::Vault| -> oneiron::Result<Option<KitOnlyFact>> {
            Ok(vault.recovery_box_kit_only_fact()?.map(|fact| KitOnlyFact {
                kit_only: fact.kit_only,
                entry: fact.entry,
            }))
        },
    )
}

/// What the watch keeps between looks, in this process only: the fact the
/// box last acknowledged, and which failure it already warned about, so a
/// failure that repeats every look is logged once at warn.
#[derive(Debug, Default)]
pub(crate) struct KitOnlyFollow {
    acknowledged: Option<KitOnlyFact>,
    read_warned: bool,
    hold_warned: Option<KitOnlyFact>,
}

/// What one look did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KitOnlyLook {
    /// The vault is paused for a reap or deleted: nothing read or sent.
    NotAdmitted,
    /// The fact did not read; the next look reads it again.
    Unreadable,
    /// The owner never switched: there is nothing to follow.
    NoFact,
    /// The box already acknowledged this fact in this process.
    Acknowledged,
    /// The box now holds the fact's choice.
    Held {
        /// The choice the box holds.
        kit_only: bool,
    },
    /// The hold failed; the next look sends it again.
    Failed,
}

/// What the watch keeps of the wait report between looks, in this process
/// only: the wait the box last took, and whether a failure was already
/// warned about.
#[derive(Debug, Default)]
pub(crate) struct WaitReportFollow {
    reported: Option<Duration>,
    warned: bool,
}

/// What one wait report did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitReport {
    /// The vault is paused for a reap or deleted: nothing read or sent.
    NotAdmitted,
    /// The box already took this wait in this process: nothing sent.
    Unchanged,
    /// The box took the wait.
    Reported {
        /// The wait the box took, in whole seconds.
        wait_secs: u64,
    },
    /// The wait did not read, or the box did not take it; the next look
    /// reports it again.
    Failed,
}

/// The box seam a wait report goes through: the relay, except that a wait
/// equal to the one the box last took in this process is not sent again.
/// `sent` holds the wait this report sent and the box took.
struct ReportWhenChanged<'a> {
    hold: &'a HypnosRecoveryBoxHold,
    reported: Option<Duration>,
    sent: Cell<Option<Duration>>,
}

impl RecoveryBoxHold for ReportWhenChanged<'_> {
    fn hold_kit_only(&self, kit_only: bool) -> oneiron::Result<()> {
        HypnosRecoveryBoxHold::hold_kit_only(self.hold, kit_only)
    }

    fn report_recovery_wait(&self, wait: Duration) -> oneiron::Result<()> {
        if self.reported == Some(wait) {
            return Ok(());
        }
        HypnosRecoveryBoxHold::report_recovery_wait(self.hold, wait)?;
        self.sent.set(Some(wait));
        Ok(())
    }

    fn cancel_pending_box_release(
        &self,
        cancelled_by: &RecoveryBoxCanceller,
        release_receipt: Option<u64>,
    ) -> oneiron::Result<bool> {
        RecoveryBoxHold::cancel_pending_box_release(self.hold, cancelled_by, release_receipt)
    }
}

impl HypnosRecoveryBoxHold {
    /// One wait report: reads the vault's recovery wait and reports it to
    /// the box when it differs from the one the box took in this process.
    /// Admitted as a background pass and held through the send.
    pub(crate) fn report_wait_when_changed(
        &self,
        vault: &oneiron::Vault,
        admit: &HousekeepingAdmission,
        follow: &mut WaitReportFollow,
    ) -> WaitReport {
        let Some(_admitted) = admit() else {
            return WaitReport::NotAdmitted;
        };
        let seam = ReportWhenChanged {
            hold: self,
            reported: follow.reported,
            sent: Cell::new(None),
        };
        match vault.report_recovery_wait_to_box(&seam) {
            Ok(()) => {
                follow.warned = false;
                let Some(wait) = seam.sent.get() else {
                    return WaitReport::Unchanged;
                };
                follow.reported = Some(wait);
                tracing::info!(
                    wait_secs = wait.as_secs(),
                    "the recovery box took the vault's recovery wait"
                );
                WaitReport::Reported {
                    wait_secs: wait.as_secs(),
                }
            }
            Err(error) => {
                if follow.warned {
                    tracing::debug!(
                        kind = ?error.kind(),
                        "the recovery box still does not take the vault's recovery wait"
                    );
                } else {
                    tracing::warn!(
                        kind = ?error.kind(),
                        "the recovery box did not take the vault's recovery wait; the next look reports it again"
                    );
                    follow.warned = true;
                }
                WaitReport::Failed
            }
        }
    }

    /// One look: reads the owner's kit-only fact and, when the box has not
    /// acknowledged it in this process, sends its hold, after the boot heal
    /// as a switch's hold goes. Admitted as a background pass and held
    /// through the send.
    pub(crate) fn look_at_kit_only_fact(
        &self,
        vault: &oneiron::Vault,
        admit: &HousekeepingAdmission,
        read: &KitOnlyFactRead,
        follow: &mut KitOnlyFollow,
    ) -> KitOnlyLook {
        let Some(_admitted) = admit() else {
            return KitOnlyLook::NotAdmitted;
        };
        let fact = match read(vault) {
            Ok(Some(fact)) => fact,
            Ok(None) => {
                follow.read_warned = false;
                return KitOnlyLook::NoFact;
            }
            Err(error) => {
                if follow.read_warned {
                    tracing::debug!(
                        kind = ?error.kind(),
                        "the owner's kit-only fact still does not read"
                    );
                } else {
                    tracing::warn!(
                        kind = ?error.kind(),
                        "the owner's kit-only fact did not read; the next look reads it again"
                    );
                    follow.read_warned = true;
                }
                return KitOnlyLook::Unreadable;
            }
        };
        follow.read_warned = false;
        if follow.acknowledged == Some(fact) {
            return KitOnlyLook::Acknowledged;
        }
        // The inherent method: the relay call, past the heal gate.
        match HypnosRecoveryBoxHold::hold_kit_only(self, fact.kit_only) {
            Ok(()) => {
                follow.acknowledged = Some(fact);
                follow.hold_warned = None;
                tracing::info!(
                    kit_only = fact.kit_only,
                    "the recovery box holds the owner's kit-only choice"
                );
                KitOnlyLook::Held {
                    kit_only: fact.kit_only,
                }
            }
            Err(error) => {
                if follow.hold_warned == Some(fact) {
                    tracing::debug!(
                        kind = ?error.kind(),
                        kit_only = fact.kit_only,
                        "the recovery box still does not hold the owner's kit-only choice"
                    );
                } else {
                    tracing::warn!(
                        kind = ?error.kind(),
                        kit_only = fact.kit_only,
                        "the recovery box does not hold the owner's kit-only choice yet; the next look sends it again"
                    );
                    follow.hold_warned = Some(fact);
                }
                KitOnlyLook::Failed
            }
        }
    }

    /// Follows the owner's kit-only fact for the life of this process: one
    /// look at once, then one every `every`, until `stopped` resolves. Each
    /// look, and the wait report after it, runs on a blocking thread, one at
    /// a time, and a stop ends the watch between looks, never during one; a
    /// stop that came before the first look ends it with no look.
    pub(crate) fn follow_kit_only_fact(
        &self,
        vault: Arc<oneiron::Vault>,
        admit: HousekeepingAdmission,
        read: KitOnlyFactRead,
        every: Duration,
        stopped: impl Future<Output = ()> + Send + 'static,
    ) -> tokio::task::JoinHandle<()> {
        // One copy of the client, and so of its spawn token, for every look.
        let hold = Arc::new(self.clone());
        tokio::spawn(async move {
            let mut stopped = std::pin::pin!(stopped);
            let mut follow = (KitOnlyFollow::default(), WaitReportFollow::default());
            // The first look goes at once, but not past a stop that came first.
            let mut wait = Duration::ZERO;
            loop {
                tokio::select! {
                    biased;
                    () = &mut stopped => return,
                    () = tokio::time::sleep(wait) => {}
                }
                wait = every;
                let (hold, vault, admit, read) = (
                    Arc::clone(&hold),
                    Arc::clone(&vault),
                    Arc::clone(&admit),
                    Arc::clone(&read),
                );
                let looked = tokio::task::spawn_blocking(move || {
                    let (mut fact_follow, mut wait_follow) = follow;
                    hold.look_at_kit_only_fact(&vault, &admit, &read, &mut fact_follow);
                    hold.report_wait_when_changed(&vault, &admit, &mut wait_follow);
                    (fact_follow, wait_follow)
                })
                .await;
                follow = match looked {
                    Ok(follow) => follow,
                    Err(error) => {
                        tracing::warn!(
                            panicked = error.is_panic(),
                            "a look at the owner's kit-only fact did not finish; the next look starts afresh"
                        );
                        (KitOnlyFollow::default(), WaitReportFollow::default())
                    }
                };
            }
        })
    }
}
