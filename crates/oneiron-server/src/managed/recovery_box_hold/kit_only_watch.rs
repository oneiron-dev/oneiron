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

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

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

/// Reads the vault's latest kit-only fact: `None` when the owner never
/// switched.
pub type KitOnlyFactRead =
    Arc<dyn Fn(&oneiron::Vault) -> oneiron::Result<Option<KitOnlyFact>> + Send + Sync>;

/// The fold's reader of the kit-only fact, which managed boot passes. The
/// fact and its fold reader belong to the preset switch (OPUS-WAYBACK's fact
/// PR). No switch writes the fact before that PR lands, so until then this
/// answers `None` and the node sends no hold for a device's switch, as
/// before.
pub(crate) fn fold_kit_only_fact() -> KitOnlyFactRead {
    Arc::new(|_vault: &oneiron::Vault| -> oneiron::Result<Option<KitOnlyFact>> { Ok(None) })
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

impl HypnosRecoveryBoxHold {
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
    /// look runs on a blocking thread, one at a time, and a stop ends the
    /// watch between looks, never during one.
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
            let mut follow = KitOnlyFollow::default();
            loop {
                let (hold, vault, admit, read) = (
                    Arc::clone(&hold),
                    Arc::clone(&vault),
                    Arc::clone(&admit),
                    Arc::clone(&read),
                );
                let looked = tokio::task::spawn_blocking(move || {
                    let mut follow = follow;
                    hold.look_at_kit_only_fact(&vault, &admit, &read, &mut follow);
                    follow
                })
                .await;
                follow = match looked {
                    Ok(follow) => follow,
                    Err(error) => {
                        tracing::warn!(
                            panicked = error.is_panic(),
                            "a look at the owner's kit-only fact did not finish; the next look starts afresh"
                        );
                        KitOnlyFollow::default()
                    }
                };
                tokio::select! {
                    biased;
                    () = &mut stopped => return,
                    () = tokio::time::sleep(every) => {}
                }
            }
        })
    }
}
