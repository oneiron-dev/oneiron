//! A vault VM's live look at its outbox carrier (FIX 6683, FIX 6684).
//!
//! The companion's revision is read once at boot. This watch asks the
//! companion again at each look, so `Ping` reports the carrier as it stands:
//! a companion that no longer answers reads as down, with no revision, as a
//! VM without one does. Restarting a companion that ended is the bootstrap's
//! part, not this one's.
//!
//! An escrow recipient the carrier delivers after the engine started is
//! sealed to and spooled at the next look, as a start seals those present
//! then, with no restart; a capsule a spool did not hand over, at a start
//! or a look, goes at a later look. A look is a cadence, not a deadline:
//! one question to the companion is in flight at a time, and one that does
//! not come back leaves the last answer standing.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use oneiron_vault_contract::vm_outbox::VM_GUEST_OUTBOX_DIR;
use tokio::task::JoinHandle;

use super::admission::WriteKind;
use super::boot_keys::{escrow_unspooled, seal_escrow_recipient, spool_escrow_capsules};
use super::{ManagedArgs, ManagedShutdown, ManagedState};

/// How often the engine looks at its outbox companion and at the escrow
/// recipients its carrier holds: the cadence of a look, not a deadline.
const LOOK_EVERY: Duration = Duration::from_secs(5);

/// The escrow recipients a VM's carrier delivers, by role, as the companion
/// lays them out under its outbox's `recipients/`.
const CARRIER_RECIPIENTS: [(&str, &str); 2] = [
    ("managed", "managed.pub"),
    ("break-glass", "break-glass.pub"),
];

/// How the outbox companion stands, as the engine last heard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompanionState {
    /// It answered with its carrier's wire revision.
    Up { revision: u32 },
    /// It did not answer: it never came up, it ended, or its endpoint went.
    Down,
}

impl CompanionState {
    fn of(revision: Option<u32>) -> Self {
        revision.map_or(Self::Down, |revision| Self::Up { revision })
    }
}

/// What the watch has taken of each recipient the carrier holds.
#[derive(Default)]
struct Recipients {
    /// Each role's recipient as last sealed to, or found sealed already.
    sealed: HashMap<&'static str, blake3::Hash>,
    /// Each role's recipient that last did not seal, said once.
    said: HashMap<&'static str, blake3::Hash>,
    /// Each role's recipient whose key wraps a look could not read, said
    /// once per version of it.
    key_wraps_said: HashMap<&'static str, blake3::Hash>,
    /// Whether a spool that did not go through was said, until one does.
    unspooled_said: bool,
}

/// Looks at the companion and, where the engine has an escrow outbox, at
/// the carrier's recipients, every [`LOOK_EVERY`] until `shutdown`.
pub(super) fn spawn(
    state: Arc<ManagedState>,
    vault: Arc<oneiron::Vault>,
    managed: ManagedArgs,
    shutdown: ManagedShutdown,
) {
    let managed = Arc::new(managed);
    tokio::spawn(async move {
        let mut stopped = shutdown.triggered();
        let mut asking = None;
        let mut recipients = Recipients::default();
        loop {
            asking = Some(look_at_companion(&state, asking).await);
            if managed.escrow_outbox.is_some() {
                let (state, vault, managed) =
                    (Arc::clone(&state), Arc::clone(&vault), Arc::clone(&managed));
                let looked = tokio::task::spawn_blocking(move || {
                    seal_carrier_recipients(&state, &vault, &managed, &mut recipients);
                    recipients
                });
                recipients = looked.await.unwrap_or_default();
            }
            tokio::select! {
                () = &mut stopped => return,
                () = tokio::time::sleep(LOOK_EVERY) => {}
            }
        }
    });
}

/// Takes the companion's answer to the question in flight once it came, and
/// asks again; while it is still in flight, the last answer stands and no
/// second question goes.
async fn look_at_companion(
    state: &ManagedState,
    asking: Option<JoinHandle<Option<u32>>>,
) -> JoinHandle<Option<u32>> {
    match asking {
        Some(ask) if !ask.is_finished() => return ask,
        Some(ask) => note_companion(state, ask.await.ok().flatten()),
        None => {}
    }
    tokio::task::spawn_blocking(crate::managed::vm_outbox::companion_revision)
}

/// Keeps the companion's answer for `Ping`, and says when it went down or
/// came up.
fn note_companion(state: &ManagedState, revision: Option<u32>) {
    let was = CompanionState::of(state.set_vm_outbox_revision(revision));
    match CompanionState::of(revision) {
        now if now == was => {}
        CompanionState::Down => tracing::warn!(
            reason = "vm_outbox_companion_down",
            "the vault VM's outbox companion does not answer; Ping reports no carrier until it \
             does, and the outbox keeps its work"
        ),
        CompanionState::Up { revision } => tracing::info!(
            reason = "vm_outbox_companion_up",
            revision,
            "the vault VM's outbox companion answers"
        ),
    }
}

/// Seals the vault's data key to each recipient the carrier holds that the
/// watch has not sealed to, and spools each capsule the outbox does not hold
/// yet, as a start does (FIX 6684): one sealed now, or one an earlier spool
/// did not hand over, which goes again as the same report and is never
/// sealed again. It writes under a background admission, held through each
/// report and its mark, so a vault frozen for reap seals and spools nothing
/// until it thaws. A recipient that does not seal, and a spool that does
/// not go through, is said once and tried again at each look.
fn seal_carrier_recipients(
    state: &ManagedState,
    vault: &oneiron::Vault,
    managed: &ManagedArgs,
    recipients: &mut Recipients,
) {
    let Some(outbox) = managed.escrow_outbox.as_deref() else {
        return;
    };
    let dir = Path::new(VM_GUEST_OUTBOX_DIR).join("recipients");
    let mut fresh = Vec::new();
    for (role, file) in CARRIER_RECIPIENTS {
        let Ok(bytes) = std::fs::read(dir.join(file)) else {
            continue;
        };
        let fingerprint = blake3::hash(&bytes);
        if recipients.sealed.get(role) != Some(&fingerprint) {
            fresh.push((role, fingerprint, bytes));
        }
    }
    if fresh.is_empty() && !escrow_unspooled(vault) {
        return;
    }
    let Some(admitted) = state.admit_background(WriteKind::BackgroundOther) else {
        return;
    };
    if !fresh.is_empty() {
        seal_fresh(vault, fresh, recipients);
    }
    match spool_escrow_capsules(vault, managed, outbox, &mut BTreeSet::new()) {
        Ok(()) => recipients.unspooled_said = false,
        Err(error) => {
            if !std::mem::replace(&mut recipients.unspooled_said, true) {
                tracing::warn!(
                    reason = "vm_escrow_capsule_unspooled",
                    error = %format!("{error:#}"),
                    "an escrow capsule is not spooled yet; the next look spools it, and the \
                     vault serves on"
                );
            }
        }
    }
    drop(admitted);
}

/// Seals the vault's data key to each `fresh` recipient, by role, with its
/// fingerprint and bytes, and notes which sealed. A recipient a look cannot
/// seal, because the seal failed or the key wraps did not read, is said once
/// per version of it; the vault serves on either way.
fn seal_fresh(
    vault: &oneiron::Vault,
    fresh: Vec<(&'static str, blake3::Hash, Vec<u8>)>,
    recipients: &mut Recipients,
) {
    let present = match vault.vault_key_wraps() {
        Ok(present) => present,
        Err(error) => {
            for &(role, fingerprint, _) in &fresh {
                if recipients.key_wraps_said.insert(role, fingerprint) != Some(fingerprint) {
                    tracing::warn!(
                        reason = "vm_escrow_recipient_unsealed",
                        role,
                        %error,
                        "the vault's key wraps do not read; a carrier's escrow recipient waits"
                    );
                }
            }
            return;
        }
    };
    for (role, fingerprint, bytes) in fresh {
        match seal_escrow_recipient(vault, &present, role, &bytes) {
            Ok(_) => {
                recipients.sealed.insert(role, fingerprint);
                recipients.said.remove(role);
                recipients.key_wraps_said.remove(role);
            }
            Err(error) => {
                if recipients.said.insert(role, fingerprint) != Some(fingerprint) {
                    tracing::warn!(
                        reason = "vm_escrow_recipient_unsealed",
                        role,
                        error = %format!("{error:#}"),
                        "an escrow recipient the carrier delivered is not sealed to yet; the \
                         vault serves on"
                    );
                }
            }
        }
    }
}
