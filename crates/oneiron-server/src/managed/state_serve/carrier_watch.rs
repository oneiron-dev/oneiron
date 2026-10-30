//! A vault VM's live look at its outbox carrier (FIX 6683, FIX 6684).
//!
//! The companion's revision is read once at boot. This watch asks the
//! companion again at each look, so `Ping` reports the carrier as it stands:
//! a companion that no longer answers reads as down, with no revision, as a
//! VM without one does. Restarting a companion that ended is the bootstrap's
//! part, not this one's.
//!
//! Each copy the carrier keeps of a member it never agreed on, as the
//! member's origin retired the agreed version, raises one owner ask, remove
//! or keep, at the look that first finds it waiting, and its ask is cleared
//! at the look that finds it answered or gone ([`diverged_ask`], FIX 11074).
//!
//! An escrow recipient the carrier delivers after the engine started is
//! sealed to at the next look, as a start seals those present then, with
//! no restart, whether or not the engine has an escrow outbox (FIX 11078).
//! Where it has one, the capsule is spooled too, and a capsule a spool did
//! not hand over, at a start or a look, goes at a later look; with none, it
//! stays in the vault unspooled, as a start's does. A cold restore's check
//! reads the same files ([`carrier_recipient`]), and the first look runs
//! the check's plan check again before it seals, so a recipient swapped in
//! between waits unsealed while it stands (FIX 11851). A process host's argv
//! recipient files get the same late seal ([`spawn_argv_watch`], FIX 11852).
//! A look is a cadence, not a deadline: one question to the companion is in
//! flight at a time, and one that does not come back leaves the last answer
//! standing.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use oneiron_vault_contract::restore::{EscrowRole, FreshRecipient};
use oneiron_vault_contract::vm_outbox::VM_GUEST_OUTBOX_DIR;
use tokio::task::JoinHandle;

use self::diverged_ask::DivergedAsks;
use super::admission::WriteKind;
use super::boot_keys::{escrow_unspooled, seal_escrow_recipient, spool_escrow_capsules};
use super::{ManagedArgs, ManagedShutdown, ManagedState};
use crate::managed::restore::fresh_authorizes;

mod diverged_ask;

/// How often the engine looks at its outbox companion and at the escrow
/// recipients its carrier holds: the cadence of a look, not a deadline.
const LOOK_EVERY: Duration = Duration::from_secs(5);

/// The file a VM's carrier delivers `role`'s escrow recipient in, as the
/// companion lays the recipients out under its outbox's `recipients/`:
/// read as it stands at each look, and by a cold restore's check.
pub(in crate::managed) fn carrier_recipient(role: EscrowRole) -> PathBuf {
    let file = match role {
        EscrowRole::Managed => "managed.pub",
        EscrowRole::BreakGlass => "break-glass.pub",
    };
    Path::new(VM_GUEST_OUTBOX_DIR).join("recipients").join(file)
}

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

/// What the watch has taken of each recipient the watched files hold.
#[derive(Default)]
struct Recipients {
    /// Each role's recipient as last sealed to, or found sealed already.
    sealed: HashMap<&'static str, blake3::Hash>,
    /// Each role's recipient that last did not seal, said once.
    said: HashMap<&'static str, blake3::Hash>,
    /// Each role's recipient whose key wraps a look could not read, said
    /// once per version of it.
    key_wraps_said: HashMap<&'static str, blake3::Hash>,
    /// Each role's recipient the first look refused as outside the cold
    /// restore's plan, said once and held while it stands (FIX 11851): a
    /// recipient swapped in between the begin-check and the first look is
    /// never sealed; a new delivery seals at a later look as a late arrival.
    unplanned: HashMap<&'static str, blake3::Hash>,
    /// Whether a spool that did not go through was said, until one does.
    unspooled_said: bool,
}

/// Looks at the companion and at the carrier's recipients every
/// [`LOOK_EVERY`] until `shutdown`. `restore_fresh` is a cold restore's
/// fresh recipients: the first look seals only to those (FIX 11851);
/// `None` without a restore, and the first look is then unplanned as
/// every later one is.
pub(super) fn spawn(
    state: Arc<ManagedState>,
    vault: Arc<oneiron::Vault>,
    managed: ManagedArgs,
    shutdown: ManagedShutdown,
    restore_fresh: Option<Vec<FreshRecipient>>,
) {
    let managed = Arc::new(managed);
    tokio::spawn(async move {
        let mut stopped = shutdown.triggered();
        let mut asking = None;
        let mut recipients = Recipients::default();
        let mut asks: Option<JoinHandle<DivergedAsks>> = None;
        let mut plan_check = restore_fresh;
        loop {
            asking = Some(look_at_companion(&state, asking).await);
            asks = Some(look_at_diverged(&state, &vault, asks).await);
            let plan = plan_check.take();
            let (state, vault, managed) =
                (Arc::clone(&state), Arc::clone(&vault), Arc::clone(&managed));
            let looked = tokio::task::spawn_blocking(move || {
                let files = [EscrowRole::Managed, EscrowRole::BreakGlass]
                    .map(|role| (role, carrier_recipient(role)));
                seal_watched_recipients(
                    &state,
                    &vault,
                    &managed,
                    &mut recipients,
                    &files,
                    plan.as_deref(),
                );
                recipients
            });
            recipients = looked.await.unwrap_or_default();
            tokio::select! {
                () = &mut stopped => return,
                () = tokio::time::sleep(LOOK_EVERY) => {}
            }
        }
    });
}

/// Looks at a process host's argv escrow recipient files every [`LOOK_EVERY`]
/// until `shutdown` (FIX 11852): a file replaced after the start seals at
/// the next look, as the carrier's late recipients do, on the same
/// [`seal_watched_recipients`], with the spool a start runs where the engine
/// has an outbox. `restore_fresh` gates the first look on the cold
/// restore's plan exactly as [`spawn`]'s does.
pub(super) fn spawn_argv_watch(
    state: Arc<ManagedState>,
    vault: Arc<oneiron::Vault>,
    managed: ManagedArgs,
    shutdown: ManagedShutdown,
    restore_fresh: Option<Vec<FreshRecipient>>,
) {
    let files: Vec<(EscrowRole, PathBuf)> = [
        (EscrowRole::Managed, managed.escrow_recipient.clone()),
        (
            EscrowRole::BreakGlass,
            managed.break_glass_recipient.clone(),
        ),
    ]
    .into_iter()
    .filter_map(|(role, path)| path.map(|path| (role, path)))
    .collect();
    let managed = Arc::new(managed);
    tokio::spawn(async move {
        let mut stopped = shutdown.triggered();
        let mut recipients = Recipients::default();
        let mut plan_check = restore_fresh;
        loop {
            let plan = plan_check.take();
            let (state, vault, managed, files) = (
                Arc::clone(&state),
                Arc::clone(&vault),
                Arc::clone(&managed),
                files.clone(),
            );
            let looked = tokio::task::spawn_blocking(move || {
                seal_watched_recipients(
                    &state,
                    &vault,
                    &managed,
                    &mut recipients,
                    &files,
                    plan.as_deref(),
                );
                recipients
            });
            recipients = looked.await.unwrap_or_default();
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

/// Takes the diverged copies' look in flight once it ended, and starts the
/// next; while it is still in flight, no second one starts.
async fn look_at_diverged(
    state: &Arc<ManagedState>,
    vault: &Arc<oneiron::Vault>,
    looking: Option<JoinHandle<DivergedAsks>>,
) -> JoinHandle<DivergedAsks> {
    let asks = match looking {
        Some(look) if !look.is_finished() => return look,
        Some(look) => look.await.unwrap_or_default(),
        None => DivergedAsks::default(),
    };
    let (state, vault) = (Arc::clone(state), Arc::clone(vault));
    tokio::task::spawn_blocking(move || asks.look(&state, &vault))
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

/// Seals the vault's data key to each watched recipient file's bytes that
/// the watch has not sealed to: a VM's carrier files, or a process host's
/// argv files (FIX 11078, FIX 11852). With or without an escrow outbox,
/// and, where the engine has one, spools each capsule it does not hold yet,
/// as a start does (FIX 6684): one sealed now, or one an earlier spool did
/// not hand over, which goes again as the same report and is never sealed
/// again. With no outbox a capsule stays unspooled in the vault, as a
/// start leaves it. `plan` is a cold restore's fresh recipients, passed on
/// the first look only: bytes outside it are a swap (or a torn read) in
/// between the begin-check, which read these same files, and this look, so
/// they are said once and held unsealed while they stand, and a new
/// delivery seals at a later look as a late arrival (FIX 11851). It writes
/// under a background admission, held through each report and its mark, so
/// a vault frozen for reap seals and spools nothing until it thaws. A
/// recipient that does not seal, and a spool that does not go through, is
/// said once and tried again at each look.
fn seal_watched_recipients(
    state: &ManagedState,
    vault: &oneiron::Vault,
    managed: &ManagedArgs,
    recipients: &mut Recipients,
    files: &[(EscrowRole, PathBuf)],
    plan: Option<&[FreshRecipient]>,
) {
    let mut fresh = Vec::new();
    for (role, path) in files {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let label = role.label_prefix();
        let fingerprint = blake3::hash(&bytes);
        if let Some(plan) = plan
            && !fresh_authorizes(plan, *role, &bytes)
        {
            if recipients.unplanned.insert(label, fingerprint) != Some(fingerprint) {
                tracing::warn!(
                    reason = "escrow_recipient_unplanned",
                    role = label,
                    path = %path.display(),
                    "an escrow recipient outside the cold restore's plan is not sealed to; it \
                     waits while it stands, and a new delivery seals at a later look"
                );
            }
            continue;
        }
        if recipients.unplanned.get(label) == Some(&fingerprint) {
            continue;
        }
        if recipients.sealed.get(label) != Some(&fingerprint) {
            fresh.push((label, fingerprint, bytes));
        }
    }
    let outbox = managed.escrow_outbox.as_deref();
    let unspooled = outbox.is_some() && escrow_unspooled(vault);
    if fresh.is_empty() && !unspooled {
        return;
    }
    let Some(admitted) = state.admit_background(WriteKind::BackgroundOther) else {
        return;
    };
    if !fresh.is_empty() {
        seal_fresh(vault, fresh, recipients);
    }
    if let Some(outbox) = outbox {
        match spool_escrow_capsules(vault, managed, outbox, &mut BTreeSet::new()) {
            Ok(()) => recipients.unspooled_said = false,
            Err(error) => {
                if !std::mem::replace(&mut recipients.unspooled_said, true) {
                    tracing::warn!(
                        reason = "vm_escrow_capsule_unspooled",
                        error = %format!("{error:#}"),
                        "an escrow capsule is not spooled yet; the next look spools it, and \
                         the vault serves on"
                    );
                }
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
