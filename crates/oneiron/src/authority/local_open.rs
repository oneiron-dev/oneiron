//! A raw open's own machine profile, from the host's root secret (FIX 4730).
//!
//! The desktop app, N-API and C-FFI open a vault without serving it, so no
//! serving start profiles the install they open. Given the vault's host root
//! secret, such an open enrols this install as `Unanswered` through the same
//! door a serving start uses, so the owner's acts carry from it. Only a new
//! local-origin vault is rooted here, through the
//! existing [`Vault::ensure_host_root_slip`]: never a store that was already
//! there, which may be a replica awaiting its root (CALLS "root-secret
//! raw-open door (l02/rootdoor)"). No machine is ever relabelled the owner's.

use std::path::Path;

use oneiron_keystore::{KeystoreSlot, SlotKind};
use zeroize::Zeroizing;

use crate::Vault;
use crate::error::Result;

use super::machine_identity::{
    SERVING_INSTALL_ROLE, SERVING_NO_ISSUER, SERVING_ROOT_NOT_ISSUER, serving_profile_stands,
};
use super::*;

/// Hook (CALLS "rootdoor open gates", open): an explicit `initialize_root`
/// on the N-API and C-FFI host-root openers roots only a store that open
/// creates, as the desktop's does, so a store a host opened before (a
/// replica awaiting its root among them) never roots on a later open.
const RAW_OPEN_ROOTS_ONLY_A_STORE_IT_CREATES: bool = true;

/// Hook (CALLS "hostroot wrong-root typed fact", open): a host-root open of
/// an install that already carries its profile, given a root that is not
/// the vault's settled root, still opens under the settled root and reports
/// the mismatch ([`LocalOpenProfile::AlreadyCarrying`]`::wrong_root`); it is
/// never refused (Engine 10-19 15:3x). The plain open reaches the same
/// install with no secret, so a refusal would guard nothing. `true` refuses
/// it with the engine's not-the-live-root reason.
const WRONG_ROOT_OPEN_REFUSES: bool = false;

/// What [`Vault::profile_local_open`] did. Every outcome but `Skipped`
/// checked the secret against the vault's settled root; only
/// `AlreadyCarrying` goes on past a mismatch, and it says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalOpenProfile {
    /// No host root secret on this open: the install stays unprofiled, and
    /// the owner's acts refuse "no carrier" here, as before.
    Skipped,
    /// This open rooted a new local-origin vault under the secret's issuer
    /// and enrolled this install in it.
    RootedAndProfiled,
    /// The vault was rooted under the secret's issuer already; this open
    /// enrolled this install.
    Profiled,
    /// A live profile of this install already stood, so nothing was
    /// written. `wrong_root` is the secret's standing, read in the same
    /// snapshot: `true` when its issuer is not this vault's settled live
    /// root (another vault's root, a revoked one, or a root in conflict).
    /// The secret then went unused and the install carries on under the
    /// settled root, as before: the mismatch is a fact for the host to show
    /// or re-key on, never a refusal (`WRONG_ROOT_OPEN_REFUSES`).
    AlreadyCarrying { wrong_root: bool },
    /// No profile of this install stood, and the secret's issuer is not this
    /// vault's settled live root (FIX 8120): nothing was enrolled under it,
    /// nothing was re-rooted, and the vault stays open under its settled
    /// root with this install unprofiled, so the owner's acts refuse "no
    /// carrier" here as on a plain open. The mismatch is reported, never
    /// refused (`WRONG_ROOT_OPEN_REFUSES`); possession of the open grants no
    /// owner rights.
    UnprofiledWrongRoot,
}

impl LocalOpenProfile {
    /// Whether this open was given a root that is not the vault's settled
    /// root, which it did not use: only an `AlreadyCarrying` open says so.
    #[must_use]
    pub const fn wrong_root(self) -> bool {
        matches!(
            self,
            Self::AlreadyCarrying { wrong_root: true } | Self::UnprofiledWrongRoot
        )
    }
}

impl Vault {
    /// Whether `path` names no vault yet: absent, or an empty directory.
    /// Read before an open that may create the store, it tells an open that
    /// brings a store into existence from one over a store that was there
    /// already. Anything it cannot read counts as started.
    #[must_use]
    pub fn is_unstarted_vault_dir(path: &Path) -> bool {
        match std::fs::read_dir(path) {
            Ok(mut entries) => entries.next().is_none(),
            Err(error) => error.kind() == std::io::ErrorKind::NotFound,
        }
    }

    /// Read before a host-root open of `path` (N-API, C-FFI): whether its
    /// explicit `initialize_root` may root what it opens.
    #[must_use]
    pub fn host_root_open_may_root(path: &Path, initialize_root: bool) -> bool {
        initialize_root
            && (!RAW_OPEN_ROOTS_ONLY_A_STORE_IT_CREATES || Self::is_unstarted_vault_dir(path))
    }

    /// Profiles this install under the vault's host root, for an open that
    /// serves nothing (FIX 4730), given the host root `secret` that admits
    /// it. No secret is a skip. The root signs with this install's own
    /// issuer seed for the vault (FIX-LIST 3018), never one the secret
    /// derives. With `initialize_root`, a vault whose authority is unstarted
    /// (no log row, no pin, no adopted checkpoint) is rooted first through
    /// [`Self::ensure_host_root_slip`], once this install's keys load and
    /// its seed is drawn ([`Self::bootstrap_host_slip_issuer`]); the caller
    /// sets it only for a store its own open created as a new local-origin
    /// vault. Any other open loads the seed it holds
    /// ([`Self::load_host_slip_issuer`]), once an empty slot took back the
    /// vault's escrowed seed of its live root, where custody holds one
    /// ([`Self::prepare_host_issuer_custody_logged`], FIX-LIST 10770). Then
    /// [`Self::ensure_serving_install_profile`] as `Unanswered`, whose
    /// refusals come back with their reason. Over a profile that already
    /// stands, an issuer that is not the vault's settled root is reported in
    /// `AlreadyCarrying`, not refused.
    /// A root committed before a refused profile stays, and is never minted
    /// again.
    pub fn profile_local_open(
        &self,
        secret: Option<&[u8]>,
        initialize_root: bool,
    ) -> Result<LocalOpenProfile> {
        let Some(secret) = secret else {
            return Ok(LocalOpenProfile::Skipped);
        };
        // An empty secret admits nothing, as before the seed moved out of it.
        if secret.is_empty() {
            return Err(invalid_authority());
        }
        let rooted = initialize_root && self.authority_is_unstarted()?;
        let issuer = if rooted {
            // A root this install could not carry is never minted.
            self.prepare_install_signing()?;
            let issuer = self.bootstrap_host_slip_issuer()?;
            self.ensure_host_root_slip(&issuer)?;
            issuer
        } else {
            // Never a refusal: a mismatch or a fault is warned, and the load
            // answers as before.
            self.prepare_host_issuer_custody_logged();
            match self.load_host_slip_issuer() {
                Ok(issuer) => issuer,
                // No issuer of this vault on this install: over a profile
                // that already stands, the open carries on under the settled
                // root and says so, as a wrong root does; with none, the
                // missing key comes back as the reason.
                Err(error) => {
                    if !self.install_profile_stands().unwrap_or(false) {
                        return Err(error);
                    }
                    if WRONG_ROOT_OPEN_REFUSES {
                        return Err(authority_refused(SERVING_ROOT_NOT_ISSUER));
                    }
                    return Ok(LocalOpenProfile::AlreadyCarrying { wrong_root: true });
                }
            }
        };
        let stood = match self.ensure_install_profile_reporting(&issuer, SERVING_INSTALL_ROLE) {
            Ok((_, stood)) => stood,
            Err(error) if !rooted && unprofiled_wrong_root(&error) => {
                if WRONG_ROOT_OPEN_REFUSES {
                    return Err(error);
                }
                return Ok(LocalOpenProfile::UnprofiledWrongRoot);
            }
            Err(error) => return Err(error),
        };
        Ok(match (rooted, stood) {
            (true, _) => LocalOpenProfile::RootedAndProfiled,
            (false, None) => LocalOpenProfile::Profiled,
            (false, Some(issuer_is_root)) => {
                if !issuer_is_root && WRONG_ROOT_OPEN_REFUSES {
                    return Err(authority_refused(SERVING_ROOT_NOT_ISSUER));
                }
                LocalOpenProfile::AlreadyCarrying {
                    wrong_root: !issuer_is_root,
                }
            }
        })
    }

    /// [`Self::profile_local_open`], logged with its reason under `open`: a
    /// skip or a profile at debug, a wrong root or a refusal as a warning.
    /// The caller decides whether the open goes on.
    pub fn profile_local_open_logged(
        &self,
        secret: Option<&[u8]>,
        initialize_root: bool,
        open: &'static str,
    ) -> Result<LocalOpenProfile> {
        let outcome = self.profile_local_open(secret, initialize_root);
        match &outcome {
            Ok(LocalOpenProfile::Skipped) => {
                tracing::debug!(
                    open,
                    reason = SERVING_NO_ISSUER,
                    "no machine profile ensured"
                );
            }
            Ok(LocalOpenProfile::UnprofiledWrongRoot) => tracing::warn!(
                open,
                reason = SERVING_ROOT_NOT_ISSUER,
                "this open's host root is not the vault's settled root, so it went unused; \
                 this install stays unprofiled under the settled root"
            ),
            Ok(profile) if profile.wrong_root() => tracing::warn!(
                open,
                reason = SERVING_ROOT_NOT_ISSUER,
                "this open's host root is not the vault's settled root, so it went unused; \
                 this install's standing profile carries on under the settled root"
            ),
            Ok(profile) => tracing::debug!(open, ?profile, "this install's machine profile stands"),
            Err(error) => tracing::warn!(
                open,
                kind = ?error.kind(),
                reason = %error,
                "this open did not profile the install, so the owner's acts refuse \
                 \"no carrier\" here until a profile stands"
            ),
        }
        outcome
    }

    /// This install's retained host root secret for this vault: its
    /// this-device-only `HostRoot` keystore slot, `None` while empty.
    /// `create` fills an empty slot with a fresh secret first, only for a
    /// new local-origin vault this install roots itself with no configured
    /// secret (the desktop's own vault). Never device-key residue.
    pub fn retained_host_root_secret(&self, create: bool) -> Result<Option<Zeroizing<[u8; 32]>>> {
        let keystore = self.device_keystore()?;
        let machine = self.prepare_install_signing()?;
        let slot = KeystoreSlot {
            vault_id: *self.vault_id().as_bytes(),
            install: *machine.as_bytes(),
            kind: SlotKind::HostRoot,
        };
        if create {
            return crate::world_keys::slot_seed(keystore.as_ref(), &slot).map(Some);
        }
        keystore
            .get(&slot)
            .map_err(crate::world_keys::keystore_error)
    }

    /// Whether this install's own live carrier profile, naming both its
    /// keys, stands here, as the profile door reads it. Writes nothing.
    fn install_profile_stands(&self) -> Result<bool> {
        let Some(vault_id) = self.authority_fold()?.vault_id else {
            return Ok(false);
        };
        let encryption_key = self.machine_encryption_key(vault_id)?;
        let request = self.machine_enrolment_request(vault_id, encryption_key)?;
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        Ok(fold
            .machine(request.machine)
            .is_some_and(|folded| serving_profile_stands(&fold, folded, &request)))
    }

    /// No authority log row, no pin and no adopted checkpoint: a vault no
    /// root, replica or restore has reached. Never `vault_id == None`, which
    /// a conflicted or invalid history has too.
    pub(super) fn authority_is_unstarted(&self) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        if !authority_log_rows_in_txn(&self.store, &txn)?.is_empty() {
            return Ok(false);
        }
        let pin = super::pinned_root::read_pin_row_in_txn(&self.store, &txn)?;
        if pin.pin.is_some() || pin.awaiting.is_some() {
            return Ok(false);
        }
        Ok(adopted_authority_checkpoint_in_txn(&self.store, &txn)?.is_none())
    }
}

/// Whether `error` is the profile door's refusal of an issuer that is not
/// the vault's settled live root over an install no profile of stands: the
/// one refusal a host-root open reports as [`LocalOpenProfile::UnprofiledWrongRoot`]
/// (FIX 8120). Every other refusal, storage fault included, stays itself.
fn unprofiled_wrong_root(error: &crate::error::Error) -> bool {
    matches!(
        error,
        crate::error::Error::Record(crate::error::RecordError::AuthorityRefused(reason))
            if *reason == SERVING_ROOT_NOT_ISSUER
    )
}
