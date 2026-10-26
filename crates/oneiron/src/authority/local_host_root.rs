//! Re-keying this install's host root (FIX 5571, the re-key half of FIX
//! 5346; owner ruling FIX 5341 = A).
//!
//! A wrong-root open stays reported, never refused
//! (`WRONG_ROOT_OPEN_REFUSES` in `local_open`). Re-keying is the owner's
//! explicit act, never automatic: he supplies the settled root's issuer
//! seed (FIX-LIST 3018: the root signs with that independent seed, never
//! with a key a configured secret derives), these doors check it against
//! the root that stands and this install, and the host keeps it where its
//! next open reads it. Nothing here changes the vault's root, its
//! authority, this install's machine keys, its recovery pin or its
//! standing: no Genesis is minted, no authority row is written, and the
//! validator writes nothing to the vault. The one write is the in-place
//! keystore replace of this install's `HostIssuerSeed` slot. No secret byte
//! is returned, logged or named in an error.

use oneiron_keystore::KeystoreError;

use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::{EntityId, Vault};

use super::machine_identity::serving_profile_stands;
use super::slip_vault::require_host;
use super::*;

/// The vault has no single settled root: none yet, or one in conflict.
const REKEY_NO_SETTLED_ROOT: &str = "the vault has no settled root to re-key this install to";
/// This install never minted its machine identity in this vault.
const REKEY_NO_INSTALL: &str = "this install has no machine identity in this vault yet";
/// The host installed no keystore, or this install's keys did not load.
const REKEY_KEYS_NOT_LOADED: &str =
    "this install's keys are not loaded here, so its standing cannot be checked";
/// The root or the install moved since the context was shown.
const REKEY_CHANGED: &str =
    "the vault's root or this install is no longer what the re-key showed; prepare it again";
/// No live carrier profile of this install names both its keys.
const REKEY_INSTALL_NOT_CARRYING: &str =
    "this install's own machine profile does not stand here, so there is no install to re-key";
/// The replacement's issuer is not a live owner key of the settled root.
const REKEY_NOT_THE_ROOT: &str =
    "the replacement is not the secret of the vault's settled live root; nothing is kept";

/// The public facts a re-key shows before the owner supplies a secret, and
/// binds his confirmation to: [`Vault::local_host_root_context`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalHostRootContext {
    /// The vault id the settled root roots (its authority vault id).
    pub vault_id: AuthorityVaultId,
    /// This install's machine.
    pub install: EntityId,
}

/// A replacement secret that validated, as public facts only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalHostRootValidated {
    /// What the owner was shown, unchanged when the check ran.
    pub context: LocalHostRootContext,
    /// The replacement's root binding key: a live owner key of the settled
    /// root, which the seed derives.
    pub root_key: [u8; 32],
}

/// What [`Vault::replace_retained_host_root_secret`] did with this install's
/// `HostIssuerSeed` slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetainedHostRootReplace {
    /// The slot now holds the validated seed, replaced in place.
    Replaced(LocalHostRootValidated),
    /// The slot was empty, so nothing was written: a replace never fills one.
    Empty,
    /// This device's keystore cannot replace a slot in one operation, so
    /// nothing was written; the reason names the keystore, never the secret.
    Unsupported(&'static str),
}

impl Vault {
    /// The settled root's vault id and this install's machine, read in one
    /// snapshot, for a host to show before the owner re-keys this install.
    /// Refuses when the vault has no single settled root or this install
    /// has no machine identity. Writes nothing.
    pub fn local_host_root_context(&self) -> Result<LocalHostRootContext> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let vault_id = settled_vault_id(&fold)?;
        let install = crate::identity::read_machine_id_in_txn(self, &txn)?
            .ok_or_else(|| authority_refused(REKEY_NO_INSTALL))?;
        Ok(LocalHostRootContext { vault_id, install })
    }

    /// Checks `replacement`, a host issuer seed the owner supplied for this
    /// install, before any host keeps it. In one snapshot: `owner` is still
    /// a live owner of this vault; the settled root and this install are the
    /// ones `shown` names; this install's own carrier profile stands, naming
    /// both its keys (the check the profile door makes,
    /// [`Vault::ensure_serving_install_profile`]); and the seed's issuer
    /// ([`HostSlipIssuer::from_seed`]) is a live owner key of that settled
    /// root (the check a host-root open and slip issuance make). A
    /// replacement that is not a seed's length is not the root. Writes
    /// nothing to the vault, mints no root and changes no authority.
    pub fn validate_local_host_root_replacement(
        &self,
        owner: &AuthenticatedOwner,
        shown: &LocalHostRootContext,
        replacement: &[u8],
    ) -> Result<LocalHostRootValidated> {
        let seed: &[u8; HOST_ISSUER_SEED_BYTES] = replacement
            .try_into()
            .map_err(|_| authority_refused(REKEY_NOT_THE_ROOT))?;
        let issuer = HostSlipIssuer::from_seed(seed)?;
        match self.loaded_install_signer() {
            None => return Err(authority_refused(REKEY_KEYS_NOT_LOADED)),
            Some(signer) if signer.machine != shown.install => {
                return Err(authority_refused(REKEY_CHANGED));
            }
            Some(_) => {}
        }
        // What was shown must still stand before this install's keys are
        // read for that vault id: a stale or foreign id reads no key slot.
        if self.local_host_root_context()? != *shown {
            return Err(authority_refused(REKEY_CHANGED));
        }
        // This install's identity, read and signed outside the snapshot, as
        // the profile door reads it.
        let encryption_key = self.machine_encryption_key(shown.vault_id)?;
        let request = self.machine_enrolment_request(shown.vault_id, encryption_key)?;
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        if settled_vault_id(&fold)? != shown.vault_id || request.machine != shown.install {
            return Err(authority_refused(REKEY_CHANGED));
        }
        if !fold
            .machine(request.machine)
            .is_some_and(|folded| serving_profile_stands(&fold, folded, &request))
        {
            return Err(authority_refused(REKEY_INSTALL_NOT_CARRYING));
        }
        require_host(&fold, &issuer).map_err(|_| authority_refused(REKEY_NOT_THE_ROOT))?;
        Ok(LocalHostRootValidated {
            context: *shown,
            root_key: issuer.binding_key(),
        })
    }

    /// Replaces this install's `HostIssuerSeed` slot, the one
    /// [`Vault::load_host_slip_issuer`] reads, with `replacement`, once
    /// [`Self::validate_local_host_root_replacement`] passes, through the
    /// keystore's in-place replace: never delete then create. An empty slot
    /// stays empty, and a keystore with no in-place update writes nothing;
    /// both are answers, not errors. The vault itself is not written.
    pub fn replace_retained_host_root_secret(
        &self,
        owner: &AuthenticatedOwner,
        shown: &LocalHostRootContext,
        replacement: &[u8; 32],
    ) -> Result<RetainedHostRootReplace> {
        let validated = self.validate_local_host_root_replacement(owner, shown, replacement)?;
        self.device_keystore()?;
        match self.replace_host_issuer_seed(validated.context.install, replacement) {
            Ok(true) => {
                tracing::info!(
                    "the owner replaced this install's retained host root in place; \
                     the vault's root and this install's standing are unchanged"
                );
                Ok(RetainedHostRootReplace::Replaced(validated))
            }
            Ok(false) => Ok(RetainedHostRootReplace::Empty),
            Err(KeystoreError::Unsupported(reason)) => {
                Ok(RetainedHostRootReplace::Unsupported(reason))
            }
            Err(error) => Err(crate::world_keys::keystore_error(error)),
        }
    }
}

/// The vault id of the fold's one settled root, or the refusal.
fn settled_vault_id(fold: &AuthorityFold) -> Result<AuthorityVaultId> {
    match fold.vault_id {
        Some(vault_id) if !fold.vault_root_is_conflicted() => Ok(vault_id),
        _ => Err(authority_refused(REKEY_NO_SETTLED_ROOT)),
    }
}
