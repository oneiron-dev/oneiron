//! The embedded half of [`crate::OneironClient::open_with_host_root`]
//! (FIX 4730): the shared open, then this install's own machine profile from
//! the vault's host root secret, through the core door a raw host-root open
//! uses, then the normal actor binding.
//!
//! The secret is borrowed for this call only. It never enters
//! [`OpenOptions`], the [`SharedVault`] or the registry, so it takes no part
//! in the I9 same-vault test, and the issuer derived from it is dropped
//! (zeroized) before the handle returns. The handle gets no owner proof, no
//! root signer and no actor beyond the generic embedded owner every open
//! binds: the open only profiles the install, as `Unanswered`.

use std::path::Path;

use oneiron::authority::{AuthorityTier, LocalOpenProfile, ROLE_CLOUD};
use oneiron::memory::MemoryError;
use oneiron::{EdgeActorClass, HostingPrivacyPosture, Vault};

use super::{EmbeddedClient, SharedVault, open_shared};
use crate::error::{bad_request, forbidden};
use crate::{HostRootProfile, OpenOptions};

/// Hook (CALLS "hostroot SDK factory shape", open): the SDK host-root open
/// is rooted-only. It profiles an install of a vault already rooted, and
/// never roots a store, so it has no `initializeRoot`; the raw N-API and
/// C-FFI openers keep theirs.
const SDK_HOST_ROOT_OPEN_ROOTS: bool = false;

/// Hook (CALLS "hostroot hosted guard", open): the SDK host-root open is an
/// owner-local convenience. It refuses a vault open under the managed or
/// relay posture, and a given root whose roster row the log marks as the
/// provider's (`ROLE_CLOUD` or `CloudCustodial`), whatever posture the opener
/// chose. A managed host profiles its own node at serving start, and its
/// owner acts through his credential.
const SDK_HOST_ROOT_REFUSES_HOSTED: bool = true;

impl EmbeddedClient {
    /// [`Self::open`], with this install profiled from `host_root_secret`
    /// on every call, a registry join included. A refusal fails the open
    /// with its reason, and no handle returns; a store the shared open
    /// created stays, as a plain open's would. Over a profile that already
    /// stands, a secret that is not the vault's settled root is reported in
    /// the profile, never refused.
    pub(crate) fn open_with_host_root(
        path: Option<&Path>,
        options: &OpenOptions,
        host_root_secret: &[u8],
    ) -> Result<(Self, HostRootProfile), MemoryError> {
        if host_root_secret.is_empty() {
            return Err(bad_request(
                "the host root secret is empty",
                &["Pass the vault's host root secret, or open without one to stay unprofiled."],
            ));
        }
        let shared = open_shared(path, options)?;
        if SDK_HOST_ROOT_REFUSES_HOSTED {
            refuse_hosted_root(&shared)?;
        }
        let profile = shared
            .vault()
            .profile_local_open(Some(host_root_secret), SDK_HOST_ROOT_OPEN_ROOTS)?;
        let actor = shared.vault().ensure_embedded_owner_actor()?;
        let client = Self {
            shared,
            actor,
            actor_class: EdgeActorClass::Human,
            room_turn: None,
            off_record_session: None,
            host_open: None,
            read_proof: None,
        };
        Ok((client, HostRootProfile::from_core(profile)))
    }
}

impl HostRootProfile {
    /// The SDK's projection of what the core door did. `Skipped` and
    /// `RootedAndProfiled` never come back here: the open always names a
    /// secret, and never roots.
    const fn from_core(profile: LocalOpenProfile) -> Self {
        match profile {
            LocalOpenProfile::Profiled | LocalOpenProfile::RootedAndProfiled => Self {
                enrolled: true,
                wrong_root: false,
            },
            LocalOpenProfile::AlreadyCarrying { wrong_root } => Self {
                enrolled: false,
                wrong_root,
            },
            // No profile stood and the given root is not the settled one:
            // nothing was enrolled, and the open stands under the settled
            // root (FIX 8120).
            LocalOpenProfile::UnprofiledWrongRoot => Self {
                enrolled: false,
                wrong_root: true,
            },
            LocalOpenProfile::Skipped => Self {
                enrolled: false,
                wrong_root: false,
            },
        }
    }
}

/// Refuses a managed or relay posture, and a given root the log marks as the
/// provider's, naming why. Marks are read as the fold holds them, never
/// relabelled: a hosted root is stamped `ROLE_CLOUD` and `CloudCustodial`
/// when it is minted, and the opener's local default does not erase that.
fn refuse_hosted_root(shared: &SharedVault) -> Result<(), MemoryError> {
    let vault: &Vault = shared.vault();
    match vault.privacy_posture() {
        HostingPrivacyPosture::SelfHostLocal => {}
        posture @ (HostingPrivacyPosture::Hosted | HostingPrivacyPosture::Relay) => {
            return Err(forbidden(
                format!(
                    "this vault is open under the {} posture, so this owner-local host-root \
                     open does not profile its install",
                    posture.as_str()
                ),
                &[
                    "A managed host profiles its own node when it starts serving; the owner \
                     acts through his credential.",
                    "Works self-hosted: open the vault on the owner's own machine with its host \
                     root secret.",
                ],
            ));
        }
    }
    // The root this install signs with is its own issuer seed for the
    // vault (FIX-LIST 3018), not one the secret derives. With none here the
    // profile door after this guard answers for the missing key.
    let Ok(issuer) = vault.load_host_slip_issuer() else {
        return Ok(());
    };
    let fold = vault.authority_fold()?;
    let provider_held = fold.roster.get(&issuer.public_key()).is_some_and(|row| {
        row.roles & ROLE_CLOUD != 0 || row.tier == AuthorityTier::CloudCustodial
    });
    if provider_held {
        return Err(forbidden(
            "the given host root is a hosted root the provider holds, so this owner-local \
             host-root open does not profile an install with it",
            &[
                "A managed host profiles its own node when it starts serving; the owner acts \
                 through his credential.",
                "Works self-hosted: open with the root secret of a vault the owner roots himself.",
            ],
        ));
    }
    Ok(())
}
