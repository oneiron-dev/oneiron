//! `Oneiron.open_with_host_root` (FIX 4730): `Oneiron.open`, then this
//! install's own machine profile from the vault's host root secret, through
//! the shared client's rooted-only `open_with_host_root`.
//!
//! The secret crosses as its own parameter, never a field of
//! [`OpenOptions`], and this binding's copy of it is zeroized when the call
//! returns. The foreign caller's own `Data` stays the caller's to clear.

use std::sync::Arc;

use zeroize::Zeroizing;

use crate::codec::Lower;
use crate::{Oneiron, OneironError, OpenOptions};

/// What `open_with_host_root` did with the host root it was given.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct HostRootProfile {
    /// This open enrolled this install as an `Unanswered` machine; false
    /// when its live profile already stood, and nothing was written.
    pub enrolled: bool,
    /// The given root is not this vault's settled root, so it went unused:
    /// the handle stands under the settled root as before. Reported, never
    /// refused, so the app can show it or re-key. Never with `enrolled`.
    pub wrong_root: bool,
}

#[uniffi::export]
impl Oneiron {
    /// `open`, then this install's own machine profile from the vault's
    /// host root secret, so the owner's acts carry from it.
    ///
    /// `host_root_secret` is the secret's exact bytes (a server's configured
    /// `auth_secret` as its UTF-8, or a retained root), never an encoding of
    /// them. Rooted-only: the vault must already be rooted, and nothing here
    /// roots it. An empty secret fails `BAD_REQUEST`; a vault open under the
    /// managed or relay posture, or a root the provider holds, fails
    /// `FORBIDDEN`; a secret that cannot profile the install fails with the
    /// engine's reason, and `open` stays the rootless door. A secret that is
    /// not the vault's settled root, over a profile that already stands,
    /// opens and says so in `host_root_profile`. The handle binds the
    /// embedded owner actor, as `open` does, and carries no owner proof.
    #[uniffi::constructor]
    pub fn open_with_host_root(
        path: Option<String>,
        options: Option<OpenOptions>,
        host_root_secret: Vec<u8>,
    ) -> Result<Arc<Self>, OneironError> {
        let host_root_secret = Zeroizing::new(host_root_secret);
        // Crash output never carries world text: the engine's hook goes in
        // before any vault opens (owner ruling 2026-10-14, fix 6).
        oneiron::panic_report::install_panic_hook();
        let dimensions: Option<usize> = options.and_then(|options| options.dimensions).lower()?;
        let path = path.map(std::path::PathBuf::from);
        let inner = oneiron_remote::OneironClient::open_with_host_root(
            path.as_deref(),
            &oneiron_remote::OpenOptions {
                dimensions,
                device_class: None,
            },
            host_root_secret.as_slice(),
        )?;
        Ok(Arc::new(Self {
            inner,
            #[cfg(feature = "engine")]
            engine: None,
        }))
    }

    /// What `open_with_host_root` did with its root, on the handle it
    /// returned; nil on every other handle, one rebound from it included.
    pub fn host_root_profile(&self) -> Option<HostRootProfile> {
        self.inner
            .host_root_profile()
            .map(|profile| HostRootProfile {
                enrolled: profile.enrolled,
                wrong_root: profile.wrong_root,
            })
    }
}
