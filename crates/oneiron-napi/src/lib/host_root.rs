//! The host root secret the raw openers take (FIX 4730): `NapiVault` and
//! `VaultBridge` opens that profile this install, so the owner's acts carry
//! from it. The old openers stay as they were.

use std::path::Path;
use std::sync::Arc;

use napi_derive::napi;
use oneiron::Vault;

/// What a host passes to an `openWithHostRoot` factory.
#[napi(object)]
pub struct HostRootOpenOptions {
    /// The vault's host root secret, the exact UTF-8 of the server's
    /// configured `auth_secret`. Never empty.
    pub host_root_secret: String,
    /// Roots the vault under this secret when this open creates its store
    /// and its authority log is empty: a new local-origin vault. Off when
    /// omitted. Never set it for a replica awaiting its root.
    pub initialize_root: Option<bool>,
    /// Holds this install's host root as the vault's checkpoint signer for
    /// the handle's life (FIX 5343): the device sync's steady pass attests
    /// with it the images its home writes. Off when omitted. A secret that
    /// went unused is never held.
    pub hold_checkpoint_root_signer: Option<bool>,
}

/// The options, checked before the open creates anything.
pub(crate) struct HostRootRequest<'a> {
    secret: &'a [u8],
    may_root: bool,
    hold: bool,
}

impl HostRootOpenOptions {
    /// Refuses an empty secret before any store exists, and reads whether
    /// this open of `path` may root what it opens.
    pub(crate) fn before_open(&self, path: &str) -> Result<HostRootRequest<'_>, String> {
        if self.host_root_secret.is_empty() {
            return Err(
                "hostRootSecret is empty; open without host root options to stay unprofiled"
                    .to_owned(),
            );
        }
        Ok(HostRootRequest {
            secret: self.host_root_secret.as_bytes(),
            may_root: Vault::host_root_open_may_root(
                Path::new(path),
                self.initialize_root.unwrap_or(false),
            ),
            hold: self.hold_checkpoint_root_signer.unwrap_or(false),
        })
    }
}

impl HostRootRequest<'_> {
    /// Profiles the vault this open returned, refusing with the engine's
    /// reason when its install cannot be profiled. `true` is the wrong-root
    /// fact: the secret is not this vault's settled root and went unused,
    /// since the install already carried its profile, and the open stands
    /// under the settled root as before (reported, never refused). With
    /// the hold opt-in (FIX 5343) the vault also holds this install's
    /// loaded issuer as its checkpoint signer, unless the secret went
    /// unused.
    pub(crate) fn profile(&self, vault: &Vault) -> Result<bool, oneiron::Error> {
        let profile = vault.profile_local_open(Some(self.secret), self.may_root)?;
        let wrong_root = profile.wrong_root();
        if self.hold && !wrong_root {
            let issuer = vault.load_host_slip_issuer()?;
            vault.hold_checkpoint_root_signer(Arc::new(issuer));
        }
        Ok(wrong_root)
    }
}
