//! Ephemeral audience and credentials for a session's declared live port.
//! Nothing here creates an artifact pointer or persists a process across boot.

use std::collections::{BTreeMap, BTreeSet};

use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use oneiron_vault_contract::preview::validate_preview_ref;
pub use oneiron_vault_contract::preview::{
    PreviewEndpoint, PreviewPortDeclaration, PreviewSessionManifest, PreviewStage,
};
use oneiron_vault_contract::{TokenHex, from_hex};

/// Created only from a host-authenticated manifest. Principals passed to the
/// management methods must already have been authenticated by that host.
pub struct PrivatePreview {
    manifest: PreviewSessionManifest,
    invited: BTreeSet<String>,
    credentials: BTreeMap<[u8; 32], String>,
    sharing: Option<[u8; 32]>,
    ended: bool,
}

impl PrivatePreview {
    pub fn new(manifest: PreviewSessionManifest, now: u64) -> Result<Self> {
        manifest.validate(now).map_err(invalid)?;
        Ok(Self {
            manifest,
            invited: BTreeSet::new(),
            credentials: BTreeMap::new(),
            sharing: None,
            ended: false,
        })
    }

    pub fn manifest(&self) -> &PreviewSessionManifest {
        &self.manifest
    }

    pub fn is_live(&self, now: u64) -> bool {
        !self.ended && now < self.manifest.expires_at
    }

    /// Only the owner is admitted initially. An invitation is a named
    /// principal, not world membership and never a public tier.
    pub fn admits_principal(&self, principal: &str, now: u64) -> bool {
        self.is_live(now)
            && (principal == self.manifest.owner_ref || self.invited.contains(principal))
    }

    pub fn invite(&mut self, owner: &str, principal: &str, now: u64) -> Result<()> {
        self.require_owner(owner, now)?;
        validate_preview_ref(principal).map_err(invalid)?;
        self.invited.insert(principal.to_owned());
        Ok(())
    }

    pub fn revoke_invite(&mut self, owner: &str, principal: &str, now: u64) -> Result<bool> {
        self.require_owner(owner, now)?;
        self.credentials.retain(|_, subject| subject != principal);
        Ok(self.invited.remove(principal))
    }

    /// Issued after the host authenticates this owner or invited principal.
    /// The browser needs only this preview credential, never a vault slip.
    pub fn access_token(&mut self, principal: &str, now: u64) -> Result<TokenHex> {
        if !self.admits_principal(principal, now) {
            return Err(invalid("preview access refused"));
        }
        let (digest, token) = mint_token();
        self.credentials.insert(digest, principal.to_owned());
        Ok(token)
    }

    /// A new sharing URL replaces the earlier sharing credential. Personal
    /// owner/invite credentials remain separate from the revocable URL.
    pub fn share(&mut self, owner: &str, now: u64) -> Result<TokenHex> {
        self.require_owner(owner, now)?;
        let (digest, token) = mint_token();
        self.sharing = Some(digest);
        Ok(token)
    }

    pub fn revoke_share(&mut self, owner: &str, now: u64) -> Result<bool> {
        self.require_owner(owner, now)?;
        Ok(self.sharing.take().is_some())
    }

    /// Checked on every HTTP request, including bootstrap and upgrades. An
    /// expired or ended lease invalidates all credentials without a sweep.
    pub fn admits_token(&self, token: &str, now: u64) -> bool {
        if !self.is_live(now) || token.len() != 64 {
            return false;
        }
        let Some(secret) = from_hex(token).map(Zeroizing::new) else {
            return false;
        };
        let candidate = token_digest(&secret);
        let mut admitted = self
            .sharing
            .is_some_and(|digest| equal_digest(&digest, &candidate));
        for (digest, principal) in &self.credentials {
            admitted |= equal_digest(digest, &candidate) && self.admits_principal(principal, now);
        }
        admitted
    }

    /// Idempotent and scoped to the lease that declared this port.
    pub fn end_lease(&mut self, lease_ref: &str) -> bool {
        if self.manifest.lease_ref != lease_ref {
            return false;
        }
        self.ended = true;
        self.invited.clear();
        self.credentials.clear();
        self.sharing = None;
        true
    }

    fn require_owner(&self, owner: &str, now: u64) -> Result<()> {
        if !self.is_live(now) || owner != self.manifest.owner_ref {
            return Err(invalid("preview owner action refused"));
        }
        Ok(())
    }
}

fn invalid(message: &'static str) -> Error {
    Error::InvalidConfig(message.into())
}

fn mint_token() -> ([u8; 32], TokenHex) {
    let mut secret = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(secret.as_mut());
    (token_digest(secret.as_ref()), TokenHex::from_token(&secret))
}

fn token_digest(secret: &[u8]) -> [u8; 32] {
    blake3::derive_key("oneiron private preview access v1", secret)
}

fn equal_digest(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0_u8, |diff, (a, b)| diff | (a ^ b)) == 0
}
