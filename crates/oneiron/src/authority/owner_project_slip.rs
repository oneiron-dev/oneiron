//! The host's owner-project slip (OF-497): the host-held project.write slip an
//! [`OwnerProjectSigner`] signs the owner's project states with.
use super::*;
use crate::Vault;
use crate::error::Result;
use crate::federation::{Scope, ScopeAxis};
use crate::side_table::{self, Raw, SideTable};
use crate::workspace_roster::OwnerProjectSigner;
use std::collections::BTreeSet;

const OWNER_PROJECT_SLIP_LIFETIME: u64 = 10 * 365 * 24 * 60 * 60;
/// Cached host-held project.write slip token for one host signing key. Key: hex64.
const OWNER_PROJECT_SLIP_CACHE: SideTable<String, String, Raw> =
    SideTable::new(&side_table::AUTHORITY_OWNER_PROJECT_SLIP_CACHE);

impl Vault {
    /// The owner's project signer: the host's project.write slip, minted once
    /// per host key in the authority log and reused while the fold keeps it
    /// live. A cached slip the fold no longer holds live (expired or revoked)
    /// is replaced by a fresh mint under the host's standing root; a host the
    /// fold does not recognize, or a relay, gets none.
    pub fn owner_project_signer<'a>(
        &self,
        issuer: &'a HostSlipIssuer,
    ) -> Result<OwnerProjectSigner<'a>> {
        if self.privacy_posture() == crate::HostingPrivacyPosture::Relay {
            return Err(invalid_authority());
        }
        let cache_key = blake3::hash(&issuer.binding_key()).to_hex().to_string();
        let mut txn = self.store.env.write_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        super::slip_vault::require_host(&fold, issuer)?;
        let now = self.instant_in_txn(&txn)?.secs();
        let cached = OWNER_PROJECT_SLIP_CACHE
            .get(&self.store, &txn, &cache_key)?
            .and_then(|token| CapabilitySlip::from_token(&token).ok())
            .filter(|slip| {
                slip.claims.holder_ref == "host"
                    && slip
                        .verify_authority(&issuer.public_key(), &fold, now)
                        .is_ok()
            });
        let slip = match cached {
            Some(slip) => slip,
            None => {
                let mut scope = Scope::top();
                scope.verbs = ScopeAxis::Some(BTreeSet::from(["project.write".to_owned()]));
                let claims = SlipClaims {
                    slip_id: super::slip_vault::random_slip_id(),
                    vault_id: fold.vault_id.ok_or_else(invalid_authority)?,
                    parent_id: None,
                    holder_ref: "host".into(),
                    binding_key: issuer.binding_key(),
                    scope,
                    issued_at: now,
                    expires_at: now.saturating_add(OWNER_PROJECT_SLIP_LIFETIME),
                    ttl_secs: OWNER_PROJECT_SLIP_LIFETIME,
                    single_use: false,
                    records: BTreeSet::new(),
                    channels: BTreeSet::new(),
                    actor_class: None,
                    org_ref: None,
                    grant_ref: None,
                };
                let slip = self.mint_slip_in_txn(&mut txn, issuer, claims)?;
                OWNER_PROJECT_SLIP_CACHE.put(
                    &self.store,
                    &mut txn,
                    &cache_key,
                    &slip.to_token()?,
                )?;
                slip
            }
        };
        txn.commit()?;
        OwnerProjectSigner::new(issuer, slip)
    }
}
