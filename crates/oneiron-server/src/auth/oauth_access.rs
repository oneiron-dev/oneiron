//! A stock cloud client's `/mcp` caller, from the OAuth access token it presented (FIX 4902
//! slice C; ARCH-0028:91 "The OAuth bearer maps to the vault grant at ingress. Clients never
//! hold our slip or keys.").
//!
//! The `/mcp` ingress resolves the token to the vault grant it stands on
//! (`Vault::resolve_oauth_access_token`): the client's own agent principal, the tier the owner
//! gave and its owner agent grant. This caller is that agent and nothing more: an agent with
//! the tier's core scopes and no slip, invocation slip, token id, account key or host credential
//! of anyone's, never owner grade. Its instrument names the token family (`oauth:<family hex>`)
//! and keeps no secret; the caller stays live while that family still resolves the token
//! ([`OAuthAccessInstrument::is_live`]). Only the `/mcp` door builds it: every other door reads a
//! slip or an account key, and refuses the token.

use oneiron::authority::PeerMachine;
use oneiron::claim::CallerLocality;

use super::{CoreAuth, CoreScope};

/// What an OAuth caller's instrument name spells before its token family's hex.
const OAUTH_INSTRUMENT_PREFIX: &str = "oauth:";

/// The instrument an OAuth caller acts on: the token family its access token is of, the
/// resource the token was resolved on, and when the token lapses. Never the token itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OAuthAccessInstrument {
    family: oneiron::EntityId,
    resource: String,
    expires_at: u64,
}

impl OAuthAccessInstrument {
    /// The instrument's name: `oauth:` and its token family's hex. One sign-in and every refresh
    /// of it share the name; another sign-in of the same client does not.
    pub(crate) fn name(&self) -> String {
        format!("{OAUTH_INSTRUMENT_PREFIX}{}", self.family.to_hex())
    }

    /// Whether its token still resolves to its family now (`Vault::oauth_access_is_live`), on
    /// the wall clock the token endpoint minted it by. A store fault reads not live.
    pub(super) fn is_live(&self, vault: &oneiron::Vault) -> bool {
        vault
            .oauth_access_is_live(
                self.family,
                &self.resource,
                self.expires_at,
                oneiron_vault_contract::now_ts(),
            )
            .unwrap_or(false)
    }

    /// [`Self::is_live`], read in the writer `txn`.
    pub(super) fn is_live_in_txn(&self, vault: &oneiron::Vault, txn: &heed::RwTxn<'_>) -> bool {
        vault
            .oauth_access_is_live_in_txn(
                txn,
                self.family,
                &self.resource,
                self.expires_at,
                oneiron_vault_contract::now_ts(),
            )
            .unwrap_or(false)
    }
}

impl CoreAuth {
    /// The caller an OAuth access token resolved to on `resource` (FIX 4902 slice C): the
    /// client's agent principal, as an agent, with exactly the core scopes of its tier, placed
    /// at `locality` and toward `peer`, where the request's connection sits. Built without
    /// reading any header: no slip, invocation slip, token id or instrument fingerprint, no
    /// organization, never owner grade, never the managed owner or a managed person. Its
    /// instrument names the token family.
    pub(crate) fn for_oauth_access(
        access: &oneiron::authority::OAuthAccess,
        resource: &str,
        locality: CallerLocality,
        peer: PeerMachine,
    ) -> Self {
        Self {
            principal: access.agent.to_hex(),
            principal_ref: Some(access.agent.to_hex()),
            scopes: access
                .scopes
                .iter()
                .copied()
                .filter_map(CoreScope::parse)
                .collect(),
            implicit_all_scopes: false,
            jti: None,
            actor_class: Some(access.actor_class.gate_actor_class().to_owned()),
            org_ref: None,
            verified_slip: None,
            invocation_slip: None,
            instrument: None,
            locality,
            peer,
            facets_owner_exempt: false,
            off_record_session: None,
            managed_owner: None,
            managed_person: None,
            oauth_access: Some(OAuthAccessInstrument {
                family: access.family,
                resource: resource.to_owned(),
                expires_at: access.expires_at,
            }),
        }
    }

    /// The OAuth access token's instrument this caller acts on ([`Self::for_oauth_access`]);
    /// `None` for every other caller.
    pub(crate) fn oauth_access(&self) -> Option<&OAuthAccessInstrument> {
        self.oauth_access.as_ref()
    }
}
