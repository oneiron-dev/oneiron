//! The native capability slip the server holds for each access token (FIX 4902 slice C;
//! ARCH-0028:91 "The OAuth bearer maps to the vault grant at ingress. Clients never hold our slip
//! or keys.").
//!
//! Each code exchange and each refresh mints, beside its access token, a slip of the family's
//! client agent through the paired path every connector's slip takes: a host-made pairing link
//! for that agent ([`Vault::issue_pairing_link_for_principal`]), with the tier's core scopes and
//! the grant's world bound and the access token's lifetime, redeemed here at once
//! ([`Vault::redeem_pairing_link_with_possession`]). Its authority is the owner agent grant the
//! family stands on, judged in the writer that minted the token; the slip names no owner, as a
//! host-made link names none. Its holder key is derived from the host issuer's secret and the
//! token's own row key ([`super::access_holder_key`]) and never stored, so the slip kept on the
//! token's row proves nothing to whoever copies the vault file. The `/mcp` ingress swaps the token
//! for this slip and a fresh holder proof per request, and the request is that connector's.
//!
//! A family holds one live slip: a refresh retires the family's previous access token with its
//! slip, and a revoked family (RFC 7009, a code redeemed twice, a refresh token spent twice, or an
//! owner agent grant that no longer stands) has its slip revoked once its writer commits.

use std::collections::BTreeSet;

use ed25519_dalek::{Signer, SigningKey};

use super::rows::{AuthorizedGrant, FAMILIES, TOKENS, TokenFamily};
use super::tokens::revoke_family_in_txn;
use super::{OAUTH_ACCESS_SLIP_COMM, OAUTH_ACCESS_TTL_SECS, access_holder_key};
use crate::authority::{
    CapabilitySlip, HostSlipIssuer, PairingPrincipal, pairing_binding_transcript_pinned,
};
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::federation::{Scope, ScopeAxis, ScopeId};
use crate::side_table::HexId;
use crate::{EntityId, Vault};

/// Retires `family`'s live access token in the caller's writer: drops its row and answers the
/// id of the slip it held, for the caller to revoke once its writer commits
/// ([`Vault::retire_access_slip`]). `None` when the family holds none. A family holds one live
/// access token (CALLS, FIX 4902: an engine call): a refresh retires the one it replaces at
/// once, so that token answers `invalid_token` rather than running on to its lapse beside a
/// revoked slip.
pub(super) fn take_live_access_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    family: &mut TokenFamily,
) -> Result<Option<[u8; 32]>> {
    let Some(key) = family.live_access.take() else {
        return Ok(None);
    };
    let slip = TOKENS
        .get(&vault.store, txn, &key)?
        .and_then(|row| row.slip)
        .and_then(|token| CapabilitySlip::from_token(&token).ok())
        .map(|slip| slip.claims.slip_id);
    TOKENS.delete(&vault.store, txn, &key)?;
    Ok(slip)
}

impl Vault {
    /// Mints the native slip of `grant`'s agent for the access token of `family` whose row key
    /// is `access_key`, and keeps it on that row as the family's live access token. `true` once
    /// it stands; `false` when the family was revoked while the slip was minted, which revokes
    /// the slip again. A mint or a landing that fails revokes the family, so its tokens, never
    /// handed out, stand for nothing.
    ///
    /// # Errors
    /// The slip's mint or its landing failed.
    pub(super) fn hold_access_slip(
        &self,
        issuer: &HostSlipIssuer,
        family: EntityId,
        access_key: &str,
        grant: &AuthorizedGrant,
    ) -> Result<bool> {
        let holder_key = access_holder_key(issuer, family, access_key);
        let slip = match self.mint_access_slip(issuer, grant, &holder_key) {
            Ok(slip) => slip,
            Err(error) => {
                self.revoke_family_after_failure(issuer, family);
                return Err(error);
            }
        };
        let slip_id = slip.claims.slip_id;
        let access_key = access_key.to_owned();
        let family_key = HexId(family);
        let landed = slip.to_token().and_then(|token| {
            self.with_write_txn_grouped(|txn| {
                let Some(mut row) = FAMILIES
                    .get(&self.store, txn, &family_key)?
                    .filter(|row| !row.revoked)
                else {
                    return Ok(None);
                };
                let Some(mut access) = TOKENS.get(&self.store, txn, &access_key)? else {
                    return Ok(None);
                };
                access.slip = Some(token);
                TOKENS.put(&self.store, txn, &access_key, &access)?;
                let previous = take_live_access_in_txn(self, txn, &mut row)?;
                row.live_access = Some(access_key.clone());
                FAMILIES.put(&self.store, txn, &family_key, &row)?;
                Ok(Some(previous))
            })
        });
        match landed {
            Ok(Some(previous)) => {
                if let Some(previous) = previous {
                    self.retire_access_slip(issuer, family, previous);
                }
                Ok(true)
            }
            Ok(None) => {
                self.retire_access_slip(issuer, family, slip_id);
                Ok(false)
            }
            Err(error) => {
                self.retire_access_slip(issuer, family, slip_id);
                self.revoke_family_after_failure(issuer, family);
                Err(error)
            }
        }
    }

    /// The slip of `grant`'s agent the server holds for one access token, minted through the
    /// paired path: a host-made link fixing the agent as its holder, of class agent, with the
    /// tier's core scopes ([`crate::authority::AgentTier::core_scopes`]) in the one world the
    /// grant is bound to, or every world, for [`OAUTH_ACCESS_TTL_SECS`] (the vault's credential
    /// lifetime ceiling may cut it shorter), redeemed at once with `holder_key` as its binding
    /// key. The link's code never leaves this call.
    fn mint_access_slip(
        &self,
        issuer: &HostSlipIssuer,
        grant: &AuthorizedGrant,
        holder_key: &SigningKey,
    ) -> Result<CapabilitySlip> {
        let holder = grant.agent.to_hex();
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(
            grant
                .tier
                .core_scopes()
                .iter()
                .map(|verb| (*verb).to_owned())
                .collect(),
        );
        if let Some(world) = grant.world {
            scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(world)]));
        }
        let link = self.issue_pairing_link_for_principal(
            issuer,
            scope,
            OAUTH_ACCESS_TTL_SECS,
            PairingPrincipal {
                holder_ref: Some(holder.clone()),
                actor_class: Some(EdgeActorClass::Agent.gate_actor_class().to_owned()),
                org_ref: None,
                write_facet: None,
                comm: OAUTH_ACCESS_SLIP_COMM,
            },
        )?;
        let binding_key = holder_key.verifying_key().to_bytes();
        let transcript = pairing_binding_transcript_pinned(
            &link.code,
            &binding_key,
            &holder,
            link.pin.as_ref(),
        )?;
        let signature = holder_key.sign(&transcript).to_bytes();
        self.redeem_pairing_link_with_possession(
            issuer,
            &link.code,
            &holder,
            binding_key,
            &signature,
            None,
            None,
        )
        .map(|redeemed| redeemed.slip)
    }

    /// Revokes `family` and then the slip its live access token held, each in its own writer:
    /// for a family whose owner agent grant the `/mcp` ingress found no longer standing, or
    /// whose new access token's slip did not land.
    ///
    /// # Errors
    /// A store failure revoking the family.
    pub(super) fn revoke_oauth_family(
        &self,
        issuer: &HostSlipIssuer,
        family: EntityId,
    ) -> Result<()> {
        let retired = self.with_write_txn_grouped(|txn| revoke_family_in_txn(self, txn, family))?;
        if let Some(slip) = retired {
            self.retire_access_slip(issuer, family, slip);
        }
        Ok(())
    }

    /// [`Self::revoke_oauth_family`] after a slip that could not land, where the failure that
    /// caused it is the answer: a second failure is logged.
    fn revoke_family_after_failure(&self, issuer: &HostSlipIssuer, family: EntityId) {
        if let Err(error) = self.revoke_oauth_family(issuer, family) {
            tracing::warn!(
                %error,
                family = %family.to_hex(),
                "revoking an OAuth token family whose access slip did not land failed"
            );
        }
    }

    /// Revokes `slip`, the slip of `family`'s access token that a committed writer retired: the
    /// authority log takes its own writer. A failure is logged and the answer stands: the token
    /// no longer resolves, so no ingress swaps the slip in again, and it lapses with the token.
    pub(super) fn retire_access_slip(
        &self,
        issuer: &HostSlipIssuer,
        family: EntityId,
        slip: [u8; 32],
    ) {
        if let Err(error) = self.revoke_capability_slip(issuer, slip) {
            tracing::warn!(
                %error,
                family = %family.to_hex(),
                "revoking a retired OAuth access token's slip failed"
            );
        }
    }
}
