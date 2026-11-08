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
//! slip, and a revoked family (RFC 7009, a code redeemed twice, a refresh token spent twice, an
//! owner agent grant that no longer stands, or a slip that did not land) has its slip revoked once
//! its writer commits. A new family whose first slip does not stand ends its sign-in before the
//! client held a token: the writer that revokes the family takes the sign-in's grant back too, as a
//! lapse takes it back, and marks the family's opening ended (FIX 22193). When that writer fails,
//! the family's opening stays pending, and the `oauth_expiry` sweep's next pass ends the sign-in
//! in the same one write (FIX 22226).

use std::collections::BTreeSet;

use ed25519_dalek::{Signer, SigningKey};

use super::rows::{AuthorizedGrant, FAMILIES, FamilyOpening, TOKENS, TokenFamily};
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

/// Whether a live token family other than `family`, one not revoked, names `grant`: its tokens
/// may stand on the grant, so a sign-in that ends with `family` leaves the grant to the owner's
/// revoke. A revoked family's tokens stand on nothing.
fn grant_held_by_other_family_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    family: EntityId,
    grant: &AuthorizedGrant,
) -> Result<bool> {
    Ok(FAMILIES.scan(&vault.store, txn)?.iter().any(|(key, row)| {
        key.0 != family && !row.revoked && row.grant.grant_ref == grant.grant_ref
    }))
}

impl Vault {
    /// Mints the native slip of `grant`'s agent for the access token of `family` whose row key
    /// is `access_key`, and keeps it on that row as the family's live access token. `true` once
    /// it stands; `false` when the family was revoked, or its access token's row went, while the
    /// slip was minted, which revokes the slip again. A mint or a landing that fails revokes the
    /// family, so its tokens, never handed out, stand for nothing. A slip that stands marks the
    /// family's opening [`FamilyOpening::Stood`]. When the slip is the first of a family a code's
    /// exchange just opened (`opens_family`), every outcome but `true` ends the sign-in with no
    /// token handed out: the family is revoked, and its writer takes `grant` back (FIX 22193); a
    /// failed end is the expiry sweep's to retry (FIX 22226).
    ///
    /// # Errors
    /// The slip's mint or its landing failed.
    pub(super) fn hold_access_slip(
        &self,
        issuer: &HostSlipIssuer,
        family: EntityId,
        access_key: &str,
        grant: &AuthorizedGrant,
        opens_family: bool,
    ) -> Result<bool> {
        let ended = opens_family.then_some(grant);
        let holder_key = access_holder_key(issuer, family, access_key);
        let slip = match self.mint_access_slip(issuer, grant, &holder_key) {
            Ok(slip) => slip,
            Err(error) => {
                self.revoke_family_after_failure(issuer, family, ended);
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
                row.opening = FamilyOpening::Stood;
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
                if ended.is_some() {
                    self.revoke_family_after_failure(issuer, family, ended);
                }
                Ok(false)
            }
            Err(error) => {
                self.retire_access_slip(issuer, family, slip_id);
                self.revoke_family_after_failure(issuer, family, ended);
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
    /// whose new access token's slip did not land. With `ended`, the grant of a sign-in whose
    /// family's first slip did not stand, the family's writer also ends that sign-in
    /// ([`Self::end_sign_in_in_txn`]): no client held a token on the grant (FIX 22193).
    ///
    /// # Errors
    /// A store failure revoking the family, or a store or fold failure taking the grant back.
    pub(super) fn revoke_oauth_family(
        &self,
        issuer: &HostSlipIssuer,
        family: EntityId,
        ended: Option<&AuthorizedGrant>,
    ) -> Result<()> {
        let retired = self.with_write_txn_grouped(|txn| {
            let slip = revoke_family_in_txn(self, txn, family)?;
            if let Some(grant) = ended {
                self.end_sign_in_in_txn(txn, Some(issuer), family, grant)?;
            }
            Ok(slip)
        })?;
        if let Some(slip) = retired {
            self.retire_access_slip(issuer, family, slip);
        }
        Ok(())
    }

    /// [`Self::revoke_oauth_family`] after a slip that could not land, where the failure that
    /// caused it is the answer: a second failure is logged.
    fn revoke_family_after_failure(
        &self,
        issuer: &HostSlipIssuer,
        family: EntityId,
        ended: Option<&AuthorizedGrant>,
    ) {
        if let Err(error) = self.revoke_oauth_family(issuer, family, ended) {
            tracing::warn!(
                %error,
                family = %family.to_hex(),
                "revoking an OAuth token family whose access slip did not land failed"
            );
        }
    }

    /// Ends the sign-in of `family`, a token family whose first access slip did not stand, in
    /// the caller's writer `txn`, after that writer revoked the family: marks the family's opening
    /// [`FamilyOpening::Ended`], so no sweep pass ends it again, and takes `grant` back
    /// ([`Self::withdraw_lapsed_oauth_grant_in_txn`], signed by `issuer` when it is the vault's
    /// live host) unless another live family names it (FIX 22193, 22226). Answers whether the
    /// grant was taken back.
    ///
    /// # Errors
    /// A store failure, or a store or fold failure taking the grant back.
    fn end_sign_in_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: Option<&HostSlipIssuer>,
        family: EntityId,
        grant: &AuthorizedGrant,
    ) -> Result<bool> {
        let key = HexId(family);
        if let Some(mut row) = FAMILIES.get(&self.store, txn, &key)? {
            row.opening = FamilyOpening::Ended;
            FAMILIES.put(&self.store, txn, &key, &row)?;
        }
        if grant_held_by_other_family_in_txn(self, txn, family, grant)? {
            return Ok(false);
        }
        self.withdraw_lapsed_oauth_grant_in_txn(txn, issuer, grant)
    }

    /// The expiry sweep's retry of a sign-in end that failed (FIX 22226): ends the sign-in of
    /// `family` while its end is due at `now` ([`FamilyOpening::end_due_at`]), judged again in
    /// this one writer, which revokes the family and ends its sign-in
    /// ([`Self::end_sign_in_in_txn`]) together, as the failed write would have. A family whose
    /// first slip stood, or whose sign-in was ended already, is left as it is. Answers whether
    /// its grant was taken back.
    ///
    /// # Errors
    /// A store failure, or a store or fold failure taking the grant back.
    pub(super) fn retry_oauth_sign_in_end(
        &self,
        issuer: Option<&HostSlipIssuer>,
        family: EntityId,
        now: u64,
    ) -> Result<bool> {
        let (withdrawn, retired) = self.with_write_txn_grouped(|txn| {
            let Some(row) = FAMILIES
                .get(&self.store, txn, &HexId(family))?
                .filter(|row| row.opening.end_due_at(now))
            else {
                return Ok((false, None));
            };
            let slip = revoke_family_in_txn(self, txn, family)?;
            let withdrawn = self.end_sign_in_in_txn(txn, issuer, family, &row.grant)?;
            Ok((withdrawn, slip))
        })?;
        // Only the landing that marks a family's first slip stood names a live access token, so
        // a family whose end is due holds none; were one named, its slip is revoked once the
        // writer commits, as `revoke_oauth_family` revokes it.
        if let Some((issuer, slip)) = issuer.zip(retired) {
            self.retire_access_slip(issuer, family, slip);
        }
        Ok(withdrawn)
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
