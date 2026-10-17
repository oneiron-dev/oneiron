//! OF-232: the owner mints an ask guest's capability slip, bound to its
//! grant, and withdraws one ask guest's access at this host.
//!
//! A guest slip's signed claims name the guest FEDERATION_GRANT it was minted
//! under (`grant_ref`). The withdrawal's one writer deletes the grant,
//! disconnects every live pact the grant still governs, tombstones every
//! slip minted under it, and keeps a withdrawal row, so a repeat revoke
//! reports the first one with `changed: false`. Every slip door also checks a
//! grant-bound slip's grant when it reads the slip, so a slip minted on another
//! replica and merged after the withdrawal stands no longer than its grant. A host answers with
//! [`crate::receipt::project_guest_revoke`] over the outcome.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::slip_vault::{random_slip_id, require_host};
use super::*;
use crate::Vault;
use crate::batch::{BatchOp, apply_ops};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::{FederationGrantScope, decode_federation_grant_body};
use crate::receipt::{GuestDeletionRequestStatus, GuestRevokeOutcome};
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::side_table::{self, Named, SideTable};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// A withdrawn guest grant: the guest it conferred on and when. Key: id16
/// (grant).
const WITHDRAWN: SideTable<EntityId, GuestWithdrawal, Named> =
    SideTable::new(&side_table::FEDERATION_GUEST_REVOKE);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GuestWithdrawal {
    guest_ref: EntityId,
    revoked_at: u64,
}

impl Vault {
    /// Mints the capability slip of one ask guest (OF-232; canon names no
    /// issuance door, Engine ruling 2026-10-17): the vault owner's act, under
    /// the host's `issuer`, for the live, unwithdrawn guest FEDERATION_GRANT
    /// `grant_ref`. The slip's signed claims name that grant, carry its
    /// scope, hold for its member, and bind `holder_key`, the public key the
    /// guest generated on their own device; no private key is delivered
    /// anywhere. It lives until `expires_at`, and withdrawing the grant
    /// ([`Vault::revoke_guest_access`]) tombstones it.
    pub fn mint_guest_slip(
        &self,
        owner: &AuthenticatedOwner,
        issuer: &HostSlipIssuer,
        grant_ref: EntityId,
        holder_key: [u8; 32],
        expires_at: u64,
    ) -> Result<CapabilitySlip> {
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        require_host(&fold, issuer)?;
        if WITHDRAWN.get(&self.store, &txn, &grant_ref)?.is_some() {
            return Err(Error::EntityNotFound);
        }
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_FEDERATION_GRANT,
            body,
        } = live_entity_row_in_txn(&self.store, &txn, &grant_ref)?
        else {
            return Err(Error::EntityNotFound);
        };
        let grant = decode_federation_grant_body(&body)?;
        if !grant.role.is_guest() || !matches!(grant.scope, FederationGrantScope::Ask { .. }) {
            return Err(Error::EntityNotFound);
        }
        let now = self.instant_in_txn(&txn)?.secs();
        if !grant.confers_at(now) || expires_at <= now {
            return Err(invalid_authority());
        }
        let claims = SlipClaims {
            slip_id: random_slip_id(),
            vault_id: fold.vault_id.ok_or_else(invalid_authority)?,
            parent_id: None,
            holder_ref: grant.member_ref.to_hex(),
            binding_key: holder_key,
            scope: grant.authority_scope,
            issued_at: now,
            expires_at,
            ttl_secs: expires_at - now,
            single_use: false,
            records: BTreeSet::new(),
            channels: BTreeSet::new(),
            actor_class: None,
            org_ref: None,
            grant_ref: Some(grant_ref.to_hex()),
            invitation_ref: None,
        };
        let slip = self.mint_slip_in_txn(&mut txn, issuer, claims)?;
        txn.commit()?;
        Ok(slip)
    }

    /// A grant-bound slip (OF-232) stands only while its grant does: the
    /// FEDERATION_GRANT its claims name is live, not withdrawn, still an ask
    /// guest's grant for the slip's holder, and confers at `now`. A slip that
    /// names no grant passes. Every slip door reads this beside the fold's
    /// revocation check.
    pub(super) fn require_live_slip_grant_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        claims: &SlipClaims,
        now: u64,
    ) -> Result<()> {
        let Some(grant_ref) = &claims.grant_ref else {
            return Ok(());
        };
        let grant_ref = EntityId::from_hex(grant_ref).map_err(|_| invalid_authority())?;
        if WITHDRAWN.get(&self.store, txn, &grant_ref)?.is_some() {
            return Err(invalid_authority());
        }
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_FEDERATION_GRANT,
            body,
        } = live_entity_row_in_txn(&self.store, txn, &grant_ref)?
        else {
            return Err(invalid_authority());
        };
        let grant = decode_federation_grant_body(&body)?;
        if !grant.role.is_guest()
            || !matches!(grant.scope, FederationGrantScope::Ask { .. })
            || grant.member_ref.to_hex() != claims.holder_ref
            || !grant.confers_at(now)
        {
            return Err(invalid_authority());
        }
        Ok(())
    }

    /// Tombstones, in the caller's writer, every slip minted under
    /// `grant_ref` that no revoke names yet, expired ones included, and
    /// answers their ids.
    fn revoke_grant_slips_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        grant_ref: EntityId,
    ) -> Result<Vec<[u8; 32]>> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let grant_hex = grant_ref.to_hex();
        let bound: Vec<[u8; 32]> = fold
            .slips
            .mints
            .iter()
            .filter(|(id, mint)| {
                mint.action.claims.grant_ref.as_deref() == Some(grant_hex.as_str())
                    && !fold.slips.explicit_revoked.contains(*id)
            })
            .map(|(id, _)| *id)
            .collect();
        for slip_id in &bound {
            self.append_slip_op_in_txn(txn, issuer, AuthorityOp::SlipRevoke { slip_id: *slip_id })?;
        }
        Ok(bound)
    }

    /// Withdraws one ask guest's access at this host (OF-232) in one writer:
    /// deletes the guest's FEDERATION_GRANT, disconnects each live pact the
    /// grant still governs, tombstones every slip minted under the grant, and
    /// keeps the withdrawal, so a repeat returns the first revoke with
    /// `changed: false` and no slips. `owner` authorizes the act; `issuer` is
    /// the host's own signing key, which signs the disconnects and the slip
    /// revokes. A disconnect the fold refuses (a multi-key roster wants a
    /// second signer) fails the whole revoke; it never reports a partial one.
    pub fn revoke_guest_access(
        &self,
        owner: &AuthenticatedOwner,
        issuer: &HostSlipIssuer,
        grant_ref: EntityId,
    ) -> Result<GuestRevokeOutcome> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            require_host(&*self.authority_view_readonly_in_txn(txn)?, issuer)?;
            if let Some(done) = WITHDRAWN.get(&self.store, txn, &grant_ref)? {
                return Ok(GuestRevokeOutcome {
                    grant_ref,
                    guest_ref: done.guest_ref,
                    changed: false,
                    revoked_at: done.revoked_at,
                    revoked_slips: Vec::new(),
                    pact: federation_grant_activation(
                        &*self.authority_view_readonly_in_txn(txn)?,
                        &grant_ref,
                    ),
                    deletion_request: GuestDeletionRequestStatus::NotRequested,
                });
            }
            let LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_FEDERATION_GRANT,
                body,
            } = live_entity_row_in_txn(&self.store, txn, &grant_ref)?
            else {
                return Err(Error::EntityNotFound);
            };
            let grant = decode_federation_grant_body(&body)?;
            if !grant.role.is_guest() || !matches!(grant.scope, FederationGrantScope::Ask { .. }) {
                return Err(Error::EntityNotFound);
            }
            let revoked_at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            for action in
                live_pact_disconnects(&*self.authority_view_readonly_in_txn(txn)?, grant_ref)?
            {
                self.append_slip_op_in_txn(txn, issuer, AuthorityOp::FederationLifecycle(action))?;
            }
            let revoked_slips = self.revoke_grant_slips_in_txn(txn, issuer, grant_ref)?;
            apply_ops(
                &self.store,
                &self.config,
                &self.analyzer,
                txn,
                vec![BatchOp::Delete { id: grant_ref }],
                self.text_index_trusted
                    .load(std::sync::atomic::Ordering::Acquire),
                false,
                true,
            )?;
            let withdrawal = GuestWithdrawal {
                guest_ref: grant.member_ref,
                revoked_at,
            };
            WITHDRAWN.put(&self.store, txn, &grant_ref, &withdrawal)?;
            Ok(GuestRevokeOutcome {
                grant_ref,
                guest_ref: withdrawal.guest_ref,
                changed: true,
                revoked_at,
                revoked_slips,
                pact: federation_grant_activation(
                    &*self.authority_view_readonly_in_txn(txn)?,
                    &grant_ref,
                ),
                deletion_request: GuestDeletionRequestStatus::NotRequested,
            })
        })
    }
}

/// A Disconnect for each pact the grant is still the operative, non-terminal
/// binding of. A pact superseded by another grant's binding stays as it is.
/// A binding with no pact state fails closed.
fn live_pact_disconnects(
    fold: &AuthorityFold,
    grant_ref: EntityId,
) -> Result<Vec<FederationLifecycleAction>> {
    let Some(pact_ids) = fold.federation_grant_bindings.get(&grant_ref) else {
        return Ok(Vec::new());
    };
    let mut disconnects = Vec::new();
    for pact_id in pact_ids {
        let pact = fold
            .federation_pacts
            .get(pact_id)
            .ok_or_else(invalid_authority)?;
        if pact.grant_ref != grant_ref || pact.status.is_terminal() {
            continue;
        }
        disconnects.push(FederationLifecycleAction {
            kind: FederationLifecycleKind::Disconnect,
            pact_id: *pact_id,
            grant_ref,
            peer_vault_id: pact.peer_vault_id,
            pact_epoch: pact.pact_epoch,
            pact_scope: None,
            effective_scope: None,
            scope_digest: None,
            gesture: None,
            successor_vault_id: None,
            pact_nonce: pact_nonce(),
        });
    }
    Ok(disconnects)
}

fn pact_nonce() -> [u8; 16] {
    use rand_core::{OsRng, RngCore};
    let mut nonce = [0; 16];
    OsRng.fill_bytes(&mut nonce);
    nonce
}
