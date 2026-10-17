//! OF-232: the owner withdraws one ask guest's access at this host.
//!
//! One writer deletes the guest's FEDERATION_GRANT, disconnects every live
//! pact the grant still governs, and keeps a withdrawal row, so a repeat
//! revoke reports the first one with `changed: false`. A host answers with
//! [`crate::receipt::project_guest_revoke`] over the outcome.

use serde::{Deserialize, Serialize};

use super::slip_vault::require_host;
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
    /// Withdraws one ask guest's access at this host (OF-232) in one writer:
    /// deletes the guest's FEDERATION_GRANT, disconnects each live pact the
    /// grant still governs, and keeps the withdrawal, so a repeat returns the
    /// first revoke with `changed: false`. `owner` authorizes the act;
    /// `issuer` is the host's own signing key, which signs the disconnects.
    ///
    /// No slip names the grant it was minted under, and an ask birth mints
    /// none, so this revokes no slip: `revoked_slips` stays empty rather than
    /// tombstoning every slip the guest's companion holds. A disconnect the
    /// fold refuses (a multi-key roster wants a second signer) fails the
    /// whole revoke; it never reports a partial one.
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
            for action in live_pact_disconnects(&*self.authority_view_readonly_in_txn(txn)?, grant_ref)? {
                self.append_slip_op_in_txn(txn, issuer, AuthorityOp::FederationLifecycle(action))?;
            }
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
                revoked_slips: Vec::new(),
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
