//! OF-232: the owner mints an Ask or Connect guest's capability slip, bound to its
//! grant, and withdraws one guest's access at this host: an ask guest's, or
//! a Connect peer's (FIX 3016; canon: guest grants are host-owner revocable).
//!
//! A guest slip's signed claims name the guest FEDERATION_GRANT it was minted
//! under (`grant_ref`). The withdrawal's one writer deletes the grant,
//! disconnects every live pact the grant still governs, tombstones every
//! slip minted under it, and keeps a withdrawal row, so a repeat revoke
//! reports the first one with `changed: false`. Every slip door also checks a
//! grant-bound slip's grant when it reads the slip, so a slip minted on another
//! replica and merged after the withdrawal stands no longer than its grant,
//! and the withdrawal logs a signed `SlipGrantRevoke`, so every replica's fold
//! tombstones such a slip as this host's does (FIX 1978). A host answers with
//! [`crate::receipt::project_guest_revoke`] over the outcome.
//!
//! The outcome names each ended pact the grant governed (FIX 1634), the
//! courtesy-delete courier's typed input. Asking the guest's host to drop its
//! copy is the server's, after this writer returns, and only when the owner
//! names that host's origin (`peer`), since no grant or pact records it.

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
use crate::receipt::{GuestDeletionRequestStatus, GuestRevokeCourtesyTarget, GuestRevokeOutcome};
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

/// Whether this vault withdrew the guest Grant a slip's `grant_ref` names
/// (FIX-LIST 1978): what the merged fold tombstones a guest slip by here,
/// beside the signed `SlipGrantRevoke` every replica folds. A
/// `grant_ref` that names no entity id is no guest Grant. A row that cannot
/// be read answers by [`super::ISOLATION_NEW_CHECK_ERROR_MODE`]: not known,
/// with a warning, so the fold stands as it did before the check.
pub(super) fn guest_grant_known_withdrawn_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    grant_ref: &str,
) -> bool {
    let Ok(grant) = EntityId::from_hex(grant_ref) else {
        return false;
    };
    match WITHDRAWN.get(store, txn, &grant) {
        Ok(withdrawal) => withdrawal.is_some(),
        Err(error) => match super::ISOLATION_NEW_CHECK_ERROR_MODE {
            super::NewCheckErrorMode::KeepExistingPath => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a guest withdrawal did not read; the merged fold keeps that grant's slips as they stand"
                );
                false
            }
        },
    }
}

impl Vault {
    /// Mints the capability slip of one Ask or active Connect guest (OF-232; canon names no
    /// issuance door, Engine ruling 2026-10-17): the vault owner's act, under
    /// the host's `issuer`, for the live, unwithdrawn guest FEDERATION_GRANT
    /// `grant_ref`. The slip's signed claims name that grant, carry its
    /// scope, hold for its member, and bind the public key the guest
    /// generated on their own device: the one their ask carried into the
    /// grant (FIX-LIST 1978), else the owner's `holder_key`; with neither,
    /// the mint refuses. No private key is delivered anywhere. It lives until `expires_at`, and withdrawing the grant
    /// ([`Vault::revoke_guest_access`]) tombstones it. `comm` is the owner's
    /// cap on whom the guest may message (FIX 3899); `None` is the vault's.
    pub fn mint_guest_slip(
        &self,
        owner: &AuthenticatedOwner,
        issuer: &HostSlipIssuer,
        grant_ref: EntityId,
        holder_key: Option<[u8; 32]>,
        expires_at: u64,
        comm: Option<super::CommReach>,
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
        require_guest_purpose_in_txn(self, &txn, grant_ref, &grant)?;
        let now = self.instant_in_txn(&txn)?.secs();
        if !grant.confers_at(now) || expires_at <= now {
            return Err(invalid_authority());
        }
        let holder_key = grant
            .guest
            .as_ref()
            .and_then(|guest| guest.holder_key)
            .or(holder_key)
            .ok_or_else(|| {
                Error::InvalidConfig(
                    "holder_key is required: the guest's grant carries no key of theirs".to_owned(),
                )
            })?;
        // FIX 7928/7929: an Ask guest's slip signs its disclosure as its record
        // bound; a Connect guest's meets its pact's current effective scope.
        let (scope, records) = super::current_scope::guest_slip_bounds(&fold, &grant_ref, &grant);
        let claims = SlipClaims {
            slip_id: random_slip_id(),
            vault_id: fold.vault_id.ok_or_else(invalid_authority)?,
            parent_id: None,
            holder_ref: grant.member_ref.to_hex(),
            binding_key: holder_key,
            scope,
            issued_at: now,
            expires_at,
            ttl_secs: expires_at - now,
            single_use: false,
            records,
            channels: BTreeSet::new(),
            actor_class: None,
            org_ref: None,
            grant_ref: Some(grant_ref.to_hex()),
            invitation_ref: None,
            delegation: None,
            comm,
        };
        let slip = self.mint_slip_in_txn(&mut txn, issuer, claims)?;
        txn.commit()?;
        Ok(slip)
    }

    /// A grant-bound slip (OF-232) stands only while its grant does: the
    /// FEDERATION_GRANT its claims name is live, not withdrawn, still an Ask or active Connect
    /// guest's grant for the slip's holder, and confers at `now`; or it is
    /// the holder's own-device grant (FIX 3134), live and conferring. An Ask
    /// guest's slip also stays inside the grant's current disclosure (FIX
    /// 7928). A slip that names no grant passes. Every slip door reads this
    /// beside the fold's revocation check.
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
        if self.own_device_grant_stands_in_txn(txn, grant_ref, &claims.holder_ref, now)? {
            return Ok(());
        }
        let grant = self.live_guest_grant_in_txn(txn, grant_ref, &claims.holder_ref, now)?;
        if !super::current_scope::ask_bounds_hold(&grant, claims) {
            return Err(invalid_authority());
        }
        Ok(())
    }

    /// An Ask or active Connect guest's FEDERATION_GRANT `grant_ref` still stands for `member`
    /// (PERSON hex): live, not withdrawn, a guest grant whose member it
    /// is, and conferring at `now`. A grant-bound slip and a guest's task-verb
    /// proof (OF-220) both read it.
    pub(super) fn require_live_guest_grant_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        grant_ref: EntityId,
        member: &str,
        now: u64,
    ) -> Result<()> {
        self.live_guest_grant_in_txn(txn, grant_ref, member, now)
            .map(drop)
    }

    /// [`Self::require_live_guest_grant_in_txn`], answering the grant.
    fn live_guest_grant_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        grant_ref: EntityId,
        member: &str,
        now: u64,
    ) -> Result<crate::federation::FederationGrant> {
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
        require_guest_purpose_in_txn(self, txn, grant_ref, &grant)?;
        if grant.member_ref.to_hex() != member || !grant.confers_at(now) {
            return Err(invalid_authority());
        }
        Ok(grant)
    }

    /// Whether the owner withdrew guest grant `grant_ref` here (OF-232):
    /// a withdrawn grant confers nothing, whatever its row says. A booking
    /// payer's grant is judged by it too (FIX 5327).
    pub(crate) fn guest_grant_withdrawn_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        grant_ref: &EntityId,
    ) -> Result<bool> {
        Ok(WITHDRAWN.get(&self.store, txn, grant_ref)?.is_some())
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

    /// Withdraws one guest's access at this host (OF-232), an ask guest's or a
    /// Connect peer's guest grant (FIX 3016), in one writer:
    /// deletes the guest's FEDERATION_GRANT, disconnects each live pact the
    /// grant still governs, retires the grant's scope opening keys,
    /// tombstones every slip minted under the grant, and
    /// keeps the withdrawal, so a repeat returns the first revoke with
    /// `changed: false` and no slips. `owner` authorizes the act; `issuer` is
    /// the host's own signing key, which alone signs the disconnects and the
    /// slip revokes, on any roster (FIX 1634). A disconnect the fold refuses
    /// fails the whole revoke; it never reports a partial one. Both answers
    /// name the grant's ended pacts as courtesy-delete targets.
    pub fn revoke_guest_access(
        &self,
        owner: &AuthenticatedOwner,
        issuer: &HostSlipIssuer,
        grant_ref: EntityId,
    ) -> Result<GuestRevokeOutcome> {
        self.with_write_txn_grouped(|txn| {
            self.revoke_guest_access_in_txn(txn, owner, issuer, grant_ref)
        })
    }

    /// [`Self::revoke_guest_access`] in the caller's writer: the whole
    /// withdrawal commits or rolls back with the caller's transaction. A
    /// delete of the guest's PERSON withdraws its grants here (FIX 3875).
    pub(crate) fn revoke_guest_access_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        issuer: &HostSlipIssuer,
        grant_ref: EntityId,
    ) -> Result<GuestRevokeOutcome> {
        owner.revalidate_in_txn(self, txn)?;
        require_host(&*self.authority_view_readonly_in_txn(txn)?, issuer)?;
        if let Some(done) = WITHDRAWN.get(&self.store, txn, &grant_ref)? {
            let fold = self.authority_view_readonly_in_txn(txn)?;
            return Ok(GuestRevokeOutcome {
                grant_ref,
                guest_ref: done.guest_ref,
                changed: false,
                revoked_at: done.revoked_at,
                revoked_slips: Vec::new(),
                pact: federation_grant_activation(&fold, &grant_ref),
                deletion_request: GuestDeletionRequestStatus::NotRequested,
                courtesy_targets: ended_pact_targets(&fold, grant_ref),
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
        if !grant.role.is_guest()
            || !matches!(
                grant.scope,
                FederationGrantScope::Ask { .. } | FederationGrantScope::Connect { .. }
            )
        {
            return Err(Error::EntityNotFound);
        }
        let revoked_at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
        for action in live_pact_disconnects(&*self.authority_view_readonly_in_txn(txn)?, grant_ref)?
        {
            self.append_slip_op_in_txn(txn, issuer, AuthorityOp::FederationLifecycle(action))?;
        }
        // The grant's scope opening key of every epoch retires with it, as a
        // disconnect's does, so no signed commitment of its pacts tests a
        // guessed scope again (FIX 7907).
        crate::store::grant_scope_custody::retire_scope_keys(&self.store, txn, &grant_ref)?;
        let revoked_slips = self.revoke_grant_slips_in_txn(txn, issuer, grant_ref)?;
        // The signed withdrawal of every slip under the grant: each replica's
        // fold and every checkpoint image carry it, so a slip another replica
        // minted under the grant and merges later is tombstoned there too
        // (FIX 1978).
        self.append_slip_op_in_txn(txn, issuer, AuthorityOp::SlipGrantRevoke { grant_ref })?;
        // The withdrawal stays known here, in this writer (FIX-LIST 5107).
        super::mark_withdrawn_grant_in_txn(&self.store, txn, grant_ref)?;
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
        let fold = self.authority_view_readonly_in_txn(txn)?;
        Ok(GuestRevokeOutcome {
            grant_ref,
            guest_ref: withdrawal.guest_ref,
            changed: true,
            revoked_at,
            revoked_slips,
            pact: federation_grant_activation(&fold, &grant_ref),
            deletion_request: GuestDeletionRequestStatus::NotRequested,
            courtesy_targets: ended_pact_targets(&fold, grant_ref),
        })
    }

    /// The live, unwithdrawn Connect guest grants whose member is `person`
    /// (FIX 3875): what a delete of that PERSON withdraws before it scrubs
    /// or publishes, so no pact goes on naming a deleted actor. Every grant
    /// is read; one whose body does not decode is no Connect guest's here.
    pub(crate) fn live_connect_guest_grants_of_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        person: EntityId,
    ) -> Result<Vec<EntityId>> {
        let mut grants = Vec::new();
        for id in crate::ports::EntityStoreRead::port_entity_ids_by_type(
            &self.store,
            txn,
            ENTITY_TYPE_FEDERATION_GRANT,
            None,
        )? {
            let id = id?;
            if WITHDRAWN.get(&self.store, txn, &id)?.is_some() {
                continue;
            }
            let LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_FEDERATION_GRANT,
                body,
            } = live_entity_row_in_txn(&self.store, txn, &id)?
            else {
                continue;
            };
            let Ok(grant) = decode_federation_grant_body(&body) else {
                continue;
            };
            if grant.role.is_guest()
                && matches!(grant.scope, FederationGrantScope::Connect { .. })
                && grant.member_ref == person
            {
                grants.push(id);
            }
        }
        Ok(grants)
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

/// Each pact the grant was the operative binding of that now stands
/// Disconnected or Dissolved, with the epoch it ended at: what a courtesy
/// delete may ask its peer to drop. A Promoted pact carried on into a shared
/// vault and a pact another grant took over are not the guest's to drop.
fn ended_pact_targets(fold: &AuthorityFold, grant_ref: EntityId) -> Vec<GuestRevokeCourtesyTarget> {
    let Some(pact_ids) = fold.federation_grant_bindings.get(&grant_ref) else {
        return Vec::new();
    };
    pact_ids
        .iter()
        .filter_map(|pact_id| {
            let pact = fold.federation_pacts.get(pact_id)?;
            let ended = matches!(
                pact.status,
                FederationPactStatus::Disconnected | FederationPactStatus::Dissolved
            );
            (pact.grant_ref == grant_ref && ended).then_some(GuestRevokeCourtesyTarget {
                pact_id: *pact_id,
                peer_vault_id: pact.peer_vault_id,
                epoch_cutoff: pact.terminal_epoch?,
            })
        })
        .collect()
}

fn pact_nonce() -> [u8; 16] {
    use rand_core::{OsRng, RngCore};
    let mut nonce = [0; 16];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Guest purposes that may confer a credential: Ask disclosure, or one live
/// operative Connect pact. This is shared by minting and later slip liveness.
fn require_guest_purpose_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    grant_ref: EntityId,
    grant: &crate::federation::FederationGrant,
) -> Result<()> {
    if !grant.role.is_guest() {
        return Err(invalid_authority());
    }
    match grant.scope {
        FederationGrantScope::Ask { .. } => Ok(()),
        FederationGrantScope::Connect { .. } => {
            let fold = vault.authority_fold_readonly_in_txn(txn)?;
            if crate::federation::pact_admits_grant(&fold, &grant_ref, grant) {
                fold.active_pact_delivery_context(&grant_ref).map(|_| ())
            } else {
                Err(invalid_authority())
            }
        }
        FederationGrantScope::Vault { .. } => Err(invalid_authority()),
    }
}
