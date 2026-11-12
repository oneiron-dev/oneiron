//! The asking side's route to one member's vault (INQUIRE-1 PR 4; Engine
//! ruling INQUIRE-SHAPE Q2 = A). It lives on the company vault and is bound
//! to the member's seat in one shared vault. It names the member's own
//! vault, the member host an inquiry goes to, and the guest slip that vault
//! minted for this host on its inquiry edge.
//!
//! The company Owner opens it once the Connect pact over the edge is Active.
//! The member's leave or removal ends it in the membership writer, in the
//! same transaction as the seat ([`end_inquiry_route_in_txn`]).

use serde::{Deserialize, Serialize};

use super::record::refuse;
use crate::Vault;
use crate::authority::{AuthorityVaultId, CapabilitySlip, FederationPactStatus, HostSlipIssuer};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

/// Shared vault and the member's PERSON → the route.
const ROUTES: SideTable<(u64, EntityId), InquiryRoute, Named> =
    SideTable::new(&side_table::INQUIRY_ROUTE);

/// What the company Owner gives to open a route.
#[derive(Clone, Debug)]
pub struct InquiryRouteRequest {
    /// The shared vault the member holds a seat in.
    pub shared_vault_id: u64,
    /// The member's seat: the member's PERSON in this vault.
    pub member: EntityId,
    /// The member's own vault: the peer of the Active Connect pact.
    pub member_vault_id: AuthorityVaultId,
    /// The member host's origin, `https://host[:port]`.
    pub member_host: String,
    /// The guest slip the member's vault minted for this host on its
    /// inquiry edge.
    pub slip: CapabilitySlip,
}

/// One route, as the company vault stores it.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct InquiryRoute {
    pub shared_vault_id: u64,
    /// The member's PERSON in this vault.
    pub member: EntityId,
    pub member_vault_id: AuthorityVaultId,
    pub member_host: String,
    /// The member vault's inquiry edge grant, as the slip names it.
    pub edge_grant: String,
    /// The slip's token. It is bound to this host's key: it acts only with
    /// this host's signature on each call.
    slip_token: String,
    pub slip_expires_at: u64,
    pub opened_at: u64,
}

impl InquiryRoute {
    pub(crate) fn slip_token(&self) -> &str {
        &self.slip_token
    }
}

impl std::fmt::Debug for InquiryRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InquiryRoute")
            .field("shared_vault_id", &self.shared_vault_id)
            .field("member", &self.member)
            .field("member_host", &self.member_host)
            .field("edge_grant", &self.edge_grant)
            .field("slip_expires_at", &self.slip_expires_at)
            .field("opened_at", &self.opened_at)
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Opens the route to `request.member`'s vault, approved by the company
    /// vault's `owner`. The member holds a seat in the shared vault; a
    /// Connect pact with the member's vault is Active here; the slip was
    /// issued by that vault, names a grant, is bound to `issuer`'s key and
    /// has not expired. A later open for the same seat replaces the route,
    /// so a renewed slip takes the old one's place.
    ///
    /// # Errors
    ///
    /// The first of those rules that fails; an owner proof that does not
    /// stand; storage errors.
    pub fn open_inquiry_route(
        &self,
        owner: &AuthenticatedOwner,
        issuer: &HostSlipIssuer,
        request: &InquiryRouteRequest,
    ) -> Result<InquiryRoute> {
        let member_host = request.member_host.trim();
        let origin = member_host
            .strip_prefix("https://")
            .or_else(|| member_host.strip_prefix("http://"));
        if origin.is_none_or(|rest| rest.is_empty() || rest.contains(char::is_whitespace)) {
            return Err(refuse("a route names the member host as an http(s) origin"));
        }
        let claims = &request.slip.claims;
        if claims.vault_id != request.member_vault_id {
            return Err(refuse("the slip was not issued by the member's vault"));
        }
        if claims.binding_key != issuer.binding_key() {
            return Err(refuse("the slip is not bound to this host's key"));
        }
        let Some(edge_grant) = claims.grant_ref.clone() else {
            return Err(refuse("the slip names no inquiry edge grant"));
        };
        let slip_token = request.slip.to_token()?;
        self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            if claims.expires_at <= now {
                return Err(refuse("the slip has expired"));
            }
            let fold = self.authority_fold_readonly_in_txn(txn)?;
            if !fold.federation_pacts.values().any(|pact| {
                pact.peer_vault_id == request.member_vault_id
                    && pact.status == FederationPactStatus::Active
            }) {
                return Err(refuse(
                    "this vault has no Active Connect pact with the member's vault",
                ));
            }
            if !self.holds_inquiry_seat_in_txn(txn, request.shared_vault_id, request.member)? {
                return Err(refuse("the member holds no seat in that shared vault"));
            }
            let route = InquiryRoute {
                shared_vault_id: request.shared_vault_id,
                member: request.member,
                member_vault_id: request.member_vault_id,
                member_host: member_host.to_owned(),
                edge_grant,
                slip_token,
                slip_expires_at: claims.expires_at,
                opened_at: now,
            };
            ROUTES.put(
                &self.store,
                txn,
                &(request.shared_vault_id, request.member),
                &route,
            )?;
            Ok(route)
        })
    }

    /// The route to `member`'s vault in shared vault `shared_vault_id`, if
    /// one is open.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn inquiry_route(
        &self,
        shared_vault_id: u64,
        member: EntityId,
    ) -> Result<Option<InquiryRoute>> {
        let txn = self.store.env.read_txn()?;
        ROUTES.get(&self.store, &txn, &(shared_vault_id, member))
    }

    /// Whether `member` holds a seat in `shared_vault_id` that an inquiry
    /// may go to: a member role, delegates and guests aside.
    pub(crate) fn holds_inquiry_seat_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        shared_vault_id: u64,
        member: EntityId,
    ) -> Result<bool> {
        Ok(self
            .shared_members_in_txn(txn, shared_vault_id)?
            .iter()
            .any(|(person, _)| *person == member))
    }
}

/// The open route for `member`'s seat in `shared_vault_id`, read in the
/// caller's transaction.
pub(crate) fn inquiry_route_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    shared_vault_id: u64,
    member: EntityId,
) -> Result<Option<InquiryRoute>> {
    ROUTES.get(store, txn, &(shared_vault_id, member))
}

/// Ends the route of `member`'s seat in `shared_vault_id`, in the membership
/// writer's transaction: a leave, a removal or an Owner's hand-over ends the
/// seat and its route together. Returns whether a route was open.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn end_inquiry_route_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    shared_vault_id: u64,
    member: EntityId,
) -> Result<bool> {
    ROUTES.delete(store, wtxn, &(shared_vault_id, member))
}

/// An erase of `actor` drops every route of `actor`'s seats.
pub(crate) fn erase_inquiry_route_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    for (key, _) in ROUTES.scan(&vault.store, wtxn)? {
        if key.1 == *actor {
            ROUTES.delete(&vault.store, wtxn, &key)?;
        }
    }
    Ok(())
}
