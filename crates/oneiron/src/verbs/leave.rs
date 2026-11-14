//! The inputs and answers of the leaving rows (ARCH-0043
//! #leaving-a-company, L7-09): `vault.leave.holdings`, what this vault holds
//! from another vault by attribution, and `vault.leave.erase_requests.send`,
//! the one action that asks that vault to erase what it holds from this one.
//! Both are the owner's. The holdings read is a projection of this vault's
//! delivery history, so a server and an embedded handle answer it alike.
//! The send signs with a server's own authority key and queues through its
//! courtesy outbox, so an embedded handle refuses it
//! ([`super::courtesy_delete_host_only`]). A member ends its inquiry edges
//! first (`vault.inquiry.edge.end`), so its pact with the company is ended
//! and the ask can be signed.

use serde::{Deserialize, Serialize};

use super::courtesy_delete::{CourtesyDeleteSent, courtesy_delete_sent_ask};
use super::inquiry::vault_id;
use crate::consent::AuthenticatedOwner;
use crate::deletion::CooperativeDeletionNotice;
use crate::entity_id::bytes_to_hex_lower;
use crate::federation::Holdings;
use crate::memory::MemoryResult;
use crate::{EntityId, Vault};

/// `vault.leave.holdings`'s input: the other vault, as 64 hex.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LeaveHoldingsRequest {
    pub peer_vault: String,
}

/// One world here that holds what the other vault delivered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LeaveHeldWorld {
    /// The world as this vault names it: the foreign WORLD a delivery
    /// landed in, or base reality's id.
    pub world: EntityId,
    /// The delivered records this vault still holds.
    pub records: Vec<EntityId>,
    /// The pacts with the other vault that delivered into it or registered
    /// it, as 64 hex each.
    pub pacts: Vec<String>,
    /// Whether a pact registered the world, as a synced world is; a copied
    /// inquiry answer's world is not.
    pub registered: bool,
}

/// `vault.leave.holdings`'s answer: what this vault holds from the other
/// vault, world by world.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LeaveHoldings {
    /// The other vault, as 64 hex.
    pub peer_vault: String,
    pub worlds: Vec<LeaveHeldWorld>,
}

/// `vault.leave.erase_requests.send`'s input: the other vault (64 hex) and
/// its host origin, `https://host[:port]`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LeaveEraseRequestsSendRequest {
    pub peer_vault: String,
    pub peer: String,
}

/// `vault.leave.erase_requests.send`'s answer: one ask per ended pact with
/// the other vault, in pact order, each as `vault.courtesy_delete.sent`
/// lists it. An ask the action had already queued is listed as it stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LeaveEraseRequestsSent {
    pub asks: Vec<CourtesyDeleteSent>,
}

/// The wire view of [`Holdings`].
pub fn leave_holdings_view(holdings: Holdings) -> LeaveHoldings {
    LeaveHoldings {
        peer_vault: bytes_to_hex_lower(&holdings.peer_vault_id),
        worlds: holdings
            .worlds
            .into_iter()
            .map(|held| LeaveHeldWorld {
                world: held.world,
                records: held.records,
                pacts: held
                    .pacts
                    .iter()
                    .map(|pact| bytes_to_hex_lower(pact.as_slice()))
                    .collect(),
                registered: held.registered,
            })
            .collect(),
    }
}

/// `vault.leave.holdings` for `owner`, on a server or an embedded handle.
///
/// # Errors
///
/// `peer_vault` is not 64 hex; the owner's proof no longer holds; storage
/// errors.
pub fn read_leave_holdings(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: LeaveHoldingsRequest,
) -> MemoryResult<LeaveHoldings> {
    let peer_vault_id = vault_id("peer_vault", &input.peer_vault)?;
    Ok(leave_holdings_view(
        vault.holdings_from(owner, &peer_vault_id)?,
    ))
}

/// The answer of `vault.leave.erase_requests.send` for the asks it queued.
pub fn leave_erase_requests_sent(
    notices: Vec<CooperativeDeletionNotice>,
) -> LeaveEraseRequestsSent {
    LeaveEraseRequestsSent {
        asks: notices.into_iter().map(courtesy_delete_sent_ask).collect(),
    }
}
