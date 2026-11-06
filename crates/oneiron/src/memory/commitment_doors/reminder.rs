//! The owner's commitment reminder route as SDK verbs (OF-187): read it, or
//! set and clear it. Both doors act as the authenticated owner only; setting
//! the route approves no reminder and changes none already approved.

use serde::{Deserialize, Serialize};

use super::owner_in;
use crate::commitment_wake::CommitmentReminderRoute;
use crate::consent::AuthenticatedOwner;
use crate::error::Error;
use crate::memory::{Memory, MemoryResult};

/// `vault.commitments.reminder_route.set` input: the new route, or `null`
/// to stop reminding the owner. The route's own shape is the native one.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommitmentReminderRouteSetRequest {
    pub route: Option<CommitmentReminderRoute>,
}

/// The route as the owner sees it; `route: null` when none is set.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CommitmentReminderRouteReply {
    pub route: Option<CommitmentReminderRoute>,
}

impl Memory<'_> {
    /// Reads the owner's reminder route: the proof identity plus human
    /// check first, then the native side-table read.
    pub fn commitments_reminder_route_get_as(
        &self,
        owner: &AuthenticatedOwner,
    ) -> MemoryResult<CommitmentReminderRouteReply> {
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        owner_in(self, &txn, owner)?;
        drop(txn);
        Ok(CommitmentReminderRouteReply {
            route: self.vault.commitment_reminder_route()?,
        })
    }

    /// Sets (or, with `None`, clears) the owner's reminder route: the
    /// proof identity plus human check on a read transaction first, then
    /// the native setter, which validates the route and revalidates the
    /// owner in its own write transaction. No writer opens here, so the
    /// native writer never nests. Answers the submitted route itself, with
    /// no fallible re-read after the commit.
    pub fn commitments_reminder_route_set_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CommitmentReminderRouteSetRequest,
    ) -> MemoryResult<CommitmentReminderRouteReply> {
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        owner_in(self, &txn, owner)?;
        drop(txn);
        let route = input.route;
        self.vault
            .set_commitment_reminder_route(owner, route.as_ref())?;
        Ok(CommitmentReminderRouteReply { route })
    }
}
