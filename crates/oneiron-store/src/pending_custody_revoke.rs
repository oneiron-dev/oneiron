//! The custody revokes this install still owes the owner's other machines
//! (CALLS CUSTODY_REVOKE_PENDING_CARRY): one value-free row per custody
//! record. Custody's revoke carry (`secret_custody::control`) writes and
//! settles them; an erase of the owner drops his.

use oneiron_authority::authority::ActSurface;
use serde::{Deserialize, Serialize};

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// One revoke this install has not carried yet. It holds no value and no
/// proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRevoke {
    /// The owner PERSON the revoke is by.
    pub owner: EntityId,
    /// Where he decided it: audit only.
    pub surface: ActSurface,
    /// The second the revoke was made at: its transition's.
    pub at: u64,
    /// The generation it revoked.
    pub generation: u32,
}
