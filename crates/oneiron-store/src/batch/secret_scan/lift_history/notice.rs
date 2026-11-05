//! The needs-you notice of the lift proposals (OF-067). It is an inbox Ask
//! (`NOTIFICATION`), raised as the found-key notice is: non-blocking, one per
//! owner. A run that files proposals raises one notice for the proposals left
//! open, counted by cause, whose result points at `vault.secrets.lift_history`;
//! the next such run's notice replaces it, and it resolves, acknowledged for
//! each owner it was raised for, once no proposal is open. It names no row
//! and holds no value.

use std::collections::BTreeMap;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_NOTIFICATION;
use oneiron_contracts::entity_id::EntityId;

/// Producer name of the lift proposals' notice.
pub const NOTIFICATION_PRODUCER_SECRET_LIFT: &str = "secret.lift_proposals";

/// Where the notice sends the owner: the row that lists the proposals and
/// closes them.
pub const POINTER: &str = "vault.secrets.lift_history";

/// The notice raised last: the run that raised it, and each owner's inbox
/// row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiftNotice {
    pub run_id: EntityId,
    /// `(notification, owner)`.
    pub raised: Vec<(EntityId, EntityId)>,
}
