//! Registers a machine's sync connection with the `vault.residence.*` rows,
//! as the device sync loop registers the connection it runs
//! (`crate::residence_machines::register`), so a test reaches a row's applied
//! leg on this host without a live home.

use std::sync::Arc;

use oneiron::EntityId;
use oneiron::sync::SyncConnection;

/// Makes `connection` the one the residence rows reach for `machine`.
pub fn register_residence_connection(machine: EntityId, connection: &Arc<SyncConnection>) {
    crate::residence_machines::register(machine, connection);
}
