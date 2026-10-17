//! The machines whose residence this host can act on (OF-534, FIX 531): the
//! `vault.residence.*` rows name a machine, and its own `SyncConnection`
//! applies each one. A host registers each connection it runs under its
//! machine id ([`register`]); a row naming a machine with none registered
//! here is refused, never guessed onto another machine. The registry holds
//! weak references, so a connection that ends leaves nothing reachable.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, Weak};

use oneiron::EntityId;
use oneiron::sync::SyncConnection;

fn machines() -> &'static Mutex<HashMap<EntityId, Weak<SyncConnection>>> {
    static MACHINES: OnceLock<Mutex<HashMap<EntityId, Weak<SyncConnection>>>> = OnceLock::new();
    MACHINES.get_or_init(Mutex::default)
}

/// Makes `connection` the one the residence rows reach for `machine`.
#[allow(
    dead_code,
    reason = "L03 registers the device sync connection it runs (FIX 531)"
)]
pub(crate) fn register(machine: EntityId, connection: &Arc<SyncConnection>) {
    if let Ok(mut machines) = machines().lock() {
        machines.retain(|_, connection| connection.strong_count() > 0);
        machines.insert(machine, Arc::downgrade(connection));
    }
}

/// The live connection registered for `machine`, if any.
pub(crate) fn connection(machine: &EntityId) -> Option<Arc<SyncConnection>> {
    machines().lock().ok()?.get(machine)?.upgrade()
}
