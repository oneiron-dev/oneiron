//! The machine readiness Setting key (pass 34 sections 6.3 and 16, practice 6; row Q4): rows
//! the setting catalogue reads from this file.

use crate::EntityId;
use crate::setting::{ItemDomain, Kind};

/// Three failed checks in a row: 45 minutes at the 900 s period.
const fn escalate_after_default() -> u32 {
    3
}

/// Whether `item` names a machine: an entity ref in lower-case hex, the one spelling the
/// issuer reads, so no row sits under another spelling of the same machine.
fn is_machine_ref(item: &str) -> bool {
    EntityId::from_hex(item).is_ok_and(|machine| machine.to_hex() == item)
}

crate::setting::setting_keys! {
    /// How many failed readiness checks in a row a machine reports before its issuer asks the
    /// owner, once for that run (`Vault::raise_machine_readiness_ask`). One item per machine,
    /// named by its ref in hex. Three by default. Fewer is tighter: the owner hears sooner. A
    /// raise is the looser direction, so an agent's raise waits on the owner's answer. A value
    /// under one reads as one, and a row that does not decode reads as three.
    pub(crate) MACHINE_READINESS_ESCALATE_AFTER: u32 = "machines.readiness.escalate_after" {
        kind: Kind::new(escalate_after_default)
            .strictest(escalate_after_default)
            .lower(),
        item: Some(ItemDomain { name: "machine refs", admits: is_machine_ref }),
    };
}
