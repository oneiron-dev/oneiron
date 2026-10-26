//! What a restore says of the custody head's compartments it left unopened
//! (FIX 9178): which key opens each, by public id alone.

use std::collections::BTreeSet;

use super::super::head::CompartmentScope;
use super::CustodyLanding;

/// Whether a compartment the restore left `unopened` may hold a key an image
/// requires: a world's holds its pads alone, which no image requires by
/// census (KS-5), so a missing key with only worlds unopened is missing.
pub(super) fn may_hold_required(unopened: &BTreeSet<CompartmentScope>) -> bool {
    unopened
        .iter()
        .any(|scope| !matches!(scope, CompartmentScope::WorldPad(_)))
}

/// The refusal's words for `count` key(s) the backup needs that no
/// compartment the restore opened holds, naming what opens each one it left
/// `unopened`: the backup's data key or the recovery kit for the
/// host-readable one, the kit for the owner-only one, and for a world's pads
/// the key of a machine admitted to that world or a kit root it admits.
/// Never a key, only world ids.
pub(super) fn owner_key_required(count: usize, unopened: &BTreeSet<CompartmentScope>) -> String {
    let mut openers = Vec::new();
    let mut worlds = Vec::new();
    for scope in unopened {
        match scope {
            CompartmentScope::HostReadable => openers.push(
                "the host-readable compartment opens with the backup's data key or the recovery \
                 kit (--unlock kit)"
                    .to_owned(),
            ),
            CompartmentScope::OwnerOnly => openers.push(
                "the owner-only compartment opens with the recovery kit (--unlock kit)".to_owned(),
            ),
            CompartmentScope::WorldPad(scope) => worlds.push(scope.world().to_hex()),
        }
    }
    if !worlds.is_empty() {
        openers.push(format!(
            "the pads of world(s) {} open with the key of a machine admitted to that world or a \
             recovery kit whose root it admits (--unlock kit)",
            worlds.join(", ")
        ));
    }
    format!(
        "{count} key(s) the backup needs are in no custody head compartment this restore opened: \
         {}",
        openers.join("; ")
    )
}

impl CustodyLanding {
    /// Whether the head this restore landed holds an owner-only compartment
    /// its opener did not open (FIX-LIST 9246 item 4): the one place an
    /// eligible credential's missing key may still ride.
    pub(crate) fn owner_compartment_unopened(&self) -> bool {
        self.admitted.owner_unopened
    }
}
