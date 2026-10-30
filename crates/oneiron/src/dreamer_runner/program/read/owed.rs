//! The wakes a landed turn still owes its programs (FIX 12172): each one no
//! admission has decided yet, with the hold an admission keeps it owed
//! under when its sealed slip lapsed (FIX 12058) and the second that hold
//! expires, so the waking actor or the owner sees a wake that waits for its
//! rebind. The read admits, drains and holds nothing.

use crate::Vault;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{ErrorKind, Result};

use super::super::WAKE;
use super::super::types::TurnProgramWake;
use super::views::{OwedWakeHoldView, TurnProgramOwedWakeItem};
use super::{Caller, class_name};

/// The wakes `turn` still owes the armed programs `caller` reads (only the
/// one `registration` names, when it names one), in registration order, in
/// `txn`. A row that does not decode is passed over.
pub(super) fn owed_wakes_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: EntityId,
    registration: Option<EntityId>,
    caller: &Caller,
) -> Result<Vec<TurnProgramWake>> {
    let mut owed = Vec::new();
    for row in WAKE.iter_from(vault, txn, turn.as_bytes())? {
        let wake = match row {
            Ok((_, wake)) => wake,
            Err(error) if error.kind() == ErrorKind::SideTableRow => continue,
            Err(error) => return Err(error),
        };
        if wake.turn.turn == turn
            && registration.is_none_or(|registration| registration == wake.registration)
            && caller.reads(wake.authority.actor(), wake.authority.class_byte())
        {
            owed.push(wake);
        }
    }
    Ok(owed)
}

/// One owed wake as the caller reads it: its hold's expiry derives from the
/// turn's landing, so it is withheld unless the turn reads on the caller's
/// lane (`turn_reads`).
pub(super) fn owed_wake_item(wake: TurnProgramWake, turn_reads: bool) -> TurnProgramOwedWakeItem {
    let mut withheld = Vec::new();
    let held = wake.held.map(|hold| {
        if !turn_reads {
            withheld.push("held.expires_at".to_owned());
        }
        OwedWakeHoldView {
            reason: hold.reason,
            held_at: hold.held_at,
            expires_at: turn_reads.then_some(hold.expires_at),
        }
    });
    TurnProgramOwedWakeItem {
        registration: wake.registration,
        actor: wake.authority.actor(),
        actor_class: class_name(wake.authority.class_byte()),
        revision: bytes_to_hex_lower(&wake.revision),
        sealed_scope: wake
            .authority
            .scope_digest()
            .map(|digest| bytes_to_hex_lower(&digest)),
        held,
        withheld,
    }
}
