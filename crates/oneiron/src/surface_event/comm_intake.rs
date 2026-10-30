//! The comm record an admitted inbound surface event leaves for the comm
//! projector.

use super::{SurfaceEvent, SurfaceEventAction, SurfaceInteractionKind};
use crate::Vault;
use crate::error::Result;

/// Records, in the admission's write, what `event` tells the comm projector
/// about its counterparty. A message is a touch on its channel, which the
/// projector makes their `comm.last_touch`. An opt-out is a STOP: it holds
/// sends to them on the channel from this write, and the projector makes it
/// their standing opt-out. Any other interaction records nothing.
pub(super) fn record_comm_inbound_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    event: &SurfaceEvent,
) -> Result<()> {
    let party = event.counterparty.reference_key();
    match &event.action {
        SurfaceEventAction::Message => crate::comm::record_comm_inbound_reply_in_txn(
            vault,
            wtxn,
            &party,
            &event.channel,
            event.received_at,
        ),
        SurfaceEventAction::Interaction {
            interaction: SurfaceInteractionKind::OptOut,
            ..
        } => crate::comm::record_comm_inbound_stop_in_txn(
            vault,
            wtxn,
            &party,
            &event.channel,
            event.received_at,
        ),
        SurfaceEventAction::Interaction { .. } => Ok(()),
    }
}
