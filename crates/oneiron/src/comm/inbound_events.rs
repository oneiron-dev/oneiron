//! The inbound reply and STOP events an admission records in its own write,
//! for the projector's next pass.

use super::claims::CommError;
use super::parties::resolve_or_create_party_in_txn;
use super::projector::put_source_event_in_txn;
use super::records::{CommEventKind, validate_channel_class, validate_key_string};
use crate::Vault;
use crate::counterparty_contact::normalize_channel_class;
use crate::error::Error;

/// [`super::record_comm_inbound_reply`] in the caller's write, so the event lands
/// with the inbound admission that took the message, or not at all. The
/// channel class is normalized first. A party key or channel class the comm
/// family cannot hold records nothing: the message is admitted either way.
pub(crate) fn record_comm_inbound_reply_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    party: &str,
    channel_class: &str,
    occurred_at: u64,
) -> crate::error::Result<()> {
    record_inbound_event_in_txn(
        vault,
        wtxn,
        party,
        channel_class,
        CommEventKind::InboundReply,
        occurred_at,
    )
}

/// [`super::record_comm_inbound_stop`] in the caller's write, as
/// [`record_comm_inbound_reply_in_txn`] records a reply: the STOP's send hold
/// starts in this write, and the projector's next pass makes it the party's
/// standing opt-out on the channel.
pub(crate) fn record_comm_inbound_stop_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    party: &str,
    channel_class: &str,
    occurred_at: u64,
) -> crate::error::Result<()> {
    record_inbound_event_in_txn(
        vault,
        wtxn,
        party,
        channel_class,
        CommEventKind::InboundStop,
        occurred_at,
    )
}

fn record_inbound_event_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    party: &str,
    channel_class: &str,
    kind: CommEventKind,
    occurred_at: u64,
) -> crate::error::Result<()> {
    let channel_class = normalize_channel_class(channel_class);
    if validate_key_string(party).is_err() || validate_channel_class(&channel_class).is_err() {
        return Ok(());
    }
    resolve_or_create_party_in_txn(vault, wtxn, party)
        .and_then(|party_ref| {
            put_source_event_in_txn(
                vault,
                wtxn,
                party_ref,
                kind,
                Some(channel_class.as_str()),
                None,
                occurred_at,
            )
        })
        .map(|_| ())
        .map_err(|error| match error {
            CommError::Engine(error) => error,
            _ => Error::InvalidClaimBody("inbound comm record refused"),
        })
}
