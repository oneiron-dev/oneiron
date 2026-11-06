//! Parse an event after placing its normalized data in its raw owner.

use oneiron::Vault;
use oneiron::outbound_consent::{RawOutboundBody, ZeroizingBufReader};
use serde_json::Value;
use zeroize::Zeroizing;

pub(super) fn read(
    mut event: Zeroizing<String>,
    vault: Option<&Vault>,
) -> Result<Option<(Value, RawOutboundBody)>, ()> {
    if let Some(vault) = vault
        && let Ok(body) = RawOutboundBody::read_spooled(vault, event.as_bytes())
    {
        drop(event);
        return match serde_json::from_reader(ZeroizingBufReader::new(body.reader())) {
            Ok(message) => Ok(Some((message, body))),
            Err(error) if error.is_io() => Err(()),
            Err(_) => Ok(None),
        };
    }
    Ok(serde_json::from_str(&event).ok().map(|message| {
        let body = RawOutboundBody::from_bytes(std::mem::take(&mut *event).into_bytes());
        (message, body)
    }))
}
