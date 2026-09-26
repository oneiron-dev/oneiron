//! Vault-local ceremony rate accounting; no process-global counters.
use super::model::invalid;
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::{Result, Vault};

/// Public ceremony rate counter. Key: hex32 [/ string].
const PUBLIC_RATE: SideTable<String, RateWindow, Raw> =
    SideTable::new(&side_table::ESIGN_PUBLIC_RATE);

/// A one-minute rate window: the window index the count belongs to, and the
/// count within it. Eight big-endian bytes then four big-endian bytes; any
/// other length is a corrupted rate row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RateWindow {
    window: u64,
    count: u32,
}

impl RawValue for RateWindow {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok([
            self.window.to_be_bytes().as_slice(),
            self.count.to_be_bytes().as_slice(),
        ]
        .concat())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        if bytes.len() != 12 {
            return Err(invalid("rate record").into());
        }
        Ok(Self {
            window: u64::from_be_bytes(bytes[..8].try_into().map_err(|_| invalid("rate record"))?),
            count: u32::from_be_bytes(bytes[8..].try_into().map_err(|_| invalid("rate record"))?),
        })
    }
}

pub(super) fn admit(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    document: &str,
    recipient: &str,
    now: u64,
) -> Result<()> {
    for (suffix, limit) in [
        (format!("{document}/{recipient}"), 120u32),
        (document.to_owned(), 1200u32),
    ] {
        let window = now / 60;
        let (prior, count) = match PUBLIC_RATE.get(&vault.store, txn, &suffix)? {
            Some(row) => (row.window, row.count),
            None => (window, 0),
        };
        let count = if prior == window { count } else { 0 };
        if count >= limit {
            return Err(invalid("ceremony rate limit; retry next minute"));
        }
        PUBLIC_RATE.put(
            &vault.store,
            txn,
            &suffix,
            &RateWindow {
                window,
                count: count + 1,
            },
        )?;
    }
    Ok(())
}
