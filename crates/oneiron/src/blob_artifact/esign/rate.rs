//! Vault-local ceremony rate accounting; no process-global counters.
use super::model::invalid;
use crate::{Result, Vault};
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
        let key = [b"esign.public_rate.v1/".as_slice(), suffix.as_bytes()].concat();
        let window = now / 60;
        let (prior, count) = if let Some(bytes) = vault.store.vault_meta.get(txn, &key)? {
            if bytes.len() != 12 {
                return Err(invalid("rate record"));
            }
            (
                u64::from_be_bytes(bytes[..8].try_into().map_err(|_| invalid("rate record"))?),
                u32::from_be_bytes(bytes[8..].try_into().map_err(|_| invalid("rate record"))?),
            )
        } else {
            (window, 0)
        };
        let count = if prior == window { count } else { 0 };
        if count >= limit {
            return Err(invalid("ceremony rate limit; retry next minute"));
        }
        vault.store.vault_meta.put(
            txn,
            &key,
            &[
                window.to_be_bytes().as_slice(),
                (count + 1).to_be_bytes().as_slice(),
            ]
            .concat(),
        )?;
    }
    Ok(())
}
