//! Vault-local, receipt-backed ceremony observation; rate never denies signing.
use super::model::invalid;
use crate::side_table::{self, Named, Raw, SideTable};
use crate::{EntityId, Error, Result, Vault};
use serde::{Deserialize, Serialize};

const COUNT: SideTable<String, [u8; 16], Raw> = SideTable::new(&side_table::ESIGN_PUBLIC_RATE_V2);
const CHECK: SideTable<Vec<u8>, EsignRateCheck, Named> =
    SideTable::new(&side_table::ESIGN_PUBLIC_CHECK);

const WINDOW_SECS: u64 = 60;
const RECIPIENT_THRESHOLD: u64 = 120;
const DOCUMENT_THRESHOLD: u64 = 1200;

/// Local per-window call count. A capability is never stored in this receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EsignRateReceipt {
    pub document: String,
    pub recipient: Option<String>,
    pub window_started_at_secs: u64,
    pub count: u64,
}

/// OF-520 question at the first crossing of an advisory threshold.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EsignRateCheck {
    pub receipt: EsignRateReceipt,
    pub threshold: u64,
}
impl EsignRateCheck {
    pub const KIND: &'static str = "esign_ceremony_burst";
}

fn count_key(document: &str, recipient: Option<&str>) -> String {
    format!("{document}/{}", recipient.unwrap_or("all"))
}
fn check_key(document: &str, recipient: Option<&str>, window: u64) -> Vec<u8> {
    [
        document.as_bytes(),
        b"/",
        recipient.unwrap_or("all").as_bytes(),
        b"/",
        window.to_be_bytes().as_slice(),
    ]
    .concat()
}
fn decode_count(raw: &[u8]) -> Result<(u64, u64)> {
    let bytes: &[u8; 16] = raw
        .try_into()
        .map_err(|_| Error::CorruptedIndex("esign rate receipt"))?;
    Ok((
        u64::from_be_bytes(bytes[..8].try_into().map_err(|_| invalid("rate receipt"))?),
        u64::from_be_bytes(bytes[8..].try_into().map_err(|_| invalid("rate receipt"))?),
    ))
}

/// Called in its own transaction. Callers ignore observation errors: storage
/// accounting cannot change capability, turn, input-budget or consent verdicts.
pub(super) fn observe(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    document: &str,
    recipient: &str,
    now: u64,
) -> Result<()> {
    let window = now / WINDOW_SECS * WINDOW_SECS;
    for (scope, threshold) in [
        (Some(recipient), RECIPIENT_THRESHOLD),
        (None, DOCUMENT_THRESHOLD),
    ] {
        let key = count_key(document, scope);
        let count = match COUNT.get(&vault.store, txn, &key)? {
            Some(raw) => {
                let (prior_window, count) = decode_count(&raw)?;
                if prior_window == window { count } else { 0 }
            }
            None => 0,
        }
        .saturating_add(1);
        let receipt = EsignRateReceipt {
            document: document.to_owned(),
            recipient: scope.map(str::to_owned),
            window_started_at_secs: window,
            count,
        };
        if count > threshold {
            let check_key = check_key(document, scope, window);
            if CHECK.get(&vault.store, txn, &check_key)?.is_none() {
                let check = EsignRateCheck {
                    receipt: receipt.clone(),
                    threshold,
                };
                CHECK.put(&vault.store, txn, &check_key, &check)?;
            }
        }
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(&window.to_be_bytes());
        bytes[8..].copy_from_slice(&count.to_be_bytes());
        COUNT.put(&vault.store, txn, &key, &bytes)?;
    }
    Ok(())
}

impl Vault {
    /// Latest local accounting receipt for a document or one recipient.
    pub fn esign_rate_receipt(
        &self,
        document: EntityId,
        recipient: Option<&str>,
    ) -> Result<Option<EsignRateReceipt>> {
        let txn = self.store.env.read_txn()?;
        COUNT
            .get(&self.store, &txn, &count_key(&document.to_hex(), recipient))?
            .map(|raw| {
                let (window_started_at_secs, count) = decode_count(&raw)?;
                Ok(EsignRateReceipt {
                    document: document.to_hex(),
                    recipient: recipient.map(str::to_owned),
                    window_started_at_secs,
                    count,
                })
            })
            .transpose()
    }

    /// Durable, node-local OF-520 checks. A check never denies a ceremony call.
    pub fn esign_rate_checks(&self, document: EntityId) -> Result<Vec<EsignRateCheck>> {
        let txn = self.store.env.read_txn()?;
        let prefix = [document.to_hex().as_bytes(), b"/"].concat();
        let mut checks = Vec::new();
        for row in CHECK.iter_from(&self.store, &txn, &prefix)? {
            let (_, check) = row.map_err(|_| Error::CorruptedIndex("esign rate check"))?;
            if check.receipt.document != document.to_hex() {
                return Err(Error::CorruptedIndex("esign rate check document"));
            }
            checks.push(check);
        }
        Ok(checks)
    }
}
