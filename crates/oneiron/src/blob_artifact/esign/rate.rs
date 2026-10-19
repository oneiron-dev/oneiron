//! Vault-local, receipt-backed ceremony observation and signature-upload
//! `[limits]` crossings; neither ever denies signing.
use super::model::invalid;
use crate::limit_ask::EngineLimit;
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
    /// The `[limits]` row, by its config key, a signature upload crossed,
    /// when this check is that crossing and not a ceremony burst (FIX 3807):
    /// `threshold` is then the row's bound and `receipt.count` what the
    /// upload measured.
    #[serde(default)]
    pub limit: Option<String>,
}
impl EsignRateCheck {
    pub const KIND: &'static str = "esign_ceremony_burst";
    /// The kind of a signature upload's `[limits]` crossing.
    pub const LIMIT_KIND: &'static str = "esign_signature_limit";
}

/// One signature upload's measure past one of its `[limits]` rows: the row,
/// the bound it stood at and what the upload measured.
pub(super) type LimitCrossing = (EngineLimit, u64, u64);

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
                    limit: None,
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

/// Keeps each of one signature upload's `[limits]` crossings as a check,
/// the first of its row in its window, which the host's OF-520 worker asks
/// the envelope's sender as it asks a ceremony burst (FIX 3807, Engine ruling
/// 10-19). A check never holds or refuses the upload: it is stored and bound.
pub(super) fn keep_limit_crossings(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    document: &str,
    recipient: &str,
    crossings: &[LimitCrossing],
    now: u64,
) -> Result<()> {
    let window = now / WINDOW_SECS * WINDOW_SECS;
    for &(row, bound, observed) in crossings {
        let key = [
            check_key(document, Some(recipient), window).as_slice(),
            b"/",
            row.key().as_bytes(),
        ]
        .concat();
        if CHECK.get(&vault.store, txn, &key)?.is_none() {
            let check = EsignRateCheck {
                receipt: EsignRateReceipt {
                    document: document.to_owned(),
                    recipient: Some(recipient.to_owned()),
                    window_started_at_secs: window,
                    count: observed,
                },
                threshold: bound,
                limit: Some(row.key().to_owned()),
            };
            CHECK.put(&vault.store, txn, &key, &check)?;
        }
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

    /// Every kept check past `after`, in key order, each with the cursor
    /// that names it (its key in hex): what the host's OF-520 worker reads.
    pub fn esign_rate_checks_after(
        &self,
        after: Option<&str>,
    ) -> Result<Vec<(String, EsignRateCheck)>> {
        let txn = self.store.env.read_txn()?;
        let mut checks = Vec::new();
        for row in CHECK.iter_from(&self.store, &txn, &[])? {
            let (key, check) = row.map_err(|_| Error::CorruptedIndex("esign rate check"))?;
            let cursor = crate::entity_id::bytes_to_hex_lower(&key);
            if after.is_none_or(|after| cursor.as_str() > after) {
                checks.push((cursor, check));
            }
        }
        Ok(checks)
    }
}
