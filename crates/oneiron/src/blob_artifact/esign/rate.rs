//! Vault-local, receipt-backed ceremony observation and the `[limits]`
//! crossings of signature uploads and signing door bodies; neither ever
//! denies signing.
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
    /// The `[limits]` row, by its config key, a signature upload or a signing
    /// door's request body crossed, when this check is that crossing and not
    /// a ceremony burst (FIX 3807, 3808): `threshold` is then the row's bound
    /// and `receipt.count` what the upload or body measured.
    #[serde(default)]
    pub limit: Option<String>,
}
impl EsignRateCheck {
    pub const KIND: &'static str = "esign_ceremony_burst";
    /// The kind of a signature upload's or a signing door body's `[limits]`
    /// crossing.
    pub const LIMIT_KIND: &'static str = "esign_signature_limit";
}

/// One signature upload's or signing door body's measure past one of its
/// `[limits]` rows: the row, the bound it stood at and what was measured.
pub(super) type LimitCrossing = (EngineLimit, u64, u64);

fn count_key(document: &str, recipient: Option<&str>) -> String {
    format!("{document}/{}", recipient.unwrap_or("all"))
}
/// A kept check's key. It leads with the recorded clock read in the
/// transaction that keeps it and a store-local id minted there, both
/// big-endian, then names its document, scope and window (and a crossing's
/// row). Writes commit one at a time and both lead fields only rise, so key
/// order is the order checks were kept: the host's one cursor past the last
/// key it read never passes over a check kept later, whatever its document
/// (FIX 5206).
fn check_key(
    vault: &Vault,
    document: &str,
    recipient: Option<&str>,
    window: u64,
    row: Option<EngineLimit>,
) -> Result<Vec<u8>> {
    let mut key = [
        vault.now_recorded_at().to_be_bytes().as_slice(),
        vault.new_entity_id()?.as_bytes().as_slice(),
        document.as_bytes(),
        b"/",
        recipient.unwrap_or("all").as_bytes(),
        b"/",
        window.to_be_bytes().as_slice(),
    ]
    .concat();
    if let Some(row) = row {
        key.extend_from_slice(b"/");
        key.extend_from_slice(row.key().as_bytes());
    }
    Ok(key)
}

/// Whether a check for this recipient's `row` crossing was kept in `window`
/// already. Every such check was kept at or after the window opened, so only
/// keys from its start on are read.
fn limit_kept_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    document: &str,
    recipient: &str,
    window: u64,
    row: EngineLimit,
) -> Result<bool> {
    let start = window.to_be_bytes().to_vec();
    for kept in CHECK.iter_range(
        &vault.store,
        txn,
        std::ops::Bound::Included(&start),
        std::ops::Bound::Unbounded,
    )? {
        let (_, check) = kept.map_err(|_| Error::CorruptedIndex("esign rate check"))?;
        if check.receipt.window_started_at_secs == window
            && check.receipt.document == document
            && check.receipt.recipient.as_deref() == Some(recipient)
            && check.limit.as_deref() == Some(row.key())
        {
            return Ok(true);
        }
    }
    Ok(false)
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
        // The count rises by one a call within its window, so it passes the
        // threshold exactly once there: that call keeps the window's check.
        if count == threshold.saturating_add(1) {
            let check = EsignRateCheck {
                receipt,
                threshold,
                limit: None,
            };
            CHECK.put(
                &vault.store,
                txn,
                &check_key(vault, document, scope, window, None)?,
                &check,
            )?;
        }
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(&window.to_be_bytes());
        bytes[8..].copy_from_slice(&count.to_be_bytes());
        COUNT.put(&vault.store, txn, &key, &bytes)?;
    }
    Ok(())
}

/// Keeps each of one signature upload's or signing door body's `[limits]`
/// crossings as a check, the first of its row in its window, which the
/// host's OF-520 worker asks the envelope's sender as it asks a ceremony
/// burst (FIX 3807, 3808, Engine ruling 10-19). A check never holds or
/// refuses the upload or the body: each is served whole.
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
        if !limit_kept_in(vault, txn, document, recipient, window, row)? {
            let key = check_key(vault, document, Some(recipient), window, Some(row))?;
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

    /// Durable, node-local OF-520 checks, in the order they were kept. A
    /// check never denies a ceremony call.
    pub fn esign_rate_checks(&self, document: EntityId) -> Result<Vec<EsignRateCheck>> {
        let txn = self.store.env.read_txn()?;
        let document = document.to_hex();
        let mut checks = Vec::new();
        for row in CHECK.iter_from(&self.store, &txn, &[])? {
            let (_, check) = row.map_err(|_| Error::CorruptedIndex("esign rate check"))?;
            if check.receipt.document == document {
                checks.push(check);
            }
        }
        Ok(checks)
    }

    /// Every kept check past `after`, in key order, which is the order they
    /// were kept, each with the cursor that names it (its key in hex): what
    /// the host's OF-520 worker reads.
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
