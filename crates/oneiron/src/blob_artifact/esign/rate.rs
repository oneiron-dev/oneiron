//! Vault-local, receipt-backed ceremony observation and the `[limits]`
//! crossings of signature uploads and signing door bodies; neither ever
//! denies signing.
use super::model::{EsignAuthenticationMethod, invalid};
use crate::limit_ask::EngineLimit;
use crate::side_table::{self, Named, Raw, SideTable};
use crate::{EntityId, Error, Result, Vault};
use serde::{Deserialize, Serialize};

const COUNT: SideTable<String, Vec<u8>, Raw> = SideTable::new(&side_table::ESIGN_PUBLIC_RATE_V2);
const CHECK: SideTable<Vec<u8>, EsignRateCheck, Named> =
    SideTable::new(&side_table::ESIGN_PUBLIC_CHECK);

const WINDOW_SECS: u64 = 60;

fn unknown_esign_rate_verb() -> String {
    "unknown".to_owned()
}
fn unknown_esign_rate_actor_class() -> String {
    "unknown".to_owned()
}

/// Local per-window call count. A capability is never stored in this receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EsignRateReceipt {
    pub document: String,
    pub recipient: Option<String>,
    pub window_started_at_secs: u64,
    pub count: u64,
    /// The call's verb and class; old mixed counter reads say "unknown".
    #[serde(default = "unknown_esign_rate_verb")]
    pub verb: String,
    #[serde(default = "unknown_esign_rate_actor_class")]
    pub actor_class: String,
    /// The verified actor id, or `None` for bearer-only or an id-less credential.
    #[serde(default)]
    pub actor: Option<String>,
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
/// The latest call's verb, class and actor travel with the counter, so a
/// fresh receipt names what it counted. Counts and windows are unchanged.
fn encode_count(
    window: u64,
    count: u64,
    verb: &str,
    actor_class: &str,
    actor: Option<&str>,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(19 + verb.len() + actor_class.len());
    bytes.extend_from_slice(&window.to_be_bytes());
    bytes.extend_from_slice(&count.to_be_bytes());
    for part in [verb, actor_class] {
        bytes.extend_from_slice(&(part.len() as u16).to_be_bytes());
        bytes.extend_from_slice(part.as_bytes());
    }
    match actor {
        Some(actor) => {
            bytes.push(1);
            bytes.extend_from_slice(&(actor.len() as u16).to_be_bytes());
            bytes.extend_from_slice(actor.as_bytes());
        }
        None => bytes.push(0),
    }
    bytes
}
fn decode_part(raw: &[u8], mut at: usize) -> Result<(String, usize)> {
    let end = at
        .checked_add(2)
        .filter(|&end| end <= raw.len())
        .ok_or_else(|| Error::CorruptedIndex("esign rate receipt"))?;
    let len = u16::from_be_bytes([raw[at], raw[at + 1]]) as usize;
    at = end;
    let end = at
        .checked_add(len)
        .filter(|&end| end <= raw.len())
        .ok_or_else(|| Error::CorruptedIndex("esign rate receipt"))?;
    let part = str::from_utf8(&raw[at..end])
        .map_err(|_| Error::CorruptedIndex("esign rate receipt"))?
        .to_owned();
    Ok((part, end))
}
fn decode_count(raw: &[u8]) -> Result<(u64, u64, String, String, Option<String>)> {
    if raw.len() == 16 {
        // Rows kept before evidence travelled with the counter.
        let (window, count) = (
            u64::from_be_bytes(raw[..8].try_into().map_err(|_| invalid("rate receipt"))?),
            u64::from_be_bytes(raw[8..].try_into().map_err(|_| invalid("rate receipt"))?),
        );
        return Ok((
            window,
            count,
            unknown_esign_rate_verb(),
            unknown_esign_rate_actor_class(),
            None,
        ));
    }
    if raw.len() < 19 {
        return Err(Error::CorruptedIndex("esign rate receipt"));
    }
    let window = u64::from_be_bytes(raw[..8].try_into().map_err(|_| invalid("rate receipt"))?);
    let count = u64::from_be_bytes(raw[8..16].try_into().map_err(|_| invalid("rate receipt"))?);
    let (verb, at) = decode_part(raw, 16)?;
    let (actor_class, mut at) = decode_part(raw, at)?;
    if at >= raw.len() {
        return Err(Error::CorruptedIndex("esign rate receipt"));
    }
    let present = raw[at];
    at += 1;
    let actor = match present {
        0 => None,
        1 => {
            let (actor, end) = decode_part(raw, at)?;
            if end != raw.len() {
                return Err(Error::CorruptedIndex("esign rate receipt"));
            }
            Some(actor)
        }
        _ => return Err(Error::CorruptedIndex("esign rate receipt")),
    };
    if present == 0 && at != raw.len() {
        return Err(Error::CorruptedIndex("esign rate receipt"));
    }
    Ok((window, count, verb, actor_class, actor))
}

/// Called in its own transaction. Callers ignore observation errors: storage
/// accounting cannot change capability, turn, input-budget or consent verdicts.
pub(super) fn observe(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    document: &str,
    recipient: &str,
    now: u64,
    verb: &str,
    authentication_method: EsignAuthenticationMethod,
    verified_actor: Option<EntityId>,
) -> Result<()> {
    let window = now / WINDOW_SECS * WINDOW_SECS;
    let thresholds = vault
        .store
        .gate_hooks
        .esign_rate_thresholds_in_txn(&vault.store, txn);
    for (scope, threshold) in [
        (Some(recipient), thresholds.recipient),
        (None, thresholds.document),
    ] {
        let key = count_key(document, scope);
        let count = match COUNT.get(&vault.store, txn, &key)? {
            Some(raw) => {
                let (prior_window, count, _, _, _) = decode_count(&raw)?;
                if prior_window == window { count } else { 0 }
            }
            None => 0,
        }
        .saturating_add(1);
        let actor_class = match authentication_method {
            EsignAuthenticationMethod::Bearer => "bearer",
            EsignAuthenticationMethod::Person => "person",
            EsignAuthenticationMethod::Agent => "agent",
        };
        let receipt = EsignRateReceipt {
            document: document.to_owned(),
            recipient: scope.map(str::to_owned),
            window_started_at_secs: window,
            count,
            verb: verb.to_owned(),
            actor_class: actor_class.to_owned(),
            actor: verified_actor.map(|actor| actor.to_hex()),
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
        COUNT.put(
            &vault.store,
            txn,
            &key,
            &encode_count(
                window,
                count,
                verb,
                actor_class,
                verified_actor.map(|actor| actor.to_hex()).as_deref(),
            ),
        )?;
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
                    verb: unknown_esign_rate_verb(),
                    actor_class: unknown_esign_rate_actor_class(),
                    actor: None,
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
                let (window_started_at_secs, count, verb, actor_class, actor) = decode_count(&raw)?;
                Ok(EsignRateReceipt {
                    document: document.to_hex(),
                    recipient: recipient.map(str::to_owned),
                    window_started_at_secs,
                    count,
                    verb,
                    actor_class,
                    actor,
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
