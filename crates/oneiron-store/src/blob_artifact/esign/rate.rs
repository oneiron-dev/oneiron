//! Vault-local, receipt-backed ceremony observation and the `[limits]`
//! crossings of signature uploads and signing door bodies; neither ever
//! denies signing.
use crate::blob_artifact::esign::model::EsignAuthenticationMethod;
use crate::blob_artifact::esign::model::invalid;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::limit_ask::EngineLimit;
use serde::{Deserialize, Serialize};

pub const WINDOW_SECS: u64 = 60;

pub fn unknown_esign_rate_verb() -> String {
    "unknown".to_owned()
}
pub fn unknown_esign_rate_actor_class() -> String {
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
pub type LimitCrossing = (EngineLimit, u64, u64);

pub fn count_key(document: &str, recipient: Option<&str>) -> String {
    format!("{document}/{}", recipient.unwrap_or("all"))
}

/// The latest call's verb, class and actor travel with the counter, so a
/// fresh receipt names what it counted. Counts and windows are unchanged.
pub fn encode_count(
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
pub fn decode_count(raw: &[u8]) -> Result<(u64, u64, String, String, Option<String>)> {
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
