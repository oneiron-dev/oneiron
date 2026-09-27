//! Vault-local tier-2 sampling. Only censored text enters the export ledger.
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{
    EntityId, Vault,
    edge::EdgeKind,
    error::{Error, Result},
    registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN},
};

const PREFIX: &[u8] = b"failure_signals:tier2:sample:";
const WEEK_PREFIX: &[u8] = b"failure_signals:tier2:week:";
const WEEK: u64 = 7 * 24 * 60 * 60;
const TTL: u64 = 35 * 24 * 60 * 60;
const CAP: usize = 50;
const MAX_TEXT_BYTES: usize = 16 * 1024;

/// Closed placeholder vocabulary: the model supplies spans, never replacement text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedactionKind {
    Person,
    Place,
    Organization,
    Email,
    Phone,
    Address,
    Account,
    PrivateFact,
}
impl RedactionKind {
    fn marker(self) -> &'static str {
        match self {
            Self::Person => "[PERSON]",
            Self::Place => "[PLACE]",
            Self::Organization => "[ORGANIZATION]",
            Self::Email => "[EMAIL]",
            Self::Phone => "[PHONE]",
            Self::Address => "[ADDRESS]",
            Self::Account => "[ACCOUNT]",
            Self::PrivateFact => "[PRIVATE_FACT]",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RedactionSpan {
    pub start: usize,
    pub end: usize,
    pub kind: RedactionKind,
}

/// Host-local oneiroNER PII head. `None` means uncertain: refuse the sample.
/// This callback runs inside the vault before any sample is persisted or returned.
pub trait Tier2Redactor {
    fn detect(&self, text: &str) -> Result<Option<Vec<RedactionSpan>>>;
}

/// The exportable projection has no source reference or raw text field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tier2Sample {
    pub text: String,
    pub sampled_at: u64,
    pub expires_at: u64,
}

fn deny(reason: &'static str) -> Error {
    Error::InvalidConfig(reason.into())
}
fn scrub(text: &str, ner: &dyn Tier2Redactor, denylist: &[&str]) -> Result<String> {
    if text.len() > MAX_TEXT_BYTES || text.is_empty() {
        return Err(deny("tier-2 text exceeds limit or is empty"));
    }
    let mut spans = ner
        .detect(text)?
        .ok_or_else(|| deny("tier-2 redaction uncertain"))?;
    spans.sort_by_key(|s| (s.start, s.end));
    let mut result = String::new();
    let mut pos = 0;
    for span in spans {
        if span.start < pos
            || span.start >= span.end
            || span.end > text.len()
            || !text.is_char_boundary(span.start)
            || !text.is_char_boundary(span.end)
        {
            return Err(deny("invalid tier-2 redaction span"));
        }
        result.push_str(&text[pos..span.start]);
        result.push_str(span.kind.marker());
        pos = span.end;
    }
    result.push_str(&text[pos..]);
    // Independent post-NER backstop. A detector miss or malformed denylist
    // never results in a best-effort raw export.
    if denylist
        .iter()
        .any(|word| word.is_empty() || result.to_lowercase().contains(&word.to_lowercase()))
    {
        return Err(deny("tier-2 denylist rejected sample"));
    }
    let pattern = Regex::new(
        r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}|(?:https?://|www\.)\S+|\+?\d[\d() .-]{6,}\d",
    )
    .map_err(|_| Error::InvariantViolation("invalid tier-2 denylist pattern"))?;
    if pattern.is_match(&result) {
        return Err(deny("tier-2 denylist rejected sample"));
    }
    Ok(result)
}

#[derive(Deserialize)]
struct TranscriptMessage {
    content: String,
    is_visible: bool,
    order: u32,
}

fn transcript_text(vault: &Vault, turn: &EntityId) -> Result<String> {
    let messages = vault.sources(turn, EdgeKind::PartOf, Some(ENTITY_TYPE_MESSAGE))?;
    if messages.is_empty() {
        // Older direct TURN writes carry their text on the body. Witnessed
        // turns do not: their body carries only the speaker grouping fact.
        return crate::dreamer_consolidation::turn_text_for_shadow(vault, turn);
    }
    let mut parts = Vec::new();
    for id in messages {
        if vault.store.off_record_sessions.contains_entity(&id)? {
            return Err(Error::InvariantViolation(
                "off-record message reached tier-2 base source",
            ));
        }
        let bytes = vault
            .get(&id)?
            .ok_or(Error::CorruptedIndex("tier-2 message"))?;
        let row: TranscriptMessage =
            rmp_serde::from_slice(&bytes).map_err(|_| Error::CorruptedIndex("tier-2 message"))?;
        if row.is_visible && !row.content.is_empty() {
            parts.push((row.order, row.content));
        }
    }
    parts.sort_by_key(|(order, _)| *order);
    if parts.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(Error::CorruptedIndex("tier-2 message order"));
    }
    if parts.is_empty() {
        return Err(deny("tier-2 transcript is empty"));
    }
    Ok(parts
        .into_iter()
        .map(|(_, text)| text)
        .collect::<Vec<_>>()
        .join("\n"))
}

fn sample_key(week: u64, id: &EntityId) -> Vec<u8> {
    format!("failure_signals:tier2:sample:{week:016x}:{}", id.to_hex()).into_bytes()
}
fn week_key(week: u64) -> Vec<u8> {
    format!("failure_signals:tier2:week:{week:016x}").into_bytes()
}
fn decode(raw: &[u8]) -> Result<Tier2Sample> {
    serde_json::from_slice(raw).map_err(|_| Error::CorruptedIndex("tier-2 sample"))
}

/// Select at most 50 distinct, base-vault TURN candidates in a UTC seven-day
/// bucket. No caller-supplied content, timestamp, or off-record override exists.
/// The durable count is consumed atomically with the redacted samples; repeats
/// cannot bypass the cap, including after reopening the vault.
pub fn capture_tier2_samples(
    vault: &Vault,
    candidates: &[EntityId],
    ner: &dyn Tier2Redactor,
    denylist: &[&str],
) -> Result<Vec<Tier2Sample>> {
    if !vault.config.failure_signals.exports() {
        return Ok(Vec::new());
    }
    let now = vault.store.clock.now_recorded_at();
    let week = now / WEEK;
    let mut prepared = Vec::new();
    let mut ordered = candidates.to_vec();
    ordered.sort_unstable();
    ordered.dedup();
    for id in ordered {
        // A live room is never a source. The base row check prevents forged
        // caller text, deleted turns, and non-turn IDs from becoming samples.
        if vault.store.off_record_sessions.contains_entity(&id)? {
            continue;
        }
        if vault.get_entity_type(&id)? != Some(ENTITY_TYPE_TURN) {
            continue;
        }
        let text = transcript_text(vault, &id)?;
        let text = scrub(&text, ner, denylist)?;
        prepared.push((
            id,
            Tier2Sample {
                text,
                sampled_at: now,
                expires_at: now.saturating_add(TTL),
            },
        ));
    }
    vault.with_write_txn(|txn| {
        let wk = week_key(week);
        let count = match vault.store.vault_meta.get(&*txn, &wk)? {
            Some(raw) if raw.len() == 8 => u64::from_be_bytes(
                raw.as_ref()
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("tier-2 week"))?,
            ),
            Some(_) => return Err(Error::CorruptedIndex("tier-2 week")),
            None => 0,
        };
        if count > CAP as u64 {
            return Err(Error::CorruptedIndex("tier-2 week"));
        }
        let mut selected = Vec::new();
        for (id, sample) in &prepared {
            if selected.len() + count as usize == CAP {
                break;
            }
            let key = sample_key(week, id);
            if vault.store.vault_meta.get(&*txn, &key)?.is_some() {
                continue;
            }
            vault.store.vault_meta.put(
                txn,
                &key,
                &serde_json::to_vec(sample)
                    .map_err(|_| Error::InvariantViolation("tier-2 sample encoding"))?,
            )?;
            selected.push(sample.clone());
        }
        vault
            .store
            .vault_meta
            .put(txn, &wk, &(count + selected.len() as u64).to_be_bytes())?;
        Ok(selected)
    })
}

/// Read only unexpired redacted rows. Expired rows are swept in the same call,
/// while independent weekly counters remain until their bucket passes.
pub fn read_tier2_samples(vault: &Vault) -> Result<Vec<Tier2Sample>> {
    if !vault.config.failure_signals.exports() {
        return Ok(Vec::new());
    }
    let now = vault.store.clock.now_recorded_at();
    vault.with_write_txn(|txn| {
        let mut live = Vec::new();
        let mut expired = Vec::new();
        for entry in vault.store.vault_meta.prefix_iter(&*txn, PREFIX)? {
            let (key, raw) = entry?;
            let sample = decode(&raw)?;
            if sample.expires_at <= now {
                expired.push(key.to_vec());
            } else {
                live.push(sample);
            }
        }
        for key in expired {
            vault.store.vault_meta.delete(txn, &key)?;
        }
        // Old counters cannot be used to restore expired samples.
        let current_week = now / WEEK;
        let stale = vault
            .store
            .vault_meta
            .prefix_iter(&*txn, WEEK_PREFIX)?
            .map(|entry| {
                let (key, _) = entry?;
                let bucket = std::str::from_utf8(&key[WEEK_PREFIX.len()..])
                    .ok()
                    .and_then(|s| u64::from_str_radix(s, 16).ok())
                    .ok_or(Error::CorruptedIndex("tier-2 week"))?;
                Ok((bucket, key.to_vec()))
            })
            .collect::<Result<Vec<_>>>()?;
        for (bucket, key) in stale {
            if bucket < current_week {
                vault.store.vault_meta.delete(txn, &key)?;
            }
        }
        Ok(live)
    })
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
