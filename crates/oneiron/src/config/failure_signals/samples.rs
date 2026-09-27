//! Vault-local tier-2 sampling. Only censored text enters the export ledger.
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{
    EntityId, Vault,
    edge::EdgeKind,
    error::{Error, Result},
    ports::{EdgeStoreRead, EntityStore},
    registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN},
    store::Store,
};

const PREFIX: &[u8] = b"failure_signals:tier2:sample:";
const WEEK_PREFIX: &[u8] = b"failure_signals:tier2:week:";
const SOURCE_PREFIX: &[u8] = b"failure_signals:tier2:source:";
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

// Private custody. Source IDs and body fingerprints never enter the export DTO.
#[derive(Clone, Serialize, Deserialize)]
struct SourceProof {
    id: [u8; 16],
    body_hash: [u8; 32],
}
impl SourceProof {
    fn new(id: &EntityId, body: &[u8]) -> Self {
        Self {
            id: *id.as_bytes(),
            body_hash: *blake3::hash(body).as_bytes(),
        }
    }
    fn entity_id(&self) -> Result<EntityId> {
        EntityId::from_bytes(self.id)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSample {
    sample: Tier2Sample,
    // First entry is the TURN; the rest are visible MESSAGE sources.
    sources: Vec<SourceProof>,
}
struct Prepared {
    turn: EntityId,
    text: String,
    sources: Vec<SourceProof>,
}

fn transcript_text(vault: &Vault, turn: &EntityId) -> Result<Option<(String, Vec<SourceProof>)>> {
    let messages = vault.sources(turn, EdgeKind::PartOf, Some(ENTITY_TYPE_MESSAGE))?;
    // A TURN body is a grouping fact, not a transcript. Never use txt/text
    // aliases to turn a bare or previously emptied TURN into a sample.
    if messages.is_empty() {
        return Ok(None);
    }
    let turn_body = vault
        .get(turn)?
        .ok_or(Error::CorruptedIndex("tier-2 turn"))?;
    let mut sources = vec![SourceProof::new(turn, &turn_body)];
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
            sources.push(SourceProof::new(&id, &bytes));
            parts.push((row.order, row.content));
        }
    }
    parts.sort_by_key(|(order, _)| *order);
    if parts.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(Error::CorruptedIndex("tier-2 message order"));
    }
    if parts.is_empty() {
        return Ok(None);
    }
    Ok(Some((
        parts
            .into_iter()
            .map(|(_, text)| text)
            .collect::<Vec<_>>()
            .join("\n"),
        sources,
    )))
}

fn sample_key(week: u64, id: &EntityId) -> Vec<u8> {
    format!("failure_signals:tier2:sample:{week:016x}:{}", id.to_hex()).into_bytes()
}
fn week_key(week: u64) -> Vec<u8> {
    format!("failure_signals:tier2:week:{week:016x}").into_bytes()
}
fn source_prefix(id: &EntityId) -> Vec<u8> {
    let mut key = SOURCE_PREFIX.to_vec();
    key.extend_from_slice(id.to_hex().as_bytes());
    key.push(b':');
    key
}
fn source_key(id: &EntityId, sample_key: &[u8]) -> Vec<u8> {
    let mut key = source_prefix(id);
    key.extend_from_slice(sample_key);
    key
}
fn decode(raw: &[u8]) -> Result<StoredSample> {
    serde_json::from_slice(raw).map_err(|_| Error::CorruptedIndex("tier-2 sample"))
}
fn count_for_week(vault: &Vault, txn: &heed::RoTxn<'_>, week: u64) -> Result<u64> {
    match vault.store.vault_meta.get(txn, &week_key(week))? {
        Some(raw) if raw.len() == 8 => Ok(u64::from_be_bytes(
            raw.as_ref()
                .try_into()
                .map_err(|_| Error::CorruptedIndex("tier-2 week"))?,
        )),
        Some(_) => Err(Error::CorruptedIndex("tier-2 week")),
        None => Ok(0),
    }
}
fn sources_live(vault: &Vault, txn: &heed::RoTxn<'_>, sources: &[SourceProof]) -> Result<bool> {
    let store = &vault.store;
    let Some(turn) = sources.first() else {
        return Err(Error::CorruptedIndex("tier-2 sources"));
    };
    let turn_id = turn.entity_id()?;
    for (index, proof) in sources.iter().enumerate() {
        let id = proof.entity_id()?;
        let expected = if index == 0 {
            ENTITY_TYPE_TURN
        } else {
            ENTITY_TYPE_MESSAGE
        };
        if store.off_record_sessions.contains_entity(&id)? {
            return Ok(false);
        }
        // The exact port used by Vault::get resolves EntityDoc content in
        // this transaction. Comparing the raw pointer would falsely reject
        // stream/edit MESSAGEs and miss later document-only edits.
        match vault.port_entity_get(txn, &id)? {
            Some(row)
                if row.entity_type == expected
                    && blake3::hash(&row.body).as_bytes() == &proof.body_hash => {}
            _ => return Ok(false),
        }
        if index != 0
            && (store
                .port_edge_get(txn, &id, EdgeKind::PartOf, &turn_id)?
                .is_none()
                || !store.port_edge_consistent(txn, &id, EdgeKind::PartOf, &turn_id)?)
        {
            return Ok(false);
        }
    }
    Ok(true)
}
fn purge_sample(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8],
    row: &StoredSample,
) -> Result<()> {
    for proof in &row.sources {
        store
            .vault_meta
            .delete(txn, &source_key(&proof.entity_id()?, key))?;
    }
    store.vault_meta.delete(txn, key)?;
    Ok(())
}

/// Erase every stored carrier derived from a deleted TURN or MESSAGE in the
/// same transaction as the source tear. Used by hard, soft and replay doors.
pub(crate) fn purge_tier2_for_source_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let prefix = source_prefix(id);
    let keys = store
        .vault_meta
        .prefix_iter(&*txn, &prefix)?
        .map(|entry| {
            let (_, value) = entry?;
            Ok(value.to_vec())
        })
        .collect::<Result<Vec<_>>>()?;
    for key in keys {
        if !key.starts_with(PREFIX) {
            return Err(Error::CorruptedIndex("tier-2 source index"));
        }
        if let Some(raw) = store.vault_meta.get(&*txn, &key)? {
            purge_sample(store, txn, &key, &decode(&raw)?)?;
        } else {
            store.vault_meta.delete(txn, &source_key(id, &key))?;
        }
    }
    Ok(())
}

/// Select at most 50 distinct base-vault transcript candidates per UTC
/// seven-day bucket. No caller-supplied content, timestamp, or off-record
/// override exists. Quota, source proofs, and the recorded clock commit as one.
pub fn capture_tier2_samples(
    vault: &Vault,
    candidates: &[EntityId],
    ner: &dyn Tier2Redactor,
    denylist: &[&str],
) -> Result<Vec<Tier2Sample>> {
    if !vault.config.failure_signals.exports() {
        return Ok(Vec::new());
    }
    let mut ordered = candidates.to_vec();
    ordered.sort_unstable();
    ordered.dedup();
    // Advisory preflight avoids paying for the host-local model when quota is
    // already full. The final write transaction rechecks the count and sources.
    let (to_prepare, remaining) = {
        let txn = vault.store.env.read_txn()?;
        let week = vault.store.clock.now_recorded_at() / WEEK;
        let count = count_for_week(vault, &txn, week)?;
        if count > CAP as u64 {
            return Err(Error::CorruptedIndex("tier-2 week"));
        }
        if count == CAP as u64 {
            return Ok(Vec::new());
        }
        let mut chosen = Vec::new();
        for id in ordered {
            if vault
                .store
                .vault_meta
                .get(&txn, &sample_key(week, &id))?
                .is_none()
            {
                chosen.push(id);
            }
        }
        (chosen, CAP - count as usize)
    };
    let mut prepared = Vec::new();
    for id in to_prepare {
        if prepared.len() == remaining {
            break;
        }
        if vault.store.off_record_sessions.contains_entity(&id)? {
            continue;
        }
        if vault.get_entity_type(&id)? != Some(ENTITY_TYPE_TURN) {
            continue;
        }
        let Some((text, sources)) = transcript_text(vault, &id)? else {
            continue;
        };
        prepared.push(Prepared {
            turn: id,
            text: scrub(&text, ner, denylist)?,
            sources,
        });
    }
    vault.with_write_txn(|txn| {
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        let week = now / WEEK;
        let wk = week_key(week);
        let count = count_for_week(vault, &*txn, week)?;
        if count > CAP as u64 {
            return Err(Error::CorruptedIndex("tier-2 week"));
        }
        let mut selected = Vec::new();
        for row in &prepared {
            if selected.len() + count as usize == CAP {
                break;
            }
            let key = sample_key(week, &row.turn);
            if vault.store.vault_meta.get(&*txn, &key)?.is_some() {
                continue;
            }
            if !sources_live(vault, &*txn, &row.sources)? {
                continue;
            }
            let sample = Tier2Sample {
                text: row.text.clone(),
                sampled_at: now,
                expires_at: now.saturating_add(TTL),
            };
            let stored = StoredSample {
                sample: sample.clone(),
                sources: row.sources.clone(),
            };
            vault.store.vault_meta.put(
                txn,
                &key,
                &serde_json::to_vec(&stored)
                    .map_err(|_| Error::InvariantViolation("tier-2 sample encoding"))?,
            )?;
            for proof in &row.sources {
                vault
                    .store
                    .vault_meta
                    .put(txn, &source_key(&proof.entity_id()?, &key), &key)?;
            }
            selected.push(sample);
        }
        vault
            .store
            .vault_meta
            .put(txn, &wk, &(count + selected.len() as u64).to_be_bytes())?;
        Ok(selected)
    })
}

/// Read only unexpired rows whose original TURN and every visible MESSAGE
/// still exist with the captured bytes. Retire stale samples and counters.
pub fn read_tier2_samples(vault: &Vault) -> Result<Vec<Tier2Sample>> {
    if !vault.config.failure_signals.exports() {
        return Ok(Vec::new());
    }
    vault.with_write_txn(|txn| {
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        let mut live = Vec::new();
        let mut stale = Vec::new();
        for entry in vault.store.vault_meta.prefix_iter(&*txn, PREFIX)? {
            let (key, raw) = entry?;
            let stored = decode(&raw)?;
            if stored.sample.expires_at <= now || !sources_live(vault, &*txn, &stored.sources)? {
                stale.push((key.to_vec(), stored));
            } else {
                live.push(stored.sample);
            }
        }
        for (key, row) in stale {
            purge_sample(&vault.store, txn, &key, &row)?;
        }
        let current_week = now / WEEK;
        let stale_weeks = vault
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
        for (bucket, key) in stale_weeks {
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
