//! The durable per-(skill, receipt) outcome ledger: the contributing-win door and the tallies read off it.

use rmpv::Value;

use crate::Vault;
use crate::attempt_queue::ManifestEntry;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::receipt::ReceiptRecord;
use crate::skill::SkillRecord;

use super::codec::{
    ENTITY_ID_LEN, KEY_AT, KEY_SCHEMA_VERSION, KEY_WIN, decode_value, encode_value, invalid,
    map_entry, map_u64,
};
use super::posterior::{SKILL_RELIABILITY_SCHEMA_VERSION, SkillReliabilityPosterior, count_weight};
use super::read::read_skill;

/// `skill_reliability:outcome:v1:` + skill id (16 B) + receipt id (UTF-8).
///
/// The receipt id in the KEY is what makes the projector idempotent: an outcome
/// already recorded re-writes its own row instead of incrementing a counter, so
/// re-running a pass over the same judgments cannot double-count.
const OUTCOME_PREFIX: &[u8] = b"skill_reliability:outcome:v1:";
const PAIRED_OUTCOME_PREFIX: &[u8] = b"skill_reliability:outcome:v2:";
const DISPLACED_PREFIX: &[u8] = b"skill_reliability:displaced_judge:v1:";

pub(crate) fn mark_displaced_outcome_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    skill: &EntityId,
    executor: Option<&str>,
    receipt: &str,
    old: &str,
    replacement: &str,
) -> Result<bool> {
    let outcome = outcome_key(skill, executor, receipt);
    let mut key = DISPLACED_PREFIX.to_vec();
    key.extend_from_slice(&outcome);
    let mark = Value::Map(vec![
        (Value::from("displaced"), Value::from(old)),
        (Value::from("replacement"), Value::from(replacement)),
    ]);
    let existed = vault.store.vault_meta.get(txn, &outcome)?.is_some();
    vault
        .store
        .vault_meta
        .put(txn, &key, &encode_value(&mark)?)?;
    Ok(existed)
}

fn is_displaced(vault: &Vault, txn: &heed::RoTxn<'_>, outcome: &[u8]) -> Result<bool> {
    let mut key = DISPLACED_PREFIX.to_vec();
    key.extend_from_slice(outcome);
    Ok(vault.store.vault_meta.get(txn, &key)?.is_some())
}

/// The immutable model identity on the terminal receipt. Unstamped receipts
/// remain in the legacy/unknown bucket and cannot train a named model.
pub(super) fn receipt_executor(receipt: &ReceiptRecord) -> Option<&str> {
    receipt
        .fields
        .get("model")
        .map(String::as_str)
        .filter(|id| !id.is_empty())
}

/// Terminal attempt state that credits a contributing win
/// (`AttemptState::Completed`'s wire string, as stamped on the pack receipt).
const ATTEMPT_OUTCOME_COMPLETED: &str = "completed";

/// Upper bound on the receipts one reliability claim cites.
///
/// α and β count EVERY attributed outcome; the citation list is the trace, and
/// a trace that grows without bound turns a hot claim body into a ledger. The
/// most recent [`SKILL_RELIABILITY_MAX_CITED_RECEIPTS`] are kept — the outcome
/// keyspace remains the complete record.
pub const SKILL_RELIABILITY_MAX_CITED_RECEIPTS: usize = 64;

// ---------------------------------------------------------------------------
// Outcome ledger
// ---------------------------------------------------------------------------

/// Credits one CONTRIBUTING WIN against a skill.
///
/// Grounded at the door, exactly as SK-04 grounds blame evidence: the receipt
/// must be a stamped terminal pack receipt, its attempt must have COMPLETED,
/// and the skill must appear in the manifest that receipt recorded. A win the
/// pack never loaded is attribution by assertion.
///
/// Recording is idempotent — the key carries the receipt id — so replaying a
/// close, or crediting the same receipt from two call sites, moves α once.
pub fn record_skill_contributing_win(
    vault: &Vault,
    skill: &EntityId,
    receipt_ref: &str,
    at: u64,
) -> Result<()> {
    let record = read_skill(vault, skill)?;
    if crate::skill::resident_of(&record)?.is_some() {
        return Err(invalid("resident win requires its attributed actor"));
    }
    let Some(receipt) = crate::receipt::attempt_pack_receipt(vault, receipt_ref)? else {
        return Err(invalid("contributing win cites an unstamped receipt"));
    };
    if receipt.outcome != ATTEMPT_OUTCOME_COMPLETED {
        return Err(invalid(
            "a contributing win requires a completed attempt receipt",
        ));
    }
    if !receipt_manifest_names_skill(&receipt, &record) {
        return Err(invalid(
            "contributing win names a skill absent from the receipt manifest",
        ));
    }
    vault.with_write_txn(|wtxn| {
        record_outcome_in_txn(
            vault,
            wtxn,
            skill,
            receipt_executor(&receipt),
            receipt_ref,
            true,
            at,
        )
    })
}

/// Credits a resident fork only from its own attributed outcome. The
/// unrestricted win door cannot name an actor and therefore refuses forks.
pub fn record_resident_skill_contributing_win(
    vault: &Vault,
    resident: &EntityId,
    skill: &EntityId,
    receipt_ref: &str,
    at: u64,
) -> Result<()> {
    let record = read_skill(vault, skill)?;
    if crate::skill::resident_of(&record)? != Some(*resident)
        || crate::skill::resident::receipt_resident(vault, receipt_ref)? != Some(*resident)
        || !crate::skill::resident::receipt_loaded_skill(vault, receipt_ref, skill)?
    {
        return Err(invalid(
            "resident win names a foreign or unowned skill or attempt",
        ));
    }
    let Some(receipt) = crate::receipt::attempt_pack_receipt(vault, receipt_ref)? else {
        return Err(invalid("contributing win cites an unstamped receipt"));
    };
    if receipt.outcome != ATTEMPT_OUTCOME_COMPLETED {
        return Err(invalid(
            "a contributing win requires a completed attempt receipt",
        ));
    }
    let Some(manifest) = receipt.pack_manifest_skills() else {
        return Err(invalid("resident win needs a versioned manifest"));
    };
    if !manifest.iter().any(|entry| {
        ManifestEntry::parse_wire_form(entry)
            .is_some_and(|(name, version)| name == record.skill_id && version == record.version)
    }) {
        return Err(invalid("resident win needs its exact revision"));
    }
    vault.with_write_txn(|txn| {
        record_outcome_in_txn(
            vault,
            txn,
            skill,
            receipt_executor(&receipt),
            receipt_ref,
            true,
            at,
        )
    })
}

/// The manifest chokepoint BOTH outcome doors run: did the pack that stamped
/// this receipt actually load this skill revision?
///
/// A receipt stamped before the manifest field-set carries no manifest and
/// cannot answer which skills the pack loaded — an absent fact, not a failed
/// check (the ONE-1737 evidence door draws the same line).
pub(super) fn receipt_manifest_names_skill(receipt: &ReceiptRecord, record: &SkillRecord) -> bool {
    let Some(manifest) = receipt.pack_manifest_skills() else {
        return true;
    };
    manifest
        .iter()
        .any(|entry| crate::skill_attribution::manifest_entry_names_skill(entry, record))
}

/// Writes one outcome row, keyed `(skill, receipt)`.
///
/// **A routed verdict outranks the default credit, whichever arrives first.** A
/// blamed attempt still reaches its terminal door COMPLETED, so the same receipt
/// can plausibly be offered as a contributing win and routed to a skill defect —
/// and a host that does both would otherwise get a posterior that depends on
/// call order. A loss overwrites a win (SK-04 corrected the default); a win never
/// overwrites a loss.
pub(super) fn record_outcome_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    skill: &EntityId,
    executor: Option<&str>,
    receipt_ref: &str,
    win: bool,
    at: u64,
) -> Result<()> {
    if receipt_ref.is_empty() {
        return Err(invalid("a reliability outcome must cite a receipt"));
    }
    if let Some(model) = executor {
        super::read::validate_executor(model)?;
    }
    let key = outcome_key(skill, executor, receipt_ref);
    if win
        && let Some(existing) = vault.store.vault_meta.get(wtxn, &key)?
        && !decode_outcome_win(&existing)?
    {
        return Ok(());
    }
    let row = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(SKILL_RELIABILITY_SCHEMA_VERSION),
        ),
        (Value::from(KEY_WIN), Value::Boolean(win)),
        (Value::from(KEY_AT), Value::from(at)),
    ]);
    let encoded = encode_value(&row)?;
    vault.store.vault_meta.put(wtxn, &key, &encoded)?;
    Ok(())
}

fn outcome_prefix(skill: &EntityId, executor: Option<&str>) -> Vec<u8> {
    let prefix = if executor.is_some() {
        PAIRED_OUTCOME_PREFIX
    } else {
        OUTCOME_PREFIX
    };
    let mut key =
        Vec::with_capacity(prefix.len() + ENTITY_ID_LEN + executor.map_or(0, str::len) + 2);
    key.extend_from_slice(prefix);
    key.extend_from_slice(skill.as_bytes());
    if let Some(executor) = executor {
        // Length framing keeps model ids with common prefixes disjoint.
        let length = u16::try_from(executor.len()).expect("receipt model capped at 256 bytes");
        key.extend_from_slice(&length.to_be_bytes());
        key.extend_from_slice(executor.as_bytes());
    }
    key
}

pub(super) fn outcome_key(skill: &EntityId, executor: Option<&str>, receipt_ref: &str) -> Vec<u8> {
    let mut key = outcome_prefix(skill, executor);
    key.extend_from_slice(receipt_ref.as_bytes());
    key
}

/// Attributed-outcome counts for one skill, plus the citation trace.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct OutcomeTally {
    wins: u32,
    losses: u32,
    /// The most recent [`SKILL_RELIABILITY_MAX_CITED_RECEIPTS`] receipt ids, in
    /// ledger order. Pack receipt ids embed the UUIDv7 attempt id, so key order
    /// IS mint order.
    pub(super) cited: Vec<String>,
}

impl OutcomeTally {
    pub(super) fn posterior(&self, prior: SkillReliabilityPosterior) -> SkillReliabilityPosterior {
        SkillReliabilityPosterior {
            alpha: prior.alpha + count_weight(self.wins),
            beta: prior.beta + count_weight(self.losses),
        }
    }
}

/// Every receipt id attributed to `skill`, in ledger order.
///
/// The durable outcome ledger IS the attributed-receipt basis, so this is what
/// ONE-1449's held-out split partitions ([`crate::skill_optimize::dev_receipts`]
/// / [`crate::skill_optimize::held_out_receipts`]). Deliberately UNCAPPED,
/// unlike [`OutcomeTally::cited`]: a citation trace is a bounded summary a brief
/// can read, while a split has to be STABLE for the life of the skill — a view
/// that dropped the oldest row at 65 outcomes would silently move receipts
/// across the dev/held-out line as evidence accumulated, which is exactly the
/// leakage the split exists to prevent.
///
/// Key order is mint order (pack receipt ids embed the UUIDv7 attempt id), so
/// repeated reads answer identically.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on a non-UTF-8 outcome key.
pub(crate) fn attributed_outcome_receipts(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
) -> Result<Vec<String>> {
    Ok(attributed_outcome_results(vault, rtxn, skill)?
        .into_iter()
        .map(|(receipt, _)| receipt)
        .collect())
}

/// Every attributed outcome for `skill`, in ledger order, WITH its result.
///
/// The same uncapped basis [`attributed_outcome_receipts`] serves, plus the one
/// bit a partitioned aggregate needs: a consumer that may only look at one side
/// of ONE-1449's split cannot use the projected `skill.reliability` posterior —
/// that posterior is a fold over BOTH sides — so it has to fold its own side
/// itself, from here.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on a non-UTF-8 outcome key; body
/// errors on an undecodable outcome row.
pub(crate) fn attributed_outcome_results(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
) -> Result<Vec<(String, bool)>> {
    let prefix = outcome_prefix(skill, None);
    let mut outcomes = Vec::new();
    for row in vault.store.vault_meta.prefix_iter(rtxn, &prefix)? {
        let (key, raw) = row?;
        if is_displaced(vault, rtxn, &key)? {
            continue;
        }
        let receipt = key
            .get(prefix.len()..)
            .and_then(|suffix| std::str::from_utf8(suffix).ok())
            .ok_or(Error::CorruptedIndex("skill reliability outcome key"))?;
        outcomes.push((receipt.to_owned(), decode_outcome_win(&raw)?));
    }
    // Optimization's split is over receipts, across all executors. Pair
    // measurements remain separate; this read only supplies the evidence basis.
    let mut paired_prefix = PAIRED_OUTCOME_PREFIX.to_vec();
    paired_prefix.extend_from_slice(skill.as_bytes());
    for row in vault.store.vault_meta.prefix_iter(rtxn, &paired_prefix)? {
        let (key, raw) = row?;
        if is_displaced(vault, rtxn, &key)? {
            continue;
        }
        let suffix = key
            .get(paired_prefix.len()..)
            .ok_or(Error::CorruptedIndex("skill reliability pair key"))?;
        let length = suffix
            .get(..2)
            .ok_or(Error::CorruptedIndex("skill reliability pair key"))?;
        let len = usize::from(u16::from_be_bytes([length[0], length[1]]));
        let receipt = suffix
            .get(2 + len..)
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .filter(|id| !id.is_empty())
            .ok_or(Error::CorruptedIndex("skill reliability pair key"))?;
        outcomes.push((receipt.to_owned(), decode_outcome_win(&raw)?));
    }
    outcomes.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(outcomes)
}

pub(super) fn tally_outcomes(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
    executor: Option<&str>,
) -> Result<OutcomeTally> {
    let prefix = outcome_prefix(skill, executor);
    let mut tally = OutcomeTally::default();
    for row in vault.store.vault_meta.prefix_iter(rtxn, &prefix)? {
        let (key, raw) = row?;
        let receipt = key
            .get(prefix.len()..)
            .and_then(|suffix| std::str::from_utf8(suffix).ok())
            .ok_or(Error::CorruptedIndex("skill reliability outcome key"))?;
        if is_displaced(vault, rtxn, &key)? {
            continue;
        }
        if decode_outcome_win(&raw)? {
            tally.wins = tally.wins.saturating_add(1);
        } else {
            tally.losses = tally.losses.saturating_add(1);
        }
        tally.cited.push(receipt.to_owned());
        if tally.cited.len() > SKILL_RELIABILITY_MAX_CITED_RECEIPTS {
            tally.cited.remove(0);
        }
    }
    Ok(tally)
}

fn decode_outcome_win(raw: &[u8]) -> Result<bool> {
    let value = decode_value(raw)?;
    if map_u64(&value, KEY_SCHEMA_VERSION) != Some(SKILL_RELIABILITY_SCHEMA_VERSION) {
        return Err(invalid("unsupported skill reliability outcome schema"));
    }
    map_entry(&value, KEY_WIN)
        .and_then(Value::as_bool)
        .ok_or(invalid("skill reliability outcome is missing win"))
}
