//! The durable per-(skill, receipt) outcome ledger: the contributing-win door and the tallies read off it.

use rmpv::Value;

use crate::Vault;
use crate::attempt_queue::ManifestEntry;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::receipt::ReceiptRecord;
use crate::side_table::{self, FixedSideKey, Raw, RawValue, SideKey, SideTable};
use crate::skill::SkillRecord;

use super::codec::{
    KEY_AT, KEY_SCHEMA_VERSION, KEY_WIN, decode_value, encode_value, invalid, map_entry, map_u64,
};
use super::posterior::{SKILL_RELIABILITY_SCHEMA_VERSION, SkillReliabilityPosterior, count_weight};
use super::read::read_skill;

/// Durable per-(skill, receipt) attributed-outcome ledger. Key: id16(skill) + string(receipt).
///
/// The receipt id in the KEY is what makes the projector idempotent: an outcome
/// already recorded re-writes its own row instead of incrementing a counter, so
/// re-running a pass over the same judgments cannot double-count.
const OUTCOME: SideTable<(EntityId, String), OutcomeRow, Raw> =
    SideTable::new(&side_table::SKILL_RELIABILITY_OUTCOME);

/// [`OUTCOME`]'s row: the byte layout [`record_outcome_in_txn`] has always spelled. `at` is
/// carried for round-trip fidelity only — no reader decodes it back out today.
pub(super) struct OutcomeRow {
    pub(super) win: bool,
    at: u64,
}

impl RawValue for OutcomeRow {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, side_table::CodecError> {
        let row = Value::Map(vec![
            (
                Value::from(KEY_SCHEMA_VERSION),
                Value::from(SKILL_RELIABILITY_SCHEMA_VERSION),
            ),
            (Value::from(KEY_WIN), Value::Boolean(self.win)),
            (Value::from(KEY_AT), Value::from(self.at)),
        ]);
        Ok(encode_value(&row)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, side_table::CodecError> {
        let value = decode_value(bytes)?;
        if map_u64(&value, KEY_SCHEMA_VERSION) != Some(SKILL_RELIABILITY_SCHEMA_VERSION) {
            return Err(invalid("unsupported skill reliability outcome schema").into());
        }
        let win = map_entry(&value, KEY_WIN)
            .and_then(Value::as_bool)
            .ok_or(invalid("skill reliability outcome is missing win"))?;
        Ok(Self {
            win,
            at: map_u64(&value, KEY_AT).unwrap_or(0),
        })
    }
}

/// The same outcome row for a named executor's arm: [`OUTCOME`]'s value, keyed by the arm and
/// the receipt id, so one model's evidence never folds into another's or the legacy arm.
const PAIRED_OUTCOME: SideTable<PairedOutcomeKey, OutcomeRow, Raw> =
    SideTable::new(&side_table::SKILL_RELIABILITY_PAIRED_OUTCOME);

/// A named executor's arm of one skill: the skill id, then the model id framed by its big-endian
/// `u16` byte length so model ids with common prefixes stay disjoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExecutorArm {
    pub(super) skill: EntityId,
    pub(super) executor: String,
}

impl ExecutorArm {
    pub(super) fn new(skill: &EntityId, executor: &str) -> Self {
        Self {
            skill: *skill,
            executor: executor.to_owned(),
        }
    }

    /// The arm's key bytes, the prefix every row of this arm starts with.
    fn key_prefix(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    /// Splits one arm off the front of `bytes`, returning it and the bytes after it.
    fn decode_front(bytes: &[u8]) -> Option<(Self, &[u8])> {
        let (skill, rest) = bytes.split_at_checked(<EntityId as FixedSideKey>::WIDTH)?;
        let (length, rest) = rest.split_at_checked(2)?;
        let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
        let (executor, rest) = rest.split_at_checked(length)?;
        let arm = Self {
            skill: EntityId::decode_key(skill)?,
            executor: std::str::from_utf8(executor).ok()?.to_owned(),
        };
        Some((arm, rest))
    }
}

impl SideKey for ExecutorArm {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.skill.encode_into(out);
        let length = u16::try_from(self.executor.len()).expect("receipt model capped at 256 bytes");
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(self.executor.as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (arm, rest) = Self::decode_front(bytes)?;
        rest.is_empty().then_some(arm)
    }
}

/// [`PAIRED_OUTCOME`]'s key: the executor arm, then the receipt id (the rest of the key).
pub(super) struct PairedOutcomeKey {
    arm: ExecutorArm,
    receipt: String,
}

impl SideKey for PairedOutcomeKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.arm.encode_into(out);
        out.extend_from_slice(self.receipt.as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (arm, receipt) = ExecutorArm::decode_front(bytes)?;
        Some(Self {
            arm,
            receipt: std::str::from_utf8(receipt).ok()?.to_owned(),
        })
    }
}

/// One outcome row, on the legacy unknown-executor arm or a named executor's arm.
pub(super) enum OutcomeRef {
    Unknown((EntityId, String)),
    Paired(PairedOutcomeKey),
}

impl OutcomeRef {
    pub(super) fn new(skill: &EntityId, executor: Option<&str>, receipt: &str) -> Self {
        match executor {
            None => Self::Unknown((*skill, receipt.to_owned())),
            Some(executor) => Self::Paired(PairedOutcomeKey {
                arm: ExecutorArm::new(skill, executor),
                receipt: receipt.to_owned(),
            }),
        }
    }

    fn into_receipt(self) -> String {
        match self {
            Self::Unknown((_, receipt)) | Self::Paired(PairedOutcomeKey { receipt, .. }) => receipt,
        }
    }

    fn get(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Option<OutcomeRow>> {
        match self {
            Self::Unknown(key) => OUTCOME.get(&vault.store, txn, key),
            Self::Paired(key) => PAIRED_OUTCOME.get(&vault.store, txn, key),
        }
    }

    pub(super) fn contains(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
        match self {
            Self::Unknown(key) => OUTCOME.contains(&vault.store, txn, key),
            Self::Paired(key) => PAIRED_OUTCOME.contains(&vault.store, txn, key),
        }
    }

    fn put(&self, vault: &Vault, txn: &mut heed::RwTxn<'_>, row: &OutcomeRow) -> Result<()> {
        match self {
            Self::Unknown(key) => OUTCOME.put(&vault.store, txn, key, row),
            Self::Paired(key) => PAIRED_OUTCOME.put(&vault.store, txn, key, row),
        }
    }
}

/// A displacement mark names its outcome row by the row's full stored key, table prefix included.
impl SideKey for OutcomeRef {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Unknown(key) => out.extend_from_slice(&OUTCOME.key_bytes(key)),
            Self::Paired(key) => out.extend_from_slice(&PAIRED_OUTCOME.key_bytes(key)),
        }
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        if let Some(key) = bytes.strip_prefix(OUTCOME.decl().prefix) {
            return <(EntityId, String)>::decode_key(key).map(Self::Unknown);
        }
        let key = bytes.strip_prefix(PAIRED_OUTCOME.decl().prefix)?;
        PairedOutcomeKey::decode_key(key).map(Self::Paired)
    }
}

/// Outcome rows whose judge was displaced: the row stays, its weight leaves every fold.
const DISPLACED: SideTable<OutcomeRef, DisplacedMark, Raw> =
    SideTable::new(&side_table::SKILL_RELIABILITY_DISPLACED_JUDGE);

/// [`DISPLACED`]'s row: the displaced and replacement judge revisions, as a MessagePack map.
/// Only its presence is read today.
struct DisplacedMark {
    displaced: String,
    replacement: String,
}

impl RawValue for DisplacedMark {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, side_table::CodecError> {
        let mark = Value::Map(vec![
            (
                Value::from("displaced"),
                Value::from(self.displaced.as_str()),
            ),
            (
                Value::from("replacement"),
                Value::from(self.replacement.as_str()),
            ),
        ]);
        Ok(encode_value(&mark)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, side_table::CodecError> {
        let value = decode_value(bytes)?;
        let field = |key: &str| {
            map_entry(&value, key)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(invalid("skill reliability displacement mark is malformed"))
        };
        Ok(Self {
            displaced: field("displaced")?,
            replacement: field("replacement")?,
        })
    }
}

pub(crate) fn mark_displaced_outcome_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    skill: &EntityId,
    executor: Option<&str>,
    receipt: &str,
    old: &str,
    replacement: &str,
) -> Result<bool> {
    let outcome = OutcomeRef::new(skill, executor, receipt);
    let mark = DisplacedMark {
        displaced: old.to_owned(),
        replacement: replacement.to_owned(),
    };
    let existed = outcome.contains(vault, txn)?;
    DISPLACED.put(&vault.store, txn, &outcome, &mark)?;
    Ok(existed)
}

fn is_displaced(vault: &Vault, txn: &heed::RoTxn<'_>, outcome: &OutcomeRef) -> Result<bool> {
    DISPLACED.contains(&vault.store, txn, outcome)
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
    let key = OutcomeRef::new(skill, executor, receipt_ref);
    if win
        && let Some(existing) = key.get(vault, wtxn)?
        && !existing.win
    {
        return Ok(());
    }
    key.put(vault, wtxn, &OutcomeRow { win, at })
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
/// Storage errors; a typed side-table row error on a malformed outcome key.
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
/// Storage errors; a typed side-table row error on a malformed outcome key or an
/// undecodable outcome row; [`Error::CorruptedIndex`] on a paired key without a receipt.
pub(crate) fn attributed_outcome_results(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
) -> Result<Vec<(String, bool)>> {
    let mut outcomes = Vec::new();
    for (key, row) in OUTCOME.scan_from(&vault.store, rtxn, skill.as_bytes())? {
        let outcome = OutcomeRef::Unknown(key);
        if is_displaced(vault, rtxn, &outcome)? {
            continue;
        }
        outcomes.push((outcome.into_receipt(), row.win));
    }
    // Optimization's split is over receipts, across all executors. Pair
    // measurements remain separate; this read only supplies the evidence basis.
    for (key, row) in PAIRED_OUTCOME.scan_from(&vault.store, rtxn, skill.as_bytes())? {
        if key.receipt.is_empty() {
            return Err(Error::CorruptedIndex("skill reliability pair key"));
        }
        let outcome = OutcomeRef::Paired(key);
        if is_displaced(vault, rtxn, &outcome)? {
            continue;
        }
        outcomes.push((outcome.into_receipt(), row.win));
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
    let rows: Vec<(OutcomeRef, OutcomeRow)> = match executor {
        None => OUTCOME
            .scan_from(&vault.store, rtxn, skill.as_bytes())?
            .into_iter()
            .map(|(key, row)| (OutcomeRef::Unknown(key), row))
            .collect(),
        Some(executor) => PAIRED_OUTCOME
            .scan_from(
                &vault.store,
                rtxn,
                &ExecutorArm::new(skill, executor).key_prefix(),
            )?
            .into_iter()
            .map(|(key, row)| (OutcomeRef::Paired(key), row))
            .collect(),
    };
    let mut tally = OutcomeTally::default();
    for (outcome, row) in rows {
        if is_displaced(vault, rtxn, &outcome)? {
            continue;
        }
        if row.win {
            tally.wins = tally.wins.saturating_add(1);
        } else {
            tally.losses = tally.losses.saturating_add(1);
        }
        tally.cited.push(outcome.into_receipt());
        if tally.cited.len() > SKILL_RELIABILITY_MAX_CITED_RECEIPTS {
            tally.cited.remove(0);
        }
    }
    Ok(tally)
}
