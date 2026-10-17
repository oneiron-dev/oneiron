//! The runner's durable rows: cursors, the run memo, saved intents, the
//! Hook receipts and the run index (ARCH-0080 §4 Delivery, Crash-safe
//! outcomes; §6 receipt; §8 golden set).

use serde::{Deserialize, Serialize};

use crate::receipt::{
    MAX_RECEIPT_QUERY_SCAN, ReceiptQuery, ReceiptRecord, hex_lower, retain_newest_receipt,
};
use crate::side_table::{self, Named, SideTable};
use crate::skill_hub::pack_catalog::PackHookBinding;
use crate::{EntityId, Error, Result, Vault};

use super::lineage::LineageLink;
use super::source::{
    ClaimChangelogPosition, FactEntry, FactKind, FactPosition, FactSource, SettlementPosition,
};

/// A run's identity: BLAKE3 over its derivation envelope and its position.
pub(super) type RunKey = [u8; 32];

/// One cursor per binding and source.
const CURSORS: SideTable<(EntityId, [u8; 1]), CursorRow, Named> =
    SideTable::new(&side_table::HOOKS_CURSOR);
/// The saved result of each run, by run key.
pub(super) const MEMOS: SideTable<RunKey, HookRunRecord, Named> =
    SideTable::new(&side_table::HOOKS_MEMO);
/// Queued work saved before the cursor moves, by run key.
pub(super) const INTENTS: SideTable<RunKey, HookIntent, Named> =
    SideTable::new(&side_table::HOOKS_INTENT);
/// One Hook receipt per run, by run key.
pub(super) const RECEIPTS: SideTable<RunKey, ReceiptRecord, Named> =
    SideTable::new(&side_table::HOOKS_RECEIPT);
/// Each binding's runs in commit order: binding, commit time in Unix ms, run
/// key. The last rows under a binding are its newest runs.
pub(super) const RUN_INDEX: SideTable<(EntityId, u64, RunKey), HookRunRef, Named> =
    SideTable::new(&side_table::HOOKS_RUN_INDEX);

/// The derivation envelope's model id for a body that calls no model.
const HOOK_MODEL_ID: &str = "hook-js";

/// The ARCH-0035 derivation envelope shape, for one hook run. Copied rather
/// than shared, as `SavedQueryDerivationEnvelope` is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HookDerivationEnvelope {
    /// Hex of the fact's input hash.
    content_hash: String,
    model_id: String,
    /// The hook version and its body hash.
    version: String,
    /// Hex BLAKE3 of the selector JSON and the binding id.
    params_hash: String,
}

/// The run key for `binding` on `fact`.
pub(super) fn run_key(
    binding_id: EntityId,
    binding: &PackHookBinding,
    fact: &FactEntry,
) -> Result<RunKey> {
    let selector = serde_json::to_vec(&binding.selector)
        .map_err(|_| Error::InvariantViolation("hook selector encode"))?;
    let mut params = blake3::Hasher::new();
    params.update(&selector);
    params.update(binding_id.as_bytes());
    let envelope = HookDerivationEnvelope {
        content_hash: hex_lower(&fact.input_hash),
        model_id: HOOK_MODEL_ID.to_owned(),
        version: format!("{}+{}", binding.hook_version, binding.body_hash),
        params_hash: params.finalize().to_hex().to_string(),
    };
    let envelope = serde_json::to_vec(&envelope)
        .map_err(|_| Error::InvariantViolation("hook envelope encode"))?;
    let mut key = blake3::Hasher::new_derive_key("oneiron.hook-run-key.v1");
    key.update(&envelope);
    key.update(&[fact.position.source().tag()]);
    key.update(&fact.position.bytes());
    Ok(*key.finalize().as_bytes())
}

/// A cursor row: the last position delivered to its binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct CursorRow {
    /// `None` is the start of the source.
    position: Option<CursorPosition>,
    /// The binding was seen disabled; it restarts where it is re-enabled.
    pub(super) paused: bool,
    updated_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CursorPosition {
    ClaimChangelog([u8; 16]),
    Settlement(u64),
}

impl CursorRow {
    pub(super) fn new(position: Option<FactPosition>, at: u64) -> Self {
        Self {
            position: position.map(|position| match position {
                FactPosition::ClaimChangelog(position) => {
                    CursorPosition::ClaimChangelog(position.0)
                }
                FactPosition::Settlement(position) => CursorPosition::Settlement(position.0),
            }),
            paused: false,
            updated_at: at,
        }
    }

    pub(super) fn paused(self, at: u64) -> Self {
        Self {
            paused: true,
            updated_at: at,
            ..self
        }
    }

    pub(super) fn position(self) -> Option<FactPosition> {
        self.position.map(|position| match position {
            CursorPosition::ClaimChangelog(id) => {
                FactPosition::ClaimChangelog(ClaimChangelogPosition(id))
            }
            CursorPosition::Settlement(sequence) => {
                FactPosition::Settlement(SettlementPosition(sequence))
            }
        })
    }
}

pub(super) fn cursor(
    vault: &Vault,
    binding: EntityId,
    source: FactSource,
) -> Result<Option<CursorRow>> {
    let rtxn = vault.store.env.read_txn()?;
    CURSORS.get(&vault.store, &rtxn, &(binding, [source.tag()]))
}

pub(super) fn put_cursor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    binding: EntityId,
    source: FactSource,
    row: &CursorRow,
) -> Result<()> {
    CURSORS.put(&vault.store, txn, &(binding, [source.tag()]), row)
}

/// Moves `binding`'s cursor to `position` unless it already stands there or
/// past it.
pub(super) fn advance_cursor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    binding: EntityId,
    position: FactPosition,
    at: u64,
) -> Result<()> {
    let source = position.source();
    let current = CURSORS
        .get(&vault.store, txn, &(binding, [source.tag()]))?
        .and_then(CursorRow::position);
    if current.is_some_and(|current| current >= position) {
        return Ok(());
    }
    put_cursor_in_txn(
        vault,
        txn,
        binding,
        source,
        &CursorRow::new(Some(position), at),
    )
}

/// How a run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum HookRunState {
    Completed,
    Refused,
    Failed,
}

/// One read a run made, pinned by what it answered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct HookReadPin {
    pub(super) request: String,
    /// Hex BLAKE3 of the JSON the read answered.
    pub(super) response_hash: String,
    pub(super) rows: Vec<HookReadRow>,
}

/// One row a read served: its id and its revision's content-hash byte.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct HookReadRow {
    #[serde(with = "crate::serialize::entity_ref")]
    pub(super) id: EntityId,
    pub(super) content_hash: u8,
}

/// One `ai.verdict` a run asked, and what it heard: the verdict's JSON, or
/// the refusal's text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct HookVerdictPin {
    pub(super) request_json: String,
    pub(super) reply: std::result::Result<String, String>,
}

/// The memo row: a run's saved result. A repeat run finds it and computes
/// nothing. It does not prove an effect landed; the intent row says that.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct HookRunRecord {
    #[serde(with = "crate::serialize::entity_ref")]
    pub(super) binding: EntityId,
    #[serde(with = "crate::serialize::entity_ref")]
    pub(super) code: EntityId,
    pub(super) body_hash: String,
    pub(super) source: FactSource,
    pub(super) position: String,
    pub(super) fact: FactKind,
    #[serde(with = "crate::serialize::entity_ref")]
    pub(super) entity: EntityId,
    /// The exact input the body saw; `None` past the pin bound.
    pub(super) input_json: Option<String>,
    pub(super) input_hash: String,
    pub(super) reads: Vec<HookReadPin>,
    /// Each `ai.verdict` the run asked, in order, while they fit the pin
    /// bound.
    pub(super) verdicts: Vec<HookVerdictPin>,
    /// False once a verdict did not fit: replay has no verdict history then.
    pub(super) verdicts_complete: bool,
    pub(super) outcome_json: Option<String>,
    /// The outcome kind, or `refused` / `failed`.
    pub(super) outcome: String,
    pub(super) reason: Option<String>,
    pub(super) state: HookRunState,
    pub(super) receipt_id: String,
    pub(super) duration_ms: u64,
    /// Unix milliseconds, as the body saw it.
    pub(super) now: u64,
    /// Unix milliseconds of the write: its place in the run index.
    pub(super) committed_at: u64,
}

/// The saved row a run index entry names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum HookRunRef {
    /// A fact run's memo row.
    Fact(RunKey),
    /// A verb run's saved record.
    Verb(RunKey),
}

impl HookRunRef {
    const fn key(self) -> RunKey {
        match self {
            Self::Fact(key) | Self::Verb(key) => key,
        }
    }
}

/// Indexes `run` under `binding` at `at`, its commit time in Unix ms. A
/// rewrite of the same run drops the row its earlier write left at
/// `previous`, so each run stands once.
pub(super) fn index_run_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    binding: EntityId,
    previous: Option<u64>,
    at: u64,
    run: HookRunRef,
) -> Result<()> {
    let key = run.key();
    if let Some(previous) = previous {
        RUN_INDEX.delete(&vault.store, txn, &(binding, previous, key))?;
    }
    RUN_INDEX.put(&vault.store, txn, &(binding, at, key), &run)
}

/// Where a saved intent stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum HookIntentState {
    Pending,
    Applied,
    Refused,
}

/// Queued work a run saved before its cursor moved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct HookIntent {
    #[serde(with = "crate::serialize::entity_ref")]
    pub(super) binding: EntityId,
    /// The hook's author: the outcome runs as this actor.
    #[serde(with = "crate::serialize::entity_ref")]
    pub(super) author: EntityId,
    pub(super) outcome_json: String,
    pub(super) lineage: Vec<LineageLink>,
    pub(super) state: HookIntentState,
    /// What landed: a row id or a door's ref.
    pub(super) landed: Option<String>,
    pub(super) reason: Option<String>,
    pub(super) created_at: u64,
    pub(super) settled_at: Option<u64>,
}

pub(super) fn memo(vault: &Vault, key: &RunKey) -> Result<Option<HookRunRecord>> {
    let rtxn = vault.store.env.read_txn()?;
    MEMOS.get(&vault.store, &rtxn, key)
}

/// The id of the receipt a run writes.
pub(super) fn receipt_id(key: &RunKey) -> String {
    format!("hook:{}", hex_lower(key))
}

/// The Hook receipt projector: runs, newest first within the query's bound.
pub(crate) fn hook_receipts(vault: &Vault, query: &ReceiptQuery) -> Result<Vec<ReceiptRecord>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for row in RECEIPTS
        .iter_from(&vault.store, &rtxn, &[])?
        .take(MAX_RECEIPT_QUERY_SCAN)
    {
        let (_, receipt) = row?;
        if !query.matches(&receipt) {
            continue;
        }
        if query.job_ref.is_some() {
            out.push(receipt);
        } else {
            retain_newest_receipt(&mut out, receipt, query.limit);
        }
    }
    Ok(out)
}
