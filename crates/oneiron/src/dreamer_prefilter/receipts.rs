//! Skip and round receipt rows: keys, codec, atomic write, and the Extraction projector.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::dreamer_consolidation::WorkingSetTurn;
use crate::dreamer_runner::DreamerConsolidationScope;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::receipt::{
    FIELD_PREFILTER_DECISION, FIELD_PREFILTER_FEATURE_PREFIX, FIELD_PREFILTER_PASSED,
    FIELD_PREFILTER_PHASE, FIELD_PREFILTER_ROUND, FIELD_PREFILTER_SCANNED, FIELD_PREFILTER_SCORE,
    FIELD_PREFILTER_SKIPPED, FIELD_PREFILTER_THRESHOLD, FIELD_PREFILTER_TOKENS_SAVED,
    FIELD_PREFILTER_TURN, MAX_RECEIPT_QUERY_SCAN, ReceiptKind, ReceiptQuery, ReceiptRecord,
    hex_lower, retain_newest_receipt,
};

use super::config::invalid_prefilter_config;
use super::screen::PrefilterScreen;
use super::supersession;

/// One SKIP receipt row per screened-out turn: `prefix || round_hash(32) || turn_id(16)`.
const PREFILTER_SKIP_PREFIX: &[u8] = b"dreamer:prefilter:skip:v1:";

/// One ROLLUP receipt row per screened round: `prefix || round_hash(32)`.
const PREFILTER_ROUND_PREFIX: &[u8] = b"dreamer:prefilter:round:v1:";

pub(super) const PREFILTER_RECEIPT_VERSION: u8 = 1;

pub(super) const PREFILTER_ROUND_HASH_LEN: usize = 32;

pub(super) const PREFILTER_TURN_ID_LEN: usize = 16;

/// Value of the receipt `phase` field: which pre-extraction stage ruled.
/// Pinned here rather than in the receipt kernel because it is this writer's
/// own vocabulary, not part of the family's field ABI.
pub const PREFILTER_PHASE: &str = "prefilter";

/// `outcome` of a per-turn SKIP receipt.
pub const PREFILTER_DECISION_SKIP: &str = "skip";

/// `decision` field value of a turn the screen kept.
pub const PREFILTER_DECISION_PASS: &str = "pass";

/// `outcome` of the per-round ROLLUP receipt.
pub const PREFILTER_OUTCOME_SCREENED: &str = "screened";

const PREFILTER_SKIP_TRACE: &str = "dreamer.prefilter.skip";

const PREFILTER_ROUND_TRACE: &str = "dreamer.prefilter.round";

// ---------------------------------------------------------------------------
// Receipts
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct PrefilterSkipRow {
    pub(super) version: u8,
    pub(super) occurred_at: u64,
    pub(super) score: f32,
    pub(super) threshold: f32,
    pub(super) estimated_tokens: u64,
    pub(super) features: BTreeMap<String, f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct PrefilterRoundRow {
    pub(super) version: u8,
    pub(super) occurred_at: u64,
    // Still-current members of this round. A partial rescan retires only its
    // overlapping decisions and reduces the rollup, retaining the rest.
    pub(super) members: Vec<[u8; 16]>,
    pub(super) scanned: u64,
    pub(super) passed: u64,
    pub(super) skipped: u64,
    pub(super) estimated_tokens_saved: u64,
    pub(super) threshold: f32,
}

pub(super) fn prefilter_skip_key(round: &[u8; 32], turn: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(
        PREFILTER_SKIP_PREFIX.len() + PREFILTER_ROUND_HASH_LEN + PREFILTER_TURN_ID_LEN,
    );
    key.extend_from_slice(PREFILTER_SKIP_PREFIX);
    key.extend_from_slice(round);
    key.extend_from_slice(turn.as_bytes());
    key
}

pub(super) fn prefilter_round_key(round: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(PREFILTER_ROUND_PREFIX.len() + PREFILTER_ROUND_HASH_LEN);
    key.extend_from_slice(PREFILTER_ROUND_PREFIX);
    key.extend_from_slice(round);
    key
}

/// Persists the exact screen consumed by the transaction's partition planner.
/// Per-turn rows remain SKIPS ONLY; passes ride a lossy round's rollup. An
/// all-pass or disabled round writes nothing, but still retires earlier
/// decisions for its input turns. Disjoint historical decisions stay intact.
///
/// The owner reconstructs all input rows before planning and passes that same
/// input and screen here. Any storage/accounting error aborts the surrounding
/// enqueue and watermark transaction; no reconstruction error becomes success.
pub(crate) fn write_prefilter_receipts_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    scope: DreamerConsolidationScope,
    turns: &[WorkingSetTurn],
    screen: &PrefilterScreen,
    now: u64,
) -> Result<()> {
    supersession::retire_overlapping_decisions(vault, wtxn, scope, turns)?;
    if !screen.enabled || screen.skipped == 0 {
        return Ok(());
    }
    let round = supersession::round_hash(scope, turns);

    for entry in &screen.verdicts {
        if entry.verdict.pass {
            continue;
        }
        let row = PrefilterSkipRow {
            version: PREFILTER_RECEIPT_VERSION,
            occurred_at: now,
            score: entry.verdict.score,
            threshold: screen.threshold,
            estimated_tokens: entry.verdict.estimated_tokens,
            features: entry
                .verdict
                .features
                .iter()
                .map(|(name, value)| ((*name).to_owned(), *value))
                .collect(),
        };
        let encoded = rmp_serde::to_vec_named(&row).map_err(|_| {
            invalid_prefilter_config("dreamer prefilter skip receipt encode failed")
        })?;
        vault
            .store
            .vault_meta
            .put(wtxn, &prefilter_skip_key(&round, &entry.turn_id), &encoded)?;
    }

    let rollup = PrefilterRoundRow {
        version: PREFILTER_RECEIPT_VERSION,
        occurred_at: now,
        members: turns.iter().map(|turn| *turn.turn_id.as_bytes()).collect(),
        scanned: screen.scanned as u64,
        passed: screen.passed as u64,
        skipped: screen.skipped as u64,
        estimated_tokens_saved: screen.estimated_tokens_saved,
        threshold: screen.threshold,
    };
    let encoded = rmp_serde::to_vec_named(&rollup)
        .map_err(|_| invalid_prefilter_config("dreamer prefilter round receipt encode failed"))?;
    vault
        .store
        .vault_meta
        .put(wtxn, &prefilter_round_key(&round), &encoded)?;
    supersession::index_round(vault, wtxn, scope, &round, turns)?;
    Ok(())
}

fn prefilter_skip_receipt(round: &[u8], turn: &EntityId, row: &PrefilterSkipRow) -> ReceiptRecord {
    let round_hex = hex_lower(round);
    let turn_hex = turn.to_hex();
    let mut fields = BTreeMap::from([
        (FIELD_PREFILTER_PHASE.to_owned(), PREFILTER_PHASE.to_owned()),
        (
            FIELD_PREFILTER_DECISION.to_owned(),
            PREFILTER_DECISION_SKIP.to_owned(),
        ),
        (
            FIELD_PREFILTER_SCORE.to_owned(),
            format!("{:.6}", row.score),
        ),
        (
            FIELD_PREFILTER_THRESHOLD.to_owned(),
            format!("{:.6}", row.threshold),
        ),
        (
            FIELD_PREFILTER_TOKENS_SAVED.to_owned(),
            row.estimated_tokens.to_string(),
        ),
        (FIELD_PREFILTER_ROUND.to_owned(), round_hex.clone()),
        (FIELD_PREFILTER_TURN.to_owned(), turn_hex.clone()),
    ]);
    for (name, value) in &row.features {
        fields.insert(
            format!("{FIELD_PREFILTER_FEATURE_PREFIX}{name}"),
            format!("{value:.6}"),
        );
    }
    ReceiptRecord {
        receipt_id: format!("prefilter:skip:{round_hex}:{turn_hex}"),
        receipt_kind: ReceiptKind::Extraction,
        occurred_at: row.occurred_at,
        actor: None,
        on_behalf_of: None,
        outcome: PREFILTER_DECISION_SKIP.to_owned(),
        job_ref: None,
        trigger_ref: Some(format!("turn:{turn_hex}")),
        policy_trace: vec![PREFILTER_SKIP_TRACE.to_owned()],
        fields,
    }
}

fn prefilter_round_receipt(round: &[u8], row: &PrefilterRoundRow) -> ReceiptRecord {
    let round_hex = hex_lower(round);
    let fields = BTreeMap::from([
        (FIELD_PREFILTER_PHASE.to_owned(), PREFILTER_PHASE.to_owned()),
        (
            FIELD_PREFILTER_DECISION.to_owned(),
            PREFILTER_OUTCOME_SCREENED.to_owned(),
        ),
        (FIELD_PREFILTER_ROUND.to_owned(), round_hex.clone()),
        (FIELD_PREFILTER_SCANNED.to_owned(), row.scanned.to_string()),
        (FIELD_PREFILTER_PASSED.to_owned(), row.passed.to_string()),
        (FIELD_PREFILTER_SKIPPED.to_owned(), row.skipped.to_string()),
        (
            FIELD_PREFILTER_TOKENS_SAVED.to_owned(),
            row.estimated_tokens_saved.to_string(),
        ),
        (
            FIELD_PREFILTER_THRESHOLD.to_owned(),
            format!("{:.6}", row.threshold),
        ),
    ]);
    ReceiptRecord {
        receipt_id: format!("prefilter:round:{round_hex}"),
        receipt_kind: ReceiptKind::Extraction,
        occurred_at: row.occurred_at,
        actor: None,
        on_behalf_of: None,
        outcome: PREFILTER_OUTCOME_SCREENED.to_owned(),
        job_ref: None,
        trigger_ref: None,
        policy_trace: vec![PREFILTER_ROUND_TRACE.to_owned()],
        fields,
    }
}

/// The [`ReceiptKind::Extraction`] projector: per-turn skip rulings and the
/// per-round rollup they belong to.
///
/// Own store, own read transaction, own field class — the additive-projector
/// house pattern the Gate kind already carries four of. The kind gate is
/// applied by the caller in `receipt::family`, as every sibling projector's
/// is, so a single-kind query never pays for a family it did not ask for.
///
/// Both walks are bounded by [`MAX_RECEIPT_QUERY_SCAN`]. The keys are round
/// hashes, which are not time-ordered, so the walk cannot stop early on time
/// the way a ledger-ordered projector can; the newest `query.limit` of the
/// matches is retained as it is everywhere else, and a `job_ref` query stays
/// exhaustive within the walk because that join runs after collection.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on a malformed key or row.
pub(crate) fn prefilter_receipts(
    vault: &Vault,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();

    for (scanned, row) in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, PREFILTER_SKIP_PREFIX)?
        .take(MAX_RECEIPT_QUERY_SCAN + 1)
        .enumerate()
    {
        if scanned == MAX_RECEIPT_QUERY_SCAN {
            note_prefilter_scan_capped("skip");
            break;
        }
        let (key, raw) = row?;
        let (round, turn) = parse_prefilter_skip_key(&key)?;
        let decoded: PrefilterSkipRow = rmp_serde::from_slice(&raw)
            .map_err(|_| Error::CorruptedIndex("dreamer prefilter skip receipt"))?;
        // The key is version-scoped, so a foreign version UNDER a v1 key is
        // corruption rather than a migration.
        if decoded.version != PREFILTER_RECEIPT_VERSION {
            return Err(Error::CorruptedIndex("dreamer prefilter skip receipt"));
        }
        collect_prefilter_receipt(
            &mut out,
            query,
            prefilter_skip_receipt(round, &turn, &decoded),
        );
    }

    for (scanned, row) in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, PREFILTER_ROUND_PREFIX)?
        .take(MAX_RECEIPT_QUERY_SCAN + 1)
        .enumerate()
    {
        if scanned == MAX_RECEIPT_QUERY_SCAN {
            note_prefilter_scan_capped("round");
            break;
        }
        let (key, raw) = row?;
        let round = key
            .get(PREFILTER_ROUND_PREFIX.len()..)
            .filter(|rest| rest.len() == PREFILTER_ROUND_HASH_LEN)
            .ok_or(Error::CorruptedIndex("dreamer prefilter round key"))?;
        let decoded: PrefilterRoundRow = rmp_serde::from_slice(&raw)
            .map_err(|_| Error::CorruptedIndex("dreamer prefilter round receipt"))?;
        if decoded.version != PREFILTER_RECEIPT_VERSION {
            return Err(Error::CorruptedIndex("dreamer prefilter round receipt"));
        }
        collect_prefilter_receipt(&mut out, query, prefilter_round_receipt(round, &decoded));
    }

    Ok(out)
}

fn parse_prefilter_skip_key(key: &[u8]) -> Result<(&[u8], EntityId)> {
    let rest = key
        .get(PREFILTER_SKIP_PREFIX.len()..)
        .filter(|rest| rest.len() == PREFILTER_ROUND_HASH_LEN + PREFILTER_TURN_ID_LEN)
        .ok_or(Error::CorruptedIndex("dreamer prefilter skip key"))?;
    let (round, turn_bytes) = rest.split_at(PREFILTER_ROUND_HASH_LEN);
    let raw: [u8; PREFILTER_TURN_ID_LEN] = turn_bytes
        .try_into()
        .map_err(|_| Error::CorruptedIndex("dreamer prefilter skip key"))?;
    let turn = EntityId::from_bytes(raw)
        .map_err(|_| Error::CorruptedIndex("dreamer prefilter skip key"))?;
    Ok((round, turn))
}

fn collect_prefilter_receipt(
    out: &mut Vec<ReceiptRecord>,
    query: &ReceiptQuery,
    record: ReceiptRecord,
) {
    if !query.matches(&record) {
        return;
    }
    if query.job_ref.is_some() {
        out.push(record);
    } else {
        retain_newest_receipt(out, record, query.limit);
    }
}

/// Surfaces a screening-receipt walk that stopped at the receipt-family work
/// cap: the answer is a bounded PREFIX of the family, not the family.
fn note_prefilter_scan_capped(family: &str) {
    tracing::warn!(
        scan_cap = MAX_RECEIPT_QUERY_SCAN,
        family,
        "dreamer prefilter receipt scan hit the receipt-family work cap; older rows were not projected"
    );
}
