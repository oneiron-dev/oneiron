//! The idle call at a parked run's cache horizon (L2-37 PR-2; ARCH-0067 #idle-fold-policy).
//!
//! A parked canonical run whose last turn answer left a prompt prefix cached gets one due row,
//! written right after its park. A minute before the provider lets that prefix go, the resident
//! pump's pass makes one call for the wait, Fold or Expire (Keep is PR-3), by E+ over PR-1's
//! return cells:
//!
//! - Fold seals the run's applicable kind marks now, as the token feed would at the run's next
//!   breakpoint, with no model call, so a return after the prefix is gone writes the smaller
//!   context. The resumed run takes the batch as its first brief boundary (Engine call FOLD B).
//! - Expire writes nothing.
//!
//! Each call is recorded per wait for the replay check. A cell too thin to read decides Expire
//! (RULING L2-37-COLD-START = A), as does a run with no kind mark to fold or a price the catalog
//! does not hold. A wait whose run came back first, or moved off its park, gets no call.

use serde::{Deserialize, Serialize};

use super::e_plus::{self, CachePrices, PromptAtHorizon};
use super::returns::backed_off_cell;
use super::{IdleWait, WAITS, band_of, row};
use crate::attempt_queue::AttemptId;
use crate::code_run::WaitKey;
use crate::engine_executor::ParkedKindFolds;
use crate::llm::{LlmUsage, ModelId, ServedCacheHorizon};
use crate::side_table::{self, Named, SideKey, SideTable};
use crate::{EntityId, Error, Result, Vault};

/// A parked wait's due idle call. Key: the wait's own row key (run, wait, generation).
const DUE: SideTable<(EntityId, EntityId, u64), IdleFoldDue, Named> =
    SideTable::new(&side_table::IDLE_FOLD_DUE);
/// The call each wait got. Key: the wait's own row key.
const CALLS: SideTable<(EntityId, EntityId, u64), IdleCallRecord, Named> =
    SideTable::new(&side_table::IDLE_FOLD_CALLS);
/// The folds an idle call landed while their run was parked, which its next entry takes as a
/// brief boundary. Key: the run.
const BOUNDARIES: SideTable<EntityId, Vec<u64>, Named> =
    SideTable::new(&side_table::IDLE_FOLD_BOUNDARIES);

/// The call is made this long before the provider lets the prefix go: the reference's one
/// minute (M = 1).
const CALL_BEFORE_EXPIRY_MS: u64 = 60_000;

/// The prompt prefix a run's last turn answer left cached, and the model that answered it, whose
/// catalog prices the call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CachedPrefixHorizon {
    pub horizon: ServedCacheHorizon,
    pub model: ModelId,
}

impl CachedPrefixHorizon {
    /// The prefix an answer's served receipt names, with the model that answered it: `None` when
    /// its ladder stamped no cache horizon or no model id.
    #[must_use]
    pub fn of_answer(usage: &LlmUsage) -> Option<Self> {
        Some(Self {
            horizon: usage.served_cache_horizon()?,
            model: ModelId::new(usage.served_model_id()?).ok()?,
        })
    }
}

/// A parked wait's due idle call: the prefix, the parked attempt, the run's own agent (the
/// byline of the folds its marks ask for) and when the call is due, in unix milliseconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IdleFoldDue {
    pub(crate) prefix: CachedPrefixHorizon,
    pub(crate) attempt: AttemptId,
    pub(crate) actor: EntityId,
    pub(crate) due_ms: u64,
}

/// What an idle call did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum IdleCall {
    /// Landed `folds` folds by kind, whose bodies held about `tokens` prompt tokens.
    Fold { folds: u32, tokens: u64 },
    /// Let the prefix go.
    Expire,
}

/// One wait's idle call, and when it was made, in unix milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IdleCallRecord {
    pub(crate) call: IdleCall,
    pub(crate) at_ms: u64,
}

/// Writes `key`'s due idle call for the prefix its parked run's last turn answer left cached,
/// in its own write right after the park commit. `attempt` is the parked attempt and `actor` the
/// run's own agent. A wait that is no longer open and parked (its reply came first), or one the
/// wait records do not hold (a budget trap), gets none; `false` then. A stop between the park and
/// this write leaves no due row, which is Expire.
pub fn record_cache_horizon(
    vault: &Vault,
    key: &WaitKey,
    attempt: AttemptId,
    actor: EntityId,
    prefix: &CachedPrefixHorizon,
) -> Result<bool> {
    let due = IdleFoldDue {
        prefix: prefix.clone(),
        attempt,
        actor,
        due_ms: prefix
            .horizon
            .expires_unix_ms()
            .saturating_sub(CALL_BEFORE_EXPIRY_MS),
    };
    vault.with_write_txn_grouped(|txn| {
        if !still_parked_in_txn(vault, txn, key, attempt)? {
            return Ok(false);
        }
        DUE.put(&vault.store, txn, &row(key), &due)?;
        Ok(true)
    })
}

/// When the earliest due idle call is due, in unix milliseconds, for the pump's sleep; `None`
/// with none due. A row that does not decode is skipped.
pub fn next_idle_call_due_ms(vault: &Vault) -> Result<Option<u64>> {
    let txn = vault.store.env.read_txn()?;
    Ok(due_rows(vault, &txn)?
        .into_iter()
        .filter_map(|(_, due)| due.map(|due| due.due_ms))
        .min())
}

/// Every due row: its wait, and its call or `None` for a value that does not decode. A key that
/// does not decode names no wait and is skipped, so one damaged row never stops a pass.
fn due_rows(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Vec<(WaitKey, Option<IdleFoldDue>)>> {
    let mut rows = Vec::new();
    for raw in DUE.iter_raw_from(&vault.store, txn, &[])? {
        let (key, value) = raw?;
        let Some((run, wait_id, generation)) = <(EntityId, EntityId, u64)>::decode_key(&key) else {
            continue;
        };
        let wait = WaitKey {
            run,
            wait_id,
            generation,
        };
        rows.push((wait, DUE.decode_value(&value).ok()));
    }
    Ok(rows)
}

/// Makes every idle call due at `now_ms`, one per due row, and returns how many it made. Each is
/// recorded in IDLE_FOLD_CALLS and its due row goes. A call that fails is logged and its due row
/// dropped, so it never blocks a later pass; its wait reads as Expire, as does a row that does
/// not decode. No model is called.
pub fn run_due_idle_calls(vault: &Vault, now_ms: u64) -> Result<usize> {
    let (due, undecodable) = {
        let txn = vault.store.env.read_txn()?;
        let (mut due, mut undecodable) = (Vec::new(), Vec::new());
        for (key, call) in due_rows(vault, &txn)? {
            match call {
                Some(call) if call.due_ms <= now_ms => due.push((key, call)),
                Some(_) => {}
                None => undecodable.push(key),
            }
        }
        (due, undecodable)
    };
    if !undecodable.is_empty() {
        vault.with_write_txn_grouped(|txn| {
            for key in &undecodable {
                DUE.delete(&vault.store, txn, &row(key))?;
            }
            Ok(())
        })?;
    }
    let mut made = 0;
    for (key, call) in due {
        match idle_call(vault, &key, &call, now_ms) {
            Ok(Some(_)) => made += 1,
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    run = %key.run.to_hex(),
                    "a parked run's idle call failed; its prefix expires"
                );
                vault.with_write_txn_grouped(|txn| DUE.delete(&vault.store, txn, &row(&key)))?;
            }
        }
    }
    Ok(made)
}

/// Takes the folds idle calls landed while `run` was parked, for its entry's first brief
/// boundary; `None` when there are none.
pub(crate) fn take_parked_fold_boundary(vault: &Vault, run: EntityId) -> Result<Option<Vec<u64>>> {
    vault.with_write_txn_grouped(|txn| {
        let folds = BOUNDARIES.get_lenient(&vault.store, txn, &run)?;
        if folds.is_some() {
            BOUNDARIES.delete(&vault.store, txn, &run)?;
        }
        Ok(folds.filter(|folds| !folds.is_empty()))
    })
}

/// Drops `key`'s due idle call, in the commit that closes its wait: a run that came back needs
/// none.
pub(super) fn forget_due_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &WaitKey,
) -> Result<()> {
    DUE.delete(&vault.store, txn, &row(key))?;
    Ok(())
}

/// The call `key`'s wait got, and when.
#[cfg(oneiron_test_support)]
pub(crate) fn idle_call_of(vault: &Vault, key: &WaitKey) -> Result<Option<IdleCallRecord>> {
    let txn = vault.store.env.read_txn()?;
    CALLS.get(&vault.store, &txn, &row(key))
}

/// `key`'s due idle call, while it is due.
#[cfg(oneiron_test_support)]
pub(crate) fn due_of(vault: &Vault, key: &WaitKey) -> Result<Option<IdleFoldDue>> {
    let txn = vault.store.env.read_txn()?;
    DUE.get(&vault.store, &txn, &row(key))
}

/// Whether `key`'s wait is still open in the wait records and its run still parked on it, with
/// no reply.
fn still_parked_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &WaitKey,
    attempt: AttemptId,
) -> Result<bool> {
    let open = WAITS
        .get_lenient(&vault.store, txn, &row(key))?
        .is_some_and(|wait| wait.is_open());
    Ok(open && crate::code_run::wait_still_parked_in_txn(vault, txn, key, attempt)?)
}

/// One wait's idle call. Phase one reads outside any write: the wait's record, the fold the run's
/// marks ask for (body files and taint rows are read outside a write), its prices and its odds.
/// Phase two is one write that rechecks the park, the due row and the run's fold ledger, lands
/// the fold or nothing, and records the call. `None` when the run came back or moved first.
fn idle_call(
    vault: &Vault,
    key: &WaitKey,
    due: &IdleFoldDue,
    now_ms: u64,
) -> Result<Option<IdleCall>> {
    let fold = fold_if_cheaper(vault, key, due, now_ms)?;
    vault.with_write_txn_grouped(|txn| {
        let current = DUE.get_lenient(&vault.store, txn, &row(key))?;
        if current.as_ref() != Some(due) || !still_parked_in_txn(vault, txn, key, due.attempt)? {
            DUE.delete(&vault.store, txn, &row(key))?;
            return Ok(None);
        }
        let call = match fold {
            Some(fold)
                if crate::code_run::base_code_run_folds_in_txn(&vault.store, txn, key.run)?
                    == fold.ledger =>
            {
                let tokens = fold.folded_tokens;
                let committed = crate::code_run::land_code_run_folds_in_txn(
                    vault,
                    txn,
                    key.run,
                    fold.records,
                    &[],
                )?;
                if committed.is_empty() {
                    IdleCall::Expire
                } else {
                    let mut boundary = BOUNDARIES
                        .get_lenient(&vault.store, txn, &key.run)?
                        .unwrap_or_default();
                    boundary.extend_from_slice(&committed);
                    BOUNDARIES.put(&vault.store, txn, &key.run, &boundary)?;
                    IdleCall::Fold {
                        folds: u32::try_from(committed.len()).unwrap_or(u32::MAX),
                        tokens,
                    }
                }
            }
            // No fold, or the ledger moved since it was sealed: the prefix goes.
            _ => IdleCall::Expire,
        };
        CALLS.put(
            &vault.store,
            txn,
            &row(key),
            &IdleCallRecord {
                call,
                at_ms: now_ms,
            },
        )?;
        DUE.delete(&vault.store, txn, &row(key))?;
        Ok(Some(call))
    })
}

/// The fold `key`'s run's marks ask for, when E+ finds it cheaper than letting the prefix go at
/// `now_ms`; `None` for Expire: no open wait, no kind mark to fold, no catalog price, or a cell
/// too thin to read.
fn fold_if_cheaper(
    vault: &Vault,
    key: &WaitKey,
    due: &IdleFoldDue,
    now_ms: u64,
) -> Result<Option<ParkedKindFolds>> {
    let Some(prices) = cache_prices(vault, &due.prefix.model)? else {
        return Ok(None);
    };
    let wait: Option<IdleWait> = {
        let txn = vault.store.env.read_txn()?;
        WAITS
            .get_lenient(&vault.store, &txn, &row(key))?
            .filter(IdleWait::is_open)
    };
    let Some(wait) = wait else {
        return Ok(None);
    };
    let Some(fold) = crate::engine_executor::parked_kind_folds(vault, key.run, due.actor)
        .map_err(engine_error)?
    else {
        return Ok(None);
    };
    let elapsed_secs = now_ms.saturating_sub(wait.parked_at_ms) / 1_000;
    let hold_secs = due.prefix.horizon.expires_unix_ms().saturating_sub(now_ms) / 1_000;
    let cell = {
        let txn = vault.store.env.read_txn()?;
        let parked_secs = wait.parked_at_ms / 1_000;
        let offset = vault
            .commitment_reminder_route_in_txn(&txn)?
            .and_then(|route| route.utc_offset_minutes_at(parked_secs))
            .unwrap_or(0);
        backed_off_cell(
            vault,
            &txn,
            (wait.session_kind, wait.wait_class),
            band_of(parked_secs, offset),
            elapsed_secs,
        )?
    };
    let Some(cell) = cell else {
        return Ok(None);
    };
    let prompt = PromptAtHorizon {
        prefix_tokens: due.prefix.horizon.tokens,
        folded_tokens: fold.folded_tokens,
    };
    Ok(e_plus::fold_beats_expire(&cell, elapsed_secs, hold_secs, prompt, prices).then_some(fold))
}

/// `model`'s cache prices as the vault's catalog quotes them; `None` when it quotes none.
fn cache_prices(vault: &Vault, model: &ModelId) -> Result<Option<CachePrices>> {
    Ok(vault
        .model_registry_row(model)?
        .and_then(|row| row.catalog.cost)
        .as_ref()
        .and_then(CachePrices::of))
}

/// The engine error an executor error carries; any other is an invariant this path breaks.
fn engine_error(error: crate::engine_executor::EngineExecutorError) -> Error {
    match error {
        crate::engine_executor::EngineExecutorError::Engine(error) => error,
        _ => Error::InvariantViolation("a parked run's kind folds did not seal"),
    }
}
