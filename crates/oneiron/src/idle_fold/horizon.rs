//! The idle call at a parked run's cache horizon (L2-37 PR-3; ARCH-0067 #idle-fold-policy).
//!
//! A parked canonical run whose last turn answer left a prompt prefix cached gets one due row,
//! written right after its park. A minute before the provider lets that prefix go, the resident
//! pump's pass makes one call for the wait, Keep, Fold or Expire, by E+ over PR-1's return cells:
//!
//! - Keep sends one refresh of the cached prefix and asks again before it expires, re-arming the
//!   due row on the refreshed horizon.
//! - Fold seals the run's applicable kind marks now, as the token feed would at the run's next
//!   breakpoint, with no model call, so a return after the prefix is gone writes the smaller
//!   context. The resumed run takes the batch as its first brief boundary (Engine call FOLD B).
//! - Expire writes nothing.
//!
//! Each call is recorded per wait for the replay check. A cell too thin to read takes the fixed
//! cold-start rule D (RULING L2-37-COLD-START = B): Keep through the owner's
//! `idle_fold.cold_start_keep_through_secs` (thirty minutes unless set), then Fold when the run
//! holds kind marks, else Expire. A price the catalog does not hold decides Expire. A wait whose
//! run came back first, or moved off its park, gets no call. The pump sends each refresh outside
//! any vault write through the pass's refresh callback, which returns the horizon its answer
//! stamped, or nothing when nothing was sent or nothing answered.

use serde::{Deserialize, Serialize};

use super::e_plus::{self, CachePrices, IdleChoice, PromptAtHorizon};
use super::returns::backed_off_cell;
use super::setting_keys::COLD_START_KEEP_THROUGH_SECS;
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

/// The asks E+ looks ahead at most per wait: the reference's CAP.
const MAX_ASKS_PER_WAIT: u32 = 36;

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
    /// The Keeps this wait got before this row.
    #[serde(default)]
    pub(crate) keeps: u32,
}

/// What an idle call did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum IdleCall {
    /// Sent one refresh of the cached prefix and asked again before it expires.
    Keep,
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
    /// The Keeps this wait got before this row.
    #[serde(default)]
    pub(crate) keeps: u32,
}

/// What one pass of idle calls did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IdleCallsMade {
    /// The calls it made: Keep, Fold or Expire.
    pub made: usize,
    /// The waits whose calls are over (a Fold, an Expire, or a due row dropped), whose kept
    /// request the pump lets go.
    pub ended: Vec<WaitKey>,
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
        keeps: 0,
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

/// Makes every idle call due at `now_ms`, one per due row. Each is recorded in IDLE_FOLD_CALLS; a
/// Keep re-arms its due row on the refreshed horizon and any other call drops it. `refresh` sends
/// one refresh of a wait's cached prefix and returns the horizon its answer stamped, or `None`
/// when nothing was sent or nothing answered; it runs outside any vault transaction, at most once
/// per due row. A call that fails is logged and its due row dropped, so it never blocks a later
/// pass; its wait reads as Expire, as does a row that does not decode.
pub fn run_due_idle_calls(
    vault: &Vault,
    now_ms: u64,
    refresh: &mut dyn FnMut(&WaitKey) -> Option<ServedCacheHorizon>,
) -> Result<IdleCallsMade> {
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
    let mut ended = Vec::new();
    if !undecodable.is_empty() {
        vault.with_write_txn_grouped(|txn| {
            for key in &undecodable {
                DUE.delete(&vault.store, txn, &row(key))?;
            }
            Ok(())
        })?;
        ended.extend(undecodable);
    }
    let mut made = 0;
    for (key, call) in due {
        match idle_call(vault, &key, &call, now_ms, refresh) {
            Ok(Some(call)) => {
                made += 1;
                if !matches!(call, IdleCall::Keep) {
                    ended.push(key);
                }
            }
            Ok(None) => {
                ended.push(key);
            }
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    run = %key.run.to_hex(),
                    "a parked run's idle call failed; its prefix expires"
                );
                vault.with_write_txn_grouped(|txn| DUE.delete(&vault.store, txn, &row(&key)))?;
                ended.push(key);
            }
        }
    }
    Ok(IdleCallsMade { made, ended })
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

/// Sets `key`'s due idle call's Keeps count, for the last-ask test.
#[cfg(oneiron_test_support)]
pub(crate) fn set_due_keeps(vault: &Vault, key: &WaitKey, keeps: u32) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        let Some(mut due) = DUE.get(&vault.store, txn, &row(key))? else {
            return Ok(());
        };
        due.keeps = keeps;
        DUE.put(&vault.store, txn, &row(key), &due)?;
        Ok(())
    })
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
/// On Keep the refresh goes out outside any write too. Phase two is one write that rechecks the
/// park and the due row, lands the fold or nothing, and records the call. `None` when the run came
/// back or moved first.
fn idle_call(
    vault: &Vault,
    key: &WaitKey,
    due: &IdleFoldDue,
    now_ms: u64,
    refresh: &mut dyn FnMut(&WaitKey) -> Option<ServedCacheHorizon>,
) -> Result<Option<IdleCall>> {
    let plan = plan_idle_call(vault, key, due, now_ms)?;
    if plan.choice == IdleChoice::Keep {
        let answered = refresh(key)
            .filter(|horizon| horizon.expires_unix_ms() > due.prefix.horizon.expires_unix_ms());
        if let Some(horizon) = answered {
            return vault.with_write_txn_grouped(|txn| {
                let current = DUE.get_lenient(&vault.store, txn, &row(key))?;
                if current.as_ref() != Some(due)
                    || !still_parked_in_txn(vault, txn, key, due.attempt)?
                {
                    DUE.delete(&vault.store, txn, &row(key))?;
                    return Ok(None);
                }
                let keeps = due.keeps.saturating_add(1);
                CALLS.put(
                    &vault.store,
                    txn,
                    &row(key),
                    &IdleCallRecord {
                        call: IdleCall::Keep,
                        at_ms: now_ms,
                        keeps,
                    },
                )?;
                DUE.put(
                    &vault.store,
                    txn,
                    &row(key),
                    &IdleFoldDue {
                        prefix: CachedPrefixHorizon {
                            horizon,
                            model: due.prefix.model.clone(),
                        },
                        attempt: due.attempt,
                        actor: due.actor,
                        due_ms: horizon
                            .expires_unix_ms()
                            .saturating_sub(CALL_BEFORE_EXPIRY_MS),
                        keeps,
                    },
                )?;
                Ok(Some(IdleCall::Keep))
            });
        }
        // The Keep sent nothing, or its horizon is not later: fall back to the one-step call.
        let fold = if plan.fallback == IdleChoice::Fold {
            plan.fold
        } else {
            None
        };
        return land_fold_or_expire(vault, key, due, now_ms, fold);
    }
    let fold = if plan.choice == IdleChoice::Fold {
        plan.fold
    } else {
        None
    };
    land_fold_or_expire(vault, key, due, now_ms, fold)
}

/// Phase one's decision: the fold the run's marks ask for, if any, E+'s call with the asks left,
/// and the one-step call with a single ask, for a Keep whose refresh sends nothing.
struct IdlePlan {
    fold: Option<ParkedKindFolds>,
    choice: IdleChoice,
    fallback: IdleChoice,
}

/// E+'s call for `key`'s wait at `now_ms`, with the fold its marks ask for. A thin cell takes rule
/// D ([`cold_start_plan`]); a price the catalog does not hold decides Expire. With one ask left
/// Keep is not offered.
fn plan_idle_call(
    vault: &Vault,
    key: &WaitKey,
    due: &IdleFoldDue,
    now_ms: u64,
) -> Result<IdlePlan> {
    let expired = IdlePlan {
        fold: None,
        choice: IdleChoice::Expire,
        fallback: IdleChoice::Expire,
    };
    let Some(prices) = cache_prices(vault, &due.prefix.model)? else {
        return Ok(expired);
    };
    let wait: Option<IdleWait> = {
        let txn = vault.store.env.read_txn()?;
        WAITS
            .get_lenient(&vault.store, &txn, &row(key))?
            .filter(IdleWait::is_open)
    };
    let Some(wait) = wait else {
        return Ok(expired);
    };
    let fold = crate::engine_executor::parked_kind_folds(vault, key.run, due.actor)
        .map_err(engine_error)?;
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
    let lifetime_secs = u64::from(due.prefix.horizon.lifetime_secs);
    let asks_left = MAX_ASKS_PER_WAIT.saturating_sub(due.keeps);
    let Some(cell) = cell else {
        return cold_start_plan(vault, due, fold, prices, lifetime_secs, asks_left);
    };
    let prompt = PromptAtHorizon {
        prefix_tokens: due.prefix.horizon.tokens,
        folded_tokens: fold.as_ref().map_or(0, |fold| fold.folded_tokens),
    };
    let choice = e_plus::idle_choice(
        &cell,
        elapsed_secs,
        hold_secs,
        lifetime_secs,
        prompt,
        prices,
        asks_left,
    );
    let fallback = e_plus::idle_choice(
        &cell,
        elapsed_secs,
        hold_secs,
        lifetime_secs,
        prompt,
        prices,
        1,
    );
    Ok(IdlePlan {
        fold,
        choice,
        fallback,
    })
}

/// Rule D's call for a wait whose cell is too thin to read (RULING L2-37-COLD-START = B): Keep
/// while the wait has had fewer Keeps than the owner's window asks
/// ([`e_plus::cold_start_keeps`]), then Fold when the run holds kind marks, else Expire. As in
/// E+, Keep needs a later ask and an output price that reads; a Keep whose refresh sends nothing
/// falls back to the call after the Keeps.
fn cold_start_plan(
    vault: &Vault,
    due: &IdleFoldDue,
    fold: Option<ParkedKindFolds>,
    prices: CachePrices,
    lifetime_secs: u64,
    asks_left: u32,
) -> Result<IdlePlan> {
    let keep_through_secs = {
        let txn = vault.store.env.read_txn()?;
        COLD_START_KEEP_THROUGH_SECS
            .read_in_txn(vault, &txn, &[], None)?
            .value
    };
    let after = if fold.is_some() {
        IdleChoice::Fold
    } else {
        IdleChoice::Expire
    };
    let keep = due.keeps < e_plus::cold_start_keeps(keep_through_secs, lifetime_secs)
        && asks_left > 1
        && prices.output_per_token.is_some();
    Ok(IdlePlan {
        fold,
        choice: if keep { IdleChoice::Keep } else { after },
        fallback: after,
    })
}

/// Phase two for Fold and Expire: one write that rechecks the park, the due row and the run's fold
/// ledger, lands the fold or nothing, and records the call with the Keeps the wait got before it.
/// `None` when the run came back or moved first.
fn land_fold_or_expire(
    vault: &Vault,
    key: &WaitKey,
    due: &IdleFoldDue,
    now_ms: u64,
    fold: Option<ParkedKindFolds>,
) -> Result<Option<IdleCall>> {
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
                keeps: due.keeps,
            },
        )?;
        DUE.delete(&vault.store, txn, &row(key))?;
        Ok(Some(call))
    })
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
