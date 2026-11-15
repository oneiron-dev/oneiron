//! Wall-clock wait records for the idle fold call (L2-37 PR-1; ARCH-0067 #idle-fold-policy).
//!
//! While an agent waits on a tool or on its user, the provider's prompt cache runs down. Canon
//! has the engine keep the cache warm, fold, or let it expire shortly before it does, by E+:
//! odds tables by session kind, time band and weekday, rebuilt weekly (RESEARCH-1333). This
//! module gathers what those tables are built from, and nothing here acts yet:
//!
//! - one row per parked canonical wait, written in the commit that parks the run's attempt under
//!   its trap: the session kind its dispatch was admitted through, the wait class its trap names,
//!   and the wall-clock park time;
//! - the return, written in the commit that delivers the wait's reply, at the delivery's time; a
//!   run that resumes with no delivery (a code consent wait, consumed in its own row) returns when
//!   its wait rows retire, at the vault's clock;
//! - a wait whose run never resumes stays open, and the Coach's weekly pass
//!   ([`rebuild_return_tables`]) counts it as never once it has waited a day.
//!
//! At a parked wait's cache horizon the resident pump makes one call for it, Fold or Expire
//! (PR-2, [`run_due_idle_calls`]); see `horizon`.
//!
//! Off-record room runs bind no trap and park no attempt, so they are not recorded; nor are chat
//! turn gaps (FIX [IDLE-FOLD-CHAT-ROOM-WAITS]). A budget trap waits on money, not on a reply, and
//! is not recorded either.

mod e_plus;
mod horizon;
mod returns;
pub(crate) mod tables;

use serde::{Deserialize, Serialize};

use crate::agent_dispatch::CallerOrigin;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::code_run::WaitKey;
use crate::llm::DreamerTrapKind;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

pub(crate) use horizon::take_parked_fold_boundary;
pub use horizon::{
    CachedPrefixHorizon, next_idle_call_due_ms, record_cache_horizon, run_due_idle_calls,
};
#[cfg(oneiron_test_support)]
pub(crate) use horizon::{IdleCall, IdleCallRecord, IdleFoldDue, due_of, idle_call_of};
pub(crate) use returns::rebuild_return_tables;
#[cfg(oneiron_test_support)]
pub(crate) use returns::{IdleReturnCell, put_return_cell, return_cell};

/// One parked canonical wait. Key: the wait's own row key (run, wait, generation).
const WAITS: SideTable<(EntityId, EntityId, u64), IdleWait, Named> =
    SideTable::new(&side_table::IDLE_FOLD_WAITS);

/// How the waiting run's root was admitted: the engine's form of the research's interactive
/// `cli` against headless `sdk-cli` key, read from the dispatch's caller origin (FIX 4973).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum IdleSessionKind {
    /// A caller over a connection: a person's client at the other end.
    Connected,
    /// The host's own dispatch, a resident among them.
    Hosted,
    /// No dispatch input, or one that names no origin.
    Unknown,
}

/// Who the wait waits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum IdleWaitClass {
    /// A person: a human answer or a consent.
    User,
    /// A tool: a peer's result.
    Tool,
}

/// One wait's wall-clock record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IdleWait {
    pub(crate) session_kind: IdleSessionKind,
    pub(crate) wait_class: IdleWaitClass,
    pub(crate) parked_at_ms: u64,
    /// When the reply came back; `None` while the wait is open, or once it counts as never.
    pub(crate) returned_at_ms: Option<u64>,
    /// The weekly pass found it still open a day after it parked.
    pub(crate) never: bool,
}

impl IdleWait {
    fn is_open(&self) -> bool {
        self.returned_at_ms.is_none() && !self.never
    }
}

impl IdleSessionKind {
    #[cfg(oneiron_test_support)]
    pub(crate) const ALL: [Self; 3] = [Self::Connected, Self::Hosted, Self::Unknown];

    fn of(origin: Option<CallerOrigin>) -> Self {
        match origin {
            Some(CallerOrigin::Connection { .. }) => Self::Connected,
            Some(CallerOrigin::NativeHost) => Self::Hosted,
            Some(CallerOrigin::Unknown) | None => Self::Unknown,
        }
    }

    #[cfg(oneiron_test_support)]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Hosted => "hosted",
            Self::Unknown => "unknown",
        }
    }

    /// The byte a return cell's key carries.
    const fn code(self) -> u8 {
        match self {
            Self::Connected => 0,
            Self::Hosted => 1,
            Self::Unknown => 2,
        }
    }
}

impl IdleWaitClass {
    #[cfg(oneiron_test_support)]
    pub(crate) const ALL: [Self; 2] = [Self::User, Self::Tool];

    /// The class a trap's wait has, or `None` for a trap that waits on no reply.
    const fn of_trap(kind: DreamerTrapKind) -> Option<Self> {
        match kind {
            DreamerTrapKind::HumanResponse | DreamerTrapKind::Consent => Some(Self::User),
            DreamerTrapKind::PeerResult => Some(Self::Tool),
            DreamerTrapKind::Budget => None,
        }
    }

    #[cfg(oneiron_test_support)]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Tool => "tool",
        }
    }

    /// The byte a return cell's key carries.
    const fn code(self) -> u8 {
        match self {
            Self::User => 0,
            Self::Tool => 1,
        }
    }
}

fn row(key: &WaitKey) -> (EntityId, EntityId, u64) {
    (key.run, key.wait_id, key.generation)
}

/// Records `key`'s wait as parked at `now_ms`, in the commit that parks `attempt` under a trap
/// of `kind`. A budget trap is not recorded, and a wait already recorded keeps its first park.
pub(crate) fn record_parked_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &WaitKey,
    kind: DreamerTrapKind,
    attempt: AttemptId,
    now_ms: u64,
) -> Result<()> {
    let Some(wait_class) = IdleWaitClass::of_trap(kind) else {
        return Ok(());
    };
    if WAITS.contains(&vault.store, txn, &row(key))? {
        return Ok(());
    }
    let origin = AttemptQueue::new(vault)
        .get_in_txn(txn, attempt)?
        .and_then(|record| crate::agent_dispatch::record_dispatch_input(&record))
        .map(|input| input.caller_origin);
    let wait = IdleWait {
        session_kind: IdleSessionKind::of(origin),
        wait_class,
        parked_at_ms: now_ms,
        returned_at_ms: None,
        never: false,
    };
    WAITS.put(&vault.store, txn, &row(key), &wait)
}

/// Closes `key`'s open wait as returned at `returned_at_ms`, in the commit that delivers its
/// reply. A wait with no row, one already closed, or a row that does not decode is left as it
/// is: the record never refuses a delivery.
pub(crate) fn record_returned_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &WaitKey,
    returned_at_ms: u64,
) -> Result<()> {
    close_in_txn(vault, txn, key, Some(returned_at_ms))
}

/// Closes `key`'s wait, if it is still open once its run resumed, at the vault's clock: the run
/// came back with no delivery, as a code consent wait does.
pub(crate) fn record_resumed_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &WaitKey,
) -> Result<()> {
    close_in_txn(vault, txn, key, None)
}

/// Closes `key`'s open wait at `returned_at_ms`, or at the vault's clock for `None`.
fn close_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &WaitKey,
    returned_at_ms: Option<u64>,
) -> Result<()> {
    // RED SEAM: a reply does not drop the due call.
    let Some(mut wait) = WAITS.get_lenient(&vault.store, txn, &row(key))? else {
        return Ok(());
    };
    if !wait.is_open() {
        return Ok(());
    }
    let returned_at_ms = match returned_at_ms {
        Some(at) => at,
        None => vault.instant_in_txn(txn)?.secs().saturating_mul(1_000),
    };
    wait.returned_at_ms = Some(returned_at_ms.max(wait.parked_at_ms));
    WAITS.put(&vault.store, txn, &row(key), &wait)
}

/// Every recorded wait, in key order; a row that does not decode is skipped.
#[cfg(oneiron_test_support)]
pub(crate) fn waits(vault: &Vault) -> Result<Vec<(WaitKey, IdleWait)>> {
    let txn = vault.store.env.read_txn()?;
    let mut waits = Vec::new();
    for (run, wait_id, generation) in WAITS.scan_keys(&vault.store, &txn, &[])? {
        let key = WaitKey {
            run,
            wait_id,
            generation,
        };
        if let Some(wait) = WAITS.get_lenient(&vault.store, &txn, &row(&key))? {
            waits.push((key, wait));
        }
    }
    Ok(waits)
}

/// The four-hour band of the day, 0 to 5, and whether the day is a Saturday or a Sunday, at
/// `at_secs` on a clock `offset_minutes` east of UTC: the research's time key, `(hour // 4,
/// weekend)`.
pub(crate) fn band_of(at_secs: u64, offset_minutes: i16) -> (u8, bool) {
    let local = i64::try_from(at_secs)
        .unwrap_or(i64::MAX)
        .saturating_add(i64::from(offset_minutes) * 60);
    let hour = local.rem_euclid(86_400) / 3_600;
    // 1970-01-01 was a Thursday: counted from Monday as 0, Saturday is 5 and Sunday 6.
    let weekday = (local.div_euclid(86_400) + 3).rem_euclid(7);
    (u8::try_from(hour / 4).unwrap_or(0), weekday >= 5)
}
