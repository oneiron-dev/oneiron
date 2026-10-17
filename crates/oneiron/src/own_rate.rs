//! Node-local OF-520 own-rate windows. An own actor's acts count per window,
//! and the first crossing of the advisory threshold in a window leaves one
//! typed check. A check never refuses, holds or narrows the act that crossed.
use serde::{Deserialize, Serialize};

use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::{EntityId, Result, Vault};

/// Counted acts per (actor, kind) in the current window.
const WINDOWS: SideTable<(EntityId, String), OwnRateWindow, Named> =
    SideTable::new(&side_table::OWN_RATE_WINDOW);
/// The latest crossing per (actor, kind).
const CHECKS: SideTable<(EntityId, String), OwnRateCheck, Named> =
    SideTable::new(&side_table::OWN_RATE_CHECK);

/// What an own-rate window counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnRateKind {
    /// Task creates and asks by one actor.
    TaskCreate,
    /// Claims an agent wrote as Auto.
    AutoWrite,
    /// Wrong labels one reader filed on one weave link or item.
    WeaveCorrection,
    /// Consult fan-out requests by one actor, one count per request.
    ConsultFanout,
}

impl OwnRateKind {
    const fn token(self) -> &'static str {
        match self {
            Self::TaskCreate => "task_create",
            Self::AutoWrite => "auto_write",
            Self::WeaveCorrection => "weave_correction",
            Self::ConsultFanout => "consult_fanout",
        }
    }
}

/// An advisory threshold and the window it counts over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OwnRate {
    pub(crate) threshold: u64,
    pub(crate) window_seconds: u64,
}

/// The Dreamer's auto-write rate: 1000 Auto claims an hour per agent actor.
const AUTO_WRITE: OwnRate = OwnRate {
    threshold: 1000,
    window_seconds: 3600,
};

#[cfg(test)]
thread_local! {
    static AUTO_WRITE_THRESHOLD: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// Test seam: lowers this thread's auto-write threshold until reset with None.
#[cfg(test)]
pub(crate) fn set_auto_write_threshold_for_test(threshold: Option<u64>) {
    AUTO_WRITE_THRESHOLD.with(|cell| cell.set(threshold));
}

pub(crate) fn auto_write_rate() -> OwnRate {
    #[cfg(test)]
    if let Some(threshold) = AUTO_WRITE_THRESHOLD.with(std::cell::Cell::get) {
        return OwnRate {
            threshold,
            ..AUTO_WRITE
        };
    }
    AUTO_WRITE
}

/// Declares [`AutoWriteDoor`] and its `ALL` list from one list of doors, so
/// the check that walks the list cannot miss a door the enum names.
#[cfg(test)]
macro_rules! auto_write_doors {
    ($($(#[doc = $doc:literal])* $door:ident,)*) => {
        /// Every door through which the Dreamer's consolidation writer lands
        /// an Auto claim. Each counts its write on the Dreamer actor's
        /// window and names itself here as it does.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(crate) enum AutoWriteDoor {
            $($(#[doc = $doc])* $door,)*
        }

        impl AutoWriteDoor {
            pub(crate) const ALL: &'static [Self] = &[$(Self::$door,)*];
        }
    };
}

#[cfg(test)]
auto_write_doors! {
    /// `promote_one`: unscoped and scoped promotions, and the conflict closes
    /// routed through them.
    Promotion,
    /// `attach_ref`: a new evidence assertion on a claim that already stands.
    Attachment,
    /// `grant_deferred_claim_auto_after`: a replacement a Dreamer run parked,
    /// granted Auto through the public or the scoped grant door.
    DeferredGrant,
}

#[cfg(test)]
thread_local! {
    static COUNTED_AUTO_WRITES: std::cell::RefCell<Vec<AutoWriteDoor>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Notes that `door` just counted an Auto write.
#[cfg(test)]
pub(crate) fn counted_auto_write(door: AutoWriteDoor) {
    COUNTED_AUTO_WRITES.with(|doors| doors.borrow_mut().push(door));
}

/// The doors that counted on this thread since the last call.
#[cfg(test)]
pub(crate) fn take_counted_auto_writes() -> Vec<AutoWriteDoor> {
    COUNTED_AUTO_WRITES.with(|doors| std::mem::take(&mut *doors.borrow_mut()))
}

/// OF-520 question at an own actor's first threshold crossing in one window.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnRateCheck {
    pub kind: OwnRateKind,
    pub actor: String,
    pub window_started_at: u64,
    /// 0 for a count with no time window, such as every report on one link.
    pub window_seconds: u64,
    pub count: u64,
    pub threshold: u64,
}

impl OwnRateCheck {
    pub const KIND: &'static str = "own_rate_burst";
}

#[derive(Serialize, Deserialize)]
struct OwnRateWindow {
    window: u64,
    count: u64,
}

/// Counts one act in the actor's current window, inside the act's own
/// transaction, and returns the window's count. A rolled-back act leaves no
/// count and no check.
pub(crate) fn count_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    kind: OwnRateKind,
    actor: EntityId,
    now: u64,
    rate: OwnRate,
) -> Result<u64> {
    let window = now / rate.window_seconds.max(1);
    let key = (actor, kind.token().to_owned());
    let count = match WINDOWS.get(store, txn, &key)? {
        Some(row) if row.window == window => row.count,
        _ => 0,
    }
    .saturating_add(1);
    WINDOWS.put(store, txn, &key, &OwnRateWindow { window, count })?;
    observe_in_txn(store, txn, kind, actor, window, count, rate)?;
    Ok(count)
}

/// Writes the typed check for the first act past the threshold in force in
/// `window`. A caller that keeps its own window counter calls this directly.
///
/// "First" is judged against the check already written, not by `count`
/// landing exactly on `threshold + 1`: a threshold narrowed below an actor's
/// running count would otherwise never meet that equality, and the act that
/// first runs past the narrowed one still owes its check.
pub(crate) fn observe_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    kind: OwnRateKind,
    actor: EntityId,
    window: u64,
    count: u64,
    rate: OwnRate,
) -> Result<()> {
    if count <= rate.threshold {
        return Ok(());
    }
    let key = (actor, kind.token().to_owned());
    let window_started_at = window.saturating_mul(rate.window_seconds);
    if let Some(check) = CHECKS.get(store, txn, &key)?
        && check.window_started_at == window_started_at
        && check.window_seconds == rate.window_seconds
        && check.threshold == rate.threshold
    {
        return Ok(());
    }
    CHECKS.put(
        store,
        txn,
        &key,
        &OwnRateCheck {
            kind,
            actor: actor.to_hex(),
            window_started_at,
            window_seconds: rate.window_seconds,
            count,
            threshold: rate.threshold,
        },
    )
}

impl Vault {
    /// The latest window in which this actor's acts of `kind` crossed the
    /// advisory threshold, if any. A check never refuses an act.
    pub fn own_rate_check(
        &self,
        actor: EntityId,
        kind: OwnRateKind,
    ) -> Result<Option<OwnRateCheck>> {
        let txn = self.store.env.read_txn()?;
        CHECKS.get(&self.store, &txn, &(actor, kind.token().to_owned()))
    }
}
