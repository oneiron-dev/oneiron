//! Node-local OF-520 own-rate windows. An own actor's acts count per window,
//! and the first crossing of the advisory threshold in a window leaves one
//! typed check. A check never refuses, holds or narrows the act that crossed.
use crate::{EntityId, Result, Vault};

use crate::store::own_rate_rows::CHECKS;
pub(crate) use crate::store::own_rate_rows::{count_in_txn, observe_in_txn, erase_window_actor_in_txn, erase_check_actor_in_txn};

pub(crate) use crate::store::own_rate_record::OwnRate;
pub use crate::store::own_rate_record::OwnRateKind;

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

pub use crate::store::own_rate_record::OwnRateCheck;

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
