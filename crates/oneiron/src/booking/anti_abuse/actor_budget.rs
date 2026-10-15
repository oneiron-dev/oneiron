//! OF-520 for authenticated booking work.
//!
//! The owner's booking rates and caps (`SlotListRate`, `HoldRate`, `BookRate`
//! and the quarantine budget) shed the anonymous public route per address. An
//! authenticated actor is never refused for rate or count (rule 5): its
//! requests are counted per budget kind and window, and the first request
//! past the advisory threshold in a window records one typed check the host
//! raises as its question. Counting never denies a request; a caller drops a
//! failed observation.

use serde::{Deserialize, Serialize};

use super::storage::{RATE_WINDOW_SECS, engine_failure};
use crate::booking::BookingError;
use crate::booking::lifecycle::booking_writer;
use crate::side_table::{self, Named, Raw, SideTable};
use crate::{EntityId, Vault};

/// One actor's count of one kind in its current window:
/// `{window(8 BE), count(8 BE)}`. Key: actor + kind tag.
const COUNT: SideTable<(EntityId, [u8; 1]), [u8; 16], Raw> =
    SideTable::new(&side_table::BOOKING_ACTOR_BUDGET_COUNT);
/// One check per actor, kind and window. Key: actor + kind tag + window start.
const CHECK: SideTable<(EntityId, [u8; 1], u64), BookingBudgetCheck, Named> =
    SideTable::new(&side_table::BOOKING_ACTOR_BUDGET_CHECK);

/// Requests of one kind by one actor in one window past which the check is
/// recorded: ten times a fleet of 200 agents each sending one a minute.
pub const BOOKING_ADVISORY_THRESHOLD: u64 = 2_000;

/// What an authenticated booking request spends, one kind per admission
/// guard.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BookingBudgetKind {
    /// An availability listing (`SlotListRate`).
    SlotList,
    /// A hold (`HoldRate`).
    Hold,
    /// A confirmation, and a quarantined one (`BookRate`, the quarantine budget).
    Book,
    /// A reschedule or a cancellation (`BookRate`).
    Amend,
}

impl BookingBudgetKind {
    /// Every kind, in tag order.
    pub const ALL: [Self; 4] = [Self::SlotList, Self::Hold, Self::Book, Self::Amend];

    const fn tag(self) -> [u8; 1] {
        [match self {
            Self::SlotList => 0,
            Self::Hold => 1,
            Self::Book => 2,
            Self::Amend => 3,
        }]
    }
}

/// One actor's requests of one kind in one window.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingBudgetReceipt {
    pub actor: String,
    pub budget: BookingBudgetKind,
    pub window_started_at_secs: u64,
    pub count: u64,
}

/// OF-520 question at the first crossing of the advisory threshold.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingBudgetCheck {
    pub receipt: BookingBudgetReceipt,
    pub threshold: u64,
}

impl BookingBudgetCheck {
    pub const KIND: &'static str = "booking_budget_burst";
}

/// Counts one authenticated request of `budget` by `actor`, in its own
/// transaction, and records the check when this request is the first past
/// the threshold in its window.
///
/// # Errors
///
/// Storage failures. The request proceeds either way.
pub fn observe_authenticated_booking(
    vault: &Vault,
    actor: EntityId,
    budget: BookingBudgetKind,
    now_secs: u64,
) -> Result<BookingBudgetReceipt, BookingError> {
    let window = now_secs / RATE_WINDOW_SECS * RATE_WINDOW_SECS;
    let key = (actor, budget.tag());
    booking_writer(vault, |wtxn| {
        let count = match COUNT
            .get(&vault.store, &*wtxn, &key)
            .map_err(|error| engine_failure("budget count read", error))?
        {
            Some(stored) if stored[..8] == window.to_be_bytes() => {
                u64::from_be_bytes(stored[8..].try_into().expect("count is eight bytes"))
            }
            _ => 0,
        }
        .saturating_add(1);
        let receipt = BookingBudgetReceipt {
            actor: actor.to_hex(),
            budget,
            window_started_at_secs: window,
            count,
        };
        if count == BOOKING_ADVISORY_THRESHOLD + 1 {
            let check = BookingBudgetCheck {
                receipt: receipt.clone(),
                threshold: BOOKING_ADVISORY_THRESHOLD,
            };
            CHECK
                .put(&vault.store, wtxn, &(actor, budget.tag(), window), &check)
                .map_err(|error| engine_failure("budget check write", error))?;
        }
        let mut value = [0_u8; 16];
        value[..8].copy_from_slice(&window.to_be_bytes());
        value[8..].copy_from_slice(&count.to_be_bytes());
        COUNT
            .put(&vault.store, wtxn, &key, &value)
            .map_err(|error| engine_failure("budget count write", error))?;
        Ok(receipt)
    })
}

/// The checks recorded for `actor`, by kind, oldest window first.
///
/// # Errors
///
/// Storage failures.
pub fn booking_budget_checks(
    vault: &Vault,
    actor: EntityId,
) -> Result<Vec<BookingBudgetCheck>, BookingError> {
    let txn = vault
        .store
        .env
        .read_txn()
        .map_err(|error| engine_failure("budget check read", error))?;
    let rows = CHECK
        .scan_from(&vault.store, &txn, actor.as_bytes())
        .map_err(|error| engine_failure("budget check read", error))?;
    Ok(rows.into_iter().map(|(_, check)| check).collect())
}
