//! The vault-backed [`ActiveHoldSource`] the solver asks for live holds, with
//! the self-exclusion a confirm needs.

use super::storage::{decode_row, engine_failure, read_txn};
use super::token::SessionKey;
use super::types::{BOOKING_HOLD_META_PREFIX, SoftHoldRow};
use crate::booking::{ActiveHoldSource, BookingError};
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};

/// BK-00's [`ActiveHoldSource`], backed by the session-keyed hold rows.
///
/// `exclude_session_key` is not a convenience: [`crate::booking::BookingSolver`]
/// passes `None` for the trait's own exclusion argument on every solve, so the
/// confirming session's exclusion has to be bound into the source the caller
/// builds. Both exclusions are honored, so either door works.
pub struct VaultActiveHoldSource<'a> {
    pub vault: &'a Vault,
    /// The session whose own hold this source hides — the confirming session.
    pub exclude_session_key: Option<SessionKey>,
}

impl<'a> VaultActiveHoldSource<'a> {
    /// A source that hides nothing: every live hold blocks.
    #[must_use]
    pub const fn new(vault: &'a Vault) -> Self {
        Self {
            vault,
            exclude_session_key: None,
        }
    }

    /// A source that hides one session's own hold.
    #[must_use]
    pub const fn excluding(vault: &'a Vault, session_key: SessionKey) -> Self {
        Self {
            vault,
            exclude_session_key: Some(session_key),
        }
    }
}

impl ActiveHoldSource for VaultActiveHoldSource<'_> {
    fn active_holds(
        &self,
        page_ref: EntityId,
        window: TimeRange,
        now_utc: u64,
        exclude_session_key: Option<&[u8; 32]>,
    ) -> Result<Vec<TimeRange>, BookingError> {
        let bound = self.exclude_session_key.map(|key| key.0);
        let rtxn = read_txn(self.vault)?;
        let mut holds = Vec::new();
        let rows = self
            .vault
            .store
            .vault_meta
            .prefix_iter(&rtxn, BOOKING_HOLD_META_PREFIX)
            .map_err(|error| engine_failure("hold scan", error))?;
        for entry in rows {
            let (_, raw) = entry.map_err(|error| engine_failure("hold scan", error))?;
            let row: SoftHoldRow = decode_row(&raw)?;
            if row.page_ref != page_ref || !row.is_live_at(now_utc) {
                continue;
            }
            if bound == Some(row.session_key.0) || exclude_session_key == Some(&row.session_key.0) {
                continue;
            }
            if row.slot.start < window.end && window.start < row.slot.end {
                holds.push(row.slot);
            }
        }
        Ok(holds)
    }
}
