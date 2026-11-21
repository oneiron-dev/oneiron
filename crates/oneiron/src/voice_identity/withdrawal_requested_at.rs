//! The date a withdrawal's request asked for, where the vault recorded it at its own clock
//! instead (VOICE-FUTURE-DATED-WITHDRAWAL = B, Engine 21 Nov 05:31; REVIEW-10046 P1).
//!
//! A withdrawal dated past the vault's clock is recorded at that clock, so the consent log keeps
//! the recorded date alone. The recorder's retry of that request is a replay, and any other
//! request under the same event id is refused: the replay compares the asked date with the date
//! this table keeps for the stored withdrawal, or, with no row, with its recorded date, which its
//! request then asked for itself. A row binds the exact withdrawal it was written for, by its id
//! and by a fingerprint of its stored encoding, so a row an owner restore brings in never reaches
//! a different event that reuses the id here.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

use super::consent_void::consent_event_fingerprint;
use super::math_keys::digest16;
use super::types::VoiceConsentEventV1;

/// The date one withdrawal's request asked for, past the vault's clock when it was recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct VoiceWithdrawalRequestedAt {
    /// The withdrawal's consent event id.
    pub(super) withdrawal_event_id: String,
    /// [`consent_event_fingerprint`] of the withdrawal as stored.
    pub(super) withdrawal_fingerprint: [u8; 16],
    /// The date its request asked for.
    pub(super) requested_occurred_at: u64,
}

/// Requested dates of withdrawals recorded at the vault's clock. Key: subject id16 + the
/// withdrawal's event digest, as the consent log keys the withdrawal.
pub(super) const WITHDRAWAL_REQUESTED_AT: SideTable<
    (EntityId, [u8; 16]),
    VoiceWithdrawalRequestedAt,
    Named,
> = SideTable::new(&side_table::VOICE_IDENTITY_WITHDRAWAL_REQUESTED_AT);

/// The consent log's key of `withdrawal`.
fn withdrawal_key(withdrawal: &VoiceConsentEventV1) -> (EntityId, [u8; 16]) {
    (
        withdrawal.subject_ref,
        digest16(b"voice_identity.consent", withdrawal.event_id.as_bytes()),
    )
}

/// In the withdrawal's own write, on its first insertion: keeps `requested_occurred_at`, the
/// date its request asked for, when the vault recorded `withdrawal` at another date, its clock.
pub(super) fn record_requested_date_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    withdrawal: &VoiceConsentEventV1,
    requested_occurred_at: u64,
) -> Result<()> {
    if requested_occurred_at == withdrawal.occurred_at {
        return Ok(());
    }
    let row = VoiceWithdrawalRequestedAt {
        withdrawal_event_id: withdrawal.event_id.clone(),
        withdrawal_fingerprint: consent_event_fingerprint(withdrawal)?,
        requested_occurred_at,
    };
    WITHDRAWAL_REQUESTED_AT.put(store, txn, &withdrawal_key(withdrawal), &row)
}

/// The date the request of the stored withdrawal `withdrawal` asked for: the date a row keeps
/// for exactly that withdrawal, else its recorded date.
pub(super) fn requested_date(
    store: &Store,
    rtxn: &RoTxn<'_>,
    withdrawal: &VoiceConsentEventV1,
) -> Result<u64> {
    let Some(row) = WITHDRAWAL_REQUESTED_AT.get(store, rtxn, &withdrawal_key(withdrawal))? else {
        return Ok(withdrawal.occurred_at);
    };
    let exact = row.withdrawal_event_id == withdrawal.event_id
        && row.withdrawal_fingerprint == consent_event_fingerprint(withdrawal)?;
    Ok(if exact {
        row.requested_occurred_at
    } else {
        withdrawal.occurred_at
    })
}
