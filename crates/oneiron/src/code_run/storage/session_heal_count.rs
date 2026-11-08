//! A live off-record session's model heal tally (CODE-RUNTIME-02 slice 2:
//! FIX 4415).
//!
//! A session-bound run's healed turn adds one to the tally its route
//! targets: the vault's base row on record, the session overlay's own delta
//! row off record. The overlay row holds that delta alone, never a copy of
//! the base total, so a composed read, which lets the overlay row shadow
//! the base one, would lose the base. This read takes both rows apart and
//! adds them with checked arithmetic. It reads the one session it is given,
//! while that session lives, and never another session or the base alone.

use super::records::MODEL_HEAL_COUNTS;
use crate::off_record::OffRecordSession;
use crate::{Error, ModelId, Result};

/// One model's heal tally as one live session reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionModelHealCount {
    pub(crate) model_id: String,
    /// The vault's canonical tally.
    pub(crate) canonical_healed_turns: u64,
    /// The healed turns the session's runs committed off record.
    pub(crate) session_healed_turns: u64,
    /// The two summed.
    pub(crate) healed_turns: u64,
}

/// `model`'s heal tally as `session` reads it: the base tally plus the
/// delta the session's overlay holds, zero for a row either side lacks.
///
/// # Errors
///
/// Storage errors; a session that is closing or gone, or whose run's
/// participant left its room; a corrupted tally row; and a sum past
/// `u64::MAX`.
pub(crate) fn session_model_heal_count(
    session: &OffRecordSession<'_>,
    model: &ModelId,
) -> Result<SessionModelHealCount> {
    let model_id = model.as_str().to_owned();
    let (base, overlay) = session.side_table_counter_components(&MODEL_HEAL_COUNTS, &model_id)?;
    let canonical_healed_turns = base.map_or(0, |count| count.0);
    let session_healed_turns = overlay.map_or(0, |count| count.0);
    let healed_turns = canonical_healed_turns
        .checked_add(session_healed_turns)
        .ok_or(Error::ArithmeticOverflow("code-run model heal count"))?;
    Ok(SessionModelHealCount {
        model_id,
        canonical_healed_turns,
        session_healed_turns,
        healed_turns,
    })
}
