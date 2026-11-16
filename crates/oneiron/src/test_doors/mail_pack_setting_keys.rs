//! Doors for `tests/pack_keys_mail.rs` (owner ruling PACK-SETTINGS-ALL = B): the mail and
//! calendar pack's Setting keys, read where the engine reads them.

use crate::error::Result;
use crate::{TimeRange, Vault};

/// How many recipients a drafted reply to one sender with `cc` in Cc names under the vault's
/// `mail_calendar.reply.max_recipients`, or the refusal's message.
///
/// # Errors
///
/// Storage errors.
pub fn reply_recipient_count(
    vault: &Vault,
    cc: &[String],
) -> Result<std::result::Result<usize, String>> {
    crate::mail_pack::setting_keys::reply_recipient_count(vault, cc)
}

/// The first link a Microsoft 365 calendar view opened at `now` reads, and the span its
/// listing covers, under the vault's `mail_calendar.microsoft365_calendar.*` keys.
///
/// # Errors
///
/// Storage errors.
pub fn graph_calendar_opening(vault: &Vault, now: u64) -> Result<(String, TimeRange)> {
    crate::mail_pack::graph_calendar_opening(vault, now)
}

/// The span the listing of a Microsoft 365 calendar view covers, read from its stored cursor.
///
/// # Errors
///
/// A cursor that does not decode.
pub fn graph_calendar_cursor_covers(cursor: &str) -> Result<TimeRange> {
    crate::mail_pack::graph_calendar_cursor_covers(cursor)
}
