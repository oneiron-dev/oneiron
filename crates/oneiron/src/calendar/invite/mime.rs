//! iMIP MIME rendering and blob reads.

use super::CalendarError;
use super::admission::refused;
use super::payload::{
    CALENDAR_INVITE_MEDIA_TYPE, CALENDAR_INVITE_PART_FILENAME, CalendarInviteMethod,
    CalendarInvitePayload,
};
use crate::Vault;
use crate::entity_id::EntityId;

/// The `text/calendar` part one invite send carries beside the ordinary body.
///
/// Not a parallel connector payload: it is the resolved form of the SAME frozen
/// reference, built at the last boundary before transport, exactly like the
/// CA-05 hygiene headers are read from frozen bytes rather than re-derived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarInviteMimePart {
    /// Full `Content-Type` header value, method parameter included.
    pub content_type: String,
    /// The iMIP method this part carries.
    pub method: CalendarInviteMethod,
    /// Suggested attachment filename.
    pub filename: String,
    /// The rendered `.ics` bytes, dereferenced from the frozen blob ref.
    pub ics: Vec<u8>,
}

/// Builds the `text/calendar; method=…` part for one frozen invite.
///
/// # Errors
///
/// [`CalendarError::InviteRefused`] when the frozen blob ref does not resolve;
/// [`CalendarError::IcsIngest`] on store failures.
pub fn build_calendar_invite_mime_part(
    vault: &Vault,
    payload: &CalendarInvitePayload,
) -> Result<CalendarInviteMimePart, CalendarError> {
    let ics = read_calendar_invite_ics(vault, payload)?;
    Ok(CalendarInviteMimePart {
        content_type: format!(
            "{CALENDAR_INVITE_MEDIA_TYPE}; method={}; charset=utf-8",
            payload.method.as_str()
        ),
        method: payload.method,
        filename: CALENDAR_INVITE_PART_FILENAME.to_owned(),
        ics,
    })
}

/// Resolves the ICS bytes one frozen invite references.
///
/// # Errors
///
/// [`CalendarError::InviteRefused`] when the reference does not dereference to
/// stored bytes; [`CalendarError::IcsIngest`] on store failures.
pub fn read_calendar_invite_ics(
    vault: &Vault,
    payload: &CalendarInvitePayload,
) -> Result<Vec<u8>, CalendarError> {
    let artifact_id = parse_blob_ref(&payload.ics_blob_ref)?;
    let head = vault
        .blob_artifact_head(&artifact_id)
        .map_err(CalendarError::from)?
        .ok_or_else(|| refused("ics_blob_ref names no stored blob artifact version"))?;
    vault
        .read_blob_artifact_version(&artifact_id, head.version)
        .map_err(CalendarError::from)?
        .ok_or_else(|| refused("ics_blob_ref head has no stored bytes"))
}

/// Resolves `ics_blob_ref` to a real blob artifact head and returns its
/// content hash.
///
/// Two jobs in one read: it proves the frozen reference dereferences (I10's
/// precondition — the connector must be able to build the MIME part) and it
/// supplies the passport's content hash, so "same SEQUENCE, drifted content"
/// is decidable without ever putting `.ics` bytes in the frozen body.
pub(super) fn ics_blob_content_hash(
    vault: &Vault,
    blob_ref: &str,
) -> Result<[u8; 32], CalendarError> {
    let artifact_id = parse_blob_ref(blob_ref)?;
    let head = vault
        .blob_artifact_head(&artifact_id)
        .map_err(CalendarError::from)?
        .ok_or_else(|| refused("ics_blob_ref names no stored blob artifact version"))?;
    Ok(head.content_hash)
}

/// Accepts `blob:<32-hex>` and a bare `<32-hex>` entity id.
fn parse_blob_ref(blob_ref: &str) -> Result<EntityId, CalendarError> {
    let trimmed = blob_ref.trim();
    let hex = trimmed.strip_prefix("blob:").unwrap_or(trimmed);
    EntityId::from_hex(hex).map_err(|_| refused("ics_blob_ref is not a blob artifact entity ref"))
}
