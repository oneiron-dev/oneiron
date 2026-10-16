//! iMIP MIME rendering and blob reads.

use super::CalendarError;
use super::admission::refused;
use super::payload::{
    CALENDAR_INVITE_MEDIA_TYPE, CALENDAR_INVITE_PART_FILENAME, CalendarInviteMethod,
    CalendarInvitePayload,
};
use crate::Vault;

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
    let (ics, _) = read_checked_invite_ics(vault, payload)?;
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
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    read_calendar_invite_ics_in_txn(vault, &txn, payload)
}

pub(crate) fn read_calendar_invite_ics_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    payload: &CalendarInvitePayload,
) -> Result<Vec<u8>, CalendarError> {
    let (artifact_id, version) = payload.blob_version_ref()?;
    let record = vault
        .blob_artifact_version_metadata_in_txn(txn, &artifact_id, version)?
        .ok_or_else(|| refused("ics_blob_ref names no stored blob artifact version"))?;
    let bytes = vault
        .read_blob_artifact_version_in_txn(txn, &artifact_id, version)?
        .ok_or_else(|| refused("ics_blob_ref version has no stored bytes"))?;
    if blake3::hash(&bytes).as_bytes() != &record.content_hash {
        return Err(refused(
            "ics_blob_ref version content hash does not match its bytes",
        ));
    }
    Ok(bytes)
}

/// Reads the ICS one invite references and proves it is that invite: its
/// VEVENT UID and SEQUENCE and its VCALENDAR METHOD are the payload's own.
/// Admission and the transport both read through here, so the bytes a send
/// carries answer to the payload that was admitted.
pub(super) fn read_checked_invite_ics(
    vault: &Vault,
    payload: &CalendarInvitePayload,
) -> Result<(Vec<u8>, super::ics::InviteIcsIdentity), CalendarError> {
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    read_checked_invite_ics_in_txn(vault, &txn, payload)
}

pub(super) fn read_checked_invite_ics_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    payload: &CalendarInvitePayload,
) -> Result<(Vec<u8>, super::ics::InviteIcsIdentity), CalendarError> {
    let ics = read_calendar_invite_ics_in_txn(vault, txn, payload)?;
    let identity = super::ics::invite_identity(&ics)?;
    if identity.uid != payload.uid
        || identity.sequence != payload.sequence
        || !identity
            .method
            .eq_ignore_ascii_case(payload.method.as_str())
    {
        return Err(refused(
            "the ICS blob does not carry this invite's UID, SEQUENCE and METHOD",
        ));
    }
    Ok((ics, identity))
}
