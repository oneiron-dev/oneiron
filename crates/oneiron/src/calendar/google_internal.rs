//! Workspace-Internal Google calendar adapter (CAL-05, ONE-1787).
//!
//! The dogfood rung only: one internal seat reading and writing its OWN
//! calendar through a host transport that resolves an internal OAuth
//! `secret_ref`. There is deliberately no bring-your-own-credentials path, no
//! public shared OAuth application, and no consent surface here — those are
//! parked v2 work, and inventing them is not this ticket's job.
//!
//! The custody class check in [`is_workspace_internal_secret_ref`] is capability
//! selection, not a newly invented human approval step: a seat may only run this
//! transport with a `secret_ref` provisioned for the internal dogfood class.
//! Credential material itself never reaches this module — the wire resolves the
//! custody record at its own egress door, exactly as
//! [`super::ingest::CustodyDoorIcsFeedFetcher`] does, and swaps to SECRET-02's
//! door/lease API with no signature change here.
//!
//! Protocol details (REST, incremental `syncToken`, OAuth refresh) stay private
//! behind [`GoogleInternalWire`], so the same engine-level orchestration that
//! drives CalDAV drives this provider with no second sync implementation.

use super::connectors::{
    CalendarConnectorError, CalendarRemoteTransport, RemoteSyncBatch, RemoteWriteReceipt,
    RemoteWriteRequest,
};

/// Provider key stamped on this transport's receipts and attempt kinds.
pub const GOOGLE_INTERNAL_PROVIDER_KEY: &str = "google_internal";

/// Custody-name prefix that marks a `secret_ref` as provisioned for the
/// Workspace-Internal dogfood class.
pub const GOOGLE_INTERNAL_SECRET_REF_PREFIX: &str = "google-internal:";

/// Whether a custody name belongs to the Workspace-Internal dogfood class.
#[must_use]
pub fn is_workspace_internal_secret_ref(secret_ref: &str) -> bool {
    secret_ref.starts_with(GOOGLE_INTERNAL_SECRET_REF_PREFIX)
}

/// The Google protocol seam.
///
/// Implementations own the REST calls, the incremental sync token, and the
/// internal OAuth read. No library type crosses these signatures, and no method
/// is handed a credential.
pub trait GoogleInternalWire {
    /// Lists the changes after `sync_token` for the seat's own calendar.
    ///
    /// # Errors
    ///
    /// [`CalendarConnectorError::Transport`] for provider failures and
    /// [`CalendarConnectorError::CredentialUnavailable`] when custody refuses.
    fn list_changes(
        &self,
        secret_ref: &str,
        calendar_ref: &str,
        sync_token: Option<&str>,
    ) -> Result<RemoteSyncBatch, CalendarConnectorError>;

    /// Conditionally stores one event, preserving its UID.
    ///
    /// # Errors
    ///
    /// [`CalendarConnectorError::EtagMismatch`] when the precondition fails,
    /// plus the transport/custody variants.
    fn upsert_event(
        &self,
        secret_ref: &str,
        calendar_ref: &str,
        request: &RemoteWriteRequest,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError>;

    /// Conditionally removes one event.
    ///
    /// # Errors
    ///
    /// Same contract as [`Self::upsert_event`].
    fn delete_event(
        &self,
        secret_ref: &str,
        calendar_ref: &str,
        href: &str,
        expected_etag: Option<&str>,
        uid: &str,
        sequence: u32,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError>;
}

/// The Workspace-Internal transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoogleInternalConnector<W> {
    wire: W,
}

impl<W> GoogleInternalConnector<W> {
    /// Binds the connector to one wire implementation.
    pub const fn new(wire: W) -> Self {
        Self { wire }
    }

    /// The wire this connector calls.
    pub const fn wire(&self) -> &W {
        &self.wire
    }

    /// Refuses any `secret_ref` outside the internal dogfood class before a
    /// single byte of provider I/O happens.
    fn guard_internal_class(secret_ref: &str) -> Result<(), CalendarConnectorError> {
        if is_workspace_internal_secret_ref(secret_ref) {
            return Ok(());
        }
        Err(CalendarConnectorError::CredentialUnavailable {
            secret_ref: secret_ref.to_owned(),
        })
    }
}

impl<W: GoogleInternalWire> CalendarRemoteTransport for GoogleInternalConnector<W> {
    fn provider_key(&self) -> &'static str {
        GOOGLE_INTERNAL_PROVIDER_KEY
    }

    fn pull(
        &self,
        secret_ref: &str,
        calendar_ref: &str,
        cursor: Option<&str>,
    ) -> Result<RemoteSyncBatch, CalendarConnectorError> {
        Self::guard_internal_class(secret_ref)?;
        self.wire.list_changes(secret_ref, calendar_ref, cursor)
    }

    fn upsert(
        &self,
        secret_ref: &str,
        calendar_ref: &str,
        request: &RemoteWriteRequest,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
        Self::guard_internal_class(secret_ref)?;
        self.wire.upsert_event(secret_ref, calendar_ref, request)
    }

    fn delete(
        &self,
        secret_ref: &str,
        calendar_ref: &str,
        href: &str,
        expected_etag: Option<&str>,
        uid: &str,
        sequence: u32,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
        Self::guard_internal_class(secret_ref)?;
        self.wire
            .delete_event(secret_ref, calendar_ref, href, expected_etag, uid, sequence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_internal_custody_names_select_this_capability() {
        assert!(is_workspace_internal_secret_ref("google-internal:dogfood"));
        assert!(!is_workspace_internal_secret_ref("google-byo:someone-else"));
        assert!(matches!(
            GoogleInternalConnector::<()>::guard_internal_class("google-byo:someone-else"),
            Err(CalendarConnectorError::CredentialUnavailable { .. })
        ));
    }
}
