//! CalDAV provider adapter (CAL-05, ONE-1787).
//!
//! One client for the whole iCloud / Fastmail / Radicale class of servers. The
//! shape is RFC 4791 as those servers actually implement it:
//!
//! 1. **Discovery** — current-user-principal → calendar-home-set → the
//!    collection the seat's `calendar_ref` selects ([`CalDavDiscovery`]).
//! 2. **Incremental pull** — `sync-collection` with the seat's sync token; the
//!    server answers with changed/removed resources and the next token.
//! 3. **Conditional writes** — `PUT`/`DELETE` carrying `If-Match` built from the
//!    expected ETag. A `412` (or any precondition-failed response) becomes
//!    [`CalendarConnectorError::EtagMismatch`] so the outbox reconciles; it is
//!    never retried unconditionally and never falls back to an unconditional
//!    write.
//!
//! Everything protocol-shaped stays behind [`CalDavWire`]. HTTP, XML, WebDAV,
//! and the app-password custody read live in the host's wire implementation, so
//! this module — and the orchestration above it — is deterministic and offline
//! in tests. Nothing here receives a credential: the seat hands the wire a
//! SECRET custody `secret_ref`, and the wire resolves it at its own egress door
//! (the same custody path [`super::ingest::CustodyDoorIcsFeedFetcher`] uses, and
//! the same SECRET-02 swap point).

use super::connectors::{
    CalendarConnectorError, CalendarRemoteTransport, RemoteSyncBatch, RemoteWriteReceipt,
    RemoteWriteRequest,
};

/// Provider key stamped on this transport's receipts and attempt kinds.
pub const CALDAV_PROVIDER_KEY: &str = "caldav";

/// The three hrefs discovery resolves for one seat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalDavDiscovery {
    /// `current-user-principal`.
    pub principal_href: String,
    /// `calendar-home-set`.
    pub calendar_home_href: String,
    /// The selected calendar collection.
    pub calendar_href: String,
}

/// The CalDAV protocol seam.
///
/// Implementations own the HTTP/XML/auth details and the custody read. No
/// library type crosses these signatures, and no method is handed a credential.
pub trait CalDavWire {
    /// Resolves principal → calendar home → collection for `calendar_ref`.
    ///
    /// # Errors
    ///
    /// [`CalendarConnectorError::Transport`] for protocol failures and
    /// [`CalendarConnectorError::CredentialUnavailable`] when custody refuses.
    fn discover(
        &self,
        secret_ref: &str,
        calendar_ref: &str,
    ) -> Result<CalDavDiscovery, CalendarConnectorError>;

    /// Runs one `sync-collection` report from `sync_token`.
    ///
    /// # Errors
    ///
    /// Same contract as [`Self::discover`].
    fn sync_collection(
        &self,
        secret_ref: &str,
        discovery: &CalDavDiscovery,
        sync_token: Option<&str>,
    ) -> Result<RemoteSyncBatch, CalendarConnectorError>;

    /// `PUT`s one VEVENT resource, sending `If-Match` from
    /// [`RemoteWriteRequest::expected_etag`].
    ///
    /// # Errors
    ///
    /// [`CalendarConnectorError::EtagMismatch`] when the precondition fails,
    /// plus the transport/custody variants.
    fn put_vevent(
        &self,
        secret_ref: &str,
        discovery: &CalDavDiscovery,
        request: &RemoteWriteRequest,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError>;

    /// `DELETE`s one VEVENT resource, sending `If-Match` from `expected_etag`.
    ///
    /// # Errors
    ///
    /// Same contract as [`Self::put_vevent`].
    fn delete_vevent(
        &self,
        secret_ref: &str,
        discovery: &CalDavDiscovery,
        href: &str,
        expected_etag: Option<&str>,
        uid: &str,
        sequence: u32,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError>;
}

/// The CalDAV transport: one wire, every server in the class.
///
/// Provider differences (iCloud's principal layout, Fastmail's ETag format,
/// Radicale's collection paths) live inside the wire. The engine model carries
/// no provider-specific credential or configuration field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalDavConnector<W> {
    wire: W,
}

impl<W> CalDavConnector<W> {
    /// Binds the connector to one wire implementation.
    pub const fn new(wire: W) -> Self {
        Self { wire }
    }

    /// The wire this connector calls.
    pub const fn wire(&self) -> &W {
        &self.wire
    }
}

impl<W: CalDavWire> CalDavConnector<W> {
    /// Resolves this seat's collection.
    ///
    /// # Errors
    ///
    /// Whatever [`CalDavWire::discover`] returns.
    pub fn discover(
        &self,
        secret_ref: &str,
        calendar_ref: &str,
    ) -> Result<CalDavDiscovery, CalendarConnectorError> {
        self.wire.discover(secret_ref, calendar_ref)
    }
}

impl<W: CalDavWire> CalendarRemoteTransport for CalDavConnector<W> {
    fn provider_key(&self) -> &'static str {
        CALDAV_PROVIDER_KEY
    }

    fn pull(
        &self,
        secret_ref: &str,
        calendar_ref: &str,
        cursor: Option<&str>,
    ) -> Result<RemoteSyncBatch, CalendarConnectorError> {
        let discovery = self.wire.discover(secret_ref, calendar_ref)?;
        self.wire.sync_collection(secret_ref, &discovery, cursor)
    }

    fn upsert(
        &self,
        secret_ref: &str,
        calendar_ref: &str,
        request: &RemoteWriteRequest,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
        let discovery = self.wire.discover(secret_ref, calendar_ref)?;
        // `If-Match` rides inside the request: a mismatch surfaces as
        // `EtagMismatch` for the outbox, never as an unconditional PUT.
        self.wire.put_vevent(secret_ref, &discovery, request)
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
        let discovery = self.wire.discover(secret_ref, calendar_ref)?;
        self.wire
            .delete_vevent(secret_ref, &discovery, href, expected_etag, uid, sequence)
    }
}

/// Maps a CalDAV write response status onto the precondition verdict.
///
/// `412 Precondition Failed` (and the `409`/`428` conditional family servers in
/// this class also emit) means the resource moved under us: the caller
/// reconciles from its outbox row. Any other non-2xx is a plain transport
/// failure. Returns `None` for a success status so wires can use this as their
/// single status classifier.
#[must_use]
pub fn caldav_write_status_error(
    status: u16,
    operation: &'static str,
    href: &str,
    expected: Option<&str>,
    actual: Option<&str>,
) -> Option<CalendarConnectorError> {
    match status {
        200..=299 => None,
        409 | 412 | 428 => Some(CalendarConnectorError::EtagMismatch {
            href: href.to_owned(),
            expected: expected.map(str::to_owned),
            actual: actual.map(str::to_owned),
        }),
        other => Some(CalendarConnectorError::Transport {
            provider: CALDAV_PROVIDER_KEY,
            operation,
            detail: format!("provider returned HTTP {other}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precondition_statuses_reconcile_and_others_are_transport_failures() {
        assert!(caldav_write_status_error(204, "put", "/c/1.ics", None, None).is_none());
        assert!(matches!(
            caldav_write_status_error(412, "put", "/c/1.ics", Some("v1"), Some("v2")),
            Some(CalendarConnectorError::EtagMismatch { .. })
        ));
        assert!(matches!(
            caldav_write_status_error(503, "put", "/c/1.ics", None, None),
            Some(CalendarConnectorError::Transport { .. })
        ));
    }
}
