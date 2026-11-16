//! Doors to the calendar's network boundary for CalDAV and the iMIP
//! submission (FIX [CALDAV-SEAL-SKIP-HOSTED-EGRESS]): the CalDAV wire's
//! endpoint and client, the iMIP send's endpoint admission and submission
//! client, and one request on each client, with or without a managed node's
//! hosted egress guard. The owner proof, the seat row and the credential the
//! real wire and send also need are left out: they decide nothing about where
//! a request may go.

use std::sync::Arc;

use oneiron::web_fetch::HostedEgressGuard;

/// What the iMIP send runs on the installed submission endpoint before it
/// sends.
///
/// # Errors
///
/// The refusal a managed node gives a private or node address.
pub fn admit_calendar_endpoint(
    egress: Option<Arc<HostedEgressGuard>>,
    endpoint: &str,
) -> Result<(), String> {
    crate::calendar_host::admit_calendar_endpoint(endpoint, egress.as_deref())
        .map_err(str::to_owned)
}

/// Builds the CalDAV wire's endpoint and client as `HttpCalDav::new` does
/// and, when they build, sends one depth-0 PROPFIND to the endpoint: `Ok`
/// with the server's status.
///
/// # Errors
///
/// The wire's refusal, or `CalDAV request failed` when the request does not
/// complete.
pub fn caldav_propfind(
    egress: Option<Arc<HostedEgressGuard>>,
    endpoint: &str,
) -> Result<u16, String> {
    let (base, client) = crate::calendar_host::caldav_endpoint_client(endpoint, egress)
        .map_err(|error| error.to_string())?;
    let method =
        reqwest::Method::from_bytes(b"PROPFIND").map_err(|_| "invalid method".to_owned())?;
    client
        .request(method, base)
        .header("Depth", "0")
        .send()
        .map(|response| response.status().as_u16())
        .map_err(|_| "CalDAV request failed".to_owned())
}

/// Admits the submission endpoint as the iMIP send does before it sends,
/// then POSTs one message on the submission client `CalendarSendClients::new`
/// builds: `Ok` with the service's status.
///
/// # Errors
///
/// The admission's refusal, or `iMIP submission failed` when the request
/// does not complete.
pub fn imip_post(egress: Option<Arc<HostedEgressGuard>>, endpoint: &str) -> Result<u16, String> {
    crate::calendar_host::admit_calendar_endpoint(endpoint, egress.as_deref())
        .map_err(str::to_owned)?;
    let clients = crate::calendar_host::CalendarSendClients::new(egress)
        .map_err(|_| "calendar send client unavailable".to_owned())?;
    clients
        .submission_client()
        .post(endpoint)
        .header(reqwest::header::CONTENT_TYPE, "message/rfc822")
        .body("Subject: Calendar invitation\r\n\r\n")
        .send()
        .map(|response| response.status().as_u16())
        .map_err(|_| "iMIP submission failed".to_owned())
}
