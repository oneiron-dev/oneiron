//! The ICS wire of the pack's calendar sources (FIX 12559 row 5;
//! MAIL-PROVIDERS = A): a calendar subscription read whole over HTTPS, its
//! URL (often a secret address) held in custody as the source's
//! credential.
//!
//! Each read takes the URL at the source's credential door
//! ([`Vault::with_source_token_at_door`]), effector
//! `connector:ics_calendar`, and fetches it inside the door callback: the URL
//! never leaves it. HTTPS only (a `webcal://` address reads as `https://`),
//! no redirects, the body bounded. On a managed (hosted) node the host
//! builds the wire with its egress guard
//! ([`HttpIcsCalendarWire::with_hosted_guard`]): an address literal the
//! guard refuses is refused before any connect, and every name resolves
//! through the guard, so an owner-supplied internal address reaches no
//! hosted network. A self-hosted node carries no guard and fetches as
//! before. The response's ETag is the cursor, so an
//! unchanged calendar answers 304 and lands nothing. A complete feed is
//! landed whole: a UID it no longer carries is removed for this source.
//!
//! Call it from a blocking context: `reqwest::blocking` owns its own runtime.

use std::io::Read;
use std::net::IpAddr;
use std::sync::Arc;

use reqwest::StatusCode;
use reqwest::header::{ETAG, IF_NONE_MATCH};

use super::calendar::{MailCalendarFeed, MailCalendarRead, MailCalendarWire};
use super::credential::WireReads;
use super::rest::{self, refused};
use super::source::MailProvider;
use super::wire::MailSyncSource;
use crate::Vault;
use crate::error::{Error, Result};
use crate::web_fetch::{HostedEgressGuard, HostedEgressRefusal};

/// The custody effector an ICS subscription's URL is bound to.
pub const ICS_CALENDAR_CONNECTOR_EFFECTOR: &str = "connector:ics_calendar";

/// The largest calendar feed read.
const MAX_ICS_FEED_BYTES: u64 = 16 * 1024 * 1024;

/// Host-side ICS subscription wire over `reqwest::blocking`.
pub struct HttpIcsCalendarWire<'v> {
    vault: &'v Vault,
    client: reqwest::blocking::Client,
    /// A managed (hosted) node's egress guard; none on a self-hosted node,
    /// which fetches as before.
    guard: Option<Arc<HostedEgressGuard>>,
}

impl<'v> HttpIcsCalendarWire<'v> {
    /// Builds the wire: HTTPS only, no redirects, a 60 s timeout.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when the TLS client cannot be built.
    pub fn new(vault: &'v Vault) -> Result<Self> {
        Self::with_hosted_guard(vault, None)
    }

    /// Builds the wire on a managed (hosted) node, with its egress guard:
    /// an address literal the guard refuses is refused before any connect,
    /// and every name the client connects to resolves through the guard.
    /// With no guard, the wire a self-hosted node fetches with, exactly as
    /// [`Self::new`] builds it.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when the TLS client cannot be built.
    pub fn with_hosted_guard(
        vault: &'v Vault,
        guard: Option<Arc<HostedEgressGuard>>,
    ) -> Result<Self> {
        Ok(Self {
            vault,
            client: rest::https_client_with_hosted_guard(guard.clone())?,
            guard,
        })
    }

    /// Refuses `url` before any connect when this wire carries a hosted
    /// guard: an address literal by its address (a literal reaches no
    /// resolver), and a listed private name at an origin no entry lists.
    /// A named host's addresses are checked by the client's resolver as it
    /// connects. With no guard, every URL is admitted here, as before.
    fn admit_hosted(&self, url: &str) -> Result<()> {
        let Some(guard) = &self.guard else {
            return Ok(());
        };
        let parsed =
            reqwest::Url::parse(url).map_err(|_| refused("ics_calendar_transport_failed"))?;
        let literal = parsed
            .host_str()
            .map(|host| host.trim_start_matches('[').trim_end_matches(']'))
            .and_then(|host| host.parse::<IpAddr>().ok());
        let refusal = match literal {
            Some(address) => guard.refuses(address),
            None => guard.refuses_origin(&parsed),
        };
        match refusal {
            Some(refusal) => Err(refused(refusal.reason())),
            None => Ok(()),
        }
    }

    fn fetch(&self, url: &str, etag: Option<&str>) -> Result<MailCalendarRead> {
        self.admit_hosted(url)?;
        let mut request = self.client.get(url);
        if let Some(etag) = etag {
            request = request.header(IF_NONE_MATCH, etag);
        }
        let response =
            request
                .send()
                .map_err(|error| match HostedEgressRefusal::of_error(&error) {
                    Some(refusal) => refused(refusal.reason()),
                    None => refused("ics_calendar_transport_failed"),
                })?;
        let status = response.status();
        if status == StatusCode::NOT_MODIFIED {
            return Ok(MailCalendarRead::Unchanged);
        }
        if !status.is_success() {
            return Err(Error::InvalidConfig(format!(
                "ics_calendar_status_{}",
                status.as_u16()
            )));
        }
        let next_cursor = response
            .headers()
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty() && value.len() <= 512)
            .map(str::to_owned);
        let mut ics = Vec::new();
        response
            .take(MAX_ICS_FEED_BYTES + 1)
            .read_to_end(&mut ics)
            .map_err(|_| refused("ics_calendar_response_unreadable"))?;
        if ics.len() as u64 > MAX_ICS_FEED_BYTES {
            return Err(refused("ics_calendar_feed_too_large"));
        }
        Ok(MailCalendarRead::Feed(MailCalendarFeed {
            ics,
            next_cursor,
        }))
    }
}

impl MailCalendarWire for HttpIcsCalendarWire<'_> {
    fn pull(&self, source: &MailSyncSource, cursor: Option<&str>) -> Result<MailCalendarRead> {
        if source.provider != MailProvider::Ics {
            return Err(refused("ics_calendar_wire_reads_ics_sources_only"));
        }
        let mut read: Option<MailCalendarRead> = None;
        let _receipt = self.vault.with_source_token_at_door(
            source,
            WireReads::Calendar,
            ICS_CALENDAR_CONNECTOR_EFFECTOR,
            &mut |value: &[u8]| {
                let url = subscription_url(value)?;
                read = Some(self.fetch(&url, cursor)?);
                Ok(())
            },
        )?;
        read.ok_or_else(|| refused("ics_calendar_credential_door_refused"))
    }
}

/// The subscription's HTTPS URL from its custody value: `https://` as is,
/// `webcal://` as `https://`, nothing else.
fn subscription_url(value: &[u8]) -> Result<String> {
    let invalid = || refused("ics_calendar_credential_is_not_an_https_url");
    let text = std::str::from_utf8(value).map_err(|_| invalid())?.trim();
    let url = if let Some(rest) = text.strip_prefix("webcal://") {
        format!("https://{rest}")
    } else if text.starts_with("https://") {
        text.to_owned()
    } else {
        return Err(invalid());
    };
    if url.chars().any(|ch| ch.is_control() || ch.is_whitespace()) {
        return Err(invalid());
    }
    Ok(url)
}
