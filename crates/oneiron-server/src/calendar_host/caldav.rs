//! Real CalDAV discovery, sync-collection and conditional resource writes.
use std::collections::BTreeSet;
use std::io::Read;
use std::sync::Arc;

use oneiron::Vault;
use oneiron::calendar::connectors::door::{
    CalendarConnectorOperation, CalendarConnectorRegistration,
};
use oneiron::calendar::{
    CalDavDiscovery, CalDavWire, CalendarConnectorError, RemoteCalendarChange,
    RemoteCalendarObject, RemoteSyncBatch, RemoteWriteReceipt, RemoteWriteRequest,
    caldav_write_status_error, parse_ics_feed,
};
use oneiron::consent::AuthenticatedOwner;
use reqwest::blocking::{Client, Response};
use reqwest::{Method, Url};

use super::xml::{self, CAL, DAV, Node};

const MAX_RESPONSE: u64 = 16 * 1024 * 1024;

pub(crate) struct HttpCalDav {
    vault: Arc<Vault>,
    operation: CalendarConnectorOperation,
    row: CalendarConnectorRegistration,
    client: Client,
    base: Url,
}

fn failure(operation: &'static str, detail: impl Into<String>) -> CalendarConnectorError {
    CalendarConnectorError::Transport {
        provider: "caldav",
        operation,
        detail: detail.into(),
    }
}

impl HttpCalDav {
    pub(crate) fn new(
        vault: Arc<Vault>,
        owner: AuthenticatedOwner,
        row: CalendarConnectorRegistration,
    ) -> Result<Self, CalendarConnectorError> {
        let base =
            Url::parse(&row.endpoint).map_err(|_| failure("configure", "invalid endpoint"))?;
        let client =
            super::client().map_err(|_| failure("configure", "HTTP client unavailable"))?;
        let operation =
            CalendarConnectorOperation::new(&vault, owner, row.clone()).map_err(|_| {
                CalendarConnectorError::CredentialUnavailable {
                    secret_ref: row.seat.config.secret_ref.clone(),
                }
            })?;
        Ok(Self {
            vault,
            operation,
            row,
            client,
            base,
        })
    }

    fn url(&self, href: &str) -> Result<Url, CalendarConnectorError> {
        let url = self
            .base
            .join(href)
            .map_err(|_| failure("href", "invalid DAV href"))?;
        if url.origin() != self.base.origin()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(failure("href", "DAV href leaves the installed origin"));
        }
        Ok(url)
    }

    pub(crate) fn operation(&self) -> &CalendarConnectorOperation {
        &self.operation
    }

    fn with_credential<T>(
        &self,
        apply: impl FnOnce(&[u8]) -> Result<T, CalendarConnectorError>,
    ) -> Result<T, CalendarConnectorError> {
        let effector = format!("calendar.caldav:{}", self.row.seat.config.seat_ref);
        let mut apply = Some(apply);
        let mut outcome = None;
        let result = self.vault.inject_secret_at_door(
            &self.row.seat.config.secret_ref,
            &effector,
            &mut |credential: &[u8]| {
                self.operation.revalidate(&self.vault)?;
                outcome = Some(apply.take().expect("one credential application")(
                    credential,
                ));
                Ok(())
            },
        );
        if let Some(outcome) = outcome {
            return outcome;
        }
        result.map_err(|_| CalendarConnectorError::CredentialUnavailable {
            secret_ref: self.row.seat.config.secret_ref.clone(),
        })?;
        Err(failure("request", "credential door did not send"))
    }

    fn send(
        &self,
        credential: &[u8],
        method: Method,
        url: Url,
        body: Vec<u8>,
        content_type: &str,
        expected: Option<&str>,
        create: bool,
        depth: Option<&'static str>,
    ) -> Result<Response, CalendarConnectorError> {
        let auth = super::authorization(credential).map_err(|_| {
            CalendarConnectorError::CredentialUnavailable {
                secret_ref: self.row.seat.config.secret_ref.clone(),
            }
        })?;
        let mut request = self
            .client
            .request(method, url)
            .header(reqwest::header::AUTHORIZATION, auth)
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .body(body);
        if let Some(depth) = depth {
            request = request.header("Depth", depth);
        }
        if let Some(etag) = expected {
            request = request.header(reqwest::header::IF_MATCH, etag);
        }
        if create {
            request = request.header(reqwest::header::IF_NONE_MATCH, "*");
        }
        request
            .send()
            .map_err(|_| failure("request", "CalDAV request failed"))
    }

    fn request(
        &self,
        method: Method,
        href: &str,
        body: Vec<u8>,
        content_type: &str,
        expected: Option<&str>,
        create: bool,
        depth: Option<&'static str>,
    ) -> Result<Response, CalendarConnectorError> {
        self.with_credential(|credential| {
            let url = self.url(href)?;
            self.send(
                credential,
                method,
                url,
                body,
                content_type,
                expected,
                create,
                depth,
            )
        })
    }

    fn report(
        &self,
        href: &str,
        method: &str,
        body: String,
    ) -> Result<Node, CalendarConnectorError> {
        let response = self.request(
            Method::from_bytes(method.as_bytes())
                .map_err(|_| failure("method", "invalid method"))?,
            href,
            body.into_bytes(),
            "application/xml; charset=utf-8",
            None,
            false,
            Some("1"),
        )?;
        if response.status().as_u16() != 207 {
            return Err(failure(
                "report",
                format!("CalDAV returned HTTP {}", response.status().as_u16()),
            ));
        }
        multistatus(response, "report")
    }

    /// GETs the calendar resource at `href`: its bytes and ETag, or `None`
    /// when the server answers that it is gone (404 or 410). Any other
    /// failure is an error.
    fn read_calendar_resource(
        &self,
        href: &str,
    ) -> Result<Option<CalendarResource>, CalendarConnectorError> {
        let response = self.request(
            Method::GET,
            href,
            Vec::new(),
            "text/calendar",
            None,
            false,
            None,
        )?;
        if matches!(response.status().as_u16(), 404 | 410) {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(failure("sync", "calendar resource unreadable"));
        }
        let etag = response
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let mut ics = Vec::new();
        response
            .take(MAX_RESPONSE + 1)
            .read_to_end(&mut ics)
            .map_err(|_| failure("sync", "calendar resource unreadable"))?;
        if ics.len() as u64 > MAX_RESPONSE {
            return Err(failure("sync", "calendar resource too large"));
        }
        Ok(Some(CalendarResource { ics, etag }))
    }

    fn property_href(
        &self,
        href: &str,
        property: &str,
        ns: &str,
    ) -> Result<String, CalendarConnectorError> {
        let body = format!(
            "<d:propfind xmlns:d=\"DAV:\" xmlns:c=\"{CAL}\"><d:prop><{property}/></d:prop></d:propfind>"
        );
        let document = self.report(href, "PROPFIND", body)?;
        let local = property.split(':').next_back().unwrap_or(property);
        let value = document
            .children(DAV, "response")
            .find_map(|r| r.property(ns, local)?.child(DAV, "href"))
            .map(|n| n.text.trim().to_owned())
            .ok_or_else(|| failure("discover", "required DAV property absent"))?;
        Ok(self.url(&value)?.to_string())
    }

    fn receipt(
        &self,
        response: Response,
        href: String,
        uid: &str,
        sequence: u32,
        hash: [u8; 32],
        expected: Option<&str>,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
        let etag = response
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        if let Some(error) = caldav_write_status_error(
            response.status().as_u16(),
            "write",
            &href,
            expected,
            etag.as_deref(),
        ) {
            return Err(error);
        }
        Ok(RemoteWriteReceipt {
            href,
            etag,
            uid: uid.to_owned(),
            sequence,
            content_hash: hash,
        })
    }
}

impl CalDavWire for HttpCalDav {
    fn discover(
        &self,
        _secret_ref: &str,
        calendar_ref: &str,
    ) -> Result<CalDavDiscovery, CalendarConnectorError> {
        let principal_href =
            self.property_href(self.base.as_str(), "d:current-user-principal", DAV)?;
        let calendar_home_href = self.property_href(&principal_href, "c:calendar-home-set", CAL)?;
        let document = self.report(&calendar_home_href, "PROPFIND", format!("<d:propfind xmlns:d=\"DAV:\" xmlns:c=\"{CAL}\"><d:prop><d:resourcetype/><d:displayname/></d:prop></d:propfind>"))?;
        let selected = document
            .children(DAV, "response")
            .filter(|row| {
                row.property(DAV, "resourcetype")
                    .and_then(|n| n.child(CAL, "calendar"))
                    .is_some()
            })
            .find_map(|row| {
                let href = row.child(DAV, "href")?.text.trim();
                let url = self.url(href).ok()?;
                let name = row.property(DAV, "displayname").map(|n| n.text.as_str());
                (calendar_ref == href || calendar_ref == url.as_str() || Some(calendar_ref) == name)
                    .then(|| url.to_string())
            })
            .ok_or_else(|| failure("discover", "configured calendar collection absent"))?;
        Ok(CalDavDiscovery {
            principal_href,
            calendar_home_href,
            calendar_href: selected,
        })
    }

    fn collection_timezone(
        &self,
        _secret_ref: &str,
        discovery: &CalDavDiscovery,
    ) -> Result<Option<String>, CalendarConnectorError> {
        // Depth 0: the selected collection's own properties, not its
        // members'. The zone is optional metadata (fix list row 19192): a
        // server that refuses or lacks it names none, and the sync goes on.
        let response = self.request(
            Method::from_bytes(b"PROPFIND").map_err(|_| failure("method", "invalid method"))?,
            &discovery.calendar_href,
            format!("<d:propfind xmlns:d=\"DAV:\" xmlns:c=\"{CAL}\"><d:prop><c:calendar-timezone-id/><c:calendar-timezone/></d:prop></d:propfind>").into_bytes(),
            "application/xml; charset=utf-8",
            None,
            false,
            Some("0"),
        )?;
        match response.status().as_u16() {
            207 => {}
            403 | 404 => return Ok(None),
            status => {
                return Err(failure(
                    "timezone",
                    format!("CalDAV returned HTTP {status}"),
                ));
            }
        }
        let document = multistatus(response, "timezone")?;
        Ok(oneiron::calendar::caldav_collection_timezone(
            collection_property(&document, "calendar-timezone-id"),
            collection_property(&document, "calendar-timezone"),
        ))
    }

    fn sync_collection(
        &self,
        _secret_ref: &str,
        discovery: &CalDavDiscovery,
        sync_token: Option<&str>,
    ) -> Result<RemoteSyncBatch, CalendarConnectorError> {
        // An empty token lists every member and no removed one (RFC 6578
        // §3.4), so what this seat holds that the listing omits was removed
        // (fix list row 19192). Its rows are read before the listing: a row
        // a write makes during it is no member, and one a write changes
        // during it fails the omission's admission.
        let full_listing = sync_token.is_none_or(str::is_empty);
        let members = if full_listing {
            oneiron::calendar::connectors::calendar_collection_members_for_operation(
                &self.vault,
                &self.operation,
            )?
        } else {
            Vec::new()
        };
        let token = xml::escape(sync_token.unwrap_or_default());
        let document = self.report(&discovery.calendar_href, "REPORT", format!("<d:sync-collection xmlns:d=\"DAV:\" xmlns:c=\"{CAL}\"><d:sync-token>{token}</d:sync-token><d:sync-level>1</d:sync-level><d:prop><d:getetag/><c:calendar-data/></d:prop></d:sync-collection>"))?;
        let cursor = document
            .child(DAV, "sync-token")
            .map(|n| n.text.trim().to_owned())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| failure("sync", "DAV sync token absent"))?;
        let mut changes = Vec::new();
        let mut listed_hrefs = BTreeSet::new();
        let mut listed_uids = BTreeSet::new();
        for row in document.children(DAV, "response") {
            let href = row
                .child(DAV, "href")
                .map(|n| n.text.trim())
                .ok_or_else(|| failure("sync", "resource href absent"))?;
            let href = self.url(href)?.to_string();
            let status = row
                .child(DAV, "status")
                .and_then(|n| n.text.split_whitespace().nth(1));
            if status == Some("507") {
                // The server truncated the listing (RFC 6578 §3.6). A delta
                // resumes from the token it returned; a full listing that
                // is not whole proves no omission, so it is no checkpoint.
                if full_listing {
                    return Err(failure("sync", "the full DAV listing was truncated"));
                }
                continue;
            }
            listed_hrefs.insert(href.clone());
            if matches!(status, Some("404" | "410")) {
                if let Some(uid) =
                    oneiron::calendar::connectors::calendar_remote_uid_for_href_for_operation(
                        &self.vault,
                        &self.operation,
                        &href,
                    )?
                {
                    listed_uids.insert(uid.clone());
                    changes.push(RemoteCalendarChange::Delete { href, uid });
                }
                continue;
            }
            let etag = row.property(DAV, "getetag").map(|n| n.text.clone());
            let ics = match row.property(CAL, "calendar-data") {
                Some(data) => data.text.as_bytes().to_vec(),
                None => {
                    self.read_calendar_resource(&href)?
                        .ok_or_else(|| failure("sync", "calendar resource unreadable"))?
                        .ics
                }
            };
            let change = upsert_change(href, etag, ics)?;
            listed_uids.insert(change.uid().to_owned());
            changes.push(change);
        }
        for member in members {
            // A stored href that no longer resolves inside the installed
            // origin cannot be compared with the listing; it is left alone.
            let Ok(url) = self.url(&member.href) else {
                continue;
            };
            let href = url.to_string();
            if listed_hrefs.contains(&href) || listed_uids.contains(&member.uid) {
                continue;
            }
            // A write settled content the archive does not hold, so the
            // listing may predate it: the resource is read back first, and
            // only a gone answer makes the omission.
            if !member.read_observed
                && let Some(resource) = self.read_calendar_resource(&href)?
            {
                changes.push(upsert_change(href, resource.etag, resource.ics)?);
                continue;
            }
            changes.push(RemoteCalendarChange::Omitted {
                href,
                uid: member.uid,
                observation: member.observation,
            });
        }
        Ok(RemoteSyncBatch {
            next_cursor: Some(cursor),
            changes,
        })
    }

    fn put_vevent(
        &self,
        _secret_ref: &str,
        discovery: &CalDavDiscovery,
        request: &RemoteWriteRequest,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
        self.with_credential(|credential| {
            let href = match &request.href {
                Some(href) => {
                    if request.expected_etag.is_none() {
                        return Err(failure("write", "existing resource has no ETag"));
                    }
                    self.url(href)?
                }
                None => {
                    let mut url = self.url(&discovery.calendar_href)?;
                    let filename = format!("{}.ics", blake3::hash(request.uid.as_bytes()).to_hex());
                    url.path_segments_mut()
                        .map_err(|_| failure("write", "invalid calendar collection"))?
                        .pop_if_empty()
                        .push(&filename);
                    url
                }
            };
            let feed = parse_ics_feed(&request.ics)?;
            let hash = feed
                .events
                .first()
                .ok_or_else(|| failure("write", "resource has no VEVENT"))?
                .content_hash;
            let response = self.send(
                credential,
                Method::PUT,
                href.clone(),
                request.ics.clone(),
                "text/calendar; charset=utf-8",
                request.expected_etag.as_deref(),
                request.href.is_none(),
                None,
            )?;
            self.receipt(
                response,
                href.to_string(),
                &request.uid,
                request.sequence,
                hash,
                request.expected_etag.as_deref(),
            )
        })
    }

    fn delete_vevent(
        &self,
        _secret_ref: &str,
        _discovery: &CalDavDiscovery,
        href: &str,
        expected_etag: Option<&str>,
        uid: &str,
        sequence: u32,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
        self.with_credential(|credential| {
            let expected =
                expected_etag.ok_or_else(|| failure("delete", "delete requires an ETag"))?;
            let url = self.url(href)?;
            let href = url.to_string();
            let response = self.send(
                credential,
                Method::DELETE,
                url,
                Vec::new(),
                "text/calendar",
                Some(expected),
                false,
                None,
            )?;
            self.receipt(response, href, uid, sequence, [0; 32], Some(expected))
        })
    }
}

/// One calendar resource a GET read.
struct CalendarResource {
    ics: Vec<u8>,
    etag: Option<String>,
}

/// Reads one multistatus body, bounded like every DAV response.
fn multistatus(
    response: Response,
    operation: &'static str,
) -> Result<Node, CalendarConnectorError> {
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| failure(operation, "DAV response unreadable"))?;
    if bytes.len() as u64 > MAX_RESPONSE {
        return Err(failure(operation, "DAV response too large"));
    }
    xml::parse(&bytes).map_err(|error| failure(operation, error))
}

/// The text of the CalDAV property `name` a Depth 0 multistatus carries in a
/// successful propstat; a failed propstat carries none.
fn collection_property<'d>(document: &'d Node, name: &str) -> Option<&'d str> {
    document
        .children(DAV, "response")
        .find_map(|row| row.property(CAL, name))
        .map(|node| node.text.as_str())
}

/// The upsert one read of the resource at `href` returns.
fn upsert_change(
    href: String,
    etag: Option<String>,
    ics: Vec<u8>,
) -> Result<RemoteCalendarChange, CalendarConnectorError> {
    let feed = parse_ics_feed(&ics)?;
    let event = feed
        .events
        .first()
        .ok_or_else(|| failure("sync", "calendar resource has no VEVENT"))?;
    Ok(RemoteCalendarChange::Upsert(RemoteCalendarObject {
        href,
        etag,
        uid: event.uid.clone(),
        sequence: event.sequence,
        content_hash: event.content_hash,
        ics,
    }))
}
