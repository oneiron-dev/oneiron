//! Real CalDAV discovery, sync-collection and conditional resource writes.
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
        self.report_at(href, method, body, "1")
    }

    /// [`Self::report`] at `depth`: `0` reads the resource itself alone.
    fn report_at(
        &self,
        href: &str,
        method: &str,
        body: String,
        depth: &'static str,
    ) -> Result<Node, CalendarConnectorError> {
        let response = self.request(
            Method::from_bytes(method.as_bytes())
                .map_err(|_| failure("method", "invalid method"))?,
            href,
            body.into_bytes(),
            "application/xml; charset=utf-8",
            None,
            false,
            Some(depth),
        )?;
        if response.status().as_u16() != 207 {
            return Err(failure(
                "report",
                format!("CalDAV returned HTTP {}", response.status().as_u16()),
            ));
        }
        let mut bytes = Vec::new();
        response
            .take(MAX_RESPONSE + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| failure("report", "DAV response unreadable"))?;
        if bytes.len() as u64 > MAX_RESPONSE {
            return Err(failure("report", "DAV response too large"));
        }
        xml::parse(&bytes).map_err(|error| failure("report", error))
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

    /// The zone the calendar collection at `calendar_href` names its own
    /// (`CALDAV:calendar-timezone`): its VTIMEZONE's `TZID` (fix list row
    /// 17868). `None` when it names none, or a name that is not a plain zone
    /// name.
    fn collection_zone(
        &self,
        calendar_href: &str,
    ) -> Result<Option<String>, CalendarConnectorError> {
        let document = self.report_at(
            calendar_href,
            "PROPFIND",
            format!(
                "<d:propfind xmlns:d=\"DAV:\" xmlns:c=\"{CAL}\"><d:prop><c:calendar-timezone/></d:prop></d:propfind>"
            ),
            "0",
        )?;
        Ok(document
            .children(DAV, "response")
            .find_map(|row| row.property(CAL, "calendar-timezone"))
            .and_then(|zone| vtimezone_tzid(&zone.text)))
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

    fn sync_collection(
        &self,
        _secret_ref: &str,
        discovery: &CalDavDiscovery,
        sync_token: Option<&str>,
    ) -> Result<RemoteSyncBatch, CalendarConnectorError> {
        // The collection's zone places its all-day days and heads each of
        // its resources (fix list row 17868). A zone other than the one the
        // token's sync wrote leaves those resources on the old one: the
        // collection is read again whole, so every all-day event takes it.
        let zone = self.collection_zone(&discovery.calendar_href)?;
        let (written_zone, written_token) = sync_token.map_or((None, None), read_cursor);
        let sync_token = written_token.filter(|_| written_zone == zone.as_deref());
        let token = xml::escape(sync_token.unwrap_or_default());
        let document = self.report(&discovery.calendar_href, "REPORT", format!("<d:sync-collection xmlns:d=\"DAV:\" xmlns:c=\"{CAL}\"><d:sync-token>{token}</d:sync-token><d:sync-level>1</d:sync-level><d:prop><d:getetag/><c:calendar-data/></d:prop></d:sync-collection>"))?;
        let cursor = document
            .child(DAV, "sync-token")
            .map(|n| n.text.trim().to_owned())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| failure("sync", "DAV sync token absent"))?;
        let mut changes = Vec::new();
        for row in document.children(DAV, "response") {
            let href = row
                .child(DAV, "href")
                .map(|n| n.text.trim())
                .ok_or_else(|| failure("sync", "resource href absent"))?;
            let href = self.url(href)?.to_string();
            let deleted = row
                .child(DAV, "status")
                .is_some_and(|n| matches!(n.text.split_whitespace().nth(1), Some("404" | "410")));
            if deleted {
                if let Some(uid) =
                    oneiron::calendar::connectors::calendar_remote_uid_for_href_for_operation(
                        &self.vault,
                        &self.operation,
                        &href,
                    )?
                {
                    changes.push(RemoteCalendarChange::Delete { href, uid });
                }
                continue;
            }
            let ics = match row.property(CAL, "calendar-data") {
                Some(data) => data.text.as_bytes().to_vec(),
                None => {
                    let response = self.request(
                        Method::GET,
                        &href,
                        Vec::new(),
                        "text/calendar",
                        None,
                        false,
                        None,
                    )?;
                    if !response.status().is_success() {
                        return Err(failure("sync", "calendar resource unreadable"));
                    }
                    let mut bytes = Vec::new();
                    response
                        .take(MAX_RESPONSE + 1)
                        .read_to_end(&mut bytes)
                        .map_err(|_| failure("sync", "calendar resource unreadable"))?;
                    if bytes.len() as u64 > MAX_RESPONSE {
                        return Err(failure("sync", "calendar resource too large"));
                    }
                    bytes
                }
            };
            let ics = with_calendar_zone(ics, zone.as_deref());
            let feed = parse_ics_feed(&ics)?;
            let event = feed
                .events
                .first()
                .ok_or_else(|| failure("sync", "calendar resource has no VEVENT"))?;
            changes.push(RemoteCalendarChange::Upsert(RemoteCalendarObject {
                href,
                etag: row.property(DAV, "getetag").map(|n| n.text.clone()),
                uid: event.uid.clone(),
                sequence: event.sequence,
                content_hash: event.content_hash,
                ics,
            }));
        }
        Ok(RemoteSyncBatch {
            next_cursor: Some(write_cursor(zone.as_deref(), &cursor)),
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

/// The longest collection zone name read.
const MAX_ZONE_BYTES: usize = 64;

/// What a cursor this host wrote names before its DAV sync token: the zone
/// the sync wrote into its resources.
const ZONED_CURSOR: &str = "oneiron-zone:";

/// The zone and DAV sync token a cursor holds. A cursor that names no zone
/// is the token alone.
fn read_cursor(cursor: &str) -> (Option<&str>, Option<&str>) {
    match cursor
        .strip_prefix(ZONED_CURSOR)
        .and_then(|rest| rest.split_once('\n'))
    {
        Some((zone, token)) => (Some(zone), Some(token)),
        None => (None, Some(cursor)),
    }
}

/// The cursor for DAV sync token `token`, naming the zone `zone` its sync
/// wrote into its resources.
fn write_cursor(zone: Option<&str>, token: &str) -> String {
    match zone {
        Some(zone) => format!("{ZONED_CURSOR}{zone}\n{token}"),
        None => token.to_owned(),
    }
}

/// The `TZID` of the VTIMEZONE a `CALDAV:calendar-timezone` value carries,
/// when it is a plain zone name: ASCII letters, digits and `/_+-` only.
fn vtimezone_tzid(calendar: &str) -> Option<String> {
    let unfolded = calendar
        .replace("\r\n ", "")
        .replace("\r\n\t", "")
        .replace("\n ", "")
        .replace("\n\t", "");
    let mut in_zone = false;
    for line in unfolded.lines().map(str::trim) {
        if line.eq_ignore_ascii_case("BEGIN:VTIMEZONE") {
            in_zone = true;
        } else if line.eq_ignore_ascii_case("END:VTIMEZONE") {
            in_zone = false;
        } else if in_zone
            && let Some((name, value)) = line.split_once(':')
            && name
                .split(';')
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case("TZID"))
        {
            let zone = value.trim();
            return (!zone.is_empty()
                && zone.len() <= MAX_ZONE_BYTES
                && zone
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"/_+-".contains(&byte)))
            .then(|| zone.to_owned());
        }
    }
    None
}

/// `ics` headed by the collection's zone as its `X-WR-TIMEZONE`, which
/// places its all-day days (fix list row 17868), unless it names a zone of
/// its own or does not open with `BEGIN:VCALENDAR`.
fn with_calendar_zone(ics: Vec<u8>, zone: Option<&str>) -> Vec<u8> {
    let Some(zone) = zone else {
        return ics;
    };
    let Ok(text) = std::str::from_utf8(&ics) else {
        return ics;
    };
    let names_zone = text.lines().any(|line| {
        line.split([':', ';'])
            .next()
            .is_some_and(|name| name.trim().eq_ignore_ascii_case("X-WR-TIMEZONE"))
    });
    let Some(first) = text.find('\n') else {
        return ics;
    };
    if names_zone || !text[..first].trim().eq_ignore_ascii_case("BEGIN:VCALENDAR") {
        return ics;
    }
    let mut headed = String::with_capacity(text.len() + zone.len() + 17);
    headed.push_str(&text[..=first]);
    headed.push_str("X-WR-TIMEZONE:");
    headed.push_str(zone);
    headed.push_str("\r\n");
    headed.push_str(&text[first + 1..]);
    headed.into_bytes()
}
