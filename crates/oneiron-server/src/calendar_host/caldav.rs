//! Real CalDAV discovery, sync-collection and conditional resource writes.
use std::io::Read;
use std::sync::Arc;

use oneiron::calendar::connectors::door::CalendarConnectorRegistration;
use oneiron::calendar::{
    CalDavDiscovery, CalDavWire, CalendarConnectorError, RemoteCalendarChange,
    RemoteCalendarObject, RemoteSyncBatch, RemoteWriteReceipt, RemoteWriteRequest,
    caldav_write_status_error, parse_ics_feed,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::Vault;
use reqwest::blocking::{Client, Response};
use reqwest::{Method, Url};

use super::xml::{self, CAL, DAV, Node};

const MAX_RESPONSE: u64 = 16 * 1024 * 1024;

pub(crate) struct HttpCalDav {
    vault: Arc<Vault>,
    owner: AuthenticatedOwner,
    row: CalendarConnectorRegistration,
    client: Client,
    base: Url,
}

fn failure(operation: &'static str, detail: impl Into<String>) -> CalendarConnectorError {
    CalendarConnectorError::Transport { provider: "caldav", operation, detail: detail.into() }
}

impl HttpCalDav {
    pub(crate) fn new(vault: Arc<Vault>, owner: AuthenticatedOwner, row: CalendarConnectorRegistration) -> Result<Self, CalendarConnectorError> {
        let base = Url::parse(&row.endpoint).map_err(|_| failure("configure", "invalid endpoint"))?;
        let client = super::client().map_err(|_| failure("configure", "HTTP client unavailable"))?;
        Ok(Self { vault, owner, row, client, base })
    }

    fn url(&self, href: &str) -> Result<Url, CalendarConnectorError> {
        let url = self.base.join(href).map_err(|_| failure("href", "invalid DAV href"))?;
        if url.origin() != self.base.origin() || !url.username().is_empty() || url.password().is_some()
            || url.query().is_some() || url.fragment().is_some()
        {
            return Err(failure("href", "DAV href leaves the installed origin"));
        }
        Ok(url)
    }

    fn request(&self, method: Method, href: &str, body: Vec<u8>, content_type: &str, expected: Option<&str>, create: bool, depth: bool) -> Result<Response, CalendarConnectorError> {
        let url = self.url(href)?;
        let effector = format!("calendar.caldav:{}", self.row.seat.config.seat_ref);
        let mut sent = None;
        let result = self.vault.inject_secret_at_door(&self.row.seat.config.secret_ref, &effector, &mut |credential: &[u8]| {
            // Recheck live owner and installed seat after custody admission,
            // immediately before egress; the value door released its writer.
            oneiron::calendar::connectors::door::check_installed_connector(&self.vault, &self.owner, &self.row)?;
            let auth = super::authorization(credential)?;
            let mut request = self.client.request(method.clone(), url.clone())
                .header(reqwest::header::AUTHORIZATION, auth)
                .header(reqwest::header::CONTENT_TYPE, content_type).body(body.clone());
            if depth { request = request.header("Depth", "1"); }
            if let Some(etag) = expected { request = request.header(reqwest::header::IF_MATCH, etag); }
            if create { request = request.header(reqwest::header::IF_NONE_MATCH, "*"); }
            sent = Some(request.send().map_err(|_| failure("request", "CalDAV request failed")));
            Ok(())
        });
        if let Some(sent) = sent { return sent; }
        result.map_err(|_| CalendarConnectorError::CredentialUnavailable { secret_ref: self.row.seat.config.secret_ref.clone() })?;
        Err(failure("request", "credential door did not send"))
    }

    fn report(&self, href: &str, method: &str, body: String) -> Result<Node, CalendarConnectorError> {
        let response = self.request(Method::from_bytes(method.as_bytes()).map_err(|_| failure("method", "invalid method"))?, href, body.into_bytes(), "application/xml; charset=utf-8", None, false, true)?;
        if response.status().as_u16() != 207 { return Err(failure("report", format!("CalDAV returned HTTP {}", response.status().as_u16()))); }
        let mut bytes = Vec::new();
        response.take(MAX_RESPONSE + 1).read_to_end(&mut bytes).map_err(|_| failure("report", "DAV response unreadable"))?;
        if bytes.len() as u64 > MAX_RESPONSE { return Err(failure("report", "DAV response too large")); }
        xml::parse(&bytes).map_err(|error| failure("report", error))
    }

    fn property_href(&self, href: &str, property: &str, ns: &str) -> Result<String, CalendarConnectorError> {
        let body = format!("<d:propfind xmlns:d=\"DAV:\" xmlns:c=\"{CAL}\"><d:prop><{property}/></d:prop></d:propfind>");
        let document = self.report(href, "PROPFIND", body)?;
        let local = property.split(':').next_back().unwrap_or(property);
        let value = document.children(DAV, "response").find_map(|r| r.property(ns, local)?.child(DAV, "href"))
            .map(|n| n.text.trim().to_owned()).ok_or_else(|| failure("discover", "required DAV property absent"))?;
        Ok(self.url(&value)?.to_string())
    }

    fn receipt(&self, response: Response, href: String, uid: &str, sequence: u32, hash: [u8;32], expected: Option<&str>) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
        let etag = response.headers().get(reqwest::header::ETAG).and_then(|v| v.to_str().ok()).map(str::to_owned);
        if let Some(error) = caldav_write_status_error(response.status().as_u16(), "write", &href, expected, etag.as_deref()) { return Err(error); }
        Ok(RemoteWriteReceipt { href, etag, uid: uid.to_owned(), sequence, content_hash: hash })
    }
}

impl CalDavWire for HttpCalDav {
    fn discover(&self, _secret_ref: &str, calendar_ref: &str) -> Result<CalDavDiscovery, CalendarConnectorError> {
        let principal_href = self.property_href(self.base.as_str(), "d:current-user-principal", DAV)?;
        let calendar_home_href = self.property_href(&principal_href, "c:calendar-home-set", CAL)?;
        let document = self.report(&calendar_home_href, "PROPFIND", format!("<d:propfind xmlns:d=\"DAV:\" xmlns:c=\"{CAL}\"><d:prop><d:resourcetype/><d:displayname/></d:prop></d:propfind>"))?;
        let selected = document.children(DAV, "response").filter(|row| {
            row.property(DAV, "resourcetype").and_then(|n| n.child(CAL, "calendar")).is_some()
        }).find_map(|row| {
            let href = row.child(DAV, "href")?.text.trim();
            let url = self.url(href).ok()?;
            let name = row.property(DAV, "displayname").map(|n| n.text.as_str());
            (calendar_ref == href || calendar_ref == url.as_str() || Some(calendar_ref) == name).then(|| url.to_string())
        }).ok_or_else(|| failure("discover", "configured calendar collection absent"))?;
        Ok(CalDavDiscovery { principal_href, calendar_home_href, calendar_href: selected })
    }

    fn sync_collection(&self, _secret_ref: &str, discovery: &CalDavDiscovery, sync_token: Option<&str>) -> Result<RemoteSyncBatch, CalendarConnectorError> {
        let token = xml::escape(sync_token.unwrap_or_default());
        let document = self.report(&discovery.calendar_href, "REPORT", format!("<d:sync-collection xmlns:d=\"DAV:\" xmlns:c=\"{CAL}\"><d:sync-token>{token}</d:sync-token><d:sync-level>1</d:sync-level><d:prop><d:getetag/><c:calendar-data/></d:prop></d:sync-collection>"))?;
        let cursor = document.child(DAV, "sync-token").map(|n| n.text.trim().to_owned())
            .filter(|s| !s.is_empty()).ok_or_else(|| failure("sync", "DAV sync token absent"))?;
        let mut changes = Vec::new();
        for row in document.children(DAV, "response") {
            let href = row.child(DAV, "href").map(|n| n.text.trim()).ok_or_else(|| failure("sync", "resource href absent"))?;
            let href = self.url(href)?.to_string();
            let deleted = row.child(DAV, "status").is_some_and(|n| matches!(n.text.split_whitespace().nth(1), Some("404" | "410")));
            if deleted {
                if let Some(uid) = oneiron::calendar::connectors::calendar_remote_uid_for_href(&self.vault, &self.row.seat.config.system, &self.row.seat.config.calendar_ref, &href)? {
                    changes.push(RemoteCalendarChange::Delete { href, uid });
                }
                continue;
            }
            let ics = match row.property(CAL, "calendar-data") {
                Some(data) => data.text.as_bytes().to_vec(),
                None => {
                    let response = self.request(Method::GET, &href, Vec::new(), "text/calendar", None, false, false)?;
                    if !response.status().is_success() { return Err(failure("sync", "calendar resource unreadable")); }
                    let mut bytes = Vec::new();
                    response.take(MAX_RESPONSE + 1).read_to_end(&mut bytes).map_err(|_| failure("sync", "calendar resource unreadable"))?;
                    if bytes.len() as u64 > MAX_RESPONSE { return Err(failure("sync", "calendar resource too large")); }
                    bytes
                }
            };
            let feed = parse_ics_feed(&ics)?;
            let event = feed.events.first().ok_or_else(|| failure("sync", "calendar resource has no VEVENT"))?;
            changes.push(RemoteCalendarChange::Upsert(RemoteCalendarObject {
                href, etag: row.property(DAV, "getetag").map(|n| n.text.clone()),
                uid: event.uid.clone(), sequence: event.sequence, content_hash: event.content_hash, ics,
            }));
        }
        Ok(RemoteSyncBatch { next_cursor: Some(cursor), changes })
    }

    fn put_vevent(&self, _secret_ref: &str, discovery: &CalDavDiscovery, request: &RemoteWriteRequest) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
        let href = match &request.href {
            Some(href) => {
                if request.expected_etag.is_none() { return Err(failure("write", "existing resource has no ETag")); }
                self.url(href)?
            }
            None => {
                let mut url = self.url(&discovery.calendar_href)?;
                let filename = format!("{}.ics", blake3::hash(request.uid.as_bytes()).to_hex());
                url.path_segments_mut().map_err(|_| failure("write", "invalid calendar collection"))?.pop_if_empty().push(&filename);
                url
            }
        };
        let feed = parse_ics_feed(&request.ics)?;
        let hash = feed.events.first().ok_or_else(|| failure("write", "resource has no VEVENT"))?.content_hash;
        let response = self.request(Method::PUT, href.as_str(), request.ics.clone(), "text/calendar; charset=utf-8", request.expected_etag.as_deref(), request.href.is_none(), false)?;
        self.receipt(response, href.to_string(), &request.uid, request.sequence, hash, request.expected_etag.as_deref())
    }

    fn delete_vevent(&self, _secret_ref: &str, _discovery: &CalDavDiscovery, href: &str, expected_etag: Option<&str>, uid: &str, sequence: u32) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
        let expected = expected_etag.ok_or_else(|| failure("delete", "delete requires an ETag"))?;
        let href = self.url(href)?.to_string();
        let response = self.request(Method::DELETE, &href, Vec::new(), "text/calendar", Some(expected), false, false)?;
        self.receipt(response, href, uid, sequence, [0;32], Some(expected))
    }
}
