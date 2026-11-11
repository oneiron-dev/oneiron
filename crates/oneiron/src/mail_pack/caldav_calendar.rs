//! The CalDAV wire of the pack's calendar sources (fix list row 16307;
//! MAIL-PROVIDERS = A): one calendar collection of an iCloud, Fastmail,
//! Nextcloud or other CalDAV account (RFC 4791, RFC 6578), over
//! `reqwest::blocking`.
//!
//! - **Credential.** The source's custody record, read at its door with
//!   effector `connector:caldav_calendar`, is JSON: `url` (the account's
//!   CalDAV server over HTTPS, for example `https://caldav.icloud.com/`),
//!   `username`, `password` (an app password where the provider offers one),
//!   and `calendar` (the collection's display name or href; when absent, the
//!   first collection that holds events). The source's provider account is
//!   `<username>@<host>`, the host the URL's: a credential for another
//!   account never fills it.
//! - **One origin.** Every request goes to the URL's origin over HTTPS, with
//!   no redirects; an href the server answers with that leaves the origin is
//!   refused.
//! - **Listing.** Discovery (`current-user-principal`, `calendar-home-set`,
//!   the collection), then the collection's sync token, then its members
//!   read 200 a page in href order by `calendar-multiget`. Once the listing
//!   ends, the changes after the token its first page took are read, so a
//!   change made while it listed is read again.
//! - **Changes.** `sync-collection` from the token: a changed member is read
//!   again whole; a removed one is a delete, by the UID landed for it, unless
//!   another member holds that UID now (an event the provider moved). A round
//!   reads its changed members before its removed ones, so a move is seen
//!   whichever pages its two members fall on. A UID a changed member no
//!   longer holds is marked absent, never deleted, so the page that reads it
//!   under another member lands it live again. A token the server no longer
//!   honours lists the calendar again.
//!
//! Call it from a blocking context: `reqwest::blocking` owns its own runtime.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Read;
use std::ops::Bound;

use base64::Engine as _;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use reqwest::{Method, Url};
use serde::{Deserialize, Serialize};

use super::calendar::{MailCalendarPull, MailCalendarRead, MailCalendarWire, landed_uid};
use super::credential::WireReads;
use super::dav_xml::{self, CAL, DAV, Node, status_code};
use super::rest::{self, refused};
use super::source::MailProvider;
use super::wire::MailSyncSource;
use crate::Vault;
use crate::calendar::{RemoteCalendarChange, RemoteCalendarObject};
use crate::error::{Error, Result};

/// The custody effector a CalDAV calendar credential is bound to.
pub const CALDAV_CALENDAR_CONNECTOR_EFFECTOR: &str = "connector:caldav_calendar";

/// The largest DAV answer read.
const MAX_DAV_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
/// The members one listing page reads.
const LIST_PAGE: usize = 200;
/// The changed members one pull reads.
const CHANGES_PAGE: usize = 200;
/// The members one `calendar-multiget` reads.
const MULTIGET_BATCH: usize = 100;
/// The longest href taken from a server.
const MAX_HREF_BYTES: usize = 2_048;

/// The custody record of a CalDAV calendar source.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CalDavCredential {
    url: String,
    username: String,
    password: String,
    #[serde(default)]
    calendar: Option<String>,
}

/// Where a CalDAV calendar source's pulls stand.
#[derive(Debug, Serialize, Deserialize)]
struct CalDavCursor {
    /// The calendar collection's URL.
    calendar: String,
    /// The sync token changes are read from: the one the listing's first
    /// page took, then the one each change read answered.
    token: String,
    /// While the listing runs, the last member it read (empty before its
    /// first page); `None` once it ended.
    #[serde(default)]
    listed: Option<String>,
    /// While a round of changes runs over more pages than one.
    #[serde(default)]
    round: Option<ChangeRound>,
}

/// A round of changes past its first page. A round reads its changed
/// members first, then its removed ones, each in href order.
#[derive(Debug, Serialize, Deserialize)]
struct ChangeRound {
    /// The last member it read.
    after: String,
    /// Whether that member was a removed one.
    #[serde(default)]
    removed: bool,
    /// The token its first page answered, followed once it ends.
    token: String,
}

/// Host-side CalDAV calendar wire over `reqwest::blocking`.
pub struct HttpCalDavCalendarWire<'v> {
    vault: &'v Vault,
    client: reqwest::blocking::Client,
}

impl<'v> HttpCalDavCalendarWire<'v> {
    /// Builds the wire: HTTPS only, no redirects, a 60 s timeout.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when the TLS client cannot be built.
    pub fn new(vault: &'v Vault) -> Result<Self> {
        Ok(Self {
            vault,
            client: rest::https_client()?,
        })
    }
}

/// What one `sync-collection` answered.
struct Synced {
    token: String,
    changed: Vec<String>,
    removed: Vec<String>,
    /// Whether the server cut the answer short: more changes follow from
    /// its token.
    truncated: bool,
}

/// The account a credential opens: its server's origin and its Basic
/// authorization.
struct Account<'c> {
    client: &'c reqwest::blocking::Client,
    base: Url,
    authorization: HeaderValue,
}

impl<'c> Account<'c> {
    /// Opens the account the credential `secret` names for `source`, and
    /// the collection it selects.
    fn open(
        client: &'c reqwest::blocking::Client,
        secret: &[u8],
        source: &MailSyncSource,
    ) -> Result<(Self, Option<String>)> {
        let stored: CalDavCredential = serde_json::from_slice(secret)
            .map_err(|_| refused("caldav_calendar_credential_unreadable"))?;
        let invalid = || refused("caldav_calendar_credential_url_invalid");
        let base = Url::parse(stored.url.trim()).map_err(|_| invalid())?;
        if base.scheme() != "https"
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
        {
            return Err(invalid());
        }
        let host = base.host_str().ok_or_else(invalid)?.to_ascii_lowercase();
        // The credential reads the account the source names, and no other:
        // its user exactly, as a server may tell case apart, and its host.
        let reads_account =
            source
                .provider_account
                .rsplit_once('@')
                .is_some_and(|(user, named)| {
                    user == stored.username && named.eq_ignore_ascii_case(&host)
                });
        if !reads_account {
            return Err(refused("caldav_calendar_credential_reads_another_account"));
        }
        if stored.username.contains(':') {
            return Err(refused("caldav_calendar_credential_username_unsupported"));
        }
        let basic = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", stored.username, stored.password));
        let mut authorization = HeaderValue::from_str(&format!("Basic {basic}"))
            .map_err(|_| refused("caldav_calendar_credential_unreadable"))?;
        authorization.set_sensitive(true);
        Ok((
            Self {
                client,
                base,
                authorization,
            },
            stored.calendar,
        ))
    }

    /// `href` resolved against the server, on its origin only.
    fn url(&self, href: &str) -> Result<Url> {
        if href.len() > MAX_HREF_BYTES {
            return Err(refused("caldav_calendar_href_invalid"));
        }
        let url = self
            .base
            .join(href.trim())
            .map_err(|_| refused("caldav_calendar_href_invalid"))?;
        if url.origin() != self.base.origin()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(refused("caldav_calendar_href_leaves_the_server"));
        }
        Ok(url)
    }

    /// One DAV request: its status and its body, bounded.
    fn dav(&self, method: &str, url: &Url, depth: &str, body: String) -> Result<(u16, Vec<u8>)> {
        let method = Method::from_bytes(method.as_bytes())
            .map_err(|_| refused("caldav_calendar_method_invalid"))?;
        let response = self
            .client
            .request(method, url.clone())
            .header(AUTHORIZATION, self.authorization.clone())
            .header(CONTENT_TYPE, "application/xml; charset=utf-8")
            .header("Depth", depth)
            .body(body)
            .send()
            .map_err(|_| refused("caldav_calendar_transport_failed"))?;
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(MAX_DAV_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| refused("caldav_calendar_response_unreadable"))?;
        if bytes.len() as u64 > MAX_DAV_RESPONSE_BYTES {
            return Err(refused("caldav_calendar_response_too_large"));
        }
        Ok((status, bytes))
    }

    /// One DAV request answered by a `multistatus`.
    fn multistatus(&self, method: &str, url: &Url, depth: &str, body: String) -> Result<Node> {
        let (status, bytes) = self.dav(method, url, depth, body)?;
        if status != 207 {
            return Err(Error::InvalidConfig(format!(
                "caldav_calendar_status_{status}"
            )));
        }
        dav_xml::parse(&bytes).map_err(|_| refused("caldav_calendar_response_malformed"))
    }

    /// The href property `ns:name` of `url`.
    fn href_property(&self, url: &Url, ns: &str, name: &str) -> Result<Url> {
        let prefix = if ns == CAL { "c" } else { "d" };
        let body = format!(
            "<d:propfind xmlns:d=\"DAV:\" xmlns:c=\"{CAL}\"><d:prop><{prefix}:{name}/></d:prop></d:propfind>"
        );
        let document = self.multistatus("PROPFIND", url, "0", body)?;
        let href = document
            .children(DAV, "response")
            .find_map(|response| response.property(ns, name)?.child(DAV, "href"))
            .map(|href| href.text.trim().to_owned())
            .ok_or_else(|| refused("caldav_calendar_discovery_failed"))?;
        self.url(&href)
    }

    /// The calendar collection `wanted` names (its display name, href or
    /// URL), else the first collection, in href order, that holds events.
    fn discover(&self, wanted: Option<&str>) -> Result<Url> {
        let principal = self.href_property(&self.base, DAV, "current-user-principal")?;
        let home = self.href_property(&principal, CAL, "calendar-home-set")?;
        let body = format!(
            "<d:propfind xmlns:d=\"DAV:\" xmlns:c=\"{CAL}\"><d:prop><d:resourcetype/><d:displayname/><c:supported-calendar-component-set/></d:prop></d:propfind>"
        );
        let document = self.multistatus("PROPFIND", &home, "1", body)?;
        let mut calendars = Vec::new();
        for response in document.children(DAV, "response") {
            let calendar = response
                .property(DAV, "resourcetype")
                .and_then(|kind| kind.child(CAL, "calendar"))
                .is_some();
            let Some(href) = response.child(DAV, "href").filter(|_| calendar) else {
                continue;
            };
            let url = self.url(&href.text)?;
            let name = response
                .property(DAV, "displayname")
                .map(|name| name.text.trim().to_owned());
            // A collection that names its components holds events only
            // when VEVENT is among them.
            let events = response
                .property(CAL, "supported-calendar-component-set")
                .is_none_or(|set| {
                    set.children(CAL, "comp").any(|comp| {
                        comp.attribute("name")
                            .is_some_and(|component| component.eq_ignore_ascii_case("VEVENT"))
                    })
                });
            calendars.push((url, name, events));
        }
        calendars.sort();
        let chosen = match wanted.map(str::trim) {
            Some(wanted) => {
                let named = self.url(wanted).ok();
                calendars.into_iter().find(|(url, name, _)| {
                    named.as_ref() == Some(url) || name.as_deref() == Some(wanted)
                })
            }
            None => calendars.into_iter().find(|(_, _, events)| *events),
        };
        chosen
            .map(|(url, _, _)| url)
            .ok_or_else(|| refused("caldav_calendar_collection_not_found"))
    }

    /// The collection's current sync token (RFC 6578 `DAV:sync-token`).
    fn sync_token(&self, calendar: &Url) -> Result<String> {
        let body = "<d:propfind xmlns:d=\"DAV:\"><d:prop><d:sync-token/></d:prop></d:propfind>";
        let document = self.multistatus("PROPFIND", calendar, "0", body.to_owned())?;
        document
            .children(DAV, "response")
            .find_map(|response| response.property(DAV, "sync-token"))
            .map(|token| token.text.trim().to_owned())
            .filter(|token| !token.is_empty())
            .ok_or_else(|| refused("caldav_calendar_server_keeps_no_sync_token"))
    }

    /// The collection's members, in href order.
    fn members(&self, calendar: &Url) -> Result<BTreeSet<String>> {
        let body = "<d:propfind xmlns:d=\"DAV:\"><d:prop><d:resourcetype/><d:getetag/></d:prop></d:propfind>";
        let document = self.multistatus("PROPFIND", calendar, "1", body.to_owned())?;
        let mut members = BTreeSet::new();
        for response in document.children(DAV, "response") {
            let Some(href) = response.child(DAV, "href") else {
                continue;
            };
            let url = self.url(&href.text)?;
            let collection = response
                .property(DAV, "resourcetype")
                .and_then(|kind| kind.child(DAV, "collection"))
                .is_some();
            if url != *calendar && !collection {
                members.insert(url.to_string());
            }
        }
        Ok(members)
    }

    /// The changes after `token` (`sync-collection`); `None` when the server
    /// no longer honours it.
    fn sync(&self, calendar: &Url, token: &str) -> Result<Option<Synced>> {
        let body = format!(
            "<d:sync-collection xmlns:d=\"DAV:\"><d:sync-token>{}</d:sync-token><d:sync-level>1</d:sync-level><d:prop><d:getetag/></d:prop></d:sync-collection>",
            dav_xml::escape(token)
        );
        let (status, bytes) = self.dav("REPORT", calendar, "0", body)?;
        if matches!(status, 403 | 409 | 410) {
            return Ok(None);
        }
        if status != 207 {
            return Err(Error::InvalidConfig(format!(
                "caldav_calendar_status_{status}"
            )));
        }
        let document =
            dav_xml::parse(&bytes).map_err(|_| refused("caldav_calendar_response_malformed"))?;
        let token = document
            .child(DAV, "sync-token")
            .map(|token| token.text.trim().to_owned())
            .filter(|token| !token.is_empty())
            .ok_or_else(|| refused("caldav_calendar_sync_token_absent"))?;
        let mut synced = Synced {
            token,
            changed: Vec::new(),
            removed: Vec::new(),
            truncated: false,
        };
        for response in document.children(DAV, "response") {
            let Some(href) = response.child(DAV, "href") else {
                continue;
            };
            let url = self.url(&href.text)?;
            let status = response
                .child(DAV, "status")
                .and_then(|status| status_code(&status.text));
            if url == *calendar {
                synced.truncated |= status == Some(507);
                continue;
            }
            match status {
                Some(404 | 410) => synced.removed.push(url.to_string()),
                _ => synced.changed.push(url.to_string()),
            }
        }
        Ok(Some(synced))
    }

    /// What each of the members `hrefs` holds, read whole
    /// (`calendar-multiget`), keyed by the href as asked. Every member asked
    /// for is answered, or the read fails and nothing advances: one the
    /// server leaves out, answers without its data, or whose data does not
    /// parse is never read as gone.
    fn multiget(&self, calendar: &Url, hrefs: &[String]) -> Result<Vec<(String, Member)>> {
        if hrefs.is_empty() {
            return Ok(Vec::new());
        }
        let mut asked = BTreeMap::new();
        let mut body = format!(
            "<c:calendar-multiget xmlns:d=\"DAV:\" xmlns:c=\"{CAL}\"><d:prop><d:getetag/><c:calendar-data/></d:prop>"
        );
        for href in hrefs {
            let url = self.url(href)?;
            let _ = write!(body, "<d:href>{}</d:href>", dav_xml::escape(url.path()));
            asked.insert(decoded_path(&url), href.clone());
        }
        body.push_str("</c:calendar-multiget>");
        let document = self.multistatus("REPORT", calendar, "1", body)?;
        let mut members = Vec::with_capacity(asked.len());
        for response in document.children(DAV, "response") {
            let Some(href) = response.child(DAV, "href") else {
                continue;
            };
            let Some(href) = asked.remove(&decoded_path(&self.url(&href.text)?)) else {
                continue;
            };
            let gone = response
                .child(DAV, "status")
                .and_then(|status| status_code(&status.text))
                .is_some_and(|code| matches!(code, 404 | 410));
            if gone {
                members.push((href, Member::NoEvent));
                continue;
            }
            let data = response
                .property(CAL, "calendar-data")
                .ok_or_else(|| refused("caldav_calendar_member_unreadable"))?;
            let ics = data.text.as_bytes().to_vec();
            let feed = crate::calendar::parse_ics_feed(&ics)
                .map_err(|_| refused("caldav_calendar_member_does_not_parse"))?;
            // A member holding no event (a task) lands none.
            let Some(event) = feed.events.first() else {
                members.push((href, Member::NoEvent));
                continue;
            };
            let object = RemoteCalendarObject {
                href: href.clone(),
                etag: response
                    .property(DAV, "getetag")
                    .map(|etag| etag.text.trim().to_owned()),
                uid: event.uid.clone(),
                sequence: event.sequence,
                content_hash: event.content_hash,
                ics,
            };
            members.push((href, Member::Event(object)));
        }
        if !asked.is_empty() {
            return Err(refused("caldav_calendar_member_unanswered"));
        }
        Ok(members)
    }

    /// What each of `hrefs` holds, read a batch at a time.
    fn read_members(&self, calendar: &Url, hrefs: &[String]) -> Result<Vec<(String, Member)>> {
        let mut members = Vec::with_capacity(hrefs.len());
        for batch in hrefs.chunks(MULTIGET_BATCH) {
            members.extend(self.multiget(calendar, batch)?);
        }
        Ok(members)
    }
}

/// What one member of a collection holds.
enum Member {
    /// An event, read whole.
    Event(RemoteCalendarObject),
    /// No event: gone meanwhile, or holding something else (a task).
    NoEvent,
}

/// `url`'s path with its percent escapes decoded: how two spellings of one
/// member's href compare.
fn decoded_path(url: &Url) -> Vec<u8> {
    let path = url.path().as_bytes();
    let digit = |at: usize| {
        path.get(at)
            .and_then(|byte| char::from(*byte).to_digit(16))
            .and_then(|digit| u8::try_from(digit).ok())
    };
    let mut out = Vec::with_capacity(path.len());
    let mut at = 0;
    while let Some(&byte) = path.get(at) {
        if byte == b'%'
            && let (Some(high), Some(low)) = (digit(at + 1), digit(at + 2))
        {
            out.push((high << 4) | low);
            at += 3;
        } else {
            out.push(byte);
            at += 1;
        }
    }
    out
}

/// The next page of a run over `members` in order, after `after`: at most
/// `limit`, and whether more follow.
fn page_after<K: Ord + Clone>(members: &BTreeSet<K>, after: &K, limit: usize) -> (Vec<K>, bool) {
    let mut page: Vec<K> = members
        .range((Bound::Excluded(after), Bound::Unbounded))
        .take(limit + 1)
        .cloned()
        .collect();
    let more = page.len() > limit;
    page.truncate(limit);
    (page, more)
}

impl HttpCalDavCalendarWire<'_> {
    /// One pull through the open `account`: the listing's next page, or the
    /// next page of changes after the cursor's token.
    fn read(
        &self,
        account: &Account<'_>,
        source: &MailSyncSource,
        wanted: Option<&str>,
        cursor: Option<CalDavCursor>,
    ) -> Result<MailCalendarRead> {
        let cursor = match cursor {
            Some(cursor) => cursor,
            None => {
                let calendar = account.discover(wanted)?;
                let token = account.sync_token(&calendar)?;
                CalDavCursor {
                    calendar: calendar.to_string(),
                    token,
                    listed: Some(String::new()),
                    round: None,
                }
            }
        };
        let calendar = account.url(&cursor.calendar)?;
        let page = if let Some(after) = &cursor.listed {
            list_page(account, &calendar, cursor.token.clone(), after)?
        } else {
            match self.changes(account, source, &calendar, cursor)? {
                Some(page) => page,
                None => return Ok(MailCalendarRead::Expired),
            }
        };
        Ok(MailCalendarRead::Pull(MailCalendarPull {
            changes: page.changes,
            next_cursor: Some(
                serde_json::to_string(&page.next)
                    .map_err(|_| refused("caldav_calendar_cursor_unencodable"))?,
            ),
            complete: page.complete,
            covers: None,
            vacated: page.vacated,
        }))
    }

    /// The next page of changes after the cursor's token, at most
    /// `CHANGES_PAGE` members: the changed members first, then the removed
    /// ones, each in href order, so every event a round reads has landed
    /// before any member it removes is settled. A removed member's landed
    /// UID is deleted: the provider's tombstone. A UID a changed member held
    /// before it holds another or none is vacated: marked absent, as a
    /// finished listing marks one it omitted, so a later page that reads it
    /// under another member lands it live again. A UID read again under
    /// another member, on this page or landed under one that keeps it, is
    /// neither: its old member's row is retired. A round over more pages
    /// than one goes on from its last member under the same token, and ends
    /// on the token its first page answered, so a change made while it ran
    /// is read again. `None` when the server no longer honours the token.
    fn changes(
        &self,
        account: &Account<'_>,
        source: &MailSyncSource,
        calendar: &Url,
        cursor: CalDavCursor,
    ) -> Result<Option<Page>> {
        let Some(synced) = account.sync(calendar, &cursor.token)? else {
            return Ok(None);
        };
        let (after, round_token) = match cursor.round {
            Some(round) => ((round.removed, round.after), round.token),
            None => ((false, String::new()), synced.token.clone()),
        };
        let removed: BTreeSet<String> = synced.removed.into_iter().collect();
        let members: BTreeSet<(bool, String)> = synced
            .changed
            .into_iter()
            .filter(|href| !removed.contains(href))
            .map(|href| (false, href))
            .chain(removed.iter().map(|href| (true, href.clone())))
            .collect();
        let (page, more) = page_after(&members, &after, CHANGES_PAGE);
        let read = self.page_changes(account, source, calendar, &page)?;
        let (changes, vacated) = self.settle(source, read)?;
        let next = if more {
            let (in_removed, after) = page.last().cloned().unwrap_or(after);
            CalDavCursor {
                calendar: calendar.to_string(),
                token: cursor.token,
                listed: None,
                round: Some(ChangeRound {
                    after,
                    removed: in_removed,
                    token: round_token,
                }),
            }
        } else {
            CalDavCursor {
                calendar: calendar.to_string(),
                token: round_token,
                listed: None,
                round: None,
            }
        };
        Ok(Some(Page {
            changes,
            vacated,
            next,
            complete: !more && !synced.truncated,
        }))
    }
}

/// One pull's read, its cursor not spelled yet.
struct Page {
    changes: Vec<RemoteCalendarChange>,
    /// Each changed member and the UID landed for it that no member holds
    /// now ([`MailCalendarPull::vacated`]).
    vacated: Vec<(String, String)>,
    next: CalDavCursor,
    complete: bool,
}

/// What one page of a change round read.
struct PageRead {
    /// Each removed member and the UID landed for it.
    removed: Vec<(String, String)>,
    /// Each changed member and the UID landed for it that it holds no
    /// longer: it holds another, or no event.
    left: Vec<(String, String)>,
    /// The events the page's changed members hold now.
    events: Vec<RemoteCalendarObject>,
}

impl HttpCalDavCalendarWire<'_> {
    /// What one page of changed (`false`) and removed (`true`) members
    /// holds: the UIDs it no longer holds where it held them (a removed
    /// member's landed UID, the one a changed member held before it holds
    /// another or none), and the events it holds now.
    fn page_changes(
        &self,
        account: &Account<'_>,
        source: &MailSyncSource,
        calendar: &Url,
        page: &[(bool, String)],
    ) -> Result<PageRead> {
        let changed: Vec<String> = page
            .iter()
            .filter(|(removed, _)| !*removed)
            .map(|(_, href)| href.clone())
            .collect();
        let mut removed = Vec::new();
        for (_, href) in page.iter().filter(|(removed, _)| *removed) {
            if let Some(uid) = landed_uid(self.vault, source.source_ref, href)? {
                removed.push((href.clone(), uid));
            }
        }
        let mut left = Vec::new();
        let mut events = Vec::new();
        for (href, member) in account.read_members(calendar, &changed)? {
            let held = landed_uid(self.vault, source.source_ref, &href)?;
            let now = match member {
                Member::Event(object) => {
                    let uid = object.uid.clone();
                    events.push(object);
                    Some(uid)
                }
                Member::NoEvent => None,
            };
            if let Some(held) = held.filter(|held| now.as_ref() != Some(held)) {
                left.push((href, held));
            }
        }
        Ok(PageRead {
            removed,
            left,
            events,
        })
    }

    /// The changes one page makes, deletes first, then the events, and the
    /// UIDs it vacates. A UID still held is neither deleted nor vacated: one
    /// this page reads under another member, or one the source landed under
    /// a member that does not leave it on this page (an earlier page of the
    /// round read it there). The row of the member that left it is retired
    /// instead. A UID two removed members leave is deleted once.
    fn settle(
        &self,
        source: &MailSyncSource,
        read: PageRead,
    ) -> Result<(Vec<RemoteCalendarChange>, Vec<(String, String)>)> {
        let PageRead {
            removed,
            left,
            events,
        } = read;
        let unread: BTreeSet<String> = removed
            .iter()
            .chain(&left)
            .filter(|(_, uid)| !events.iter().any(|event| event.uid == *uid))
            .map(|(_, uid)| uid.clone())
            .collect();
        let kept = {
            let leaving: BTreeSet<&str> = removed
                .iter()
                .chain(&left)
                .map(|(href, _)| href.as_str())
                .collect();
            super::calendar::uids_held_outside(self.vault, source.source_ref, &unread, &leaving)?
        };
        let held = |uid: &String| !unread.contains(uid) || kept.contains(uid);
        let mut deleted = BTreeSet::new();
        let mut changes = Vec::new();
        for (href, uid) in removed {
            if !held(&uid) && deleted.insert(uid.clone()) {
                changes.push(RemoteCalendarChange::Delete { href, uid });
            } else {
                super::calendar::forget_resource_href(self.vault, source.source_ref, &href)?;
            }
        }
        let mut vacated = Vec::new();
        for (href, uid) in left {
            if !held(&uid) {
                vacated.push((href, uid));
            } else if !events.iter().any(|event| event.href == href) {
                super::calendar::forget_resource_href(self.vault, source.source_ref, &href)?;
            }
        }
        changes.extend(events.into_iter().map(RemoteCalendarChange::Upsert));
        Ok((changes, vacated))
    }
}

/// The listing's next page after the member `after`: up to `LIST_PAGE`
/// members read whole. The last page ends the listing, and the cursor then
/// follows the changes after `token`.
fn list_page(account: &Account<'_>, calendar: &Url, token: String, after: &str) -> Result<Page> {
    let members = account.members(calendar)?;
    let (hrefs, more) = page_after(&members, &after.to_owned(), LIST_PAGE);
    let mut changes = Vec::new();
    for (_, member) in account.read_members(calendar, &hrefs)? {
        if let Member::Event(object) = member {
            changes.push(RemoteCalendarChange::Upsert(object));
        }
    }
    let next = CalDavCursor {
        calendar: calendar.to_string(),
        token,
        listed: if more { hrefs.last().cloned() } else { None },
        round: None,
    };
    Ok(Page {
        changes,
        vacated: Vec::new(),
        next,
        complete: !more,
    })
}

impl MailCalendarWire for HttpCalDavCalendarWire<'_> {
    fn pull(&self, source: &MailSyncSource, cursor: Option<&str>) -> Result<MailCalendarRead> {
        if source.provider != MailProvider::Caldav {
            return Err(refused("caldav_calendar_wire_reads_caldav_sources_only"));
        }
        let mut cursor: Option<CalDavCursor> = cursor
            .map(|cursor| {
                serde_json::from_str(cursor)
                    .map_err(|_| refused("caldav_calendar_cursor_unreadable"))
            })
            .transpose()?;
        let mut read: Option<MailCalendarRead> = None;
        let _receipt = self.vault.with_source_token_at_door(
            source,
            WireReads::Calendar,
            CALDAV_CALENDAR_CONNECTOR_EFFECTOR,
            &mut |secret: &[u8]| {
                let (account, wanted) = Account::open(&self.client, secret, source)?;
                read = Some(self.read(&account, source, wanted.as_deref(), cursor.take())?);
                Ok(())
            },
        )?;
        read.ok_or_else(|| refused("caldav_calendar_credential_door_refused"))
    }
}
