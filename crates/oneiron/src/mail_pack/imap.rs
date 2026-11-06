//! The IMAP mail wire (FIX 12559 row 4, fix list row 15425): one IMAP4rev1
//! mailbox over TLS, through the engine's own client
//! ([`super::imap_client`]).
//!
//! - **Credential.** The source's custody record, read at its door with
//!   effector `connector:imap`, is JSON: `host`, `port`, `security` (`tls`,
//!   TLS from the first byte, port 993 when absent; or `starttls`, the plain
//!   port upgraded before anything else is sent, port 143 when absent; a
//!   record naming port 143 alone means `starttls`), `username`, and
//!   `password` or an OAuth `access_token` (`XOAUTH2`). The
//!   source's provider account is `<username>@<host>`: a credential for
//!   another account never fills it. One session serves one wire, opened at
//!   the first read and opened again when the record changes.
//! - **Ids.** A message is named as an mbox import names it: `mbox` and the
//!   first 32 hex of the BLAKE3 of its `Message-ID`. So an mbox import and
//!   the live mailbox land a message once, and one filed in two folders is
//!   one message. One with no `Message-ID` is named by where it is:
//!   `imapuid.<folder digest>.<UIDVALIDITY>.<UID>`.
//! - **Folders are labels.** Every selectable folder is read but drafts and
//!   the all-mail, flagged and important views; trash and junk are looked in
//!   only to see that a message went there.
//! - **Changes.** The anchor holds each folder's UIDVALIDITY, UIDNEXT and the
//!   count of messages below it. New UIDs are added mail; a folder holding
//!   fewer of its old messages than it did lost some, and each copy labelled
//!   with it that it no longer holds is looked for in the other folders:
//!   moved, it carries its new folders; in trash or junk, or nowhere, it was
//!   deleted at the provider. A changed UIDVALIDITY expires the anchor.
//! - **What a folder holds.** The wire keeps which message each UID of a
//!   folder it read holds (fix list row 17871): a folder that lost mail is
//!   checked by one UID search, and only the UIDs it never read are fetched
//!   for their `Message-ID`, not every message in the folder.
//!
//! Call it from a blocking context: each call is socket I/O.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use super::credential::WireReads;
use super::gmail::{address_list, rfc2822_seconds};
use super::imap_client::{
    Fetched, FolderStatus, ImapSession, Item, ListedFolder, decode_mailbox_name, range_set,
    ranges_hold, uid_set,
};
use super::mime::MimeMessage;
use super::rest::refused;
use super::source::MailProvider;
use super::state::{MailPresence, OCCURRENCES, SYNC, occurrence_key};
use super::wire::{
    MailAttachmentRef, MailFull, MailHeaders, MailHistoryChange, MailHistoryPage, MailHistoryRead,
    MailIdPage, MailListQuery, MailMessageRef, MailProviderWire, MailSyncSource,
};
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

/// The effector an IMAP source's credential is injected at.
pub const IMAP_CONNECTOR_EFFECTOR: &str = "connector:imap";

/// The messages one listing page names.
const LIST_PAGE: u64 = 100;
/// The new messages one change read takes from one folder.
const NEW_PER_FOLDER: usize = 200;
/// The most folders one mailbox is read through; a mailbox with more is
/// refused whole rather than read in part.
const MAX_FOLDERS: usize = 1_000;
/// The old UIDs one read of a folder's `Message-ID`s covers.
const DEPARTURE_BATCH: u64 = 2_000;
/// The most UID ranges one such read names, so its command line stays short.
const MAX_SET_RANGES: usize = 200;
/// The search hits one read of their `Message-ID`s checks.
const HIT_BATCH: usize = 64;
/// The largest message read whole: a bigger one lands by its headers.
const MAX_MESSAGE_BYTES: u64 = 40 * 1024 * 1024;
/// The prefix of an anchor this wire writes.
const ANCHOR_PREFIX: &str = "imap2";
/// The prefix of a listing page this wire writes.
const LIST_PREFIX: &str = "imap1";

/// Which message each UID of a read folder holds: by the source, the
/// BLAKE3 of the folder's digest and the UID. A UID names one message for
/// as long as its folder's UIDVALIDITY stands, which the row keeps.
const UIDS: SideTable<(EntityId, [u8; 32], u64), HeldUid, Named> =
    SideTable::new(&side_table::MAIL_PACK_IMAP_UID);

/// The message one UID holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HeldUid {
    uid_validity: u64,
    provider_id: String,
}

/// How a session reaches TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ImapSecurity {
    /// TLS from the first byte.
    Tls,
    /// The plain port, upgraded by `STARTTLS` before anything else is sent.
    Starttls,
}

/// The custody record of an IMAP source.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImapCredential {
    host: String,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    security: Option<ImapSecurity>,
    username: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    access_token: Option<String>,
}

/// What a folder is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FolderRole {
    /// Mail the mailbox received or keeps.
    Mail,
    /// Mail it sent.
    Sent,
    /// Trash or junk: a message there is deleted at the provider.
    Discarded,
}

#[derive(Debug, Clone)]
struct Folder {
    /// Its name as the server spells it.
    name: String,
    /// Its name as text: the message's label.
    label: String,
    role: FolderRole,
    /// The first 16 hex of the BLAKE3 of its label.
    digest: String,
}

impl Folder {
    const fn read(&self) -> bool {
        !matches!(self.role, FolderRole::Discarded)
    }
}

/// Where a message is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Location {
    folder: usize,
    uid_validity: u64,
    uid: u64,
}

struct OpenSession {
    session: ImapSession,
    /// The source it reads.
    source: EntityId,
    /// The keyed digest of the credential it signed in with.
    credential: [u8; 32],
    folders: Vec<Folder>,
}

/// The IMAP wire for one host's sync step.
pub struct ImapMailWire<'v> {
    vault: &'v Vault,
    /// This wire's own key for credential digests; it never leaves it.
    key: [u8; 32],
    session: RefCell<Option<OpenSession>>,
    /// The headers this wire's session read, by message id, and where it
    /// read them; emptied when the session opens again.
    seen: RefCell<BTreeMap<String, (MailHeaders, Location)>>,
}

impl<'v> ImapMailWire<'v> {
    /// Builds the wire; it connects at its first read.
    #[must_use]
    pub fn new(vault: &'v Vault) -> Self {
        Self {
            vault,
            key: rand::random(),
            session: RefCell::new(None),
            seen: RefCell::new(BTreeMap::new()),
        }
    }
}

impl Drop for ImapMailWire<'_> {
    fn drop(&mut self) {
        if let Some(open) = self.session.get_mut().take() {
            open.session.logout();
        }
    }
}

fn digest_of(label: &str) -> String {
    blake3::hash(label.as_bytes()).to_hex()[..16].to_owned()
}

/// The folders a mailbox is read through, INBOX first.
///
/// # Errors
///
/// A mailbox of more than [`MAX_FOLDERS`] folders.
fn folders_of(listed: Vec<ListedFolder>) -> Result<Vec<Folder>> {
    let mut folders: Vec<Folder> = listed
        .into_iter()
        .filter_map(|folder| {
            let has = |attribute: &str| folder.attributes.iter().any(|held| held == attribute);
            if has("\\noselect") || has("\\nonexistent") {
                return None;
            }
            let label = decode_mailbox_name(&folder.name);
            let lower = label.to_lowercase();
            let leaf = lower.rsplit(['/', '.']).next().unwrap_or(&lower).trim();
            if has("\\drafts")
                || has("\\all")
                || has("\\flagged")
                || has("\\important")
                || matches!(leaf, "drafts" | "draft")
            {
                return None;
            }
            let role = if has("\\trash")
                || has("\\junk")
                || matches!(
                    leaf,
                    "trash"
                        | "deleted items"
                        | "deleted messages"
                        | "junk"
                        | "junk e-mail"
                        | "junk email"
                        | "spam"
                        | "bulk mail"
                ) {
                FolderRole::Discarded
            } else if has("\\sent")
                || matches!(leaf, "sent" | "sent items" | "sent messages" | "sent mail")
            {
                FolderRole::Sent
            } else {
                FolderRole::Mail
            };
            Some(Folder {
                digest: digest_of(&label),
                name: folder.name,
                label,
                role,
            })
        })
        .collect();
    folders.sort_by_key(|folder| {
        (
            !folder.name.eq_ignore_ascii_case("INBOX"),
            folder.name.clone(),
        )
    });
    if folders.len() > MAX_FOLDERS {
        return Err(refused("imap_mailbox_has_too_many_folders"));
    }
    Ok(folders)
}

/// A message's id from its `Message-ID`, as an mbox import gives it.
fn content_id(rfc_message_id: &str) -> String {
    format!(
        "mbox{}",
        &blake3::hash(rfc_message_id.as_bytes()).to_hex()[..32]
    )
}

fn place_id(folder: &Folder, uid_validity: u64, uid: u64) -> String {
    format!("imapuid.{}.{uid_validity}.{uid}", folder.digest)
}

/// An `INTERNALDATE` (`17-Jul-1996 02:44:25 -0700`) as Unix seconds.
fn internal_seconds(value: &str) -> Option<u64> {
    let at = chrono::DateTime::parse_from_str(value.trim(), "%d-%b-%Y %H:%M:%S %z").ok()?;
    u64::try_from(at.timestamp()).ok()
}

/// A day as `SEARCH SINCE` takes it: `6-Nov-2026`.
fn search_date(seconds: u64) -> Option<String> {
    let at = chrono::DateTime::from_timestamp(i64::try_from(seconds).ok()?, 0)?;
    Some(at.format("%-d-%b-%Y").to_string())
}

/// What the attributes of one fetched message say of it, with its parsed
/// header block.
struct MessageRead<'f> {
    uid: u64,
    flags: Vec<String>,
    received_at: Option<u64>,
    thread: Option<String>,
    raw: &'f [u8],
}

fn read_of<'f>(fetched: &'f Fetched, section: &str) -> Option<MessageRead<'f>> {
    let uid = fetched.uid()?;
    let raw = fetched.value(section)?.bytes()?;
    let flags = fetched
        .value("FLAGS")
        .and_then(Item::list)
        .unwrap_or_default()
        .iter()
        .filter_map(Item::atom)
        .map(str::to_ascii_lowercase)
        .collect();
    let received_at = fetched
        .value("INTERNALDATE")
        .and_then(Item::bytes)
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .and_then(internal_seconds);
    let thread = fetched
        .value("THREADID")
        .and_then(Item::list)
        .and_then(<[Item]>::first)
        .and_then(Item::atom)
        .map(str::to_owned);
    Some(MessageRead {
        uid,
        flags,
        received_at,
        thread,
        raw,
    })
}

/// A message's headers from its header block (or the whole message), read
/// in `folder`.
fn headers_of(
    read: &MessageRead<'_>,
    folder: &Folder,
    uid_validity: u64,
    labels: Vec<String>,
) -> MailHeaders {
    let parsed = MimeMessage::parse(read.raw);
    let rfc_message_id = parsed.header("message-id").filter(|id| !id.is_empty());
    let provider_id = rfc_message_id
        .as_deref()
        .map_or_else(|| place_id(folder, uid_validity, read.uid), content_id);
    let addresses = |name: &str| {
        parsed
            .header(name)
            .map(|value| address_list(&value))
            .unwrap_or_default()
    };
    let date = parsed.header("date").as_deref().and_then(rfc2822_seconds);
    let flagged = |flag: &str| read.flags.iter().any(|held| held == flag);
    MailHeaders {
        provider_id,
        thread_id: read.thread.clone(),
        in_reply_to: parsed.header("in-reply-to").filter(|id| !id.is_empty()),
        references: parsed
            .header("references")
            .map(|value| value.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_default(),
        from: parsed.header("from").filter(|from| !from.is_empty()),
        to: addresses("to"),
        cc: addresses("cc"),
        reply_to: addresses("reply-to"),
        subject: parsed.header("subject"),
        date,
        received_at: read.received_at.or(date).unwrap_or(0),
        sent_by_mailbox: folder.role == FolderRole::Sent,
        // A message marked deleted waits for its expunge.
        trash_or_spam: folder.role == FolderRole::Discarded || flagged("\\deleted"),
        draft: flagged("\\draft"),
        rfc_message_id,
        labels,
    }
}

/// One folder's entry in an anchor:
/// `digest:uidvalidity:uidnext:top:exists`. `uid_next` is the frontier the
/// change feed has consumed; `top` and `exists` are the folder's UIDNEXT and
/// message count when the anchor was read, so any message it held then and
/// holds no more is seen to leave, however far past the frontier it lies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Mark {
    uid_validity: u64,
    uid_next: u64,
    top: u64,
    exists: u64,
}

fn parse_anchor(anchor: &str) -> Option<BTreeMap<String, Mark>> {
    let mut parts = anchor.split(';');
    if parts.next()? != ANCHOR_PREFIX {
        return None;
    }
    let mut marks = BTreeMap::new();
    for part in parts.filter(|part| !part.is_empty()) {
        let mut fields = part.split(':');
        let digest = fields.next()?.to_owned();
        let mut number = || fields.next()?.parse::<u64>().ok();
        let mark = Mark {
            uid_validity: number()?,
            uid_next: number()?,
            top: number()?,
            exists: number()?,
        };
        marks.insert(digest, mark);
    }
    Some(marks)
}

fn write_anchor(marks: &BTreeMap<String, Mark>) -> String {
    let mut anchor = ANCHOR_PREFIX.to_owned();
    for (digest, mark) in marks {
        let _ = write!(
            anchor,
            ";{digest}:{}:{}:{}:{}",
            mark.uid_validity, mark.uid_next, mark.top, mark.exists
        );
    }
    anchor
}

/// Where a listing stands: the folder (by its place in the read folders
/// and its digest), its UIDVALIDITY, the UID the next page is below, and the
/// sequence number it ends at.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ListCursor {
    folder: usize,
    digest: String,
    uid_validity: u64,
    below: Option<u64>,
    end: Option<u64>,
}

impl ListCursor {
    fn parse(page: Option<&str>) -> Result<Self> {
        let Some(page) = page else {
            return Ok(Self::default());
        };
        let fields: Vec<&str> = page.split(':').collect();
        let number = |at: usize| -> Result<Option<u64>> {
            match fields.get(at) {
                Some(&"") => Ok(None),
                Some(field) => field
                    .parse()
                    .map(Some)
                    .map_err(|_| refused("imap_list_page_unreadable")),
                None => Err(refused("imap_list_page_unreadable")),
            }
        };
        if fields.first() != Some(&LIST_PREFIX) || fields.len() != 6 {
            return Err(refused("imap_list_page_unreadable"));
        }
        Ok(Self {
            folder: number(1)?
                .and_then(|folder| usize::try_from(folder).ok())
                .unwrap_or(0),
            digest: fields[2].to_owned(),
            uid_validity: number(3)?.unwrap_or(0),
            below: number(4)?,
            end: number(5)?,
        })
    }

    fn write(&self) -> String {
        let text = |value: Option<u64>| value.map(|value| format!("{value}")).unwrap_or_default();
        format!(
            "{LIST_PREFIX}:{}:{}:{}:{}:{}",
            self.folder,
            self.digest,
            self.uid_validity,
            text(self.below),
            text(self.end)
        )
    }
}

/// The attributes a header read fetches.
fn header_attributes(session: &ImapSession) -> &'static str {
    if session.has("OBJECTID") {
        "UID FLAGS INTERNALDATE RFC822.SIZE BODY.PEEK[HEADER] THREADID"
    } else {
        "UID FLAGS INTERNALDATE RFC822.SIZE BODY.PEEK[HEADER]"
    }
}

impl ImapMailWire<'_> {
    /// Runs `read` on this wire's session, through the source's credential
    /// at its door: the session opens at the first read and again when the
    /// record presented differs. A failed read closes it.
    fn with_session<T>(
        &self,
        source: &MailSyncSource,
        mut read: impl FnMut(&mut OpenSession) -> Result<T>,
    ) -> Result<T> {
        if source.provider != MailProvider::Imap {
            return Err(refused("imap_mail_wire_reads_imap_mailboxes_only"));
        }
        let mut answer = None;
        self.vault.with_source_token_at_door(
            source,
            WireReads::Mailbox,
            IMAP_CONNECTOR_EFFECTOR,
            &mut |secret: &[u8]| {
                let credential = *blake3::keyed_hash(&self.key, secret).as_bytes();
                let mut slot = self.session.borrow_mut();
                // A session is one source's, signed in with one credential:
                // another source, or a changed record, opens a new one.
                if slot.as_ref().is_none_or(|open| {
                    open.credential != credential || open.source != source.source_ref
                }) {
                    if let Some(old) = slot.take() {
                        old.session.logout();
                    }
                    self.seen.borrow_mut().clear();
                    *slot = Some(open_session(source, secret, credential)?);
                }
                let open = slot
                    .as_mut()
                    .ok_or_else(|| refused("imap_session_unavailable"))?;
                match read(open) {
                    Ok(value) => {
                        answer = Some(value);
                        Ok(())
                    }
                    Err(error) => {
                        *slot = None;
                        self.seen.borrow_mut().clear();
                        Err(error)
                    }
                }
            },
        )?;
        answer.ok_or_else(|| refused("imap_session_unavailable"))
    }

    /// Reads the headers of `uids` in `folder`, keeping each as seen.
    fn read_headers(
        &self,
        open: &mut OpenSession,
        folder: usize,
        status: FolderStatus,
        uids: &[u64],
    ) -> Result<Vec<MailHeaders>> {
        if uids.is_empty() {
            return Ok(Vec::new());
        }
        let attributes = header_attributes(&open.session);
        let fetched = open.session.uid_fetch(&uid_set(uids), attributes)?;
        let place = &open.folders[folder];
        let mut out = Vec::with_capacity(fetched.len());
        for message in &fetched {
            let Some(read) = read_of(message, "BODY[HEADER]") else {
                continue;
            };
            let mut headers =
                headers_of(&read, place, status.uid_validity, vec![place.label.clone()]);
            let mut seen = self.seen.borrow_mut();
            // A message read in several folders carries each of them.
            let at = match seen.get(&headers.provider_id) {
                Some((held, at)) => {
                    let mut labels = held.labels.clone();
                    labels.push(place.label.clone());
                    headers.labels = dedup(labels);
                    *at
                }
                None => Location {
                    folder,
                    uid_validity: status.uid_validity,
                    uid: read.uid,
                },
            };
            seen.insert(headers.provider_id.clone(), (headers.clone(), at));
            drop(seen);
            out.push(headers);
        }
        Ok(out)
    }

    /// The `Message-ID` the vault holds for its copy of `provider_id`, and
    /// the labels it was last seen under; `None` when it holds no copy.
    fn held(
        &self,
        source: &MailSyncSource,
        provider_id: &str,
    ) -> Result<Option<(Option<String>, Vec<String>)>> {
        let txn = self.vault.store.env.read_txn()?;
        Ok(OCCURRENCES
            .get(
                &self.vault.store,
                &txn,
                &occurrence_key(source.source_ref, provider_id),
            )?
            .map(|occurrence| (occurrence.rfc_message_id, occurrence.labels)))
    }

    /// The highest UID in the open `folder` whose own `Message-ID` names
    /// `provider_id`, read a bounded batch at a time: for an id the server
    /// cannot be searched for.
    fn scan_for(
        &self,
        open: &mut OpenSession,
        folder: usize,
        status: FolderStatus,
        provider_id: &str,
    ) -> Result<Option<u64>> {
        let place = open.folders[folder].clone();
        let top = uid_next_of(&mut open.session, status)?;
        let mut best = None;
        let mut low = 1;
        while low < top {
            let high = low.saturating_add(DEPARTURE_BATCH - 1).min(top - 1);
            let fetched = open.session.uid_fetch(
                &format!("{low}:{high}"),
                "UID BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)]",
            )?;
            for message in &fetched {
                if fetched_id(message, &place, status.uid_validity).as_deref() == Some(provider_id)
                {
                    best = best.max(message.uid());
                }
            }
            low = high + 1;
        }
        Ok(best)
    }

    /// Every place the message `provider_id` is now: the folders it was last
    /// seen in first; with `all`, every folder, else the first place found.
    fn locate(
        &self,
        open: &mut OpenSession,
        source: &MailSyncSource,
        provider_id: &str,
        all: bool,
    ) -> Result<Vec<Location>> {
        if !all {
            let seen = self.seen.borrow().get(provider_id).map(|(_, at)| *at);
            if let Some(at) = seen {
                if self.still_at(open, provider_id, at)? {
                    return Ok(vec![at]);
                }
                // Moved or gone since it was read: look for it again.
                self.seen.borrow_mut().remove(provider_id);
            }
        }
        if let Some(place) = provider_id.strip_prefix("imapuid.") {
            let mut fields = place.split('.');
            let (Some(digest), Some(uid_validity), Some(uid)) = (
                fields.next(),
                fields.next().and_then(|value| value.parse::<u64>().ok()),
                fields.next().and_then(|value| value.parse::<u64>().ok()),
            ) else {
                return Ok(Vec::new());
            };
            let Some(folder) = open
                .folders
                .iter()
                .position(|folder| folder.digest == digest)
            else {
                return Ok(Vec::new());
            };
            let name = open.folders[folder].name.clone();
            let status = open.session.examine(&name)?;
            if status.uid_validity != uid_validity
                || open.session.uid_search(&format!("UID {uid}"))?.first() != Some(&uid)
            {
                return Ok(Vec::new());
            }
            return Ok(vec![Location {
                folder,
                uid_validity,
                uid,
            }]);
        }
        let Some((message_id, labels)) = self.held(source, provider_id)? else {
            // The vault holds no copy: nothing to look for.
            return Ok(Vec::new());
        };
        // A copy whose Message-ID the vault does not hold cannot be looked
        // for, and not finding it is no sign it is gone.
        let message_id = message_id.ok_or_else(|| refused("imap_message_not_locatable"))?;
        // One the server cannot be searched for is read folder by folder.
        let criterion = search_string(&message_id);
        let mut order: Vec<usize> = (0..open.folders.len()).collect();
        order.sort_by_key(|&at| {
            let folder = &open.folders[at];
            (!labels.contains(&folder.label), !folder.read())
        });
        let mut found = Vec::new();
        for folder in order {
            let name = open.folders[folder].name.clone();
            let status = open.session.examine(&name)?;
            let hit = match &criterion {
                Some(criterion) => {
                    let uids = open
                        .session
                        .uid_search(&format!("HEADER Message-ID {criterion}"))?;
                    // The search matches a substring: a hit is taken only
                    // when its own Message-ID is the one asked for.
                    self.exact_hit(open, folder, status, &uids, provider_id)?
                }
                None => self.scan_for(open, folder, status, provider_id)?,
            };
            if let Some(uid) = hit {
                found.push(Location {
                    folder,
                    uid_validity: status.uid_validity,
                    uid,
                });
                if !all && open.folders[folder].read() {
                    break;
                }
            }
        }
        Ok(found)
    }

    /// Whether the message read at `at` is there still.
    fn still_at(&self, open: &mut OpenSession, provider_id: &str, at: Location) -> Result<bool> {
        let name = open.folders[at.folder].name.clone();
        let status = open.session.examine(&name)?;
        if status.uid_validity != at.uid_validity {
            return Ok(false);
        }
        let uids = open.session.uid_search(&format!("UID {}", at.uid))?;
        if uids.first() != Some(&at.uid) {
            return Ok(false);
        }
        // A place id names the place itself; a content id is checked.
        if provider_id.starts_with("imapuid.") {
            return Ok(true);
        }
        Ok(self
            .exact_hit(open, at.folder, status, &[at.uid], provider_id)?
            .is_some())
    }

    /// The highest of `uids` in the open `folder` whose own `Message-ID`
    /// names `provider_id`.
    fn exact_hit(
        &self,
        open: &mut OpenSession,
        folder: usize,
        status: FolderStatus,
        uids: &[u64],
        provider_id: &str,
    ) -> Result<Option<u64>> {
        // Every hit is checked, a bounded batch at a time: an unchecked
        // hit is no evidence that the message is gone.
        let place = open.folders[folder].clone();
        let mut best = None;
        for batch in uids.chunks(HIT_BATCH) {
            let fetched = open
                .session
                .uid_fetch(&uid_set(batch), "UID BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)]")?;
            for message in &fetched {
                if fetched_id(message, &place, status.uid_validity).as_deref() == Some(provider_id)
                {
                    best = best.max(message.uid());
                }
            }
        }
        Ok(best)
    }

    /// The headers and the whole message at the first place `provider_id`
    /// is; a message too large to read whole comes with its headers alone.
    fn whole(
        &self,
        open: &mut OpenSession,
        source: &MailSyncSource,
        provider_id: &str,
    ) -> Result<Option<(MailHeaders, Vec<u8>)>> {
        let places = self.locate(open, source, provider_id, false)?;
        let Some(&at) = places.first() else {
            return Ok(None);
        };
        let name = open.folders[at.folder].name.clone();
        let status = open.session.examine(&name)?;
        if status.uid_validity != at.uid_validity {
            return Ok(None);
        }
        let uid = at.uid.to_string();
        let sized = open.session.uid_fetch(&uid, "UID RFC822.SIZE")?;
        let Some(size) = sized
            .iter()
            .find(|message| message.uid() == Some(at.uid))
            .and_then(|message| message.value("RFC822.SIZE").and_then(Item::number))
        else {
            return Ok(None);
        };
        let whole = size <= MAX_MESSAGE_BYTES;
        let (section, returned) = if whole {
            ("BODY.PEEK[]", "BODY[]")
        } else {
            ("BODY.PEEK[HEADER]", "BODY[HEADER]")
        };
        let thread = if open.session.has("OBJECTID") {
            " THREADID"
        } else {
            ""
        };
        let fetched = open
            .session
            .uid_fetch(&uid, &format!("UID FLAGS INTERNALDATE {section}{thread}"))?;
        let Some(read) = fetched
            .iter()
            .find(|message| message.uid() == Some(at.uid))
            .and_then(|message| read_of(message, returned))
        else {
            return Ok(None);
        };
        // The labels it has landed with stay, with this folder: a body read
        // in one folder takes no other folder away.
        let folder = &open.folders[at.folder];
        let mut labels = self.landed_labels(source, provider_id)?.unwrap_or_default();
        labels.push(folder.label.clone());
        let headers = headers_of(&read, folder, at.uid_validity, dedup(labels));
        let raw = if whole { read.raw.to_vec() } else { Vec::new() };
        Ok(Some((headers, raw)))
    }

    /// The headers of the message at `at`.
    fn headers_at(&self, open: &mut OpenSession, at: Location) -> Result<Option<MailHeaders>> {
        let name = open.folders[at.folder].name.clone();
        let status = open.session.examine(&name)?;
        if status.uid_validity != at.uid_validity {
            return Ok(None);
        }
        let attributes = header_attributes(&open.session);
        let fetched = open.session.uid_fetch(&at.uid.to_string(), attributes)?;
        let folder = &open.folders[at.folder];
        Ok(fetched
            .iter()
            .find(|message| message.uid() == Some(at.uid))
            .and_then(|message| read_of(message, "BODY[HEADER]"))
            .map(|read| headers_of(&read, folder, at.uid_validity, vec![folder.label.clone()])))
    }

    /// The copies labelled with `folder` that it no longer holds below
    /// `uid_next` (the top of the last read), each as the change it is: moved (its folders now), or
    /// deleted at the provider (in trash or junk, or nowhere).
    fn departures(
        &self,
        open: &mut OpenSession,
        source: &MailSyncSource,
        folder: usize,
        uid_next: u64,
        changes: &mut Vec<MailHistoryChange>,
        pending: &mut BTreeMap<String, Vec<String>>,
    ) -> Result<()> {
        let place = open.folders[folder].clone();
        let status = open.session.examine(&place.name)?;
        let held = self.held_below(open, source.source_ref, &place, status, uid_next)?;
        let gone: Vec<String> = {
            let txn = self.vault.store.env.read_txn()?;
            let mut gone = Vec::new();
            for occurrence in
                OCCURRENCES.iter_from(&self.vault.store, &txn, source.source_ref.as_bytes())?
            {
                let (_, occurrence) = occurrence?;
                if matches!(occurrence.presence, MailPresence::Present)
                    && occurrence.labels.contains(&place.label)
                    && !held.contains(&occurrence.provider_id)
                {
                    gone.push(occurrence.provider_id);
                }
            }
            gone
        };
        for provider_id in gone {
            let places = self.locate(open, source, &provider_id, true)?;
            let kept: Vec<String> = places
                .iter()
                .filter(|at| open.folders[at.folder].read())
                .map(|at| open.folders[at.folder].label.clone())
                .collect();
            if kept.is_empty() {
                pending.remove(&provider_id);
                changes.push(MailHistoryChange::Deleted { provider_id });
            } else {
                // Where it is now: the labels later folders of this read
                // build on.
                let labels = dedup(kept);
                pending.insert(provider_id.clone(), labels.clone());
                changes.push(MailHistoryChange::Labels {
                    provider_id,
                    labels,
                    trash_or_spam: false,
                });
            }
        }
        Ok(())
    }
}

impl ImapMailWire<'_> {
    /// The ids of the messages the open `place` holds below `top`: the UIDs
    /// one search answers, each named from the UID map, and only the UIDs
    /// the map does not hold read for their `Message-ID`, a bounded batch at
    /// a time. The map learns those, and forgets the UIDs the folder no
    /// longer holds and the rows of an older UIDVALIDITY.
    fn held_below(
        &self,
        open: &mut OpenSession,
        source: EntityId,
        place: &Folder,
        status: FolderStatus,
        top: u64,
    ) -> Result<BTreeSet<String>> {
        let mut held = BTreeSet::new();
        if top <= 1 {
            return Ok(held);
        }
        let present = open.session.uid_ranges(1, top - 1)?;
        let folder_key = *blake3::hash(place.digest.as_bytes()).as_bytes();
        let mut prefix = source.as_bytes().to_vec();
        prefix.extend_from_slice(&folder_key);
        let mapped = {
            let txn = self.vault.store.env.read_txn()?;
            UIDS.iter_from(&self.vault.store, &txn, &prefix)?
                .collect::<Result<Vec<_>>>()?
        };
        let mut known = BTreeSet::new();
        let mut stale = Vec::new();
        for ((_, _, uid), row) in mapped {
            if row.uid_validity != status.uid_validity {
                stale.push(uid);
            } else if ranges_hold(&present, uid) {
                known.insert(uid);
                held.insert(row.provider_id);
            } else if uid < top {
                stale.push(uid);
            }
        }
        let unknown = without(&present, &known);
        for batch in (UidBatches {
            ranges: unknown.iter(),
            current: None,
        }) {
            let fetched = open.session.uid_fetch(
                &range_set(&batch),
                "UID BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)]",
            )?;
            let learned: Vec<(u64, String)> = fetched
                .iter()
                .filter_map(|message| {
                    let uid = message.uid().filter(|&uid| uid < top)?;
                    // Only an answer that carries the section asked for
                    // names the message: an unsolicited update (its flags)
                    // carries none.
                    message
                        .value_starting("BODY[HEADER.FIELDS")
                        .and_then(Item::bytes)?;
                    Some((uid, fetched_id(message, place, status.uid_validity)?))
                })
                .collect();
            held.extend(learned.iter().map(|(_, id)| id.clone()));
            self.remember_uids(source, folder_key, status.uid_validity, learned)?;
        }
        self.forget_uids(source, folder_key, &stale)?;
        Ok(held)
    }

    /// Records which message each of the `learned` UIDs of a folder holds.
    fn remember_uids(
        &self,
        source: EntityId,
        folder_key: [u8; 32],
        uid_validity: u64,
        learned: Vec<(u64, String)>,
    ) -> Result<()> {
        if learned.is_empty() {
            return Ok(());
        }
        self.vault.with_write_txn_grouped(|txn| {
            for (uid, provider_id) in learned {
                let row = HeldUid {
                    uid_validity,
                    provider_id,
                };
                UIDS.put(&self.vault.store, txn, &(source, folder_key, uid), &row)?;
            }
            Ok(())
        })
    }

    /// Forgets the rows of a folder's `uids`.
    fn forget_uids(&self, source: EntityId, folder_key: [u8; 32], uids: &[u64]) -> Result<()> {
        if uids.is_empty() {
            return Ok(());
        }
        self.vault.with_write_txn_grouped(|txn| {
            for uid in uids {
                UIDS.delete(&self.vault.store, txn, &(source, folder_key, *uid))?;
            }
            Ok(())
        })
    }
}

/// The UIDs of ascending `ranges` not in `known`, as ascending ranges.
fn without(ranges: &[(u64, u64)], known: &BTreeSet<u64>) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    for &(low, high) in ranges {
        let mut start = low;
        for &uid in known.range(low..=high) {
            if uid > start {
                out.push((start, uid - 1));
            }
            start = uid + 1;
        }
        if start <= high {
            out.push((start, high));
        }
    }
    out
}

/// Ascending UID ranges cut into batches of at most `DEPARTURE_BATCH` UIDs
/// and `MAX_SET_RANGES` ranges, as one fetch names them.
struct UidBatches<'r> {
    ranges: std::slice::Iter<'r, (u64, u64)>,
    /// What is left of a range the last batch cut.
    current: Option<(u64, u64)>,
}

impl Iterator for UidBatches<'_> {
    type Item = Vec<(u64, u64)>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut batch = Vec::new();
        let mut span = 0;
        while span < DEPARTURE_BATCH && batch.len() < MAX_SET_RANGES {
            let Some((low, high)) = self.current.take().or_else(|| self.ranges.next().copied())
            else {
                break;
            };
            let take = (high - low + 1).min(DEPARTURE_BATCH - span);
            batch.push((low, low + take - 1));
            span += take;
            if low + take <= high {
                self.current = Some((low + take, high));
            }
        }
        (!batch.is_empty()).then_some(batch)
    }
}

/// The id of a message fetched with its `Message-ID` field.
fn fetched_id(message: &Fetched, folder: &Folder, uid_validity: u64) -> Option<String> {
    let uid = message.uid()?;
    Some(
        message
            .value_starting("BODY[HEADER.FIELDS")
            .and_then(Item::bytes)
            .and_then(|raw| MimeMessage::parse(raw).header("message-id"))
            .filter(|id| !id.is_empty())
            .map_or_else(|| place_id(folder, uid_validity, uid), |id| content_id(&id)),
    )
}

fn dedup(mut labels: Vec<String>) -> Vec<String> {
    labels.sort();
    labels.dedup();
    labels
}

/// `message_id` quoted as a `SEARCH` string, when it can be one.
fn search_string(message_id: &str) -> Option<String> {
    if message_id.is_empty()
        || message_id.len() > 998
        || message_id.chars().any(|c| c.is_control() || !c.is_ascii())
    {
        return None;
    }
    let escaped = message_id.replace('\\', "\\\\").replace('"', "\\\"");
    Some(format!("\"{escaped}\""))
}

/// Opens a session with the credential `secret` for `source`.
fn open_session(
    source: &MailSyncSource,
    secret: &[u8],
    credential: [u8; 32],
) -> Result<OpenSession> {
    let stored: ImapCredential =
        serde_json::from_slice(secret).map_err(|_| refused("imap_credential_unreadable"))?;
    let host = stored.host.trim().to_ascii_lowercase();
    if host.is_empty()
        || host.len() > 253
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(refused("imap_credential_host_invalid"));
    }
    // The credential reads the account the source names, and no other: its
    // user exactly, as a server may tell case apart, and its host.
    let reads_account = source
        .provider_account
        .rsplit_once('@')
        .is_some_and(|(user, named)| user == stored.username && named.eq_ignore_ascii_case(&host));
    if !reads_account {
        return Err(refused("imap_credential_reads_another_account"));
    }
    let starttls = stored
        .security
        .map_or(stored.port == Some(143), |security| {
            security == ImapSecurity::Starttls
        });
    let port = stored.port.unwrap_or(if starttls { 143 } else { 993 });
    let mut session = ImapSession::connect(&host, port, starttls)?;
    session.authenticate(
        &stored.username,
        stored.password.as_deref(),
        stored.access_token.as_deref(),
    )?;
    let folders = folders_of(session.list()?)?;
    Ok(OpenSession {
        session,
        source: source.source_ref,
        credential,
        folders,
    })
}

impl MailProviderWire for ImapMailWire<'_> {
    fn current_anchor(&self, source: &MailSyncSource) -> Result<String> {
        self.with_session(source, |open| {
            let mut marks = BTreeMap::new();
            let folders: Vec<Folder> = open.folders.iter().filter(|f| f.read()).cloned().collect();
            for folder in folders {
                let status = open.session.examine(&folder.name)?;
                let top = uid_next_of(&mut open.session, status)?;
                marks.insert(
                    folder.digest,
                    Mark {
                        uid_validity: status.uid_validity,
                        uid_next: top,
                        top,
                        exists: status.exists,
                    },
                );
            }
            Ok(write_anchor(&marks))
        })
    }

    fn list_page(
        &self,
        source: &MailSyncSource,
        query: &MailListQuery,
        page: Option<&str>,
    ) -> Result<MailIdPage> {
        let mut cursor = ListCursor::parse(page)?;
        let marks = self.anchor_marks(source)?;
        self.with_session(source, |open| {
            let read: Vec<usize> = (0..open.folders.len())
                .filter(|&at| open.folders[at].read())
                .collect();
            // The folder the page names, found again by its digest when the
            // folders changed meanwhile.
            let place = read
                .iter()
                .position(|&at| open.folders[at].digest == cursor.digest)
                .unwrap_or(cursor.folder);
            let Some(&folder) = read.get(place) else {
                return Ok(MailIdPage::default());
            };
            if open.folders[folder].digest != cursor.digest {
                cursor = ListCursor {
                    folder: place,
                    digest: open.folders[folder].digest.clone(),
                    ..ListCursor::default()
                };
            }
            let name = open.folders[folder].name.clone();
            let status = open.session.examine(&name)?;
            if status.uid_validity != cursor.uid_validity {
                cursor.uid_validity = status.uid_validity;
                cursor.below = None;
                cursor.end = None;
            }
            let below = cursor.below;
            // The listing copies only what the change anchor stands past: a
            // message above its frontier comes through the change feed,
            // which also sees it leave (a folder the anchor does not hold,
            // or holds under another UIDVALIDITY, comes that way whole).
            let frontier = marks.as_ref().map(|marks| {
                marks
                    .get(&open.folders[folder].digest)
                    .filter(|mark| mark.uid_validity == status.uid_validity)
                    .map_or(1, |mark| mark.uid_next)
            });
            let listed = |uid: u64| {
                below.is_none_or(|below| uid < below)
                    && frontier.is_none_or(|frontier| uid < frontier)
            };
            let (mut uids, more, end) = match query.newer_than {
                Some(after) => {
                    // SINCE reads a day in the server's own zone: a day early,
                    // the copy setting's exact cutoff applies to each
                    // message's received time.
                    let since = search_date(after.saturating_sub(86_400))
                        .ok_or_else(|| refused("imap_cutoff_unreadable"))?;
                    let mut uids = open.session.uid_search(&format!("SINCE {since}"))?;
                    uids.retain(|&uid| listed(uid));
                    let start = uids
                        .len()
                        .saturating_sub(usize::try_from(LIST_PAGE).unwrap_or(usize::MAX));
                    let more = start > 0;
                    (uids.split_off(start), more, None)
                }
                None => {
                    // Sequence numbers run in UID order, and only an expunge
                    // below moves them, down: a page ending at the last one
                    // read again reads no message twice past the UID filter
                    // and skips none.
                    let end = cursor.end.unwrap_or(status.exists).min(status.exists);
                    if end == 0 {
                        (Vec::new(), false, None)
                    } else {
                        let start = end.saturating_sub(LIST_PAGE - 1).max(1);
                        let fetched = open.session.fetch_sequence(start, end, "UID")?;
                        let uids: Vec<u64> = fetched
                            .iter()
                            .filter_map(Fetched::uid)
                            .filter(|&uid| listed(uid))
                            .collect();
                        (uids, start > 1, Some(start - 1))
                    }
                }
            };
            uids.sort_unstable();
            uids.dedup();
            let mut headers = self.read_headers(open, folder, status, &uids)?;
            // Newest first, by when the mailbox received each.
            headers.sort_by_key(|headers| std::cmp::Reverse(headers.received_at));
            let messages: Vec<MailMessageRef> = headers
                .into_iter()
                .map(|headers| MailMessageRef {
                    provider_id: headers.provider_id,
                    thread_id: headers.thread_id,
                })
                .collect();
            let next = if more {
                ListCursor {
                    below: uids.first().copied().or(below),
                    end: end.filter(|&end| end > 0),
                    ..cursor.clone()
                }
            } else {
                let next = place + 1;
                match read.get(next) {
                    Some(&folder) => ListCursor {
                        folder: next,
                        digest: open.folders[folder].digest.clone(),
                        ..ListCursor::default()
                    },
                    None => {
                        return Ok(MailIdPage {
                            messages,
                            next_page: None,
                        });
                    }
                }
            };
            Ok(MailIdPage {
                messages,
                next_page: Some(next.write()),
            })
        })
    }

    fn headers(&self, source: &MailSyncSource, provider_id: &str) -> Result<Option<MailHeaders>> {
        self.with_session(source, |open| {
            let seen = self
                .seen
                .borrow()
                .get(provider_id)
                .map(|(headers, _)| headers.clone());
            if let Some(headers) = seen {
                return Ok(Some(headers));
            }
            let places = self.locate(open, source, provider_id, true)?;
            let Some(&first) = places
                .iter()
                .find(|at| open.folders[at.folder].read())
                .or_else(|| places.first())
            else {
                return Ok(None);
            };
            let Some(mut headers) = self.headers_at(open, first)? else {
                return Ok(None);
            };
            let kept: Vec<String> = places
                .iter()
                .filter(|at| open.folders[at.folder].read())
                .map(|at| open.folders[at.folder].label.clone())
                .collect();
            if !kept.is_empty() {
                headers.labels = dedup(kept);
            }
            Ok(Some(headers))
        })
    }

    fn full(&self, source: &MailSyncSource, provider_id: &str) -> Result<Option<MailFull>> {
        self.with_session(source, |open| {
            let Some((headers, raw)) = self.whole(open, source, provider_id)? else {
                return Ok(None);
            };
            if raw.is_empty() {
                return Ok(Some(MailFull {
                    headers,
                    body_text: None,
                    attachments: Vec::new(),
                }));
            }
            let body = MimeMessage::parse(&raw).body();
            Ok(Some(MailFull {
                headers,
                body_text: body.text,
                attachments: body.attachments,
            }))
        })
    }

    fn history(
        &self,
        source: &MailSyncSource,
        anchor: &str,
        _page: Option<&str>,
    ) -> Result<MailHistoryRead> {
        let Some(marks) = parse_anchor(anchor) else {
            return Ok(MailHistoryRead::Expired);
        };
        self.with_session(source, |open| {
            let mut changes = Vec::new();
            let mut reached = BTreeMap::new();
            // Each message's labels as this read has set them so far.
            let mut pending: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for (at, folder) in open.folders.clone().into_iter().enumerate() {
                if !folder.read() {
                    continue;
                }
                let status = open.session.examine(&folder.name)?;
                // A folder new since the anchor: all its mail is added.
                let mark = marks.get(&folder.digest).copied().unwrap_or(Mark {
                    uid_validity: status.uid_validity,
                    uid_next: 1,
                    top: 1,
                    exists: 0,
                });
                if mark.uid_validity != status.uid_validity {
                    return Ok(MailHistoryRead::Expired);
                }
                let uid_next = uid_next_of(&mut open.session, status)?;
                let mut new = if uid_next > mark.uid_next {
                    open.session
                        .uid_search(&format!("UID {}:*", mark.uid_next))?
                } else {
                    Vec::new()
                };
                new.retain(|&uid| uid >= mark.uid_next);
                // Of the messages the folder held at the last read, those it
                // holds now: each one at or past that read's top arrived since.
                let arrived = new.iter().filter(|&&uid| uid >= mark.top).count();
                let still_held = status
                    .exists
                    .saturating_sub(u64::try_from(arrived).unwrap_or(u64::MAX));
                let taken: Vec<u64> = new.iter().copied().take(NEW_PER_FOLDER).collect();
                for headers in self.read_headers(open, at, status, &taken)? {
                    // A message already landed, filed here too, carries this
                    // folder as well, over the labels this read gave it.
                    let landed = match pending.get(&headers.provider_id) {
                        Some(labels) => Some(labels.clone()),
                        None => self.landed_labels(source, &headers.provider_id)?,
                    };
                    match landed {
                        Some(labels) if labels.contains(&folder.label) => {}
                        Some(mut labels) => {
                            labels.push(folder.label.clone());
                            let labels = dedup(labels);
                            pending.insert(headers.provider_id.clone(), labels.clone());
                            changes.push(MailHistoryChange::Labels {
                                provider_id: headers.provider_id,
                                labels,
                                trash_or_spam: false,
                            });
                        }
                        None => changes.push(MailHistoryChange::Added(MailMessageRef {
                            provider_id: headers.provider_id,
                            thread_id: headers.thread_id,
                        })),
                    }
                }
                if still_held < mark.exists {
                    self.departures(open, source, at, mark.top, &mut changes, &mut pending)?;
                }
                let next = match taken.last() {
                    Some(&last) if taken.len() < new.len() => last + 1,
                    _ => uid_next.max(mark.uid_next),
                };
                reached.insert(
                    folder.digest,
                    Mark {
                        uid_validity: status.uid_validity,
                        uid_next: next,
                        top: uid_next.max(mark.top),
                        exists: status.exists,
                    },
                );
            }
            // A folder gone since the anchor: each copy under it is looked
            // up again.
            for digest in marks.keys().filter(|digest| !reached.contains_key(*digest)) {
                for label in self.labels_with_digest(source, digest)? {
                    changes.push(MailHistoryChange::LabelGone { label });
                }
            }
            Ok(MailHistoryRead::Page(MailHistoryPage {
                changes,
                next_page: None,
                anchor: write_anchor(&reached),
            }))
        })
    }

    fn listed_labels(&self, provider_id: &str) -> Option<Vec<String>> {
        self.seen
            .borrow()
            .get(provider_id)
            .map(|(headers, _)| headers.labels.clone())
    }

    fn attachment(
        &self,
        source: &MailSyncSource,
        provider_id: &str,
        attachment: &MailAttachmentRef,
    ) -> Result<Option<Vec<u8>>> {
        self.with_session(source, |open| {
            let Some((_, raw)) = self.whole(open, source, provider_id)? else {
                return Ok(None);
            };
            Ok(MimeMessage::parse(&raw).part_bytes(&attachment.part_id))
        })
    }
}

impl ImapMailWire<'_> {
    /// The change anchor the source stands at, per folder, as the importer
    /// keeps it; `None` before it has one.
    fn anchor_marks(&self, source: &MailSyncSource) -> Result<Option<BTreeMap<String, Mark>>> {
        let txn = self.vault.store.env.read_txn()?;
        Ok(SYNC
            .get(&self.vault.store, &txn, &source.source_ref)?
            .and_then(|state| state.anchor)
            .and_then(|anchor| parse_anchor(&anchor)))
    }

    /// The labels of the source's live copy of `provider_id`, when it has
    /// landed one.
    fn landed_labels(
        &self,
        source: &MailSyncSource,
        provider_id: &str,
    ) -> Result<Option<Vec<String>>> {
        let txn = self.vault.store.env.read_txn()?;
        Ok(OCCURRENCES
            .get(
                &self.vault.store,
                &txn,
                &occurrence_key(source.source_ref, provider_id),
            )?
            .filter(|occurrence| matches!(occurrence.presence, MailPresence::Present))
            .map(|occurrence| occurrence.labels))
    }

    /// The labels the source's copies carry whose digest is `digest`.
    fn labels_with_digest(&self, source: &MailSyncSource, digest: &str) -> Result<Vec<String>> {
        let txn = self.vault.store.env.read_txn()?;
        let mut labels = BTreeSet::new();
        for occurrence in
            OCCURRENCES.iter_from(&self.vault.store, &txn, source.source_ref.as_bytes())?
        {
            let (_, occurrence) = occurrence?;
            for label in occurrence.labels {
                if digest_of(&label) == digest {
                    labels.insert(label);
                }
            }
        }
        Ok(labels.into_iter().collect())
    }
}

/// The open folder's UIDNEXT, read from its highest UID when the server
/// did not say it.
fn uid_next_of(session: &mut ImapSession, status: FolderStatus) -> Result<u64> {
    if status.uid_next > 0 {
        return Ok(status.uid_next);
    }
    if status.exists == 0 {
        return Ok(1);
    }
    let last = session.uid_search("ALL")?.last().copied().unwrap_or(0);
    last.checked_add(1)
        .ok_or_else(|| refused("imap_response_malformed"))
}
