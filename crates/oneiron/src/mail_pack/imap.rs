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
//! - **Ids.** A message is named by what it is, never by the `Message-ID`
//!   its sender set alone (fix list rows 19145, 20917): its copies in
//!   several folders share one id, and two messages never do. A server's
//!   own id, or the digest of the whole message, is the proof; a header
//!   block only proposes an id.
//!   - Where the server announces Gmail's `X-GM-EXT-1`, the id is Gmail's
//!     own `X-GM-MSGID`, as hex, as the Gmail API and a Takeout export name
//!     it.
//!   - Where it announces `OBJECTID` (RFC 8474), the id is `emailid.` and
//!     the server's `EMAILID`, which it keeps for every copy of a message
//!     and never gives another message; but a message whose header block
//!     proposes a header id (below) the vault holds a copy under (an mbox
//!     import's, or one a sync named before the server announced
//!     `OBJECTID`) is read whole once, and named by that header id when its
//!     digest is the copy's, or by the digest id of the copy of its own
//!     digest when the vault holds one. A forgotten copy nothing proves it
//!     apart from (no digest kept, or its bytes unreadable) holds its fence:
//!     it is named by that header id too, and lands no more.
//!   - Elsewhere the header block proposes the id, as an mbox import names
//!     a message: `mbox` and the first 32 hex of the BLAKE3 of its
//!     `Message-ID`, the SHA-256 of its unfolded header block and its
//!     `RFC822.SIZE`. When another folder or UID holds the same header id
//!     (one this session named, or one the UID map names, landed or not),
//!     or a copy the vault landed does, the BLAKE3 of the two whole
//!     messages (each line ended by CRLF) decides: equal, they are one
//!     message; different, or with no copy of the other left to read, the
//!     new one is its own message, named `mboxdigest` and the first 32 hex
//!     of the BLAKE3 of the header id and its digest. A message is read
//!     whole for this only on such a collision, and the UID map keeps the
//!     id each UID was given, and each place it gives a header id, so a
//!     place is never named two ways and no session gives one id to two
//!     messages. Where the vault's copy is forgotten and no digest of it is
//!     left (it was forgotten by its headers only), nothing proves the new
//!     one another message: the fence holds, and it is named by the header
//!     id and lands no more.
//!   - One with no `Message-ID`, or whose bytes cannot be read for that
//!     proof, is named by where it is:
//!     `imapuid.<folder digest>.<UIDVALIDITY>.<UID>` (but a forgotten copy
//!     under its header id holds, as above).
//!   - On every server a UID the UID map holds keeps the id it was given,
//!     and every read names a UID alike: the listing, the change feed, the
//!     expunge scan, a search, and a message looked for.
//!   - A message a header id names (an mbox import's, on any server) is
//!     read whole only where its whole digest is the one the vault keeps of
//!     it, or where the UID map gives it that id: with neither, a server
//!     that names messages itself refuses to look for it (never read as
//!     deleted), and another message's bytes never come back under it.
//! - **Folders are labels.** Every selectable folder is read but drafts and
//!   the flagged and important views; trash and junk are looked in only to
//!   see that a message went there. The all-mail view (`\All`, Gmail's All
//!   Mail) is read last (fix list row 19144), so a message filed under no
//!   label lands too, but its name is no label: a message's labels are the
//!   other folders that hold it, and it is gone only when no folder does.
//! - **Changes.** The anchor holds each folder's UIDVALIDITY, UIDNEXT and the
//!   count of messages below it. New UIDs are added mail; a folder holding
//!   fewer of its old messages than it did lost some, and each copy labelled
//!   with it that it no longer holds is looked for in the other folders:
//!   moved, it carries its new folders; in trash or junk, or nowhere, it was
//!   deleted at the provider. A changed UIDVALIDITY expires the anchor.
//! - **What a folder holds.** The wire keeps which message each UID of a
//!   folder it read holds (fix list row 17871): a folder that lost mail is
//!   checked by one UID search, and only the UIDs it never read are fetched
//!   for what names their messages, not every message in the folder. Where
//!   the server names each message itself (Gmail, `OBJECTID`), the
//!   all-mail view reads only those ids of the messages the labelled
//!   folders landed, never their headers again.
//! - **Search.** `vault.mail.sources.search` (fix list row 19089) sends the
//!   caller's `SEARCH` keys (RFC 3501 6.4.4) to each folder it reads, newest
//!   hits first, a bounded number of folders a page. A quoted string past
//!   ASCII goes as a UTF-8 literal the server takes without a round trip
//!   (RFC 7888); a server that takes none is told the search needs ASCII.
//!
//! Call it from a blocking context: each call is socket I/O.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::credential::WireReads;
use super::gmail::rfc2822_seconds;
use super::imap_client::{
    Fetched, FolderStatus, ImapSession, Item, ListedFolder, decode_mailbox_name, range_set,
    ranges_hold, uid_set,
};
use super::mime::MimeMessage;
use super::rest::refused;
use super::source::MailProvider;
use super::state::{MailOccurrence, MailPresence, OCCURRENCES, SYNC, occurrence_key};
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
/// The UIDs one read of Gmail's own ids of them (`X-GM-MSGID`) covers.
const SERVER_ID_BATCH: u64 = 2_000;
/// The UIDs one read of their header blocks covers: each answer carries a
/// whole block.
const HEADER_BLOCK_BATCH: u64 = 500;
/// The most UID ranges one such read names, so its command line stays short.
const MAX_SET_RANGES: usize = 200;
/// The search hits one read of what names them checks.
const HIT_BATCH: usize = 64;
/// The largest message read whole: a bigger one lands by its headers, and
/// is read a part this large at a time for a proof.
const MAX_MESSAGE_BYTES: u64 = 40 * 1024 * 1024;
/// The most folders one proof that two copies are one message looks in for
/// the copy the vault holds.
const PROOF_FOLDERS: usize = 16;
/// The most places the UID map names a header id at that one proof reads.
const PROOF_PLACES: usize = 16;
/// The prefix of an id from the server's `EMAILID` (RFC 8474).
const EMAIL_ID_PREFIX: &str = "emailid.";
/// The prefix of an id a header block gives: a header id, a digest id, or
/// an mbox import's id of a message with no `Message-ID`.
const HEADER_ID_PREFIX: &str = "mbox";
/// The prefix of an id from a message's header id and its own whole digest.
const DIGEST_ID_PREFIX: &str = "mboxdigest";
/// The BLAKE3 context of such an id.
const DIGEST_ID_CONTEXT: &str = "oneiron mail_pack imap digest id v1";
/// The prefix of an anchor this wire writes.
const ANCHOR_PREFIX: &str = "imap2";
/// The prefix of a listing page this wire writes.
const LIST_PREFIX: &str = "imap1";
/// The prefix of a search page this wire writes.
const SEARCH_PREFIX: &str = "imaps1";
/// The most folders one search page looks in: a mailbox with more answers
/// the rest on the next pages.
const SEARCH_FOLDERS_PER_PAGE: usize = 25;
/// The longest literal a server announcing `LITERAL-` takes without a round
/// trip (RFC 7888).
const LITERAL_MINUS_MAX: usize = 4096;

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

/// Each place the UID map gives an id a header block gives (fix list row
/// 19145): by the source, the BLAKE3 of the id, and the place (the UID
/// map's key of its folder and the UID). A later place whose header id the
/// map gives a place already is a collision, proved by digest before it is
/// named, whichever session named the first and whether or not it landed.
/// Written and deleted with the UID map's rows, which stay the truth of
/// each place.
const ID_PLACES: SideTable<(EntityId, [u8; 32], ([u8; 32], u64)), IdPlace, Named> =
    SideTable::new(&side_table::MAIL_PACK_IMAP_ID_PLACE);

/// A place the UID map gives an id: its folder's UIDVALIDITY.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct IdPlace {
    uid_validity: u64,
}

/// Whether `provider_id` is an id a header block gives, which the digest of
/// its whole message proves (fix list row 19145).
fn named_by_header(provider_id: &str) -> bool {
    provider_id.starts_with(HEADER_ID_PREFIX)
}

/// The key prefix of the places [`ID_PLACES`] files `provider_id` under for
/// `source`.
fn id_places_prefix(source: EntityId, provider_id: &str) -> Vec<u8> {
    let mut prefix = source.as_bytes().to_vec();
    prefix.extend_from_slice(blake3::hash(provider_id.as_bytes()).as_bytes());
    prefix
}

/// The key of one place of `provider_id` in [`ID_PLACES`].
fn id_place_key(
    source: EntityId,
    provider_id: &str,
    folder_key: [u8; 32],
    uid: u64,
) -> (EntityId, [u8; 32], ([u8; 32], u64)) {
    (
        source,
        *blake3::hash(provider_id.as_bytes()).as_bytes(),
        (folder_key, uid),
    )
}

/// Whether the UID map of the IMAP source `source` gives `provider_id`, an
/// id a header block gives, to any place (fix list row 19145): a copy an
/// mbox import cannot read, so an entry proposing that id is proved the
/// same by no digest.
///
/// # Errors
///
/// Storage failures.
pub(super) fn imap_id_mapped(vault: &Vault, source: EntityId, provider_id: &str) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    let mapped = ID_PLACES
        .iter_from(&vault.store, &txn, &id_places_prefix(source, provider_id))?
        .next()
        .transpose()?
        .is_some();
    Ok(mapped)
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
    /// Where the mailbox submits mail: what its drafted replies are sent
    /// through (fix list row 17872).
    #[serde(default)]
    submission: Option<SubmissionConfig>,
}

/// The submission server (RFC 6409) of an IMAP mailbox: the same account,
/// its own host.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmissionConfig {
    host: String,
    #[serde(default)]
    port: Option<u16>,
    /// `tls` (port 465) or `starttls` (port 587, the default).
    #[serde(default)]
    security: Option<ImapSecurity>,
}

/// The submission account an IMAP source's credential names, checked as
/// its read is checked: the source's own account.
pub(super) struct SubmissionAccount {
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) security: super::smtp_client::SmtpSecurity,
    pub(super) username: String,
    pub(super) password: Option<String>,
    pub(super) access_token: Option<String>,
}

/// `host` as a server name the credential may name: letters, digits, dots
/// and hyphens, lower case.
fn server_name(host: &str, reason: &'static str) -> Result<String> {
    let host = host.trim().to_ascii_lowercase();
    if host.is_empty()
        || host.len() > 253
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(refused(reason));
    }
    Ok(host)
}

/// Whether `source` names the account `username` at `host`: its user
/// exactly, as a server may tell case apart, and its host.
fn names_account(source: &MailSyncSource, username: &str, host: &str) -> bool {
    source
        .provider_account
        .rsplit_once('@')
        .is_some_and(|(user, named)| user == username && named.eq_ignore_ascii_case(host))
}

/// The submission account of the IMAP source `source`, from its custody
/// record `secret`.
///
/// # Errors
///
/// A record that does not read, names another account, names no
/// submission server, or holds neither a password nor a token.
pub(super) fn submission_account(
    source: &MailSyncSource,
    secret: &[u8],
) -> Result<SubmissionAccount> {
    use super::smtp_client::SmtpSecurity;
    let stored: ImapCredential =
        serde_json::from_slice(secret).map_err(|_| refused("imap_credential_unreadable"))?;
    let imap_host = server_name(&stored.host, "imap_credential_host_invalid")?;
    if !names_account(source, &stored.username, &imap_host) {
        return Err(refused("imap_credential_reads_another_account"));
    }
    let submission = stored
        .submission
        .ok_or_else(|| refused("imap_submission_not_configured"))?;
    let host = server_name(&submission.host, "smtp_host_invalid")?;
    let security = match submission.security {
        Some(ImapSecurity::Tls) => SmtpSecurity::Tls,
        Some(ImapSecurity::Starttls) => SmtpSecurity::Starttls,
        None if submission.port == Some(465) => SmtpSecurity::Tls,
        None => SmtpSecurity::Starttls,
    };
    let port = submission.port.unwrap_or(match security {
        SmtpSecurity::Tls => 465,
        SmtpSecurity::Starttls => 587,
    });
    if stored.password.is_none() && stored.access_token.is_none() {
        return Err(refused("imap_credential_holds_no_secret"));
    }
    Ok(SubmissionAccount {
        host,
        port,
        security,
        username: stored.username,
        password: stored.password,
        access_token: stored.access_token,
    })
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
    /// The view of all mail (`\All`, fix list row 19144): read, but its
    /// name is no label of the messages it holds.
    AllMail,
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

    /// The label it gives a message it holds: none for the all-mail view.
    fn message_label(&self) -> Option<&str> {
        (self.role != FolderRole::AllMail).then_some(self.label.as_str())
    }

    /// [`Self::message_label`] as the labels a message read here carries.
    fn message_labels(&self) -> Vec<String> {
        self.message_label()
            .map(str::to_owned)
            .into_iter()
            .collect()
    }
}

/// How a session names each message (fix list rows 19145, 20917): by what
/// it is, so its copies in several folders share one id and two messages
/// never do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Naming {
    /// By Gmail's own id of it (`X-GM-MSGID`), where the server announces
    /// `X-GM-EXT-1`.
    Gmail,
    /// By the server's own id of it (`EMAILID`, RFC 8474), where the server
    /// announces `OBJECTID`; or by the id a header block gives, where the
    /// vault holds a copy under it that its whole digest proves, or a
    /// forgotten copy nothing proves it apart from.
    ServerId,
    /// By its `Message-ID`, its header block and its size, proved by its
    /// whole digest on a collision.
    HeaderBlock,
}

impl Naming {
    fn of(session: &ImapSession) -> Self {
        if session.has("X-GM-EXT-1") {
            Self::Gmail
        } else if session.has("OBJECTID") {
            Self::ServerId
        } else {
            Self::HeaderBlock
        }
    }

    /// The fetch items that name a message: under `EMAILID` its header
    /// block and size too, which may name it in the vault already
    /// ([`ImapMailWire::server_named_id`]).
    const fn item(self) -> &'static str {
        match self {
            Self::Gmail => "X-GM-MSGID",
            Self::ServerId => "EMAILID RFC822.SIZE BODY.PEEK[HEADER]",
            Self::HeaderBlock => "RFC822.SIZE BODY.PEEK[HEADER]",
        }
    }

    /// The most UIDs one read of what names them covers.
    const fn batch(self) -> u64 {
        match self {
            Self::Gmail => SERVER_ID_BATCH,
            Self::ServerId | Self::HeaderBlock => HEADER_BLOCK_BATCH,
        }
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
    /// How it names each message.
    naming: Naming,
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
    /// The messages the all-mail view named by their id alone, its headers
    /// not read again; emptied with `seen`.
    named_by_all_mail: RefCell<BTreeSet<String>>,
    /// The place this wire's session first named each id at, under the
    /// header block; emptied with `seen`.
    first_places: RefCell<BTreeMap<String, Location>>,
    /// The digest of the whole message each id names (its BLAKE3, each line
    /// ended by CRLF), as this wire's session read it; emptied with `seen`.
    whole_digests: RefCell<BTreeMap<String, [u8; 32]>>,
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
            named_by_all_mail: RefCell::new(BTreeSet::new()),
            first_places: RefCell::new(BTreeMap::new()),
            whole_digests: RefCell::new(BTreeMap::new()),
        }
    }

    /// Forgets what this wire's session read.
    fn forget_seen(&self) {
        self.seen.borrow_mut().clear();
        self.named_by_all_mail.borrow_mut().clear();
        self.first_places.borrow_mut().clear();
        self.whole_digests.borrow_mut().clear();
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

/// The folders a mailbox is read through, INBOX first and the all-mail
/// view last: a message any other folder holds lands from there first,
/// with its labels and whether the mailbox sent it.
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
                || has("\\flagged")
                || has("\\important")
                || matches!(leaf, "drafts" | "draft")
            {
                return None;
            }
            // The all-mail view holds a message archived under no label,
            // which no other folder holds (fix list row 19144).
            let role = if has("\\all") {
                FolderRole::AllMail
            } else if has("\\trash")
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
                )
            {
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
            folder.role == FolderRole::AllMail,
            folder.name.clone(),
        )
    });
    if folders.len() > MAX_FOLDERS {
        return Err(refused("imap_mailbox_has_too_many_folders"));
    }
    Ok(folders)
}

/// A message's header id from its `Message-ID`, its header block, read
/// from the start of `raw` (the block alone, or the whole message), and its
/// `size` (`RFC822.SIZE`), as an mbox import gives it (fix list row 19145):
/// `mbox` and the first 32 hex of the BLAKE3 of the `Message-ID`, the
/// block's SHA-256 and the size. Copies of one message hash alike; another
/// message reusing its `Message-ID`, or its whole header block with a body
/// of another size, does not. Two messages with one header block and bodies
/// of one size hash alike too, so a header id only proposes a name: where
/// another copy holds it, the whole digests decide ([`digest_variant_id`]).
/// A server that adds a header of its own to each folder's copy names the
/// copies apart: a duplicate, never a lost message.
pub(super) fn content_id(rfc_message_id: &str, raw: &[u8], size: u64) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(rfc_message_id.as_bytes());
    hasher.update(&header_digest(raw));
    hasher.update(&size.to_be_bytes());
    format!("{HEADER_ID_PREFIX}{}", &hasher.finalize().to_hex()[..32])
}

/// The SHA-256 of the header block at the start of `raw`: each field up to
/// the first empty line, unfolded (the line break before a line that starts
/// with a space or a tab dropped, RFC 5322 2.2.3) and ended by CRLF however
/// its lines were ended, so a block read alone, read at the head of its
/// whole message, kept in an mbox file with bare line feeds, or folded
/// another way hashes alike.
fn header_digest(raw: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let mut rest = raw;
    let mut started = false;
    while !rest.is_empty() {
        let (line, next) = match rest.iter().position(|&byte| byte == b'\n') {
            Some(end) => (&rest[..end], &rest[end + 1..]),
            None => (rest, &rest[rest.len()..]),
        };
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        // A continuation line goes on the field before it.
        if started && !matches!(line.first(), Some(b' ' | b'\t')) {
            hasher.update(b"\r\n");
        }
        hasher.update(line);
        started = true;
        rest = next;
    }
    if started {
        hasher.update(b"\r\n");
    }
    hasher.finalize().into()
}

/// The id of a message whose header id `header_id` another message holds
/// (fix list row 19145): `mboxdigest` and the first 32 hex of the BLAKE3,
/// under its own context, of the header id and `digest`, the message's
/// [`whole_digest`]. The same message always gets the same id, wherever it
/// is read, and another message another.
pub(super) fn digest_variant_id(header_id: &str, digest: &[u8; 32]) -> String {
    let mut hasher = blake3::Hasher::new_derive_key(DIGEST_ID_CONTEXT);
    hasher.update(header_id.as_bytes());
    hasher.update(digest);
    format!("{DIGEST_ID_PREFIX}{}", &hasher.finalize().to_hex()[..32])
}

/// The BLAKE3 of a whole message, each line ended by CRLF however it was
/// ended (a line feed with no carriage return before it gains one), as
/// [`header_digest`] reads line ends; fed a part at a time.
#[derive(Default)]
struct WholeDigest {
    hasher: blake3::Hasher,
    /// The last byte fed.
    previous: u8,
}

impl WholeDigest {
    fn update(&mut self, bytes: &[u8]) {
        let mut start = 0;
        let mut previous = self.previous;
        for (at, &byte) in bytes.iter().enumerate() {
            if byte == b'\n' && previous != b'\r' {
                self.hasher.update(&bytes[start..at]);
                self.hasher.update(b"\r\n");
                start = at + 1;
            }
            previous = byte;
        }
        self.hasher.update(&bytes[start..]);
        self.previous = previous;
    }

    fn finish(&self) -> [u8; 32] {
        *self.hasher.finalize().as_bytes()
    }
}

/// The digest of the whole message `raw` ([`WholeDigest`]): what proves two
/// copies one message (fix list row 19145).
pub(super) fn whole_digest(raw: &[u8]) -> [u8; 32] {
    let mut digest = WholeDigest::default();
    digest.update(raw);
    digest.finish()
}

fn place_id(folder: &Folder, uid_validity: u64, uid: u64) -> String {
    format!("imapuid.{}.{uid_validity}.{uid}", folder.digest)
}

/// Whether `objectid` is an `EMAILID` as RFC 8474 writes one: 1 to 255
/// letters, digits, `-` or `_`.
fn is_objectid(objectid: &str) -> bool {
    (1..=255).contains(&objectid.len())
        && objectid
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// An id from the server's `EMAILID` (fix list row 20917): `emailid.` and
/// the id.
fn email_id(objectid: &str) -> Option<String> {
    is_objectid(objectid).then(|| format!("{EMAIL_ID_PREFIX}{objectid}"))
}

/// The `EMAILID` an id carries; `None` for an id of another kind.
fn email_objectid(provider_id: &str) -> Option<&str> {
    provider_id
        .strip_prefix(EMAIL_ID_PREFIX)
        .filter(|objectid| is_objectid(objectid))
}

/// A Gmail id as the Gmail API writes it: lowercase hex.
pub(super) fn gmail_id(number: u64) -> String {
    format!("{number:x}")
}

/// Google's IMAP hosts: a session there announces `X-GM-EXT-1`.
const GMAIL_IMAP_HOSTS: [&str; 2] = ["imap.gmail.com", "imap.googlemail.com"];

/// Whether an IMAP source's account (`<username>@<host>`) is on Google's
/// IMAP host, where the wire names each message by its Gmail id: read from
/// the account alone, with no session.
pub(super) fn imap_account_on_gmail(provider_account: &str) -> bool {
    provider_account.rsplit_once('@').is_some_and(|(_, host)| {
        GMAIL_IMAP_HOSTS
            .iter()
            .any(|gmail| host.eq_ignore_ascii_case(gmail))
    })
}

/// The `X-GM-MSGID` a Gmail id carries; `None` for an id of another kind.
fn gmail_number(provider_id: &str) -> Option<u64> {
    if provider_id.is_empty()
        || provider_id.len() > 16
        || !provider_id
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    u64::from_str_radix(provider_id, 16).ok()
}

/// How `provider_id`, an id that names its message by what it is, names
/// it. A Gmail id is looked for only where Gmail answers, and an `EMAILID`
/// only where the server announces `OBJECTID`.
fn id_naming(open: &OpenSession, provider_id: &str) -> Result<Naming> {
    let naming = if gmail_number(provider_id).is_some() {
        Naming::Gmail
    } else if email_objectid(provider_id).is_some() {
        Naming::ServerId
    } else {
        return Ok(Naming::HeaderBlock);
    };
    if open.naming == naming {
        Ok(naming)
    } else {
        Err(refused("imap_message_not_locatable"))
    }
}

/// The search that finds a message by the server's own id of it, where
/// `provider_id` is one.
fn server_id_criterion(provider_id: &str) -> Option<String> {
    gmail_number(provider_id)
        .map(|number| format!("X-GM-MSGID {number}"))
        .or_else(|| email_objectid(provider_id).map(|objectid| format!("EMAILID {objectid}")))
}

/// The id a header block proposes for a message, with what it hashes that
/// a proof reads again (fix list row 19145).
struct Proposed {
    header_id: String,
    rfc_message_id: String,
    /// Its `RFC822.SIZE`.
    size: u64,
}

/// What names a message fetched with its header block and its size.
enum HeaderName {
    /// Its place: it has no `Message-ID`.
    Place(String),
    /// Its header id, which only proposes a name.
    Proposed(Proposed),
}

/// What names `message`, fetched with its header block and its size in
/// `folder`; `None` for an answer that carries neither.
fn header_name(message: &Fetched, folder: &Folder, uid_validity: u64) -> Option<HeaderName> {
    let uid = message.uid()?;
    let raw = message.value("BODY[HEADER]").and_then(Item::bytes)?;
    let rfc_message_id = MimeMessage::parse(raw)
        .header("message-id")
        .filter(|id| !id.is_empty());
    match rfc_message_id {
        Some(rfc_message_id) => {
            let size = message.value("RFC822.SIZE").and_then(Item::number)?;
            Some(HeaderName::Proposed(Proposed {
                header_id: content_id(&rfc_message_id, raw, size),
                rfc_message_id,
                size,
            }))
        }
        None => Some(HeaderName::Place(place_id(folder, uid_validity, uid))),
    }
}

/// The id of a message fetched with what names it under `naming`; `None`
/// for an answer that carries none of it, as an unsolicited update (its
/// flags) does. Under the header block it is the id proposed, and under
/// `EMAILID` the server's id, before the vault's copies and any proof are
/// read ([`ImapMailWire::resolved_ids`]).
fn fetched_id(
    message: &Fetched,
    naming: Naming,
    folder: &Folder,
    uid_validity: u64,
) -> Option<String> {
    message.uid()?;
    match naming {
        Naming::Gmail => message
            .value("X-GM-MSGID")
            .and_then(Item::number)
            .map(gmail_id),
        Naming::ServerId => message
            .value("EMAILID")
            .and_then(Item::list)
            .and_then(<[Item]>::first)
            .and_then(Item::atom)
            .and_then(email_id),
        Naming::HeaderBlock => match header_name(message, folder, uid_validity)? {
            HeaderName::Place(id) => Some(id),
            HeaderName::Proposed(proposed) => Some(proposed.header_id),
        },
    }
}

/// The digest of the whole message `uid` of the open folder, of `size`
/// octets (`RFC822.SIZE`), for a proof (fix list row 19145): read at once
/// when the wire reads a message that large whole, else
/// [`MAX_MESSAGE_BYTES`] at a time. `None` when the folder holds no such
/// UID.
fn whole_digest_of(session: &mut ImapSession, uid: u64, size: u64) -> Result<Option<[u8; 32]>> {
    let set = uid.to_string();
    let mut digest = WholeDigest::default();
    if size <= MAX_MESSAGE_BYTES {
        let fetched = session.uid_fetch(&set, "UID BODY.PEEK[]")?;
        let Some(raw) = section_bytes(&fetched, uid, "BODY[]") else {
            return Ok(None);
        };
        digest.update(raw);
        return Ok(Some(digest.finish()));
    }
    let mut offset = 0_u64;
    loop {
        let fetched = session.uid_fetch(
            &set,
            &format!("UID BODY.PEEK[]<{offset}.{MAX_MESSAGE_BYTES}>"),
        )?;
        let Some(part) = section_bytes(&fetched, uid, &format!("BODY[]<{offset}>")) else {
            // Past its end a server may answer no octets at all.
            let answered = fetched.iter().any(|message| message.uid() == Some(uid));
            return Ok((offset > 0 && answered).then(|| digest.finish()));
        };
        digest.update(part);
        let read = u64::try_from(part.len()).unwrap_or(u64::MAX);
        if read < MAX_MESSAGE_BYTES {
            return Ok(Some(digest.finish()));
        }
        offset = offset.saturating_add(read);
    }
}

/// The octets of `section` in the answer for `uid` among `fetched`.
fn section_bytes<'f>(fetched: &'f [Fetched], uid: u64, section: &str) -> Option<&'f [u8]> {
    fetched
        .iter()
        .find(|message| message.uid() == Some(uid))
        .and_then(|message| message.value(section))
        .and_then(Item::bytes)
}

/// Opens `folder` again after a read elsewhere; its UIDVALIDITY must be the
/// one `status` read.
fn reopen(open: &mut OpenSession, folder: usize, status: FolderStatus) -> Result<()> {
    let name = open.folders[folder].name.clone();
    if open.session.examine(&name)?.uid_validity == status.uid_validity {
        Ok(())
    } else {
        Err(refused("imap_folder_changed_during_read"))
    }
}

/// The digest of the whole message at `at`, of `size` octets, for a proof;
/// `None` when it is there no more. The open folder `current` (`status`) is
/// opened again after a read elsewhere.
fn digest_at(
    open: &mut OpenSession,
    at: Location,
    size: u64,
    current: usize,
    status: FolderStatus,
) -> Result<Option<[u8; 32]>> {
    if at.folder == current {
        if at.uid_validity != status.uid_validity {
            return Ok(None);
        }
        return whole_digest_of(&mut open.session, at.uid, size);
    }
    let name = open.folders[at.folder].name.clone();
    let there = open.session.examine(&name)?;
    let digest = if there.uid_validity == at.uid_validity {
        whole_digest_of(&mut open.session, at.uid, size)?
    } else {
        None
    };
    reopen(open, current, status)?;
    Ok(digest)
}

/// Of `fetched`, header blocks of the open `folder`, the UIDs whose message
/// `provider_id` names on a session that names messages by Gmail's id (an
/// mbox import's id there): by its place, or by its whole digest (fix list
/// row 19145). A header id proposes a UID whose header block gives that id,
/// a digest id one whose header id and `kept` hash to it; either names it
/// only when the digest of its whole message, read once, is `kept`, the one
/// the vault keeps of `provider_id`.
/// With no digest kept, or no message left to read, no UID is named:
/// another message with the same header block and size never comes back
/// under its id.
fn header_hits(
    session: &mut ImapSession,
    folder: &Folder,
    status: FolderStatus,
    fetched: &[Fetched],
    provider_id: &str,
    kept: Option<[u8; 32]>,
) -> Result<Vec<u64>> {
    let by_digest = provider_id.starts_with(DIGEST_ID_PREFIX);
    let mut hits = Vec::new();
    for message in fetched {
        let Some(uid) = message.uid() else {
            continue;
        };
        let names = match header_name(message, folder, status.uid_validity) {
            None => false,
            Some(HeaderName::Place(id)) => id == provider_id,
            Some(HeaderName::Proposed(proposed)) => match kept {
                Some(kept) => {
                    let proposes = if by_digest {
                        digest_variant_id(&proposed.header_id, &kept) == provider_id
                    } else {
                        proposed.header_id == provider_id
                    };
                    proposes && whole_digest_of(session, uid, proposed.size)? == Some(kept)
                }
                None => false,
            },
        };
        if names {
            hits.push(uid);
        }
    }
    Ok(hits)
}

/// Which message each UID of a fetch for what names them under `naming`
/// holds, as the fetch alone says it ([`fetched_id`]):
/// [`ImapMailWire::resolved_ids`] proves them.
fn learned_ids(
    fetched: &[Fetched],
    naming: Naming,
    place: &Folder,
    uid_validity: u64,
) -> Vec<(u64, String)> {
    fetched
        .iter()
        .filter_map(|message| {
            Some((
                message.uid()?,
                fetched_id(message, naming, place, uid_validity)?,
            ))
        })
        .collect()
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

/// The headers of the message `provider_id` from its header block (or the
/// whole message), read in `folder`. The read names the message, never this
/// function ([`ImapMailWire::resolved_ids`]): by its Gmail id or `EMAILID`
/// where the server names messages so, else by its `Message-ID`'s header id
/// ([`content_id`]) as its proof settles it, or by its place ([`place_id`])
/// when it has no `Message-ID`. Its address headers are read from the raw
/// header block, each mailbox apart before any encoded word is decoded, as a
/// reply's recipients take them (fix list row 20520).
fn headers_of(
    read: &MessageRead<'_>,
    provider_id: String,
    folder: &Folder,
    labels: Vec<String>,
) -> MailHeaders {
    let parsed = MimeMessage::parse(read.raw);
    let rfc_message_id = parsed.header("message-id").filter(|id| !id.is_empty());
    let addresses = |name: &str| parsed.address_header(name);
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
        from: Some(parsed.address_header("from").join(", ")).filter(|from| !from.is_empty()),
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

/// Where a listing or a search stands: the folder (by its place in the read
/// folders and its digest), its UIDVALIDITY, the UID the next page is below,
/// and, for a listing, the sequence number it ends at. Each kind of page
/// carries its own prefix.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ListCursor {
    folder: usize,
    digest: String,
    uid_validity: u64,
    below: Option<u64>,
    end: Option<u64>,
}

impl ListCursor {
    fn parse(page: Option<&str>, prefix: &str) -> Result<Self> {
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
        if fields.first() != Some(&prefix) || fields.len() != 6 {
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

    fn write(&self, prefix: &str) -> String {
        let text = |value: Option<u64>| value.map(|value| format!("{value}")).unwrap_or_default();
        format!(
            "{prefix}:{}:{}:{}:{}:{}",
            self.folder,
            self.digest,
            self.uid_validity,
            text(self.below),
            text(self.end)
        )
    }
}

/// The attributes a header read fetches; with `naming`, what names each
/// message under it too (the header block is read already).
fn header_attributes(session: &ImapSession, naming: Option<Naming>) -> String {
    let mut attributes = String::from("UID FLAGS INTERNALDATE RFC822.SIZE BODY.PEEK[HEADER]");
    if session.has("OBJECTID") {
        attributes.push_str(" THREADID");
    }
    match naming {
        Some(Naming::Gmail) => attributes.push_str(" X-GM-MSGID"),
        Some(Naming::ServerId) => attributes.push_str(" EMAILID"),
        Some(Naming::HeaderBlock) | None => {}
    }
    attributes
}

/// The labels the read folders among `places` give their message, or
/// `None` when none of them holds it: a message the all-mail view alone
/// holds is there still, under no label.
fn labels_at(folders: &[Folder], places: &[Location]) -> Option<Vec<String>> {
    let mut held = places
        .iter()
        .map(|at| &folders[at.folder])
        .filter(|folder| folder.read())
        .peekable();
    held.peek()?;
    Some(dedup(
        held.filter_map(Folder::message_label)
            .map(str::to_owned)
            .collect(),
    ))
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
                    self.forget_seen();
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
                        self.forget_seen();
                        Err(error)
                    }
                }
            },
        )?;
        answer.ok_or_else(|| refused("imap_session_unavailable"))
    }

    /// Reads the headers of `uids` in `folder`, each named as
    /// [`Self::resolved_ids`] names it, keeping each as seen and each UID in
    /// the UID map.
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
        let attributes = header_attributes(&open.session, Some(open.naming));
        let fetched = open.session.uid_fetch(&uid_set(uids), &attributes)?;
        let learned = self.resolved_ids(open, folder, status, &fetched)?;
        let ids: BTreeMap<u64, String> = learned.iter().cloned().collect();
        let place = &open.folders[folder];
        let mut out = Vec::with_capacity(fetched.len());
        for message in &fetched {
            let Some(read) = read_of(message, "BODY[HEADER]") else {
                continue;
            };
            let Some(provider_id) = ids.get(&read.uid).cloned() else {
                continue;
            };
            let mut headers = headers_of(&read, provider_id, place, place.message_labels());
            let mut seen = self.seen.borrow_mut();
            // A message read in several folders carries each of them, and
            // was sent by the mailbox when any of them says so.
            let at = match seen.get(&headers.provider_id) {
                Some((held, at)) => {
                    let mut labels = held.labels.clone();
                    labels.extend(place.message_labels());
                    headers.labels = dedup(labels);
                    headers.sent_by_mailbox |= held.sent_by_mailbox;
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
        self.remember_uids(
            open.source,
            uid_map_folder_key(place),
            status.uid_validity,
            learned,
        )?;
        Ok(out)
    }

    /// Of `uids` in the open `folder`, those to read for their headers, and
    /// the ids of the others. In the all-mail view of a server that names
    /// each message itself (Gmail, `OBJECTID`), one id read names each
    /// message first, and one this session read already, or whose live copy
    /// the vault holds, is never read for its headers again: the labelled
    /// folders landed it, and the view adds no label. Under `EMAILID` a UID
    /// the UID map holds is named by the id it was given, which may be a
    /// header id ([`Self::server_named_id`]), and a UID left to be read is
    /// named by that read alone.
    fn unread_in(
        &self,
        open: &mut OpenSession,
        folder: usize,
        status: FolderStatus,
        uids: &[u64],
    ) -> Result<(Vec<u64>, Vec<String>)> {
        let naming = open.naming;
        if naming == Naming::HeaderBlock
            || open.folders[folder].role != FolderRole::AllMail
            || uids.is_empty()
        {
            return Ok((uids.to_vec(), Vec::new()));
        }
        let place = open.folders[folder].clone();
        let folder_key = uid_map_folder_key(&place);
        let item = if naming == Naming::Gmail {
            "X-GM-MSGID"
        } else {
            "EMAILID"
        };
        let fetched = open
            .session
            .uid_fetch(&uid_set(uids), &format!("UID {item}"))?;
        let mut learned = learned_ids(&fetched, naming, &place, status.uid_validity);
        learned.retain(|(uid, _)| uids.contains(uid));
        let mut unread = Vec::new();
        let mut named = Vec::new();
        let mut remember = Vec::new();
        {
            let txn = self.vault.store.env.read_txn()?;
            let seen = self.seen.borrow();
            let mut by_id = self.named_by_all_mail.borrow_mut();
            for (uid, server_named) in learned {
                let mapped = if naming == Naming::ServerId {
                    UIDS.get(&self.vault.store, &txn, &(open.source, folder_key, uid))?
                        .filter(|row| row.uid_validity == status.uid_validity)
                        .map(|row| row.provider_id)
                } else {
                    None
                };
                let from_map = mapped.is_some();
                let provider_id = mapped.unwrap_or(server_named);
                let live = OCCURRENCES
                    .get(
                        &self.vault.store,
                        &txn,
                        &occurrence_key(open.source, &provider_id),
                    )?
                    .is_some_and(|occurrence| matches!(occurrence.presence, MailPresence::Present));
                let read = if seen.contains_key(&provider_id) {
                    named.push(provider_id.clone());
                    false
                } else if live {
                    // Named here alone, as far as this session read.
                    by_id.insert(provider_id.clone());
                    named.push(provider_id.clone());
                    false
                } else {
                    unread.push(uid);
                    true
                };
                // Gmail's id names its message outright. Under `EMAILID` the
                // header read names a UID left to it, and the map keeps its
                // own rows.
                if naming == Naming::Gmail || !(read || from_map) {
                    remember.push((uid, provider_id));
                }
            }
        }
        self.remember_uids(open.source, folder_key, status.uid_validity, remember)?;
        Ok((unread, named))
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

    /// The highest UID in the open `folder` whose message `provider_id`
    /// names: for an id the server cannot be searched for (fix list row
    /// 18242). One search answers the UIDs the folder holds; the UID map
    /// names those it learned under the folder's UIDVALIDITY, and only the
    /// others are read for what names them, a bounded batch at a time. The
    /// map learns them, so a later look reads only mail that arrived since.
    fn scan_for(
        &self,
        open: &mut OpenSession,
        source: EntityId,
        folder: usize,
        status: FolderStatus,
        provider_id: &str,
    ) -> Result<Option<u64>> {
        let place = open.folders[folder].clone();
        let top = uid_next_of(&mut open.session, status)?;
        if top <= 1 {
            return Ok(None);
        }
        let present = open.session.uid_ranges(1, top - 1)?;
        let folder_key = uid_map_folder_key(&place);
        let mut known = BTreeSet::new();
        let mut best = None;
        for (uid, row) in self.mapped_uids(source, folder_key)? {
            if row.uid_validity == status.uid_validity && ranges_hold(&present, uid) {
                known.insert(uid);
                if row.provider_id == provider_id {
                    best = best.max(Some(uid));
                }
            }
        }
        let unknown = without(&present, &known);
        let naming = open.naming;
        let items = format!("UID {}", naming.item());
        for batch in UidBatches::new(&unknown, naming.batch()) {
            let fetched = open.session.uid_fetch(&range_set(&batch), &items)?;
            let mut learned = self.resolved_ids(open, folder, status, &fetched)?;
            learned.retain(|&(uid, _)| uid < top);
            for (uid, id) in &learned {
                if id == provider_id {
                    best = best.max(Some(*uid));
                }
            }
            self.remember_uids(source, folder_key, status.uid_validity, learned)?;
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
        let naming = id_naming(open, provider_id)?;
        let held = self.held(source, provider_id)?;
        let (criterion, labels) = match naming {
            // The server finds a message by its own id, exactly.
            Naming::Gmail | Naming::ServerId => (
                server_id_criterion(provider_id),
                held.map(|(_, labels)| labels).unwrap_or_default(),
            ),
            Naming::HeaderBlock => {
                let Some((message_id, labels)) = held else {
                    // The vault holds no copy: nothing to look for.
                    return Ok(Vec::new());
                };
                // A copy whose Message-ID the vault does not hold cannot be
                // looked for, and not finding it is no sign it is gone.
                let message_id = message_id.ok_or_else(|| refused("imap_message_not_locatable"))?;
                // One the server cannot be searched for is read folder by
                // folder.
                let criterion =
                    search_string(&message_id).map(|quoted| format!("HEADER Message-ID {quoted}"));
                (criterion, labels)
            }
        };
        // The folders it was last seen in first, then the all-mail view,
        // which holds a copy no labelled folder does.
        let mut order: Vec<usize> = (0..open.folders.len()).collect();
        order.sort_by_key(|&at| {
            let folder = &open.folders[at];
            (
                !labels.contains(&folder.label),
                folder.role != FolderRole::AllMail,
                !folder.read(),
            )
        });
        let mut found = Vec::new();
        for folder in order {
            let name = open.folders[folder].name.clone();
            let status = open.session.examine(&name)?;
            let hit = match &criterion {
                Some(criterion) => {
                    let uids = open.session.uid_search(criterion)?;
                    // A Message-ID search matches a substring: a hit is
                    // taken only when what names it is the id asked for.
                    self.exact_hit(open, folder, status, &uids, provider_id, naming)?
                }
                None => self.scan_for(open, source.source_ref, folder, status, provider_id)?,
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
        // A place id names the place itself; any other id is checked.
        if provider_id.starts_with("imapuid.") {
            return Ok(true);
        }
        let naming = id_naming(open, provider_id)?;
        Ok(self
            .exact_hit(open, at.folder, status, &[at.uid], provider_id, naming)?
            .is_some())
    }

    /// The highest of `uids` in the open `folder` whose message
    /// `provider_id`, named under `naming`, names. Under the session's own
    /// naming, and for an id a header block gives where the server names
    /// messages by `EMAILID`, each UID is named as every other read names it
    /// ([`Self::resolved_ids`]) and the UID map learns it. On Gmail an id a
    /// header block gives (an mbox import's) is checked against each header
    /// block and proved by the whole digest the vault keeps of it
    /// ([`header_hits`]).
    fn exact_hit(
        &self,
        open: &mut OpenSession,
        folder: usize,
        status: FolderStatus,
        uids: &[u64],
        provider_id: &str,
        naming: Naming,
    ) -> Result<Option<u64>> {
        // Every hit is checked, a bounded batch at a time: an unchecked
        // hit is no evidence that the message is gone.
        let place = open.folders[folder].clone();
        let cross = naming != open.naming;
        // Under `EMAILID` every read names a UID by a header id the vault's
        // copy proves (fix list rows 19145, 20917), so a lookup of one finds
        // the UID the listing names by it.
        let resolved = !cross || open.naming == Naming::ServerId;
        // A message named in another naming is proved by its kept
        // whole-message digest. With none kept, and no UID named by it, it
        // cannot be located, which is no evidence that it is gone: refused,
        // never read as deleted at the provider.
        let kept = if cross {
            self.kept_digest(open.source, provider_id)?
        } else {
            None
        };
        if cross && !resolved && kept.is_none() {
            return Err(refused("imap_message_not_locatable"));
        }
        let read_as = if resolved { open.naming } else { naming };
        let items = format!("UID {}", read_as.item());
        let mut best = None;
        for batch in uids.chunks(HIT_BATCH) {
            let fetched = open.session.uid_fetch(&uid_set(batch), &items)?;
            if !resolved {
                let hits = header_hits(
                    &mut open.session,
                    &place,
                    status,
                    &fetched,
                    provider_id,
                    kept,
                )?;
                best = best.max(hits.into_iter().max());
                continue;
            }
            let learned = self.resolved_ids(open, folder, status, &fetched)?;
            for (uid, id) in &learned {
                if id == provider_id {
                    best = best.max(Some(*uid));
                }
            }
            self.remember_uids(
                open.source,
                uid_map_folder_key(&place),
                status.uid_validity,
                learned,
            )?;
        }
        if cross && best.is_none() && kept.is_none() {
            return Err(refused("imap_message_not_locatable"));
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
        // An id a header block gives names these bytes only when their
        // whole digest is the one the vault keeps of it (fix list row
        // 19145): another message's bytes never come back under its id.
        if whole
            && named_by_header(provider_id)
            && let Some(kept) = self.kept_digest(source.source_ref, provider_id)?
            && whole_digest(read.raw) != kept
        {
            return Ok(None);
        }
        // The labels it has landed with stay, with this folder's: a body
        // read in one folder takes no other folder away.
        let folder = &open.folders[at.folder];
        let landed = self.landed_copy(source, provider_id)?;
        let mut labels = landed
            .as_ref()
            .map(|copy| copy.labels.clone())
            .unwrap_or_default();
        labels.extend(folder.message_labels());
        let labels = dedup(labels);
        // The mailbox sent it when any copy known is in a sent folder: one
        // this session read, one it landed as or under, or this one.
        let sent = self
            .seen
            .borrow()
            .get(provider_id)
            .is_some_and(|(held, _)| held.sent_by_mailbox)
            || landed
                .as_ref()
                .and_then(|copy| copy.reply.as_ref())
                .is_some_and(|reply| reply.sent_by_mailbox)
            || open
                .folders
                .iter()
                .any(|known| known.role == FolderRole::Sent && labels.contains(&known.label));
        let mut headers = headers_of(&read, provider_id.to_owned(), folder, labels);
        headers.sent_by_mailbox |= sent;
        let raw = if whole { read.raw.to_vec() } else { Vec::new() };
        Ok(Some((headers, raw)))
    }

    /// The headers of the message `provider_id` at `at`, where it was
    /// found.
    fn headers_at(
        &self,
        open: &mut OpenSession,
        at: Location,
        provider_id: &str,
    ) -> Result<Option<MailHeaders>> {
        let name = open.folders[at.folder].name.clone();
        let status = open.session.examine(&name)?;
        if status.uid_validity != at.uid_validity {
            return Ok(None);
        }
        let attributes = header_attributes(&open.session, None);
        let fetched = open.session.uid_fetch(&at.uid.to_string(), &attributes)?;
        let folder = &open.folders[at.folder];
        Ok(fetched
            .iter()
            .find(|message| message.uid() == Some(at.uid))
            .and_then(|message| read_of(message, "BODY[HEADER]"))
            .map(|read| {
                headers_of(
                    &read,
                    provider_id.to_owned(),
                    folder,
                    folder.message_labels(),
                )
            }))
    }

    /// The copies `folder` held below `uid_next` (the top of the last read)
    /// and holds no more, each as the change it is: moved (its labels now),
    /// or deleted at the provider (in trash or junk, or nowhere). A labelled
    /// folder answers for the copies labelled with it; the all-mail view for
    /// those no labelled folder holds that the UID map knew it to hold.
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
        let below = self.held_below(open, source.source_ref, folder, status, uid_next)?;
        let label = place.message_label();
        let gone: BTreeSet<String> = {
            let txn = self.vault.store.env.read_txn()?;
            let mut gone = BTreeSet::new();
            for occurrence in
                OCCURRENCES.iter_from(&self.vault.store, &txn, source.source_ref.as_bytes())?
            {
                let (_, occurrence) = occurrence?;
                let answers_for = match label {
                    Some(label) => occurrence.labels.iter().any(|held| held == label),
                    None => {
                        occurrence.labels.is_empty()
                            && below.lost.contains_key(&occurrence.provider_id)
                    }
                };
                if matches!(occurrence.presence, MailPresence::Present)
                    && answers_for
                    && !below.held.contains(&occurrence.provider_id)
                {
                    gone.insert(occurrence.provider_id);
                }
            }
            gone
        };
        // The rows of a message reported gone stay until its change is
        // applied: a read whose change fails finds them again, and the next
        // read, which finds that change applied, forgets them.
        let mut forget = below.stale;
        for (provider_id, uids) in below.lost {
            if !gone.contains(&provider_id) {
                forget.extend(uids);
            }
        }
        for provider_id in gone {
            let places = self.locate(open, source, &provider_id, true)?;
            // Gone only when no folder read holds a copy.
            match labels_at(&open.folders, &places) {
                None => {
                    pending.remove(&provider_id);
                    changes.push(MailHistoryChange::Deleted { provider_id });
                }
                Some(labels) => {
                    // Where it is now: the labels later folders of this read
                    // build on.
                    pending.insert(provider_id.clone(), labels.clone());
                    changes.push(MailHistoryChange::Labels {
                        provider_id,
                        labels,
                        trash_or_spam: false,
                    });
                }
            }
        }
        // The other rows of what left are forgotten only once each was
        // answered for, so a read that fails part-way finds them again.
        self.forget_uids(source.source_ref, uid_map_folder_key(&place), &forget)
    }
}

/// What the open folder holds below the top of a read, by the UID map.
struct HeldBelow {
    /// The ids of the messages it holds.
    held: BTreeSet<String>,
    /// The messages the map knew it to hold under its UIDVALIDITY that it
    /// holds no more: the UIDs of each, by its id.
    lost: BTreeMap<String, Vec<u64>>,
    /// The map's rows of an older UIDVALIDITY.
    stale: Vec<u64>,
}

impl ImapMailWire<'_> {
    /// What the open `folder` holds below `top`: the UIDs one search
    /// answers, each named from the UID map, and only the UIDs the map does
    /// not hold read for what names them ([`Self::resolved_ids`]), a bounded
    /// batch at a time. The map learns those; the rows it holds of an older
    /// UIDVALIDITY, and of UIDs the folder no longer holds, are answered for
    /// the caller to forget.
    fn held_below(
        &self,
        open: &mut OpenSession,
        source: EntityId,
        folder: usize,
        status: FolderStatus,
        top: u64,
    ) -> Result<HeldBelow> {
        let place = open.folders[folder].clone();
        let mut below = HeldBelow {
            held: BTreeSet::new(),
            lost: BTreeMap::new(),
            stale: Vec::new(),
        };
        if top <= 1 {
            return Ok(below);
        }
        let present = open.session.uid_ranges(1, top - 1)?;
        let folder_key = uid_map_folder_key(&place);
        let mut known = BTreeSet::new();
        for (uid, row) in self.mapped_uids(source, folder_key)? {
            if row.uid_validity != status.uid_validity {
                below.stale.push(uid);
            } else if ranges_hold(&present, uid) {
                known.insert(uid);
                below.held.insert(row.provider_id);
            } else if uid < top {
                below.lost.entry(row.provider_id).or_default().push(uid);
            }
        }
        let unknown = without(&present, &known);
        let naming = open.naming;
        let items = format!("UID {}", naming.item());
        for batch in UidBatches::new(&unknown, naming.batch()) {
            let fetched = open.session.uid_fetch(&range_set(&batch), &items)?;
            let mut learned = self.resolved_ids(open, folder, status, &fetched)?;
            learned.retain(|&(uid, _)| uid < top);
            below.held.extend(learned.iter().map(|(_, id)| id.clone()));
            self.remember_uids(source, folder_key, status.uid_validity, learned)?;
        }
        Ok(below)
    }

    /// The UID map's rows of one folder of `source`, by UID.
    fn mapped_uids(&self, source: EntityId, folder_key: [u8; 32]) -> Result<Vec<(u64, HeldUid)>> {
        let mut prefix = source.as_bytes().to_vec();
        prefix.extend_from_slice(&folder_key);
        let txn = self.vault.store.env.read_txn()?;
        UIDS.iter_from(&self.vault.store, &txn, &prefix)?
            .map(|row| row.map(|((_, _, uid), held)| (uid, held)))
            .collect()
    }

    /// Records which message each of the `learned` UIDs of a folder holds,
    /// and, in the same write, each place an id a header block gives is
    /// given at ([`ID_PLACES`]): the place a row named another id at before
    /// is that id's no more.
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
            let store = &self.vault.store;
            for (uid, provider_id) in learned {
                let key = (source, folder_key, uid);
                if let Some(old) = UIDS.get(store, txn, &key)?
                    && old.provider_id != provider_id
                    && named_by_header(&old.provider_id)
                {
                    let place = id_place_key(source, &old.provider_id, folder_key, uid);
                    ID_PLACES.delete(store, txn, &place)?;
                }
                if named_by_header(&provider_id) {
                    let place = id_place_key(source, &provider_id, folder_key, uid);
                    ID_PLACES.put(store, txn, &place, &IdPlace { uid_validity })?;
                }
                let row = HeldUid {
                    uid_validity,
                    provider_id,
                };
                UIDS.put(store, txn, &key, &row)?;
            }
            Ok(())
        })
    }

    /// Forgets the rows of a folder's `uids`, and the places they gave ids
    /// a header block gives.
    fn forget_uids(&self, source: EntityId, folder_key: [u8; 32], uids: &[u64]) -> Result<()> {
        if uids.is_empty() {
            return Ok(());
        }
        self.vault.with_write_txn_grouped(|txn| {
            let store = &self.vault.store;
            for &uid in uids {
                let key = (source, folder_key, uid);
                if let Some(old) = UIDS.get(store, txn, &key)?
                    && named_by_header(&old.provider_id)
                {
                    let place = id_place_key(source, &old.provider_id, folder_key, uid);
                    ID_PLACES.delete(store, txn, &place)?;
                }
                UIDS.delete(store, txn, &key)?;
            }
            Ok(())
        })
    }

    /// The places the UID map gives `provider_id`, an id a header block
    /// gives, in `source`, other than `except`, at most [`PROOF_PLACES`]:
    /// each in a folder the session reads, and still the UID map's row
    /// there.
    fn mapped_places(
        &self,
        open: &OpenSession,
        provider_id: &str,
        except: Location,
    ) -> Result<Vec<Location>> {
        let keys: Vec<[u8; 32]> = open.folders.iter().map(uid_map_folder_key).collect();
        let txn = self.vault.store.env.read_txn()?;
        let mut places = Vec::new();
        for row in ID_PLACES.iter_from(
            &self.vault.store,
            &txn,
            &id_places_prefix(open.source, provider_id),
        )? {
            let ((_, _, (folder_key, uid)), place) = row?;
            let Some(folder) = keys.iter().position(|key| *key == folder_key) else {
                continue;
            };
            let at = Location {
                folder,
                uid_validity: place.uid_validity,
                uid,
            };
            if at == except {
                continue;
            }
            let mapped = UIDS
                .get(&self.vault.store, &txn, &(open.source, folder_key, uid))?
                .is_some_and(|held| {
                    held.uid_validity == place.uid_validity && held.provider_id == provider_id
                });
            if mapped {
                places.push(at);
                if places.len() >= PROOF_PLACES {
                    break;
                }
            }
        }
        Ok(places)
    }

    /// The whole digest the vault keeps of its copy of `provider_id` in
    /// `source`, of any presence; `None` when it keeps none.
    fn kept_digest(&self, source: EntityId, provider_id: &str) -> Result<Option<[u8; 32]>> {
        Ok(self
            .vault_copy(source, provider_id)?
            .and_then(|occurrence| occurrence.content_digest))
    }

    /// The vault's copy of `provider_id` in `source`, of any presence: a
    /// forgotten one is a fence.
    fn vault_copy(&self, source: EntityId, provider_id: &str) -> Result<Option<MailOccurrence>> {
        let txn = self.vault.store.env.read_txn()?;
        OCCURRENCES.get(
            &self.vault.store,
            &txn,
            &occurrence_key(source, provider_id),
        )
    }

    /// The UID map's row of one UID of one folder of `source`.
    fn uid_row(&self, source: EntityId, folder_key: [u8; 32], uid: u64) -> Result<Option<HeldUid>> {
        let txn = self.vault.store.env.read_txn()?;
        UIDS.get(&self.vault.store, &txn, &(source, folder_key, uid))
    }
}

/// What is known of a copy of a header id at another place than the one
/// being named: where this session or the UID map named it, and the
/// vault's copy.
struct KnownCopy {
    /// The places it was named at: the one this session first named it at,
    /// then those the UID map gives it, whichever session named them and
    /// whether or not their message landed.
    places: Vec<Location>,
    /// The digest of its whole message, when the vault or this session read
    /// it.
    digest: Option<[u8; 32]>,
    /// The folders the vault last saw it under.
    labels: Vec<String>,
    /// Whether the vault's copy is forgotten: a fence that holds against
    /// any copy no digest proves another message.
    forgotten: bool,
    /// Whether the vault's copy is forgotten with no digest of its whole
    /// message kept (it landed by its headers only): no digest read later,
    /// of any place, is proof of what it was, so its fence holds against
    /// every copy its header id names.
    forgotten_without_digest: bool,
}

impl ImapMailWire<'_> {
    /// Which message each UID of `fetched`, a read of the open `folder` for
    /// what names its messages, holds (fix list rows 19145, 20917). Gmail's
    /// id names a message outright. Under `EMAILID` the vault's copy under
    /// the header id a header block proposes is consulted first
    /// ([`Self::server_named_id`]), and under the header block each header
    /// id is proved first ([`Self::proved_id`]), so every read names a UID
    /// alike: the header listing, the change feed, the expunge scan, a
    /// search, a message looked for, and the importer's own reads through
    /// them.
    fn resolved_ids(
        &self,
        open: &mut OpenSession,
        folder: usize,
        status: FolderStatus,
        fetched: &[Fetched],
    ) -> Result<Vec<(u64, String)>> {
        let place = open.folders[folder].clone();
        if open.naming == Naming::Gmail {
            return Ok(learned_ids(
                fetched,
                open.naming,
                &place,
                status.uid_validity,
            ));
        }
        let mut resolved: Vec<(u64, String)> = Vec::with_capacity(fetched.len());
        let mut named = BTreeSet::new();
        for message in fetched {
            let Some(uid) = message.uid() else {
                continue;
            };
            if named.contains(&uid) {
                continue;
            }
            let at = Location {
                folder,
                uid_validity: status.uid_validity,
                uid,
            };
            let id = if open.naming == Naming::ServerId {
                let Some(id) = self.server_named_id(open, &place, at, message)? else {
                    continue;
                };
                id
            } else {
                let Some(name) = header_name(message, &place, status.uid_validity) else {
                    continue;
                };
                match name {
                    HeaderName::Place(id) => id,
                    HeaderName::Proposed(proposed) => self.proved_id(open, at, status, proposed)?,
                }
            };
            named.insert(uid);
            resolved.push((uid, id));
        }
        Ok(resolved)
    }

    /// The id of the message at `at`, in the open folder `place`, fetched as
    /// `message` with its `EMAILID`, its header block and its size, on a
    /// session that names messages by `EMAILID` (fix list rows 19145,
    /// 20917); `None` for an answer that carries no `EMAILID`:
    /// - a UID the UID map holds keeps the id it was given, as under the
    ///   header block ([`Self::proved_id`]);
    /// - one whose header block proposes a header id the vault holds a copy
    ///   under in this source (an mbox import's, or one a sync named before
    ///   the server announced `OBJECTID`), of any presence, is read whole
    ///   once: the copy's digest, it is that message; another, it is the
    ///   copy the vault holds under the id of that digest
    ///   ([`digest_variant_id`]), when it holds one. With no digest kept, or
    ///   its bytes unreadable, nothing proves it another message than a
    ///   forgotten copy, whose fence holds: it is that message;
    /// - else it is `emailid.` and its `EMAILID`. A message the vault holds
    ///   no copy under its header id costs one vault read and no other.
    fn server_named_id(
        &self,
        open: &mut OpenSession,
        place: &Folder,
        at: Location,
        message: &Fetched,
    ) -> Result<Option<String>> {
        let Some(server_id) = fetched_id(message, Naming::ServerId, place, at.uid_validity) else {
            return Ok(None);
        };
        if let Some(row) = self.uid_row(open.source, uid_map_folder_key(place), at.uid)?
            && row.uid_validity == at.uid_validity
        {
            return Ok(Some(row.provider_id));
        }
        let Some(HeaderName::Proposed(proposed)) = header_name(message, place, at.uid_validity)
        else {
            return Ok(Some(server_id));
        };
        let Some(copy) = self.vault_copy(open.source, &proposed.header_id)? else {
            return Ok(Some(server_id));
        };
        let digest = whole_digest_of(&mut open.session, at.uid, proposed.size)?;
        if let Some(digest) = digest {
            if copy.content_digest == Some(digest) {
                return Ok(Some(proposed.header_id));
            }
            let variant = digest_variant_id(&proposed.header_id, &digest);
            if self.vault_copy(open.source, &variant)?.is_some() {
                return Ok(Some(variant));
            }
        }
        let forgotten = matches!(copy.presence, MailPresence::Forgotten { .. });
        let unproved = digest.is_none() || copy.content_digest.is_none();
        Ok(Some(if forgotten && unproved {
            proposed.header_id
        } else {
            server_id
        }))
    }

    /// The id of the message at `at`, in the open folder (`status`), whose
    /// header block proposes `proposed` (fix list row 19145):
    /// - a UID the UID map holds keeps the id it was given: under one
    ///   UIDVALIDITY a UID always holds one message, and that id was proved
    ///   against every other place named before it;
    /// - a header id no other place holds names the message: none this
    ///   session named, none the UID map gives it (named by any session,
    ///   landed or not), and no copy the vault landed;
    /// - else the digests of the two whole messages decide: equal, it is
    ///   that message; different, or with no copy of the other left to read,
    ///   it is its own message, named by its digest ([`digest_variant_id`]).
    ///   One whose bytes cannot be read is named by its place;
    /// - but where the vault's copy is forgotten and no digest proves this
    ///   one another message (none of the forgotten copy kept, read this
    ///   session or left to read, or none of this one), the forgotten copy's
    ///   fence holds: it is that message, and lands no more. Another message
    ///   with the same header block and size, whose twin was forgotten by
    ///   its headers only, lands no more either.
    ///
    /// The other copy's digest is the vault's or this session's, else read
    /// where it is ([`Self::known_digest`]).
    fn proved_id(
        &self,
        open: &mut OpenSession,
        at: Location,
        status: FolderStatus,
        proposed: Proposed,
    ) -> Result<String> {
        let folder_key = uid_map_folder_key(&open.folders[at.folder]);
        if let Some(row) = self.uid_row(open.source, folder_key, at.uid)?
            && row.uid_validity == at.uid_validity
        {
            self.first_places
                .borrow_mut()
                .entry(row.provider_id.clone())
                .or_insert(at);
            return Ok(row.provider_id);
        }
        let Some(known) = self.known_copy(open, &proposed.header_id, at)? else {
            self.first_places
                .borrow_mut()
                .entry(proposed.header_id.clone())
                .or_insert(at);
            return Ok(proposed.header_id);
        };
        if known.forgotten_without_digest {
            // Nothing read now or later proves another message against a
            // fence kept without its digest: a place or a digest taken from
            // this copy would only be its own (fix list row 19145).
            return Ok(proposed.header_id);
        }
        let Some(digest) = whole_digest_of(&mut open.session, at.uid, proposed.size)? else {
            if known.forgotten {
                self.first_places
                    .borrow_mut()
                    .entry(proposed.header_id.clone())
                    .or_insert(at);
                return Ok(proposed.header_id);
            }
            return Ok(place_id(&open.folders[at.folder], at.uid_validity, at.uid));
        };
        let held = match known.digest {
            Some(held) => Some(held),
            None => self.known_digest(open, &known, &proposed, at, status)?,
        };
        let mut digests = self.whole_digests.borrow_mut();
        if let Some(held) = held {
            digests.entry(proposed.header_id.clone()).or_insert(held);
        }
        let id = if held == Some(digest) || (held.is_none() && known.forgotten) {
            proposed.header_id
        } else {
            digest_variant_id(&proposed.header_id, &digest)
        };
        digests.entry(id.clone()).or_insert(digest);
        drop(digests);
        self.first_places
            .borrow_mut()
            .entry(id.clone())
            .or_insert(at);
        Ok(id)
    }

    /// What is known of a copy of `header_id` at another place than `at`:
    /// the place this session first named it at, the places the UID map
    /// gives it (named by any session, its message landed or not: a
    /// collision no proof checked is never skipped), and the vault's copy
    /// (of any presence: a forgotten one is a fence). `None` when none is.
    fn known_copy(
        &self,
        open: &OpenSession,
        header_id: &str,
        at: Location,
    ) -> Result<Option<KnownCopy>> {
        let mut places: Vec<Location> = self
            .first_places
            .borrow()
            .get(header_id)
            .copied()
            .filter(|named| *named != at)
            .into_iter()
            .collect();
        for mapped in self.mapped_places(open, header_id, at)? {
            if !places.contains(&mapped) {
                places.push(mapped);
            }
        }
        let landed = {
            let txn = self.vault.store.env.read_txn()?;
            OCCURRENCES.get(
                &self.vault.store,
                &txn,
                &occurrence_key(open.source, header_id),
            )?
        };
        if places.is_empty() && landed.is_none() {
            return Ok(None);
        }
        let read = self.whole_digests.borrow().get(header_id).copied();
        Ok(Some(KnownCopy {
            places,
            digest: landed
                .as_ref()
                .and_then(|copy| copy.content_digest)
                .or(read),
            forgotten: landed
                .as_ref()
                .is_some_and(|copy| matches!(copy.presence, MailPresence::Forgotten { .. })),
            forgotten_without_digest: landed.as_ref().is_some_and(|copy| {
                matches!(copy.presence, MailPresence::Forgotten { .. })
                    && copy.content_digest.is_none()
            }),
            labels: landed.map(|copy| copy.labels).unwrap_or_default(),
        }))
    }

    /// The digest of the whole message of `known`, a copy of the header id
    /// `proposed` names at another place than `current`, read where it is:
    /// at the first of the places this session or the UID map named it at
    /// that still holds it, else in the folders the vault last saw it under
    /// and the all-mail view, at a UID a `Message-ID` search finds and the
    /// UID map names it at. `None` when no copy is left to read. The open
    /// folder `current` (`status`) is opened again after.
    fn known_digest(
        &self,
        open: &mut OpenSession,
        known: &KnownCopy,
        proposed: &Proposed,
        current: Location,
        status: FolderStatus,
    ) -> Result<Option<[u8; 32]>> {
        for &at in &known.places {
            let digest = digest_at(open, at, proposed.size, current.folder, status)?;
            if digest.is_some() {
                return Ok(digest);
            }
        }
        let Some(quoted) = search_string(&proposed.rfc_message_id) else {
            return Ok(None);
        };
        let criterion = format!("HEADER Message-ID {quoted}");
        let mut folders: Vec<usize> = (0..open.folders.len())
            .filter(|&at| {
                let folder = &open.folders[at];
                folder.read()
                    && (folder.role == FolderRole::AllMail || known.labels.contains(&folder.label))
            })
            .collect();
        folders.sort_by_key(|&at| open.folders[at].role == FolderRole::AllMail);
        let mut found = None;
        let mut left = false;
        for folder in folders.into_iter().take(PROOF_FOLDERS) {
            let place = open.folders[folder].clone();
            let there = if folder == current.folder && !left {
                status
            } else {
                left = true;
                open.session.examine(&place.name)?
            };
            let folder_key = uid_map_folder_key(&place);
            for uid in open.session.uid_search(&criterion)? {
                if folder == current.folder && uid == current.uid {
                    continue;
                }
                let names = self
                    .uid_row(open.source, folder_key, uid)?
                    .is_some_and(|row| {
                        row.uid_validity == there.uid_validity
                            && row.provider_id == proposed.header_id
                    });
                if names {
                    found = whole_digest_of(&mut open.session, uid, proposed.size)?;
                    if found.is_some() {
                        break;
                    }
                }
            }
            if found.is_some() {
                break;
            }
        }
        if left {
            reopen(open, current.folder, status)?;
        }
        Ok(found)
    }
}

/// The key the UID map files a folder's rows under: the BLAKE3 of its
/// digest.
fn uid_map_folder_key(place: &Folder) -> [u8; 32] {
    *blake3::hash(place.digest.as_bytes()).as_bytes()
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

/// Ascending UID ranges cut into batches of at most `size` UIDs and
/// `MAX_SET_RANGES` ranges, as one fetch names them.
struct UidBatches<'r> {
    ranges: std::slice::Iter<'r, (u64, u64)>,
    /// What is left of a range the last batch cut.
    current: Option<(u64, u64)>,
    /// The most UIDs one batch covers.
    size: u64,
}

impl<'r> UidBatches<'r> {
    fn new(ranges: &'r [(u64, u64)], size: u64) -> Self {
        Self {
            ranges: ranges.iter(),
            current: None,
            size,
        }
    }
}

impl Iterator for UidBatches<'_> {
    type Item = Vec<(u64, u64)>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut batch = Vec::new();
        let mut span = 0;
        while span < self.size && batch.len() < MAX_SET_RANGES {
            let Some((low, high)) = self.current.take().or_else(|| self.ranges.next().copied())
            else {
                break;
            };
            let take = (high - low + 1).min(self.size - span);
            batch.push((low, low + take - 1));
            span += take;
            if low + take <= high {
                self.current = Some((low + take, high));
            }
        }
        (!batch.is_empty()).then_some(batch)
    }
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

/// `query`, a caller's `SEARCH` keys, as `session` can send them (fix list
/// row 19089): grouped, its atoms and parentheses as written, each quoted
/// string quoted again, and one past ASCII sent as a literal the server
/// takes without a round trip, under `CHARSET UTF-8`. The caller's own
/// literal or a backslash outside a string is refused: either would leave
/// the server reading bytes the command never sends.
///
/// # Errors
///
/// `imap_search_query_unreadable` for a query the grammar refuses;
/// `imap_search_needs_ascii` where the server takes no such literal.
fn search_criteria(query: &str, session: &ImapSession) -> Result<String> {
    let unreadable = || refused("imap_search_query_unreadable");
    let mut keys = String::with_capacity(query.len() + 2);
    let mut utf8 = false;
    let mut chars = query.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                let mut text = String::new();
                loop {
                    match chars.next().ok_or_else(unreadable)? {
                        '"' => break,
                        '\\' => match chars.next().ok_or_else(unreadable)? {
                            escaped @ ('"' | '\\') => text.push(escaped),
                            _ => return Err(unreadable()),
                        },
                        c if c.is_control() => return Err(unreadable()),
                        c => text.push(c),
                    }
                }
                if text.is_ascii() {
                    let escaped = text.replace('\\', "\\\\").replace('"', "\\\"");
                    let _ = write!(keys, "\"{escaped}\"");
                } else {
                    let length = text.len();
                    if !(session.has("LITERAL+")
                        || (session.has("LITERAL-") && length <= LITERAL_MINUS_MAX))
                    {
                        return Err(refused("imap_search_needs_ascii"));
                    }
                    utf8 = true;
                    let _ = write!(keys, "{{{length}+}}\r\n{text}");
                }
            }
            '{' | '\\' => return Err(unreadable()),
            c if !c.is_ascii() || c.is_control() => return Err(unreadable()),
            c => keys.push(c),
        }
    }
    // The query came trimmed; a literal's own bytes are never trimmed.
    let charset = if utf8 { "CHARSET UTF-8 " } else { "" };
    Ok(format!("{charset}({keys})"))
}

/// Opens a session with the credential `secret` for `source`.
fn open_session(
    source: &MailSyncSource,
    secret: &[u8],
    credential: [u8; 32],
) -> Result<OpenSession> {
    let stored: ImapCredential =
        serde_json::from_slice(secret).map_err(|_| refused("imap_credential_unreadable"))?;
    let host = server_name(&stored.host, "imap_credential_host_invalid")?;
    // The credential reads the account the source names, and no other.
    if !names_account(source, &stored.username, &host) {
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
        naming: Naming::of(&session),
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
        let mut cursor = ListCursor::parse(page, LIST_PREFIX)?;
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
            // The all-mail view names what was landed already by its id
            // alone.
            let (unread, named) = self.unread_in(open, folder, status, &uids)?;
            let mut headers = self.read_headers(open, folder, status, &unread)?;
            // Newest first, by when the mailbox received each.
            headers.sort_by_key(|headers| std::cmp::Reverse(headers.received_at));
            let messages: Vec<MailMessageRef> = headers
                .into_iter()
                .map(|headers| MailMessageRef {
                    provider_id: headers.provider_id,
                    thread_id: headers.thread_id,
                })
                .chain(named.into_iter().map(|provider_id| MailMessageRef {
                    provider_id,
                    thread_id: None,
                }))
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
                next_page: Some(next.write(LIST_PREFIX)),
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
            let Some(mut headers) = self.headers_at(open, first, provider_id)? else {
                return Ok(None);
            };
            // Its labels are the folders read that hold it, the all-mail
            // view giving none; the mailbox sent it when any sent folder
            // holds it.
            if let Some(labels) = labels_at(&open.folders, &places) {
                headers.labels = labels;
            }
            headers.sent_by_mailbox |= places
                .iter()
                .any(|at| open.folders[at.folder].role == FolderRole::Sent);
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
                    content_digest: None,
                }));
            }
            // The digest the occurrence keeps, which proves a copy found
            // later to be this message (fix list row 19145).
            let digest = whole_digest(&raw);
            self.whole_digests
                .borrow_mut()
                .entry(provider_id.to_owned())
                .or_insert(digest);
            let body = MimeMessage::parse(&raw).body();
            Ok(Some(MailFull {
                headers,
                body_text: body.text,
                attachments: body.attachments,
                content_digest: Some(digest),
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
            // The messages this read has added.
            let mut added: BTreeSet<String> = BTreeSet::new();
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
                // What the all-mail view holds that this read or the vault
                // has already needs nothing more: the view adds no label.
                let (unread, _) = self.unread_in(open, at, status, &taken)?;
                for headers in self.read_headers(open, at, status, &unread)? {
                    // A message already landed, filed here too, carries this
                    // folder as well, over the labels this read gave it.
                    let landed = match pending.get(&headers.provider_id) {
                        Some(labels) => Some(labels.clone()),
                        None => self.landed_labels(source, &headers.provider_id)?,
                    };
                    match landed {
                        Some(labels)
                            if folder
                                .message_label()
                                .is_none_or(|label| labels.iter().any(|held| held == label)) => {}
                        Some(mut labels) => {
                            labels.extend(folder.message_labels());
                            let labels = dedup(labels);
                            pending.insert(headers.provider_id.clone(), labels.clone());
                            changes.push(MailHistoryChange::Labels {
                                provider_id: headers.provider_id,
                                labels,
                                trash_or_spam: false,
                            });
                        }
                        // A message new in several folders of this read is
                        // added once, with the labels of each.
                        None => {
                            if added.insert(headers.provider_id.clone()) {
                                changes.push(MailHistoryChange::Added(MailMessageRef {
                                    provider_id: headers.provider_id,
                                    thread_id: headers.thread_id,
                                }));
                            }
                        }
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

    /// The labels of the folders this session read `provider_id` in; none
    /// for one the all-mail view alone named, which it files under no label.
    fn listed_labels(&self, provider_id: &str) -> Option<Vec<String>> {
        if let Some((headers, _)) = self.seen.borrow().get(provider_id) {
            return Some(headers.labels.clone());
        }
        self.named_by_all_mail
            .borrow()
            .contains(provider_id)
            .then(Vec::new)
    }

    /// A quoted string in `SEARCH` keys escapes a quote or a backslash with a
    /// backslash (RFC 3501 4.3).
    fn search_escapes(&self) -> bool {
        true
    }

    /// The messages `query`, `SEARCH` keys, finds in the folders this wire
    /// reads (never trash, junk or drafts), folder by folder, the newest of
    /// each first, at most `limit` (fix list row 19089). A page looks in at
    /// most [`SEARCH_FOLDERS_PER_PAGE`] folders, so a query that finds
    /// little still answers in bounded time and names the next page. A
    /// message filed in several folders is named once a page.
    fn search_page(
        &self,
        source: &MailSyncSource,
        query: &str,
        limit: u32,
        page: Option<&str>,
    ) -> Result<MailIdPage> {
        let mut cursor = ListCursor::parse(page, SEARCH_PREFIX)?;
        let limit = usize::try_from(limit).unwrap_or(usize::MAX).max(1);
        self.with_session(source, |open| {
            let criteria = search_criteria(query, &open.session)?;
            let read: Vec<usize> = (0..open.folders.len())
                .filter(|&at| open.folders[at].read())
                .collect();
            // The folder the page names, found again by its digest when the
            // folders changed meanwhile.
            let mut place = read
                .iter()
                .position(|&at| open.folders[at].digest == cursor.digest)
                .unwrap_or(cursor.folder);
            let mut messages = Vec::new();
            let mut named = BTreeSet::new();
            let mut looked = 0_usize;
            while let Some(&folder) = read.get(place) {
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
                }
                let below = cursor.below;
                let mut uids = open.session.uid_search(&criteria)?;
                uids.retain(|&uid| below.is_none_or(|below| uid < below));
                // The newest hits: the highest UIDs.
                let start = uids
                    .len()
                    .saturating_sub(limit.saturating_sub(messages.len()));
                let taken = uids.split_off(start);
                let mut headers = self.read_headers(open, folder, status, &taken)?;
                headers.sort_by_key(|headers| std::cmp::Reverse(headers.received_at));
                for headers in headers {
                    if named.insert(headers.provider_id.clone()) {
                        messages.push(MailMessageRef {
                            provider_id: headers.provider_id,
                            thread_id: headers.thread_id,
                        });
                    }
                }
                looked += 1;
                if start > 0 {
                    // This folder holds older hits: the next page reads on
                    // below the oldest taken.
                    cursor.below = taken.first().copied();
                    return Ok(MailIdPage {
                        messages,
                        next_page: Some(cursor.write(SEARCH_PREFIX)),
                    });
                }
                place += 1;
                let Some(&next) = read.get(place) else {
                    break;
                };
                cursor = ListCursor {
                    folder: place,
                    digest: open.folders[next].digest.clone(),
                    ..ListCursor::default()
                };
                if messages.len() >= limit || looked >= SEARCH_FOLDERS_PER_PAGE {
                    return Ok(MailIdPage {
                        messages,
                        next_page: Some(cursor.write(SEARCH_PREFIX)),
                    });
                }
            }
            Ok(MailIdPage {
                messages,
                next_page: None,
            })
        })
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

    /// The source's live copy of `provider_id`, when it has landed one.
    fn landed_copy(
        &self,
        source: &MailSyncSource,
        provider_id: &str,
    ) -> Result<Option<MailOccurrence>> {
        let txn = self.vault.store.env.read_txn()?;
        Ok(OCCURRENCES
            .get(
                &self.vault.store,
                &txn,
                &occurrence_key(source.source_ref, provider_id),
            )?
            .filter(|occurrence| matches!(occurrence.presence, MailPresence::Present)))
    }

    /// The labels of the source's live copy of `provider_id`, when it has
    /// landed one.
    fn landed_labels(
        &self,
        source: &MailSyncSource,
        provider_id: &str,
    ) -> Result<Option<Vec<String>>> {
        Ok(self
            .landed_copy(source, provider_id)?
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
