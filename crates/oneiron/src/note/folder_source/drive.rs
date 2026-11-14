//! A Google Drive source (MAIL-GOOGLE = A, ARCH-0027 #mail-drive): an
//! attached folder source whose files are the Drive files its owner chose
//! at attach, read through a [`DriveWire`] instead of a host walk. The
//! owner chooses either the files they picked (`drive.file`) or their whole
//! Drive (`drive.readonly`; DRIVE-ACCESS = B, the owner 15 Nov 00:43). The
//! same ledger and the same rescan serve it: a new file lands as an
//! imported NOTE, a changed one supersedes the text it landed, and one gone
//! from Drive or put in its trash retracts its note (archived, never
//! erased). Each file is keyed on its Drive file id under the source's
//! account (RESEARCH-1393 #drive), never on a host path.
//!
//! Drive takes metadata first, chosen content next, and exports when
//! needed. The first step takes the change feed's start token
//! (`changes.getStartPageToken`) before it reads any file's metadata, so no
//! change between the two is lost, and holds each new file by its name
//! only. For picked files it reads each one's metadata. For a whole Drive
//! it lists every file (`files.list`, newest change first, its trash and
//! folders left out), a bounded number of pages a step: the listing's page
//! token is kept on the source, so a long listing spans steps and quota
//! windows, and once it ends a file the source held that it did not name
//! is read as gone. Later steps drain `changes.list` from the stored token:
//! the changes to the picked files, or every change for a whole Drive.
//! Each step then reads the text of the files it owes, newest first, within
//! its budget: a stored text file or PDF is downloaded and read as the
//! attached folder reads it; a Google Doc exports as Markdown, a Sheet as
//! CSV and a Slides deck as plain text. Every call is charged against the
//! provider's per-user quota first, through the windows kept on the source,
//! and a call that does not fit rests the source until its window opens.
//!
//! The notes land private to the owner who attached the source, as a
//! folder attached as notes lands them (ARCH-0027: never wider than the
//! source). Drive's own sharing is not read here.

use std::cell::Cell;
use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use super::super::files::{
    FILES_DEFAULT_KIND, FILES_TEXT_EXTENSIONS, FileFacts, NameOnlyFile, NameOnlyReason,
};
use super::super::import::{ImportedFile, ImportedNote, ImportedNoteStanding};
use super::{
    FolderFile, FolderFileState, FolderRescan, FolderRescanReport, FolderSource, FolderSourceFile,
    SOURCES, source_key,
};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::provider_quota::{
    ProviderQuotaWindow, RATE_LIMIT_REST_SECS, SourceSteps, minute_ceiling,
};
use crate::{EntityId, Vault};

/// What a wire answers for its provider's rate-limit answer (Drive's 429,
/// or its 403 for a usage limit): the step rests the source a minute and
/// ends without a failure.
pub const DRIVE_WIRE_RATE_LIMITED: &str = "drive_wire_rate_limited";

/// What a metered call answers once its source rests: the step reads it as
/// its pause, never as its failure.
const DRIVE_WIRE_RESTING: &str = "drive_wire_quota_resting";

/// How a Drive source's folder name starts; its account follows.
const DRIVE_FOLDER_PREFIX: &str = "drive://";

/// The longest account, custody name or file id a Drive source keeps.
const MAX_DRIVE_FIELD_BYTES: usize = 320;

/// The largest file whose bytes one step downloads, and the largest answer
/// a wire reads for one: a larger file is said as a failure and left owed,
/// never read in part.
pub(crate) const MAX_DRIVE_DOWNLOAD_BYTES: u64 = 256 * 1024 * 1024;

/// The Google-native types a step exports, and as what: a Doc as Markdown,
/// a Sheet as CSV (its first sheet), a Slides deck as plain text.
const DRIVE_EXPORTS: [(&str, &str); 3] = [
    ("application/vnd.google-apps.document", "text/markdown"),
    ("application/vnd.google-apps.spreadsheet", "text/csv"),
    ("application/vnd.google-apps.presentation", "text/plain"),
];

/// The prefix of every Google-native type: one that is not exported (a
/// form, a drawing, a folder, a shortcut) is held by its name only.
const GOOGLE_NATIVE_PREFIX: &str = "application/vnd.google-apps.";

/// A Drive folder's type: a whole Drive's source holds its files, never its
/// folders.
pub const DRIVE_FOLDER_MIME_TYPE: &str = "application/vnd.google-apps.folder";

/// The Google OAuth scope a source of picked files asks for: only the files
/// the owner picked through the Google Picker.
pub const DRIVE_PICKED_OAUTH_SCOPE: &str = "https://www.googleapis.com/auth/drive.file";

/// The Google OAuth scope a whole Drive's source asks for: every file of
/// the Drive, read only. On self-host the owner's own OAuth client asks it
/// at once; Cloud's restricted-scope verification is a later Cloud task
/// (DRIVE-ACCESS = B).
pub const DRIVE_WHOLE_OAUTH_SCOPE: &str = "https://www.googleapis.com/auth/drive.readonly";

/// What of the Drive the owner chose to attach (DRIVE-ACCESS = B: the whole
/// Drive is a first-class choice at connect time).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DriveAccess {
    /// The files the owner picked through the Google Picker, by Drive id.
    Picked { files: Vec<String> },
    /// Every file of the Drive.
    Whole,
}

impl DriveAccess {
    /// The Google OAuth scope this access asks for.
    #[must_use]
    pub const fn oauth_scope(&self) -> &'static str {
        match self {
            Self::Picked { .. } => DRIVE_PICKED_OAUTH_SCOPE,
            Self::Whole => DRIVE_WHOLE_OAUTH_SCOPE,
        }
    }
}

/// What the owner chose to attach: the Google account the files are read
/// from, the custody record holding the owner's Google grant for Drive,
/// and the files read: the picked ones, or the whole Drive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriveOrigin {
    /// The custody record the credential is stored under.
    pub custody_ref: String,
    /// The account's address: the wire reads only through a credential
    /// that reads this account.
    pub account: String,
    /// The files the source reads.
    pub access: DriveAccess,
}

impl DriveOrigin {
    /// The folder name the source is attached under: its account, so one
    /// account is one Drive source, and attaching it again finds the notes
    /// it landed.
    #[must_use]
    pub fn folder(&self) -> String {
        format!("{DRIVE_FOLDER_PREFIX}{}", self.account.to_lowercase())
    }

    /// The source's id, which a wire keys its credential caches on: its
    /// own import MACHINE, one per account.
    ///
    /// # Errors
    /// Only if id derivation fails.
    pub(crate) fn source_id(&self) -> Result<EntityId> {
        Vault::imported_note_author(&self.folder())
    }

    fn validate(&self) -> Result<()> {
        let field_ok = |field: &str| {
            !field.trim().is_empty()
                && field.len() <= MAX_DRIVE_FIELD_BYTES
                && !field.chars().any(|c| c.is_control() || c.is_whitespace())
        };
        if !field_ok(&self.custody_ref) || !field_ok(&self.account) {
            return Err(invalid(
                "a Drive source names its account and its custody record",
            ));
        }
        let DriveAccess::Picked { files } = &self.access else {
            return Ok(());
        };
        if files.is_empty() {
            return Err(invalid("a Drive source names the files the owner picked"));
        }
        if !files.iter().all(|id| {
            !id.is_empty()
                && id.len() <= MAX_DRIVE_FIELD_BYTES
                && id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        }) {
            return Err(invalid("a Drive file id is blank, too long or not plain"));
        }
        Ok(())
    }
}

/// One Drive file's metadata, as `files.get` and `changes.list` give it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriveFileMeta {
    pub id: String,
    pub name: String,
    pub mime_type: String,
    /// When the file last changed, Unix seconds.
    pub modified_at: u64,
    /// Its stored size; none for a Google-native file.
    pub size: Option<u64>,
    /// In the owner's trash: read as gone.
    pub trashed: bool,
}

impl DriveFileMeta {
    /// The facts the ledger keeps of this revision.
    fn facts(&self) -> FileFacts {
        FileFacts {
            bytes: self.size.unwrap_or(0),
            modified_at: self.modified_at,
        }
    }
}

/// One entry of the change feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriveChange {
    pub file_id: String,
    /// The file left the account's reach: deleted, or its access removed.
    pub removed: bool,
    /// The file as it is now; none when it was removed.
    pub file: Option<DriveFileMeta>,
}

/// One page of the change feed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DriveChangesPage {
    pub changes: Vec<DriveChange>,
    /// The token of the drain's next page.
    pub next_page: Option<String>,
    /// On the drain's last page, the token the next drain starts from.
    pub new_start: Option<String>,
}

/// One page of a whole Drive's listing.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DriveFilesPage {
    pub files: Vec<DriveFileMeta>,
    /// The token of the listing's next page; none on its last page.
    pub next_page: Option<String>,
}

/// One kind of provider call a Drive step makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DriveCall {
    /// The change feed's start token (`changes.getStartPageToken`).
    StartPageToken,
    /// One page of the change feed (`changes.list`).
    Changes,
    /// One page of a whole Drive's listing (`files.list`).
    List,
    /// One file's metadata (`files.get`).
    File,
    /// One stored file's bytes (`files.get` with `alt=media`).
    Download,
    /// One Google-native file's export (`files.export`).
    Export,
}

/// A provider's limits for one user, and what each kind of call costs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriveQuota {
    /// The quota units one user may spend in a minute.
    pub units_per_minute: u32,
    /// A listing call (`changes.list`, `files.list`).
    pub list: u32,
    /// A metadata read (`files.get`, the start token, and the credential
    /// check a wire makes before its first call, Drive's `about`).
    pub get: u32,
    /// A content read (a download or an export).
    pub content: u32,
}

impl DriveQuota {
    /// The units `call` costs.
    #[must_use]
    pub const fn of(&self, call: DriveCall) -> u32 {
        match call {
            DriveCall::Changes | DriveCall::List => self.list,
            DriveCall::StartPageToken | DriveCall::File => self.get,
            DriveCall::Download | DriveCall::Export => self.content,
        }
    }
}

/// The provider side of a Drive source.
pub trait DriveWire {
    /// The token the change feed starts from now.
    ///
    /// # Errors
    /// The provider's failure, or [`DRIVE_WIRE_RATE_LIMITED`].
    fn start_page_token(&self, origin: &DriveOrigin) -> Result<String>;

    /// One page of the change feed from `token`; none when the provider no
    /// longer knows `token`, and the feed starts again.
    ///
    /// # Errors
    /// As [`Self::start_page_token`].
    fn changes(&self, origin: &DriveOrigin, token: &str) -> Result<Option<DriveChangesPage>>;

    /// One page of the whole Drive's listing, newest change first, with its
    /// trash and its folders left out: its first page, or the page `page`
    /// names. None when the provider no longer knows `page`, and the
    /// listing reads again from its first page.
    ///
    /// # Errors
    /// As [`Self::start_page_token`].
    fn list(&self, origin: &DriveOrigin, page: Option<&str>) -> Result<Option<DriveFilesPage>>;

    /// One file's metadata; none for a file the account no longer reaches.
    ///
    /// # Errors
    /// As [`Self::start_page_token`].
    fn file(&self, origin: &DriveOrigin, id: &str) -> Result<Option<DriveFileMeta>>;

    /// A stored file's bytes; none for a file the account no longer reaches.
    ///
    /// # Errors
    /// As [`Self::start_page_token`].
    fn download(&self, origin: &DriveOrigin, id: &str) -> Result<Option<Vec<u8>>>;

    /// A Google-native file exported as `mime_type`; none for a file the
    /// account no longer reaches.
    ///
    /// # Errors
    /// As [`Self::start_page_token`].
    fn export(&self, origin: &DriveOrigin, id: &str, mime_type: &str) -> Result<Option<Vec<u8>>>;

    /// The provider's per-user limits; none: the wire is never charged.
    fn quota(&self) -> Option<DriveQuota> {
        None
    }
}

/// Where a Drive source's import stands, kept on the source.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DriveSyncState {
    /// The change feed's token; none until the first step takes it.
    pub page_token: Option<String>,
    /// A whole Drive's listing while it is under way; none once it ended,
    /// and for picked files. The change feed is drained once it ends.
    pub listing: Option<DriveListing>,
    /// The files whose text is owed: their metadata landed, and a later
    /// step reads their text.
    pub owed: Vec<DriveFileMeta>,
    pub(crate) quota: ProviderQuotaWindow,
}

/// Where a whole Drive's listing stands.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DriveListing {
    /// The token of the page read next; none for the listing's first page.
    pub next_page: Option<String>,
    /// The ids the listing named so far: once it ends, a file the source
    /// holds that it did not name has left the Drive.
    pub listed: Vec<String>,
}

/// A Drive source: what the owner picked, and where its import stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriveSource {
    pub origin: DriveOrigin,
    pub sync: DriveSyncState,
}

/// What one Drive step may read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriveStepBudget {
    /// The change feed's pages one step drains.
    pub change_pages: usize,
    /// The pages of a whole Drive's listing one step reads.
    pub list_pages: usize,
    /// The files whose text one step reads.
    pub texts: usize,
}

impl Default for DriveStepBudget {
    fn default() -> Self {
        Self {
            change_pages: 10,
            list_pages: 10,
            texts: 20,
        }
    }
}

/// What one Drive step did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DriveStepReport {
    /// What its rescan of the ledger did.
    pub rescan: FolderRescanReport,
    /// The files whose metadata it read.
    pub metadata: usize,
    /// The files whose text it read.
    pub texts: usize,
    /// The files whose text is still owed.
    pub owed: usize,
    /// A whole Drive's listing is still under way: a later step reads its
    /// next page.
    pub listing: bool,
    /// Until when the source rests: its quota is spent, or the provider
    /// asked it to wait.
    pub quota_paused_until: Option<u64>,
}

/// What reading one file's text gave.
enum DriveText {
    Text {
        markdown: String,
        /// The hash of the bytes a PDF's text was read from.
        raw_hash: Option<String>,
    },
    NameOnly(NameOnlyReason),
}

/// How a stored file's text is read.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StoredText {
    Markdown,
    Pdf,
    Plain,
}

fn invalid(reason: &'static str) -> Error {
    super::super::document::invalid(reason)
}

fn refused(code: &str) -> Error {
    Error::InvalidConfig(code.to_owned())
}

fn is_resting(error: &Error) -> bool {
    matches!(error, Error::InvalidConfig(code) if code == DRIVE_WIRE_RESTING)
}

/// How a stored file named `name` of type `mime_type` is read; none for a
/// format the source takes no text from.
fn stored_text(name: &str, mime_type: &str) -> Option<StoredText> {
    let extension = name
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase());
    match extension.as_deref() {
        Some("md") => return Some(StoredText::Markdown),
        Some("pdf") => return Some(StoredText::Pdf),
        Some(extension) if FILES_TEXT_EXTENSIONS.contains(&extension) => {
            return Some(StoredText::Plain);
        }
        _ => {}
    }
    match mime_type {
        "text/markdown" => Some(StoredText::Markdown),
        "application/pdf" => Some(StoredText::Pdf),
        _ if mime_type.starts_with("text/") => Some(StoredText::Plain),
        _ => None,
    }
}

/// `bytes` as text: none when they are not UTF-8 text.
fn utf8_text(bytes: Vec<u8>) -> Option<String> {
    String::from_utf8(bytes)
        .ok()
        .filter(|text| !text.contains('\0'))
}

/// The Drive sources, by folder, with a step under way in this process:
/// the host's rescan and the owner's `vault.files.sources.rescan` each wait
/// for the one under way.
static DRIVE_SOURCE_STEPS: SourceSteps<String> = SourceSteps::new();

/// A step's wire, charged within its provider's quota: every call is
/// charged before it is made, against the source's windows, and the step's
/// first call with the credential check its wire makes before it (Drive's
/// `about`, a metadata read). Once a call does not fit, or the provider
/// answered that it is rate-limited, the source rests and every later call
/// is refused with no provider call.
struct MeteredDriveWire<'w> {
    inner: &'w dyn DriveWire,
    quota: Option<DriveQuota>,
    window: Cell<ProviderQuotaWindow>,
    /// Whether the change feed reads now: it may spend the whole minute,
    /// the copy only its share of it.
    live: Cell<bool>,
    /// Whether a call was charged yet, and with it the credential check.
    charged: Cell<bool>,
}

impl<'w> MeteredDriveWire<'w> {
    fn new(inner: &'w dyn DriveWire, window: ProviderQuotaWindow) -> Self {
        Self {
            quota: inner.quota(),
            inner,
            window: Cell::new(window),
            live: Cell::new(true),
            charged: Cell::new(false),
        }
    }

    /// Rests the source until `until` and answers the refusal.
    fn rest(&self, mut window: ProviderQuotaWindow, until: u64) -> Error {
        window.resting_until = Some(until);
        self.window.set(window);
        refused(DRIVE_WIRE_RESTING)
    }

    /// Charges `call`, then makes it through `read`.
    fn metered<A>(
        &self,
        call: DriveCall,
        read: impl FnOnce(&dyn DriveWire) -> Result<A>,
    ) -> Result<A> {
        let now = crate::unix_seconds_now();
        let mut window = self.window.get();
        if window.resting_at(now).is_some() {
            return Err(refused(DRIVE_WIRE_RESTING));
        }
        window.roll(now);
        if let Some(quota) = &self.quota {
            let check = if self.charged.get() { 0 } else { quota.get };
            if let Err(until) = window.charge(
                u64::from(quota.of(call)) + u64::from(check),
                minute_ceiling(quota.units_per_minute, self.live.get()),
                None,
            ) {
                return Err(self.rest(window, until));
            }
        }
        self.charged.set(true);
        self.window.set(window);
        let answer = read(self.inner);
        if matches!(&answer, Err(Error::InvalidConfig(code)) if code == DRIVE_WIRE_RATE_LIMITED) {
            let until = crate::unix_seconds_now() + RATE_LIMIT_REST_SECS;
            return Err(self.rest(self.window.get(), until));
        }
        answer
    }

    /// The text of `file`, read as its type says. A type the source takes
    /// no text from makes no call.
    fn text(&self, origin: &DriveOrigin, file: &DriveFileMeta) -> Result<Option<DriveText>> {
        if let Some((_, export)) = DRIVE_EXPORTS
            .iter()
            .find(|(native, _)| *native == file.mime_type)
        {
            let Some(bytes) = self.metered(DriveCall::Export, |wire| {
                wire.export(origin, &file.id, export)
            })?
            else {
                return Ok(None);
            };
            let Some(text) = utf8_text(bytes) else {
                return Ok(Some(DriveText::NameOnly(NameOnlyReason::NotText)));
            };
            return Ok(Some(DriveText::Text {
                markdown: text,
                raw_hash: None,
            }));
        }
        let read = if file.mime_type.starts_with(GOOGLE_NATIVE_PREFIX) {
            None
        } else {
            stored_text(&file.name, &file.mime_type)
        };
        let Some(read) = read else {
            return Ok(Some(DriveText::NameOnly(NameOnlyReason::Unsupported)));
        };
        if file
            .size
            .is_some_and(|size| size > MAX_DRIVE_DOWNLOAD_BYTES)
        {
            return Err(refused("drive_file_larger_than_one_download"));
        }
        let Some(bytes) =
            self.metered(DriveCall::Download, |wire| wire.download(origin, &file.id))?
        else {
            return Ok(None);
        };
        Ok(Some(match read {
            StoredText::Pdf => match crate::ingest::pdf_text(&bytes) {
                // A PDF none of whose text could be read is unreadable;
                // one with no text at all is blank.
                Ok(pdf) if pdf.unread == 0 || !pdf.text.trim().is_empty() => DriveText::Text {
                    markdown: pdf.text,
                    raw_hash: Some(blake3::hash(&bytes).to_hex().to_string()),
                },
                _ => DriveText::NameOnly(NameOnlyReason::Unreadable),
            },
            StoredText::Markdown => DriveText::Text {
                markdown: String::from_utf8_lossy(&bytes).into_owned(),
                raw_hash: None,
            },
            StoredText::Plain => match utf8_text(bytes) {
                Some(text) => DriveText::Text {
                    markdown: text,
                    raw_hash: None,
                },
                None => DriveText::NameOnly(NameOnlyReason::NotText),
            },
        }))
    }
}

/// What a step's feed read: the files whose text is owed now, and the ids
/// gone from the account's reach or put in its trash.
struct FeedRead {
    owe: Vec<DriveFileMeta>,
    gone: Vec<String>,
    metadata: usize,
    /// The token the source keeps after the read; none until a start read
    /// completes.
    token: Option<String>,
    /// A whole Drive's listing as the read leaves it: none once it ended,
    /// and for picked files.
    listing: Option<DriveListing>,
    /// The ids a whole Drive's listing named, when it ended in this read.
    listed: Option<HashSet<String>>,
}

impl FeedRead {
    const fn at(token: Option<String>) -> Self {
        Self {
            owe: Vec::new(),
            gone: Vec::new(),
            metadata: 0,
            token,
            listing: None,
            listed: None,
        }
    }
}

/// `feed` as read so far when `error` is the source's rest; else `error`.
fn paused(error: Error, feed: FeedRead) -> Result<FeedRead> {
    if is_resting(&error) {
        Ok(feed)
    } else {
        Err(error)
    }
}

/// Whether a whole Drive's source holds `file`: a file out of the trash,
/// never a folder.
fn whole_drive_holds(file: &DriveFileMeta) -> bool {
    !file.trashed && file.mime_type != DRIVE_FOLDER_MIME_TYPE
}

/// The change feed's start: its start token, then each picked file's
/// metadata, or a whole Drive's listing from its first page. A call out of
/// quota before the token, or among the picked files, ends it with nothing
/// of it kept, so the next step starts it again; a listing keeps the pages
/// it read.
fn read_drive_start(
    wire: &MeteredDriveWire<'_>,
    origin: &DriveOrigin,
    budget: DriveStepBudget,
) -> Result<FeedRead> {
    let mut feed = FeedRead::at(None);
    let start = match wire.metered(DriveCall::StartPageToken, |wire| {
        wire.start_page_token(origin)
    }) {
        Ok(start) => start,
        Err(error) => return paused(error, feed),
    };
    let files = match &origin.access {
        DriveAccess::Picked { files } => files,
        DriveAccess::Whole => {
            feed.token = Some(start);
            return read_drive_listing(wire, origin, DriveListing::default(), budget, feed);
        }
    };
    let mut first = Vec::new();
    for id in files {
        match wire.metered(DriveCall::File, |wire| wire.file(origin, id)) {
            Ok(Some(file)) if !file.trashed => first.push(file),
            Ok(_) => feed.gone.push(id.clone()),
            Err(error) => {
                feed.gone.clear();
                return paused(error, feed);
            }
        }
    }
    feed.metadata = first.len();
    feed.owe = first;
    feed.token = Some(start);
    Ok(feed)
}

/// Up to the budget's pages of a whole Drive's listing, from where
/// `listing` stands, into `feed`: each file it names is owed. A page Drive
/// no longer knows reads the listing again from its first page. A call out
/// of quota ends the read, and the next step reads on from the page it
/// stopped at. On its last page the listing ends, and `feed` names every
/// file it listed.
fn read_drive_listing(
    wire: &MeteredDriveWire<'_>,
    origin: &DriveOrigin,
    mut listing: DriveListing,
    budget: DriveStepBudget,
    mut feed: FeedRead,
) -> Result<FeedRead> {
    for _ in 0..budget.list_pages {
        let page = match wire.metered(DriveCall::List, |wire| {
            wire.list(origin, listing.next_page.as_deref())
        }) {
            Ok(Some(page)) => page,
            Ok(None) => {
                listing.next_page = None;
                continue;
            }
            Err(error) => {
                feed.listing = Some(listing);
                return paused(error, feed);
            }
        };
        for file in page.files {
            if !whole_drive_holds(&file) {
                continue;
            }
            feed.metadata += 1;
            listing.listed.push(file.id.clone());
            feed.owe.push(file);
        }
        listing.next_page = page.next_page;
        if listing.next_page.is_none() {
            feed.listed = Some(listing.listed.into_iter().collect());
            return Ok(feed);
        }
    }
    feed.listing = Some(listing);
    Ok(feed)
}

impl Vault {
    /// Attaches the Drive files `origin` names, the picked ones or the
    /// whole Drive, as a standing source of notes: the owner's one act, as
    /// for a folder; each step after it reads under it. `kind` defaults to
    /// the Files world's default kind.
    ///
    /// # Errors
    /// A blank or oversize field, picked access with no file, an unknown
    /// `kind`, the account attached already, or a storage error.
    pub fn attach_drive_source(
        &self,
        owner: &AuthenticatedOwner,
        mut origin: DriveOrigin,
        kind: Option<&str>,
    ) -> Result<FolderSource> {
        origin.validate()?;
        if let DriveAccess::Picked { files } = &mut origin.access {
            let mut seen = HashSet::new();
            files.retain(|id| seen.insert(id.clone()));
        }
        let folder = origin.folder();
        self.attach_source(
            owner,
            &folder,
            Vec::new(),
            kind.unwrap_or(FILES_DEFAULT_KIND),
            None,
            Some(DriveSource {
                origin,
                sync: DriveSyncState::default(),
            }),
        )
    }

    /// One bounded step of the Drive source attached as `folder`, read
    /// through `wire`: the change feed (or, on the first step, its start
    /// token and the picked files' metadata or the whole Drive's listing;
    /// while that listing is under way, its next pages), then the owed
    /// files' text,
    /// newest first, then one rescan of the ledger with what was read. A
    /// call out of quota ends the reads cleanly: what was read lands, and
    /// the source rests until its window opens. A file whose text could not
    /// be read stays owed and is said in the report.
    ///
    /// # Errors
    /// A folder that is not an attached Drive source, an owner proof that
    /// no longer holds, the change feed's failure (nothing lands, and the
    /// feed's token stays), or a storage error.
    pub fn drive_sync_step(
        &self,
        owner: &AuthenticatedOwner,
        folder: &str,
        wire: &dyn DriveWire,
        budget: DriveStepBudget,
    ) -> Result<DriveStepReport> {
        // Each step reads the windows and the feed's token the last one left.
        let _stepping = DRIVE_SOURCE_STEPS.wait_for(folder.to_owned());
        let source = self
            .folder_source(folder)?
            .ok_or_else(|| invalid("the folder is not attached"))?;
        let namespace = source.namespace();
        let drive = source
            .drive
            .ok_or_else(|| invalid("the folder is not a Drive source"))?;
        owner.revalidate(self)?;
        let ledger: HashMap<String, FolderSourceFile> = self
            .folder_source_files(folder)?
            .into_iter()
            .map(|file| (file.path.clone(), file))
            .collect();
        let metered = MeteredDriveWire::new(wire, drive.sync.quota);
        let mut sync = drive.sync;
        let feed = match self.read_drive_feed(&metered, &drive.origin, &sync, budget) {
            Ok(feed) => feed,
            Err(error) => {
                let window = metered.window.get();
                self.store_drive_sync(folder, |state| state.quota = window)?;
                return Err(error);
            }
        };
        let mut report = DriveStepReport {
            metadata: feed.metadata,
            listing: feed.listing.is_some(),
            ..DriveStepReport::default()
        };
        sync.page_token = feed.token;
        sync.listing = feed.listing;
        let mut gone = feed.gone;
        // A whole Drive's listing that ended named every file the Drive
        // holds: one the source holds that it did not name has left.
        if let Some(listed) = &feed.listed {
            gone.extend(
                ledger
                    .iter()
                    .filter(|(id, row)| {
                        !matches!(row.state, FolderFileState::Retracted)
                            && !listed.contains(id.as_str())
                    })
                    .map(|(id, _)| id.clone()),
            );
        }
        sync.owed = owed_after(std::mem::take(&mut sync.owed), feed.owe, &gone, &ledger);
        metered.live.set(false);
        let mut read = Vec::new();
        let mut kept = Vec::new();
        let mut failed: Vec<String> = Vec::new();
        let mut left = Vec::new();
        let mut owed = std::mem::take(&mut sync.owed).into_iter();
        for file in owed.by_ref().take(budget.texts) {
            match metered.text(&drive.origin, &file) {
                Ok(Some(text)) => read.push((file, text)),
                Ok(None) => left.push(file.id),
                Err(error) if is_resting(&error) => {
                    kept.push(file);
                    break;
                }
                Err(error) => {
                    failed.push(error.to_string());
                    kept.push(file);
                }
            }
        }
        kept.extend(owed);
        report.texts = read.len();
        let mut rescan = FolderRescan {
            folder: folder.to_owned(),
            new: Vec::new(),
            links: Vec::new(),
            present: Vec::new(),
            name_only: Vec::new(),
            missing: Vec::new(),
            raw_hashes: HashMap::new(),
            facts: HashMap::new(),
            whole: true,
        };
        let mut taken_titles = HashSet::new();
        for (file, text) in read {
            rescan.facts.insert(file.id.clone(), file.facts());
            let (markdown, raw_hash) = match text {
                DriveText::Text { markdown, raw_hash } if !markdown.trim().is_empty() => {
                    (markdown, raw_hash)
                }
                DriveText::Text { .. } => {
                    rescan
                        .name_only
                        .push(name_only(&file, NameOnlyReason::Empty));
                    continue;
                }
                DriveText::NameOnly(why) => {
                    rescan.name_only.push(name_only(&file, why));
                    continue;
                }
            };
            let standing = self.imported_note_standings(
                &namespace,
                &[ImportedFile {
                    path: &file.id,
                    markdown: &markdown,
                    decoded: "",
                }],
            )?[0];
            if let Some(raw_hash) = raw_hash {
                rescan.raw_hashes.insert(file.id.clone(), raw_hash);
            }
            match standing {
                ImportedNoteStanding::New => rescan.new.push(ImportedNote {
                    title: self.drive_title(&namespace, &file.name, &mut taken_titles)?,
                    path: file.id,
                    kind: source.kind.clone(),
                    written_at: file.modified_at,
                    markdown,
                    original: None,
                }),
                ImportedNoteStanding::Refused => rescan
                    .name_only
                    .push(name_only(&file, NameOnlyReason::Refused)),
                ImportedNoteStanding::Unchanged
                | ImportedNoteStanding::Changed
                | ImportedNoteStanding::Removed => rescan.present.push(FolderFile {
                    path: file.id,
                    markdown,
                    links: Some(Vec::new()),
                }),
            }
        }
        // A file new to the vault is held by its name until its text is
        // read; a file whose earlier text landed keeps that text meanwhile.
        for file in &kept {
            if ledger.get(&file.id).is_none_or(|row| row.note.is_none()) {
                rescan.facts.insert(file.id.clone(), file.facts());
                rescan
                    .name_only
                    .push(name_only(file, NameOnlyReason::Unread));
            }
        }
        rescan.missing = gone
            .iter()
            .chain(&left)
            .filter(|id| ledger.contains_key(id.as_str()))
            .cloned()
            .collect();
        report.rescan = self.rescan_folder_source(owner, rescan)?;
        report.rescan.failed += failed.len();
        if let Some(error) = failed.into_iter().next() {
            report.rescan.first_error.get_or_insert(error);
        }
        report.owed = kept.len();
        sync.owed = kept;
        sync.quota = metered.window.get();
        report.quota_paused_until = sync.quota.resting_at(crate::unix_seconds_now());
        self.store_drive_sync(folder, |state| *state = sync)?;
        Ok(report)
    }

    /// The change feed's read for one step: on the first step its start
    /// (see [`read_drive_start`]); while a whole Drive's listing is under
    /// way, its next pages (see [`read_drive_listing`]); after it, up to the
    /// budget's pages of changes: to the picked files, or every change to a
    /// file of a whole Drive. A token the provider no longer knows starts
    /// the feed again. A call out of quota ends the read; the source keeps
    /// the token of the last page read.
    fn read_drive_feed(
        &self,
        wire: &MeteredDriveWire<'_>,
        origin: &DriveOrigin,
        sync: &DriveSyncState,
        budget: DriveStepBudget,
    ) -> Result<FeedRead> {
        let Some(mut token) = sync.page_token.clone() else {
            return read_drive_start(wire, origin, budget);
        };
        let mut feed = FeedRead::at(Some(token.clone()));
        if let Some(listing) = &sync.listing {
            return read_drive_listing(wire, origin, listing.clone(), budget, feed);
        }
        let picked: Option<HashSet<&str>> = match &origin.access {
            DriveAccess::Picked { files } => Some(files.iter().map(String::as_str).collect()),
            DriveAccess::Whole => None,
        };
        for _ in 0..budget.change_pages {
            let page = match wire.metered(DriveCall::Changes, |wire| wire.changes(origin, &token)) {
                Ok(Some(page)) => page,
                Ok(None) => return read_drive_start(wire, origin, budget),
                Err(error) => return paused(error, feed),
            };
            for change in page.changes {
                let read = match &picked {
                    Some(picked) => picked.contains(change.file_id.as_str()),
                    // A folder is never held; a trashed or removed file is
                    // read as gone.
                    None => change
                        .file
                        .as_ref()
                        .is_none_or(|file| file.mime_type != DRIVE_FOLDER_MIME_TYPE),
                };
                if !read {
                    continue;
                }
                feed.metadata += 1;
                feed.owe.retain(|file| file.id != change.file_id);
                feed.gone.retain(|id| *id != change.file_id);
                match change.file {
                    Some(file) if !change.removed && !file.trashed => feed.owe.push(file),
                    _ => feed.gone.push(change.file_id),
                }
            }
            // A page names its drain's next page, or on the last page the
            // token the next drain starts from.
            match (page.next_page, page.new_start) {
                (Some(next), _) => {
                    token.clone_from(&next);
                    feed.token = Some(next);
                }
                (None, Some(start)) => {
                    feed.token = Some(start);
                    break;
                }
                (None, None) => break,
            }
        }
        Ok(feed)
    }

    /// A title for a new Drive note no other note of the source holds: the
    /// file's name without its extension, else the whole name, else none.
    fn drive_title(
        &self,
        namespace: &str,
        name: &str,
        taken: &mut HashSet<String>,
    ) -> Result<Option<String>> {
        let stem = name.rsplit_once('.').map_or(name, |(stem, _)| stem).trim();
        for candidate in [stem, name.trim()] {
            let normalized = candidate
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase();
            if candidate.is_empty()
                || super::super::document::validate_title(candidate).is_err()
                || taken.contains(&normalized)
                || !self.imported_note_title_free(namespace, candidate)?
            {
                continue;
            }
            taken.insert(normalized);
            return Ok(Some(candidate.to_owned()));
        }
        Ok(None)
    }

    /// Writes `change` to the Drive source attached as `folder`, if it is
    /// still attached.
    fn store_drive_sync(
        &self,
        folder: &str,
        change: impl FnOnce(&mut DriveSyncState),
    ) -> Result<()> {
        let key = source_key(folder);
        self.with_write_txn(|txn| {
            if let Some(mut source) = SOURCES.get(&self.store, txn, &key)?
                && let Some(drive) = source.drive.as_mut()
            {
                change(&mut drive.sync);
                SOURCES.put(&self.store, txn, &key, &source)?;
            }
            Ok(())
        })
    }
}

/// Whether the ledger took `file`'s revision already: its text, or its
/// name for a reason other than an unread text.
fn ledger_took(row: Option<&FolderSourceFile>, file: &DriveFileMeta) -> bool {
    row.is_some_and(|row| {
        let held = match row.state {
            FolderFileState::Retracted => false,
            FolderFileState::NameOnly { why } => {
                row.note.is_some() || why != NameOnlyReason::Unread
            }
            FolderFileState::Landed | FolderFileState::Proposed { .. } => row.note.is_some(),
        };
        held && row.meta.is_some_and(|meta| {
            (meta.bytes, meta.modified_at) == (file.facts().bytes, file.modified_at)
        })
    })
}

/// The files whose text is owed after a feed read: those owed before, less
/// the ones `gone`, then each file the read `named`, unless the ledger took
/// its revision already. Newest first.
fn owed_after(
    owed: Vec<DriveFileMeta>,
    named: Vec<DriveFileMeta>,
    gone: &[String],
    ledger: &HashMap<String, FolderSourceFile>,
) -> Vec<DriveFileMeta> {
    let gone: HashSet<&str> = gone.iter().map(String::as_str).collect();
    let mut owed: HashMap<String, DriveFileMeta> = owed
        .into_iter()
        .filter(|file| !gone.contains(file.id.as_str()))
        .map(|file| (file.id.clone(), file))
        .collect();
    for file in named {
        if ledger_took(ledger.get(&file.id), &file) {
            owed.remove(&file.id);
        } else {
            owed.insert(file.id.clone(), file);
        }
    }
    let mut owed: Vec<DriveFileMeta> = owed.into_values().collect();
    owed.sort_by(|a, b| b.modified_at.cmp(&a.modified_at).then(a.id.cmp(&b.id)));
    owed
}

/// `file` held by its name only, for `why`.
fn name_only(file: &DriveFileMeta, why: NameOnlyReason) -> NameOnlyFile {
    NameOnlyFile {
        path: file.id.clone(),
        why,
        facts: file.facts(),
        original: None,
    }
}
