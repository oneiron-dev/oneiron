//! mbox and Google Takeout intake (FIX 12559). The owner imports an mbox
//! file, or a Google Takeout `.zip` that holds mbox files, on this device
//! into one of the pack's mailboxes; each message lands as the importer lands
//! one, whole, bound to its thread's audience at birth.
//!
//! - A Google mailbox takes a Takeout export: each message keeps the id the
//!   Gmail API knows it by (Takeout's `X-GM-MSGID`, as hex) and its thread
//!   (`X-GM-THRID`), so the live Gmail sync finds it landed and never lands
//!   it twice, and its attachments open through the Gmail wire by their part
//!   ids. A message with no Gmail id is refused.
//! - An IMAP mailbox takes any mbox: a message's id is the hash of its
//!   `Message-ID` and its header block, as the IMAP wire names it on a
//!   server that is not Gmail (of its bytes when it has no `Message-ID`).
//!
//! Trash, spam, drafts and chats never land; a "recent months" copy setting
//! leaves older mail out; a search-only mailbox imports nothing. One call
//! reads a bounded number of messages and keeps its place, so a large
//! export imports over several calls; a changed file starts over, and what
//! landed already lands as the same.

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::gmail::{address_list, reads_google_mail, rfc2822_seconds};
use super::imap::content_id;
use super::importer::{MONTH_SECONDS, copies};
use super::landing::{LandOutcome, Landing};
use super::mbox::{MboxMessage, MboxReader};
use super::mime::MimeMessage;
use super::pack::require_pack_active_in;
use super::source::{
    MailCopySetting, MailProvider, MailSourceKind, MailSourceRow, MailSourceStatus, SOURCES,
};
use super::state::{MailPresence, MailStage, OCCURRENCES, occurrence_key};
use super::wire::{MailFull, MailHeaders};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

/// Each import's place, by the source and the BLAKE3 of the file's path.
const IMPORTS: SideTable<(EntityId, [u8; 32]), MboxImportProgress, Named> =
    SideTable::new(&side_table::MAIL_PACK_MBOX_IMPORT);

/// The messages one call reads when the request names none.
const DEFAULT_MESSAGES: u32 = 500;
/// The most messages one call reads.
const MAX_MESSAGES: u32 = 5_000;
/// How often a call keeps its place while it reads.
const PROGRESS_EVERY: u64 = 100;
/// The read buffer.
const READ_BUFFER_BYTES: usize = 1 << 20;
/// The most refusal reasons one report lists.
const MAX_REASONS: usize = 20;

/// Where one file's import stands.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
struct MboxImportProgress {
    path: String,
    /// The file's size and change time when the import started: a changed
    /// file starts over.
    size: u64,
    modified: u64,
    /// The mbox file of a `.zip` read now, by its place among the archive's
    /// mbox files; 0 for a plain mbox.
    entry: u32,
    /// The byte offset of the next message in that file.
    offset: u64,
    done: bool,
    read: u64,
    landed: u64,
    updated_at: u64,
}

/// `vault.mail.sources.import_mbox`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailMboxImportRequest {
    /// The mailbox source, 32-hex.
    pub source_ref: String,
    /// The mbox file, or a Google Takeout `.zip` holding mbox files, on this
    /// device: an absolute path.
    pub path: String,
    /// The messages this call reads; 500 when absent, at most 5,000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub messages: Option<u32>,
}

/// What one import call did.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailMboxImportReport {
    pub source_ref: String,
    /// Messages that landed.
    pub landed: u64,
    /// Messages the vault held whole already, or forgot.
    pub same: u64,
    /// Messages refused (no Gmail id, or refused by the write door), with
    /// why.
    pub refused: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refusal_reasons: Vec<String>,
    /// Messages left out: trash, spam, drafts, chats, older than the copy
    /// setting keeps, or larger than this host reads.
    pub skipped: u64,
    /// Messages read from this file over every call so far.
    pub read_total: u64,
    /// Whether the whole file has been read.
    pub done: bool,
}

impl MailMboxImportReport {
    fn refuse(&mut self, reason: String) {
        self.refused += 1;
        if self.refusal_reasons.len() < MAX_REASONS {
            self.refusal_reasons.push(reason);
        }
    }
}

fn unreadable(error: &std::io::Error) -> MemoryError {
    MemoryError::bad_request(format!("the file cannot be read: {error}"))
}

fn zip_unreadable(error: &zip::result::ZipError) -> MemoryError {
    MemoryError::bad_request(format!("the archive cannot be read: {error}"))
}

/// The Gmail id of a Takeout message: the decimal `X-GM-MSGID` its
/// separator (`From <id>@xxx <date>`) or its header carries, as the hex the
/// Gmail API names it by.
fn gmail_message_id(separator: &str, message: &MimeMessage<'_>) -> Option<String> {
    let from_separator = separator
        .strip_prefix("From ")
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|sender| sender.split('@').next())
        .and_then(|digits| digits.parse::<u64>().ok());
    let id = from_separator.or_else(|| {
        message
            .header("x-gm-msgid")
            .and_then(|value| value.trim().parse::<u64>().ok())
    })?;
    Some(format!("{id:x}"))
}

/// A separator's date (`Wed Nov 06 01:02:03 +0000 2024`, or the zoneless
/// asctime form, read as UTC) as Unix seconds.
fn separator_seconds(separator: &str) -> Option<u64> {
    let text = separator
        .split_whitespace()
        .skip(2)
        .collect::<Vec<_>>()
        .join(" ");
    if let Ok(date) = chrono::DateTime::parse_from_str(&text, "%a %b %d %H:%M:%S %z %Y") {
        return u64::try_from(date.timestamp()).ok();
    }
    chrono::NaiveDateTime::parse_from_str(&text, "%a %b %e %H:%M:%S %Y")
        .ok()
        .and_then(|date| u64::try_from(date.and_utc().timestamp()).ok())
}

/// A Takeout `X-Gmail-Labels` value as the label ids the Gmail API uses:
/// system labels by their ids, categories as `CATEGORY_*`, the owner's own
/// labels by name; Takeout's own "Opened" and "Archived" are not labels.
fn takeout_labels(value: &str) -> Vec<String> {
    let mut labels: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut pieces = Vec::new();
    for ch in value.chars() {
        match ch {
            '"' => quoted = !quoted,
            ',' if !quoted => pieces.push(std::mem::take(&mut current)),
            _ => current.push(ch),
        }
    }
    pieces.push(current);
    for piece in pieces {
        let label = piece.trim();
        if label.is_empty() {
            continue;
        }
        let lower = label.to_ascii_lowercase();
        let mapped = match lower.as_str() {
            "inbox" => "INBOX".to_owned(),
            "sent" => "SENT".to_owned(),
            "trash" => "TRASH".to_owned(),
            "spam" => "SPAM".to_owned(),
            "draft" | "drafts" => "DRAFT".to_owned(),
            "important" => "IMPORTANT".to_owned(),
            "starred" => "STARRED".to_owned(),
            "unread" => "UNREAD".to_owned(),
            "chat" | "chats" => "CHAT".to_owned(),
            "opened" | "archived" => continue,
            _ => match lower.strip_prefix("category ") {
                Some(category) => format!(
                    "CATEGORY_{}",
                    category.trim().to_ascii_uppercase().replace(' ', "_")
                ),
                None => label.to_owned(),
            },
        };
        if !labels.contains(&mapped) {
            labels.push(mapped);
        }
    }
    labels
}

/// One call's landings into one source.
struct Intake<'v> {
    vault: &'v Vault,
    source: EntityId,
    row: MailSourceRow,
    landing: Landing<'v>,
    /// Whether the source reads Gmail ids (a Takeout export).
    gmail: bool,
    newer_than: Option<u64>,
    report: MailMboxImportReport,
}

impl Intake<'_> {
    fn headers(&self, message: &MboxMessage, parsed: &MimeMessage<'_>) -> Option<MailHeaders> {
        let rfc_message_id = parsed.header("message-id").filter(|id| !id.is_empty());
        let (provider_id, thread_id, labels) = if self.gmail {
            let id = gmail_message_id(&message.separator, parsed)?;
            let thread = parsed
                .header("x-gm-thrid")
                .and_then(|value| value.trim().parse::<u64>().ok())
                .map(|thread| format!("{thread:x}"));
            let labels = parsed
                .header("x-gmail-labels")
                .map(|value| takeout_labels(&value))
                .unwrap_or_default();
            (id, thread, labels)
        } else {
            // Named as the IMAP wire names a message (fix list row 19145).
            let id = rfc_message_id.as_deref().map_or_else(
                || format!("mbox{}", &blake3::hash(&message.raw).to_hex()[..32]),
                |message_id| content_id(message_id, &message.raw),
            );
            (id, None, Vec::new())
        };
        let date = parsed.header("date").as_deref().and_then(rfc2822_seconds);
        let received_at = separator_seconds(&message.separator).or(date).unwrap_or(0);
        let addresses = |name: &str| {
            parsed
                .header(name)
                .map(|value| address_list(&value))
                .unwrap_or_default()
        };
        Some(MailHeaders {
            provider_id,
            thread_id,
            rfc_message_id,
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
            received_at,
            sent_by_mailbox: labels.iter().any(|label| label == "SENT"),
            trash_or_spam: labels
                .iter()
                .any(|label| label == "TRASH" || label == "SPAM"),
            draft: labels.iter().any(|label| label == "DRAFT"),
            labels,
        })
    }

    /// Lands one message whole, unless it is left out or held whole
    /// already.
    fn take(&mut self, message: &MboxMessage) -> MemoryResult<()> {
        if message.oversized {
            self.report.skipped += 1;
            return Ok(());
        }
        let parsed = MimeMessage::parse(&message.raw);
        let Some(headers) = self.headers(message, &parsed) else {
            self.report
                .refuse("a message with no Gmail id: not a Google Takeout export".to_owned());
            return Ok(());
        };
        if headers.labels.iter().any(|label| label == "CHAT") || !copies(&headers, self.newer_than)
        {
            self.report.skipped += 1;
            return Ok(());
        }
        let held = {
            let txn = self
                .vault
                .store
                .env
                .read_txn()
                .map_err(crate::Error::from)?;
            OCCURRENCES.get(
                &self.vault.store,
                &txn,
                &occurrence_key(self.source, &headers.provider_id),
            )?
        };
        if held.is_some_and(|held| {
            held.stage == MailStage::Body || held.presence != MailPresence::Present
        }) {
            self.report.same += 1;
            return Ok(());
        }
        let body = parsed.body();
        let full = MailFull {
            headers: headers.clone(),
            body_text: body.text,
            attachments: body.attachments,
        };
        match self.landing.land(&self.row, &headers, Some(&full), false)? {
            LandOutcome::Landed => self.report.landed += 1,
            LandOutcome::Same => self.report.same += 1,
            LandOutcome::Refused(reason) => self.report.refuse(reason),
        }
        Ok(())
    }

    fn save(&self, key: &(EntityId, [u8; 32]), progress: &MboxImportProgress) -> MemoryResult<()> {
        self.vault
            .with_write_txn_grouped(|txn| IMPORTS.put(&self.vault.store, txn, key, progress))?;
        Ok(())
    }
}

/// Reads up to `budget` messages of one mbox stream into `intake`, keeping
/// the place in `progress`. Answers whether the stream ended.
fn read_stream<R: BufRead>(
    mut reader: MboxReader<R>,
    key: &(EntityId, [u8; 32]),
    progress: &mut MboxImportProgress,
    budget: &mut u32,
    intake: &mut Intake<'_>,
) -> MemoryResult<bool> {
    while *budget > 0 {
        let Some(message) = reader.next_message().map_err(|error| unreadable(&error))? else {
            return Ok(true);
        };
        *budget -= 1;
        intake.take(&message)?;
        progress.offset = reader.resume_offset();
        progress.read += 1;
        if progress.read % PROGRESS_EVERY == 0 {
            intake.save(key, progress)?;
        }
    }
    Ok(false)
}

/// Reads the next `limit` messages of the file at `path`: a plain mbox, or
/// each mbox file of a `.zip` in turn.
fn read_file(
    path: &Path,
    key: &(EntityId, [u8; 32]),
    progress: &mut MboxImportProgress,
    limit: u32,
    intake: &mut Intake<'_>,
) -> MemoryResult<()> {
    let mut budget = limit;
    if !progress.path.to_ascii_lowercase().ends_with(".zip") {
        let mut file = File::open(path).map_err(|error| unreadable(&error))?;
        file.seek(SeekFrom::Start(progress.offset))
            .map_err(|error| unreadable(&error))?;
        let reader = BufReader::with_capacity(READ_BUFFER_BYTES, file);
        if read_stream(
            MboxReader::new(reader, progress.offset),
            key,
            progress,
            &mut budget,
            intake,
        )? {
            progress.done = true;
        }
        return Ok(());
    }
    let file = File::open(path).map_err(|error| unreadable(&error))?;
    let mut archive = zip::ZipArchive::new(file).map_err(|error| zip_unreadable(&error))?;
    let mut entries = Vec::new();
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|error| zip_unreadable(&error))?;
        if !entry.is_dir() && entry.name().to_ascii_lowercase().ends_with(".mbox") {
            entries.push(index);
        }
    }
    if entries.is_empty() {
        return Err(MemoryError::bad_request_with(
            "the archive holds no .mbox file",
            &["Export Mail from Google Takeout as mbox, then import its .zip or its .mbox file."],
        ));
    }
    while let Some(&index) = entries.get(progress.entry as usize) {
        let entry = archive
            .by_index(index)
            .map_err(|error| zip_unreadable(&error))?;
        let mut reader = BufReader::with_capacity(READ_BUFFER_BYTES, entry);
        // A zipped mbox reads from its start: what an earlier call read is
        // passed over.
        std::io::copy(
            &mut (&mut reader).take(progress.offset),
            &mut std::io::sink(),
        )
        .map_err(|error| unreadable(&error))?;
        let ended = read_stream(
            MboxReader::new(reader, progress.offset),
            key,
            progress,
            &mut budget,
            intake,
        )?;
        if !ended {
            return Ok(());
        }
        progress.entry += 1;
        progress.offset = 0;
    }
    progress.done = true;
    Ok(())
}

impl Memory<'_> {
    /// Imports the next messages of an mbox file or a Google Takeout `.zip`
    /// on this device into one of the pack's mailboxes, by the mailbox's own
    /// person (a group address by an Owner or an Admin), as the vault's
    /// owner on this device: see the module doc. It reads the file outside
    /// any vault transaction; each message lands in its own commit.
    pub fn mail_sources_import_mbox(
        &self,
        input: &MailMboxImportRequest,
    ) -> MemoryResult<MailMboxImportReport> {
        let owner = self.embedded_owner("vault.mail.sources.import_mbox")?;
        let source = EntityId::from_hex(&input.source_ref)?;
        let vault = self.vault();
        let path = Path::new(&input.path);
        if !path.is_absolute() {
            return Err(MemoryError::bad_request(
                "name the mbox file by its absolute path",
            ));
        }
        let metadata = std::fs::metadata(path).map_err(|error| unreadable(&error))?;
        if !metadata.is_file() {
            return Err(MemoryError::bad_request("the path names no file"));
        }
        let size = metadata.len();
        let modified = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |since| since.as_secs());
        let key = (source, *blake3::hash(input.path.as_bytes()).as_bytes());
        let (row, progress) = {
            let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
            require_pack_active_in(vault, &txn)?;
            let row = SOURCES
                .get(&vault.store, &txn, &source)?
                .filter(|row| row.kind.is_mailbox() && row.status == MailSourceStatus::Active)
                .ok_or_else(|| MemoryError::not_found("no syncing mailbox source by that ref"))?;
            if row.kind == MailSourceKind::GroupAddress {
                if !super::compliance::manages_in(vault, &txn, self.actor())? {
                    return Err(MemoryError::bad_request(
                        "a group address's mail is imported by an Owner or an Admin",
                    ));
                }
            } else if row.owner != Some(self.mail_caller_person_in(&txn)?) {
                return Err(MemoryError::bad_request(
                    "a mailbox's mail is imported by the person it belongs to",
                ));
            }
            let progress = IMPORTS
                .get(&vault.store, &txn, &key)?
                .filter(|progress| progress.size == size && progress.modified == modified);
            (row, progress)
        };
        let gmail = reads_google_mail(row.provider);
        if !gmail && row.provider != MailProvider::Imap {
            return Err(MemoryError::bad_request_with(
                "an mbox file imports into a Google or an IMAP mailbox",
                &["A Microsoft 365 mailbox copies through its own sync."],
            ));
        }
        let at = crate::unix_seconds_now();
        let newer_than = match row.copy {
            MailCopySetting::SearchOnly => {
                return Err(MemoryError::bad_request(
                    "this mailbox keeps no copy (search only), so nothing imports",
                ));
            }
            MailCopySetting::RecentMonths { months } => {
                Some(at.saturating_sub(u64::from(months) * MONTH_SECONDS))
            }
            MailCopySetting::All => None,
        };
        let mut progress = progress.unwrap_or_else(|| MboxImportProgress {
            path: input.path.clone(),
            size,
            modified,
            ..MboxImportProgress::default()
        });
        let mut intake = Intake {
            vault,
            source,
            row,
            landing: Landing::new(vault, &owner, source, at)?,
            gmail,
            newer_than,
            report: MailMboxImportReport {
                source_ref: source.to_hex(),
                ..MailMboxImportReport::default()
            },
        };
        if !progress.done {
            let limit = input
                .messages
                .unwrap_or(DEFAULT_MESSAGES)
                .clamp(1, MAX_MESSAGES);
            let outcome = read_file(path, &key, &mut progress, limit, &mut intake);
            progress.landed += intake.report.landed;
            progress.updated_at = at;
            intake.save(&key, &progress)?;
            outcome?;
        }
        intake.report.read_total = progress.read;
        intake.report.done = progress.done;
        Ok(intake.report)
    }
}
