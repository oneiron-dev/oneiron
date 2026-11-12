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
//! - An IMAP mailbox on Google's IMAP host takes a Takeout export by the
//!   same Gmail id, as the IMAP wire names a message there; it lands under
//!   no label, and the live sync files it under the folders that hold it. A
//!   message with no Gmail id is refused.
//! - Any other IMAP mailbox takes any mbox, and a message is named as the
//!   IMAP wire names it where the server names messages neither by Gmail's
//!   id nor by its own (`OBJECTID`). Its header id, the hash of its
//!   `Message-ID`, its header block and its size with each line ended by
//!   CRLF, only proposes a name (fix list row 19145): when the vault holds a
//!   copy under that id, the BLAKE3 of the whole message decides. The same
//!   as that copy's, it is that message; another, or not known (a copy the
//!   live sync landed by its headers only, or a place it named by that id
//!   whose message never landed), it is its own message, named by its
//!   digest. A forgotten copy whose digest is not known is a fence nothing
//!   proves the entry apart from: the entry is that message, and lands no
//!   more. One with no `Message-ID` is named by the hash of its bytes.
//!   Every message landed keeps its digest, so a copy the live sync finds
//!   later is proved against it; where the server names messages by
//!   `EMAILID`, the live sync names a copy proved so by the import's id.
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

use super::gmail::{reads_google_mail, rfc2822_seconds};
use super::imap::{
    content_id, digest_variant_id, gmail_id, imap_account_on_gmail, imap_id_mapped, whole_digest,
};
use super::importer::{MONTH_SECONDS, copies};
use super::landing::{LandOutcome, Landing};
use super::mbox::{MboxMessage, MboxReader};
use super::mime::MimeMessage;
use super::pack::require_pack_active_in;
use super::source::{
    MailCopySetting, MailProvider, MailSourceKind, MailSourceRow, MailSourceStatus, SOURCES,
};
use super::state::{MailOccurrence, MailPresence, MailStage, OCCURRENCES, occurrence_key};
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
#[doc(hidden)]
use oneiron_verb_wire::mail_pack::mbox_import::MAX_REASONS;
#[doc(hidden)]
pub use oneiron_verb_wire::mail_pack::mbox_import::{MailMboxImportReport, MailMboxImportRequest};

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

fn unreadable(error: &std::io::Error) -> MemoryError {
    MemoryError::bad_request(format!("the file cannot be read: {error}"))
}

fn zip_unreadable(error: &zip::result::ZipError) -> MemoryError {
    MemoryError::bad_request(format!("the archive cannot be read: {error}"))
}

/// The Gmail id of a Takeout message: the decimal `X-GM-MSGID` its
/// separator (`From <id>@xxx <date>`) or its header carries, as the hex the
/// Gmail API and the IMAP wire on Gmail name it by.
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
    Some(gmail_id(id))
}

/// The size of the message `raw` as an IMAP server counts it
/// (`RFC822.SIZE`): each line ended by CRLF.
fn crlf_size(raw: &[u8]) -> u64 {
    let mut size = 0_u64;
    let mut previous = 0_u8;
    for &byte in raw {
        if byte == b'\n' && previous != b'\r' {
            size += 1;
        }
        size += 1;
        previous = byte;
    }
    size
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

/// How an import names each message: as its source's live wire names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImportNaming {
    /// A Google mailbox: the Gmail API's id, thread and labels.
    GmailApi,
    /// An IMAP mailbox on Google's IMAP host: the Gmail id, as the IMAP wire
    /// names a message where the server announces `X-GM-EXT-1`.
    GmailImap,
    /// Any other IMAP mailbox: its `Message-ID`, header block and size,
    /// proved by its whole digest on a collision.
    HeaderBlock,
}

/// The headers the mbox message `raw` lands with, named by its header block
/// (fix list row 20852). A test door: built only under
/// `--cfg oneiron_test_support`.
#[cfg(oneiron_test_support)]
pub(crate) fn mbox_landed_headers(raw: &[u8]) -> Option<MailHeaders> {
    let message = MboxMessage {
        separator: "From MAILER-DAEMON Thu Nov 12 00:00:00 2026".to_owned(),
        raw: raw.to_vec(),
        oversized: false,
    };
    Intake::headers(
        ImportNaming::HeaderBlock,
        &message,
        &MimeMessage::parse(raw),
    )
}

/// One call's landings into one source.
struct Intake<'v> {
    vault: &'v Vault,
    source: EntityId,
    row: MailSourceRow,
    landing: Landing<'v>,
    naming: ImportNaming,
    newer_than: Option<u64>,
    report: MailMboxImportReport,
}

impl Intake<'_> {
    /// A message's headers, named as `naming` names it: its labels Takeout's
    /// and its address headers read from its whole raw header block, each
    /// mailbox apart, as a reply's recipients take them (fix list rows 20520,
    /// 20852); `None` for one its source names by a Gmail id it does not
    /// carry.
    fn headers(
        naming: ImportNaming,
        message: &MboxMessage,
        parsed: &MimeMessage<'_>,
    ) -> Option<MailHeaders> {
        let rfc_message_id = parsed.header("message-id").filter(|id| !id.is_empty());
        let takeout = || {
            parsed
                .header("x-gmail-labels")
                .map(|value| takeout_labels(&value))
                .unwrap_or_default()
        };
        let (provider_id, thread_id, labels) = match naming {
            ImportNaming::GmailApi => {
                let id = gmail_message_id(&message.separator, parsed)?;
                let thread = parsed
                    .header("x-gm-thrid")
                    .and_then(|value| value.trim().parse::<u64>().ok())
                    .map(|thread| format!("{thread:x}"));
                (id, thread, takeout())
            }
            // Named as the IMAP wire on Gmail names it, never in the other
            // namespace (fix list row 19145).
            ImportNaming::GmailImap => (
                gmail_message_id(&message.separator, parsed)?,
                None,
                takeout(),
            ),
            ImportNaming::HeaderBlock => {
                // Named as the IMAP wire names a message (fix list row 19145).
                let id = rfc_message_id.as_deref().map_or_else(
                    || format!("mbox{}", &blake3::hash(&message.raw).to_hex()[..32]),
                    |message_id| content_id(message_id, &message.raw, crlf_size(&message.raw)),
                );
                (id, None, Vec::new())
            }
        };
        let date = parsed.header("date").as_deref().and_then(rfc2822_seconds);
        let received_at = separator_seconds(&message.separator).or(date).unwrap_or(0);
        // A parse keeps only a message's first header fields, so a late
        // Reply-To would be lost and the reply would go to From.
        let addresses = super::mime::raw_address_headers(&message.raw);
        Some(MailHeaders {
            provider_id,
            thread_id,
            rfc_message_id,
            in_reply_to: parsed.header("in-reply-to").filter(|id| !id.is_empty()),
            references: parsed
                .header("references")
                .map(|value| value.split_whitespace().map(str::to_owned).collect())
                .unwrap_or_default(),
            from: Some(addresses.from.join(", ")).filter(|from| !from.is_empty()),
            to: addresses.to,
            cc: addresses.cc,
            reply_to: addresses.reply_to,
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
        let Some(mut headers) = Self::headers(self.naming, message, &parsed) else {
            let reason = if self.naming == ImportNaming::GmailImap {
                "a message with no Gmail id: a Gmail mailbox over IMAP names each message by \
                 its Gmail id, which a Google Takeout export carries"
            } else {
                "a message with no Gmail id: not a Google Takeout export"
            };
            self.report.refuse(reason.to_owned());
            return Ok(());
        };
        if headers.labels.iter().any(|label| label == "CHAT") || !copies(&headers, self.newer_than)
        {
            self.report.skipped += 1;
            return Ok(());
        }
        let digest = whole_digest(&message.raw);
        let mut held = self.occurrence(&headers.provider_id)?;
        // A header id is proved as the IMAP wire proves it (fix list row
        // 19145): a copy under it whose digest is another, or not known, is
        // another message, and this one is named by its own digest; but a
        // forgotten copy whose digest is not known is a fence nothing
        // proves this one apart from, and it holds. A place the live wire
        // named by that id, whose message never landed, is a copy whose
        // digest an import cannot read.
        if self.naming == ImportNaming::HeaderBlock && headers.rfc_message_id.is_some() {
            let proved = match held.as_ref() {
                Some(held) => match held.content_digest {
                    Some(kept) => kept == digest,
                    None => matches!(held.presence, MailPresence::Forgotten { .. }),
                },
                None => !imap_id_mapped(self.vault, self.source, &headers.provider_id)?,
            };
            if !proved {
                headers.provider_id = digest_variant_id(&headers.provider_id, &digest);
                held = self.occurrence(&headers.provider_id)?;
            }
        }
        if held.as_ref().is_some_and(|held| {
            held.stage == MailStage::Body || held.presence != MailPresence::Present
        }) {
            self.report.same += 1;
            return Ok(());
        }
        // An IMAP mailbox's labels are the folders its wire reads, which an
        // mbox does not name: a copy the live sync landed keeps its own, and
        // a new one waits for that sync to file it. It was sent by the
        // mailbox when either says so.
        if self.naming != ImportNaming::GmailApi {
            if let Some(held) = held {
                headers.labels = held.labels;
                headers.sent_by_mailbox |= held.reply.is_some_and(|reply| reply.sent_by_mailbox);
            } else {
                headers.labels.clear();
            }
        }
        let body = parsed.body();
        let full = MailFull {
            headers: headers.clone(),
            body_text: body.text,
            attachments: body.attachments,
            content_digest: Some(digest),
        };
        match self.landing.land(&self.row, &headers, Some(&full), false)? {
            LandOutcome::Landed => self.report.landed += 1,
            LandOutcome::Same => self.report.same += 1,
            LandOutcome::Refused(reason) => self.report.refuse(reason),
        }
        Ok(())
    }

    /// The source's copy of `provider_id`, of any presence.
    fn occurrence(&self, provider_id: &str) -> MemoryResult<Option<MailOccurrence>> {
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        Ok(OCCURRENCES.get(
            &self.vault.store,
            &txn,
            &occurrence_key(self.source, provider_id),
        )?)
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
        let naming = if reads_google_mail(row.provider) {
            ImportNaming::GmailApi
        } else if row.provider != MailProvider::Imap {
            return Err(MemoryError::bad_request_with(
                "an mbox file imports into a Google or an IMAP mailbox",
                &["A Microsoft 365 mailbox copies through its own sync."],
            ));
        } else if imap_account_on_gmail(&row.provider_account) {
            ImportNaming::GmailImap
        } else {
            ImportNaming::HeaderBlock
        };
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
            naming,
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
