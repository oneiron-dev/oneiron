//! The Gmail wire of the mail importer (FIX 12559 row 1b; MAIL-GOOGLE = A):
//! Gmail REST over `reqwest::blocking`, for a Google Workspace or Google
//! mailbox source, and the owner's door that runs one import step with it on
//! this device (`vault.mail.sources.sync`).
//!
//! Each provider call reads the source's own credential at its door
//! ([`Vault::with_mail_source_token_at_door`]): the custody record the source
//! names now, while the source is Active and the pack installed. HTTPS only,
//! no redirects; the Bearer header exists only inside the door callback,
//! marked sensitive. The token the door injects is the bare OAuth access
//! token or JSON carrying `access_token`; refreshing it is the host's custody
//! job. Before a source's first read the wire checks that the credential
//! reads the mailbox the source names (the Gmail profile's address), so a
//! credential for one mailbox never fills another mailbox's source.
//!
//! Call it from a blocking context: `reqwest::blocking` owns its own runtime.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::io::Read;
use std::time::Duration;

use base64::Engine as _;
use dom_query::Document;
use reqwest::StatusCode;
use reqwest::header::{AUTHORIZATION, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::importer::{MailSyncBudget, MailSyncReport};
use super::source::{MailProvider, MailSourceStatus, SOURCES};
use super::wire::{
    MailAttachmentRef, MailFull, MailHeaders, MailHistoryChange, MailHistoryPage, MailHistoryRead,
    MailIdPage, MailListQuery, MailMessageRef, MailProviderWire, MailSyncSource,
};
use crate::channel_identity_provider::gmail::GMAIL_CONNECTOR_EFFECTOR;
use crate::error::{Error, Result};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::secret_lease::DoorInjectionReceipt;
use crate::{EntityId, Vault};

const GMAIL_USER_URL: &str = "https://gmail.googleapis.com/gmail/v1/users/me";
/// The largest Gmail answer read: a whole message with its inline parts.
const MAX_GMAIL_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;
const GMAIL_LIST_PAGE_SIZE: u32 = 100;
const GMAIL_HISTORY_PAGE_SIZE: u32 = 500;
/// The most bodies one step of `vault.mail.sources.sync` fills in.
const MAX_BODIES_PER_STEP: u32 = 500;
/// The deepest MIME nesting read for a body.
const MAX_PART_DEPTH: usize = 32;
/// The headers a header stage reads.
const MESSAGE_HEADERS: [&str; 8] = [
    "From",
    "To",
    "Cc",
    "Subject",
    "Date",
    "Message-ID",
    "In-Reply-To",
    "References",
];
/// HTML elements whose text is not the message's.
const HTML_IGNORED: [&str; 6] = ["head", "script", "style", "template", "noscript", "title"];
/// HTML elements that start a new line of text.
const HTML_BLOCKS: [&str; 18] = [
    "p",
    "div",
    "br",
    "tr",
    "li",
    "ul",
    "ol",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "table",
    "blockquote",
    "pre",
    "hr",
    "section",
];

impl Vault {
    /// Runs `apply` with the credential of the mailbox source `source` at
    /// its door: the custody record the source names now, while the pack is
    /// installed, the source Active and still the one the wire was given
    /// (provider, address and custody record), and no other source names
    /// that custody record. The value never leaves `apply`; the receipt
    /// carries no value bytes.
    pub(crate) fn with_mail_source_token_at_door(
        &self,
        source: &MailSyncSource,
        effector: &str,
        apply: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<DoorInjectionReceipt> {
        let wtxn = self.store.env.write_txn()?;
        if super::pack::require_pack_active_in(self, &wtxn).is_err() {
            return Err(refused("mail_source_pack_not_installed"));
        }
        let row = SOURCES
            .get(&self.store, &wtxn, &source.source_ref)?
            .ok_or_else(|| refused("mail_source_unknown"))?;
        if row.status != MailSourceStatus::Active
            || !row.kind.is_mailbox()
            || row.provider != source.provider
            || row.custody_ref != source.custody_ref
            || !row.address.eq_ignore_ascii_case(&source.address)
        {
            return Err(refused("mail_source_changed_or_not_active"));
        }
        // One credential fills one mailbox source: a second mailbox naming
        // the same custody record reads nothing through it. (A person's
        // calendar may ride the same Google credential.)
        for other in SOURCES.iter_from(&self.store, &wtxn, &[])? {
            let (other_ref, other) = other?;
            if other_ref != source.source_ref
                && other.kind.is_mailbox()
                && other.custody_ref == row.custody_ref
            {
                return Err(refused("mail_source_credential_backs_another_source"));
            }
        }
        let custody_ref = row.custody_ref;
        self.inject_secret_at_door_in_txn(wtxn, &custody_ref, effector, apply)
    }
}

/// Host-side Gmail REST mail wire over `reqwest::blocking`, for the mailbox
/// sources of one vault.
pub struct HttpGmailMailWire<'v> {
    vault: &'v Vault,
    client: reqwest::blocking::Client,
    /// The sources whose credential this wire has seen read their mailbox.
    verified: RefCell<BTreeSet<EntityId>>,
}

/// One Gmail answer: its JSON, or the provider's "not found".
enum GmailAnswer {
    Found(Value),
    Gone,
}

impl<'v> HttpGmailMailWire<'v> {
    /// Builds the wire: HTTPS only, no redirects, a 60 s timeout.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when the TLS client cannot be built.
    pub fn new(vault: &'v Vault) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|_| refused("gmail_mail_http_client_setup_failed"))?;
        Ok(Self {
            vault,
            client,
            verified: RefCell::new(BTreeSet::new()),
        })
    }

    /// One GET with the source's credential, read at its door.
    fn get(
        &self,
        source: &MailSyncSource,
        url: &str,
        query: &[(&str, String)],
    ) -> Result<GmailAnswer> {
        if !reads_google_mail(source.provider) {
            return Err(refused("gmail_mail_wire_reads_google_mailboxes_only"));
        }
        let mut answer = None;
        let _receipt = self.vault.with_mail_source_token_at_door(
            source,
            GMAIL_CONNECTOR_EFFECTOR,
            &mut |token: &[u8]| {
                let auth = bearer_header(token)?;
                answer = Some(self.send(&auth, url, query)?);
                Ok(())
            },
        )?;
        answer.ok_or_else(|| refused("gmail_mail_credential_door_refused"))
    }

    fn send(&self, auth: &HeaderValue, url: &str, query: &[(&str, String)]) -> Result<GmailAnswer> {
        let response = self
            .client
            .get(url)
            .query(query)
            .header(AUTHORIZATION, auth.clone())
            .send()
            .map_err(|_| refused("gmail_mail_transport_failed"))?;
        let status = response.status();
        if status == StatusCode::NOT_FOUND {
            return Ok(GmailAnswer::Gone);
        }
        if !status.is_success() {
            return Err(Error::InvalidConfig(format!(
                "gmail_mail_status_{}",
                status.as_u16()
            )));
        }
        let mut bytes = Vec::new();
        response
            .take(MAX_GMAIL_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| refused("gmail_mail_response_unreadable"))?;
        if bytes.len() as u64 > MAX_GMAIL_RESPONSE_BYTES {
            return Err(refused("gmail_mail_response_too_large"));
        }
        serde_json::from_slice(&bytes)
            .map(GmailAnswer::Found)
            .map_err(|_| refused("gmail_mail_response_unreadable"))
    }

    /// The mailbox's Gmail profile: its address and current history id.
    fn profile(&self, source: &MailSyncSource) -> Result<Value> {
        match self.get(source, &format!("{GMAIL_USER_URL}/profile"), &[])? {
            GmailAnswer::Found(profile) => Ok(profile),
            GmailAnswer::Gone => Err(refused("gmail_mail_profile_not_found")),
        }
    }

    /// Checks once per source that its credential reads the mailbox it
    /// names; answers the profile when it read one.
    fn verify(&self, source: &MailSyncSource) -> Result<Option<Value>> {
        if self.verified.borrow().contains(&source.source_ref) {
            return Ok(None);
        }
        let profile = self.profile(source)?;
        let address = profile
            .get("emailAddress")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !address.trim().eq_ignore_ascii_case(source.address.trim()) {
            return Err(refused("gmail_mail_credential_reads_another_mailbox"));
        }
        self.verified.borrow_mut().insert(source.source_ref);
        Ok(Some(profile))
    }

    fn message_url(provider_id: &str) -> Result<String> {
        require_plain_id(provider_id)?;
        Ok(format!("{GMAIL_USER_URL}/messages/{provider_id}"))
    }
}

impl MailProviderWire for HttpGmailMailWire<'_> {
    fn current_anchor(&self, source: &MailSyncSource) -> Result<String> {
        let profile = match self.verify(source)? {
            Some(profile) => profile,
            None => self.profile(source)?,
        };
        profile
            .get("historyId")
            .and_then(id_text)
            .ok_or_else(|| refused("gmail_mail_profile_without_history_id"))
    }

    fn list_page(
        &self,
        source: &MailSyncSource,
        query: &MailListQuery,
        page: Option<&str>,
    ) -> Result<MailIdPage> {
        self.verify(source)?;
        // Trash and spam are left out by Gmail's default; drafts by the query.
        let search = match query.newer_than {
            Some(newer_than) => format!("-in:drafts after:{newer_than}"),
            None => "-in:drafts".to_owned(),
        };
        let mut params = vec![
            ("maxResults", GMAIL_LIST_PAGE_SIZE.to_string()),
            ("q", search),
        ];
        if let Some(page) = page {
            params.push(("pageToken", page.to_owned()));
        }
        let GmailAnswer::Found(listed) =
            self.get(source, &format!("{GMAIL_USER_URL}/messages"), &params)?
        else {
            return Err(refused("gmail_mail_listing_not_found"));
        };
        let mut messages = Vec::new();
        for entry in array(&listed, "messages") {
            messages.push(MailMessageRef {
                provider_id: plain_id(entry.get("id"))?,
                thread_id: text_of(entry.get("threadId")),
            });
        }
        Ok(MailIdPage {
            messages,
            next_page: text_of(listed.get("nextPageToken")),
        })
    }

    fn headers(&self, source: &MailSyncSource, provider_id: &str) -> Result<Option<MailHeaders>> {
        self.verify(source)?;
        let mut params = vec![("format", "metadata".to_owned())];
        params.extend(
            MESSAGE_HEADERS
                .iter()
                .map(|header| ("metadataHeaders", (*header).to_owned())),
        );
        match self.get(source, &Self::message_url(provider_id)?, &params)? {
            GmailAnswer::Found(message) => headers_of(&message).map(Some),
            GmailAnswer::Gone => Ok(None),
        }
    }

    fn full(&self, source: &MailSyncSource, provider_id: &str) -> Result<Option<MailFull>> {
        self.verify(source)?;
        let params = [("format", "full".to_owned())];
        match self.get(source, &Self::message_url(provider_id)?, &params)? {
            GmailAnswer::Found(message) => full_of(&message).map(Some),
            GmailAnswer::Gone => Ok(None),
        }
    }

    fn history(
        &self,
        source: &MailSyncSource,
        anchor: &str,
        page: Option<&str>,
    ) -> Result<MailHistoryRead> {
        self.verify(source)?;
        if anchor.is_empty() || !anchor.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(refused("gmail_mail_anchor_not_a_history_id"));
        }
        let mut params = vec![
            ("startHistoryId", anchor.to_owned()),
            ("maxResults", GMAIL_HISTORY_PAGE_SIZE.to_string()),
        ];
        for kind in ["messageAdded", "messageDeleted", "labelAdded", "labelRemoved"] {
            params.push(("historyTypes", kind.to_owned()));
        }
        if let Some(page) = page {
            params.push(("pageToken", page.to_owned()));
        }
        // Gmail answers 404 for a start it no longer keeps history from.
        let listed = match self.get(source, &format!("{GMAIL_USER_URL}/history"), &params)? {
            GmailAnswer::Found(listed) => listed,
            GmailAnswer::Gone => return Ok(MailHistoryRead::Expired),
        };
        let mut changes = Vec::new();
        for record in array(&listed, "history") {
            for added in array(record, "messagesAdded") {
                let Some(message) = added.get("message") else {
                    continue;
                };
                changes.push(MailHistoryChange::Added(MailMessageRef {
                    provider_id: plain_id(message.get("id"))?,
                    thread_id: text_of(message.get("threadId")),
                }));
            }
            for deleted in array(record, "messagesDeleted") {
                let Some(message) = deleted.get("message") else {
                    continue;
                };
                changes.push(MailHistoryChange::Deleted {
                    provider_id: plain_id(message.get("id"))?,
                });
            }
            for changed in array(record, "labelsAdded")
                .iter()
                .chain(array(record, "labelsRemoved"))
            {
                let Some(message) = changed.get("message") else {
                    continue;
                };
                let labels = labels_of(message);
                changes.push(MailHistoryChange::Labels {
                    provider_id: plain_id(message.get("id"))?,
                    trash_or_spam: trash_or_spam(&labels),
                    labels,
                });
            }
        }
        let reached = listed
            .get("historyId")
            .and_then(id_text)
            .unwrap_or_else(|| anchor.to_owned());
        Ok(MailHistoryRead::Page(MailHistoryPage {
            changes,
            next_page: text_of(listed.get("nextPageToken")),
            anchor: reached,
        }))
    }
}

/// Whether the Gmail wire reads `provider`'s mailboxes.
const fn reads_google_mail(provider: MailProvider) -> bool {
    matches!(provider, MailProvider::GoogleWorkspace | MailProvider::Google)
}

/// A message's headers from its Gmail `metadata` or `full` answer.
fn headers_of(message: &Value) -> Result<MailHeaders> {
    let provider_id = plain_id(message.get("id"))?;
    let labels = labels_of(message);
    let headers = message.pointer("/payload/headers");
    let header = |name: &str| header_value(headers, name).map(str::trim);
    let received_at = message
        .get("internalDate")
        .and_then(id_text)
        .and_then(|millis| millis.parse::<u64>().ok())
        .map_or(0, |millis| millis / 1_000);
    Ok(MailHeaders {
        provider_id,
        thread_id: text_of(message.get("threadId")),
        rfc_message_id: header("Message-ID").map(str::to_owned),
        in_reply_to: header("In-Reply-To").map(str::to_owned),
        references: header("References")
            .map(|references| references.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_default(),
        from: header("From").map(str::to_owned),
        to: header("To").map(address_list).unwrap_or_default(),
        cc: header("Cc").map(address_list).unwrap_or_default(),
        subject: header("Subject").map(str::to_owned),
        date: header("Date").and_then(rfc2822_seconds),
        received_at,
        sent_by_mailbox: labels.iter().any(|label| label == "SENT"),
        trash_or_spam: trash_or_spam(&labels),
        draft: labels.iter().any(|label| label == "DRAFT"),
        labels,
    })
}

/// A message read whole from its Gmail `full` answer: its plain text (or
/// its HTML's text), and its attachments described, never their bytes.
fn full_of(message: &Value) -> Result<MailFull> {
    let headers = headers_of(message)?;
    let mut parts = MessageParts::default();
    if let Some(payload) = message.get("payload") {
        collect_parts(payload, 0, &mut parts);
    }
    let body_text = if !parts.plain.is_empty() {
        Some(parts.plain.join("\n\n"))
    } else if !parts.html.is_empty() {
        Some(html_text(&parts.html.join("\n")))
    } else {
        None
    };
    Ok(MailFull {
        headers,
        body_text: body_text.filter(|text| !text.trim().is_empty()),
        attachments: parts.attachments,
    })
}

/// What a message's MIME parts hold.
#[derive(Default)]
struct MessageParts {
    plain: Vec<String>,
    html: Vec<String>,
    attachments: Vec<MailAttachmentRef>,
}

fn collect_parts(part: &Value, depth: usize, parts: &mut MessageParts) {
    if depth > MAX_PART_DEPTH {
        return;
    }
    let media_type = part
        .get("mimeType")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let filename = part
        .get("filename")
        .and_then(Value::as_str)
        .filter(|filename| !filename.is_empty());
    let body = part.get("body");
    let attachment_id = body
        .and_then(|body| body.get("attachmentId"))
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty());
    if filename.is_some() || (attachment_id.is_some() && !media_type.starts_with("text/")) {
        parts.attachments.push(MailAttachmentRef {
            part_id: part
                .get("partId")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            provider_attachment_id: attachment_id.map(str::to_owned),
            filename: filename.map(str::to_owned),
            size_bytes: body
                .and_then(|body| body.get("size"))
                .and_then(Value::as_u64)
                .unwrap_or(0),
            media_type,
        });
        return;
    }
    let children = array(part, "parts");
    if !children.is_empty() {
        for child in children {
            collect_parts(child, depth + 1, parts);
        }
        return;
    }
    let Some(data) = body
        .and_then(|body| body.get("data"))
        .and_then(Value::as_str)
    else {
        return;
    };
    let Some(text) = part_text(part, data) else {
        return;
    };
    if media_type == "text/plain" {
        parts.plain.push(text);
    } else if media_type == "text/html" {
        parts.html.push(text);
    }
}

/// A text part's words: its base64url data in the charset its
/// `Content-Type` names, UTF-8 when it names none or one unknown.
fn part_text(part: &Value, data: &str) -> Option<String> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(data.trim_end_matches('='))
        .ok()?;
    let encoding = header_value(part.get("headers"), "Content-Type")
        .and_then(charset_of)
        .and_then(|label| encoding_rs::Encoding::for_label(label.as_bytes()))
        .unwrap_or(encoding_rs::UTF_8);
    let (decoded, _, _) = encoding.decode(&bytes);
    Some(decoded.into_owned())
}

/// The `charset` parameter of a `Content-Type` value.
fn charset_of(content_type: &str) -> Option<String> {
    content_type.split(';').skip(1).find_map(|param| {
        let (name, value) = param.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("charset")
            .then(|| value.trim().trim_matches('"').to_owned())
    })
}

/// The visible text of an HTML body, a line per block.
fn html_text(html: &str) -> String {
    let document = Document::from(html);
    let mut out = String::new();
    let mut pending = vec![document.root()];
    while let Some(node) = pending.pop() {
        if node.is_text() {
            out.push_str(&node.text());
            continue;
        }
        if let Some(name) = node.node_name() {
            let name = name.to_ascii_lowercase();
            if HTML_IGNORED.contains(&name.as_str()) {
                continue;
            }
            if HTML_BLOCKS.contains(&name.as_str()) && !out.ends_with('\n') {
                out.push('\n');
            }
        }
        let children = node.children_it(false).collect::<Vec<_>>();
        pending.extend(children.into_iter().rev());
    }
    tidy_text(&out)
}

/// Text with each line's runs of whitespace made one space and no more than
/// one blank line in a row.
fn tidy_text(text: &str) -> String {
    let mut out = String::new();
    let mut blank = false;
    for line in text.lines() {
        let line = line.split_whitespace().collect::<Vec<_>>().join(" ");
        if line.is_empty() {
            if blank || out.is_empty() {
                continue;
            }
            blank = true;
        } else {
            blank = false;
        }
        out.push_str(&line);
        out.push('\n');
    }
    out.trim_end().to_owned()
}

/// The value of the header `name` in a Gmail header list, if any.
fn header_value<'v>(headers: Option<&'v Value>, name: &str) -> Option<&'v str> {
    headers?
        .as_array()?
        .iter()
        .find(|header| {
            header
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|held| held.eq_ignore_ascii_case(name))
        })?
        .get("value")?
        .as_str()
}

/// The addresses of an address-list header, split at the commas outside
/// quotes and angle brackets.
fn address_list(value: &str) -> Vec<String> {
    let mut addresses = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut angle = 0_u32;
    for ch in value.chars() {
        match ch {
            '"' => quoted = !quoted,
            '<' if !quoted => angle += 1,
            '>' if !quoted => angle = angle.saturating_sub(1),
            ',' if !quoted && angle == 0 => {
                push_address(&mut addresses, &current);
                current.clear();
                continue;
            }
            _ => {}
        }
        current.push(ch);
    }
    push_address(&mut addresses, &current);
    addresses
}

fn push_address(addresses: &mut Vec<String>, text: &str) {
    let text = text.trim();
    if !text.is_empty() {
        addresses.push(text.to_owned());
    }
}

/// An RFC 5322 `Date` value as Unix seconds; a trailing comment is dropped.
fn rfc2822_seconds(value: &str) -> Option<u64> {
    let bare = value.split_once(" (").map_or(value, |(head, _)| head).trim();
    chrono::DateTime::parse_from_rfc2822(bare)
        .ok()
        .and_then(|date| u64::try_from(date.timestamp()).ok())
}

fn labels_of(message: &Value) -> Vec<String> {
    array(message, "labelIds")
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn trash_or_spam(labels: &[String]) -> bool {
    labels.iter().any(|label| label == "TRASH" || label == "SPAM")
}

fn array<'v>(value: &'v Value, key: &str) -> &'v [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
}

/// A nonempty string field.
fn text_of(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

/// A Gmail id that is a string or a number (`historyId`, `internalDate`).
fn id_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) if !text.is_empty() => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

/// A Gmail message id: letters and digits only, so it is safe in a path.
fn plain_id(value: Option<&Value>) -> Result<String> {
    let id = value.and_then(Value::as_str).unwrap_or_default();
    require_plain_id(id)?;
    Ok(id.to_owned())
}

fn require_plain_id(id: &str) -> Result<()> {
    if id.is_empty() || !id.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err(refused("gmail_mail_message_id_not_plain"));
    }
    Ok(())
}

/// The sensitive `Authorization: Bearer` value for one injected credential.
fn bearer_header(token: &[u8]) -> Result<HeaderValue> {
    let invalid = || refused("gmail_mail_credential_not_an_access_token");
    let text = std::str::from_utf8(token).map_err(|_| invalid())?.trim();
    let access_token = if text.starts_with('{') {
        let value: Value = serde_json::from_str(text).map_err(|_| invalid())?;
        value
            .get("access_token")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?
            .trim()
            .to_owned()
    } else {
        text.to_owned()
    };
    if access_token.is_empty() {
        return Err(invalid());
    }
    let mut value =
        HeaderValue::from_str(&format!("Bearer {access_token}")).map_err(|_| invalid())?;
    value.set_sensitive(true);
    Ok(value)
}

fn refused(code: &str) -> Error {
    Error::InvalidConfig(code.to_owned())
}

/// `vault.mail.sources.sync`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailSourceSyncRequest {
    /// The mailbox source, 32-hex.
    pub source_ref: String,
    /// The bodies this step fills in; 50 when absent, at most 500.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bodies: Option<u32>,
}

impl Memory<'_> {
    /// One bounded import step of a Google mailbox source on this device,
    /// through the Gmail wire, by the vault's owner (FIX 12559 row 1b): new
    /// changes since the source's anchor, the next newest-first pages under
    /// its copy setting, then waiting bodies. The rows land bound to the
    /// source's audience; the owner's authority lands them and reads none.
    /// It reads the provider over blocking HTTP: call it off any async
    /// runtime, as the local SDKs do.
    pub fn mail_sources_sync(&self, input: &MailSourceSyncRequest) -> MemoryResult<MailSyncReport> {
        let owner = self.embedded_owner("vault.mail.sources.sync")?;
        let source = EntityId::from_hex(&input.source_ref)?;
        let vault = self.vault();
        let snapshot = vault
            .mail_sync_source(source)?
            .ok_or_else(|| MemoryError::not_found("no mailbox source by that ref"))?;
        if !reads_google_mail(snapshot.provider) {
            return Err(MemoryError::bad_request_with(
                "this device reads Google mailboxes so far",
                &["Connect a Google Workspace or Google mailbox; other providers follow."],
            ));
        }
        let wire = HttpGmailMailWire::new(vault)?;
        let mut budget = MailSyncBudget::default();
        if let Some(bodies) = input.bodies {
            budget.bodies = bodies.min(MAX_BODIES_PER_STEP);
        }
        vault.mail_sync_step(&owner, source, &wire, budget)
    }
}
