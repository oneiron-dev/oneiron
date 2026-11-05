//! The Gmail wire of the mail importer (FIX 12559 row 1b; MAIL-GOOGLE = A):
//! Gmail REST over `reqwest::blocking`, for a Google Workspace or Google
//! mailbox source.
//!
//! Each provider call reads the source's own credential at its door
//! ([`Vault::with_source_token_at_door`]), effector `connector:gmail`.
//! HTTPS only, no redirects; the Bearer header exists only inside the door
//! callback, marked sensitive. Refreshing the token is the host's custody
//! job. Before a source's first read the wire checks that the credential
//! reads the mailbox the source names (the Gmail profile's address), so a
//! credential for one mailbox never fills another mailbox's source.
//!
//! Call it from a blocking context: `reqwest::blocking` owns its own runtime.

use std::cell::RefCell;
use std::collections::BTreeSet;

use base64::Engine as _;
use reqwest::header::AUTHORIZATION;
use serde_json::Value;

use super::credential::WireReads;
use super::rest::{
    self, RestAnswer, array, bearer_header, header_value, html_text, refused, text_of,
};
use super::source::MailProvider;
use super::wire::{
    MailAttachmentRef, MailFull, MailHeaders, MailHistoryChange, MailHistoryPage, MailHistoryRead,
    MailIdPage, MailListQuery, MailMessageRef, MailProviderWire, MailSyncSource,
};
use crate::channel_identity_provider::gmail::GMAIL_CONNECTOR_EFFECTOR;
use crate::error::Result;
use crate::{EntityId, Vault};

const GMAIL_USER_URL: &str = "https://gmail.googleapis.com/gmail/v1/users/me";
const GMAIL_LIST_PAGE_SIZE: u32 = 100;
const GMAIL_HISTORY_PAGE_SIZE: u32 = 500;
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

/// Host-side Gmail REST mail wire over `reqwest::blocking`, for the mailbox
/// sources of one vault.
pub struct HttpGmailMailWire<'v> {
    vault: &'v Vault,
    client: reqwest::blocking::Client,
    /// The sources whose credential this wire has seen read their mailbox.
    verified: RefCell<BTreeSet<EntityId>>,
}

impl<'v> HttpGmailMailWire<'v> {
    /// Builds the wire: HTTPS only, no redirects, a 60 s timeout.
    ///
    /// # Errors
    ///
    /// [`crate::Error::InvalidConfig`] when the TLS client cannot be built.
    pub fn new(vault: &'v Vault) -> Result<Self> {
        Ok(Self {
            vault,
            client: rest::https_client()?,
            verified: RefCell::new(BTreeSet::new()),
        })
    }

    /// One GET with the source's credential, read at its door; `None` for
    /// Gmail's "not found".
    fn get(
        &self,
        source: &MailSyncSource,
        url: &str,
        query: &[(&str, String)],
    ) -> Result<Option<Value>> {
        if !reads_google_mail(source.provider) {
            return Err(refused("gmail_mail_wire_reads_google_mailboxes_only"));
        }
        let mut answer: Option<RestAnswer> = None;
        let _receipt = self.vault.with_source_token_at_door(
            source,
            WireReads::Mailbox,
            GMAIL_CONNECTOR_EFFECTOR,
            &mut |token: &[u8]| {
                let auth = bearer_header(token)?;
                let request = self.client.get(url).query(query).header(AUTHORIZATION, auth);
                answer = Some(rest::send(request)?);
                Ok(())
            },
        )?;
        answer
            .ok_or_else(|| refused("gmail_mail_credential_door_refused"))?
            .found_or_gone("gmail_mail")
    }

    /// The mailbox's Gmail profile: its address and current history id.
    fn profile(&self, source: &MailSyncSource) -> Result<Value> {
        self.get(source, &format!("{GMAIL_USER_URL}/profile"), &[])?
            .ok_or_else(|| refused("gmail_mail_profile_not_found"))
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
        let listed = self
            .get(source, &format!("{GMAIL_USER_URL}/messages"), &params)?
            .ok_or_else(|| refused("gmail_mail_listing_not_found"))?;
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
            Some(message) => headers_of(&message).map(Some),
            None => Ok(None),
        }
    }

    fn full(&self, source: &MailSyncSource, provider_id: &str) -> Result<Option<MailFull>> {
        self.verify(source)?;
        let params = [("format", "full".to_owned())];
        match self.get(source, &Self::message_url(provider_id)?, &params)? {
            Some(message) => full_of(&message).map(Some),
            None => Ok(None),
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
        let Some(listed) = self.get(source, &format!("{GMAIL_USER_URL}/history"), &params)? else {
            return Ok(MailHistoryRead::Expired);
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

    fn attachment(
        &self,
        source: &MailSyncSource,
        provider_id: &str,
        attachment: &MailAttachmentRef,
    ) -> Result<Option<Vec<u8>>> {
        self.verify(source)?;
        let message_url = Self::message_url(provider_id)?;
        // An attachment Gmail keeps apart is fetched by its id; a small one
        // rides inline in its part of the whole message.
        if let Some(id) = &attachment.provider_attachment_id {
            let plain = id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
            if id.is_empty() || !plain {
                return Err(refused("gmail_mail_attachment_id_not_plain"));
            }
            let url = format!("{message_url}/attachments/{id}");
            let Some(answer) = self.get(source, &url, &[])? else {
                return Ok(None);
            };
            let data = answer
                .get("data")
                .and_then(Value::as_str)
                .ok_or_else(|| refused("gmail_mail_attachment_without_data"))?;
            return base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(data.trim_end_matches('='))
                .map(Some)
                .map_err(|_| refused("gmail_mail_attachment_data_unreadable"));
        }
        let params = [("format", "full".to_owned())];
        let Some(message) = self.get(source, &message_url, &params)? else {
            return Ok(None);
        };
        Ok(message
            .get("payload")
            .and_then(|payload| part_bytes(payload, &attachment.part_id, 0)))
    }
}

/// The bytes of one part of a Gmail `full` answer, by its part id.
fn part_bytes(part: &Value, part_id: &str, depth: usize) -> Option<Vec<u8>> {
    if depth > MAX_PART_DEPTH {
        return None;
    }
    if part.get("partId").and_then(Value::as_str) == Some(part_id) {
        let data = part.pointer("/body/data").and_then(Value::as_str)?;
        return base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(data.trim_end_matches('='))
            .ok();
    }
    array(part, "parts")
        .iter()
        .find_map(|child| part_bytes(child, part_id, depth + 1))
}

/// Whether the Gmail wire reads `provider`'s mailboxes.
pub(super) const fn reads_google_mail(provider: MailProvider) -> bool {
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

/// The addresses of an address-list header, split at the commas outside
/// quotes and angle brackets.
pub(super) fn address_list(value: &str) -> Vec<String> {
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
pub(super) fn rfc2822_seconds(value: &str) -> Option<u64> {
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
