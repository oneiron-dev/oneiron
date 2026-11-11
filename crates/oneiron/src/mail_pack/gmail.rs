//! The Gmail wire of the mail importer (FIX 12559 row 1b; MAIL-GOOGLE = A):
//! Gmail REST over `reqwest::blocking`, for a Google Workspace or Google
//! mailbox source.
//!
//! Each provider call reads the source's own credential at its door
//! ([`Vault::with_source_token_at_door`]), effector `connector:gmail`.
//! HTTPS only, no redirects; the Bearer header exists only inside the door
//! callback, marked sensitive. Refreshing the token is the host's custody
//! job. Inside each door, before the credential presented there reads
//! anything, the wire checks that it reads the mailbox the source names (the
//! Gmail profile's address), once per credential: a credential for one
//! mailbox never fills another mailbox's source, even one replaced at its
//! door between two reads.
//!
//! Call it from a blocking context: `reqwest::blocking` owns its own runtime.

use std::collections::BTreeSet;

use base64::Engine as _;
use reqwest::header::{AUTHORIZATION, HeaderValue};
use serde_json::Value;

use super::credential::WireReads;
use super::rest::{
    self, FreshGoogleTokens, RestAnswer, VerifiedCredentials, array, header_value, html_text,
    refused, text_of,
};
use super::source::MailProvider;
use super::wire::{
    MailAddressHeaders, MailAttachmentRef, MailFull, MailHeaders, MailHistoryChange,
    MailHistoryPage, MailHistoryRead, MailIdPage, MailListQuery, MailMessageRef, MailProviderWire,
    MailSyncSource,
};
use crate::Vault;
use crate::channel_identity_provider::gmail::GMAIL_CONNECTOR_EFFECTOR;
use crate::error::Result;

const GMAIL_USER_URL: &str = "https://gmail.googleapis.com/gmail/v1/users/me";
const GMAIL_PROFILE_URL: &str = "https://gmail.googleapis.com/gmail/v1/users/me/profile";
/// The longest Gmail attachment id read.
const MAX_ATTACHMENT_ID_BYTES: usize = 1_024;
const GMAIL_LIST_PAGE_SIZE: u32 = 100;
const GMAIL_HISTORY_PAGE_SIZE: u32 = 500;
/// The deepest MIME nesting read for a body.
const MAX_PART_DEPTH: usize = 32;
/// The headers a header stage reads.
const MESSAGE_HEADERS: [&str; 9] = [
    "From",
    "To",
    "Cc",
    "Subject",
    "Date",
    "Message-ID",
    "In-Reply-To",
    "References",
    "Reply-To",
];

/// Host-side Gmail REST mail wire over `reqwest::blocking`, for the mailbox
/// sources of one vault.
pub struct HttpGmailMailWire<'v> {
    vault: &'v Vault,
    client: reqwest::blocking::Client,
    /// The credentials this wire has seen read their source's mailbox.
    verified: VerifiedCredentials,
    /// The fresh access tokens its sources' stored grants were exchanged
    /// for (fix list row 16311).
    tokens: FreshGoogleTokens,
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
            verified: VerifiedCredentials::new(),
            tokens: FreshGoogleTokens::new(),
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
        self.with_verified_bearer(source, |auth, profile| match profile {
            // The profile just read is the one asked for.
            Some(profile) if url == GMAIL_PROFILE_URL && query.is_empty() => {
                Ok(RestAnswer::Found(profile))
            }
            _ => rest::send(
                self.client
                    .get(url)
                    .query(query)
                    .header(AUTHORIZATION, auth),
            ),
        })?
        .found_or_gone("gmail_mail")
    }

    /// The answer of `read`, run at the door of the source's credential
    /// with its Bearer header, once the credential presented there is
    /// checked to read the mailbox the source names; with the Gmail profile
    /// that check read, when it ran in this call.
    fn with_verified_bearer<A>(
        &self,
        source: &MailSyncSource,
        mut read: impl FnMut(HeaderValue, Option<Value>) -> Result<A>,
    ) -> Result<A> {
        if !reads_google_mail(source.provider) {
            return Err(refused("gmail_mail_wire_reads_google_mailboxes_only"));
        }
        let mut answer: Option<A> = None;
        let _receipt = self.vault.with_source_token_at_door(
            source,
            WireReads::Mailbox,
            GMAIL_CONNECTOR_EFFECTOR,
            &mut |token: &[u8]| {
                let auth = self.tokens.bearer(&self.client, source.source_ref, token)?;
                // The credential presented here is the one checked.
                let profile = if self.verified.holds(source.source_ref, token) {
                    None
                } else {
                    let request = self
                        .client
                        .get(GMAIL_PROFILE_URL)
                        .header(AUTHORIZATION, auth.clone());
                    let profile = rest::send(request)?
                        .found_or_gone("gmail_mail")?
                        .ok_or_else(|| refused("gmail_mail_profile_not_found"))?;
                    reads_mailbox(&profile, source)?;
                    self.verified.insert(source.source_ref, token);
                    Some(profile)
                };
                answer = Some(read(auth, profile)?);
                Ok(())
            },
        )?;
        answer.ok_or_else(|| refused("gmail_mail_credential_door_refused"))
    }

    /// The mailbox's Gmail profile: its address and current history id.
    fn profile(&self, source: &MailSyncSource) -> Result<Value> {
        self.get(source, GMAIL_PROFILE_URL, &[])?
            .ok_or_else(|| refused("gmail_mail_profile_not_found"))
    }

    fn message_url(provider_id: &str) -> Result<String> {
        require_plain_id(provider_id)?;
        Ok(format!("{GMAIL_USER_URL}/messages/{provider_id}"))
    }
}

impl HttpGmailMailWire<'_> {
    /// One page of the ids `search` (Gmail's `q`) finds, at most `limit`.
    fn listed_ids(
        &self,
        source: &MailSyncSource,
        search: String,
        limit: u32,
        page: Option<&str>,
    ) -> Result<MailIdPage> {
        let mut params = vec![("maxResults", limit.to_string()), ("q", search)];
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
}

impl MailProviderWire for HttpGmailMailWire<'_> {
    fn current_anchor(&self, source: &MailSyncSource) -> Result<String> {
        self.profile(source)?
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
        // Trash and spam are left out by Gmail's default; drafts by the query.
        let search = match query.newer_than {
            Some(newer_than) => format!("-in:drafts after:{newer_than}"),
            None => "-in:drafts".to_owned(),
        };
        self.listed_ids(source, search, GMAIL_LIST_PAGE_SIZE, page)
    }

    fn search_page(
        &self,
        source: &MailSyncSource,
        query: &str,
        limit: u32,
        page: Option<&str>,
    ) -> Result<MailIdPage> {
        // The caller's own operators, grouped, beside the listing's: trash
        // and spam are left out by Gmail's default, drafts by the query. The
        // search door takes only a query whose parentheses balance, so no
        // `)` of the caller's closes this group.
        self.listed_ids(source, format!("-in:drafts ({query})"), limit, page)
    }

    fn headers(&self, source: &MailSyncSource, provider_id: &str) -> Result<Option<MailHeaders>> {
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
        let params = [("format", "full".to_owned())];
        let url = Self::message_url(provider_id)?;
        let Some(message) = self.get(source, &url, &params)? else {
            return Ok(None);
        };
        let headers = headers_of(&message)?;
        let mut parts = MessageParts::default();
        if let Some(payload) = message.get("payload") {
            collect_parts(payload, 0, &mut parts);
        }
        // A text part Gmail keeps apart is read by its attachment id, under
        // the same door; a user's attachments are never read here.
        for external in std::mem::take(&mut parts.external) {
            require_attachment_id(&external.attachment_id)?;
            let attachment = format!("{url}/attachments/{}", external.attachment_id);
            let Some(body) = self.get(source, &attachment, &[])? else {
                continue;
            };
            let Some(text) = body
                .get("data")
                .and_then(Value::as_str)
                .and_then(|data| decode_text(external.content_type.as_deref(), data))
            else {
                continue;
            };
            if external.html {
                parts.html.push(text);
            } else {
                parts.plain.push(text);
            }
        }
        Ok(Some(full_from(headers, parts)))
    }

    fn raw_address_headers(
        &self,
        source: &MailSyncSource,
        provider_id: &str,
    ) -> Result<Option<MailAddressHeaders>> {
        // Gmail's `metadata` and `full` headers come with their encoded
        // words decoded, so an encoded comma or address would split a
        // mailbox; only `raw` keeps each one's bounds as the sender wrote
        // them (fix list row 20520). The raw message is the whole message,
        // attachments included: only its `raw` field is asked for, and it is
        // read as it arrives up to the end of its header block, so a message
        // of any size is answered (fix list row 20738).
        let url = Self::message_url(provider_id)?;
        let params = [("format", "raw".to_owned()), ("fields", "raw".to_owned())];
        let header_block = self
            .with_verified_bearer(source, |auth, _profile| {
                let request = self
                    .client
                    .get(url.as_str())
                    .query(&params)
                    .header(AUTHORIZATION, auth);
                rest::send_raw_header_block(request)
            })?
            .found_or_gone("gmail_mail")?
            .ok_or_else(|| refused("gmail_mail_message_not_found"))?;
        Ok(Some(super::mime::raw_address_headers(&header_block)))
    }

    fn own_addresses(&self, source: &MailSyncSource) -> Result<Option<Vec<String>>> {
        // The mailbox's primary address and each alias Gmail verified it
        // owns (fix list row 20400); a pending alias never counts.
        let Some(listed) = self.get(source, &format!("{GMAIL_USER_URL}/settings/sendAs"), &[])?
        else {
            return Ok(None);
        };
        Ok(Some(
            array(&listed, "sendAs")
                .iter()
                .filter(|alias| proven_send_as(alias))
                .filter_map(|alias| text_of(alias.get("sendAsEmail")))
                .collect(),
        ))
    }

    fn history(
        &self,
        source: &MailSyncSource,
        anchor: &str,
        page: Option<&str>,
    ) -> Result<MailHistoryRead> {
        if anchor.is_empty() || !anchor.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(refused("gmail_mail_anchor_not_a_history_id"));
        }
        let mut params = vec![
            ("startHistoryId", anchor.to_owned()),
            ("maxResults", GMAIL_HISTORY_PAGE_SIZE.to_string()),
        ];
        for kind in [
            "messageAdded",
            "messageDeleted",
            "labelAdded",
            "labelRemoved",
        ] {
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
        // A label record names the labels it changed, not where the message
        // stands now: each such message is read again below.
        let mut relabeled = BTreeSet::new();
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
                relabeled.insert(plain_id(message.get("id"))?);
            }
        }
        let minimal = [("format", "minimal".to_owned())];
        for provider_id in relabeled {
            match self.get(source, &Self::message_url(&provider_id)?, &minimal)? {
                Some(message) => {
                    let labels = labels_of(&message);
                    let trash_or_spam = trash_or_spam(&labels);
                    changes.push(MailHistoryChange::Labels {
                        provider_id: provider_id.clone(),
                        trash_or_spam,
                        labels,
                    });
                    // A message out of trash and spam may never have been
                    // copied (Gmail reports no addition for it): it is filed
                    // as added, under the copy setting's rules.
                    if !trash_or_spam {
                        changes.push(MailHistoryChange::Added(MailMessageRef {
                            provider_id,
                            thread_id: text_of(message.get("threadId")),
                        }));
                    }
                }
                // Gone since: deleted at the provider.
                None => changes.push(MailHistoryChange::Deleted { provider_id }),
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
        let message_url = Self::message_url(provider_id)?;
        // An attachment Gmail keeps apart is fetched by its id; a small one
        // rides inline in its part of the whole message.
        if let Some(id) = &attachment.provider_attachment_id {
            return self.attachment_by_id(source, &message_url, id);
        }
        let params = [("format", "full".to_owned())];
        let Some(message) = self.get(source, &message_url, &params)? else {
            return Ok(None);
        };
        let Some(part) = message
            .get("payload")
            .and_then(|payload| part_by_id(payload, &attachment.part_id, 0))
        else {
            return Ok(None);
        };
        if let Some(data) = part.pointer("/body/data").and_then(Value::as_str) {
            return attachment_data(data).map(Some);
        }
        // A part described without its id (an imported copy) whose bytes
        // Gmail keeps apart: fetched by the id its part names now.
        match part.pointer("/body/attachmentId").and_then(Value::as_str) {
            Some(id) => self.attachment_by_id(source, &message_url, id),
            None => Ok(None),
        }
    }
}

impl HttpGmailMailWire<'_> {
    /// The bytes of the attachment `id` of the message at `message_url`.
    fn attachment_by_id(
        &self,
        source: &MailSyncSource,
        message_url: &str,
        id: &str,
    ) -> Result<Option<Vec<u8>>> {
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
        attachment_data(data).map(Some)
    }
}

/// An attachment's bytes from Gmail's URL-safe base64.
fn attachment_data(data: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(data.trim_end_matches('='))
        .map_err(|_| refused("gmail_mail_attachment_data_unreadable"))
}

/// One part of a Gmail `full` answer, by its part id.
fn part_by_id<'a>(part: &'a Value, part_id: &str, depth: usize) -> Option<&'a Value> {
    if depth > MAX_PART_DEPTH {
        return None;
    }
    if part.get("partId").and_then(Value::as_str) == Some(part_id) {
        return Some(part);
    }
    array(part, "parts")
        .iter()
        .find_map(|child| part_by_id(child, part_id, depth + 1))
}

/// Whether the Gmail wire reads `provider`'s mailboxes.
pub(super) const fn reads_google_mail(provider: MailProvider) -> bool {
    matches!(
        provider,
        MailProvider::GoogleWorkspace | MailProvider::Google
    )
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
        reply_to: header("Reply-To").map(address_list).unwrap_or_default(),
        subject: header("Subject").map(str::to_owned),
        date: header("Date").and_then(rfc2822_seconds),
        received_at,
        sent_by_mailbox: labels.iter().any(|label| label == "SENT"),
        trash_or_spam: trash_or_spam(&labels),
        draft: labels.iter().any(|label| label == "DRAFT"),
        labels,
    })
}

/// A message read whole: its plain text (or its HTML's text), and its
/// attachments described, never their bytes.
fn full_from(headers: MailHeaders, parts: MessageParts) -> MailFull {
    let body_text = if !parts.plain.is_empty() {
        Some(parts.plain.join("\n\n"))
    } else if !parts.html.is_empty() {
        Some(html_text(&parts.html.join("\n")))
    } else {
        None
    };
    MailFull {
        headers,
        body_text: body_text.filter(|text| !text.trim().is_empty()),
        attachments: parts.attachments,
        content_digest: None,
    }
}

/// The mailbox the Gmail profile `profile` names is the one `source` names.
fn reads_mailbox(profile: &Value, source: &MailSyncSource) -> Result<()> {
    let address = profile
        .get("emailAddress")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if address.trim().eq_ignore_ascii_case(source.address.trim()) {
        Ok(())
    } else {
        Err(refused("gmail_mail_credential_reads_another_mailbox"))
    }
}

/// Whether a Gmail `sendAs` entry is an address the mailbox owns: its
/// primary address, or an alias whose verification Gmail accepted.
fn proven_send_as(alias: &Value) -> bool {
    alias.get("isPrimary").and_then(Value::as_bool) == Some(true)
        || alias.get("verificationStatus").and_then(Value::as_str) == Some("accepted")
}

/// What a message's MIME parts hold.
#[derive(Default)]
struct MessageParts {
    plain: Vec<String>,
    html: Vec<String>,
    attachments: Vec<MailAttachmentRef>,
    /// The text parts Gmail keeps apart, read by their attachment id.
    external: Vec<ExternalText>,
}

/// A `text/plain` or `text/html` body part whose bytes Gmail keeps apart.
struct ExternalText {
    attachment_id: String,
    content_type: Option<String>,
    html: bool,
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
    let content_type = header_value(part.get("headers"), "Content-Type");
    // Text stored behind an attachment id comes with no data, or empty data.
    let Some(data) = body
        .and_then(|body| body.get("data"))
        .and_then(Value::as_str)
        .filter(|data| !data.is_empty())
    else {
        if let Some(attachment_id) = attachment_id
            && (media_type == "text/plain" || media_type == "text/html")
        {
            parts.external.push(ExternalText {
                attachment_id: attachment_id.to_owned(),
                content_type: content_type.map(str::to_owned),
                html: media_type == "text/html",
            });
        }
        return;
    };
    let Some(text) = decode_text(content_type, data) else {
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
fn decode_text(content_type: Option<&str>, data: &str) -> Option<String> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(data.trim_end_matches('='))
        .ok()?;
    let encoding = content_type
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

/// Where one character of an RFC 5322 address header value stands.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum AddressPlace {
    /// Outside every quoted string, comment, angle address and domain
    /// literal. The delimiters that open and close one stand here too.
    Top,
    /// Inside a quoted string (`"Name, Jr."`).
    Quoted,
    /// Inside a comment (`(work)`), nested ones included.
    Comment,
    /// Inside an angle address (`<a@b>`), a quoted local part included.
    Angle,
    /// Inside a domain literal (`[192.0.2.1]`).
    Literal,
}

/// Each character of the address header value `value`, with its byte
/// offset and its [`AddressPlace`]; and whether a quoted string, comment,
/// angle address or domain literal is still open at its end. A `\\`
/// escape inside a quoted string, comment or domain literal takes the next
/// character with it, so an escaped delimiter closes nothing.
pub(super) fn address_places(value: &str) -> (Vec<(usize, char, AddressPlace)>, bool) {
    let mut places = Vec::with_capacity(value.len());
    let (mut comment, mut quoted, mut angled, mut literal, mut escaped) =
        (0_usize, false, false, false, false);
    for (at, character) in value.char_indices() {
        let place = if comment > 0 {
            if escaped {
                escaped = false;
            } else {
                match character {
                    '\\' => escaped = true,
                    '(' => comment += 1,
                    ')' => comment -= 1,
                    _ => {}
                }
            }
            if comment > 0 || character != ')' {
                AddressPlace::Comment
            } else {
                AddressPlace::Top
            }
        } else if angled {
            if escaped {
                escaped = false;
            } else if quoted {
                match character {
                    '\\' => escaped = true,
                    '"' => quoted = false,
                    _ => {}
                }
            } else {
                match character {
                    '"' => quoted = true,
                    '>' => angled = false,
                    _ => {}
                }
            }
            if angled {
                AddressPlace::Angle
            } else {
                AddressPlace::Top
            }
        } else if quoted {
            if escaped {
                escaped = false;
                AddressPlace::Quoted
            } else {
                match character {
                    '\\' => {
                        escaped = true;
                        AddressPlace::Quoted
                    }
                    '"' => {
                        quoted = false;
                        AddressPlace::Top
                    }
                    _ => AddressPlace::Quoted,
                }
            }
        } else if literal {
            if escaped {
                escaped = false;
                AddressPlace::Literal
            } else {
                match character {
                    '\\' => {
                        escaped = true;
                        AddressPlace::Literal
                    }
                    ']' => {
                        literal = false;
                        AddressPlace::Top
                    }
                    _ => AddressPlace::Literal,
                }
            }
        } else {
            match character {
                '(' => comment = 1,
                '"' => quoted = true,
                '<' => angled = true,
                '[' => literal = true,
                _ => {}
            }
            AddressPlace::Top
        };
        places.push((at, character, place));
    }
    (places, comment > 0 || quoted || angled || literal)
}

/// The addresses of an address-list header, split at its top-level commas:
/// a comma inside a quoted string, a comment, an angle address or a domain
/// literal never splits a mailbox.
pub(super) fn address_list(value: &str) -> Vec<String> {
    let mut addresses = Vec::new();
    let mut start = 0;
    for (at, character, place) in address_places(value).0 {
        if character == ',' && place == AddressPlace::Top {
            push_address(&mut addresses, &value[start..at]);
            start = at + 1;
        }
    }
    push_address(&mut addresses, &value[start..]);
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
    let bare = value
        .split_once(" (")
        .map_or(value, |(head, _)| head)
        .trim();
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
    labels
        .iter()
        .any(|label| label == "TRASH" || label == "SPAM")
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

/// A Gmail attachment id: base64url, so it is safe in a path.
fn require_attachment_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > MAX_ATTACHMENT_ID_BYTES
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(refused("gmail_mail_attachment_id_not_plain"));
    }
    Ok(())
}

fn require_plain_id(id: &str) -> Result<()> {
    if id.is_empty() || !id.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err(refused("gmail_mail_message_id_not_plain"));
    }
    Ok(())
}
