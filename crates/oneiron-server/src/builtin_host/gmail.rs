//! The Gmail seats' served mailboxes (FIX 1168): while the built-in email
//! pack is Active and its Gmail connection's check Verified, the host pages
//! every active Gmail seat's mailbox through the adapter's own page door
//! ([`GmailDelegatedAdapter::run_mailbox_page`]) once per
//! [`GMAIL_POLL_EVERY`], from where the seat's stored progress left it.
//!
//! The wire lists the placement and reads each message's metadata first.
//! A MailRead seat also reads the non-attachment plain-text body of messages
//! its placement admits, so the archived email can feed the reply worker.
//! MailMetadata seats stay header-only. Each page's calls run inside the
//! seat's identity-bound credential door, on its own grant; the mailbox
//! address is the user id each call names.

use std::io::Read;
use std::time::{Duration, Instant};

use oneiron::channel_identity::{AssignmentAddress, DelegatedGrantScope, MailboxAddr};
use oneiron::channel_identity_provider::gmail::{
    GmailDelegatedAdapter, GmailInboxPage, GmailMessageMetadata, GmailReadAuthority, GmailReadWire,
    HeaderMailbox, active_gmail_seats, gmail_authorization,
};
use oneiron::channel_identity_provider::mail_placement::{MailPlacement, PlacementPolicy};
use oneiron::channel_identity_provider::mailbox_cursor::{
    MailboxPageToken, mailbox_cursor_snapshot,
};
use oneiron::channel_identity_provider::{EMAIL_CHANNEL, EmailThreadHeaders};
use oneiron::outbound::ServedChannelSink;
use oneiron::{EntityId, Vault};
use reqwest::header::{AUTHORIZATION, HeaderValue};
use serde_json::Value;

/// The built-in email pack's Gmail connection (packs/builtin/email/PACK.md).
pub(super) const GMAIL_CONNECTION: &str = "gmail";
/// How often every Gmail seat's mailbox is paged.
const GMAIL_POLL_EVERY: Duration = Duration::from_secs(60);
/// The most pages one seat reads in one poll, so a first scan of a large
/// mailbox spreads over polls rather than holding the built-in pass.
const GMAIL_PAGES_PER_POLL: usize = 10;
/// How far before its last full scan's end a new scan reads back. Mail
/// Gmail received earlier was listed by that scan, so the scan ends there.
const GMAIL_RESCAN_OVERLAP_SECS: u64 = 86_400;
/// Gmail's users collection; a seat's mailbox address is the user id.
const GMAIL_USERS_URL: &str = "https://gmail.googleapis.com/gmail/v1/users";
/// How many messages one page lists.
const GMAIL_PAGE_SIZE: u32 = 50;
/// The headers the adapter reads: the sender, the subject, and the RFC
/// threading headers.
const GMAIL_METADATA_HEADERS: [&str; 5] =
    ["From", "Subject", "Message-ID", "References", "In-Reply-To"];
/// The largest Gmail JSON reply, including a full MIME message and its
/// base64url body (which can exceed the old metadata-only reply size).
const MAX_GMAIL_REPLY_BYTES: u64 = 128 * 1024 * 1024;

/// Whether the Gmail mailboxes are served, and when they were last paged,
/// kept across passes in memory. Each poll builds its own HTTPS client on
/// the pass's blocking thread, and drops it there.
#[derive(Default)]
pub(crate) struct GmailMailboxes {
    served: bool,
    polled_at: Option<Instant>,
}

impl GmailMailboxes {
    /// One pass: while the email pack's Gmail connection is `checked`, every
    /// active Gmail seat's mailbox is paged once per [`GMAIL_POLL_EVERY`];
    /// unchecked, no mailbox is read.
    pub(super) fn pass(&mut self, vault: &Vault, checked: bool) {
        if !checked {
            if self.served {
                tracing::info!("Gmail mailboxes no longer served");
            }
            *self = Self::default();
            return;
        }
        if !self.served {
            tracing::info!("Gmail mailboxes served");
            self.served = true;
        }
        if self
            .polled_at
            .is_some_and(|at| at.elapsed() < GMAIL_POLL_EVERY)
        {
            return;
        }
        self.polled_at = Some(Instant::now());
        let client = match ServedChannelSink::client() {
            Ok(client) => client,
            Err(error) => {
                tracing::warn!(%error, "the Gmail read client did not start; mailboxes are read next poll");
                return;
            }
        };
        let seats = match active_gmail_seats(vault) {
            Ok(seats) => seats,
            Err(error) => {
                tracing::warn!(%error, "Gmail seats unreadable");
                return;
            }
        };
        for identity in seats {
            if let Err(error) = poll_seat(vault, &client, identity) {
                tracing::warn!(identity = %identity.to_hex(), %error, "a Gmail mailbox read failed; it is read again next poll");
            }
        }
    }
}

/// Pages one seat's mailbox from where its stored progress left it, until
/// the scan ends or [`GMAIL_PAGES_PER_POLL`] pages are read. A seat whose
/// grant only sends has no mailbox to read.
fn poll_seat(
    vault: &Vault,
    client: &reqwest::blocking::Client,
    identity: EntityId,
) -> oneiron::Result<()> {
    let Some(adapter) = GmailDelegatedAdapter::for_delegated_identity(vault, identity)? else {
        return Ok(());
    };
    if !adapter.config().grants_read() {
        return Ok(());
    }
    let wire = HttpGmailReadWire {
        client,
        read_since: read_since(vault, &adapter, identity)?,
        read_body: adapter
            .config()
            .scopes()
            .contains(&DelegatedGrantScope::MailRead),
    };
    let mut admitted = 0_usize;
    for _ in 0..GMAIL_PAGES_PER_POLL {
        let page = adapter.run_mailbox_page(vault, identity, &wire, vault.now_recorded_at());
        let outcome = match page {
            Ok(outcome) => outcome,
            Err(error) => {
                log_admitted(identity, admitted);
                return Err(error);
            }
        };
        admitted = admitted.saturating_add(outcome.messages_admitted);
        for skipped in &outcome.skipped {
            tracing::warn!(identity = %identity.to_hex(), message = %skipped.message_id, reason = %skipped.reason, "a Gmail message was set aside; the mailbox reads on");
        }
        if outcome.progress.next_cursor.is_none() {
            break;
        }
    }
    log_admitted(identity, admitted);
    Ok(())
}

fn log_admitted(identity: EntityId, admitted: usize) {
    if admitted > 0 {
        tracing::info!(identity = %identity.to_hex(), admitted, "Gmail mail admitted");
    }
}

/// Where a scan of this seat's mailbox reads back to: its last full scan's
/// end, less [`GMAIL_RESCAN_OVERLAP_SECS`], while the stored progress is this
/// mailbox's under the same placement. `None` reads the whole mailbox: the
/// seat's first scan, or a scan after the mailbox or placement changed.
fn read_since(
    vault: &Vault,
    adapter: &GmailDelegatedAdapter,
    identity: EntityId,
) -> oneiron::Result<Option<u64>> {
    let config = adapter.config();
    let mailbox = AssignmentAddress::normalize(EMAIL_CHANNEL, config.mailbox_address());
    Ok(mailbox_cursor_snapshot(vault, identity)?
        .filter(|progress| {
            progress.mailbox_address == mailbox.as_str()
                && progress.placement_policy == config.placement_policy()
        })
        .and_then(|progress| progress.last_complete_at)
        .map(|at| at.saturating_sub(GMAIL_RESCAN_OVERLAP_SECS)))
}

/// The production [`GmailReadWire`]: Gmail's REST API on the served HTTPS
/// client (no proxy, no redirects, short timeouts).
struct HttpGmailReadWire<'a> {
    client: &'a reqwest::blocking::Client,
    /// Mail Gmail received before this instant (Unix seconds) ends a scan:
    /// the seat's last full scan listed it. `None` reads the whole mailbox.
    read_since: Option<u64>,
    /// Metadata-only grants never fetch message bodies.
    read_body: bool,
}

impl HttpGmailReadWire<'_> {
    /// One page after `cursor`: the listed messages' metadata, in Gmail's
    /// newest-first order, keeping those `policy` admits. The page ends the
    /// scan at the first message received before [`Self::read_since`], or
    /// where Gmail lists no more.
    fn read_page(
        &self,
        auth: &HeaderValue,
        mailbox: &str,
        policy: PlacementPolicy,
        cursor: Option<&MailboxPageToken>,
    ) -> oneiron::Result<GmailInboxPage> {
        let mut list = self
            .client
            .get(messages_url(mailbox, None)?)
            .header(AUTHORIZATION, auth.clone())
            .query(&[("maxResults", GMAIL_PAGE_SIZE.to_string())]);
        list = match policy {
            PlacementPolicy::InboxOnly => list.query(&[("labelIds", "INBOX")]),
            PlacementPolicy::InboxAndArchive => list,
            PlacementPolicy::EntireMailbox => list.query(&[("includeSpamTrash", "true")]),
        };
        if let Some(cursor) = cursor {
            list = list.query(&[("pageToken", cursor.as_str())]);
        }
        let listed = gmail_json(list, "list", false)?.ok_or_else(|| gmail_error("list", 404))?;
        let ids = listed
            .get("messages")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|message| message.get("id").and_then(Value::as_str));
        let mut messages = Vec::new();
        let mut reached_read = false;
        for id in ids {
            // A message deleted since the list is not mail any more.
            let Some(message) = self.read_message(auth, mailbox, id)? else {
                continue;
            };
            reached_read = self
                .read_since
                .is_some_and(|since| message.internal_date_secs < since);
            if let Some(mut message) = message.metadata.filter(|m| policy.includes(m.placement)) {
                if self.read_body
                    && let Some(text) = self.read_plain_text(auth, mailbox, id)?
                {
                    message = message.with_plain_text(text);
                }
                messages.push(message);
            }
            if reached_read {
                break;
            }
        }
        let next_cursor = if reached_read {
            None
        } else {
            listed
                .get("nextPageToken")
                .and_then(Value::as_str)
                .map(MailboxPageToken::new)
                .transpose()?
        };
        Ok(GmailInboxPage::new(messages, next_cursor))
    }

    /// One message's metadata; `None` when Gmail no longer has it.
    fn read_message(
        &self,
        auth: &HeaderValue,
        mailbox: &str,
        id: &str,
    ) -> oneiron::Result<Option<ReadMessage>> {
        let mut query = vec![("format", "metadata")];
        query.extend(GMAIL_METADATA_HEADERS.map(|name| ("metadataHeaders", name)));
        let request = self
            .client
            .get(messages_url(mailbox, Some(id))?)
            .header(AUTHORIZATION, auth.clone())
            .query(&query);
        let Some(message) = gmail_json(request, "get", false)? else {
            return Ok(None);
        };
        project_message(mailbox, id, &message).map(Some)
    }

    /// Reads only a MIME plain-text message body, never an attachment,
    /// HTML alternative or Gmail's snippet of earlier/quoted words.
    fn read_plain_text(
        &self,
        auth: &HeaderValue,
        mailbox: &str,
        id: &str,
    ) -> oneiron::Result<Option<String>> {
        let request = self
            .client
            .get(messages_url(mailbox, Some(id))?)
            .header(AUTHORIZATION, auth.clone())
            .query(&[("format", "full"), ("fields", "payload")]);
        let Some(message) = gmail_json(request, "get body", true)? else {
            return Ok(None);
        };
        let Some(part) = message.get("payload").and_then(plain_text_part) else {
            return Ok(None);
        };
        let charset = plain_text_charset(part);
        if let Some(data) = part
            .pointer("/body/data")
            .and_then(Value::as_str)
            .filter(|data| !data.is_empty())
        {
            // These are sender-controlled bytes, not a transport failure.
            // Preserve the admitted metadata when this body cannot be decoded.
            return Ok(GmailMessageMetadata::decode_plain_text(data, charset).ok());
        }
        let Some(attachment) = part.pointer("/body/attachmentId").and_then(Value::as_str) else {
            return Ok(None);
        };
        // Gmail can keep a message body's bytes behind this endpoint too.
        // plain_text_part already excluded MIME attachments.
        let mut url = messages_url(mailbox, Some(id))?;
        url.path_segments_mut()
            .map_err(|()| oneiron::Error::InvalidConfig("gmail body URL did not build".to_owned()))?
            .push("attachments")
            .push(attachment);
        let request = self.client.get(url).header(AUTHORIZATION, auth.clone());
        let Some(body) = gmail_json(request, "get body bytes", true)? else {
            return Ok(None);
        };
        Ok(body
            .get("data")
            .and_then(Value::as_str)
            .and_then(|data| GmailMessageMetadata::decode_plain_text(data, charset).ok()))
    }
}

impl GmailReadWire for HttpGmailReadWire<'_> {
    fn fetch_inbox_page(
        &self,
        authority: &GmailReadAuthority<'_>,
        mailbox_address: &str,
        policy: PlacementPolicy,
        cursor: Option<&MailboxPageToken>,
    ) -> oneiron::Result<GmailInboxPage> {
        let mut page = None;
        authority.with_token_at_door(&mut |token: &[u8]| {
            let auth = gmail_authorization(self.client, token)?;
            page = Some(self.read_page(&auth, mailbox_address, policy, cursor)?);
            Ok(())
        })?;
        page.ok_or_else(|| oneiron::Error::InvalidConfig("gmail page was not read".to_owned()))
    }
}

/// The first non-attachment plain-text part, in MIME order. Nested message
/// attachments are not traversed as if their words were the new reply.
fn plain_text_part(payload: &Value) -> Option<&Value> {
    let mut parts = vec![payload];
    while let Some(part) = parts.pop() {
        let attachment = part
            .get("filename")
            .and_then(Value::as_str)
            .is_some_and(|name| !name.is_empty())
            || part
                .get("headers")
                .and_then(Value::as_array)
                .is_some_and(|headers| {
                    headers.iter().any(|header| {
                        header
                            .get("name")
                            .and_then(Value::as_str)
                            .is_some_and(|name| name.eq_ignore_ascii_case("Content-Disposition"))
                            && header
                                .get("value")
                                .and_then(Value::as_str)
                                .is_some_and(|value| {
                                    value
                                        .split(';')
                                        .next()
                                        .unwrap_or_default()
                                        .trim()
                                        .eq_ignore_ascii_case("attachment")
                                })
                    })
                });
        if attachment {
            continue;
        }
        let mime = part
            .get("mimeType")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if mime.eq_ignore_ascii_case("text/plain") {
            return Some(part);
        }
        if mime.to_ascii_lowercase().starts_with("multipart/")
            && let Some(children) = part.get("parts").and_then(Value::as_array)
        {
            parts.extend(children.iter().rev());
        }
    }
    None
}

fn plain_text_charset(part: &Value) -> Option<&str> {
    let content_type = part
        .get("headers")?
        .as_array()?
        .iter()
        .find(|header| {
            header
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| name.eq_ignore_ascii_case("Content-Type"))
        })?
        .get("value")?
        .as_str()?;
    content_type.split(';').skip(1).find_map(|parameter| {
        let (name, value) = parameter.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("charset")
            .then(|| value.trim().trim_matches('"'))
    })
}

/// One listed message as Gmail returned it: when Gmail received it, and its
/// metadata, `None` for a draft, which is not mail the mailbox received.
struct ReadMessage {
    internal_date_secs: u64,
    metadata: Option<GmailMessageMetadata>,
}

/// Projects one `format=metadata` reply onto the adapter's message metadata.
/// The receiving address is the seat's mailbox, the mailbox the message is
/// in; the sender is the `From` header's mailbox, or a digest of the header
/// when it names none. The `Subject` header rides along for the STOP check.
fn project_message(
    mailbox: &str,
    listed_id: &str,
    message: &Value,
) -> oneiron::Result<ReadMessage> {
    let text = |field: &str| message.get(field).and_then(Value::as_str);
    let internal_date_secs = text("internalDate")
        .and_then(|millis| millis.parse::<u64>().ok())
        .map(|millis| millis / 1000)
        .ok_or_else(|| {
            oneiron::Error::InvalidConfig("gmail message names no receive time".to_owned())
        })?;
    let labels = message
        .get("labelIds")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    if labels.contains(&"DRAFT") {
        return Ok(ReadMessage {
            internal_date_secs,
            metadata: None,
        });
    }
    let header = |name: &str| {
        message
            .pointer("/payload/headers")
            .and_then(Value::as_array)?
            .iter()
            .find(|header| {
                header
                    .get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|found| found.eq_ignore_ascii_case(name))
            })?
            .get("value")
            .and_then(Value::as_str)
    };
    let from = header("From").unwrap_or_default();
    let sender = MailboxAddr::parse_addr_spec(addr_spec(from))
        .map_or_else(|_| HeaderMailbox::unparsed(from), HeaderMailbox::Parsed);
    let mut metadata = GmailMessageMetadata::new(
        text("id").unwrap_or(listed_id),
        text("threadId").unwrap_or_default(),
        mailbox,
        sender,
        internal_date_secs,
        placement(&labels),
    );
    if let Some(subject) = header("Subject") {
        metadata = metadata.with_subject(subject.to_owned());
    }
    if let Some(message_id) = header("Message-ID").and_then(|value| message_ids(value).next()) {
        metadata = metadata.with_thread_headers(EmailThreadHeaders::new(
            message_id,
            header("References")
                .into_iter()
                .flat_map(message_ids)
                .map(str::to_owned)
                .collect(),
            header("In-Reply-To")
                .and_then(|value| message_ids(value).next())
                .map(str::to_owned),
        ));
    }
    Ok(ReadMessage {
        internal_date_secs,
        metadata: Some(metadata),
    })
}

/// Where Gmail's labels place a message. Junk and trash take precedence
/// over inbox; a message in neither and outside the inbox is archived.
fn placement(labels: &[&str]) -> MailPlacement {
    if labels.contains(&"SPAM") {
        MailPlacement::Spam
    } else if labels.contains(&"TRASH") {
        MailPlacement::Trash
    } else if labels.contains(&"INBOX") {
        MailPlacement::Inbox
    } else {
        MailPlacement::Archive
    }
}

/// The addr-spec a `From` header names: the bracketed address of a
/// `Name <addr>` form, else the whole value.
fn addr_spec(from: &str) -> &str {
    from.rfind('<')
        .and_then(|open| {
            let rest = &from[open + 1..];
            rest.find('>').map(|close| &rest[..close])
        })
        .unwrap_or(from)
        .trim()
}

/// The `<msg-id>` tokens of a `Message-ID`, `References` or `In-Reply-To`
/// value, in order; a value with no brackets is one token.
fn message_ids(value: &str) -> impl Iterator<Item = &str> {
    let bracketed = value.contains('<');
    let mut rest = value;
    let mut bare = (!bracketed)
        .then(|| value.trim())
        .filter(|id| !id.is_empty());
    std::iter::from_fn(move || {
        if let Some(id) = bare.take() {
            return Some(id);
        }
        if !bracketed {
            return None;
        }
        let open = rest.find('<')?;
        let close = rest[open..].find('>')? + open;
        let id = &rest[open..=close];
        rest = &rest[close + 1..];
        Some(id)
    })
}

/// A Gmail messages URL under the mailbox's user id, with each path segment
/// percent-encoded.
fn messages_url(mailbox: &str, message: Option<&str>) -> oneiron::Result<reqwest::Url> {
    let invalid = || oneiron::Error::InvalidConfig("gmail request URL did not build".to_owned());
    let mut url = reqwest::Url::parse(GMAIL_USERS_URL).map_err(|_| invalid())?;
    {
        let mut segments = url.path_segments_mut().map_err(|()| invalid())?;
        segments.push(mailbox).push("messages");
        if let Some(message) = message {
            segments.push(message);
        }
    }
    Ok(url)
}

/// One Gmail call's JSON reply; `None` when Gmail answers 404. Any other
/// refusal fails the page, which the next poll reads again. An oversized
/// optional body leaves the already-read metadata intact instead of blocking
/// the page. Network, authentication and unreadable-response errors still
/// propagate. The URL names the mailbox, so an error drops it.
fn gmail_json(
    request: reqwest::blocking::RequestBuilder,
    call: &str,
    optional_body: bool,
) -> oneiron::Result<Option<Value>> {
    let response = request.send().map_err(|error| {
        oneiron::Error::InvalidConfig(format!(
            "gmail {call} did not reach Gmail: {}",
            error.without_url()
        ))
    })?;
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(gmail_error(call, status.as_u16()));
    }
    let mut body = Vec::new();
    response
        .take(MAX_GMAIL_REPLY_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|_| oneiron::Error::InvalidConfig(format!("gmail {call} reply unreadable")))?;
    if body.len() as u64 > MAX_GMAIL_REPLY_BYTES {
        if optional_body {
            return Ok(None);
        }
        return Err(oneiron::Error::InvalidConfig(format!(
            "gmail {call} reply exceeds its bound"
        )));
    }
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|_| oneiron::Error::InvalidConfig(format!("gmail {call} reply is not JSON")))
}

fn gmail_error(call: &str, status: u16) -> oneiron::Error {
    oneiron::Error::InvalidConfig(format!("gmail {call} answered HTTP {status}"))
}
