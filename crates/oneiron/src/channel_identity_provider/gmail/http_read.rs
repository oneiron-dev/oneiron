//! Production Gmail read wire (FIX 1054): one `users.messages.list` page,
//! then each listed message's metadata, both inside the read authority's
//! door callback.
//!
//! As the send wire: HTTPS only, no redirects, and the Bearer header exists
//! only inside the door callback, marked sensitive. Only `format=metadata`
//! is asked for, so no body text is read. The token the door injects is the
//! bare OAuth access token or JSON carrying `access_token`; refreshing it is
//! the host's custody job.

use std::time::Duration;

use reqwest::header::{AUTHORIZATION, HeaderValue};
use serde_json::Value;

use super::http::{bearer_header, read_bounded_json};
use super::{
    GmailInboxPage, GmailMessageMetadata, GmailReadAuthority, GmailReadWire, HeaderMailbox,
    MAX_GMAIL_MESSAGES_PER_PAGE,
};
use crate::channel_identity_provider::EmailThreadHeaders;
use crate::channel_identity_provider::mail_placement::{MailPlacement, PlacementPolicy};
use crate::channel_identity_provider::mailbox_cursor::MailboxPageToken;
use crate::error::{Error, Result};

const GMAIL_MESSAGES_URL: &str = "https://gmail.googleapis.com/gmail/v1/users/me/messages";

/// The headers a message's metadata is read with: what routing and the
/// passport graph take, never its body.
const METADATA_HEADERS: [&str; 4] = ["From", "Message-ID", "In-Reply-To", "References"];

/// Host-side Gmail REST read wire over `reqwest::blocking`.
///
/// Call it from a blocking context (it owns an internal runtime).
pub struct HttpGmailReadWire {
    client: reqwest::blocking::Client,
}

impl HttpGmailReadWire {
    /// Builds the wire: HTTPS only, no redirects, a 30 s timeout.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when the TLS client cannot be built.
    pub fn new() -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| Error::InvalidConfig("gmail HTTP client setup failed".to_owned()))?;
        Ok(Self { client })
    }

    /// One page of `mailbox_address`'s messages in `policy` after `cursor`.
    fn read_page(
        &self,
        auth: &HeaderValue,
        mailbox_address: &str,
        policy: PlacementPolicy,
        cursor: Option<&MailboxPageToken>,
    ) -> Result<GmailInboxPage> {
        let mut query = vec![("maxResults", MAX_GMAIL_MESSAGES_PER_PAGE.to_string())];
        match policy {
            PlacementPolicy::InboxOnly => query.push(("labelIds", "INBOX".to_owned())),
            PlacementPolicy::InboxAndArchive => {
                query.push(("q", "-in:spam -in:trash".to_owned()));
            }
            PlacementPolicy::EntireMailbox => query.push(("includeSpamTrash", "true".to_owned())),
        }
        if let Some(cursor) = cursor {
            query.push(("pageToken", cursor.as_str().to_owned()));
        }
        let listed = self.get_json(GMAIL_MESSAGES_URL, auth, &query)?;
        let mut messages = Vec::new();
        for entry in listed
            .get("messages")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice)
        {
            let id = entry
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| unreadable("gmail_read_list_entry_without_id"))?;
            messages.push(self.read_metadata(auth, mailbox_address, id)?);
        }
        let next_cursor = listed
            .get("nextPageToken")
            .and_then(Value::as_str)
            .map(MailboxPageToken::new)
            .transpose()?;
        Ok(GmailInboxPage::new(messages, next_cursor))
    }

    /// One listed message's metadata: its ids, sender, date, placement by
    /// its labels, and its threading headers.
    fn read_metadata(
        &self,
        auth: &HeaderValue,
        mailbox_address: &str,
        id: &str,
    ) -> Result<GmailMessageMetadata> {
        if id.is_empty() || !id.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
            return Err(unreadable("gmail_read_message_id_not_plain"));
        }
        let mut query = vec![("format", "metadata".to_owned())];
        query.extend(
            METADATA_HEADERS
                .iter()
                .map(|header| ("metadataHeaders", (*header).to_owned())),
        );
        let value = self.get_json(&format!("{GMAIL_MESSAGES_URL}/{id}"), auth, &query)?;
        let thread_id = value
            .get("threadId")
            .and_then(Value::as_str)
            .ok_or_else(|| unreadable("gmail_read_message_without_thread"))?;
        let internal_date_secs = value
            .get("internalDate")
            .and_then(Value::as_str)
            .and_then(|millis| millis.parse::<u64>().ok())
            .map_or(0, |millis| millis / 1_000);
        let labels: Vec<&str> = value
            .get("labelIds")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice)
            .iter()
            .filter_map(Value::as_str)
            .collect();
        let header = |name: &str| header_value(&value, name);
        let from = header("From").map_or_else(|| HeaderMailbox::unparsed(""), sender_mailbox);
        let mut metadata = GmailMessageMetadata::new(
            id,
            thread_id,
            mailbox_address,
            from,
            internal_date_secs,
            placement_of(&labels),
        );
        if let Some(message_id) = header("Message-ID") {
            let references: Vec<String> = header("References")
                .map(|references| references.split_whitespace().map(str::to_owned).collect())
                .unwrap_or_default();
            let in_reply_to = header("In-Reply-To").map(|value| value.trim().to_owned());
            metadata = metadata.with_thread_headers(EmailThreadHeaders::new(
                message_id.trim(),
                references,
                in_reply_to,
            ));
        }
        Ok(metadata)
    }

    fn get_json(&self, url: &str, auth: &HeaderValue, query: &[(&str, String)]) -> Result<Value> {
        let response = self
            .client
            .get(url)
            .query(query)
            .header(AUTHORIZATION, auth.clone())
            .send()
            .map_err(|_| unreadable("gmail_read_transport_failed"))?;
        let status = response.status();
        if !status.is_success() {
            return Err(Error::InvalidConfig(format!(
                "gmail_read_status_{}",
                status.as_u16()
            )));
        }
        read_bounded_json(response).ok_or_else(|| unreadable("gmail_read_response_unreadable"))
    }
}

impl GmailReadWire for HttpGmailReadWire {
    fn fetch_inbox_page(
        &self,
        authority: &GmailReadAuthority<'_>,
        mailbox_address: &str,
        policy: PlacementPolicy,
        cursor: Option<&MailboxPageToken>,
    ) -> Result<GmailInboxPage> {
        let mut page = None;
        let _receipt = authority.with_token_at_door(&mut |token: &[u8]| {
            let auth = bearer_header(token)?;
            page = Some(self.read_page(&auth, mailbox_address, policy, cursor)?);
            Ok(())
        })?;
        page.ok_or_else(|| unreadable("gmail_read_credential_door_refused"))
    }
}

/// The value of the header `name` a message's metadata carries, if any.
fn header_value<'v>(value: &'v Value, name: &str) -> Option<&'v str> {
    value
        .pointer("/payload/headers")?
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

/// A message's placement by its Gmail labels: junk and trash before the
/// inbox, as the placement facts rank them; no such label is archive.
fn placement_of(labels: &[&str]) -> MailPlacement {
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

/// The sender a `From` header names: the address inside its last angle
/// brackets when it has them, else the header whole, projected as
/// [`HeaderMailbox`] projects a bare addr-spec.
fn sender_mailbox(from: &str) -> HeaderMailbox {
    let addr = from
        .rsplit_once('<')
        .and_then(|(_, rest)| rest.split_once('>'))
        .map_or(from, |(addr, _)| addr);
    HeaderMailbox::from(addr.trim())
}

fn unreadable(code: &str) -> Error {
    Error::InvalidConfig(code.to_owned())
}
