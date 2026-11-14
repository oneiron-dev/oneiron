//! What the mail pack's REST wires share (Gmail, Microsoft Graph): one
//! HTTPS client shape, one bounded JSON read, a raw message read to the end
//! of its header block, the Bearer header for an injected credential, and
//! the text helpers a message body needs.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read};
use std::time::Duration;

use base64::Engine as _;
use dom_query::Document;
use reqwest::header::HeaderValue;
use serde_json::Value;

use super::quota::MAIL_WIRE_RATE_LIMITED;
use crate::EntityId;
use crate::Vault;
use crate::connector_key::{GrantAccess, ProviderConnectionChecks};
use crate::error::{Error, Result};
use crate::secret_lease::DoorInjectionReceipt;

/// The largest provider answer read: a whole message with its inline parts.
pub(super) const MAX_REST_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;
/// The longest header block a raw message read keeps, its ending empty line
/// included: a longer one refuses the read, never reads as cut.
const MAX_RAW_HEADER_BLOCK_BYTES: usize = 8 * 1024 * 1024;
/// The bytes of a raw message answer taken from the network at a time.
const RAW_READ_BUFFER_BYTES: usize = 16 * 1024;
/// The base64url characters of a raw message decoded at a time: whole
/// quartets, so each piece decodes alone and what the read keeps or refuses
/// depends on the message alone, never on how the network split it.
const RAW_DECODE_PIECE_CHARS: usize = 4 * 1024;
/// The most bytes a raw message answer may take before its `raw` value
/// starts (`{"raw":"` and the JSON whitespace around its tokens): an answer
/// that pads its front without end is refused, never read for ever.
const MAX_RAW_PREFIX_BYTES: usize = 4 * 1024;
/// How long a raw message read may take, from its first byte to its header
/// block's end: an answer that trickles in without end is refused, as each
/// network read starts a timeout of its own.
const RAW_READ_DEADLINE: Duration = Duration::from_secs(120);
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

/// One provider answer: its JSON (or what a streamed read kept of it), or a
/// failure status with the provider's error code when its body names one
/// (`error.code`).
pub(super) enum RestAnswer<T = Value> {
    Found(T),
    Failed { status: u16, code: Option<String> },
}

/// Google's reasons for a 403 that is a usage limit, not a refusal: a
/// user's or the project's rate.
const USAGE_LIMIT_REASONS: [&str; 2] = ["rateLimitExceeded", "userRateLimitExceeded"];

impl<T> RestAnswer<T> {
    /// The answer, unless the provider answered that its rate is spent (a
    /// 429, or Google's 403 for a usage limit): that one is
    /// [`MAIL_WIRE_RATE_LIMITED`], which rests the source rather than
    /// failing its step.
    pub(super) fn unless_rate_limited(self) -> Result<Self> {
        match &self {
            Self::Failed { status: 429, .. } => Err(refused(MAIL_WIRE_RATE_LIMITED)),
            Self::Failed {
                status: 403,
                code: Some(code),
            } if USAGE_LIMIT_REASONS.contains(&code.as_str()) => {
                Err(refused(MAIL_WIRE_RATE_LIMITED))
            }
            _ => Ok(self),
        }
    }

    /// The answer, `None` for the provider's "not found", else an error
    /// named `{wire}_status_{status}`.
    pub(super) fn found_or_gone(self, wire: &str) -> Result<Option<T>> {
        match self {
            Self::Found(value) => Ok(Some(value)),
            Self::Failed { status: 404, .. } => Ok(None),
            Self::Failed { status, .. } => {
                Err(Error::InvalidConfig(format!("{wire}_status_{status}")))
            }
        }
    }
}

/// The client every REST wire uses: HTTPS only, no redirects, a 60 s
/// timeout.
pub(super) fn https_client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|_| refused("mail_wire_http_client_setup_failed"))
}

/// Sends `request` and reads its answer, bounded.
pub(super) fn send(request: reqwest::blocking::RequestBuilder) -> Result<RestAnswer> {
    send_counted(request, &Cell::new(0))
}

/// Sends `request` and reads its answer, bounded, adding each byte of it
/// read to `read`.
pub(super) fn send_counted(
    request: reqwest::blocking::RequestBuilder,
    read: &Cell<u64>,
) -> Result<RestAnswer> {
    let response = request
        .send()
        .map_err(|_| refused("mail_wire_transport_failed"))?;
    let status = response.status();
    let body = read_bounded_json(CountedRead::new(response, read));
    if status.is_success() {
        return body
            .map(RestAnswer::Found)
            .ok_or_else(|| refused("mail_wire_response_unreadable"));
    }
    Ok(RestAnswer::Failed {
        status: status.as_u16(),
        code: error_code(body.as_ref()),
    })
}

/// Sends `request`, a read whose answer is `{"raw": "<base64url>"}` (Gmail's
/// `messages.get` with `format=raw` and `fields=raw`), and reads from its
/// raw message only the header block (fix list row 20738): the body is
/// decoded as it arrives and the answer dropped unread past the block's end,
/// so a message of any size names its headers. A failure status is read as
/// [`send`] reads it. Each byte of the answer read is added to `read`.
///
/// # Errors
///
/// The transport's failure; an answer of another shape, cut short, or
/// whose value is not base64url; a header block longer than
/// [`MAX_RAW_HEADER_BLOCK_BYTES`].
pub(super) fn send_raw_header_block(
    request: reqwest::blocking::RequestBuilder,
    read: &Cell<u64>,
) -> Result<RestAnswer<Vec<u8>>> {
    let response = request
        .send()
        .map_err(|_| refused("mail_wire_transport_failed"))?;
    let status = response.status();
    let response = CountedRead::new(response, read);
    if !status.is_success() {
        return Ok(RestAnswer::Failed {
            status: status.as_u16(),
            code: error_code(read_bounded_json(response).as_ref()),
        });
    }
    raw_header_block(response).map(RestAnswer::Found)
}

/// The provider's error code a failure answer's body names: Graph's
/// `error.code`, or Google's first `error.errors[].reason`, as Google's
/// `error.code` is the HTTP status again.
fn error_code(body: Option<&Value>) -> Option<String> {
    let error = body?.get("error")?;
    error
        .get("code")
        .and_then(Value::as_str)
        .or_else(|| error.pointer("/errors/0/reason").and_then(Value::as_str))
        .map(str::to_owned)
}

/// An answer's body, each byte read from it added to a count.
struct CountedRead<'c, R> {
    body: R,
    count: &'c Cell<u64>,
}

impl<'c, R: Read> CountedRead<'c, R> {
    fn new(body: R, count: &'c Cell<u64>) -> Self {
        Self { body, count }
    }
}

impl<R: Read> Read for CountedRead<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let taken = self.body.read(buf)?;
        self.count
            .set(self.count.get().saturating_add(taken as u64));
        Ok(taken)
    }
}

/// The header block of the raw message in `body`, a JSON object whose only
/// field, `raw`, holds the message in base64url: decoded a piece at a time,
/// and read no further than the block's end (its first empty line, kept) or
/// the value's end (a message of headers alone). `=` padding ends the value.
fn raw_header_block(body: impl Read) -> Result<Vec<u8>> {
    let mut body = BufReader::with_capacity(RAW_READ_BUFFER_BYTES, body);
    let deadline = std::time::Instant::now() + RAW_READ_DEADLINE;
    let mut prefix_budget = MAX_RAW_PREFIX_BYTES;
    raw_value_start(&mut body, &mut prefix_budget)?;
    let mut block = HeaderBlock::new();
    let mut pending: Vec<u8> = Vec::with_capacity(RAW_DECODE_PIECE_CHARS + RAW_READ_BUFFER_BYTES);
    loop {
        if std::time::Instant::now() > deadline {
            return Err(refused("mail_wire_raw_read_too_slow"));
        }
        let (taken, value_ended) = {
            let chunk = body.fill_buf().map_err(|_| cut_short())?;
            if chunk.is_empty() {
                return Err(cut_short());
            }
            match chunk.iter().position(|&byte| matches!(byte, b'"' | b'=')) {
                Some(end) => {
                    pending.extend_from_slice(&chunk[..end]);
                    (end + 1, true)
                }
                None => {
                    pending.extend_from_slice(chunk);
                    (chunk.len(), false)
                }
            }
        };
        body.consume(taken);
        let mut decoded = 0;
        while pending.len() - decoded >= RAW_DECODE_PIECE_CHARS {
            if block.push(&pending[decoded..decoded + RAW_DECODE_PIECE_CHARS])? {
                return Ok(block.bytes);
            }
            decoded += RAW_DECODE_PIECE_CHARS;
        }
        pending.drain(..decoded);
        if value_ended {
            block.push(&pending)?;
            return Ok(block.bytes);
        }
    }
}

/// Reads `{"raw":"` from `body`, JSON whitespace allowed between its
/// tokens: the start of the `raw` value, the object's only field. Another
/// field, an escape in the field's name or a value that is not a string is
/// another shape. At most `budget` bytes are taken; more is another shape.
fn raw_value_start(body: &mut impl BufRead, budget: &mut usize) -> Result<()> {
    let unreadable = || refused("mail_wire_raw_message_unreadable");
    if next_token(body, budget)? != Some(b'{') {
        return Err(unreadable());
    }
    match next_token(body, budget)? {
        Some(b'"') => {}
        Some(b'}') => return Err(refused("mail_wire_raw_message_missing")),
        _ => return Err(unreadable()),
    }
    for &expected in b"raw\"" {
        if next_byte(body, budget)? != Some(expected) {
            return Err(unreadable());
        }
    }
    if next_token(body, budget)? != Some(b':') || next_token(body, budget)? != Some(b'"') {
        return Err(unreadable());
    }
    Ok(())
}

/// The next byte of `body` that is not JSON whitespace; `None` at its end.
fn next_token(body: &mut impl BufRead, budget: &mut usize) -> Result<Option<u8>> {
    loop {
        match next_byte(body, budget)? {
            Some(b' ' | b'\t' | b'\n' | b'\r') => {}
            other => return Ok(other),
        }
    }
}

/// The next byte of `body`, taken from `budget`; `None` at its end. A
/// spent budget refuses the answer as another shape.
fn next_byte(body: &mut impl BufRead, budget: &mut usize) -> Result<Option<u8>> {
    let byte = body.fill_buf().map_err(|_| cut_short())?.first().copied();
    if byte.is_some() {
        *budget = budget
            .checked_sub(1)
            .ok_or_else(|| refused("mail_wire_raw_message_unreadable"))?;
        body.consume(1);
    }
    Ok(byte)
}

/// An answer the network ended, or failed to give, before its raw value
/// ended.
fn cut_short() -> Error {
    refused("mail_wire_response_unreadable")
}

/// The decoded front of a raw message, up to the end of its header block:
/// its first empty line (`\n` or `\r\n` at the message's start or after a
/// `\n`), where a header block's lines end as the MIME reader splits them.
struct HeaderBlock {
    bytes: Vec<u8>,
    /// Whether the next byte starts a line.
    line_start: bool,
    /// Whether the line so far is one `\r`.
    lone_cr: bool,
}

impl HeaderBlock {
    const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            line_start: true,
            lone_cr: false,
        }
    }

    /// Decodes the base64url `chars` onto the block; `true` once it holds
    /// the block's end, the bytes after it dropped.
    fn push(&mut self, chars: &[u8]) -> Result<bool> {
        let from = self.bytes.len();
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode_vec(chars, &mut self.bytes)
            .map_err(|_| refused("mail_wire_raw_message_unreadable"))?;
        let (mut line_start, mut lone_cr) = (self.line_start, self.lone_cr);
        // The `\n` of the first empty line, its offset in the bytes decoded now.
        let block_end = self.bytes[from..].iter().position(|&byte| {
            let empty_line = byte == b'\n' && (line_start || lone_cr);
            lone_cr = byte == b'\r' && line_start;
            line_start = byte == b'\n';
            empty_line
        });
        (self.line_start, self.lone_cr) = (line_start, lone_cr);
        if let Some(at) = block_end {
            self.bytes.truncate(from + at + 1);
        }
        if self.bytes.len() > MAX_RAW_HEADER_BLOCK_BYTES {
            return Err(refused("mail_wire_raw_header_block_too_large"));
        }
        Ok(block_end.is_some())
    }
}

fn read_bounded_json(response: impl Read) -> Option<Value> {
    let mut bytes = Vec::new();
    response
        .take(MAX_REST_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_REST_RESPONSE_BYTES {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

/// The sensitive `Authorization: Bearer` value for one injected credential:
/// the bare OAuth access token, or JSON carrying `access_token`.
pub(super) fn bearer_header(token: &[u8]) -> Result<HeaderValue> {
    let invalid = || refused("mail_wire_credential_not_an_access_token");
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

pub(super) fn refused(code: &str) -> Error {
    Error::InvalidConfig(code.to_owned())
}

/// The array field `key` of `value`, empty when absent.
pub(super) fn array<'v>(value: &'v Value, key: &str) -> &'v [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
}

/// A nonempty string field.
pub(super) fn text_of(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

/// The value of the header `name` in a `[{name, value}]` header list (a
/// Gmail payload's, a Graph message's `internetMessageHeaders`), if any.
pub(super) fn header_value<'v>(headers: Option<&'v Value>, name: &str) -> Option<&'v str> {
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

/// The visible text of an HTML body, a line per block.
pub(super) fn html_text(html: &str) -> String {
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
pub(super) fn tidy_text(text: &str) -> String {
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

/// Whose token endpoint refreshes a source's stored grant: the provider the
/// wire reading it serves. A grant goes to no other provider's endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GrantIssuer {
    /// Gmail and Google Calendar: a grant that carries a refresh token and
    /// its OAuth client.
    Google,
    /// Graph mail and calendar: a grant that carries a refresh token, its
    /// OAuth client and its tenant ([MICROSOFT365-OAUTH-EXCHANGE]).
    Microsoft,
}

impl GrantIssuer {
    /// A fresh access token for the stored grant `token`, when it is one
    /// this issuer refreshes, with the grant's successor when the refresh
    /// rotated it (Microsoft's); `None` for any other credential.
    ///
    /// # Errors
    ///
    /// `<issuer>_credential_refresh_failed` when the issuer refuses the
    /// grant's refresh token or cannot be reached.
    pub(crate) fn refresh(
        self,
        client: &reqwest::blocking::Client,
        token: &[u8],
    ) -> Result<Option<GrantAccess>> {
        match self {
            Self::Google => ProviderConnectionChecks::refresh_stored_google_grant(client, token)
                .map(|fresh| {
                    fresh.map(|access_token| GrantAccess {
                        access_token,
                        successor: None,
                    })
                })
                .map_err(|_| refused("google_credential_refresh_failed")),
            Self::Microsoft => {
                ProviderConnectionChecks::refresh_stored_microsoft_grant(client, token)
                    .map_err(|_| refused("microsoft_credential_refresh_failed"))
            }
        }
    }
}

/// The fresh access tokens one wire exchanged its sources' stored grants for
/// (fix list row 16311), by the source and the keyed digest of the grant: a
/// grant its issuer refreshes is exchanged at the issuer's token endpoint
/// once per wire, not once per call, and a rotated grant is exchanged again.
/// Read only inside the source's credential door, so a credential its door
/// refuses sends nothing; held in memory for the wire's life, never stored.
pub(super) struct FreshAccessTokens {
    issuer: GrantIssuer,
    key: [u8; 32],
    fresh: RefCell<BTreeMap<EntityId, ([u8; 32], zeroize::Zeroizing<String>)>>,
    /// The grant a refresh rotated, by source, until the source's door
    /// returns and [`Self::keep_successor`] hands it to the write-back.
    successors: RefCell<BTreeMap<EntityId, zeroize::Zeroizing<Vec<u8>>>>,
}

impl FreshAccessTokens {
    pub(super) fn new(issuer: GrantIssuer) -> Self {
        Self {
            issuer,
            key: rand::random(),
            fresh: RefCell::new(BTreeMap::new()),
            successors: RefCell::new(BTreeMap::new()),
        }
    }

    /// Hands the grant a refresh for `source` rotated to the custody
    /// write-back ([`Vault::keep_provider_refreshed_grant`]) for the door
    /// `door` that read the grant, once that door has returned. A door that
    /// refused drops it: the stored grant still works.
    pub(super) fn keep_successor(
        &self,
        vault: &Vault,
        source: EntityId,
        door: &Result<DoorInjectionReceipt>,
    ) {
        let successor = self.successors.borrow_mut().remove(&source);
        if let Ok(door) = door {
            vault.keep_provider_refreshed_grant(door, successor);
        }
    }

    /// The `Authorization: Bearer` value for `source`'s injected credential
    /// `token`: a fresh access token for a stored grant the issuer refreshes,
    /// else the credential as [`bearer_header`] reads it.
    ///
    /// # Errors
    ///
    /// [`GrantIssuer::refresh`]'s; [`bearer_header`]'s own.
    pub(super) fn bearer(
        &self,
        client: &reqwest::blocking::Client,
        source: EntityId,
        token: &[u8],
    ) -> Result<HeaderValue> {
        let digest = *blake3::keyed_hash(&self.key, token).as_bytes();
        if let Some((held, fresh)) = self.fresh.borrow().get(&source)
            && *held == digest
        {
            return bearer_header(fresh.as_bytes());
        }
        match self.issuer.refresh(client, token)? {
            Some(fresh) => {
                let header = bearer_header(fresh.access_token.as_bytes())?;
                if let Some(successor) = fresh.successor {
                    self.successors.borrow_mut().insert(source, successor);
                }
                self.fresh
                    .borrow_mut()
                    .insert(source, (digest, fresh.access_token));
                Ok(header)
            }
            None => bearer_header(token),
        }
    }
}

/// The credentials a wire has seen read the mailbox their source names, each
/// by a keyed digest of the exact bytes presented (FIX 12559, REVIEW-5754):
/// a credential replaced at its door is checked again before it reads. The
/// key is this wire's own and never leaves it, so a digest names no
/// credential outside it.
pub(super) struct VerifiedCredentials {
    key: [u8; 32],
    seen: RefCell<BTreeSet<(EntityId, [u8; 32])>>,
}

impl VerifiedCredentials {
    pub(super) fn new() -> Self {
        Self {
            key: rand::random(),
            seen: RefCell::new(BTreeSet::new()),
        }
    }

    fn digest(&self, source: EntityId, token: &[u8]) -> (EntityId, [u8; 32]) {
        (source, *blake3::keyed_hash(&self.key, token).as_bytes())
    }

    /// Whether `token` was seen read `source`'s mailbox.
    pub(super) fn holds(&self, source: EntityId, token: &[u8]) -> bool {
        self.seen.borrow().contains(&self.digest(source, token))
    }

    /// Records that `token` reads `source`'s mailbox.
    pub(super) fn insert(&self, source: EntityId, token: &[u8]) {
        let digest = self.digest(source, token);
        self.seen.borrow_mut().insert(digest);
    }
}
