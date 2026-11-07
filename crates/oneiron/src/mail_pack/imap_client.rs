//! A native IMAP4rev1 client (RFC 3501) for the mail pack's IMAP wire (FIX
//! 15425): TLS through rustls with the platform's roots, from the first byte
//! or after `STARTTLS` on a server's plain port (fix list row 17870), one
//! command at a time, each response parsed into items. It speaks what the
//! wire needs: `LOGIN` or `AUTHENTICATE` (`PLAIN`, `XOAUTH2`), `LIST`,
//! `EXAMINE`, `UID SEARCH` (`ESEARCH` where offered), `UID FETCH`, `LOGOUT`.
//! Every read is bounded, and every command ends by a deadline, however
//! slowly a server answers.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read, Write};
use std::time::{Duration, Instant};

use base64::Engine as _;

use super::rest::refused;
use super::tls_stream::{DeadlineStream, TlsRefusals, TlsStream, connect_tcp, tls_client};
use crate::error::Result;

/// The largest literal read: one whole message.
const MAX_LITERAL_BYTES: usize = 48 * 1024 * 1024;
/// The largest response read, its literals included.
const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
/// The most one command reads, all its responses together.
const MAX_COMMAND_BYTES: usize = 192 * 1024 * 1024;
/// How long connecting, the TLS handshake and the greeting may take.
const CONNECT_DEADLINE: Duration = Duration::from_secs(90);
/// How long one command may take, its answer read whole.
const COMMAND_DEADLINE: Duration = Duration::from_secs(300);
/// The largest UID, UIDVALIDITY or UIDNEXT: IMAP numbers are 32-bit.
pub(super) const MAX_IMAP_NUMBER: u64 = u32::MAX as u64;

/// The words the IMAP client gives the TLS stack's failures.
const IMAP_TLS: TlsRefusals = TlsRefusals {
    no_roots: "imap_tls_no_platform_roots",
    setup: "imap_tls_setup_failed",
    host: "imap_host_invalid",
    unresolved: "imap_host_unresolved",
    resolution_timed_out: "imap_host_resolution_timed_out",
    connect: "imap_connect_failed",
};

/// One parsed element of a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Item {
    /// An atom or a number, as written.
    Atom(String),
    /// A quoted string or a literal, its bytes.
    Text(Vec<u8>),
    /// A parenthesized list, or a bracketed response code.
    List(Vec<Item>),
    Nil,
}

impl Item {
    pub(super) fn atom(&self) -> Option<&str> {
        match self {
            Self::Atom(atom) => Some(atom),
            _ => None,
        }
    }

    pub(super) fn number(&self) -> Option<u64> {
        self.atom().and_then(|atom| atom.parse().ok())
    }

    /// The bytes of a string, a literal or an atom.
    pub(super) fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Atom(atom) => Some(atom.as_bytes()),
            Self::Text(bytes) => Some(bytes),
            _ => None,
        }
    }

    pub(super) fn list(&self) -> Option<&[Item]> {
        match self {
            Self::List(items) => Some(items),
            _ => None,
        }
    }
}

/// One untagged response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Untagged {
    /// `OK`, `NO`, `BAD`, `BYE` or `PREAUTH`, with its response code.
    Status { kind: String, code: Vec<Item> },
    /// A message-numbered response: `n EXISTS`, `n EXPUNGE`, `n FETCH (..)`.
    Numbered {
        number: u64,
        kind: String,
        items: Vec<Item>,
    },
    /// Any other data response (`CAPABILITY`, `LIST`, `SEARCH`, `ESEARCH`,
    /// `FLAGS`), its text after the name unparsed.
    Data { kind: String, rest: Vec<u8> },
}

/// What a selected mailbox reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct FolderStatus {
    pub(super) uid_validity: u64,
    pub(super) uid_next: u64,
    pub(super) exists: u64,
}

/// One mailbox a `LIST` names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ListedFolder {
    /// Its name as the server spells it (modified UTF-7).
    pub(super) name: String,
    /// Its attributes, lowercased (`\noselect`, `\trash`, `\sent`).
    pub(super) attributes: Vec<String>,
}

/// One message a `FETCH` answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Fetched {
    pub(super) sequence: u64,
    pub(super) items: Vec<Item>,
}

impl Fetched {
    /// The value after attribute `name`.
    pub(super) fn value(&self, name: &str) -> Option<&Item> {
        fetch_value(&self.items, name)
    }

    /// The value after the first attribute whose name starts with
    /// `prefix`: a section the server may spell its own way
    /// (`BODY[HEADER.FIELDS ("MESSAGE-ID")]`).
    pub(super) fn value_starting(&self, prefix: &str) -> Option<&Item> {
        self.items
            .chunks(2)
            .find(|pair| {
                pair.first().and_then(Item::atom).is_some_and(|atom| {
                    atom.len() >= prefix.len()
                        && atom.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
                })
            })
            .and_then(|pair| pair.get(1))
    }

    pub(super) fn uid(&self) -> Option<u64> {
        self.value("UID")
            .and_then(Item::number)
            .filter(|uid| (1..=MAX_IMAP_NUMBER).contains(uid))
    }
}

/// One authenticated session.
pub(super) struct ImapSession {
    reader: BufReader<TlsStream>,
    next_tag: u32,
    capabilities: BTreeSet<String>,
}

fn malformed() -> crate::Error {
    refused("imap_response_malformed")
}

/// The deepest list nesting a response may have.
const MAX_NESTING: usize = 32;

/// Parses response items from `buf`, from `at`, up to `close` (or the end).
struct Tokens<'b> {
    buf: &'b [u8],
    at: usize,
    depth: usize,
}

impl Tokens<'_> {
    fn items(&mut self, close: Option<u8>) -> Result<Vec<Item>> {
        let mut items = Vec::new();
        loop {
            while matches!(self.buf.get(self.at), Some(b' ' | b'\r' | b'\n')) {
                self.at += 1;
            }
            let Some(&byte) = self.buf.get(self.at) else {
                return if close.is_none() {
                    Ok(items)
                } else {
                    Err(malformed())
                };
            };
            if Some(byte) == close {
                self.at += 1;
                return Ok(items);
            }
            match byte {
                b'(' | b'[' => {
                    if self.depth >= MAX_NESTING {
                        return Err(malformed());
                    }
                    self.at += 1;
                    self.depth += 1;
                    let close = if byte == b'(' { b')' } else { b']' };
                    let list = self.items(Some(close))?;
                    self.depth -= 1;
                    items.push(Item::List(list));
                }
                b'"' => items.push(Item::Text(self.quoted()?)),
                b'{' => items.push(Item::Text(self.literal()?)),
                b')' | b']' => return Err(malformed()),
                _ => items.push(self.atom(close)),
            }
        }
    }

    fn quoted(&mut self) -> Result<Vec<u8>> {
        self.at += 1;
        let mut out = Vec::new();
        loop {
            match self.buf.get(self.at) {
                None | Some(b'\r' | b'\n') => return Err(malformed()),
                Some(b'"') => {
                    self.at += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    let escaped = *self.buf.get(self.at + 1).ok_or_else(malformed)?;
                    out.push(escaped);
                    self.at += 2;
                }
                Some(&byte) => {
                    out.push(byte);
                    self.at += 1;
                }
            }
        }
    }

    /// A literal: `{n}` (or `{n+}`), CRLF, then exactly `n` bytes.
    fn literal(&mut self) -> Result<Vec<u8>> {
        let rest = &self.buf[self.at..];
        let close = rest.iter().position(|&b| b == b'}').ok_or_else(malformed)?;
        let digits = std::str::from_utf8(&rest[1..close]).map_err(|_| malformed())?;
        let length: usize = digits
            .trim_end_matches('+')
            .parse()
            .map_err(|_| malformed())?;
        let start = self.at + close + 1;
        if self.buf.get(start..start + 2) != Some(b"\r\n") {
            return Err(malformed());
        }
        let body = start + 2;
        let end = body.checked_add(length).ok_or_else(malformed)?;
        let bytes = self.buf.get(body..end).ok_or_else(malformed)?.to_vec();
        self.at = end;
        Ok(bytes)
    }

    /// An atom; a section in brackets (`BODY[HEADER.FIELDS (X)]`) is part of
    /// it, spaces and all.
    fn atom(&mut self, close: Option<u8>) -> Item {
        let start = self.at;
        while let Some(&byte) = self.buf.get(self.at) {
            match byte {
                b'[' => match self.buf[self.at..].iter().position(|&b| b == b']') {
                    Some(end) => self.at += end + 1,
                    None => self.at = self.buf.len(),
                },
                b' ' | b'(' | b')' | b'"' | b'{' | b'\r' | b'\n' => break,
                b']' if close == Some(b']') => break,
                _ => self.at += 1,
            }
        }
        let atom = String::from_utf8_lossy(&self.buf[start..self.at]).into_owned();
        if atom.eq_ignore_ascii_case("NIL") {
            Item::Nil
        } else {
            Item::Atom(atom)
        }
    }
}

/// Parses `buf` whole into items.
pub(super) fn parse_items(buf: &[u8]) -> Result<Vec<Item>> {
    Tokens {
        buf,
        at: 0,
        depth: 0,
    }
    .items(None)
}

/// The length of the literal a response line ends announcing, if it does.
fn literal_at_end(line: &[u8]) -> Option<usize> {
    let line = line.strip_suffix(b"\r\n")?;
    let line = line.strip_suffix(b"}")?;
    let open = line.iter().rposition(|&b| b == b'{')?;
    let digits = std::str::from_utf8(&line[open + 1..]).ok()?;
    digits.trim_end_matches('+').parse().ok()
}

/// `text` as an IMAP quoted string, when it can be one.
fn quoted(text: &str) -> Option<String> {
    if text.len() > 1_000 || text.chars().any(|c| c.is_control() || !c.is_ascii()) {
        return None;
    }
    Some(format!(
        "\"{}\"",
        text.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

/// The first word of `rest`, and what follows its space.
fn split_word(rest: &[u8]) -> (String, &[u8]) {
    let end = rest.iter().position(|&b| b == b' ').unwrap_or(rest.len());
    let word = String::from_utf8_lossy(&rest[..end]).into_owned();
    let tail = rest.get(end + 1..).unwrap_or_default();
    (word, tail)
}

/// Parses one untagged response (the bytes after `* `).
fn untagged(body: &[u8]) -> Result<Untagged> {
    let body = body.strip_suffix(b"\r\n").unwrap_or(body);
    let (first, rest) = split_word(body);
    if let Ok(number) = first.parse::<u64>() {
        let (kind, rest) = split_word(rest);
        return Ok(Untagged::Numbered {
            number,
            kind: kind.to_ascii_uppercase(),
            items: parse_items(rest)?,
        });
    }
    let kind = first.to_ascii_uppercase();
    if matches!(kind.as_str(), "OK" | "NO" | "BAD" | "BYE" | "PREAUTH") {
        // Only the bracketed code parses; the human text after it is free.
        let code = if rest.first() == Some(&b'[') {
            let end = rest.iter().position(|&b| b == b']').ok_or_else(malformed)?;
            parse_items(&rest[1..end])?
        } else {
            Vec::new()
        };
        return Ok(Untagged::Status { kind, code });
    }
    Ok(Untagged::Data {
        kind,
        rest: rest.to_vec(),
    })
}

/// The mailbox one `LIST` response names: `(attributes) delimiter name`.
fn listed(rest: &[u8]) -> Result<ListedFolder> {
    let mut tokens = Tokens {
        buf: rest,
        at: 0,
        depth: 0,
    };
    tokens.skip_spaces();
    if tokens.buf.get(tokens.at) != Some(&b'(') {
        return Err(malformed());
    }
    tokens.at += 1;
    let attributes = tokens
        .items(Some(b')'))?
        .iter()
        .filter_map(Item::atom)
        .map(str::to_ascii_lowercase)
        .collect();
    tokens.skip_spaces();
    // The hierarchy delimiter: a quoted character, or NIL.
    match tokens.buf.get(tokens.at) {
        Some(b'"') => {
            tokens.quoted()?;
        }
        Some(_) => {
            tokens.atom(None);
        }
        None => return Err(malformed()),
    }
    tokens.skip_spaces();
    let name = match tokens.buf.get(tokens.at) {
        Some(b'"') => tokens.quoted()?,
        Some(b'{') => tokens.literal()?,
        // An unquoted name may hold brackets (`[Gmail]`): it runs to the end.
        Some(_) => tokens.buf[tokens.at..].to_vec(),
        None => return Err(malformed()),
    };
    let name = String::from_utf8(name).map_err(|_| malformed())?;
    Ok(ListedFolder {
        name: name.trim().to_owned(),
        attributes,
    })
}

impl Tokens<'_> {
    fn skip_spaces(&mut self) {
        while self.buf.get(self.at) == Some(&b' ') {
            self.at += 1;
        }
    }
}

impl ImapSession {
    /// Connects to `host:port` and reads the greeting: over TLS from the
    /// first byte, or with `starttls` in the clear until the server takes
    /// `STARTTLS`, and over TLS from then on.
    ///
    /// # Errors
    ///
    /// A host that does not resolve or answer, a TLS failure (an
    /// untrusted certificate included), a server that does not upgrade to
    /// TLS when asked, or a server that is not IMAP4rev1.
    pub(super) fn connect(host: &str, port: u16, starttls: bool) -> Result<Self> {
        let tls = tls_client(host, &IMAP_TLS)?;
        let deadline = Instant::now() + CONNECT_DEADLINE;
        let mut stream = connect_tcp(host, port, deadline, &IMAP_TLS)?;
        if starttls {
            stream = start_tls(stream)?;
        }
        // The handshake runs within the first read: the greeting's, or
        // after `STARTTLS` the first command's.
        let mut session = Self {
            reader: BufReader::new(rustls::StreamOwned::new(tls, stream)),
            next_tag: 1,
            capabilities: BTreeSet::new(),
        };
        if !starttls {
            let greeting = session.read_response()?;
            let code = greeting_code(&greeting)?;
            session.take_capabilities(&code);
        }
        // The capabilities told in the clear are not taken: once TLS is up,
        // they are asked again.
        if session.capabilities.is_empty() {
            let answers = session.command("CAPABILITY")?;
            for answer in &answers {
                if let Untagged::Data { kind, rest } = answer
                    && kind == "CAPABILITY"
                {
                    let items = parse_items(rest)?;
                    session.take_capability_atoms(&items);
                }
            }
        }
        if !session.has("IMAP4REV1") && !session.has("IMAP4REV2") {
            return Err(refused("imap_server_not_imap4rev1"));
        }
        Ok(session)
    }

    fn take_capabilities(&mut self, code: &[Item]) {
        if code
            .first()
            .and_then(Item::atom)
            .is_some_and(|atom| atom.eq_ignore_ascii_case("CAPABILITY"))
        {
            self.take_capability_atoms(&code[1..]);
        }
    }

    fn take_capability_atoms(&mut self, items: &[Item]) {
        self.capabilities = capability_set(items);
    }

    /// Whether the server announced `capability` (uppercase).
    pub(super) fn has(&self, capability: &str) -> bool {
        self.capabilities.contains(capability)
    }

    /// Signs in: `XOAUTH2` with an access token, else `AUTHENTICATE PLAIN`
    /// where offered, else `LOGIN`.
    ///
    /// # Errors
    ///
    /// The server refusing the credential, or offering no way to present it.
    pub(super) fn authenticate(
        &mut self,
        username: &str,
        password: Option<&str>,
        access_token: Option<&str>,
    ) -> Result<()> {
        let engine = base64::engine::general_purpose::STANDARD;
        if let Some(token) = access_token {
            if !self.has("AUTH=XOAUTH2") {
                return Err(refused("imap_server_offers_no_xoauth2"));
            }
            let response = engine.encode(format!("user={username}\x01auth=Bearer {token}\x01\x01"));
            self.sasl("XOAUTH2", &response)?;
        } else {
            let password = password.ok_or_else(|| refused("imap_credential_has_no_password"))?;
            if self.has("AUTH=PLAIN") {
                let response = engine.encode(format!("\0{username}\0{password}"));
                self.sasl("PLAIN", &response)?;
            } else if self.has("LOGINDISABLED") {
                return Err(refused("imap_server_disables_login"));
            } else {
                let (Some(user), Some(pass)) = (quoted(username), quoted(password)) else {
                    return Err(refused("imap_credential_not_quotable"));
                };
                self.command(&format!("LOGIN {user} {pass}"))
                    .map_err(|_| refused("imap_login_refused"))?;
            }
        }
        // A server may announce other capabilities once signed in.
        let answers = self.command("CAPABILITY")?;
        for answer in &answers {
            if let Untagged::Data { kind, rest } = answer
                && kind == "CAPABILITY"
            {
                let items = parse_items(rest)?;
                self.take_capability_atoms(&items);
            }
        }
        Ok(())
    }

    /// `AUTHENTICATE mechanism` with its one response, sent in the command
    /// where the server takes an initial response, else on its prompt.
    fn sasl(&mut self, mechanism: &str, response: &str) -> Result<()> {
        self.arm();
        let tag = self.tag();
        if self.has("SASL-IR") {
            self.write(&format!("{tag} AUTHENTICATE {mechanism} {response}\r\n"))?;
        } else {
            self.write(&format!("{tag} AUTHENTICATE {mechanism}\r\n"))?;
            let prompt = self.read_response()?;
            if !prompt.starts_with(b"+") {
                return Err(refused("imap_login_refused"));
            }
            self.write(&format!("{response}\r\n"))?;
        }
        let mut answers = Vec::new();
        let mut prompts = 0_u32;
        loop {
            let response = self.read_response()?;
            if response.starts_with(b"+") {
                // A refusal's details: answer with an empty line to end it.
                prompts += 1;
                if prompts > 2 {
                    return Err(refused("imap_login_refused"));
                }
                self.write("\r\n")?;
                continue;
            }
            if let Some(done) = Self::completion(&tag, &response, &mut answers)? {
                return if done {
                    Ok(())
                } else {
                    Err(refused("imap_login_refused"))
                };
            }
        }
    }

    /// Gives the next command its own deadline.
    fn arm(&mut self) {
        self.reader.get_mut().sock.deadline = Instant::now() + COMMAND_DEADLINE;
    }

    fn tag(&mut self) -> String {
        let tag = format!("o{}", self.next_tag);
        self.next_tag += 1;
        tag
    }

    fn write(&mut self, text: &str) -> Result<()> {
        let stream = self.reader.get_mut();
        stream
            .write_all(text.as_bytes())
            .and_then(|()| stream.flush())
            .map_err(|_| refused("imap_transport_failed"))
    }

    /// One response, its literals included.
    fn read_response(&mut self) -> Result<Vec<u8>> {
        read_response_from(&mut self.reader)
    }

    /// Reads `response` as the end of command `tag`: `Some(true)` for `OK`,
    /// `Some(false)` for `NO`, `None` for an untagged response (kept in
    /// `answers`).
    fn completion(tag: &str, response: &[u8], answers: &mut Vec<Untagged>) -> Result<Option<bool>> {
        if let Some(body) = response.strip_prefix(b"* ") {
            let answer = untagged(body)?;
            if matches!(&answer, Untagged::Status { kind, .. } if kind == "BYE") {
                return Err(refused("imap_server_closed_session"));
            }
            answers.push(answer);
            return Ok(None);
        }
        let Some(rest) = response
            .strip_prefix(tag.as_bytes())
            .and_then(|rest| rest.strip_prefix(b" "))
        else {
            return Err(malformed());
        };
        let (status, _) = split_word(rest);
        match status.to_ascii_uppercase().as_str() {
            "OK" => Ok(Some(true)),
            "NO" => Ok(Some(false)),
            _ => Err(refused("imap_command_rejected")),
        }
    }

    /// Runs one command and answers its untagged responses.
    ///
    /// # Errors
    ///
    /// A `NO` or `BAD` completion, a closed session, a transport failure.
    pub(super) fn command(&mut self, text: &str) -> Result<Vec<Untagged>> {
        self.arm();
        let tag = self.tag();
        self.write(&format!("{tag} {text}\r\n"))?;
        let mut answers = Vec::new();
        let mut read = 0_usize;
        loop {
            let response = self.read_response()?;
            read = read.saturating_add(response.len());
            if read > MAX_COMMAND_BYTES {
                return Err(refused("imap_response_too_large"));
            }
            match Self::completion(&tag, &response, &mut answers)? {
                None => {}
                Some(true) => return Ok(answers),
                Some(false) => return Err(refused("imap_command_refused")),
            }
        }
    }

    /// Every mailbox: `LIST "" "*"`.
    ///
    /// # Errors
    ///
    /// The command's own.
    pub(super) fn list(&mut self) -> Result<Vec<ListedFolder>> {
        let answers = self.command("LIST \"\" \"*\"")?;
        let mut folders = Vec::new();
        for answer in &answers {
            if let Untagged::Data { kind, rest } = answer
                && kind == "LIST"
            {
                folders.push(listed(rest)?);
            }
        }
        Ok(folders)
    }

    /// Opens `folder` read-only (`EXAMINE`), again each time so its status
    /// is current, and answers that status.
    ///
    /// # Errors
    ///
    /// No such mailbox, a status out of IMAP's range, or the command's own.
    pub(super) fn examine(&mut self, folder: &str) -> Result<FolderStatus> {
        let name = mailbox_argument(folder)?;
        let answers = self.command(&format!("EXAMINE {name}"))?;
        let mut status = FolderStatus::default();
        for answer in &answers {
            match answer {
                Untagged::Numbered { number, kind, .. } if kind == "EXISTS" => {
                    status.exists = *number;
                }
                Untagged::Status { code, .. } => {
                    let value = code.get(1).and_then(Item::number);
                    match (code.first().and_then(Item::atom), value) {
                        (Some(name), Some(value)) if name.eq_ignore_ascii_case("UIDVALIDITY") => {
                            status.uid_validity = value;
                        }
                        (Some(name), Some(value)) if name.eq_ignore_ascii_case("UIDNEXT") => {
                            status.uid_next = value;
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        if status.uid_validity == 0 {
            return Err(refused("imap_mailbox_has_no_uidvalidity"));
        }
        if status.uid_validity > MAX_IMAP_NUMBER
            || status.uid_next > MAX_IMAP_NUMBER + 1
            || status.exists > MAX_IMAP_NUMBER
        {
            return Err(malformed());
        }
        Ok(status)
    }

    /// The UIDs `UID SEARCH criteria` answers in the open mailbox, ascending.
    ///
    /// # Errors
    ///
    /// The command's own.
    pub(super) fn uid_search(&mut self, criteria: &str) -> Result<Vec<u64>> {
        let answers = self.command(&format!("UID SEARCH {criteria}"))?;
        let mut uids = Vec::new();
        for answer in &answers {
            if let Untagged::Data { kind, rest } = answer
                && kind == "SEARCH"
            {
                uids.extend(
                    parse_items(rest)?
                        .iter()
                        .filter_map(Item::number)
                        .filter(|uid| (1..=MAX_IMAP_NUMBER).contains(uid)),
                );
            }
        }
        uids.sort_unstable();
        uids.dedup();
        Ok(uids)
    }

    /// The UIDs from `low` to `high` the open mailbox holds, as ascending
    /// ranges: one `ESEARCH` answer where the server offers it, which names
    /// a run of UIDs in a few bytes, else a plain `UID SEARCH`.
    ///
    /// # Errors
    ///
    /// A malformed set, or the command's own.
    pub(super) fn uid_ranges(&mut self, low: u64, high: u64) -> Result<Vec<(u64, u64)>> {
        if low > high {
            return Ok(Vec::new());
        }
        if !self.has("ESEARCH") {
            let mut uids = self.uid_search(&format!("UID {low}:{high}"))?;
            uids.retain(|uid| (low..=high).contains(uid));
            return Ok(ranges_of(&uids));
        }
        let answers = self.command(&format!("UID SEARCH RETURN (ALL) UID {low}:{high}"))?;
        let mut ranges = Vec::new();
        for answer in &answers {
            if let Untagged::Data { kind, rest } = answer
                && kind == "ESEARCH"
            {
                let items = parse_items(rest)?;
                let all = items.iter().position(|item| {
                    item.atom()
                        .is_some_and(|atom| atom.eq_ignore_ascii_case("ALL"))
                });
                if let Some(at) = all {
                    let set = items
                        .get(at + 1)
                        .and_then(Item::atom)
                        .ok_or_else(malformed)?;
                    ranges.extend(parse_set(set)?);
                }
            }
        }
        Ok(merged(ranges, low, high))
    }

    /// `UID FETCH set (attributes)` in the open mailbox: each message's
    /// sequence number and attribute list.
    ///
    /// # Errors
    ///
    /// The command's own.
    pub(super) fn uid_fetch(&mut self, set: &str, attributes: &str) -> Result<Vec<Fetched>> {
        self.fetch_command(&format!("UID FETCH {set} ({attributes})"))
    }

    /// `FETCH low:high (attributes)` by sequence number in the open mailbox.
    ///
    /// # Errors
    ///
    /// The command's own.
    pub(super) fn fetch_sequence(
        &mut self,
        low: u64,
        high: u64,
        attributes: &str,
    ) -> Result<Vec<Fetched>> {
        self.fetch_command(&format!("FETCH {low}:{high} ({attributes})"))
    }

    fn fetch_command(&mut self, command: &str) -> Result<Vec<Fetched>> {
        let answers = self.command(command)?;
        Ok(answers
            .into_iter()
            .filter_map(|answer| match answer {
                Untagged::Numbered {
                    number,
                    kind,
                    items,
                } if kind == "FETCH" => match items.into_iter().next() {
                    Some(Item::List(items)) => Some(Fetched {
                        sequence: number,
                        items,
                    }),
                    _ => None,
                },
                _ => None,
            })
            .collect())
    }

    /// Ends the session; a failure to say goodbye is no failure.
    pub(super) fn logout(mut self) {
        let _ = self.command("LOGOUT");
    }
}

/// `folder` as a command argument: quoted, or a literal-free refusal.
fn mailbox_argument(folder: &str) -> Result<String> {
    quoted(folder).ok_or_else(|| refused("imap_mailbox_name_unsupported"))
}

/// The value after attribute `name` in one message's `FETCH` list.
fn fetch_value<'i>(items: &'i [Item], name: &str) -> Option<&'i Item> {
    items
        .chunks(2)
        .find(|pair| {
            pair.first()
                .and_then(Item::atom)
                .is_some_and(|atom| atom.eq_ignore_ascii_case(name))
        })
        .and_then(|pair| pair.get(1))
}

/// `uids` as a compact UID set: `1:4,7,9:12`.
pub(super) fn uid_set(uids: &[u64]) -> String {
    let mut out = String::new();
    let mut at = 0;
    while at < uids.len() {
        let start = uids[at];
        let mut end = start;
        while at + 1 < uids.len() && uids[at + 1] == end + 1 {
            at += 1;
            end = uids[at];
        }
        if !out.is_empty() {
            out.push(',');
        }
        let _ = if start == end {
            write!(out, "{start}")
        } else {
            write!(out, "{start}:{end}")
        };
        at += 1;
    }
    out
}

/// `ranges` as a UID set: `1:4,7,9:12`.
pub(super) fn range_set(ranges: &[(u64, u64)]) -> String {
    let mut out = String::new();
    for &(low, high) in ranges {
        if !out.is_empty() {
            out.push(',');
        }
        let _ = if low == high {
            write!(out, "{low}")
        } else {
            write!(out, "{low}:{high}")
        };
    }
    out
}

/// Ascending `uids` as ascending ranges.
fn ranges_of(uids: &[u64]) -> Vec<(u64, u64)> {
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    for &uid in uids {
        match ranges.last_mut() {
            Some((_, high)) if *high + 1 == uid => *high = uid,
            _ => ranges.push((uid, uid)),
        }
    }
    ranges
}

/// A sequence set a server answered (`1:3,5,9:7`), as ranges, each in
/// IMAP's range.
fn parse_set(set: &str) -> Result<Vec<(u64, u64)>> {
    let number = |text: &str| {
        text.parse::<u64>()
            .ok()
            .filter(|uid| (1..=MAX_IMAP_NUMBER).contains(uid))
            .ok_or_else(malformed)
    };
    set.split(',')
        .map(|part| match part.split_once(':') {
            Some((a, b)) => {
                let (a, b) = (number(a)?, number(b)?);
                Ok((a.min(b), a.max(b)))
            }
            None => number(part).map(|uid| (uid, uid)),
        })
        .collect()
}

/// `ranges` cut to `low..=high`, in order, overlaps joined.
fn merged(mut ranges: Vec<(u64, u64)>, low: u64, high: u64) -> Vec<(u64, u64)> {
    ranges.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::new();
    for (start, end) in ranges {
        let (start, end) = (start.max(low), end.min(high));
        if start > end {
            continue;
        }
        match out.last_mut() {
            Some((_, last)) if start <= last.saturating_add(1) => *last = (*last).max(end),
            _ => out.push((start, end)),
        }
    }
    out
}

/// Whether ascending `ranges` hold `uid`.
pub(super) fn ranges_hold(ranges: &[(u64, u64)], uid: u64) -> bool {
    let at = ranges.partition_point(|&(_, high)| high < uid);
    ranges.get(at).is_some_and(|&(low, _)| low <= uid)
}

/// The capabilities `items` name, uppercase.
fn capability_set(items: &[Item]) -> BTreeSet<String> {
    items
        .iter()
        .filter_map(Item::atom)
        .map(str::to_ascii_uppercase)
        .collect()
}

/// The response code of a server's greeting, when it is a plain `OK`: a
/// session signed in before it presents a credential (`PREAUTH`) is not
/// this source's, and is refused.
fn greeting_code(greeting: &[u8]) -> Result<Vec<Item>> {
    let greeting = greeting
        .strip_prefix(b"* ")
        .ok_or_else(|| refused("imap_greeting_malformed"))?;
    match untagged(greeting)? {
        Untagged::Status { kind, code } if kind == "OK" => Ok(code),
        _ => Err(refused("imap_server_refused_connection")),
    }
}

/// One response from `reader`, its literals included.
fn read_response_from(reader: &mut impl BufRead) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let start = out.len();
        let room = MAX_RESPONSE_BYTES.saturating_sub(start);
        let read = (&mut *reader)
            .take(u64::try_from(room).unwrap_or(u64::MAX))
            .read_until(b'\n', &mut out)
            .map_err(|_| refused("imap_transport_failed"))?;
        if read == 0 {
            return Err(refused("imap_connection_closed"));
        }
        if !out.ends_with(b"\n") {
            return Err(refused("imap_response_too_large"));
        }
        let Some(length) = literal_at_end(&out[start..]) else {
            return Ok(out);
        };
        if length > MAX_LITERAL_BYTES || out.len() + length > MAX_RESPONSE_BYTES {
            return Err(refused("imap_response_too_large"));
        }
        let at = out.len();
        out.resize(at + length, 0);
        reader
            .read_exact(&mut out[at..])
            .map_err(|_| refused("imap_transport_failed"))?;
    }
}

/// Upgrades a connection to a server's plain port (RFC 3501 6.2.1): reads
/// its greeting, asks for its capabilities when the greeting does not tell
/// them, and sends `STARTTLS`. A server that does not offer it, or does not
/// take it, is refused: nothing but these two commands goes in the clear.
/// The stream is answered with no byte of the clear exchange left unread,
/// so nothing the server sent before the handshake is read after it.
fn start_tls(stream: DeadlineStream) -> Result<DeadlineStream> {
    let mut reader = BufReader::new(stream);
    let greeting = read_response_from(&mut reader)?;
    let code = greeting_code(&greeting)?;
    let told = code
        .first()
        .and_then(Item::atom)
        .is_some_and(|atom| atom.eq_ignore_ascii_case("CAPABILITY"));
    let mut capabilities = if told {
        capability_set(&code[1..])
    } else {
        BTreeSet::new()
    };
    if capabilities.is_empty() {
        for answer in clear_command(&mut reader, "s1", "CAPABILITY")? {
            if let Untagged::Data { kind, rest } = answer
                && kind == "CAPABILITY"
            {
                capabilities = capability_set(&parse_items(&rest)?);
            }
        }
    }
    if !capabilities.contains("STARTTLS") {
        return Err(refused("imap_server_offers_no_starttls"));
    }
    clear_command(&mut reader, "s2", "STARTTLS").map_err(|_| refused("imap_starttls_refused"))?;
    if !reader.buffer().is_empty() {
        return Err(refused("imap_starttls_data_before_handshake"));
    }
    Ok(reader.into_inner())
}

/// Runs one command in the clear, before TLS, and answers its untagged
/// responses; any completion but `OK` refuses.
fn clear_command(
    reader: &mut BufReader<DeadlineStream>,
    tag: &str,
    text: &str,
) -> Result<Vec<Untagged>> {
    let stream = reader.get_mut();
    stream
        .write_all(format!("{tag} {text}\r\n").as_bytes())
        .and_then(|()| stream.flush())
        .map_err(|_| refused("imap_transport_failed"))?;
    let mut answers = Vec::new();
    let mut read = 0_usize;
    loop {
        let response = read_response_from(reader)?;
        read = read.saturating_add(response.len());
        if read > MAX_RESPONSE_BYTES {
            return Err(refused("imap_response_too_large"));
        }
        match ImapSession::completion(tag, &response, &mut answers)? {
            None => {}
            Some(true) => return Ok(answers),
            Some(false) => return Err(refused("imap_command_refused")),
        }
    }
}

/// A modified UTF-7 mailbox name (RFC 3501 5.1.3) as text; one that does
/// not decode stays as written.
pub(super) fn decode_mailbox_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut rest = name;
    while let Some(open) = rest.find('&') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('-') else {
            return name.to_owned();
        };
        let encoded = &after[..close];
        if encoded.is_empty() {
            out.push('&');
        } else {
            let standard = encoded.replace(',', "/");
            let Ok(bytes) = base64::engine::general_purpose::STANDARD_NO_PAD.decode(standard)
            else {
                return name.to_owned();
            };
            if bytes.len() % 2 != 0 {
                return name.to_owned();
            }
            let units: Vec<u16> = bytes
                .chunks(2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                .collect();
            let Ok(text) = String::from_utf16(&units) else {
                return name.to_owned();
            };
            out.push_str(&text);
        }
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    out
}
