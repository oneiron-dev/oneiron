//! A native SMTP submission client (RFC 6409 over RFC 5321) for the pack's
//! drafted replies from IMAP mailboxes (fix list row 17872): TLS through
//! rustls with the platform's roots, from the first byte (port 465) or after
//! `STARTTLS` on the submission port (587), one command at a time. It
//! authenticates only over TLS (`PLAIN`, `LOGIN`, or `XOAUTH2` with a
//! token), names one sender and every recipient of the one message it
//! sends (fix list row 17645). A server that refuses any recipient of a
//! message to several is told `RSET` before any data goes: the message
//! reaches all of its recipients or none of them. Every reply is bounded,
//! and every command ends by a deadline. Once the data's final dot is
//! written, a missing answer is no proof the message was not taken: the
//! submission is uncertain, never refused.
//!
//! The server's `EHLO` over TLS names the most octets it takes (`SIZE`, RFC
//! 1870): a positive number is its limit; `SIZE` absent, with no number or
//! with 0 names none (fix list row 17645). A message is counted as its CRLF
//! octets, not its dot-stuffed data or the final `.<CRLF>`, and is refused
//! before `MAIL` above that limit, else above the limit its caller gives for
//! a server that names none; where the server offers `SIZE`, `MAIL FROM`
//! declares the message's octets.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::time::{Duration, Instant};

use base64::Engine as _;

use super::rest::refused;
use super::tls_stream::{DeadlineStream, TlsRefusals, TlsStream, connect_tcp, tls_client};
use crate::error::Result;

/// The longest reply line read, in bytes.
const MAX_LINE_BYTES: usize = 2_048;
/// The most lines one reply has.
const MAX_REPLY_LINES: usize = 200;
/// How long connecting, the TLS handshake, the greeting and `EHLO` may take.
const CONNECT_DEADLINE: Duration = Duration::from_secs(90);
/// How long one command may take, its reply read whole.
const COMMAND_DEADLINE: Duration = Duration::from_secs(300);
/// How long the message's data and its final reply may take (RFC 5321
/// §4.5.3.2.6 gives the final reply ten minutes).
const DATA_DEADLINE: Duration = Duration::from_secs(600);

/// The words the SMTP client gives the TLS stack's failures.
const SMTP_TLS: TlsRefusals = TlsRefusals {
    no_roots: "smtp_tls_no_platform_roots",
    setup: "smtp_tls_setup_failed",
    host: "smtp_host_invalid",
    unresolved: "smtp_host_unresolved",
    connect: "smtp_connect_failed",
};

/// How a session reaches TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SmtpSecurity {
    /// TLS from the first byte (port 465).
    Tls,
    /// The submission port in the clear, upgraded by `STARTTLS` before
    /// anything else is sent (port 587).
    Starttls,
}

/// What a session authenticates with.
pub(super) enum SmtpAuth<'a> {
    /// The account's password (an app password where the provider offers
    /// one).
    Password(&'a str),
    /// An OAuth access token (`XOAUTH2`).
    Token(&'a str),
}

/// How one submission ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Submitted {
    /// The server took the message: its final reply's text.
    Accepted(String),
    /// The server took nothing: the reason.
    NotSent(&'static str),
    /// The data went and no final reply came: the message may have been
    /// taken.
    Uncertain(&'static str),
}

/// One reply: its code, and the text of each of its lines.
struct Reply {
    code: u16,
    lines: Vec<String>,
}

/// The connection, in the clear until TLS is up.
enum Wire {
    Clear(BufReader<DeadlineStream>),
    Tls(Box<BufReader<TlsStream>>),
}

impl Wire {
    fn reader(&mut self) -> &mut dyn BufRead {
        match self {
            Self::Clear(reader) => reader,
            Self::Tls(reader) => reader.as_mut(),
        }
    }

    fn writer(&mut self) -> &mut dyn Write {
        match self {
            Self::Clear(reader) => reader.get_mut(),
            Self::Tls(reader) => reader.get_mut(),
        }
    }

    fn set_deadline(&mut self, deadline: Instant) {
        match self {
            Self::Clear(reader) => reader.get_mut().deadline = deadline,
            Self::Tls(reader) => reader.get_mut().sock.deadline = deadline,
        }
    }
}

/// One authenticated submission session.
pub(super) struct SmtpSession {
    wire: Wire,
    /// What the server's `EHLO` over TLS offered, each keyword upper case.
    extensions: BTreeSet<String>,
    /// The `AUTH` mechanisms it offered, upper case.
    mechanisms: BTreeSet<String>,
    /// The most octets one message may have, as the server's `EHLO` over TLS
    /// named it (`SIZE` with a positive number); `None` when it names none.
    size_limit: Option<u64>,
    /// The name this client gives itself in `EHLO`.
    client_name: String,
}

impl SmtpSession {
    /// Connects to `host:port`, reads the greeting and says `EHLO` as
    /// `client_name`: over TLS from the first byte, or with `Starttls` in the
    /// clear until the server takes `STARTTLS`, and over TLS from then on.
    ///
    /// # Errors
    ///
    /// A host that does not resolve or answer, a TLS failure (an untrusted
    /// certificate included), a server that does not upgrade to TLS when
    /// asked, or a server that refuses the session.
    pub(super) fn connect(
        host: &str,
        port: u16,
        security: SmtpSecurity,
        client_name: &str,
    ) -> Result<Self> {
        let tls = tls_client(host, &SMTP_TLS)?;
        let deadline = Instant::now() + CONNECT_DEADLINE;
        let stream = connect_tcp(host, port, deadline, &SMTP_TLS)?;
        let mut session = Self {
            wire: Wire::Clear(BufReader::new(stream)),
            extensions: BTreeSet::new(),
            mechanisms: BTreeSet::new(),
            size_limit: None,
            client_name: client_name.to_owned(),
        };
        if security == SmtpSecurity::Tls {
            session = session.upgrade(tls)?;
            session.greeting()?;
        } else {
            session.greeting()?;
            session.ehlo()?;
            if !session.extensions.contains("STARTTLS") {
                return Err(refused("smtp_starttls_not_offered"));
            }
            session.write_line("STARTTLS")?;
            if session.read_reply()?.code != 220 {
                return Err(refused("smtp_starttls_refused"));
            }
            // A byte the server sent before the handshake would be read as
            // if TLS had carried it.
            if let Wire::Clear(reader) = &session.wire
                && !reader.buffer().is_empty()
            {
                return Err(refused("smtp_starttls_data_before_handshake"));
            }
            session = session.upgrade(tls)?;
        }
        // What the server offered in the clear is not taken: once TLS is up,
        // it is asked again.
        session.ehlo()?;
        Ok(session)
    }

    /// The session moved onto TLS; the handshake runs on its first read or
    /// write.
    fn upgrade(self, tls: rustls::ClientConnection) -> Result<Self> {
        let Wire::Clear(reader) = self.wire else {
            return Err(refused("smtp_tls_twice"));
        };
        let stream = reader.into_inner();
        Ok(Self {
            wire: Wire::Tls(Box::new(BufReader::new(rustls::StreamOwned::new(
                tls, stream,
            )))),
            ..self
        })
    }

    fn greeting(&mut self) -> Result<()> {
        if self.read_reply()?.code == 220 {
            Ok(())
        } else {
            Err(refused("smtp_greeting_refused"))
        }
    }

    /// `EHLO`: what the server offers, from scratch, its message size limit
    /// with it.
    fn ehlo(&mut self) -> Result<()> {
        let line = format!("EHLO {}", self.client_name);
        self.write_line(&line)?;
        let reply = self.read_reply()?;
        if reply.code != 250 {
            return Err(refused("smtp_ehlo_refused"));
        }
        self.extensions.clear();
        self.mechanisms.clear();
        self.size_limit = None;
        for line in reply.lines.iter().skip(1) {
            let mut words = line.split_ascii_whitespace();
            let Some(keyword) = words.next() else {
                continue;
            };
            let keyword = keyword.to_ascii_uppercase();
            // `AUTH=PLAIN LOGIN` is the form older servers still write.
            let split = keyword
                .split_once('=')
                .map(|(keyword, first)| (keyword.to_owned(), first.to_owned()));
            let (keyword, first) = match split {
                Some((keyword, first)) => (keyword, Some(first)),
                None => (keyword, None),
            };
            match keyword.as_str() {
                "AUTH" => {
                    self.mechanisms.extend(first);
                    self.mechanisms.extend(words.map(str::to_ascii_uppercase));
                }
                "SIZE" => {
                    self.size_limit = size_limit(first.as_deref().or_else(|| words.next()));
                }
                _ => {}
            }
            self.extensions.insert(keyword);
        }
        Ok(())
    }

    /// The most octets one message may have, as the server's `EHLO` over TLS
    /// named it (fix list row 17645): its positive `SIZE`; `None` when it
    /// named none.
    pub(super) const fn advertised_size(&self) -> Option<u64> {
        self.size_limit
    }

    /// Authenticates as `username`: a token by `XOAUTH2`; a password by
    /// `PLAIN`, else `LOGIN`.
    ///
    /// # Errors
    ///
    /// No mechanism the credential can use offered, or the server refusing
    /// the credential.
    pub(super) fn authenticate(&mut self, username: &str, auth: &SmtpAuth<'_>) -> Result<()> {
        self.wire.set_deadline(Instant::now() + COMMAND_DEADLINE);
        let engine = base64::engine::general_purpose::STANDARD;
        let accepted = match auth {
            SmtpAuth::Token(token) => {
                if !self.mechanisms.contains("XOAUTH2") {
                    return Err(refused("smtp_xoauth2_not_offered"));
                }
                let payload =
                    engine.encode(format!("user={username}\x01auth=Bearer {token}\x01\x01"));
                self.write_line(&format!("AUTH XOAUTH2 {payload}"))?;
                let mut reply = self.read_reply()?;
                // A refused token is told as a challenge, which an empty
                // line answers before the final refusal.
                if reply.code == 334 {
                    self.write_line("")?;
                    reply = self.read_reply()?;
                }
                reply.code == 235
            }
            SmtpAuth::Password(password) if self.mechanisms.contains("PLAIN") => {
                let payload = engine.encode(format!("\0{username}\0{password}"));
                self.write_line(&format!("AUTH PLAIN {payload}"))?;
                self.read_reply()?.code == 235
            }
            SmtpAuth::Password(password) if self.mechanisms.contains("LOGIN") => {
                self.write_line("AUTH LOGIN")?;
                if self.read_reply()?.code != 334 {
                    return Err(refused("smtp_auth_refused"));
                }
                self.write_line(&engine.encode(username))?;
                if self.read_reply()?.code != 334 {
                    return Err(refused("smtp_auth_refused"));
                }
                self.write_line(&engine.encode(password))?;
                self.read_reply()?.code == 235
            }
            SmtpAuth::Password(_) => return Err(refused("smtp_password_auth_not_offered")),
        };
        if accepted {
            Ok(())
        } else {
            Err(refused("smtp_auth_refused"))
        }
    }

    /// Submits `message` from `from` to every address of `recipients`, one
    /// `RCPT` each, its data dot-stuffed. A message above this session's
    /// limit, the server's own `SIZE` or else `unadvertised_limit`, is
    /// `smtp_message_too_large` before `MAIL`; where the server offers
    /// `SIZE`, `MAIL FROM` declares the message's octets (fix list row
    /// 17645). Any refused envelope command is `smtp_envelope_refused`, as
    /// for a send to one. A message to several whose recipient is refused
    /// resets the transaction before `DATA`: no subset of its recipients is
    /// sent to.
    pub(super) fn submit(
        &mut self,
        from: &str,
        recipients: &[&str],
        message: &[u8],
        unadvertised_limit: u64,
    ) -> Submitted {
        if recipients.is_empty()
            || !envelope_address(from)
            || !recipients.iter().copied().all(envelope_address)
        {
            return Submitted::NotSent("smtp_envelope_address_unsupported");
        }
        // The message's own CRLF octets, as the frozen message is: not its
        // dot-stuffed data, nor the final `.<CRLF>` (RFC 1870 §3).
        let octets = message.len() as u64;
        if octets > self.size_limit.unwrap_or(unadvertised_limit) {
            return Submitted::NotSent("smtp_message_too_large");
        }
        let mail = if self.extensions.contains("SIZE") {
            format!("MAIL FROM:<{from}> SIZE={octets}")
        } else {
            format!("MAIL FROM:<{from}>")
        };
        match self.command(&mail) {
            Ok(250) => {}
            Ok(_) => return Submitted::NotSent("smtp_envelope_refused"),
            Err(_) => return Submitted::NotSent("smtp_connection_lost"),
        }
        for address in recipients {
            match self.command(&format!("RCPT TO:<{address}>")) {
                Ok(250 | 251) => {}
                Ok(_) => {
                    if recipients.len() > 1 {
                        self.reset();
                    }
                    return Submitted::NotSent("smtp_envelope_refused");
                }
                Err(_) => return Submitted::NotSent("smtp_connection_lost"),
            }
        }
        match self.command("DATA") {
            Ok(354) => {}
            Ok(_) => return Submitted::NotSent("smtp_envelope_refused"),
            Err(_) => return Submitted::NotSent("smtp_connection_lost"),
        }
        self.wire.set_deadline(Instant::now() + DATA_DEADLINE);
        // Until the final dot is written the server takes nothing.
        let data = dot_stuffed(message);
        if write_all(self.wire.writer(), &data).is_err() {
            return Submitted::NotSent("smtp_data_unsent");
        }
        if write_all(self.wire.writer(), b".\r\n").is_err() {
            return Submitted::Uncertain("smtp_data_end_unconfirmed");
        }
        match self.read_reply() {
            Ok(reply) if reply.code == 250 => Submitted::Accepted(reply.lines.join(" ")),
            Ok(_) => Submitted::NotSent("smtp_message_refused"),
            Err(_) => Submitted::Uncertain("smtp_no_final_reply"),
        }
    }

    /// Abandons the mail transaction before any data went (RFC 5321
    /// §4.1.1.5): the server keeps none of its recipients. An unanswered
    /// `RSET` changes nothing; the session ends next, with no data sent.
    fn reset(&mut self) {
        if self.command("RSET").is_err() {
            tracing::debug!("smtp session reset without its RSET answered");
        }
    }

    /// Ends the session; what the server answers changes nothing.
    pub(super) fn quit(mut self) {
        if self.command("QUIT").is_err() {
            tracing::debug!("smtp session ended without its QUIT answered");
        }
    }

    /// One command, its reply's code.
    fn command(&mut self, line: &str) -> Result<u16> {
        self.wire.set_deadline(Instant::now() + COMMAND_DEADLINE);
        self.write_line(line)?;
        Ok(self.read_reply()?.code)
    }

    fn write_line(&mut self, line: &str) -> Result<()> {
        let mut bytes = line.as_bytes().to_vec();
        bytes.extend_from_slice(b"\r\n");
        write_all(self.wire.writer(), &bytes).map_err(|_| refused("smtp_connection_lost"))
    }

    fn read_reply(&mut self) -> Result<Reply> {
        let mut lines = Vec::new();
        let mut code = None;
        loop {
            let mut line = Vec::new();
            let read = self
                .wire
                .reader()
                .take(MAX_LINE_BYTES as u64 + 1)
                .read_until(b'\n', &mut line)
                .map_err(|_| refused("smtp_connection_lost"))?;
            if read == 0 {
                return Err(refused("smtp_connection_closed"));
            }
            if line.len() > MAX_LINE_BYTES || !line.ends_with(b"\n") {
                return Err(refused("smtp_reply_too_long"));
            }
            let text = String::from_utf8_lossy(&line)
                .trim_end_matches(['\r', '\n'])
                .to_owned();
            if text.len() < 3 || !text.as_bytes()[..3].iter().all(u8::is_ascii_digit) {
                return Err(refused("smtp_reply_malformed"));
            }
            let this: u16 = text[..3]
                .parse()
                .map_err(|_| refused("smtp_reply_malformed"))?;
            if code.is_some_and(|code| code != this) {
                return Err(refused("smtp_reply_malformed"));
            }
            code = Some(this);
            let more = text.as_bytes().get(3) == Some(&b'-');
            lines.push(text.get(4..).unwrap_or_default().to_owned());
            if lines.len() > MAX_REPLY_LINES {
                return Err(refused("smtp_reply_too_long"));
            }
            if !more {
                break;
            }
        }
        let code = code.ok_or_else(|| refused("smtp_reply_malformed"))?;
        Ok(Reply { code, lines })
    }
}

/// The limit a `SIZE` keyword's `argument` names (RFC 1870 §4): a positive
/// decimal number of octets. No argument, one that is no plain decimal
/// number, or 0 names none.
fn size_limit(argument: Option<&str>) -> Option<u64> {
    argument
        .filter(|argument| {
            !argument.is_empty() && argument.bytes().all(|byte| byte.is_ascii_digit())
        })
        .and_then(|argument| argument.parse::<u64>().ok())
        .filter(|limit| *limit > 0)
}

fn write_all(writer: &mut dyn Write, bytes: &[u8]) -> std::io::Result<()> {
    writer.write_all(bytes)?;
    writer.flush()
}

/// Whether `address` can stand in an envelope as it is: ASCII, no space,
/// no angle bracket and no line break (SMTPUTF8 is not spoken).
fn envelope_address(address: &str) -> bool {
    !address.is_empty()
        && address.contains('@')
        && address
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'<' && byte != b'>')
}

/// `message` as data: every line that starts with a dot gets another
/// (RFC 5321 §4.5.2), and the data ends with a line break.
fn dot_stuffed(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() + 64);
    let mut line_start = true;
    for &byte in message {
        if line_start && byte == b'.' {
            out.push(b'.');
        }
        out.push(byte);
        line_start = byte == b'\n';
    }
    if !out.ends_with(b"\r\n") {
        out.extend_from_slice(b"\r\n");
    }
    out
}
