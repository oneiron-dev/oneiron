//! The evidence the owner's booking email checks read (FIX 7862, 8138).
//!
//! An address's shape is checked on every request. Its domain's mail
//! exchanger and its place on the disposable-domain list are resolved only
//! when a rule in scope enables those checks, and only for an address that
//! is shaped like one. A lookup that fails, times out or gets no usable
//! answer is no signal (`None`), never a negative one; a negative reading
//! reaches the engine's correction prompt, never a rejection.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use oneiron::booking::anti_abuse::{
    BookingAntiAbuseRule, BookingRequestFacts, applicable_booking_anti_abuse_rules,
};
use rand_core::{OsRng, RngCore as _};
use tokio::net::UdpSocket;

use super::helpers::booking_error;
use crate::error::ApiError;
use crate::server::SyncServer;

/// How long one DNS question waits for its answer.
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
/// The system resolver configuration the nameserver is read from.
const RESOLVER_CONFIG_PATH: &str = "/etc/resolv.conf";
const DNS_PORT: u16 = 53;
const DNS_HEADER_BYTES: usize = 12;
/// The largest answer read from one UDP datagram.
const DNS_DATAGRAM_BYTES: usize = 4_096;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_MX: u16 = 15;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_CLASS_IN: u16 = 1;
const DNS_FLAG_RESPONSE: u16 = 0x8000;
const DNS_FLAG_TRUNCATED: u16 = 0x0200;
const DNS_FLAG_RECURSION_AVAILABLE: u16 = 0x0080;
const DNS_RCODE_MASK: u16 = 0x000f;
const DNS_RCODE_NO_ERROR: u16 = 0;
const DNS_RCODE_NAME_ERROR: u16 = 3;

/// Well-known disposable-mail providers. A domain matches itself or any of
/// its subdomains.
const DISPOSABLE_EMAIL_DOMAINS: &[&str] = &[
    "10minutemail.com",
    "discard.email",
    "dispostable.com",
    "emailondeck.com",
    "fakeinbox.com",
    "getnada.com",
    "grr.la",
    "guerrillamail.biz",
    "guerrillamail.com",
    "guerrillamail.de",
    "guerrillamail.net",
    "guerrillamail.org",
    "guerrillamailblock.com",
    "mailcatch.com",
    "maildrop.cc",
    "mailinator.com",
    "mailnesia.com",
    "mintemail.com",
    "mohmal.com",
    "sharklasers.com",
    "spamgourmet.com",
    "temp-mail.org",
    "tempmail.com",
    "tempmailo.com",
    "tempr.email",
    "throwawaymail.com",
    "trashmail.com",
    "yopmail.com",
    "yopmail.net",
];

/// A deliberately structural check: one `@`, a non-empty local part, and a
/// dotted domain whose every label is non-empty. Deeper evidence is
/// [`EmailDomainEvidence`].
pub(super) fn is_syntactically_valid_email(email: &str) -> bool {
    let email = email.trim();
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.contains('@')
        && !email.contains(char::is_whitespace)
        && domain.split('.').count() >= 2
        && domain.split('.').all(|label| !label.is_empty())
}

/// What the network and the disposable-domain list say about one address's
/// domain: the two readings `EmailValidationEvidence` carries beside syntax.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct EmailDomainEvidence {
    mx_present: Option<bool>,
    disposable_domain: bool,
}

impl EmailDomainEvidence {
    /// Writes these readings into the facts' email evidence, if it has any.
    pub(super) fn apply(self, facts: &mut BookingRequestFacts) {
        if let Some(email) = &mut facts.email {
            email.mx_present = self.mx_present;
            email.disposable_domain = self.disposable_domain;
        }
    }
}

/// Resolves the domain evidence the rules in scope for `facts` enable.
///
/// A malformed address resolves nothing: the syntax check alone prompts its
/// correction, and its domain readings stay unknown.
///
/// # Errors
///
/// [`ApiError`] when the owner's rule rows cannot be read.
pub(super) async fn email_domain_evidence(
    server: &SyncServer,
    facts: &BookingRequestFacts,
    booker_email: &str,
) -> Result<EmailDomainEvidence, ApiError> {
    if !facts.email.as_ref().is_some_and(|email| email.syntax_valid) {
        return Ok(EmailDomainEvidence::default());
    }
    let rows =
        applicable_booking_anti_abuse_rules(&server.vault, &facts.page_ref, &facts.event_type)
            .map_err(booking_error)?;
    let (mut check_mx, mut check_disposable) = (false, false);
    for row in &rows {
        if let BookingAntiAbuseRule::EmailPromptToCorrect {
            check_mx: mx,
            check_disposable_domain: disposable,
            ..
        } = &row.rule
        {
            check_mx |= mx;
            check_disposable |= disposable;
        }
    }
    let Some((_, domain)) = booker_email.trim().split_once('@') else {
        return Ok(EmailDomainEvidence::default());
    };
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    Ok(EmailDomainEvidence {
        mx_present: if check_mx {
            accepts_mail(&domain).await
        } else {
            None
        },
        disposable_domain: check_disposable && is_disposable_domain(&domain),
    })
}

fn is_disposable_domain(domain: &str) -> bool {
    DISPOSABLE_EMAIL_DOMAINS.iter().any(|listed| {
        domain == *listed
            || domain
                .strip_suffix(listed)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

/// Whether `domain` accepts mail (RFC 5321 §5.1): an MX record other than
/// the null MX of RFC 7505, or, with no MX at all, an address record. `None`
/// when the resolver gives no usable answer.
async fn accepts_mail(domain: &str) -> Option<bool> {
    let nameserver = system_nameserver().await?;
    match dns_query(nameserver, domain, DNS_TYPE_MX).await? {
        DnsAnswer::NoSuchDomain => return Some(false),
        DnsAnswer::Records(records) if !records.is_empty() => {
            return Some(records.iter().any(|rdata| !is_null_mx(rdata)));
        }
        DnsAnswer::Records(_) => {}
    }
    for qtype in [DNS_TYPE_A, DNS_TYPE_AAAA] {
        match dns_query(nameserver, domain, qtype).await? {
            DnsAnswer::NoSuchDomain => return Some(false),
            DnsAnswer::Records(records) if !records.is_empty() => return Some(true),
            DnsAnswer::Records(_) => {}
        }
    }
    Some(false)
}

/// An MX record whose exchange is the root name: "this domain accepts no mail".
fn is_null_mx(rdata: &[u8]) -> bool {
    rdata.len() == 3 && rdata[2] == 0
}

/// The first `nameserver` line of the system resolver configuration.
async fn system_nameserver() -> Option<SocketAddr> {
    let config = tokio::fs::read_to_string(RESOLVER_CONFIG_PATH).await.ok()?;
    config.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        if fields.next() != Some("nameserver") {
            return None;
        }
        let address: IpAddr = fields.next()?.parse().ok()?;
        Some(SocketAddr::new(address, DNS_PORT))
    })
}

/// One recursive resolver's answer to one question.
enum DnsAnswer {
    /// The name does not exist (NXDOMAIN).
    NoSuchDomain,
    /// The record data of every answer of the asked type; empty when the name
    /// exists and has none.
    Records(Vec<Vec<u8>>),
}

/// Asks `nameserver` one question over UDP. `None` on any failure, a
/// timeout, a truncated answer, or a resolver that does not recurse.
async fn dns_query(nameserver: SocketAddr, domain: &str, qtype: u16) -> Option<DnsAnswer> {
    let query_id = OsRng.next_u32().to_be_bytes();
    let query_id = [query_id[0], query_id[1]];
    let packet = dns_question(query_id, domain, qtype)?;
    let local: SocketAddr = match nameserver.ip() {
        IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        IpAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(local).await.ok()?;
    socket.connect(nameserver).await.ok()?;
    socket.send(&packet).await.ok()?;
    let mut buffer = vec![0_u8; DNS_DATAGRAM_BYTES];
    tokio::time::timeout(DNS_QUERY_TIMEOUT, async {
        loop {
            let Ok(len) = socket.recv(&mut buffer).await else {
                return None;
            };
            let answer = &buffer[..len];
            // A datagram that is not the answer to this question is skipped.
            if answer.len() < DNS_HEADER_BYTES
                || answer[..2] != query_id
                || u16::from_be_bytes([answer[2], answer[3]]) & DNS_FLAG_RESPONSE == 0
            {
                continue;
            }
            return parse_dns_answer(answer, qtype);
        }
    })
    .await
    .ok()?
}

/// One recursion-desired question for `domain`. `None` for a name that is not
/// a valid ASCII host name.
fn dns_question(query_id: [u8; 2], domain: &str, qtype: u16) -> Option<Vec<u8>> {
    if !domain.is_ascii() || domain.len() > 253 {
        return None;
    }
    let mut packet = Vec::with_capacity(DNS_HEADER_BYTES + domain.len() + 6);
    packet.extend_from_slice(&query_id);
    // Recursion desired; one question, no answer, authority or extra records.
    packet.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in domain.split('.') {
        let len = u8::try_from(label.len())
            .ok()
            .filter(|len| (1..=63).contains(len))?;
        packet.push(len);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    Some(packet)
}

fn parse_dns_answer(packet: &[u8], qtype: u16) -> Option<DnsAnswer> {
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if flags & DNS_FLAG_TRUNCATED != 0 || flags & DNS_FLAG_RECURSION_AVAILABLE == 0 {
        return None;
    }
    match flags & DNS_RCODE_MASK {
        DNS_RCODE_NO_ERROR => {}
        DNS_RCODE_NAME_ERROR => return Some(DnsAnswer::NoSuchDomain),
        _ => return None,
    }
    let questions = u16::from_be_bytes([packet[4], packet[5]]);
    let answers = u16::from_be_bytes([packet[6], packet[7]]);
    let mut at = DNS_HEADER_BYTES;
    for _ in 0..questions {
        at = skip_dns_name(packet, at)?.checked_add(4)?;
    }
    let mut records = Vec::new();
    for _ in 0..answers {
        at = skip_dns_name(packet, at)?;
        let header = packet.get(at..at.checked_add(10)?)?;
        let rtype = u16::from_be_bytes([header[0], header[1]]);
        let rdlength = usize::from(u16::from_be_bytes([header[8], header[9]]));
        at += 10;
        let rdata = packet.get(at..at.checked_add(rdlength)?)?;
        at += rdlength;
        if rtype == qtype {
            records.push(rdata.to_vec());
        }
    }
    Some(DnsAnswer::Records(records))
}

/// The offset just past one encoded name at `at`: its labels up to the root,
/// or up to a compression pointer.
fn skip_dns_name(packet: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *packet.get(at)?;
        match len & 0xc0 {
            0x00 if len == 0 => return Some(at + 1),
            0x00 => at += 1 + usize::from(len),
            0xc0 => {
                packet.get(at + 1)?;
                return Some(at + 2);
            }
            _ => return None,
        }
    }
}
