//! Identity-bearing address VALUES, and the canonical assignment key.
//!
//! CID-1 compared `channel` and `address_or_handle` as raw bytes and left
//! normalization to whichever adapter happened to write the row. Two spellings
//! of one mailbox were therefore two assignment keys with two occupants, and
//! whether a given key was canonical depended on which road produced it: the
//! constructor, the by-assignment query and the uniqueness scan each spelled
//! the key themselves.
//!
//! That is a REPRESENTATION fault, so it is fixed here rather than at the
//! adapters. [`ChannelKey`] and [`AssignmentAddress`] normalize once, in their
//! constructors; [`AssignmentKey`] is the one value every uniqueness road
//! compares, and it has exactly one way in — [`AssignmentKey::of`], which
//! normalizes — so a non-canonical key has no inhabitant to be spelled as.

use crate::error::{Error, Result};

/// Longest addr-spec the engine will hold (RFC 5321 path ceiling).
const MAX_MAILBOX_BYTES: usize = 254;
/// Longest local-part the engine will hold.
const MAX_LOCAL_PART_BYTES: usize = 64;
/// Longest domain the engine will hold.
const MAX_DOMAIN_BYTES: usize = 253;

/// The one email value in the engine, built from its parts.
///
/// Constructed only by parsing, and normalized on the way in: the local-part
/// and domain are ASCII-lowercased and the trailing root dot is dropped, so
/// `Member@Example.Test.` and `member@example.test` are the SAME value rather
/// than two assignment keys.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MailboxAddr {
    local: String,
    domain: String,
}

impl MailboxAddr {
    /// Parses one bare addr-spec (`local@domain`), normalizing both halves.
    ///
    /// This is the engine's whole email grammar. It is deliberately narrower
    /// than RFC 5322: an unquoted-only local-part charset binds downstream, so
    /// a local-part outside it fails closed here instead of becoming a bogus
    /// routing key later.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when the value is blank, over length, carries a
    /// wildcard, has no or more than one `@`, or has an unsupported charset.
    pub fn parse_addr_spec(raw: &str) -> Result<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(Error::InvalidConfig(
                "email address must be non-empty".to_owned(),
            ));
        }
        if raw.len() > MAX_MAILBOX_BYTES {
            return Err(Error::InvalidConfig(
                "email address exceeds maximum length".to_owned(),
            ));
        }
        if raw.contains('*') {
            return Err(Error::InvalidConfig(
                "email adapter rejects wildcard or catch-all addresses".to_owned(),
            ));
        }
        let (local, domain) = raw
            .split_once('@')
            .ok_or_else(|| Error::InvalidConfig("email address must contain @".to_owned()))?;
        if local.is_empty() || local.contains('@') || domain.contains('@') {
            return Err(Error::InvalidConfig(
                "email address must contain one non-empty local-part and domain".to_owned(),
            ));
        }
        if local.len() > MAX_LOCAL_PART_BYTES {
            return Err(Error::InvalidConfig(
                "email local-part exceeds maximum length".to_owned(),
            ));
        }
        if !local.bytes().all(|byte| {
            matches!(
                byte,
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'+'
            )
        }) {
            return Err(Error::InvalidConfig(
                "email local-part contains unsupported characters".to_owned(),
            ));
        }
        Ok(Self {
            local: local.to_ascii_lowercase(),
            domain: normalize_email_domain(domain)?,
        })
    }

    /// The normalized local-part.
    #[must_use]
    pub fn local(&self) -> &str {
        &self.local
    }

    /// The normalized domain.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// The normalized `local@domain` spelling.
    #[must_use]
    pub fn to_addr_spec(&self) -> String {
        format!("{}@{}", self.local, self.domain)
    }
}

impl std::fmt::Display for MailboxAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.local, self.domain)
    }
}

/// Normalizes and validates an email domain.
///
/// # Errors
///
/// [`Error::InvalidConfig`] for a blank, over-length, wildcard, dotted-edge or
/// non-hostname domain.
pub fn normalize_email_domain(domain: &str) -> Result<String> {
    let domain = domain.trim().trim_end_matches('.');
    if domain.is_empty() {
        return Err(Error::InvalidConfig(
            "email adapter domain must be non-empty".to_owned(),
        ));
    }
    if domain.len() > MAX_DOMAIN_BYTES {
        return Err(Error::InvalidConfig(
            "email adapter domain exceeds maximum length".to_owned(),
        ));
    }
    let domain = domain.to_ascii_lowercase();
    if domain.contains('@') || domain.contains('*') || domain.contains("..") {
        return Err(Error::InvalidConfig(
            "email adapter domain must be an exact non-wildcard domain".to_owned(),
        ));
    }
    if domain.starts_with('.') || domain.ends_with('.') {
        return Err(Error::InvalidConfig(
            "email adapter domain must not start or end with a dot".to_owned(),
        ));
    }
    if !domain
        .bytes()
        .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.'))
    {
        return Err(Error::InvalidConfig(
            "email adapter domain must be ascii hostname characters".to_owned(),
        ));
    }
    for label in domain.split('.') {
        if label.is_empty() || label.starts_with('-') || label.ends_with('-') {
            return Err(Error::InvalidConfig(
                "email adapter domain contains an invalid label".to_owned(),
            ));
        }
    }
    Ok(domain)
}

/// A normalized channel key.
///
/// Trimmed and ASCII-lowercased once, at construction. The engine's channel
/// keys are a closed lowercase vocabulary (`email`, `slack`, `own_app`, ...),
/// so folding case here cannot merge two channels that were ever distinct.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChannelKey(String);

impl ChannelKey {
    /// Normalizes a raw channel key. Bounds are checked by
    /// [`ChannelIdentity::validate`](super::ChannelIdentity::validate), so this
    /// stays infallible and the record keeps ONE validation door.
    #[must_use]
    pub fn normalize(raw: &str) -> Self {
        Self(raw.trim().to_ascii_lowercase())
    }

    /// Rebuilds a key from bytes ALREADY on disk, verbatim.
    ///
    /// Decode must never renormalize: the body bytes are pinned by the codec's
    /// byte-stability tests, and a decoder that rewrote them would make
    /// `encode(decode(bytes)) != bytes` for any row an older writer produced.
    #[must_use]
    pub fn from_stored(raw: String) -> Self {
        Self(raw)
    }

    /// The normalized key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ChannelKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A normalized `(channel)`-relative assignment address.
///
/// The engine knows how to normalize the shapes it routes; everything else is
/// carried opaquely rather than guessed at. Normalization happens once, in
/// these constructors, and both the record and the assignment key take the
/// result — which is what makes "two spellings of one mailbox" unrepresentable
/// rather than merely discouraged.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssignmentAddress(String);

impl AssignmentAddress {
    /// The assignment address of an email mailbox.
    #[must_use]
    pub fn email(mailbox: &MailboxAddr) -> Self {
        Self(mailbox.to_addr_spec())
    }

    /// A shape the engine does not model: trimmed, otherwise carried verbatim.
    #[must_use]
    pub fn opaque(raw: &str) -> Self {
        Self(raw.trim().to_owned())
    }

    /// Normalizes `raw` the way `channel` addresses normalize.
    ///
    /// Infallible on purpose. An `email` value the engine cannot project is
    /// carried opaquely rather than refused: `ChannelIdentity::requested` is a
    /// total constructor, and turning it fallible here would convert a
    /// normalization improvement into a behaviour regression on every channel
    /// whose grammar the engine does not own. Bounds and blankness are still
    /// enforced by the record's single `validate` door.
    #[must_use]
    pub fn normalize(channel: &str, raw: &str) -> Self {
        if ChannelKey::normalize(channel).as_str() == EMAIL_CHANNEL_KEY
            && let Ok(mailbox) = MailboxAddr::parse_addr_spec(raw)
        {
            return Self::email(&mailbox);
        }
        Self::opaque(raw)
    }

    /// Rebuilds an address from bytes ALREADY on disk, verbatim. See
    /// [`ChannelKey::from_stored`] for why decode never renormalizes.
    #[must_use]
    pub fn from_stored(raw: String) -> Self {
        Self(raw)
    }

    /// The normalized address.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The one channel whose address grammar the engine owns.
///
/// Spelled here rather than imported from
/// [`crate::channel_identity_provider::EMAIL_CHANNEL`] so the value layer does
/// not depend on the adapter layer; the two are pinned equal by test.
const EMAIL_CHANNEL_KEY: &str = "email";

impl std::fmt::Display for AssignmentAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// WHICH mailbox, as a canonical VALUE.
///
/// CID-1 spelled the assignment key as a `(&str, &str)` pair taken verbatim
/// off the stored row, so whether a given key was canonical depended on which
/// road produced it: `requested` and the query normalized nothing at all, and
/// a row decoded from bytes an older or third-party writer produced keyed on
/// whatever spelling was on disk.
///
/// This type deletes that class by construction. There is EXACTLY ONE way in —
/// [`AssignmentKey::of`] — and it normalizes. There is no `from_stored`, no
/// public field and no deserializer, so `AssignmentKey` HAS NO NON-CANONICAL
/// INHABITANT, and every uniqueness road compares this type.
///
/// Canonicalization is a property of the KEY, never a rewrite of the ROW: the
/// stored bytes and [`ChannelKey::from_stored`] are untouched, so the codec's
/// `encode(decode(bytes)) == bytes` pin still holds. A record's key is DERIVED
/// from its stored bytes on demand
/// ([`ChannelIdentity::assignment_key`](super::ChannelIdentity::assignment_key)).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssignmentKey {
    channel: ChannelKey,
    address: AssignmentAddress,
}

impl AssignmentKey {
    /// The ONE constructor. Total, infallible and idempotent.
    ///
    /// Idempotent because both halves are: [`ChannelKey::normalize`] is
    /// trim-then-lowercase, and [`AssignmentAddress::normalize`] either yields a
    /// parsed mailbox's canonical `local@domain` (which re-parses to itself) or
    /// a trimmed opaque value (which `parse_addr_spec` trims identically). So
    /// `of(k.channel(), k.address_or_handle()) == k` for every `k`, and a key
    /// round-tripped through its own accessors cannot drift.
    ///
    /// Infallible on purpose: bounds and blankness are still enforced by the
    /// record's single `validate` door, so this stays a total function on every
    /// road.
    #[must_use]
    pub fn of(channel: &str, address: &str) -> Self {
        let channel = ChannelKey::normalize(channel);
        let address = AssignmentAddress::normalize(channel.as_str(), address);
        Self { channel, address }
    }

    /// The canonical channel key.
    ///
    /// A READ projection only. It cannot be used to build a non-canonical key:
    /// the only way back in is `of`, which re-normalizes.
    #[must_use]
    pub fn channel(&self) -> &str {
        self.channel.as_str()
    }

    /// The canonical assignment address or handle. See [`Self::channel`].
    #[must_use]
    pub fn address_or_handle(&self) -> &str {
        self.address.as_str()
    }
}

impl std::fmt::Display for AssignmentKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.channel, self.address)
    }
}
