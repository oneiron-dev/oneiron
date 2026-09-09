//! Scoped-capability identity and channel rules: normalization, canonical segments, provenance minting, never-list validators.

use crate::connector_key::charter::parse_charter_verb;
use crate::entity_id::EntityId;
use crate::error::Result;

use super::invalid_body;

/// Canonicalizes an ordinary outbound connector/channel key (duplicate of the
/// private `outbound.rs::normalize_key` on the shared string space).
///
/// An already-canonical per-grant connector spelling is the one exception:
/// storage must retain an admitted server identity, so `'-'` and `'_'` remain
/// distinct. Preserving that exact string does not classify an ordinary
/// lookalike or confer authority; only typed [`ScopedCapabilityProvenance`] does.
#[must_use]
pub(crate) fn normalize_connector_key(value: &str) -> String {
    if canonical_scoped_capability_connector_parts(value).is_some() {
        return value.to_owned();
    }
    value.trim().to_ascii_lowercase().replace('-', "_")
}

/// The reserved compiled-entry tag for a capability-only `never key` rule
/// (ONE-1885).
///
/// An ordinary channel beginning with `"capability-key:"` is not a canonical
/// per-grant connector shape, so `normalize_connector_key` rewrites that
/// prefix's `'-'` to `'_'`. No ordinary entry can therefore begin with this
/// tag. The two rule modes stay STRUCTURALLY disjoint: nothing has to guess a
/// rule's mode from its shape.
pub(in crate::connector_key) const CAPABILITY_NEVER_ENTRY_TAG: &str = "capability-key:";

/// The reserved compiled-entry tag for the exact ordinary channel of a typed
/// scoped-MCP call (ONE-1885). The ordinary normalized entry is retained
/// alongside this private form.
///
/// Like the capability tag, this prefix is UNREACHABLE for an ordinary entry:
/// an ordinary channel is stored normalized, and normalization rewrites `'-'`
/// to `'_'` everywhere except an already-canonical `mcp:{server}:grant:{id}`
/// connector — which begins with `"mcp:"`, not with this tag. The three rule
/// modes therefore stay STRUCTURALLY disjoint and nothing has to guess a rule's
/// mode from its shape.
pub(in crate::connector_key) const SCOPED_CHANNEL_NEVER_ENTRY_TAG: &str = "scoped-channel:";

/// The ONE safe canonical scoped-server segment rule (ONE-1885).
///
/// Every scoped creation seam — the scoped grant constructor, the persisted
/// grant scope encode/decode/validate, the scoped-call admission path, the
/// per-grant capability-key producer, and the charter capability-key compiler —
/// asks exactly this function. Admission accepts only an already-canonical,
/// non-empty ASCII `[a-z0-9_.-]` segment. It never trims, folds case, or rewrites
/// `'-'` to `'_'`; those bytes name distinct server identities. A colon,
/// whitespace, wildcard/glob punctuation, non-ASCII byte, or any other spelling
/// outside that alphabet has no scoped capability identity.
#[must_use]
pub(crate) fn canonical_scoped_server_segment(server: &str) -> Option<String> {
    if server.is_empty()
        || !server.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || byte == b'_'
                || byte == b'.'
                || byte == b'-'
        })
    {
        return None;
    }
    Some(server.to_owned())
}

/// Parses only the canonical storage spelling of a per-grant connector. This
/// shape check preserves identity bytes in connector-key storage; it does not
/// confer capability authority on an ordinary lookalike.
fn canonical_scoped_capability_connector_parts(text: &str) -> Option<(&str, EntityId)> {
    let mut parts = text.split(':');
    let (Some("mcp"), Some(server), Some("grant"), Some(grant_hex), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return None;
    };
    canonical_scoped_server_segment(server)?;
    let grant_id = EntityId::from_hex(grant_hex).ok()?;
    (grant_id.to_hex() == grant_hex).then_some((server, grant_id))
}

/// The one typed per-grant scoped capability identity (ONE-1885).
///
/// This value IS the capability authority: it exists only where a live scoped
/// grant, its principal, its scoped call, a safe canonical server, and the real
/// engine-produced key identity have all been admitted. Nothing derives it from
/// connector text, an `mcp:*:grant:*` spelling, a tool/server string, or a
/// caller assertion — an ordinary connector that merely LOOKS like a capability
/// key never carries one, and a charter's capability rules are consulted only
/// against a value of this type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ScopedCapabilityProvenance {
    grant_id: EntityId,
    server: String,
    connector: String,
}

impl ScopedCapabilityProvenance {
    /// Mints the identity for one verified grant on one server. `None` when the
    /// server is not a safe canonical segment: an unsafe server has no
    /// capability key at all, so no key is minted from it.
    #[must_use]
    pub(crate) fn mint(server: &str, grant_id: &EntityId) -> Option<Self> {
        let server = canonical_scoped_server_segment(server)?;
        let connector = format!("mcp:{server}:grant:{}", grant_id.to_hex());
        Some(Self {
            grant_id: *grant_id,
            server,
            connector,
        })
    }

    /// Rebuilds the identity from persisted parts, fail-closed: the stored
    /// server must already be the canonical segment and the stored connector
    /// must be EXACTLY what [`Self::mint`] produces for that pair. A malformed
    /// or mismatched durable value therefore yields no capability at all.
    #[must_use]
    pub(crate) fn from_persisted_parts(
        grant_id: &EntityId,
        server: &str,
        connector: &str,
    ) -> Option<Self> {
        let minted = Self::mint(server, grant_id)?;
        (minted.server == server && minted.connector == connector).then_some(minted)
    }

    /// Reads one OWNER-AUTHORED capability-key spelling (the `never key`
    /// operand, and the stored entry that operand compiles into).
    ///
    /// This is charter grammar, not connector authority: it decides whether an
    /// owner named an identity the engine could actually produce, and its
    /// result is only ever compared against a minted identity. It is never
    /// applied to a connector string to manufacture a capability.
    #[must_use]
    pub(in crate::connector_key) fn parse_owner_capability_key(text: &str) -> Option<Self> {
        let (server, grant_id) = canonical_scoped_capability_connector_parts(text)?;
        let minted = Self::mint(server, &grant_id)?;
        (minted.connector == text).then_some(minted)
    }

    /// The exact engine-produced per-grant connector key.
    #[must_use]
    pub(crate) fn connector(&self) -> &str {
        &self.connector
    }

    /// The safe canonical scoped-server segment.
    #[must_use]
    pub(crate) fn server(&self) -> &str {
        &self.server
    }

    /// The grant this capability was minted for.
    #[must_use]
    pub(crate) const fn grant_id(&self) -> EntityId {
        self.grant_id
    }

    /// The ORDINARY channel this scoped dispatch also travels on
    /// (`mcp:{server}`), derived from the typed identity so gate admission and
    /// recovery read the same whole channel string with no text inference.
    #[must_use]
    pub(crate) fn ordinary_channel(&self) -> String {
        format!("mcp:{}", self.server)
    }
}

/// A compiled never-list entry MUST be one of the TWO disjoint canonical rules
/// the compiler emits, byte-for-byte (ONE-1885).
///
/// 1. A CAPABILITY-ONLY rule, `"capability-key:mcp:{server}:grant:{id}"`. It
///    names one exact real engine-produced per-grant capability identity and is
///    consulted only against a typed [`ScopedCapabilityProvenance`], never
///    against a connector string. It must parse back into an identity the
///    engine could actually mint (safe canonical server, real grant id), so a
///    partial wildcard (`"…:grant:*"`, `"mcp*:acme"`) or a truncated spelling
///    fails closed here instead of compiling into a rule nothing can honour.
/// 2. An ORDINARY `"{channel}:{verb}"` rule, whose channel is everything before
///    the LAST ':' and is matched as the WHOLE connector string. Colons inside
///    an ordinary channel are data (`"mcp:calendar:send"` prohibits `send` on
///    the whole `mcp:calendar` connector), so no ordinary connector is ever
///    truncated at its first colon or re-read as a capability.
///
/// The compiler preserves the ordinary channel operand byte-for-byte, including
/// `-`, `_`, and colons. Ordinary matching normalizes that rule channel against
/// the already-normalized connector key; typed scoped-MCP matching instead uses
/// an exact whole `mcp:{server}` comparison so `-` and `_` remain distinct.
/// Only blank or partial-wildcard channels are rejected so a corrupted charter
/// cannot silently fail open.
pub(in crate::connector_key) fn validate_never_list_entry(entry: &str) -> Result<()> {
    if let Some(capability_key) = entry.strip_prefix(CAPABILITY_NEVER_ENTRY_TAG) {
        if ScopedCapabilityProvenance::parse_owner_capability_key(capability_key)
            .is_none_or(|capability| capability.connector() != capability_key)
        {
            return Err(invalid_body("never_list capability key invalid"));
        }
        return Ok(());
    }
    if let Some(exact_channel_entry) = entry.strip_prefix(SCOPED_CHANNEL_NEVER_ENTRY_TAG) {
        let Some((channel_part, verb)) = exact_channel_entry.rsplit_once(':') else {
            return Err(invalid_body("never_list scoped channel invalid"));
        };
        if !is_canonical_scoped_channel(channel_part) {
            return Err(invalid_body("never_list scoped channel invalid"));
        }
        return validate_never_list_verb(verb);
    }
    // The verb is the LAST segment; everything before it is the whole ordinary
    // channel. A first-colon split would read `"mcp:calendar:send"` as the
    // channel `"mcp"` and deny nothing the author named.
    let Some((channel_part, verb)) = entry.rsplit_once(':') else {
        return Err(invalid_body("never_list entry must be channel:verb"));
    };
    if channel_part != "*" {
        // A `'*'` anywhere else on the channel side is a partial wildcard: the
        // normalized ordinary matcher would otherwise deny nothing (fail-open).
        if channel_part.trim().is_empty() || channel_part.contains('*') {
            return Err(invalid_body("never_list entry channel invalid"));
        }
        // Ordinary entries are stored in the existing normalized form. The
        // compiler preserves the source spelling only in a private exact-scoped
        // entry, when the channel is a typed canonical `mcp:{server}` value.
        if channel_part != normalize_connector_key(channel_part) {
            return Err(invalid_body("never_list entry channel must be canonical"));
        }
    }
    validate_never_list_verb(verb)
}

fn validate_never_list_verb(verb: &str) -> Result<()> {
    if verb == "*" {
        return Ok(());
    }
    // `parse_charter_verb` LOWERCASES before validating, so it accepts a
    // non-canonical spelling like `"SEND"` (yielding `"send"`). Enforcement
    // compares the stored verb by EXACT string against the lowercased effect
    // verb, so the stored part must ALREADY equal its canonical output.
    match parse_charter_verb(verb) {
        Ok(canonical) if canonical == verb => Ok(()),
        Ok(_) => Err(invalid_body("never_list entry verb must be canonical")),
        Err(_) => Err(invalid_body("never_list entry verb invalid")),
    }
}

/// The ONE rule for the exact ordinary channel of a typed scoped-MCP call:
/// literal `"mcp:"` followed by a safe canonical server segment (ONE-1885).
///
/// The charter compiler emits the private tagged entry for exactly this shape
/// and this validator accepts exactly this shape, so emit and accept cannot
/// drift apart. Everything else — a mixed-case or wildcard server, an extra
/// colon, a non-ASCII or unsafe byte, an ordinary lookalike — has no typed
/// scoped channel and therefore never becomes a tagged entry.
pub(in crate::connector_key) fn is_canonical_scoped_channel(channel: &str) -> bool {
    channel
        .strip_prefix("mcp:")
        .is_some_and(|server| canonical_scoped_server_segment(server).is_some())
}
