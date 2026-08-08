//! `EntityId` + world-id newtypes + id parsing/hex.

use crate::registry::short_id_prefix;
use uuid::Uuid;

pub(crate) const ENTITY_ID_LEN: usize = 16;

/// A time-ordered entity identifier backed by UUIDv7 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntityId([u8; ENTITY_ID_LEN]);

impl EntityId {
    /// Creates a new identifier using the current UUIDv7 timestamp.
    #[must_use]
    pub fn now() -> Self {
        Self(Uuid::now_v7().into_bytes())
    }

    /// Creates an identifier from raw bytes, rejecting reserved sentinel IDs.
    ///
    /// The all-zero, all-`0xFF`, and `[entity_type, 0xFF×15]` patterns are
    /// reserved at the public `EntityId` layer. The latter were the pre-ABI-v3
    /// short-id counter sentinel rows (counters now live in `vault_meta`, see
    /// `store::SHORT_ID_COUNTER_KEY_PREFIX`); the reservation is kept so the
    /// legacy patterns can never be hydrated as live entity IDs.
    pub fn from_bytes(bytes: [u8; 16]) -> crate::error::Result<Self> {
        if is_reserved_entity_id_bytes(&bytes) {
            return Err(crate::error::Error::InvalidKey);
        }
        Ok(Self(bytes))
    }

    /// Creates an identifier from raw bytes without validating sentinel patterns.
    ///
    /// Reserved for internal construction where the caller already knows the
    /// bytes are either valid entity IDs or intentional sentinel values.
    #[cfg(test)]
    pub(crate) fn from_bytes_unchecked(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the raw identifier bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Returns the lowercase hex-encoded string (32 chars).
    pub fn to_hex(&self) -> String {
        bytes_to_hex_lower(&self.0)
    }

    /// Parses a 32-char hex string (case-insensitive) into an EntityId.
    pub fn from_hex(s: &str) -> crate::error::Result<Self> {
        if s.len() != 32 {
            return Err(crate::error::Error::InvalidKey);
        }
        let mut bytes = [0u8; 16];
        let (chunks, rem) = s.as_bytes().as_chunks::<2>();
        debug_assert!(rem.is_empty());
        for (i, &[hi_byte, lo_byte]) in chunks.iter().enumerate() {
            let hi = hex_nibble(hi_byte).ok_or(crate::error::Error::InvalidKey)?;
            let lo = hex_nibble(lo_byte).ok_or(crate::error::Error::InvalidKey)?;
            bytes[i] = (hi << 4) | lo;
        }
        Self::from_bytes(bytes)
    }
}

/// First leading byte reserved for received foreign world ids.
///
/// Locally authored WORLD ids remain outside this range. Keeping the foreign
/// range distinct lets outbound federation selectors require [`LocalWorldId`]
/// while the inbound/re-federation path can fail closed when raw wire bytes
/// name a received foreign world.
pub const FOREIGN_WORLD_ID_RANGE_START_BYTE: u8 = 0xF0;

/// Returns whether `id` is in the received-foreign WORLD id range.
#[must_use]
pub fn is_foreign_world_id_range(id: EntityId) -> bool {
    id.0[0] >= FOREIGN_WORLD_ID_RANGE_START_BYTE
}

/// WORLD id proven eligible for local outbound sharing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LocalWorldId(EntityId);

impl LocalWorldId {
    /// Creates a local WORLD id wrapper, rejecting the foreign range.
    pub fn from_entity_id(id: EntityId) -> crate::error::Result<Self> {
        if is_foreign_world_id_range(id) {
            return Err(crate::error::Error::InvalidKey);
        }
        Ok(Self(id))
    }

    /// Returns the raw entity id.
    #[must_use]
    pub const fn entity_id(self) -> EntityId {
        self.0
    }
}

impl TryFrom<EntityId> for LocalWorldId {
    type Error = crate::error::Error;

    fn try_from(value: EntityId) -> crate::error::Result<Self> {
        Self::from_entity_id(value)
    }
}

/// WORLD id received from a foreign vault.
///
/// This type intentionally does not convert into [`LocalWorldId`], which keeps
/// A->B->C re-share out of outbound selector construction.
///
/// ```compile_fail
/// use oneiron::sync::SyncSelectorWorld;
/// use oneiron::entity_id::{EntityId, ForeignWorldId};
///
/// let foreign = ForeignWorldId::from_entity_id(
///     EntityId::from_bytes([0xF1; 16]).unwrap(),
/// )
/// .unwrap();
/// let _cannot_reshare = SyncSelectorWorld::World(foreign);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ForeignWorldId(EntityId);

impl ForeignWorldId {
    /// Creates a foreign WORLD id wrapper, accepting only the foreign range.
    pub fn from_entity_id(id: EntityId) -> crate::error::Result<Self> {
        if !is_foreign_world_id_range(id) {
            return Err(crate::error::Error::InvalidKey);
        }
        Ok(Self(id))
    }

    /// Returns the raw entity id.
    #[must_use]
    pub const fn entity_id(self) -> EntityId {
        self.0
    }
}

impl TryFrom<EntityId> for ForeignWorldId {
    type Error = crate::error::Error;

    fn try_from(value: EntityId) -> crate::error::Result<Self> {
        Self::from_entity_id(value)
    }
}

/// Parses a `&[u8]` slice into an `EntityId`, returning
/// `Error::CorruptedIndex(context)` if the length is wrong, or
/// `Error::InvalidKey` if the bytes match a reserved sentinel pattern
/// (legacy short_id counter rows and similar internal patterns that must not
/// be hydrated as live entities). Used by index readers (HNSW neighbor keys,
/// vector keys, `short_ids_reverse` keys, `short_ids` forward values) where a
/// malformed key is on-disk corruption.
///
/// **Note:** callers needing contextual `CorruptedIndex` for diagnostics
/// should `.map_err` the `InvalidKey` variant. The HNSW read path does
/// this; `maintain.rs::recompute_short_id_hashes` handles both variants.
pub(crate) fn parse_entity_id(
    bytes: &[u8],
    context: &'static str,
) -> crate::error::Result<EntityId> {
    if bytes.len() != ENTITY_ID_LEN {
        return Err(crate::error::Error::CorruptedIndex(context));
    }
    let mut arr = [0u8; ENTITY_ID_LEN];
    arr.copy_from_slice(bytes);
    if is_reserved_entity_id_bytes(&arr) {
        return Err(crate::error::Error::InvalidKey);
    }
    Ok(EntityId(arr))
}

fn is_reserved_entity_id_bytes(bytes: &[u8; ENTITY_ID_LEN]) -> bool {
    if *bytes == [0x00; ENTITY_ID_LEN] || *bytes == [0xFF; ENTITY_ID_LEN] {
        return true;
    }

    bytes[1..].iter().all(|&b| b == 0xFF) && short_id_prefix(bytes[0]).is_ok()
}

/// A presentation id split into its two syntactic parts (ONE-1930).
///
/// Both fields borrow the input, and `digits` keeps its spelling VERBATIM —
/// leading zeros are part of the identity, so `mx01` is never normalized to
/// `mx1`. Round-tripping is therefore concatenation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedPresentationId<'a> {
    /// The maximal leading run of lowercase ASCII letters.
    pub prefix: &'a str,
    /// The decimal counter, at least one digit, exactly as written.
    pub digits: &'a str,
}

/// Shortest prefix the durable presentation grammar admits.
///
/// TWO, and that is a live-collision fact rather than a style choice.
/// `session_overlay.rs` mints room-scoped aliases as `s<decimal digits>`, and
/// its namespace-separation contract rests on those NOT parsing as durable
/// short ids: a session alias leaked to a base door must get a clean parse
/// rejection instead of a silent hit through the composed overlay ∪ base read.
/// Admitting one-letter prefixes here would put `s1` in both namespaces at
/// once.
///
/// The one-letter tier (`c/p/s/w`) therefore cannot be unlocked by relaxing
/// this alone — it needs the session sigil moved out of the way first, and it
/// needs canon (`oneiron-docs` `site/src/data/oneiron-contracts.ts`) to declare
/// those prefixes. Both are outside this ticket; see the ONE-1930 worklog.
pub const MIN_PRESENTATION_PREFIX_LEN: usize = 2;

/// Parses a presentation id — `<lowercase letters><decimal digits>` — into its
/// parts. SYNTAX ONLY.
///
/// This layer has NO registry knowledge on purpose. It rejects malformed
/// SHAPES: a too-short prefix, missing digits, uppercase, punctuation,
/// whitespace, non-ASCII, or anything trailing the digit run. It does NOT
/// reject unknown prefixes — `zz9` is a perfectly well-formed presentation id
/// that no registry declares, and saying so is the RESOLUTION layer's job
/// ([`crate::registry::id_namespace_for_prefix`] plus the alias table). Keeping
/// the two apart is what lets an exact alias row admit `mx01` while `mx` stays
/// absent from every registry.
///
/// The prefix run is MAXIMAL, which is what makes the grammar unambiguous:
/// `sm12` is prefix `sm` + `12`, never `s` + `m12`. Length ABOVE
/// [`MIN_PRESENTATION_PREFIX_LEN`] is unconstrained — that a live prefix
/// happens to be two letters is a registry fact, not a grammar fact, and
/// pinning it here is what forced every boundary parser to grow its own copy.
pub fn parse_presentation_id(raw: &str) -> crate::error::Result<ParsedPresentationId<'_>> {
    let split = raw
        .bytes()
        .position(|byte| !byte.is_ascii_lowercase())
        .ok_or(crate::error::Error::InvalidKey)?;
    let (prefix, digits) = raw.split_at(split);
    if prefix.len() < MIN_PRESENTATION_PREFIX_LEN
        || digits.is_empty()
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(crate::error::Error::InvalidKey);
    }
    Ok(ParsedPresentationId { prefix, digits })
}

/// Splits a public short REF — `"<presentation_id>:<hash-hex>"` — into a
/// syntactically valid presentation id and its one-byte content hash.
///
/// The single door every engine boundary parses short refs through, so the
/// grammar cannot drift between the facade, the HTTP API, and MCP. Like
/// [`parse_presentation_id`], this is syntax only: a well-formed ref whose
/// prefix nothing declares still parses here and fails at resolution.
pub fn parse_short_ref_syntax(reference: &str) -> crate::error::Result<(&str, u8)> {
    let (short_id, hash) = reference
        .split_once(':')
        .ok_or(crate::error::Error::InvalidKey)?;
    parse_presentation_id(short_id)?;
    if hash.len() != 2 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(crate::error::Error::InvalidKey);
    }
    let content_hash =
        u8::from_str_radix(hash, 16).map_err(|_| crate::error::Error::InvalidKey)?;
    Ok((short_id, content_hash))
}

/// Lowercase hex-encodes an arbitrary byte slice. Shared with the
/// analyzer manifest hasher so every hex rendering in the crate goes
/// through one implementation.
pub(crate) fn bytes_to_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Converts an ASCII hex character to its nibble value.
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EntityId, FOREIGN_WORLD_ID_RANGE_START_BYTE, ForeignWorldId, LocalWorldId,
        parse_presentation_id, parse_short_ref_syntax,
    };

    #[test]
    fn presentation_grammar_accepts_every_live_prefix_shape() {
        for (raw, prefix, digits) in [
            ("sm3", "sm", "3"),
            ("mc4", "mc", "4"),
            ("vt5", "vt", "5"),
            ("cl17", "cl", "17"),
            // Undeclared prefixes are SYNTACTICALLY fine; resolution rejects
            // them. `mx01` keeps its leading zero — the digits are an identity,
            // not a number.
            ("zz9", "zz", "9"),
            ("mx01", "mx", "01"),
            // Length above the minimum is a registry question, not a grammar one.
            ("abcd12", "abcd", "12"),
        ] {
            let parsed = parse_presentation_id(raw).unwrap_or_else(|_| panic!("{raw} must parse"));
            assert_eq!(parsed.prefix, prefix, "{raw} prefix");
            assert_eq!(parsed.digits, digits, "{raw} digits");
        }
    }

    /// The prefix run is MAXIMAL, so a two-letter prefix can never be read as a
    /// one-letter prefix followed by a letter-led counter.
    #[test]
    fn presentation_grammar_is_unambiguous() {
        let parsed = parse_presentation_id("sm12").expect("sm12 parses");
        assert_eq!(parsed.prefix, "sm");
        assert_eq!(parsed.digits, "12");
    }

    #[test]
    fn presentation_grammar_rejects_malformed_shapes() {
        for raw in [
            "",      // empty
            "cl",    // missing digits
            "17",    // missing prefix
            "CL17",  // uppercase
            "Cl17",  // uppercase
            "cl-17", // punctuation
            "cl 17", // whitespace
            "cl17a", // trailing letters after the digit run
            "cl1.7", // punctuation inside the counter
            "cl١",   // non-ASCII digits
        ] {
            assert!(
                parse_presentation_id(raw).is_err(),
                "{raw:?} must not parse"
            );
        }
    }

    /// ONE-1930 / DEV-3 regression pin. `session_overlay.rs` mints room aliases
    /// as `s<digits>` and its namespace-separation contract requires those to
    /// fail the durable grammar — otherwise a leaked session alias resolves
    /// through the composed overlay ∪ base read instead of being rejected.
    /// Relaxing `MIN_PRESENTATION_PREFIX_LEN` without moving that sigil first
    /// breaks the contract, so this test is the tripwire on it.
    #[test]
    fn presentation_grammar_excludes_the_session_alias_namespace() {
        for raw in ["s1", "s2", "s10", "s99"] {
            assert!(
                parse_presentation_id(raw).is_err(),
                "session alias {raw} must not parse as a durable presentation id"
            );
        }
    }

    #[test]
    fn short_ref_syntax_splits_id_and_hash() {
        let (short_id, hash) = parse_short_ref_syntax("cl17:a3").expect("valid short ref");
        assert_eq!(short_id, "cl17");
        assert_eq!(hash, 0xa3);
    }

    #[test]
    fn short_ref_syntax_rejects_malformed_refs() {
        for raw in [
            "cl17",     // no hash
            "cl17:",    // empty hash
            "cl17:a",   // one hex digit
            "cl17:abc", // three hex digits
            "cl17:zz",  // non-hex
            "s1:a3",    // session alias namespace
            ":a3",      // no short id
        ] {
            assert!(
                parse_short_ref_syntax(raw).is_err(),
                "{raw:?} must not parse as a short ref"
            );
        }
    }

    #[test]
    fn entity_id_hex_round_trip() {
        let id = EntityId::now();
        let hex = id.to_hex();
        assert_eq!(hex.len(), 32);
        let recovered = EntityId::from_hex(&hex).unwrap();
        assert_eq!(id, recovered);
    }

    #[test]
    fn entity_id_from_hex_rejects_invalid() {
        assert!(EntityId::from_hex("too_short").is_err());
        assert!(EntityId::from_hex("gggggggggggggggggggggggggggggggg").is_err());
    }

    #[test]
    fn local_world_id_rejects_foreign_range() {
        let local = EntityId::from_bytes([0xEF; 16]).unwrap();
        let foreign = EntityId::from_bytes([FOREIGN_WORLD_ID_RANGE_START_BYTE; 16]).unwrap();

        assert_eq!(
            LocalWorldId::from_entity_id(local).unwrap().entity_id(),
            local
        );
        assert!(LocalWorldId::from_entity_id(foreign).is_err());
    }

    #[test]
    fn foreign_world_id_accepts_only_foreign_range() {
        let local = EntityId::from_bytes([0xEF; 16]).unwrap();
        let foreign = EntityId::from_bytes([0xF1; 16]).unwrap();

        assert_eq!(
            ForeignWorldId::from_entity_id(foreign).unwrap().entity_id(),
            foreign
        );
        assert!(ForeignWorldId::from_entity_id(local).is_err());
    }
}
