//! `EntityId` + world-id newtypes + id parsing/hex.

use crate::registry::short_id_prefix;
use rand_core::RngCore;

pub(crate) const ENTITY_ID_LEN: usize = 16;

// Entity ids cross vault and worker boundaries. A single mint sequence is required
// by newest-id projections; thread-local counters invert causal cross-thread order.
static LAST_ULID: std::sync::Mutex<u128> = std::sync::Mutex::new(0);

/// An opaque time-ordered ULID. Existing 16-byte UUIDv7 rows remain valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, schemars::JsonSchema)]
pub struct EntityId(#[schemars(with = "String")] [u8; ENTITY_ID_LEN]);

impl EntityId {
    /// Creates an opaque ULID: 48-bit Unix milliseconds and 80 random bits.
    #[must_use]
    pub fn now() -> Self {
        let millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("entity ids require a clock after the Unix epoch")
            .as_millis() as u64;
        let mut bytes = [0; 16];
        bytes[..6].copy_from_slice(&millis.to_be_bytes()[2..]);
        rand_core::OsRng.fill_bytes(&mut bytes[6..]);
        let random = u128::from_be_bytes(bytes);
        let mut prior = LAST_ULID
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let next = if (random >> 80) <= (*prior >> 80) {
            prior.checked_add(1).expect("ULID exhausted")
        } else {
            random
        };
        *prior = next;
        Self(next.to_be_bytes())
    }

    /// Canonical 26-character Crockford representation. Identity is not encoded
    /// in this string; names and aliases remain lookup hints in stored rows.
    pub fn to_ulid(&self) -> String {
        const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
        let mut number = u128::from_be_bytes(self.0);
        let mut text = [b'0'; 26];
        for character in text.iter_mut().rev() {
            *character = ALPHABET[(number & 31) as usize];
            number >>= 5;
        }
        String::from_utf8(text.to_vec()).expect("Crockford alphabet is ASCII")
    }

    /// Parses Crockford ULID text, rejecting overflow and reserved ids.
    pub fn from_ulid(text: &str) -> crate::error::Result<Self> {
        if text.len() != 26 {
            return Err(crate::error::Error::InvalidKey);
        }
        let mut number = 0u128;
        for byte in text.bytes() {
            let digit = match byte.to_ascii_uppercase() {
                b'I' | b'L' => 1,
                b'O' => 0,
                byte => b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"
                    .iter()
                    .position(|&c| c == byte)
                    .ok_or(crate::error::Error::InvalidKey)? as u128,
            };
            number = number
                .checked_mul(32)
                .and_then(|n| n.checked_add(digit))
                .ok_or(crate::error::Error::InvalidKey)?;
        }
        Self::from_bytes(number.to_be_bytes())
    }

    /// Derives the deterministic id of `parts` under `domain`: the one rule for
    /// every id an input fixes rather than a clock (minted ids are opaque ULIDs,
    /// see [`EntityId::now`]).
    ///
    /// BLAKE3 in derive-key mode with `domain` as the context string, each part
    /// prefixed by its u64 little-endian length, truncated to the first 16 bytes
    /// and stamped with the RFC 9562 version-8 (custom) and variant bits. The
    /// domains live in [`derived_domains`]. A non-UTF-8 or empty domain is
    /// refused with [`Error::InvariantViolation`](crate::error::Error::InvariantViolation);
    /// a result in the reserved sentinel range is refused with
    /// [`Error::InvalidKey`](crate::error::Error::InvalidKey), never perturbed.
    pub(crate) fn derive(domain: &[u8], parts: &[&[u8]]) -> crate::error::Result<Self> {
        derive_with(domain, parts, is_reserved_entity_id_bytes)
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

// Entity references have one wire spelling. Deserialization always re-enters
// the sentinel-rejecting public constructor.
impl serde::Serialize for EntityId {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}
impl<'de> serde::Deserialize<'de> for EntityId {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let value = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::from_hex(&value).map_err(serde::de::Error::custom)
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

/// [`EntityId::derive`]'s body, with the reserved-range predicate as a seam.
///
/// The version and variant stamp keeps a derived id out of every reserved pattern
/// today; the check still runs so a widened reservation fails closed instead of
/// handing out a sentinel.
fn derive_with(
    domain: &[u8],
    parts: &[&[u8]],
    reserved: impl Fn(&[u8; ENTITY_ID_LEN]) -> bool,
) -> crate::error::Result<EntityId> {
    let context = std::str::from_utf8(domain)
        .ok()
        .filter(|context| !context.is_empty())
        .ok_or(crate::error::Error::InvariantViolation(
            "a derived-id domain must be non-empty UTF-8",
        ))?;
    let mut hasher = blake3::Hasher::new_derive_key(context);
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    let mut bytes = [0; ENTITY_ID_LEN];
    bytes.copy_from_slice(&hasher.finalize().as_bytes()[..ENTITY_ID_LEN]);
    bytes[6] = (bytes[6] & 0x0F) | 0x80;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    if reserved(&bytes) {
        return Err(crate::error::Error::InvalidKey);
    }
    Ok(EntityId(bytes))
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
    let content_hash = u8::from_str_radix(hash, 16).map_err(|_| crate::error::Error::InvalidKey)?;
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
        EntityId, FOREIGN_WORLD_ID_RANGE_START_BYTE, ForeignWorldId, LocalWorldId, derive_with,
        derived_domains, parse_presentation_id, parse_short_ref_syntax,
    };
    use crate::error::Error;

    #[test]
    fn every_derived_id_carries_version_eight() {
        let domains = derived_domains::ALL;
        let distinct = domains.iter().collect::<std::collections::BTreeSet<_>>();
        assert_eq!(distinct.len(), domains.len(), "every domain is its own");
        for domain in domains {
            for parts in [&[][..], &[&b"part"[..]][..], &[&b"a"[..], &b"b"[..]][..]] {
                let id = EntityId::derive(domain, parts).unwrap();
                let bytes = id.as_bytes();
                assert_eq!(bytes[6] >> 4, 8, "{}", String::from_utf8_lossy(domain));
                assert_eq!(bytes[8] >> 6, 0b10, "{}", String::from_utf8_lossy(domain));
                assert_eq!(EntityId::derive(domain, parts).unwrap(), id);
            }
        }
        // Parts are length-prefixed, so moving a byte across a boundary moves the id.
        let domain = derived_domains::KEY_VALUE;
        assert_ne!(
            EntityId::derive(domain, &[b"ab", b"c"]).unwrap(),
            EntityId::derive(domain, &[b"a", b"bc"]).unwrap()
        );
    }

    #[test]
    fn a_reserved_derived_id_is_refused_with_an_error() {
        let domain = b"oneiron test reserved derived id";
        assert!(derive_with(domain, &[b"part"], |_| false).is_ok());
        let refused = derive_with(domain, &[b"part"], |_| true);
        assert!(matches!(refused, Err(Error::InvalidKey)), "{refused:?}");
        for domain in [&b""[..], &[0xFF, 0xFE][..]] {
            let refused = EntityId::derive(domain, &[b"part"]);
            assert!(
                matches!(refused, Err(Error::InvariantViolation(_))),
                "{refused:?}"
            );
        }
    }

    #[test]
    fn no_nibble_stamp_remains_outside_entity_id() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let tree = crate::test_util::source_scan::SourceTree::read(&src);
        let offenders = tree
            .production_sources()
            .filter(|(_, text)| text.contains("[6] = ("))
            .map(|(path, _)| tree.relative(path))
            .filter(|path| path != "entity_id.rs" && !path.starts_with("entity_id/"))
            .collect::<Vec<_>>();
        assert!(
            offenders.is_empty(),
            "derive ids through EntityId::derive, not a version stamp: {offenders:?}"
        );
    }

    #[test]
    fn ulid_text_roundtrips_and_orders_by_time_without_rejecting_legacy_ids() {
        let fresh = EntityId::now();
        assert_eq!(EntityId::from_ulid(&fresh.to_ulid()).unwrap(), fresh);
        let early = EntityId::from_ulid("01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap();
        let later = EntityId::from_ulid("01ARZ3NDEM0000000000000000").unwrap();
        assert!(early < later);
        assert!(early.to_ulid() < later.to_ulid());
        assert!(EntityId::from_ulid("81ARZ3NDEKTSV4RRFFQ69G5FAV").is_err());
        let legacy = uuid::Uuid::now_v7().into_bytes();
        assert_eq!(EntityId::from_bytes(legacy).unwrap().as_bytes(), &legacy);
    }

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
    fn entity_id_mint_order_survives_cross_thread_handoffs() {
        let (request, requests) = std::sync::mpsc::channel();
        let (response, responses) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            for () in requests {
                response.send(EntityId::now()).unwrap();
            }
        });
        let mut prior = EntityId::now();
        for _ in 0..1024 {
            request.send(()).unwrap();
            let remote = responses.recv().unwrap();
            assert!(remote > prior);
            let local = EntityId::now();
            assert!(local > remote);
            prior = local;
        }
        drop(request);
        worker.join().unwrap();
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

/// Explicit opt-in hex codec for domain records; EntityId has no implicit wire ABI.
pub(crate) mod serde_hex;

pub(crate) mod derived_domains;
