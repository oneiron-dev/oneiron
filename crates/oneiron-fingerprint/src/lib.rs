//! One fingerprint rule for engine digests (fable pass 22; PLAN-UC-04 stage 0).
//!
//! The engine hashes for four reasons, and this crate is the door for two of them:
//! - a **fingerprint**: 32 bytes made from a [`Purpose`] and a list of parts
//!   ([`Fingerprint`], [`Fingerprinter`]). `EntityId::derive` is its 16-byte cut;
//! - a **content hash**: plain BLAKE3 of a body of bytes, with no purpose
//!   ([`ContentHash`], [`ContentHasher`]). It names the bytes and nothing else.
//!
//! A format that an outside party fixes, and a signature or key scheme, stay in
//! their own files, on the `raw_hasher_starts` allowlist
//! (`scripts/ratchet/raw_hasher_allowlist.txt`).
//!
//! The rule:
//!
//! ```text
//! fingerprint(purpose, parts) = BLAKE3 derive-key, context = the purpose string,
//!                               input = for each part: its length as u64 little-endian, then its bytes
//! ```
//!
//! A fingerprint is not a proof. The purpose strings are public, so anyone who knows
//! the parts can compute the 32 bytes. Equal fingerprints show equal parts; they never
//! show who made them. A door that takes a digest from a caller looks up the
//! engine-written row or checks a signature.
//!
//! The K door ([`LegacyPurpose`], [`LegacyDigest`]) keeps the exact bytes of a digest
//! that main already stores or sends (the stored-hash guard, lead 15 Nov 13:55). A new
//! digest never takes a legacy purpose. Stage 9 retires them in the launch-reset release.
//!
//! No binding crate re-exports this crate, and no verb, tool or host call takes a
//! purpose: a purpose is never made from data.

mod legacy;
pub mod purposes;
#[cfg(feature = "record")]
mod record;

pub use legacy::{LegacyDigest, LegacyHash, LegacyPurpose, TagMode};
pub use purposes::assert_distinct_contexts;
#[cfg(feature = "record")]
pub use record::{CanonicalBytesError, canonical_bytes};

use std::fmt;

/// The length of a fingerprint and of a content hash, in bytes.
pub const DIGEST_LEN: usize = 32;

/// What a fingerprint is for. Only the registry in this crate (`purposes`) makes one:
/// the field is private, and there is no `FromStr`, no `Deserialize` and no public
/// constructor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Purpose(&'static str);

impl Purpose {
    /// An empty context does not compile: the registry builds every purpose in a `const`.
    pub(crate) const fn new(context: &'static str) -> Self {
        assert!(!context.is_empty(), "a purpose context must not be empty");
        Self(context)
    }

    /// The BLAKE3 derive-key context string.
    #[must_use]
    pub const fn context(self) -> &'static str {
        self.0
    }
}

/// 32 bytes made from a purpose and a list of parts. Equal fingerprints under one
/// purpose mean equal parts.
///
/// It has no serde form of its own: a site stores [`Fingerprint::into_bytes`] or
/// [`Fingerprint::to_hex`], as its row does today.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fingerprint([u8; DIGEST_LEN]);

impl Fingerprint {
    /// The fingerprint of a fixed list of byte strings. Equals a [`Fingerprinter`]
    /// that calls [`Fingerprinter::part`] once per element.
    #[must_use]
    pub fn of_parts(purpose: Purpose, parts: &[&[u8]]) -> Self {
        let mut fingerprinter = Fingerprinter::new(purpose);
        for part in parts {
            fingerprinter.part(part);
        }
        fingerprinter.finish()
    }

    /// The fingerprint of a typed value: one part, its [`canonical_bytes`]. Equals
    /// `Fingerprint::of_parts(purpose, &[&canonical_bytes(record)?])`.
    ///
    /// A value that is stored, signed or sent as encoded bytes is fingerprinted from
    /// those bytes with [`Fingerprint::of_parts`]; it is not encoded a second time.
    ///
    /// # Errors
    /// [`CanonicalBytesError`] when the value has no canonical bytes.
    #[cfg(feature = "record")]
    pub fn of_record<T: serde::Serialize + ?Sized>(
        purpose: Purpose,
        record: &T,
    ) -> Result<Self, CanonicalBytesError> {
        let bytes = canonical_bytes(record)?;
        Ok(Self::of_parts(purpose, &[&bytes]))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DIGEST_LEN] {
        &self.0
    }

    #[must_use]
    pub const fn into_bytes(self) -> [u8; DIGEST_LEN] {
        self.0
    }

    /// 64 lowercase hex digits.
    #[must_use]
    pub fn to_hex(&self) -> String {
        oneiron_hex::encode(&self.0)
    }

    /// The first `N` bytes. `N` above 32 does not build.
    #[must_use]
    pub fn prefix<const N: usize>(&self) -> [u8; N] {
        const { assert!(N <= DIGEST_LEN, "a fingerprint prefix is at most 32 bytes") };
        let mut prefix = [0; N];
        prefix.copy_from_slice(&self.0[..N]);
        prefix
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Fingerprint({})", self.to_hex())
    }
}

/// A running fingerprint, for a layout that one slice cannot hold: a list, an
/// optional field, a nested record.
///
/// Every write is a framed part. There is no write without a length, so two
/// different lists of parts never give one byte stream. A list writes its count
/// first ([`Fingerprinter::u64`]); an optional field writes its presence first
/// ([`Fingerprinter::flag`]).
#[derive(Clone)]
pub struct Fingerprinter(blake3::Hasher);

impl Fingerprinter {
    #[must_use]
    pub fn new(purpose: Purpose) -> Self {
        Self(blake3::Hasher::new_derive_key(purpose.context()))
    }

    /// One part: its length as a u64 little-endian, then its bytes.
    pub fn part(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.update(&(bytes.len() as u64).to_le_bytes());
        self.0.update(bytes);
        self
    }

    /// A number, as one part of its 8 little-endian bytes.
    pub fn u64(&mut self, value: u64) -> &mut Self {
        self.part(&value.to_le_bytes())
    }

    /// A flag, as one part of one byte (0 or 1).
    pub fn flag(&mut self, value: bool) -> &mut Self {
        self.part(&[u8::from(value)])
    }

    /// A typed value, as one part of its [`canonical_bytes`].
    ///
    /// # Errors
    /// [`CanonicalBytesError`] when the value has no canonical bytes; nothing is written then.
    #[cfg(feature = "record")]
    pub fn record<T: serde::Serialize + ?Sized>(
        &mut self,
        record: &T,
    ) -> Result<&mut Self, CanonicalBytesError> {
        let bytes = canonical_bytes(record)?;
        Ok(self.part(&bytes))
    }

    #[must_use]
    pub fn finish(&self) -> Fingerprint {
        Fingerprint(*self.0.finalize().as_bytes())
    }
}

/// The name of a body of bytes: plain BLAKE3, with no purpose. The same bytes hash the
/// same everywhere, so an outside tool (`b3sum`) can check it. BLAKE3 sets different
/// mode flags for plain hashing and for derive-key hashing, so a content hash never
/// equals a fingerprint by accident.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentHash([u8; DIGEST_LEN]);

impl ContentHash {
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(*blake3::hash(bytes).as_bytes())
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DIGEST_LEN] {
        &self.0
    }

    #[must_use]
    pub const fn into_bytes(self) -> [u8; DIGEST_LEN] {
        self.0
    }

    /// 64 lowercase hex digits.
    #[must_use]
    pub fn to_hex(&self) -> String {
        oneiron_hex::encode(&self.0)
    }
}

impl fmt::Debug for ContentHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ContentHash({})", self.to_hex())
    }
}

/// A running content hash, for a body that arrives in pieces. Equals
/// [`ContentHash::of`] over the concatenated pieces.
#[derive(Clone, Default)]
pub struct ContentHasher(blake3::Hasher);

impl ContentHasher {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.update(bytes);
        self
    }

    #[must_use]
    pub fn finish(&self) -> ContentHash {
        ContentHash(*self.0.finalize().as_bytes())
    }
}

impl std::io::Write for ContentHasher {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
