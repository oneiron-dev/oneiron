//! The K door: a digest that main already stores or sends keeps its exact bytes.
//!
//! The stored-hash guard (lead, 15 Nov 13:55): a hash whose output is stored, sent or
//! compared across versions keeps today's recipe through a legacy purpose until the
//! launch reset (PLAN-UC-04 stage 9). A legacy purpose exists only for a site whose
//! bytes main wrote before this crate; a new digest takes a v1 [`crate::Purpose`].
//!
//! [`LegacyDigest`] replays today's transcript one write at a time, and each length
//! write names its width and byte order, so the reader of a site sees the recipe.

use sha2::Digest as _;

/// The hash a legacy recipe runs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LegacyHash {
    Blake3,
    Sha256,
}

/// Where a legacy recipe puts its tag.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TagMode {
    /// BLAKE3 derive-key mode, with the tag as the context string. BLAKE3 only.
    DeriveKeyContext,
    /// The tag's bytes are the first write, with no length before them.
    HashedFirst,
    /// The tag is not hashed: it is the registry name of a recipe that writes no tag.
    NotHashed,
}

/// A stored or sent digest that keeps today's bytes. Only the registry makes one
/// (`legacy_purposes!` in `purposes`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LegacyPurpose {
    tag: &'static str,
    hash: LegacyHash,
    tag_mode: TagMode,
}

impl LegacyPurpose {
    /// An empty tag, or SHA-256 with a derive-key context, does not compile: the
    /// registry builds every legacy purpose in a `const`.
    pub(crate) const fn new(tag: &'static str, hash: LegacyHash, tag_mode: TagMode) -> Self {
        assert!(!tag.is_empty(), "a legacy purpose tag must not be empty");
        assert!(
            !matches!(
                (hash, tag_mode),
                (LegacyHash::Sha256, TagMode::DeriveKeyContext)
            ),
            "SHA-256 has no derive-key mode"
        );
        Self {
            tag,
            hash,
            tag_mode,
        }
    }

    /// The tag string: the derive-key context, the first bytes written, or (for
    /// [`TagMode::NotHashed`]) the registry name only.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        self.tag
    }

    #[must_use]
    pub const fn hash(self) -> LegacyHash {
        self.hash
    }

    #[must_use]
    pub const fn tag_mode(self) -> TagMode {
        self.tag_mode
    }
}

/// Today's transcript of a legacy digest, one write at a time.
#[derive(Clone)]
pub struct LegacyDigest(LegacyState);

#[derive(Clone)]
enum LegacyState {
    Blake3(blake3::Hasher),
    Sha256(sha2::Sha256),
}

impl LegacyDigest {
    /// Starts the transcript. [`TagMode::HashedFirst`] writes the tag's bytes first.
    #[must_use]
    pub fn new(purpose: LegacyPurpose) -> Self {
        let tag = purpose.tag().as_bytes();
        let state = match (purpose.hash(), purpose.tag_mode()) {
            (LegacyHash::Blake3, TagMode::DeriveKeyContext) => {
                LegacyState::Blake3(blake3::Hasher::new_derive_key(purpose.tag()))
            }
            (LegacyHash::Blake3, TagMode::HashedFirst) => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(tag);
                LegacyState::Blake3(hasher)
            }
            (LegacyHash::Blake3, TagMode::NotHashed) => LegacyState::Blake3(blake3::Hasher::new()),
            // `LegacyPurpose::new` refuses SHA-256 with a derive-key context at compile
            // time, so only the two plain modes reach this arm.
            (LegacyHash::Sha256, tag_mode) => {
                let mut hasher = sha2::Sha256::new();
                if tag_mode == TagMode::HashedFirst {
                    hasher.update(tag);
                }
                LegacyState::Sha256(hasher)
            }
        };
        Self(state)
    }

    /// Bytes with no length before them, as today's site writes them.
    pub fn raw(&mut self, bytes: &[u8]) -> &mut Self {
        match &mut self.0 {
            LegacyState::Blake3(hasher) => {
                hasher.update(bytes);
            }
            LegacyState::Sha256(hasher) => hasher.update(bytes),
        }
        self
    }

    /// A length as a u64, big-endian.
    pub fn len_u64_be(&mut self, len: usize) -> &mut Self {
        self.raw(&(len as u64).to_be_bytes())
    }

    /// A length as a u64, little-endian.
    pub fn len_u64_le(&mut self, len: usize) -> &mut Self {
        self.raw(&(len as u64).to_le_bytes())
    }

    /// A length as a u32, big-endian; a length above `u32::MAX` writes `u32::MAX`
    /// (`git_wire`'s framing).
    pub fn len_u32_be_saturating(&mut self, len: usize) -> &mut Self {
        self.raw(&u32::try_from(len).unwrap_or(u32::MAX).to_be_bytes())
    }

    #[must_use]
    pub fn finish(&self) -> [u8; crate::DIGEST_LEN] {
        match &self.0 {
            LegacyState::Blake3(hasher) => *hasher.finalize().as_bytes(),
            LegacyState::Sha256(hasher) => hasher.clone().finalize().into(),
        }
    }
}
