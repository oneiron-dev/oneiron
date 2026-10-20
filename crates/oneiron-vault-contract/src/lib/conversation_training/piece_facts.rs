//! The anonymous training window's facts digest (TL-6): the one fn the
//! engine and the intake both compute a piece's `facts_digest` with.

use super::piece_check::check_head;
use super::{DIGEST_HEX, PIECE_FACTS_DOMAIN, PieceChunkV1, PieceFactsHeadV1, check_hex};

/// A piece's facts digest, its final's `facts_digest`, built as a stream.
/// It reads every list in index order, whatever pages carried it, so it does
/// not depend on paging. It is BLAKE3 over these elements in order, each
/// framed as its length, a big-endian `u32`, then its bytes:
///
/// 1. [`PIECE_FACTS_DOMAIN`];
/// 2. the head's compact JSON (`serde_json`, fields in declaration order);
/// 3. `persons_total`, 8 bytes big-endian, then each person code as its 32
///    raw bytes;
/// 4. `worlds_total`, then each world code, likewise;
/// 5. `chunks_total`, then each chunk as one element: its `bytes`, 8 bytes
///    big-endian, then its digest's 32 raw bytes.
///
/// It takes the sections in that order, each with exactly the count it
/// opened with: a short section, an extra item, a section out of order or a
/// code that is not 64 lower-case hex is an error, never a digest. The
/// engine and the intake both compute it here.
#[derive(Debug, Clone)]
pub struct PieceFactsDigest {
    hasher: blake3::Hasher,
    section: FactsSection,
    /// Items the open section still takes.
    left: u64,
}

/// The facts digest's sections, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FactsSection {
    Head,
    Persons,
    Worlds,
    Chunks,
}

impl PieceFactsDigest {
    /// Starts a digest with the domain and `head`, whose ids must be hex.
    pub fn new(head: &PieceFactsHeadV1) -> anyhow::Result<Self> {
        check_head(head)?;
        let mut hasher = blake3::Hasher::new();
        frame(&mut hasher, PIECE_FACTS_DOMAIN.as_bytes())?;
        frame(&mut hasher, &serde_json::to_vec(head)?)?;
        Ok(Self {
            hasher,
            section: FactsSection::Head,
            left: 0,
        })
    }

    /// Opens the persons, `total` of them.
    pub fn persons(&mut self, total: u64) -> anyhow::Result<()> {
        self.open(FactsSection::Head, FactsSection::Persons, total)
    }

    /// Takes the next person code.
    pub fn person(&mut self, code: &str) -> anyhow::Result<()> {
        let raw = raw_code("person", code)?;
        self.item(FactsSection::Persons, &raw)
    }

    /// Opens the worlds, `total` of them, once every person is in.
    pub fn worlds(&mut self, total: u64) -> anyhow::Result<()> {
        self.open(FactsSection::Persons, FactsSection::Worlds, total)
    }

    /// Takes the next world code.
    pub fn world(&mut self, code: &str) -> anyhow::Result<()> {
        let raw = raw_code("world", code)?;
        self.item(FactsSection::Worlds, &raw)
    }

    /// Opens the chunk table, `total` rows, once every world is in.
    pub fn chunks(&mut self, total: u64) -> anyhow::Result<()> {
        self.open(FactsSection::Worlds, FactsSection::Chunks, total)
    }

    /// Takes the next chunk table row.
    pub fn chunk(&mut self, chunk: &PieceChunkV1) -> anyhow::Result<()> {
        let digest = raw_code("chunk digest", &chunk.digest)?;
        let mut element = [0u8; 40];
        element[..8].copy_from_slice(&chunk.bytes.to_be_bytes());
        element[8..].copy_from_slice(&digest);
        self.item(FactsSection::Chunks, &element)
    }

    /// The digest, once every chunk row is in.
    pub fn finish(self) -> anyhow::Result<[u8; 32]> {
        if self.section != FactsSection::Chunks || self.left != 0 {
            anyhow::bail!("a facts digest finished before its last chunk");
        }
        Ok(*self.hasher.finalize().as_bytes())
    }

    fn open(&mut self, after: FactsSection, to: FactsSection, total: u64) -> anyhow::Result<()> {
        if self.section != after {
            anyhow::bail!("a facts digest takes persons, then worlds, then chunks");
        }
        if self.left != 0 {
            anyhow::bail!("a facts digest section is short of its total");
        }
        frame(&mut self.hasher, &total.to_be_bytes())?;
        self.section = to;
        self.left = total;
        Ok(())
    }

    fn item(&mut self, section: FactsSection, element: &[u8]) -> anyhow::Result<()> {
        if self.section != section {
            anyhow::bail!("a facts digest item came outside its section");
        }
        let Some(left) = self.left.checked_sub(1) else {
            anyhow::bail!("a facts digest section has more items than its total");
        };
        frame(&mut self.hasher, element)?;
        self.left = left;
        Ok(())
    }
}

/// A piece's [`PieceFactsDigest`] over whole lists.
pub fn piece_facts_digest(
    head: &PieceFactsHeadV1,
    persons: &[String],
    worlds: &[String],
    chunks: &[PieceChunkV1],
) -> anyhow::Result<[u8; 32]> {
    let mut digest = PieceFactsDigest::new(head)?;
    digest.persons(u64::try_from(persons.len())?)?;
    for person in persons {
        digest.person(person)?;
    }
    digest.worlds(u64::try_from(worlds.len())?)?;
    for world in worlds {
        digest.world(world)?;
    }
    digest.chunks(u64::try_from(chunks.len())?)?;
    for chunk in chunks {
        digest.chunk(chunk)?;
    }
    digest.finish()
}

/// A 64 hex code or digest as its 32 raw bytes.
fn raw_code(field: &str, code: &str) -> anyhow::Result<[u8; 32]> {
    check_hex(field, code, DIGEST_HEX)?;
    crate::from_hex(code)
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| anyhow::anyhow!("{field} is not {DIGEST_HEX} lower-case hex characters"))
}

/// Feeds one element: its length, a big-endian `u32`, then its bytes.
fn frame(hasher: &mut blake3::Hasher, element: &[u8]) -> anyhow::Result<()> {
    let Ok(len) = u32::try_from(element.len()) else {
        anyhow::bail!("a facts digest element does not fit its u32 length frame");
    };
    hasher.update(&len.to_be_bytes());
    hasher.update(element);
    Ok(())
}
