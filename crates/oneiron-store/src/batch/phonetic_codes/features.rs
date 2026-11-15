//! The articulatory features of the segments the readers emit.
//!
//! Each row is the segment's row of PanPhon's `panphon/data/ipa_all.csv`
//! (github.com/dmort27/panphon at a49c242d3307; MIT, Copyright (c) 2015
//! Carnegie Mellon University), in the CSV's feature order: syl, son, cons,
//! cont, delrel, lat, nas, strid, voi, sg, cg, ant, cor, distr, lab, hi, lo,
//! back, round, velaric, tense, long, hitone, hireg. Each value is PanPhon's
//! own: `+`, `-`, or `0` (not specified).

/// The number of PanPhon features a segment carries.
pub(super) const FEATURE_COUNT: usize = 24;

/// One phoneme of a reading: a row of the feature table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Segment(u8);

impl Segment {
    /// The segment's IPA symbol.
    pub fn symbol(self) -> &'static str {
        SEGMENTS[usize::from(self.0)].0
    }

    /// The segment's PanPhon feature values, one byte each.
    pub(super) fn features(self) -> &'static [u8; FEATURE_COUNT] {
        SEGMENTS[usize::from(self.0)].1
    }
}

/// The segments of an IPA string written with this table's symbols (a
/// stored `ipa:` key, say), read by longest match. `None` when a part of it
/// is no symbol of the table, or when it is empty.
pub fn ipa_segments(ipa: &str) -> Option<Vec<Segment>> {
    let mut segments = Vec::new();
    let mut rest = ipa;
    while !rest.is_empty() {
        let (segment, length) = longest_segment(rest)?;
        segments.push(segment);
        rest = &rest[length..];
    }
    (!segments.is_empty()).then_some(segments)
}

/// The segment whose symbol is the longest prefix of `ipa`, with the
/// symbol's length in bytes.
fn longest_segment(ipa: &str) -> Option<(Segment, usize)> {
    (0u8..)
        .zip(SEGMENTS.iter())
        .filter(|(_, (symbol, _))| ipa.starts_with(*symbol))
        .max_by_key(|(_, (symbol, _))| symbol.len())
        .map(|(index, (symbol, _))| (Segment(index), symbol.len()))
}

/// Every segment a reader emits: vowels, syllabic consonants, glides, stops,
/// affricates, fricatives, nasals and liquids.
const SEGMENTS: [(&str, &[u8; FEATURE_COUNT]); 68] = [
    ("i", b"++-+----+--0-0-+----+-00"),
    ("iː", b"++-+----+--0-0-+----++00"),
    ("ɪ", b"++-+----+--0-0-+------00"),
    ("e", b"++-+----+--0-0------+-00"),
    ("eː", b"++-+----+--0-0------++00"),
    ("ɛ", b"++-+----+--0-0--------00"),
    ("æ", b"++-+----+--0-0--+---+-00"),
    ("a", b"++-+----+--0-0--++--+-00"),
    ("aː", b"++-+----+--0-0--++--++00"),
    ("ɑ", b"++-+0---+--0-0--++--+-00"),
    ("ɔ", b"++-+----+--0-0---++---00"),
    ("o", b"++-+----+--0-0---++-+-00"),
    ("oː", b"++-+----+--0-0---++-++00"),
    ("ʊ", b"++-+----+--0-0-+-++---00"),
    ("u", b"++-+----+--0-0++-++-+-00"),
    ("uː", b"++-+----+--0-0++-++-++00"),
    ("ɯ", b"++-+----+--0-0-+-+----00"),
    ("ɯː", b"++-+----+--0-0-+-+---+00"),
    ("ɤ", b"++-+0---+--0-0---+--+-00"),
    ("ʌ", b"++-+----+--0-0---+--+-00"),
    ("ə", b"++-+----+--0-0---+----00"),
    ("ɜ", b"++-+----+--0-0---+----00"),
    ("ɨ", b"++-+----+--0-0-+-+--+-00"),
    ("y", b"++-+----+--0-0++--+-+-00"),
    ("ɹ̩", b"++-+----+--++--+--+-0-00"),
    ("ɻ̩", b"++-+----+---+-------0-00"),
    ("j", b"-+-+----+----0-+----0-00"),
    ("w", b"-+-+----+----0++-++-0-00"),
    ("ɥ", b"-+-+0---+----0++--+-+-00"),
    ("p", b"--+--------+-0+-----0-00"),
    ("pʰ", b"--+------+-+-0+-----0-00"),
    ("b", b"--+-----+--+-0+-----0-00"),
    ("t", b"--+--------++-------0-00"),
    ("tʰ", b"--+------+-++-------0-00"),
    ("d", b"--+-----+--++-------0-00"),
    ("k", b"--+----------0-+-+--0-00"),
    ("kʰ", b"--+------+---0-+-+--0-00"),
    ("ɡ", b"--+-----+----0-+-+--0-00"),
    ("t͡s", b"--+-+--+---++-------0-00"),
    ("t͡sʰ", b"--+-+--+-+-++-------0-00"),
    ("t͡ɕ", b"--+-+--+----++-+----0-00"),
    ("t͡ɕʰ", b"--+-+--+-+--++-+----0-00"),
    ("d͡ʑ", b"--+-+--++---++-+----0-00"),
    ("t͡ʃ", b"--+-+--+----++------0-00"),
    ("d͡ʒ", b"--+-+--++---++------0-00"),
    ("ʈ͡ʂ", b"--+-+--+----+--00---0-00"),
    ("ʈ͡ʂʰ", b"--+-+--+-+--+--00---0-00"),
    ("ɸ", b"--++-------+-0+-----0-00"),
    ("f", b"--++---+---+-0+-----0-00"),
    ("v", b"--++---++--+-0+-----0-00"),
    ("θ", b"--++-------+++------0-00"),
    ("ð", b"--++----+--+++------0-00"),
    ("s", b"--++---+---++-------0-00"),
    ("z", b"--++---++--++-------0-00"),
    ("ʃ", b"--++---+----++------0-00"),
    ("ʒ", b"--++---++---++------0-00"),
    ("ɕ", b"--+++--+----++-+----0-00"),
    ("ʂ", b"--++---+----+-------0-00"),
    ("ʐ", b"--++---++---+-------0-00"),
    ("x", b"--++---------0-+-+--0-00"),
    ("h", b"-+++---------0---+--0-00"),
    ("m", b"-++---+-+--+-0+-----0-00"),
    ("n", b"-++---+-+--++-------0-00"),
    ("ŋ", b"-++---+-+----0-+-+--0-00"),
    ("l", b"-+++-+--+--++-------0-00"),
    ("ɹ", b"-+-+----+--++--+--+-0-00"),
    ("ɾ", b"-+++0---+--++--00---0-00"),
    ("ɻ", b"-+-+----+---+-------0-00"),
];
