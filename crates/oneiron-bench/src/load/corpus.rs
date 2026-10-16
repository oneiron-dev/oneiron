//! The synthetic corpus: invented words drawn with Zipf frequencies from a
//! fixed seed, so two runs of one plan write the same text in the same order.
//!
//! Every record carries one tag word (`vex` and six letters of its index). A
//! recall item maps back to the record that wrote it through that tag, whatever
//! ids the server minted, which is what lets two commits' rankings be compared.

use serde::{Deserialize, Serialize};

/// splitmix64: tiny, fast and fixed forever, unlike a library generator whose
/// stream may change between versions.
pub(super) struct Rng(u64);

impl Rng {
    pub(super) fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// The generator for one item of one stream: independent of the order in
    /// which items are generated.
    fn for_item(seed: u64, stream: u64, index: u64) -> Self {
        let mut rng = Self(seed ^ stream.wrapping_mul(0xA076_1D64_78BD_642F));
        rng.0 ^= index.wrapping_mul(0xE703_7ED1_A0B4_28DB);
        rng.next_u64();
        rng
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n.max(1) as u64) as usize
    }

    pub(super) fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

const SYLLABLES: [&str; 20] = [
    "ka", "zu", "ri", "mo", "te", "la", "pi", "no", "sa", "vu", "de", "gi", "ho", "be", "fy", "ju",
    "wo", "ce", "xa", "ly",
];
/// 20^3 three-syllable words.
const VOCABULARY: usize = 8_000;
/// Turns per conversation; each conversation is also a claim subject.
pub(super) const TURNS_PER_CONVERSATION: usize = 20;
const TAG_PREFIX: &str = "vex";
/// When record 0 happened; record `i` happened `i` seconds later.
const FIRST_OCCURRED_AT: u64 = 1_791_500_000;

/// Word `rank` of the vocabulary; rank 0 is the most frequent.
fn word(rank: usize) -> String {
    let mut out = String::with_capacity(6);
    let mut rest = rank % VOCABULARY;
    for _ in 0..3 {
        out.push_str(SYLLABLES[rest % SYLLABLES.len()]);
        rest /= SYLLABLES.len();
    }
    out
}

/// The rank of a vocabulary word, the inverse of [`word`].
fn rank_of(text: &str) -> Option<usize> {
    if text.len() != 6 {
        return None;
    }
    (0..3).rev().try_fold(0, |acc, i| {
        let syllable = text.get(i * 2..i * 2 + 2)?;
        let digit = SYLLABLES.iter().position(|s| *s == syllable)?;
        Some(acc * SYLLABLES.len() + digit)
    })
}

/// The tag word of record `index`.
fn tag(index: usize) -> String {
    let mut out = String::from(TAG_PREFIX);
    let mut rest = index;
    for _ in 0..6 {
        out.push(char::from(b'a' + (rest % 26) as u8));
        rest /= 26;
    }
    out
}

/// The record a text was written by, read from its tag word.
pub(super) fn tag_index(text: &str) -> Option<usize> {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .find_map(|token| {
            let letters = token.strip_prefix(TAG_PREFIX)?;
            (letters.len() == 6 && letters.bytes().all(|b| b.is_ascii_lowercase())).then(|| {
                letters
                    .bytes()
                    .rev()
                    .fold(0usize, |acc, b| acc * 26 + usize::from(b - b'a'))
            })
        })
}

/// Cumulative Zipf (s = 1) weights over the vocabulary ranks.
struct Zipf {
    cdf: Vec<f64>,
}

impl Zipf {
    fn new() -> Self {
        let mut total = 0.0;
        let cdf = (1..=VOCABULARY)
            .map(|rank| {
                total += 1.0 / rank as f64;
                total
            })
            .collect::<Vec<_>>();
        Self {
            cdf: cdf.iter().map(|c| c / total).collect(),
        }
    }

    fn rank(&self, rng: &mut Rng) -> usize {
        let u = rng.unit();
        self.cdf.partition_point(|c| *c < u).min(VOCABULARY - 1)
    }
}

/// Who a claim is about.
#[derive(Clone, Copy, Debug)]
pub(super) enum Subject {
    /// The vault's owner: the hot subject most claims in a real vault share.
    Owner,
    /// The conversation the claim's paired turn was written in.
    Conversation(usize),
}

#[derive(Clone, Debug)]
pub(super) enum Record {
    /// One witnessed turn: one or two messages by one speaker.
    Turn {
        index: usize,
        conversation: usize,
        messages: Vec<String>,
    },
    /// One claim through `vault.claims.upsert`, with its own predicate so no claim
    /// supersedes another.
    Claim {
        index: usize,
        subject: Subject,
        predicate: String,
        value: String,
    },
}

impl Record {
    fn index(&self) -> usize {
        match self {
            Self::Turn { index, .. } | Self::Claim { index, .. } => *index,
        }
    }

    /// Unix seconds the record happened and was learned: fixed by its index.
    pub(super) fn occurred_at(&self) -> u64 {
        FIRST_OCCURRED_AT + self.index() as u64
    }

    pub(super) fn conversation(&self) -> usize {
        match self {
            Self::Turn { conversation, .. } => *conversation,
            Self::Claim { index, .. } => turn_conversation(index / 2),
        }
    }

    /// Every word of the record's text, the tag word included.
    fn text(&self) -> String {
        match self {
            Self::Turn { messages, .. } => messages.join(" "),
            Self::Claim { value, .. } => value.clone(),
        }
    }
}

/// The fixed "now" every recall resolves against (`as_of`): a minute after the
/// last of `records` records, so recency scores repeat on any day.
pub(super) fn recall_now(records: usize) -> u64 {
    FIRST_OCCURRED_AT + records as u64 + 60
}

fn turn_conversation(turn: usize) -> usize {
    turn / TURNS_PER_CONVERSATION
}

/// The corpus plan: record `i` is turn `i / 2` when `i` is even and the claim
/// paired with it when `i` is odd, so a claim's subject conversation exists
/// before the claim is written by the same caller.
pub(super) struct Corpus {
    seed: u64,
    hot_subject: f64,
    zipf: Zipf,
}

const STREAM_RECORD: u64 = 1;
const STREAM_QUERY: u64 = 2;
const STREAM_CONVERSATION: u64 = 3;

impl Corpus {
    pub(super) fn new(seed: u64, hot_subject: f64) -> Self {
        Self {
            seed,
            hot_subject,
            zipf: Zipf::new(),
        }
    }

    fn words(&self, rng: &mut Rng, low: usize, high: usize) -> Vec<String> {
        let n = low + rng.below(high - low + 1);
        (0..n).map(|_| word(self.zipf.rank(rng))).collect()
    }

    pub(super) fn record(&self, index: usize) -> Record {
        let mut rng = Rng::for_item(self.seed, STREAM_RECORD, index as u64);
        if index.is_multiple_of(2) {
            let turn = index / 2;
            let count = 1 + rng.below(2);
            let mut messages = (0..count)
                .map(|_| self.words(&mut rng, 8, 24).join(" "))
                .collect::<Vec<_>>();
            if let Some(first) = messages.first_mut() {
                first.push(' ');
                first.push_str(&tag(index));
            }
            Record::Turn {
                index,
                conversation: turn_conversation(turn),
                messages,
            }
        } else {
            let subject = if rng.unit() < self.hot_subject {
                Subject::Owner
            } else {
                Subject::Conversation(turn_conversation(index / 2))
            };
            let mut value = self.words(&mut rng, 6, 18);
            value.push(tag(index));
            Record::Claim {
                index,
                subject,
                predicate: format!("bench.f_{}", &tag(index)[TAG_PREFIX.len()..]),
                value: value.join(" "),
            }
        }
    }

    /// A conversation's 32-hex id, fixed by the seed.
    pub(super) fn conversation_ref(&self, conversation: usize) -> String {
        let mut rng = Rng::for_item(self.seed, STREAM_CONVERSATION, conversation as u64);
        // Clear the top bits so no id lands on the engine's reserved low ids.
        let high = rng.next_u64() | (1 << 62);
        format!("{high:016x}{:016x}", rng.next_u64())
    }

    /// `count` golden queries over the first `records` records: mostly the
    /// rarest three words of one record, plus a few common-word and tag queries.
    pub(super) fn queries(&self, records: usize, count: usize) -> Vec<Query> {
        (0..count)
            .map(|q| {
                let mut rng = Rng::for_item(self.seed, STREAM_QUERY, q as u64);
                let target = rng.below(records);
                match q % 10 {
                    8 => Query {
                        text: format!("{} {}", word(rng.below(30)), word(rng.below(30))),
                        target: None,
                        kind: "common".to_owned(),
                    },
                    9 => Query {
                        text: tag(target),
                        target: Some(target),
                        kind: "tag".to_owned(),
                    },
                    _ => Query {
                        text: rarest_words(&self.record(target).text(), 3),
                        target: Some(target),
                        kind: "specific".to_owned(),
                    },
                }
            })
            .collect()
    }
}

/// The `n` least frequent distinct words of a text (highest Zipf rank), tag excluded.
fn rarest_words(text: &str, n: usize) -> String {
    let mut ranked = text
        .split_whitespace()
        .filter(|w| !w.starts_with(TAG_PREFIX))
        .filter_map(|w| rank_of(w).map(|r| (r, w)))
        .collect::<Vec<_>>();
    ranked.sort_unstable_by_key(|(rank, _)| std::cmp::Reverse(*rank));
    ranked.dedup_by_key(|(rank, _)| *rank);
    ranked
        .iter()
        .take(n)
        .map(|(_, w)| *w)
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Query {
    pub(super) text: String,
    /// The record the query was drawn from, when it has one.
    pub(super) target: Option<usize>,
    pub(super) kind: String,
}
