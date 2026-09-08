//! The pure five-axis scorer: no storage, no clock, no model.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::dreamer_runner::DreamerTurnRole;

use super::config::PrefilterConfig;
use super::receipts::{PREFILTER_DECISION_PASS, PREFILTER_DECISION_SKIP};

// ---------------------------------------------------------------------------
// Feature axes
// ---------------------------------------------------------------------------

/// Token count at which the LENGTH axis saturates. A turn longer than this is
/// not "more extractable" for being longer; it is simply long enough.
const LEN_SATURATION_TOKENS: f32 = 40.0;

/// Entity mentions per token at which the DENSITY axis saturates. One named
/// span every four tokens is already dense prose about specific things.
const ENTITY_DENSITY_SATURATION: f32 = 0.25;

/// Floor on the density DENOMINATOR. Without it a two-word turn whose first
/// word happens to be capitalized (`"Got it."`) claims maximal entity density
/// off one token, which is the one way a rate with a tiny denominator lies.
/// The floor costs genuinely dense short turns nothing: two names in four
/// words still saturates.
const ENTITY_DENSITY_MIN_TOKENS: usize = 8;

/// Word n-gram width for the novelty overlap.
const NOVELTY_SHINGLE_LEN: usize = 3;

/// How many preceding turns of the SAME batch the novelty window remembers.
pub(super) const NOVELTY_WINDOW_TURNS: usize = 8;

/// Coarse prompt-cost proxy: four characters per model token.
const CHARS_PER_ESTIMATED_TOKEN: usize = 4;

/// Capitalized tokens that are sentence openers rather than named things.
/// Pinned and tiny on purpose: the density axis needs to not reward every
/// sentence for starting, and a real stopword list would be a dictionary this
/// screen has no business carrying. The contractions are here because they are
/// the capitalized first words the trim keeps intact (`I'm`, `It's`).
const SENTENCE_OPENERS: [&str; 34] = [
    "a", "an", "and", "but", "he", "how", "i", "i'll", "i'm", "i've", "if", "it", "it's", "my",
    "no", "ok", "she", "so", "that", "that's", "the", "then", "there", "there's", "they", "this",
    "we", "we'll", "we've", "what", "when", "why", "you'll", "you're",
];

/// Feature name: normalized token count.
pub const PREFILTER_FEATURE_LEN: &str = "len";

/// Feature name: type/token ratio (lexical variety).
pub const PREFILTER_FEATURE_TTR: &str = "ttr";

/// Feature name: entity-mention density.
pub const PREFILTER_FEATURE_ENTITY_DENSITY: &str = "entity_density";

/// Feature name: novelty against the recent-turn window.
pub const PREFILTER_FEATURE_NOVELTY: &str = "novelty";

/// Feature name: speaker-role weight.
pub const PREFILTER_FEATURE_ROLE: &str = "role";

// ---------------------------------------------------------------------------
// The pure scorer
// ---------------------------------------------------------------------------

/// One turn's screening verdict: the decision, the score behind it, and every
/// feature that produced the score. Nothing here is derived later — a receipt
/// reader sees exactly the arithmetic the planner ran.
#[derive(Debug, Clone, PartialEq)]
pub struct PrefilterVerdict {
    /// `true` = keep the turn in the planner input.
    pub pass: bool,
    /// Weighted mean of the axes, in `[0, 1]`.
    pub score: f32,
    /// Every axis by name, in `[0, 1]`. Empty on an unscored pass.
    pub features: BTreeMap<&'static str, f32>,
    /// Coarse prompt-cost proxy for this turn's text.
    pub estimated_tokens: u64,
}

impl PrefilterVerdict {
    /// The verdict for a turn the screen could not read.
    ///
    /// A value estimate that could not be made is not a licence to discard
    /// work, so an unreadable body PASSES, unscored and with no features. It
    /// is deliberately distinguishable in a receipt from a scored pass: an
    /// empty feature map means "not screened", never "screened at zero".
    #[must_use]
    pub fn unscored_pass() -> Self {
        Self {
            pass: true,
            score: 0.0,
            features: BTreeMap::new(),
            estimated_tokens: 0,
        }
    }

    /// This verdict in the receipt family's `decision` vocabulary — the ONE
    /// spelling, so a renderer and a receipt can never disagree about what a
    /// ruling was called.
    #[must_use]
    pub const fn decision(&self) -> &'static str {
        if self.pass {
            PREFILTER_DECISION_PASS
        } else {
            PREFILTER_DECISION_SKIP
        }
    }
}

/// A rolling window over the shingles of the preceding turns in ONE batch —
/// the basis of the novelty axis.
///
/// The window is built from every preceding turn of the input batch, kept or
/// skipped: novelty means "not just said", and what was said does not stop
/// having been said because the screen declined to extract it.
#[derive(Debug, Clone, Default)]
pub struct NoveltyWindow {
    pub(super) recent: VecDeque<BTreeSet<String>>,
}

impl NoveltyWindow {
    /// An empty window: the first turn of a batch is wholly novel.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Admits one turn's text, evicting the oldest beyond
    /// `NOVELTY_WINDOW_TURNS`.
    pub fn observe(&mut self, text: &str) {
        let tokens = normalized_tokens(text);
        self.recent.push_back(shingles(&tokens));
        while self.recent.len() > NOVELTY_WINDOW_TURNS {
            self.recent.pop_front();
        }
    }

    fn contains(&self, shingle: &str) -> bool {
        self.recent.iter().any(|set| set.contains(shingle))
    }

    fn is_empty(&self) -> bool {
        self.recent.iter().all(BTreeSet::is_empty)
    }
}

/// Whitespace tokens with leading/trailing non-alphanumerics stripped.
fn raw_tokens(text: &str) -> Vec<&str> {
    text.split_whitespace()
        .map(|token| token.trim_matches(|c: char| !c.is_alphanumeric()))
        .filter(|token| !token.is_empty())
        .collect()
}

/// [`raw_tokens`] lowercased — the form every set-valued axis compares on.
fn normalized_tokens(text: &str) -> Vec<String> {
    raw_tokens(text)
        .into_iter()
        .map(str::to_lowercase)
        .collect()
}

/// Word n-grams of width [`NOVELTY_SHINGLE_LEN`]. A text too short to shingle
/// falls back to its own token set, so a three-word turn still has a novelty
/// answer instead of a division by zero.
fn shingles(tokens: &[String]) -> BTreeSet<String> {
    if tokens.len() < NOVELTY_SHINGLE_LEN {
        return tokens.iter().cloned().collect();
    }
    tokens
        .windows(NOVELTY_SHINGLE_LEN)
        .map(|window| window.join(" "))
        .collect()
}

/// Coarse prompt-cost proxy: four characters per model token, rounded up.
/// Deliberately NOT the statistical token count — this one answers "what would
/// this turn have cost", and character count is the tokenizer-independent
/// approximation every budget estimate in the trade uses.
#[must_use]
pub fn estimated_prompt_tokens(text: &str) -> u64 {
    text.chars().count().div_ceil(CHARS_PER_ESTIMATED_TOKEN) as u64
}

/// Count of maximal CAPITALIZED SPANS plus known-name hits outside them.
///
/// A run of adjacent capitalized tokens is ONE mention ("Kyoto Station" names
/// one thing, not two). Sentence openers are excluded by
/// [`SENTENCE_OPENERS`]: a sentence is not an entity for starting.
pub(super) fn entity_mentions(tokens: &[&str], known_names: &BTreeSet<String>) -> usize {
    let mut mentions = 0;
    let mut in_span = false;
    for token in tokens {
        let lowered = token.to_lowercase();
        let capitalized = token
            .chars()
            .next()
            .is_some_and(|c| c.is_uppercase() && c.is_alphabetic())
            && token.chars().count() > 1
            && !SENTENCE_OPENERS.contains(&lowered.as_str());
        if capitalized {
            if !in_span {
                mentions += 1;
                in_span = true;
            }
        } else {
            in_span = false;
            if known_names.contains(&lowered) {
                mentions += 1;
            }
        }
    }
    mentions
}

/// The speaker-role axis. The role gate has already refused everything but
/// User and Assistant; between those two the owner's own words are the
/// stronger first-party claim source, so they carry the higher weight.
const fn role_weight(role: DreamerTurnRole) -> f32 {
    match role {
        DreamerTurnRole::User => 1.0,
        DreamerTurnRole::Assistant => 0.6,
        _ => 0.0,
    }
}

/// Scores ONE turn and rules on it. Pure: same inputs, same verdict, no
/// storage, no clock, no model.
///
/// Five axes, each landing in `[0, 1]`:
///
/// * `len` — token count against `LEN_SATURATION_TOKENS`.
/// * `ttr` — type/token ratio, SCALED BY `len`. The raw ratio is degenerate
///   at the short end: `"ok"` has perfect lexical variety and no information,
///   and an unscaled ratio would score it above a repetitive paragraph. The
///   scaling is what makes the axis mean "variety worth having" rather than
///   "variety per token".
/// * `entity_density` — mentions per token against
///   `ENTITY_DENSITY_SATURATION`, over a denominator floored at
///   `ENTITY_DENSITY_MIN_TOKENS`. Deliberately NOT scaled by length the way
///   the two axes above are: naming a specific thing is evidence at any
///   length, and a four-word turn that names two people is exactly the short
///   turn worth keeping. The denominator floor is the narrower correction the
///   axis does need.
/// * `novelty` — one minus the recent-window shingle containment, scaled by
///   `len` for the reason `ttr` is: a one-word turn is trivially unlike
///   everything before it.
/// * `role` — the speaker weight.
///
/// The score is their weighted mean, so it lands in `[0, 1]` too, and
/// `pass = score >= threshold` is a genuine cut on a bounded scale rather
/// than a comparison against an open-ended sum.
#[must_use]
pub fn prefilter_turn(
    config: &PrefilterConfig,
    text: &str,
    role: DreamerTurnRole,
    known_names: &BTreeSet<String>,
    novelty_window: &NoveltyWindow,
) -> PrefilterVerdict {
    let raw = raw_tokens(text);
    let token_count = raw.len();
    let lowered: Vec<String> = raw.iter().copied().map(str::to_lowercase).collect();

    let len = if token_count == 0 {
        0.0
    } else {
        (token_count as f32 / LEN_SATURATION_TOKENS).min(1.0)
    };
    // `len` doubles as the LENGTH CONFIDENCE of the two rate axes that are
    // degenerate at the short end (see the axis notes above).
    let ttr = if token_count == 0 {
        0.0
    } else {
        len * (lowered.iter().collect::<BTreeSet<_>>().len() as f32 / token_count as f32)
    };
    let entity_density = if token_count == 0 {
        0.0
    } else {
        let denominator = token_count.max(ENTITY_DENSITY_MIN_TOKENS) as f32;
        let density = entity_mentions(&raw, known_names) as f32 / denominator;
        (density / ENTITY_DENSITY_SATURATION).min(1.0)
    };
    let novelty = len * novelty_of(&lowered, novelty_window);
    let role_score = role_weight(role);

    let features = BTreeMap::from([
        (PREFILTER_FEATURE_LEN, len),
        (PREFILTER_FEATURE_TTR, ttr),
        (PREFILTER_FEATURE_ENTITY_DENSITY, entity_density),
        (PREFILTER_FEATURE_NOVELTY, novelty),
        (PREFILTER_FEATURE_ROLE, role_score),
    ]);

    let weights = &config.weights;
    let total = weights.total();
    let score = if total > 0.0 {
        (weights.len * len
            + weights.ttr * ttr
            + weights.entity_density * entity_density
            + weights.novelty * novelty
            + weights.role * role_score)
            / total
    } else {
        // Unreachable through a validated config; a zero-mass vector scores
        // zero rather than dividing by it.
        0.0
    };

    PrefilterVerdict {
        pass: score >= config.threshold,
        score,
        features,
        estimated_tokens: estimated_prompt_tokens(text),
    }
}

/// `1 - containment`: the share of this turn's shingles the window has NOT
/// already seen. An empty window makes everything novel; an empty turn has
/// nothing new to say.
fn novelty_of(tokens: &[String], window: &NoveltyWindow) -> f32 {
    let mine = shingles(tokens);
    if mine.is_empty() {
        return 0.0;
    }
    if window.is_empty() {
        return 1.0;
    }
    let seen = mine
        .iter()
        .filter(|shingle| window.contains(shingle.as_str()))
        .count();
    1.0 - (seen as f32 / mine.len() as f32)
}
