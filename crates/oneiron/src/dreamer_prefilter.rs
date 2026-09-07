//! ORF-2 / OF-361 — the BudgetMem statistical PRE-FILTER: the cheap screen
//! that decides what is worth extracting BEFORE a token is spent.
//!
//! # Where it sits
//!
//! The batch tier plans a Dreamer round as `scan_dirty_turns` → Phase-1
//! `plan_partitions`. Until now the only pre-extraction filter was GATE-10's
//! role gate ([`dreamer_extraction_role_admissible`]), which answers
//! *eligibility*: a System or Tool turn may never seed a first-party claim.
//! This module answers the second, different question — *value*: of the turns
//! that MAY be extracted, which ones are worth the extraction budget.
//!
//! The two compose in that order and never merge. The role gate runs inside
//! the scan (`enumerate_admissible_turns`); the screen runs at the top of both
//! partition planners, over what the scan already admitted. A turn the role
//! gate refused is never scored, and a turn the screen skipped was already
//! role-admissible.
//!
//! # What it is not
//!
//! * **Not a security gate.** It is a budget estimate. Every failure mode
//!   resolves toward KEEPING work: an unreadable body passes unscored, an
//!   absent config row bootstraps to the compiled default, and a screen that
//!   cannot reconstruct a round writes no receipts rather than a wrong one.
//! * **Not a selection authority.** It NEVER touches the watermark scan, the
//!   snapshot fence, `planned_turn_ids`, or `advance_watermark_to`. Skipped
//!   turns are still consumed by the round and still advance the cursor, so a
//!   skip costs the turn its extraction, not its place in the log — the
//!   [`reopen_prefilter_rescan`] door re-sweeps them on demand.
//! * **Not an LLM caller.** The scorer is pure arithmetic over the turn body.
//!   This module imports no model surface, by design and by test.
//!
//! # The shipped default is a no-op
//!
//! [`PrefilterConfig::default`] is `enabled` with `threshold = 0.0`, and a
//! verdict passes when `score >= threshold`. Every score is in `[0, 1]`, so
//! the default screens, scores, and drops NOTHING: planning is byte-identical
//! and no receipt is written. Turning a lossy filter on is an explicit
//! operator act ([`Vault::set_prefilter_config`]), never a side effect of
//! upgrading. The scores are still computed under the default so an operator
//! can watch the distribution before choosing a cut.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::dreamer_consolidation::{
    WorkingSetTurn, advance_watermark, decode_turn_body, partition_round_hash,
};
use crate::dreamer_runner::{DreamerConsolidationScope, DreamerTurnRole, dreamer_turn_role};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::receipt::{
    FIELD_PREFILTER_DECISION, FIELD_PREFILTER_FEATURE_PREFIX, FIELD_PREFILTER_PASSED,
    FIELD_PREFILTER_PHASE, FIELD_PREFILTER_ROUND, FIELD_PREFILTER_SCANNED, FIELD_PREFILTER_SCORE,
    FIELD_PREFILTER_SKIPPED, FIELD_PREFILTER_THRESHOLD, FIELD_PREFILTER_TOKENS_SAVED,
    FIELD_PREFILTER_TURN, MAX_RECEIPT_QUERY_SCAN, ReceiptKind, ReceiptQuery, ReceiptRecord,
    hex_lower, retain_newest_receipt,
};
use crate::registry::ENTITY_TYPE_TURN;

// ---------------------------------------------------------------------------
// Keyspace (module-local, on `vault_meta` — the `dreamer_consolidation`
// support.rs prefix precedent; `dreamer:prefilter:` was a free namespace)
// ---------------------------------------------------------------------------

/// Single active config row (the `retr_blend_weights:v0:active` precedent).
const PREFILTER_CONFIG_KEY: &[u8] = b"dreamer:prefilter:config:v1";
/// One SKIP receipt row per screened-out turn: `prefix || round_hash(32) || turn_id(16)`.
const PREFILTER_SKIP_PREFIX: &[u8] = b"dreamer:prefilter:skip:v1:";
/// One ROLLUP receipt row per screened round: `prefix || round_hash(32)`.
const PREFILTER_ROUND_PREFIX: &[u8] = b"dreamer:prefilter:round:v1:";

const PREFILTER_CONFIG_VERSION: u8 = 1;
const PREFILTER_RECEIPT_VERSION: u8 = 1;

const PREFILTER_ROUND_HASH_LEN: usize = 32;
const PREFILTER_TURN_ID_LEN: usize = 16;

/// Value of the receipt `phase` field: which pre-extraction stage ruled.
/// Pinned here rather than in the receipt kernel because it is this writer's
/// own vocabulary, not part of the family's field ABI.
pub const PREFILTER_PHASE: &str = "prefilter";
/// `outcome` of a per-turn SKIP receipt.
pub const PREFILTER_DECISION_SKIP: &str = "skip";
/// `decision` field value of a turn the screen kept.
pub const PREFILTER_DECISION_PASS: &str = "pass";
/// `outcome` of the per-round ROLLUP receipt.
pub const PREFILTER_OUTCOME_SCREENED: &str = "screened";

const PREFILTER_SKIP_TRACE: &str = "dreamer.prefilter.skip";
const PREFILTER_ROUND_TRACE: &str = "dreamer.prefilter.round";

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
const NOVELTY_WINDOW_TURNS: usize = 8;
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
// Config
// ---------------------------------------------------------------------------

/// Relative pull of each screening axis. Every weight is finite and
/// non-negative and the total mass is positive; the score is the weighted mean
/// of the axes, so it stays in `[0, 1]` whatever the weights are.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PrefilterWeights {
    /// How much sheer length is worth.
    pub len: f32,
    /// How much lexical variety is worth.
    pub ttr: f32,
    /// How much naming specific things is worth.
    pub entity_density: f32,
    /// How much saying something not just said is worth.
    pub novelty: f32,
    /// How much the speaker's role is worth.
    pub role: f32,
}

impl Default for PrefilterWeights {
    /// Entity density and novelty carry the most weight because they are the
    /// two axes that separate "a fact was stated" from "words were emitted";
    /// length and variety are supporting evidence; role is a small tilt toward
    /// the owner's own turns.
    fn default() -> Self {
        Self {
            len: 0.20,
            ttr: 0.15,
            entity_density: 0.30,
            novelty: 0.25,
            role: 0.10,
        }
    }
}

impl PrefilterWeights {
    /// The axes in receipt/feature order, for validation and scoring.
    fn axes(&self) -> [(&'static str, f32); 5] {
        [
            (PREFILTER_FEATURE_LEN, self.len),
            (PREFILTER_FEATURE_TTR, self.ttr),
            (PREFILTER_FEATURE_ENTITY_DENSITY, self.entity_density),
            (PREFILTER_FEATURE_NOVELTY, self.novelty),
            (PREFILTER_FEATURE_ROLE, self.role),
        ]
    }

    /// Total weight mass. Validation requires this to be positive.
    #[must_use]
    pub fn total(&self) -> f32 {
        self.len + self.ttr + self.entity_density + self.novelty + self.role
    }
}

/// Durable screening policy, read from `vault_meta` on every planning round so
/// a threshold change takes effect without a recompile or a restart.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PrefilterConfig {
    /// `false` disables the screen entirely: the planners take their input
    /// unchanged and read nothing extra (invariant I4).
    pub enabled: bool,
    /// Score at or above which a turn is kept, in `[0, 1]`. `0.0` keeps
    /// everything — the shipped default.
    pub threshold: f32,
    /// Relative pull of each axis.
    pub weights: PrefilterWeights,
}

impl Default for PrefilterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: 0.0,
            weights: PrefilterWeights::default(),
        }
    }
}

/// The durable row shape. The public value type carries no `version` field so
/// callers never have to know one; the row does, so an unknown schema is
/// refused instead of silently reinterpreted.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct PrefilterConfigRow {
    version: u8,
    enabled: bool,
    threshold: f32,
    weights: PrefilterWeights,
}

fn invalid_prefilter_config(reason: impl Into<String>) -> Error {
    Error::InvalidConfig(reason.into())
}

/// Refuses a config that cannot produce a meaningful score.
///
/// Non-finite (NaN/±Inf) and out-of-`[0, 1]` thresholds, negative or
/// non-finite weights, and an all-zero weight vector are all rejected here —
/// BEFORE the row is encoded, so a refused config is never persisted.
///
/// # Errors
///
/// [`Error::InvalidConfig`] naming the offending field.
pub fn validate_prefilter_config(config: &PrefilterConfig) -> Result<()> {
    if !config.threshold.is_finite() {
        return Err(invalid_prefilter_config(
            "dreamer prefilter threshold must be finite",
        ));
    }
    if !(0.0..=1.0).contains(&config.threshold) {
        return Err(invalid_prefilter_config(format!(
            "dreamer prefilter threshold must be within [0, 1], got {}",
            config.threshold
        )));
    }
    for (name, weight) in config.weights.axes() {
        if !weight.is_finite() {
            return Err(invalid_prefilter_config(format!(
                "dreamer prefilter {name} weight must be finite"
            )));
        }
        if weight < 0.0 {
            return Err(invalid_prefilter_config(format!(
                "dreamer prefilter {name} weight must be non-negative, got {weight}"
            )));
        }
    }
    if config.weights.total() <= 0.0 {
        return Err(invalid_prefilter_config(
            "dreamer prefilter weights must have positive total mass",
        ));
    }
    Ok(())
}

fn decode_prefilter_config(raw: &[u8]) -> Result<PrefilterConfig> {
    let row: PrefilterConfigRow = rmp_serde::from_slice(raw)
        .map_err(|_| invalid_prefilter_config("dreamer prefilter config row is undecodable"))?;
    if row.version != PREFILTER_CONFIG_VERSION {
        return Err(invalid_prefilter_config(
            "unsupported dreamer prefilter config schema",
        ));
    }
    let config = PrefilterConfig {
        enabled: row.enabled,
        threshold: row.threshold,
        weights: row.weights,
    };
    // A landed row is validated on the way OUT as well as on the way in: the
    // setter is the only sanctioned writer, but a corrupt or foreign row must
    // not be able to hand the planner a NaN threshold.
    validate_prefilter_config(&config)?;
    Ok(config)
}

fn encode_prefilter_config(config: &PrefilterConfig) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(&PrefilterConfigRow {
        version: PREFILTER_CONFIG_VERSION,
        enabled: config.enabled,
        threshold: config.threshold,
        weights: config.weights,
    })
    .map_err(|_| invalid_prefilter_config("dreamer prefilter config row encode failed"))
}

impl Vault {
    /// Reads the active screening policy; an absent row IS the compiled
    /// [`PrefilterConfig::default`].
    ///
    /// # Errors
    ///
    /// Storage errors, or [`Error::InvalidConfig`] when the landed row is
    /// undecodable, of an unknown schema, or out of range.
    pub fn prefilter_config(&self) -> Result<PrefilterConfig> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.vault_meta.get(&rtxn, PREFILTER_CONFIG_KEY)? else {
            return Ok(PrefilterConfig::default());
        };
        decode_prefilter_config(&raw)
    }

    /// [`Vault::prefilter_config`] through a caller-owned write transaction,
    /// so the in-transaction session-close planner screens under exactly the
    /// policy its own commit will be judged by.
    pub(crate) fn prefilter_config_in_txn(&self, txn: &heed::RwTxn<'_>) -> Result<PrefilterConfig> {
        let Some(raw) = self.store.vault_meta.get(txn, PREFILTER_CONFIG_KEY)? else {
            return Ok(PrefilterConfig::default());
        };
        decode_prefilter_config(&raw)
    }

    /// Persists a screening policy. Validation runs FIRST and a refused
    /// config never reaches the store, so a bad tuning attempt leaves the
    /// previous policy live rather than wedging the planner.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] on a non-finite or out-of-range threshold, a
    /// non-finite or negative weight, or a zero-mass weight vector; storage
    /// errors otherwise.
    pub fn set_prefilter_config(&self, config: PrefilterConfig) -> Result<()> {
        validate_prefilter_config(&config)?;
        let encoded = encode_prefilter_config(&config)?;
        let mut wtxn = self.store.env.write_txn()?;
        self.store
            .vault_meta
            .put(&mut wtxn, PREFILTER_CONFIG_KEY, &encoded)?;
        wtxn.commit()?;
        Ok(())
    }
}

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
    recent: VecDeque<BTreeSet<String>>,
}

impl NoveltyWindow {
    /// An empty window: the first turn of a batch is wholly novel.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Admits one turn's text, evicting the oldest beyond
    /// [`NOVELTY_WINDOW_TURNS`].
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
fn entity_mentions(tokens: &[&str], known_names: &BTreeSet<String>) -> usize {
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
/// * `len` — token count against [`LEN_SATURATION_TOKENS`].
/// * `ttr` — type/token ratio, SCALED BY `len`. The raw ratio is degenerate
///   at the short end: `"ok"` has perfect lexical variety and no information,
///   and an unscaled ratio would score it above a repetitive paragraph. The
///   scaling is what makes the axis mean "variety worth having" rather than
///   "variety per token".
/// * `entity_density` — mentions per token against
///   [`ENTITY_DENSITY_SATURATION`], over a denominator floored at
///   [`ENTITY_DENSITY_MIN_TOKENS`]. Deliberately NOT scaled by length the way
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

// ---------------------------------------------------------------------------
// The screen over planner input
// ---------------------------------------------------------------------------

/// One scanned turn's verdict, in scan order.
#[derive(Debug, Clone, PartialEq)]
pub struct PrefilterTurnVerdict {
    pub turn_id: EntityId,
    pub verdict: PrefilterVerdict,
}

/// The result of screening ONE planner input batch.
///
/// `kept` is the planner's new input; everything else is the accounting the
/// receipts project. `scanned == passed + skipped` always, and `kept.len() ==
/// passed`.
#[derive(Debug, Clone, PartialEq)]
pub struct PrefilterScreen {
    /// Whether the screen ran at all. `false` = the config disabled it and
    /// `kept` is the input verbatim.
    pub enabled: bool,
    /// The threshold the verdicts were ruled against.
    pub threshold: f32,
    /// Planner input after the screen, in the input's own order.
    pub kept: Vec<WorkingSetTurn>,
    /// Every scanned turn's verdict, in scan order. Empty when disabled.
    pub verdicts: Vec<PrefilterTurnVerdict>,
    pub scanned: usize,
    pub passed: usize,
    pub skipped: usize,
    /// Summed [`estimated_prompt_tokens`] of the SKIPPED turns — the budget
    /// this round did not spend.
    pub estimated_tokens_saved: u64,
}

impl PrefilterScreen {
    /// The pass-through screen: the input, unchanged and unjudged.
    fn disabled(turns: &[WorkingSetTurn], threshold: f32) -> Self {
        Self {
            enabled: false,
            threshold,
            kept: turns.to_vec(),
            verdicts: Vec::new(),
            scanned: turns.len(),
            passed: turns.len(),
            skipped: 0,
            estimated_tokens_saved: 0,
        }
    }
}

/// One screening input: the working-set row plus its body text, or `None` when
/// the body could not be read.
pub type PrefilterScreenInput = (WorkingSetTurn, Option<String>);

/// Screens a batch. Pure — every storage read happened in the caller.
///
/// Turns are scored in the batch's own order because the novelty window is
/// causal: turn *n* is judged against turns *0..n*, never against turns that
/// had not been said yet.
#[must_use]
pub fn screen_turn_inputs(
    config: &PrefilterConfig,
    inputs: &[PrefilterScreenInput],
    known_names: &BTreeSet<String>,
) -> PrefilterScreen {
    let mut screen = PrefilterScreen {
        enabled: true,
        threshold: config.threshold,
        kept: Vec::with_capacity(inputs.len()),
        verdicts: Vec::with_capacity(inputs.len()),
        scanned: inputs.len(),
        passed: 0,
        skipped: 0,
        estimated_tokens_saved: 0,
    };
    let mut window = NoveltyWindow::new();
    for (turn, text) in inputs {
        let verdict = match text {
            Some(text) => {
                let verdict = prefilter_turn(config, text, turn.role, known_names, &window);
                window.observe(text);
                verdict
            }
            None => PrefilterVerdict::unscored_pass(),
        };
        if verdict.pass {
            screen.passed += 1;
            screen.kept.push(*turn);
        } else {
            screen.skipped += 1;
            screen.estimated_tokens_saved = screen
                .estimated_tokens_saved
                .saturating_add(verdict.estimated_tokens);
        }
        screen.verdicts.push(PrefilterTurnVerdict {
            turn_id: turn.turn_id,
            verdict,
        });
    }
    screen
}

/// Turn body text for screening, or `None` when the row is absent or is not a
/// TURN.
///
/// The type check is the custody seal restated in the strongest available
/// form: the screen reads TURN bodies and nothing else, so a row of any other
/// type — a SECRET_CUSTODY carrier most of all — yields no text and the turn
/// passes unscored.
fn screen_text_from_raw(raw: &[u8]) -> Option<(DreamerTurnRole, u64, Option<String>)> {
    let header = EntityMetadataHeader::parse(raw)?;
    if header.entity_type != ENTITY_TYPE_TURN {
        return None;
    }
    let facts = decode_turn_body(&raw[ENTITY_METADATA_HEADER_LEN.min(raw.len())..]);
    Some((
        dreamer_turn_role(facts.speaker.as_deref()),
        header.learned_at,
        facts.text,
    ))
}

/// The POST-ROLE-GATE value screen over a partition planner's input.
///
/// Called at the top of [`crate::dreamer_consolidation::plan_partitions`]. The
/// input has already passed GATE-10; this decides which of it is worth
/// extracting. A disabled config short-circuits before any read, so the
/// disabled path is byte-identical planning at zero added cost.
///
/// # Errors
///
/// Storage errors, or [`Error::InvalidConfig`] when the landed config row is
/// unusable.
pub(crate) fn prefilter_partition_input(
    vault: &Vault,
    turns: &[WorkingSetTurn],
) -> Result<PrefilterScreen> {
    let config = vault.prefilter_config()?;
    if !config.enabled {
        return Ok(PrefilterScreen::disabled(turns, config.threshold));
    }
    let mut inputs = Vec::with_capacity(turns.len());
    for turn in turns {
        let text = match vault.get_raw(&turn.turn_id)? {
            Some(raw) => screen_text_from_raw(&raw).and_then(|(_, _, text)| text),
            None => None,
        };
        inputs.push((*turn, text));
    }
    Ok(screen_turn_inputs(&config, &inputs, &BTreeSet::new()))
}

/// [`prefilter_partition_input`] through a caller-owned write transaction —
/// the ONE-1685 session close screens the rows it has staged but not yet
/// committed, under the same policy and the same arithmetic, so an
/// in-transaction screen and a committed-state screen of the same turns keep
/// the byte-identical-partition-keys claim on `plan_partitions_in_txn` true.
///
/// # Errors
///
/// Storage errors, or [`Error::InvalidConfig`] when the landed config row is
/// unusable.
pub(crate) fn prefilter_partition_input_in_txn(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    turns: &[WorkingSetTurn],
) -> Result<PrefilterScreen> {
    let config = vault.prefilter_config_in_txn(txn)?;
    if !config.enabled {
        return Ok(PrefilterScreen::disabled(turns, config.threshold));
    }
    let mut inputs = Vec::with_capacity(turns.len());
    for turn in turns {
        let text = match vault.get_raw_in(txn, &turn.turn_id)? {
            Some(raw) => screen_text_from_raw(&raw).and_then(|(_, _, text)| text),
            None => None,
        };
        inputs.push((*turn, text));
    }
    Ok(screen_turn_inputs(&config, &inputs, &BTreeSet::new()))
}

// ---------------------------------------------------------------------------
// The rescan door (I7)
// ---------------------------------------------------------------------------

/// Re-opens screened-out turns for a fresh sweep by REWINDING the scope
/// watermark to just before `from_learned_at`.
///
/// A skip costs a turn its extraction, not its place in the log: the round
/// that skipped it still advanced the cursor past it (invariant I2, which is
/// what stops a low-value turn from being re-scanned forever). The cost of
/// that guarantee is that a threshold change cannot retroactively rescue what
/// an earlier threshold dropped — this door is how an operator asks for that
/// re-sweep explicitly.
///
/// It writes an ABSOLUTE cursor position through
/// [`advance_watermark`], which is the one settlement path that does not
/// refuse a backwards move (the in-transaction settler
/// `advance_watermark_in_txn` fail-closes on rewind, exactly so that a round
/// cannot quietly re-plan consumed work). `from_learned_at` is INCLUSIVE: the
/// next round re-scans every admissible turn at or after that second, and
/// `0` is a full re-sweep from the beginning of the log.
///
/// Re-planning is safe rather than duplicative because a consolidation attempt
/// is advisory identity — a re-swept batch that matches an earlier one exactly
/// coalesces on the `partition_round_hash` dedupe key.
///
/// # Errors
///
/// Storage errors.
pub fn reopen_prefilter_rescan(
    vault: &Vault,
    scope: DreamerConsolidationScope,
    from_learned_at: u64,
) -> Result<()> {
    advance_watermark(vault, scope, from_learned_at.saturating_sub(1))
}

// ---------------------------------------------------------------------------
// Receipts
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PrefilterSkipRow {
    version: u8,
    occurred_at: u64,
    score: f32,
    threshold: f32,
    estimated_tokens: u64,
    features: BTreeMap<String, f32>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct PrefilterRoundRow {
    version: u8,
    occurred_at: u64,
    scanned: u64,
    passed: u64,
    skipped: u64,
    estimated_tokens_saved: u64,
    threshold: f32,
}

fn prefilter_skip_key(round: &[u8; 32], turn: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(
        PREFILTER_SKIP_PREFIX.len() + PREFILTER_ROUND_HASH_LEN + PREFILTER_TURN_ID_LEN,
    );
    key.extend_from_slice(PREFILTER_SKIP_PREFIX);
    key.extend_from_slice(round);
    key.extend_from_slice(turn.as_bytes());
    key
}

fn prefilter_round_key(round: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(PREFILTER_ROUND_PREFIX.len() + PREFILTER_ROUND_HASH_LEN);
    key.extend_from_slice(PREFILTER_ROUND_PREFIX);
    key.extend_from_slice(round);
    key
}

/// Writes the round's screening receipts inside the CALLER's transaction — the
/// same commit as the round's enqueue and watermark advance.
///
/// That placement is what makes the receipts exactly-once: they exist if and
/// only if the round they describe committed, and a replay of the same batch
/// re-derives the same keys (`partition_round_hash || turn_id`) and replaces
/// its previous receipts rather than retaining stale skips or duplicates.
///
/// Per-turn rows are written for SKIPS ONLY. A pass costs nothing to explain
/// and would put one row in the store per extracted turn forever; the passes
/// ride the round rollup as counts. A disabled round or one that skipped
/// nothing leaves no receipts, removing any from an earlier same-batch screen.
/// Under the shipped default policy that is every round, so the screen leaves
/// no trace until an operator asks it to filter.
///
/// # Errors
///
/// Storage errors, or [`Error::InvalidConfig`] when the landed config row is
/// unusable.
pub(crate) fn write_prefilter_receipts_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    planned_turn_ids: &[EntityId],
    now: u64,
) -> Result<()> {
    if planned_turn_ids.is_empty() {
        return Ok(());
    }
    let config = vault.prefilter_config_in_txn(wtxn)?;

    let mut turns = Vec::with_capacity(planned_turn_ids.len());
    let mut inputs = Vec::with_capacity(planned_turn_ids.len());
    for turn_id in planned_turn_ids {
        let Some(raw) = vault.get_raw_in(&*wtxn, turn_id)? else {
            unreconstructable_round(turn_id);
            return Ok(());
        };
        let Some((role, learned_at, text)) = screen_text_from_raw(&raw) else {
            unreconstructable_round(turn_id);
            return Ok(());
        };
        let turn = WorkingSetTurn {
            turn_id: *turn_id,
            role,
            learned_at,
            conversation: None,
        };
        turns.push(turn);
        inputs.push((turn, text));
    }

    // The round identity is `partition_round_hash` over the WHOLE fenced batch
    // — the same function the attempt dedupe key is built from, applied at
    // round granularity rather than per partition. It is reproducible from the
    // fenced turn list alone, which is what lets a replay replace itself.
    let round = partition_round_hash(&turns);

    // Reconstruct the whole round before touching its receipts: an unreadable
    // turn must not leave a partially cleared round. These exact keys cover
    // every possible prior skip of this batch without scanning other rounds.
    // Cleanup and replacement share the caller's enqueue/watermark transaction,
    // including when the new policy disables the screen or keeps every turn.
    for turn in &turns {
        vault
            .store
            .vault_meta
            .delete(wtxn, &prefilter_skip_key(&round, &turn.turn_id))?;
    }
    vault
        .store
        .vault_meta
        .delete(wtxn, &prefilter_round_key(&round))?;
    if !config.enabled {
        return Ok(());
    }
    let screen = screen_turn_inputs(&config, &inputs, &BTreeSet::new());
    if screen.skipped == 0 {
        return Ok(());
    }

    for entry in &screen.verdicts {
        if entry.verdict.pass {
            continue;
        }
        let row = PrefilterSkipRow {
            version: PREFILTER_RECEIPT_VERSION,
            occurred_at: now,
            score: entry.verdict.score,
            threshold: screen.threshold,
            estimated_tokens: entry.verdict.estimated_tokens,
            features: entry
                .verdict
                .features
                .iter()
                .map(|(name, value)| ((*name).to_owned(), *value))
                .collect(),
        };
        let encoded = rmp_serde::to_vec_named(&row).map_err(|_| {
            invalid_prefilter_config("dreamer prefilter skip receipt encode failed")
        })?;
        vault
            .store
            .vault_meta
            .put(wtxn, &prefilter_skip_key(&round, &entry.turn_id), &encoded)?;
    }

    let rollup = PrefilterRoundRow {
        version: PREFILTER_RECEIPT_VERSION,
        occurred_at: now,
        scanned: screen.scanned as u64,
        passed: screen.passed as u64,
        skipped: screen.skipped as u64,
        estimated_tokens_saved: screen.estimated_tokens_saved,
        threshold: screen.threshold,
    };
    let encoded = rmp_serde::to_vec_named(&rollup)
        .map_err(|_| invalid_prefilter_config("dreamer prefilter round receipt encode failed"))?;
    vault
        .store
        .vault_meta
        .put(wtxn, &prefilter_round_key(&round), &encoded)?;
    Ok(())
}

/// A round whose turn rows cannot be re-read in the close transaction is not
/// receipted at all.
///
/// The rows were enumerated by the fence in THIS transaction, so this is a
/// corrupt-index shape rather than a race — but receipts are observability,
/// and failing a session close over one would trade a durable close for a
/// bookkeeping row. A partial rollup would understate the savings and a
/// mis-keyed skip row would be unjoinable with its round, so the honest answer
/// is silence plus a warning.
fn unreconstructable_round(turn_id: &EntityId) {
    tracing::warn!(
        turn = %turn_id.to_hex(),
        "dreamer prefilter round not receipted: planned turn row is unreadable"
    );
}

fn prefilter_skip_receipt(round: &[u8], turn: &EntityId, row: &PrefilterSkipRow) -> ReceiptRecord {
    let round_hex = hex_lower(round);
    let turn_hex = turn.to_hex();
    let mut fields = BTreeMap::from([
        (FIELD_PREFILTER_PHASE.to_owned(), PREFILTER_PHASE.to_owned()),
        (
            FIELD_PREFILTER_DECISION.to_owned(),
            PREFILTER_DECISION_SKIP.to_owned(),
        ),
        (
            FIELD_PREFILTER_SCORE.to_owned(),
            format!("{:.6}", row.score),
        ),
        (
            FIELD_PREFILTER_THRESHOLD.to_owned(),
            format!("{:.6}", row.threshold),
        ),
        (
            FIELD_PREFILTER_TOKENS_SAVED.to_owned(),
            row.estimated_tokens.to_string(),
        ),
        (FIELD_PREFILTER_ROUND.to_owned(), round_hex.clone()),
        (FIELD_PREFILTER_TURN.to_owned(), turn_hex.clone()),
    ]);
    for (name, value) in &row.features {
        fields.insert(
            format!("{FIELD_PREFILTER_FEATURE_PREFIX}{name}"),
            format!("{value:.6}"),
        );
    }
    ReceiptRecord {
        receipt_id: format!("prefilter:skip:{round_hex}:{turn_hex}"),
        receipt_kind: ReceiptKind::Extraction,
        occurred_at: row.occurred_at,
        actor: None,
        on_behalf_of: None,
        outcome: PREFILTER_DECISION_SKIP.to_owned(),
        job_ref: None,
        trigger_ref: Some(format!("turn:{turn_hex}")),
        policy_trace: vec![PREFILTER_SKIP_TRACE.to_owned()],
        fields,
    }
}

fn prefilter_round_receipt(round: &[u8], row: &PrefilterRoundRow) -> ReceiptRecord {
    let round_hex = hex_lower(round);
    let fields = BTreeMap::from([
        (FIELD_PREFILTER_PHASE.to_owned(), PREFILTER_PHASE.to_owned()),
        (
            FIELD_PREFILTER_DECISION.to_owned(),
            PREFILTER_OUTCOME_SCREENED.to_owned(),
        ),
        (FIELD_PREFILTER_ROUND.to_owned(), round_hex.clone()),
        (FIELD_PREFILTER_SCANNED.to_owned(), row.scanned.to_string()),
        (FIELD_PREFILTER_PASSED.to_owned(), row.passed.to_string()),
        (FIELD_PREFILTER_SKIPPED.to_owned(), row.skipped.to_string()),
        (
            FIELD_PREFILTER_TOKENS_SAVED.to_owned(),
            row.estimated_tokens_saved.to_string(),
        ),
        (
            FIELD_PREFILTER_THRESHOLD.to_owned(),
            format!("{:.6}", row.threshold),
        ),
    ]);
    ReceiptRecord {
        receipt_id: format!("prefilter:round:{round_hex}"),
        receipt_kind: ReceiptKind::Extraction,
        occurred_at: row.occurred_at,
        actor: None,
        on_behalf_of: None,
        outcome: PREFILTER_OUTCOME_SCREENED.to_owned(),
        job_ref: None,
        trigger_ref: None,
        policy_trace: vec![PREFILTER_ROUND_TRACE.to_owned()],
        fields,
    }
}

/// The [`ReceiptKind::Extraction`] projector: per-turn skip rulings and the
/// per-round rollup they belong to.
///
/// Own store, own read transaction, own field class — the additive-projector
/// house pattern the Gate kind already carries four of. The kind gate is
/// applied by the caller in `receipt::family`, as every sibling projector's
/// is, so a single-kind query never pays for a family it did not ask for.
///
/// Both walks are bounded by [`MAX_RECEIPT_QUERY_SCAN`]. The keys are round
/// hashes, which are not time-ordered, so the walk cannot stop early on time
/// the way a ledger-ordered projector can; the newest `query.limit` of the
/// matches is retained as it is everywhere else, and a `job_ref` query stays
/// exhaustive within the walk because that join runs after collection.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on a malformed key or row.
pub(crate) fn prefilter_receipts(
    vault: &Vault,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();

    for (scanned, row) in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, PREFILTER_SKIP_PREFIX)?
        .take(MAX_RECEIPT_QUERY_SCAN + 1)
        .enumerate()
    {
        if scanned == MAX_RECEIPT_QUERY_SCAN {
            note_prefilter_scan_capped("skip");
            break;
        }
        let (key, raw) = row?;
        let (round, turn) = parse_prefilter_skip_key(&key)?;
        let decoded: PrefilterSkipRow = rmp_serde::from_slice(&raw)
            .map_err(|_| Error::CorruptedIndex("dreamer prefilter skip receipt"))?;
        // The key is version-scoped, so a foreign version UNDER a v1 key is
        // corruption rather than a migration.
        if decoded.version != PREFILTER_RECEIPT_VERSION {
            return Err(Error::CorruptedIndex("dreamer prefilter skip receipt"));
        }
        collect_prefilter_receipt(
            &mut out,
            query,
            prefilter_skip_receipt(round, &turn, &decoded),
        );
    }

    for (scanned, row) in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, PREFILTER_ROUND_PREFIX)?
        .take(MAX_RECEIPT_QUERY_SCAN + 1)
        .enumerate()
    {
        if scanned == MAX_RECEIPT_QUERY_SCAN {
            note_prefilter_scan_capped("round");
            break;
        }
        let (key, raw) = row?;
        let round = key
            .get(PREFILTER_ROUND_PREFIX.len()..)
            .filter(|rest| rest.len() == PREFILTER_ROUND_HASH_LEN)
            .ok_or(Error::CorruptedIndex("dreamer prefilter round key"))?;
        let decoded: PrefilterRoundRow = rmp_serde::from_slice(&raw)
            .map_err(|_| Error::CorruptedIndex("dreamer prefilter round receipt"))?;
        if decoded.version != PREFILTER_RECEIPT_VERSION {
            return Err(Error::CorruptedIndex("dreamer prefilter round receipt"));
        }
        collect_prefilter_receipt(&mut out, query, prefilter_round_receipt(round, &decoded));
    }

    Ok(out)
}

fn parse_prefilter_skip_key(key: &[u8]) -> Result<(&[u8], EntityId)> {
    let rest = key
        .get(PREFILTER_SKIP_PREFIX.len()..)
        .filter(|rest| rest.len() == PREFILTER_ROUND_HASH_LEN + PREFILTER_TURN_ID_LEN)
        .ok_or(Error::CorruptedIndex("dreamer prefilter skip key"))?;
    let (round, turn_bytes) = rest.split_at(PREFILTER_ROUND_HASH_LEN);
    let raw: [u8; PREFILTER_TURN_ID_LEN] = turn_bytes
        .try_into()
        .map_err(|_| Error::CorruptedIndex("dreamer prefilter skip key"))?;
    let turn = EntityId::from_bytes(raw)
        .map_err(|_| Error::CorruptedIndex("dreamer prefilter skip key"))?;
    Ok((round, turn))
}

fn collect_prefilter_receipt(
    out: &mut Vec<ReceiptRecord>,
    query: &ReceiptQuery,
    record: ReceiptRecord,
) {
    if !query.matches(&record) {
        return;
    }
    if query.job_ref.is_some() {
        out.push(record);
    } else {
        retain_newest_receipt(out, record, query.limit);
    }
}

/// Surfaces a screening-receipt walk that stopped at the receipt-family work
/// cap: the answer is a bounded PREFIX of the family, not the family.
fn note_prefilter_scan_capped(family: &str) {
    tracing::warn!(
        scan_cap = MAX_RECEIPT_QUERY_SCAN,
        family,
        "dreamer prefilter receipt scan hit the receipt-family work cap; older rows were not projected"
    );
}

#[cfg(test)]
mod tests;
