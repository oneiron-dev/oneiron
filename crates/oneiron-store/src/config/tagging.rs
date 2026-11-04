//! Tagging marker configuration and identity validation.

use std::collections::BTreeMap;

use oneiron_contracts::error::{Error, Result};

/// Attempt kind of a tagging marker in the job tables.
pub const TAGGING_MARKER_KIND: &str = "oneironer.tag_turn";

pub const CHECKPOINT_HEX_LEN: usize = 16;

/// The live window's default size in tagger tokens: the serving runtime's
/// default `LIVE_K`.
pub const DEFAULT_LIVE_WINDOW_TOKENS: u32 = 256;
/// The largest live window: the serving runtime's whole input window.
pub const MAX_LIVE_WINDOW_TOKENS: u32 = 2_048;
/// Traces kept per turn by default: the turn's latest few attempts.
pub const DEFAULT_TRACES_PER_TURN: u32 = 4;
/// The most traces a turn may keep.
pub const MAX_TRACES_PER_TURN: u32 = 1_024;
/// How long a trace is kept by default, in store-clock seconds: seven days.
pub const DEFAULT_TRACE_MAX_AGE_SECS: u64 = 7 * 86_400;

/// How much tagging history a vault keeps. A settled marker leaves the job
/// ledger with every try it retried; what stays is its traces, bounded here.
/// A marker still retrying keeps behind it no more failed tries than this
/// keeps traces, and none older.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaggingTraceHistory {
    /// Traces kept per turn, the newest; 0 keeps none.
    pub per_turn: u32,
    /// Store-clock seconds a trace is kept; an older one is pruned.
    pub max_age_secs: u64,
}

impl Default for TaggingTraceHistory {
    fn default() -> Self {
        Self {
            per_turn: DEFAULT_TRACES_PER_TURN,
            max_age_secs: DEFAULT_TRACE_MAX_AGE_SECS,
        }
    }
}

/// What a checked answer does to the vault.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TaggingMode {
    /// The turn's tags are saved: a vault with a tagger saves its tags
    /// (ARCH-0036, serving the tagger).
    #[default]
    Save,
    /// The marker settles and nothing else is written: the test switch.
    Shadow,
}

/// The longest model label the label table admits, in bytes.
const MAX_LABEL_BYTES: usize = 64;

/// Whether the label table may map a label to `kind`: only a kind with a
/// declared identity key can be linked or minted, so a mention of any other
/// kind (an event, say, which the Dreamer mints) stays a tag by leaving its
/// label out of the table.
#[must_use]
pub fn label_kind_admitted(kind: u8) -> bool {
    !crate::identity_hints::identity_fields_for_kind(kind).is_empty()
}

/// Arms the tagging marker on a vault ([`crate::config::VaultConfig::tagging`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaggingMarkerConfig {
    /// The active tagger's checkpoint identity: the first 16 lowercase hex
    /// digits of the SHA-256 of its weights. Half of every marker's dedupe
    /// key, so a new checkpoint owes every turn a new pass.
    pub checkpoint: String,
    /// The served stack the host pins beside the checkpoint, when it pins
    /// one: the first 16 lowercase hex digits of the SHA-256 of the stack's
    /// canonical card, which names the trunk and every head. With it the
    /// stack is the rest of every marker's dedupe key, so a head swap at a
    /// fixed checkpoint owes every turn a new pass as a trunk swap does.
    pub stack: Option<String>,
    /// The live window, in the tagger's tokens: how much earlier text of its
    /// conversation a turn is sent with, never a later turn; 0 sends the turn
    /// alone. Set it to the tagger's own K. The engine cannot count the
    /// tagger's tokens, so this bounds what it sends (at most this many
    /// earlier turns and 16 characters per token); the tagger cuts the
    /// window to its own K. A model card does not declare K yet, so the two
    /// are not checked against each other.
    pub live_window_tokens: u32,
    /// The traces kept once their markers leave the job ledger.
    pub trace_history: TaggingTraceHistory,
    /// Save the tags, or settle in shadow.
    pub mode: TaggingMode,
    /// The label table: model label to the entity kind a span with that
    /// label is linked as. It maps name labels only. A label absent here
    /// stays a tag, and a coreferent span with one takes its antecedent's
    /// link without a lookup: a pronoun's label (a tagger's reference or
    /// pronoun mention class) stays out, so a pronoun is never linked by its
    /// own text. No model's label names sit in engine code; the host
    /// supplies the table.
    pub labels: BTreeMap<String, u8>,
}

impl TaggingMarkerConfig {
    /// A validated marker configuration, with the default live window and
    /// trace history, saving its tags under an empty label table.
    pub fn new(checkpoint: impl Into<String>) -> Result<Self> {
        let config = Self {
            checkpoint: checkpoint.into(),
            stack: None,
            live_window_tokens: DEFAULT_LIVE_WINDOW_TOKENS,
            trace_history: TaggingTraceHistory::default(),
            mode: TaggingMode::Save,
            labels: BTreeMap::new(),
        };
        config.validate()?;
        Ok(config)
    }

    /// Pins the served stack; [`Self::validate`] refuses one that is not 16
    /// lowercase hex digits.
    #[must_use]
    pub fn with_stack(mut self, stack: impl Into<String>) -> Self {
        self.stack = Some(stack.into());
        self
    }

    #[must_use]
    pub fn with_live_window_tokens(mut self, tokens: u32) -> Self {
        self.live_window_tokens = tokens;
        self
    }

    #[must_use]
    pub fn with_trace_history(mut self, history: TaggingTraceHistory) -> Self {
        self.trace_history = history;
        self
    }

    #[must_use]
    pub fn with_mode(mut self, mode: TaggingMode) -> Self {
        self.mode = mode;
        self
    }

    #[must_use]
    pub fn with_labels(mut self, labels: BTreeMap<String, u8>) -> Self {
        self.labels = labels;
        self
    }

    /// Refuses a checkpoint or a stack that is not 16 lowercase hex digits,
    /// a live window past the runtime's input window, a trace history past
    /// its bounds or with no age, and a label table row that is empty,
    /// longer than 64 bytes or maps to a kind with no identity key.
    pub fn validate(&self) -> Result<()> {
        let invalid = |reason: &str| Err(Error::InvalidConfig(reason.to_owned()));
        if !is_checkpoint(&self.checkpoint) {
            return invalid("tagging checkpoint must be 16 lowercase hex digits");
        }
        if self
            .stack
            .as_deref()
            .is_some_and(|stack| !is_checkpoint(stack))
        {
            return invalid("tagging stack must be 16 lowercase hex digits");
        }
        if self.live_window_tokens > MAX_LIVE_WINDOW_TOKENS {
            return invalid("tagging live window must be at most 2048 tokens");
        }
        if self.trace_history.per_turn > MAX_TRACES_PER_TURN {
            return invalid("tagging trace history keeps at most 1024 traces per turn");
        }
        if self.trace_history.max_age_secs == 0 {
            return invalid("tagging trace history max age must be greater than zero");
        }
        for (label, kind) in &self.labels {
            if label.is_empty() || label.len() > MAX_LABEL_BYTES {
                return invalid("a tagging label must be 1 to 64 bytes");
            }
            if !label_kind_admitted(*kind) {
                return invalid("a tagging label maps to a kind with no identity key");
            }
        }
        Ok(())
    }
}

/// Whether `value` is 16 lowercase hex digits: the form of a checkpoint and
/// of a stack identity.
pub fn is_checkpoint(value: &str) -> bool {
    value.len() == CHECKPOINT_HEX_LEN
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}
