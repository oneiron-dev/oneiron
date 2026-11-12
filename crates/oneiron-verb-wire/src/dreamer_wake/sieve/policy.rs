//! Moved from `crates/oneiron/src/dreamer_wake/sieve/policy.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_wake_contract::dreamer_wake::sieve::rules::RuleClass;
use serde::Deserialize;
use serde::Serialize;

pub fn invalid() -> Error {
    Error::InvalidConfig("invalid dreamer sieve policy row".into())
}

/// Per-vault sieve dials. Confidences and band edges are percentages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SievePolicy {
    /// Turns one pass reads; the rest wait for the next pass.
    pub max_turns_per_pass: u32,
    /// Timeline rows one pass's forward scan steps over looking for turns.
    /// The late sweep of the cursor's own second is not capped by it.
    pub max_scan_per_pass: u32,
    /// Bytes of turn text one pass hashes and reads for spans. A turn with
    /// more is read a segment at a time and keeps its place at a segment's
    /// end; the next pass reads on from there, so nothing past the bound is
    /// dropped. A pass's first segment reads whatever the bound, so every
    /// pass moves a read on.
    pub max_text_bytes_per_pass: u32,
    /// Interest of a date span at full confidence.
    pub date_interest: u32,
    /// Interest of a name span at full confidence.
    pub name_interest: u32,
    pub absolute_date_confidence: u8,
    pub relative_date_confidence: u8,
    pub vague_date_confidence: u8,
    pub name_confidence: u8,
    pub initial_name_confidence: u8,
    pub katakana_name_confidence: u8,
    /// Below this a span is low interest; it is still kept.
    pub uncertain_low: u8,
    /// From `uncertain_low` up to this a span is uncertain and owes the
    /// typing rung; at or above it the span is sure.
    pub uncertain_high: u8,
}

impl SievePolicy {
    fn validate(self) -> Result<Self> {
        let confidences = [
            self.absolute_date_confidence,
            self.relative_date_confidence,
            self.vague_date_confidence,
            self.name_confidence,
            self.initial_name_confidence,
            self.katakana_name_confidence,
            self.uncertain_high,
        ];
        if self.max_turns_per_pass == 0
            || self.max_text_bytes_per_pass == 0
            || self.max_scan_per_pass < self.max_turns_per_pass
            || confidences.iter().any(|value| *value > 100)
            || self.uncertain_low > self.uncertain_high
        {
            return Err(invalid());
        }
        Ok(self)
    }

    pub const fn rule_confidence(&self, class: RuleClass) -> u8 {
        match class {
            RuleClass::AbsoluteDate => self.absolute_date_confidence,
            RuleClass::RelativeDate => self.relative_date_confidence,
            RuleClass::VagueDate => self.vague_date_confidence,
            RuleClass::Name => self.name_confidence,
            RuleClass::InitialName => self.initial_name_confidence,
            RuleClass::KatakanaName => self.katakana_name_confidence,
        }
    }

    /// BLAKE3 of the row's canonical JSON: which policy scored a span.
    pub fn digest(&self) -> Result<[u8; 32]> {
        let json = serde_json::to_vec(self).map_err(|_| invalid())?;
        let mut hash = blake3::Hasher::new();
        hash.update(b"oneiron:dreamer-sieve:policy:v1");
        hash.update(&json);
        Ok(*hash.finalize().as_bytes())
    }
}
