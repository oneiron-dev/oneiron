//! The sieve's policy: how much one pass reads, how interesting each kind of
//! span is, how sure each rule is, and where the uncertain band lies. Every
//! number is a setting: the per-pass budgets are `dreamer.sieve.budgets`, the
//! rest `dreamer.sieve.scoring`; the defaults ship as JSON.

use serde::{Deserialize, Serialize};

use super::rules::RuleClass;
use crate::Vault;
use crate::dreamer_wake::setting_keys::{SIEVE_BUDGETS, SIEVE_SCORING};
use crate::error::Result;

#[doc(hidden)]
use oneiron_verb_wire::dreamer_wake::sieve::policy::invalid;

/// Per-vault sieve dials, as the two settings compose them. Confidences and
/// band edges are percentages.
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

    /// The policy whose budgets are `budgets` and whose scoring is `scoring`.
    const fn compose(budgets: SievePassBudgets, scoring: SieveScoring) -> Self {
        Self {
            max_turns_per_pass: budgets.max_turns_per_pass,
            max_scan_per_pass: budgets.max_scan_per_pass,
            max_text_bytes_per_pass: budgets.max_text_bytes_per_pass,
            date_interest: scoring.date_interest,
            name_interest: scoring.name_interest,
            absolute_date_confidence: scoring.absolute_date_confidence,
            relative_date_confidence: scoring.relative_date_confidence,
            vague_date_confidence: scoring.vague_date_confidence,
            name_confidence: scoring.name_confidence,
            initial_name_confidence: scoring.initial_name_confidence,
            katakana_name_confidence: scoring.katakana_name_confidence,
            uncertain_low: scoring.uncertain_low,
            uncertain_high: scoring.uncertain_high,
        }
    }

    /// The policy's per-pass budgets.
    const fn budgets(&self) -> SievePassBudgets {
        SievePassBudgets {
            max_turns_per_pass: self.max_turns_per_pass,
            max_scan_per_pass: self.max_scan_per_pass,
            max_text_bytes_per_pass: self.max_text_bytes_per_pass,
        }
    }

    /// The policy's scoring.
    const fn scoring(&self) -> SieveScoring {
        SieveScoring {
            date_interest: self.date_interest,
            name_interest: self.name_interest,
            absolute_date_confidence: self.absolute_date_confidence,
            relative_date_confidence: self.relative_date_confidence,
            vague_date_confidence: self.vague_date_confidence,
            name_confidence: self.name_confidence,
            initial_name_confidence: self.initial_name_confidence,
            katakana_name_confidence: self.katakana_name_confidence,
            uncertain_low: self.uncertain_low,
            uncertain_high: self.uncertain_high,
        }
    }

    pub(super) const fn rule_confidence(&self, class: RuleClass) -> u8 {
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
    pub(super) fn digest(&self) -> Result<[u8; 32]> {
        let json = serde_json::to_vec(self).map_err(|_| invalid())?;
        let mut hash = blake3::Hasher::new();
        hash.update(b"oneiron:dreamer-sieve:policy:v1");
        hash.update(&json);
        Ok(*hash.finalize().as_bytes())
    }
}

/// The shipped sieve_policy_defaults.json: the defaults of `dreamer.sieve.budgets` and
/// `dreamer.sieve.scoring`.
fn shipped_policy() -> SievePolicy {
    serde_json::from_str(include_str!("sieve_policy_defaults.json"))
        .expect("the shipped sieve_policy_defaults.json decodes")
}

/// The default of `dreamer.sieve.budgets`.
pub(crate) fn shipped_sieve_budgets() -> SievePassBudgets {
    shipped_policy().budgets()
}

/// The default of `dreamer.sieve.scoring`.
pub(crate) fn shipped_sieve_scoring() -> SieveScoring {
    shipped_policy().scoring()
}

/// The policy in force: the budgets and the scoring settings, each its default where unset.
pub(super) fn policy_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<SievePolicy> {
    let budgets = SIEVE_BUDGETS.read_in_txn(vault, txn, &[], None)?.value;
    let scoring = SIEVE_SCORING.read_in_txn(vault, txn, &[], None)?.value;
    SievePolicy::compose(budgets, scoring).validate()
}

impl Vault {
    /// The sieve policy in force: the settings `dreamer.sieve.budgets` and
    /// `dreamer.sieve.scoring`, each the shipped default where unset. A new
    /// value scores the spans read after it; spans already queued keep the
    /// score they were given.
    pub fn dreamer_sieve_policy(&self) -> Result<SievePolicy> {
        let txn = self.store.env.read_txn()?;
        policy_in_txn(self, &txn)
    }
}

/// The sieve's three per-pass work budgets, the setting `dreamer.sieve.budgets`.
/// A holder of the work budget class of `engine.controls` lowers each at once;
/// a raise asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SievePassBudgets {
    /// Turns one pass reads.
    pub max_turns_per_pass: u32,
    /// Timeline rows one pass's forward scan steps over.
    pub max_scan_per_pass: u32,
    /// Bytes of turn text one pass reads.
    pub max_text_bytes_per_pass: u32,
}

impl crate::setting::SettingValue for SievePassBudgets {
    fn check(self) -> Result<Self> {
        if self.max_turns_per_pass == 0
            || self.max_text_bytes_per_pass == 0
            || self.max_scan_per_pass < self.max_turns_per_pass
        {
            return Err(invalid());
        }
        Ok(self)
    }
}

oneiron_setting_contract::each_order!(SievePassBudgets {
    max_turns_per_pass: lower,
    max_scan_per_pass: lower,
    max_text_bytes_per_pass: lower,
});

/// How the sieve scores a span, the setting `dreamer.sieve.scoring`: the
/// owner's. Confidences and band edges are percentages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SieveScoring {
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

impl crate::setting::SettingValue for SieveScoring {
    fn check(self) -> Result<Self> {
        let confidences = [
            self.absolute_date_confidence,
            self.relative_date_confidence,
            self.vague_date_confidence,
            self.name_confidence,
            self.initial_name_confidence,
            self.katakana_name_confidence,
            self.uncertain_high,
        ];
        if confidences.iter().any(|value| *value > 100) || self.uncertain_low > self.uncertain_high
        {
            return Err(invalid());
        }
        Ok(self)
    }
}
