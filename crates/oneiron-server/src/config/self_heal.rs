//! The `[self_heal]` section: the model-graded detectors this deployment runs
//! over its retrieval telemetry (ARCH-0066 tiers 2 and 3, OF-418). Each
//! `[self_heal.detectors.<family>]` names the event class it raises, its tier,
//! and the prompt and rubric its question asks. Canon ships no detector
//! wording, so none runs until the owner writes one.
//!
//! - `t3` judges each completed window of runs at once; its findings are the
//!   ones the owner labels. Once `consecutive` positive and one negative are
//!   labeled, the pass registers a T2 of the family that also grades each
//!   window, shown the labeled findings, until a shipped closed-form T1
//!   reproduces every label; the `t3` keeps running.
//! - `t2` asks per run and raises on `consecutive` positive runs in a row.
//!   Once the owner has labeled `consecutive` positive and one negative `t3`
//!   finding of the same family, the labeled findings go with each question.
//! - `session` judges one conversation's runs once it has gone quiet.

use std::collections::BTreeMap;

use oneiron::self_heal::DiagnosticEventClass;
use oneiron::self_heal::tiered::{DetectorPolicy, ProposedTier};
use serde::Deserialize;

const DEFAULT_WINDOW_SECS: u64 = 3_600;

/// Resolved `[self_heal]` section.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SelfHealConfig {
    /// The detectors, by family.
    pub detectors: BTreeMap<String, DetectorConfig>,
}

/// One `[self_heal.detectors.<family>]` table.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DetectorConfig {
    /// The diagnostic event class a raised finding carries, as its wire
    /// spelling (`retrieval_miss`, `silent_conversation_degradation`, ...).
    pub class: String,
    #[serde(default)]
    pub tier: DetectorTier,
    /// What the detector looks for.
    pub prompt: String,
    /// How a positive is told from a negative.
    pub rubric: String,
    /// Runs a window needs, and for `t2` the positive runs in a row that
    /// raise; for `t2` and `t3` it is also how many labeled positives teach
    /// a T2.
    pub consecutive: usize,
    /// For `t2` and `t3`, the length of one window; for `session`, how long
    /// a conversation stays quiet before it is judged.
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
}

/// Which grade a detector runs.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DetectorTier {
    T2,
    #[default]
    T3,
    Session,
}

impl DetectorTier {
    /// The engine tier its questions and findings are keyed by.
    #[must_use]
    pub fn proposed(self) -> ProposedTier {
        match self {
            Self::T2 => ProposedTier::PromptClassifier,
            Self::T3 => ProposedTier::Judge,
            Self::Session => ProposedTier::SessionJudge,
        }
    }
}

fn default_window_secs() -> u64 {
    DEFAULT_WINDOW_SECS
}

impl DetectorConfig {
    /// The engine policy for `family`.
    ///
    /// # Errors
    ///
    /// An unknown or unraisable class, or wording the engine refuses.
    pub fn policy(&self, family: &str) -> anyhow::Result<DetectorPolicy> {
        let class = DiagnosticEventClass::from_wire(&self.class)
            // An agent-health event carries a signal no detector supplies.
            .filter(|class| *class != DiagnosticEventClass::AgentHealth)
            .ok_or_else(|| {
                anyhow::anyhow!("self_heal.detectors.{family}.class is not a raisable class")
            })?;
        let policy = DetectorPolicy {
            family: family.to_owned(),
            class,
            prompt: self.prompt.clone(),
            rubric: self.rubric.clone(),
            consecutive: self.consecutive,
        };
        policy.question(self.tier.proposed(), (0, 0)).map_err(|_| {
            anyhow::anyhow!(
                "self_heal.detectors.{family} needs a token family, a prompt and a rubric \
                 within the question bound, and consecutive in 1..=64"
            )
        })?;
        Ok(policy)
    }
}

impl SelfHealConfig {
    pub(super) fn apply_override(&mut self, over: SelfHealConfigOverride) {
        if let Some(detectors) = over.detectors {
            self.detectors = detectors;
        }
    }

    pub(super) fn validate(&self) -> anyhow::Result<()> {
        for (family, detector) in &self.detectors {
            anyhow::ensure!(
                detector.window_secs > 0,
                "self_heal.detectors.{family}.window_secs must be at least 1"
            );
            detector.policy(family)?;
        }
        Ok(())
    }
}

/// One layer's `[self_heal]` keys. A layer that names detectors replaces the
/// whole set.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(super) struct SelfHealConfigOverride {
    pub(super) detectors: Option<BTreeMap<String, DetectorConfig>>,
}
