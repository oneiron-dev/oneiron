//! `[skills.replay_judge]`: the serve replay judge's wording (OF-495,
//! FIX 1091). Every key has shipped text in `prompts/replay_judge.toml`; a
//! layer's key replaces that key alone, and blank text is refused. No key
//! turns replay judging off.

use std::collections::BTreeMap;

use serde::Deserialize;

/// The shipped wording.
const SHIPPED: &str = include_str!("../../../prompts/replay_judge.toml");
/// Where the axis question names its axis.
const AXIS: &str = "{axis}";
/// Where a missing run's objective names its receipt.
const RECEIPT: &str = "{receipt}";
/// Each key's environment variable is this prefix and the key in capitals.
const ENV_PREFIX: &str = "ONEIRON_SKILLS_REPLAY_JUDGE_";

/// The serve replay judge's resolved wording: one question per judgment key
/// the shared skill decisions ask under, the question for one goal axis, and
/// the objective a reserved run whose row is gone is checked on.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReplayJudgeWording {
    pub score: String,
    pub structural: String,
    pub contrastive: String,
    pub preference: String,
    pub honesty: String,
    pub task_success: String,
    pub tradeoff: String,
    pub live_axis: String,
    /// One response on its own task, by the common judge rubric: blind
    /// preference pairs are the responses whose scores are closest.
    pub response_score: String,
    /// The question for one goal axis; `{axis}` is the axis name.
    pub axis_template: String,
    /// The objective a reserved run whose row is gone is checked on;
    /// `{receipt}` is its receipt.
    pub missing_replay_objective_template: String,
}

impl Default for ReplayJudgeWording {
    /// The shipped wording.
    fn default() -> Self {
        toml::from_str(SHIPPED).expect("the shipped replay judge wording parses")
    }
}

impl ReplayJudgeWording {
    /// Each question by the judgment key it is asked under.
    fn judgments(&self) -> [(&'static str, &str); 9] {
        [
            ("score", self.score.as_str()),
            ("structural", self.structural.as_str()),
            ("contrastive", self.contrastive.as_str()),
            ("preference", self.preference.as_str()),
            ("honesty", self.honesty.as_str()),
            ("task_success", self.task_success.as_str()),
            ("tradeoff", self.tradeoff.as_str()),
            ("live_axis", self.live_axis.as_str()),
            ("response_score", self.response_score.as_str()),
        ]
    }

    /// Every key with its text: the questions, then the two templates.
    fn entries(&self) -> impl Iterator<Item = (&'static str, &str)> {
        self.judgments().into_iter().chain([
            ("axis_template", self.axis_template.as_str()),
            (
                "missing_replay_objective_template",
                self.missing_replay_objective_template.as_str(),
            ),
        ])
    }

    /// The questions by the judgment key each is asked under; an axis's
    /// question is [`Self::axis`].
    #[must_use]
    pub fn questions(&self) -> BTreeMap<String, String> {
        self.judgments()
            .into_iter()
            .map(|(key, text)| (key.to_owned(), text.to_owned()))
            .collect()
    }

    /// The question for the goal axis `axis`.
    #[must_use]
    pub fn axis(&self, axis: &str) -> String {
        self.axis_template.replace(AXIS, axis)
    }

    /// The objective the reserved run `receipt`, whose row is gone, is
    /// checked on.
    #[must_use]
    pub fn missing_objective(&self, receipt: &str) -> String {
        self.missing_replay_objective_template
            .replace(RECEIPT, receipt)
    }

    /// Every key and its text, in a fixed order, as 16 hex of their digest:
    /// the judge's revision names it, so changed wording is a new judge.
    #[must_use]
    pub fn digest(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        for (key, text) in self.entries() {
            for part in [key, text] {
                hasher.update(&u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
                hasher.update(part.as_bytes());
            }
        }
        hasher.finalize().to_hex().as_str()[..16].to_owned()
    }

    pub(super) fn apply_override(&mut self, over: ReplayJudgeWordingOverride) {
        let ReplayJudgeWordingOverride {
            score,
            structural,
            contrastive,
            preference,
            honesty,
            task_success,
            tradeoff,
            live_axis,
            response_score,
            axis_template,
            missing_replay_objective_template,
        } = over;
        for (slot, value) in [
            (&mut self.score, score),
            (&mut self.structural, structural),
            (&mut self.contrastive, contrastive),
            (&mut self.preference, preference),
            (&mut self.honesty, honesty),
            (&mut self.task_success, task_success),
            (&mut self.tradeoff, tradeoff),
            (&mut self.live_axis, live_axis),
            (&mut self.response_score, response_score),
            (&mut self.axis_template, axis_template),
            (
                &mut self.missing_replay_objective_template,
                missing_replay_objective_template,
            ),
        ] {
            if let Some(value) = value {
                *slot = value;
            }
        }
    }

    /// Refuses blank wording, and a template without its placeholder.
    pub(super) fn validate(&self) -> anyhow::Result<()> {
        if let Some((key, _)) = self.entries().find(|(_, text)| text.trim().is_empty()) {
            anyhow::bail!("skills.replay_judge.{key} must not be empty");
        }
        if !self.axis_template.contains(AXIS) {
            anyhow::bail!("skills.replay_judge.axis_template must name the axis as {AXIS}");
        }
        if !self.missing_replay_objective_template.contains(RECEIPT) {
            anyhow::bail!(
                "skills.replay_judge.missing_replay_objective_template must name the receipt as {RECEIPT}"
            );
        }
        Ok(())
    }
}

/// One layer's `[skills.replay_judge]` keys: each one set replaces that key
/// alone.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(in crate::config) struct ReplayJudgeWordingOverride {
    score: Option<String>,
    structural: Option<String>,
    contrastive: Option<String>,
    preference: Option<String>,
    honesty: Option<String>,
    task_success: Option<String>,
    tradeoff: Option<String>,
    live_axis: Option<String>,
    response_score: Option<String>,
    axis_template: Option<String>,
    missing_replay_objective_template: Option<String>,
}

/// The environment's `[skills.replay_judge]` keys, each
/// `ONEIRON_SKILLS_REPLAY_JUDGE_<KEY>`; `None` while none is set.
pub(super) fn lookup_replay_judge_override(
    lookup: &mut impl FnMut(&str) -> Option<String>,
) -> Option<ReplayJudgeWordingOverride> {
    let mut key = |name: &str| lookup(&format!("{ENV_PREFIX}{}", name.to_ascii_uppercase()));
    let over = ReplayJudgeWordingOverride {
        score: key("score"),
        structural: key("structural"),
        contrastive: key("contrastive"),
        preference: key("preference"),
        honesty: key("honesty"),
        task_success: key("task_success"),
        tradeoff: key("tradeoff"),
        live_axis: key("live_axis"),
        response_score: key("response_score"),
        axis_template: key("axis_template"),
        missing_replay_objective_template: key("missing_replay_objective_template"),
    };
    (over != ReplayJudgeWordingOverride::default()).then_some(over)
}
