//! Measured run plan: answerer arms, efforts and plan validation.

use super::*;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::beam) struct AnswererArm {
    pub arm: ArmKind,
    pub model: ModelPin,
    pub cheap_chat: bool,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::beam) struct Effort {
    pub name: String,
    pub token_budget: usize,
    /// Agentic retrieval steps; the trajectory arm takes as many own steps.
    pub retrieval_steps: usize,
    /// Fixed-total-token rows: query tokens one question may spend.
    pub total_token_allowance: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::beam) struct ModelRunPlan {
    pub retrieval_manifest: PathBuf,
    pub temporal_now: u64,
    pub host: HostConfig,
    pub judge: JudgeConfig,
    pub answer_prompt: String,
    pub routing_prompt: AnswerPromptPin,
    pub trajectory_prompt: AnswerPromptPin,
    pub answerers: Vec<AnswererArm>,
    /// Family disclosures keyed by the fully resolved model pin, not arm labels.
    #[serde(default)]
    pub model_families: BTreeMap<ModelId, String>,
    pub efforts: Vec<Effort>,
    pub amortized_question_count: usize,
    pub chroma: Option<super::super::chroma::ChromaConfig>,
}
impl ModelRunPlan {
    pub(in crate::beam) fn validate(&self) -> BeamResult<()> {
        self.judge.validate(&self.answer_prompt)?;
        for pin in [&self.routing_prompt, &self.trajectory_prompt] {
            if pin.content.trim().is_empty() || !pin.matches_exact_text(&pin.content) {
                return Err(refusal(
                    "exact routing and trajectory prompt content and hash required",
                ));
            }
        }
        if self.efforts.is_empty() || self.amortized_question_count == 0 || self.temporal_now == 0 {
            return Err(refusal("efforts and fixed dataset denominator required"));
        }
        let mut names = BTreeSet::new();
        for effort in &self.efforts {
            if !names.insert(&effort.name)
                || effort.name.trim().is_empty()
                || effort.token_budget == 0
                || effort.retrieval_steps == 0
                || effort.retrieval_steps > 32
                || effort.total_token_allowance == 0
            {
                return Err(refusal("invalid or duplicate effort"));
            }
        }
        let find = |kind| {
            self.answerers
                .iter()
                .filter(|a| a.arm == kind)
                .collect::<Vec<_>>()
        };
        for kind in [
            ArmKind::Deterministic,
            ArmKind::Agentic,
            ArmKind::BackboneSolo,
            ArmKind::TrajectoryOnly,
            ArmKind::Chat,
        ] {
            if find(kind).len() != 1 {
                return Err(refusal(
                    "each memory run requires deterministic, agentic, backbone_solo, trajectory_only and separate chat pins",
                ));
            }
        }
        if self.answerers.len() != 5 + usize::from(self.chroma.is_some())
            || find(ArmKind::VanillaRag).len() != usize::from(self.chroma.is_some())
        {
            return Err(refusal(
                "Chroma arm and its independent endpoint must be configured together",
            ));
        }
        let det = find(ArmKind::Deterministic)[0];
        for kind in [
            ArmKind::Agentic,
            ArmKind::BackboneSolo,
            ArmKind::TrajectoryOnly,
        ]
        .into_iter()
        .chain(self.chroma.as_ref().map(|_| ArmKind::VanillaRag))
        {
            let other = find(kind)[0];
            if serde_json::to_value(&det.model)? != serde_json::to_value(&other.model)? {
                return Err(refusal(
                    "retrieval arms, backbone-solo and trajectory-only must share identical answerer pins and parameters",
                ));
            }
        }
        for row in &self.answerers {
            if row.cheap_chat != (row.arm == ArmKind::Chat) {
                return Err(refusal("only chat is a separate cheap-model cost point"));
            }
        }
        Ok(())
    }
}
