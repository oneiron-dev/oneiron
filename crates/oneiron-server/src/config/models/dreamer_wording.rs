//! `[models.dreamer.wording]`: the host's wording of what the engine asks a
//! model in its own words today (FIX 8696). Each piece ships its default here,
//! word for word what the engine asked before, so nothing changes until the
//! owner writes one.
//!
//! * `confession_prompt` / `confession_prompt_file`: how a workflow step, an
//!   agent run and a Dreamer-lane TASK's realization are asked for their
//!   confession (OF-544). The engine still lists the objectives first and
//!   parses the answer; a wording that asks for no `oneiron-confession` block
//!   is answered with none, and none is recorded.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// The confession instruction the engine asked with before it was host
/// wording, and the one a host without its own still asks with.
const DEFAULT_CONFESSION_INSTRUCTION: &str = "When your result is complete, end it with a line \
     that is exactly DONE, then one block fenced ```oneiron-confession holding \
     {\"objectives\":[{\"objective\":\"<the assigned objective, copied exactly>\",\
     \"met\":<true or false>,\"flaw\":<null or what is wrong>,\
     \"uncertainty\":<null or what you are unsure of>}]} with one row per assigned \
     objective, in order. Say plainly what you did not meet, any flaw and any doubt: a \
     confession never costs the score. Nothing follows the closing fence.";

const DEFAULT_COACH_SKILL_WORKFLOW_ANSWER: &str =
    include_str!("../../../prompts/coach-skill-workflow-answer.md");
const DEFAULT_COACH_SKILL_DRAFT: &str = include_str!("../../../prompts/coach-skill-draft.md");
const DEFAULT_COACH_SKILL_CAUSE: &str = include_str!("../../../prompts/coach-skill-cause.md");
const DEFAULT_COACH_PRODUCER_FIX: &str = include_str!("../../../prompts/coach-producer-fix.md");

/// `[models.dreamer.wording]` as written in the config file.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DreamerWordingFile {
    confession_prompt: Option<String>,
    confession_prompt_file: Option<PathBuf>,
    coach_skill_workflow_answer_prompt: Option<String>,
    coach_skill_workflow_answer_prompt_file: Option<PathBuf>,
    coach_skill_draft_prompt: Option<String>,
    coach_skill_draft_prompt_file: Option<PathBuf>,
    coach_skill_cause_prompt: Option<String>,
    coach_skill_cause_prompt_file: Option<PathBuf>,
    coach_producer_fix_prompt: Option<String>,
    coach_producer_fix_prompt_file: Option<PathBuf>,
    commitment_reminder_prompt: Option<String>,
    commitment_reminder_prompt_file: Option<PathBuf>,
    #[serde(default)]
    commitment_reminder_personas: BTreeMap<String, String>,
}

impl DreamerWordingFile {
    /// The wording this host asks with: each piece the owner wrote, else its
    /// shipped default. `base` is the config file's directory, against which
    /// a relative `*_file` path resolves.
    pub(super) fn resolve(self, base: Option<&Path>) -> anyhow::Result<DreamerWording> {
        let confession = super::levels::prompt_text(
            "models.dreamer.wording.confession_prompt",
            self.confession_prompt,
            self.confession_prompt_file,
            base,
        )?
        .unwrap_or_else(|| DEFAULT_CONFESSION_INSTRUCTION.to_owned());
        let coach_skill_workflow_answer = super::levels::prompt_text(
            "models.dreamer.wording.coach_skill_workflow_answer_prompt",
            self.coach_skill_workflow_answer_prompt,
            self.coach_skill_workflow_answer_prompt_file,
            base,
        )?
        .unwrap_or_else(|| DEFAULT_COACH_SKILL_WORKFLOW_ANSWER.to_owned());
        let coach_skill_draft = super::levels::prompt_text(
            "models.dreamer.wording.coach_skill_draft_prompt",
            self.coach_skill_draft_prompt,
            self.coach_skill_draft_prompt_file,
            base,
        )?
        .unwrap_or_else(|| DEFAULT_COACH_SKILL_DRAFT.to_owned());
        let coach_skill_cause = super::levels::prompt_text(
            "models.dreamer.wording.coach_skill_cause_prompt",
            self.coach_skill_cause_prompt,
            self.coach_skill_cause_prompt_file,
            base,
        )?
        .unwrap_or_else(|| DEFAULT_COACH_SKILL_CAUSE.to_owned());
        let coach_producer_fix = super::levels::prompt_text(
            "models.dreamer.wording.coach_producer_fix_prompt",
            self.coach_producer_fix_prompt,
            self.coach_producer_fix_prompt_file,
            base,
        )?
        .unwrap_or_else(|| DEFAULT_COACH_PRODUCER_FIX.to_owned());
        let reminder_instruction = super::levels::prompt_text(
            "models.dreamer.wording.commitment_reminder_prompt",
            self.commitment_reminder_prompt,
            self.commitment_reminder_prompt_file,
            base,
        )?
        .unwrap_or_else(default_reminder_instruction);
        Ok(DreamerWording {
            confession,
            coach_skill_workflow_answer,
            coach_skill_draft,
            coach_skill_cause,
            coach_producer_fix,
            reminder_instruction,
            reminder_personas: self.commitment_reminder_personas,
        })
    }
}

/// The host's wording of the engine's asks, resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DreamerWording {
    confession: String,
    coach_skill_workflow_answer: String,
    coach_skill_draft: String,
    coach_skill_cause: String,
    coach_producer_fix: String,
    reminder_instruction: String,
    reminder_personas: BTreeMap<String, String>,
}

impl DreamerWording {
    /// How a run is asked for its confession, after its objectives are
    /// listed.
    #[must_use]
    pub fn confession(&self) -> &str {
        &self.confession
    }

    /// The answer instructions appended to the loaded skill-optimization workflow.
    #[must_use]
    pub fn coach_skill_workflow_answer(&self) -> &str {
        &self.coach_skill_workflow_answer
    }

    /// The fallback instruction for a skill-edit draft.
    #[must_use]
    pub fn coach_skill_draft(&self) -> &str {
        &self.coach_skill_draft
    }

    /// The explanation of a heal draft's cause-context data.
    #[must_use]
    pub fn coach_skill_cause(&self) -> &str {
        &self.coach_skill_cause
    }

    /// The instruction for a proposed producer-policy or configuration fix.
    #[must_use]
    pub fn coach_producer_fix(&self) -> &str {
        &self.coach_producer_fix
    }

    /// The instruction used to word commitment reminders, not to send them.
    #[must_use]
    pub fn commitment_reminder_instruction(&self) -> &str {
        &self.reminder_instruction
    }

    /// The host's voice text for an opaque reminder persona reference.
    #[must_use]
    pub fn commitment_reminder_persona(&self, reference: &str) -> Option<&str> {
        self.reminder_personas.get(reference).map(String::as_str)
    }
}

impl Default for DreamerWording {
    /// The shipped wording: a host with no `[models]` asks with it too.
    fn default() -> Self {
        Self {
            confession: DEFAULT_CONFESSION_INSTRUCTION.to_owned(),
            coach_skill_workflow_answer: DEFAULT_COACH_SKILL_WORKFLOW_ANSWER.to_owned(),
            coach_skill_draft: DEFAULT_COACH_SKILL_DRAFT.to_owned(),
            coach_skill_cause: DEFAULT_COACH_SKILL_CAUSE.to_owned(),
            coach_producer_fix: DEFAULT_COACH_PRODUCER_FIX.to_owned(),
            reminder_instruction: default_reminder_instruction(),
            reminder_personas: BTreeMap::new(),
        }
    }
}

fn default_reminder_instruction() -> String {
    #[derive(Deserialize)]
    struct Wording {
        instruction: String,
    }
    serde_json::from_str::<Wording>(include_str!("commitment_reminder_wording.json"))
        .expect("shipped commitment reminder wording decodes")
        .instruction
}
