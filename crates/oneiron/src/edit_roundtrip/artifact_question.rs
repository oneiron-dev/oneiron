//! Typed questions over artifact units (ARCH-0076 §2, OF-506). A sheet row,
//! a paragraph, a slide or a file in a folder is asked through the same
//! decide() call as a graph unit: one typed question over the unit's state
//! read from pinned bytes, its images as call images, its full decision kept
//! as the receipt. The answer lands as a proposal on a copy, settled once on
//! Keep; an abstention keeps its receipt and writes nothing.

use crate::EntityId;
use crate::edit_roundtrip::CellValue;
use crate::llm::decision::{
    DecisionAnswer, DecisionBandPolicy, DecisionDial, DecisionImage, DecisionLadder,
    DecisionProvider, DecisionQuestion, DecisionRung, EvidenceVersion, LocatedDecision,
    MAX_DECISION_STATE_BYTES, Reversibility, TypedDecision,
};
use crate::retrieval_depth::RetrievalDeadline;
use crate::{Error, Result};
use serde_json::Value;
use std::time::{Duration, Instant};

/// One unit's decide() call, prepared by the engine: the state it read, the
/// images it may show, the asker and the dial.
pub struct UnitCall<'a> {
    pub question: &'a DecisionQuestion,
    pub principal: EntityId,
    pub evidence: &'a [EntityId],
    /// Named images filling state fields of their names; empty for text.
    pub images: &'a [DecisionImage],
    pub state: &'a Value,
    pub dial: DecisionDial,
    pub policy: &'a DecisionBandPolicy,
    pub reversibility: Reversibility,
    pub deadline: &'a RetrievalDeadline,
}

/// The host's decide() for an artifact unit. A server binds its Local-vision
/// seat for a call with images; the bare ladder asks its own rungs.
pub trait UnitDecider {
    /// Whether a rung this decider climbs reads images. A unit's images are
    /// sent only when it does; otherwise the unit is read as text.
    fn reads_images(&self) -> bool;
    /// The rung a call of `question` over `images` starts at under `dial`:
    /// the first from the dial's first to its ceiling, short of the person,
    /// that takes them; none when no rung there does, and the images are then
    /// listed as not served ([`crate::llm::decision::MediaCall::of`]). The
    /// default starts at the dial's first when this decider reads images.
    fn first_taking(
        &self,
        _question: &DecisionQuestion,
        dial: DecisionDial,
        _images: &[DecisionImage],
    ) -> Option<DecisionRung> {
        self.reads_images().then_some(dial.first)
    }
    /// The full decision for one call, with the ladder's receipt.
    fn decide_unit(&self, call: &UnitCall<'_>) -> Result<TypedDecision>;
    /// A Box or Point call, presence first ([`DecisionLadder::run_located`]),
    /// each step with its receipt. The default asks the coordinates directly,
    /// as a ladder with no presence question does.
    fn decide_located(&self, call: &UnitCall<'_>) -> Result<LocatedDecision> {
        let location = self.decide_unit(call)?;
        Ok(LocatedDecision {
            presence: None,
            answer: location.answer.clone(),
            location: Some(location),
        })
    }
}

impl UnitDecider for DecisionLadder<'_> {
    fn reads_images(&self) -> bool {
        [
            self.rule,
            self.local,
            self.system_one,
            self.escalation,
            self.big,
        ]
        .into_iter()
        .flatten()
        .any(|provider| provider.reads_images())
    }

    fn first_taking(
        &self,
        question: &DecisionQuestion,
        dial: DecisionDial,
        images: &[DecisionImage],
    ) -> Option<DecisionRung> {
        DecisionLadder::first_taking(self, question, dial, images)
    }

    fn decide_unit(&self, call: &UnitCall<'_>) -> Result<TypedDecision> {
        self.run_images(
            call.question,
            call.principal,
            call.evidence,
            call.images,
            call.state,
            call.dial,
            call.policy,
            call.reversibility,
            call.deadline,
        )
    }

    fn decide_located(&self, call: &UnitCall<'_>) -> Result<LocatedDecision> {
        self.run_located(
            call.question,
            call.principal,
            call.evidence,
            call.images,
            call.state,
            call.dial,
            call.policy,
            call.reversibility,
            call.deadline,
        )
    }
}

/// The settings one artifact ask shares across its units, fixed by the
/// caller, never by a provider result.
#[derive(Clone, Copy)]
pub struct ArtifactAsk<'a> {
    pub question: &'a DecisionQuestion,
    pub principal: EntityId,
    pub dial: DecisionDial,
    pub policy: &'a DecisionBandPolicy,
    pub reversibility: Reversibility,
    pub decider: &'a dyn UnitDecider,
    /// Access-checked evidence beside the artifact.
    pub evidence: &'a [EntityId],
    /// Each unit call's anytime budget, from when it is asked.
    pub budget: Duration,
    /// The run's deadline: no call's clock runs past it.
    pub deadline: Instant,
    pub run_ref: &'a str,
}

impl ArtifactAsk<'_> {
    /// A question an artifact can land: valid, not a Box or Point (no cell,
    /// comment or column holds a region or a spot), on a dial that stops
    /// below the person.
    pub(crate) fn validate(&self) -> Result<()> {
        self.question.validate()?;
        self.dial.band.validate()?;
        if self.question.contract.locates()
            || self.dial.first > self.dial.ceiling
            || self.dial.ceiling == crate::llm::decision::DecisionRung::Human
            || self.budget.is_zero()
            || self.run_ref.trim().is_empty()
        {
            return Err(invalid("invalid artifact ask question or dial"));
        }
        Ok(())
    }

    /// Ask one unit: its state and images through the decider under the
    /// run's clock. The receipt's evidence is the engine's own pins, the
    /// sources read then each image the ladder was shown; `None` when the
    /// state is past the call's bound (nothing is trimmed).
    pub(crate) fn decide(
        &self,
        state: &Value,
        sources: &[EvidenceVersion],
        images: &[DecisionImage],
    ) -> Result<Option<TypedDecision>> {
        let bytes = serde_json::to_vec(state).map_err(|_| invalid("artifact unit state"))?;
        if bytes.len() > MAX_DECISION_STATE_BYTES {
            return Ok(None);
        }
        let images = if self.decider.reads_images() {
            images
        } else {
            &[]
        };
        let evidence: Vec<EntityId> = self
            .evidence
            .iter()
            .copied()
            .chain(sources.iter().map(|source| source.id))
            .collect();
        let now = Instant::now();
        let clock = RetrievalDeadline::hard(
            now,
            self.budget
                .min(self.deadline.saturating_duration_since(now)),
        );
        let mut decision = self.decider.decide_unit(&UnitCall {
            question: self.question,
            principal: self.principal,
            evidence: &evidence,
            images,
            state,
            dial: self.dial,
            policy: self.policy,
            reversibility: self.reversibility,
            deadline: &clock,
        })?;
        crate::llm::decision::questions::validate_unit_decision(
            self.question,
            self.principal,
            &decision,
        )?;
        decision.receipt.evidence_versions = sources
            .iter()
            .cloned()
            .chain(images.iter().map(|image| image.evidence.clone()))
            .collect();
        Ok(Some(decision))
    }
}

/// A unit the ask left unanswered, with its receipt; none when the unit had
/// no input to read or its state was past the call's bound.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct UnitAbstention {
    /// The unit, as the caller named it.
    pub unit: Value,
    pub decision: Option<TypedDecision>,
}

/// A unit the ask will not read as given.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UnitRefusal {
    pub unit: Value,
    pub reason: String,
}

/// What one artifact ask did: the proposal held for Keep (none when no unit
/// was answered), the units left unanswered and those refused.
#[derive(Debug, Clone)]
pub struct ArtifactAskRun {
    pub proposal: Option<super::EditProposal>,
    pub abstained: Vec<UnitAbstention>,
    pub refused: Vec<UnitRefusal>,
}

/// The cell a decided answer writes: a yes/no as a boolean, a pick as its
/// text, a score as its number. An abstention writes none.
pub(crate) fn answer_cell(answer: &DecisionAnswer) -> Result<Option<CellValue>> {
    Ok(match answer {
        DecisionAnswer::Abstain => None,
        DecisionAnswer::Noul(value) => Some(CellValue::Bool(*value)),
        DecisionAnswer::Choice(value) => Some(CellValue::Text(value.clone())),
        DecisionAnswer::Score(value) => Some(CellValue::Number(*value)),
        DecisionAnswer::Box(_) | DecisionAnswer::Point(_) => {
            return Err(invalid("a cell does not hold a box or point answer"));
        }
    })
}

/// A cell's saved value as a unit reads it: a formula by its cached value.
pub(crate) fn cell_text(value: &CellValue) -> Option<String> {
    match value {
        CellValue::Blank => None,
        CellValue::Number(number) => Some(number.to_string()),
        CellValue::Text(text) => Some(text.clone()),
        CellValue::Bool(value) => Some(value.to_string()),
        CellValue::Error(error) => Some(error.clone()),
        CellValue::Formula { cached, .. } => cached.as_deref().and_then(cell_text),
    }
}

pub(crate) fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.into())
}

impl crate::Vault {
    /// An office artifact's head version and bytes; refused unless the
    /// artifact is a `format` file.
    pub(crate) fn office_head(
        &self,
        artifact: &EntityId,
        format: super::OfficeFormat,
    ) -> Result<(u64, Vec<u8>)> {
        let head = self
            .blob_artifact_head(artifact)?
            .ok_or(Error::EntityNotFound)?;
        let body = self
            .get_blob_artifact(artifact)?
            .ok_or(Error::EntityNotFound)?;
        if super::OfficeFormat::from_media_type(&body.media_type)? != format {
            return Err(invalid("the artifact is not a file of the asked format"));
        }
        let bytes = self
            .read_blob_artifact_version(artifact, head.version)?
            .ok_or(Error::EntityNotFound)?;
        Ok((head.version, bytes))
    }
}
