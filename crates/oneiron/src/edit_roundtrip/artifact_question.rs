//! Typed questions over artifact units (ARCH-0076 §2, OF-506). A sheet row,
//! a paragraph, a slide or a file in a folder is asked through the same
//! decide() call as a graph unit: one typed question over the unit's state
//! read from pinned bytes, its images as call images, its full decision kept
//! as the receipt. The answer lands as a proposal on a copy, settled once on
//! Keep; an abstention keeps its receipt and writes nothing.

use crate::EntityId;
use crate::edit_roundtrip::CellValue;
use crate::llm::decision::questions::{question_unit_correlation, standing_ask_route};
use crate::llm::decision::{
    AskTo, DecisionAnswer, DecisionAudio, DecisionBandPolicy, DecisionDial, DecisionImage,
    DecisionLadder, DecisionProvider, DecisionQuestion, DecisionRung, EvidenceVersion,
    LocatedDecision, MAX_DECISION_STATE_BYTES, Reversibility, TypedDecision,
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
    /// Named audio clips filling state fields of their names; empty when the
    /// unit carries none or no rung hears them.
    pub audio: &'a [DecisionAudio],
    pub state: &'a Value,
    pub dial: DecisionDial,
    pub policy: &'a DecisionBandPolicy,
    pub reversibility: Reversibility,
    pub deadline: &'a RetrievalDeadline,
    /// Where the unit's person ask goes, bound by the engine from the
    /// question's principal, never by the model (OF-506).
    pub ask_to: Option<&'a AskTo>,
    /// The unit's own work, so each unit keeps its own ask
    /// ([`question_unit_correlation`]).
    pub correlation: Option<EntityId>,
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
    /// Whether a rung this decider climbs hears audio. A unit's clips are
    /// sent only when it does; otherwise they are listed as not served. The
    /// default hears none.
    fn reads_audio(&self) -> bool {
        false
    }
    /// [`Self::first_taking`] over `images` and `audio` both: the rung a call
    /// carrying both starts at ([`crate::llm::decision::MediaCall::of`]). The
    /// default is [`Self::first_taking`] for images alone, and the dial's
    /// first for audio when this decider hears it and reads any images too.
    fn first_taking_media(
        &self,
        question: &DecisionQuestion,
        dial: DecisionDial,
        images: &[DecisionImage],
        audio: &[DecisionAudio],
    ) -> Option<DecisionRung> {
        if audio.is_empty() {
            return self.first_taking(question, dial, images);
        }
        (self.reads_audio() && (images.is_empty() || self.reads_images())).then_some(dial.first)
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

    fn reads_audio(&self) -> bool {
        [
            self.rule,
            self.local,
            self.system_one,
            self.escalation,
            self.big,
        ]
        .into_iter()
        .flatten()
        .any(|provider| provider.reads_audio())
    }

    fn first_taking_media(
        &self,
        question: &DecisionQuestion,
        dial: DecisionDial,
        images: &[DecisionImage],
        audio: &[DecisionAudio],
    ) -> Option<DecisionRung> {
        DecisionLadder::first_taking_media(self, question, dial, images, audio)
    }

    fn decide_unit(&self, call: &UnitCall<'_>) -> Result<TypedDecision> {
        self.for_unit(call).run_media(
            call.question,
            call.principal,
            call.evidence,
            call.images,
            call.audio,
            call.state,
            call.dial,
            call.policy,
            call.reversibility,
            call.deadline,
        )
    }

    fn decide_located(&self, call: &UnitCall<'_>) -> Result<LocatedDecision> {
        self.for_unit(call).run_located(
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

impl<'a> DecisionLadder<'a> {
    /// The ladder with `call`'s person route and unit work, where it binds
    /// them.
    fn for_unit(&self, call: &UnitCall<'a>) -> Self {
        let mut ladder = self.clone();
        ladder.ask_to = call.ask_to.or(self.ask_to);
        ladder.correlation = call.correlation.or(self.correlation);
        ladder
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
    /// comment or column holds a region or a spot), on an ordered dial. A
    /// dial up to the person asks the next authorised role for each unit it
    /// reaches (FIX 9912); the unit stays unanswered while its ask is open.
    pub(crate) fn validate(&self) -> Result<()> {
        self.question.validate()?;
        self.dial.band.validate()?;
        if self.question.contract.locates()
            || self.dial.first > self.dial.ceiling
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
        let to = standing_ask_route(self.principal);
        let mut read = blake3::Hasher::new();
        for source in sources {
            read.update(source.id.as_bytes());
            read.update(&source.body_hash);
        }
        let correlation = question_unit_correlation(
            self.question,
            self.principal,
            &bytes,
            read.finalize().as_bytes(),
        )?;
        let mut decision = self.decider.decide_unit(&UnitCall {
            question: self.question,
            principal: self.principal,
            evidence: &evidence,
            images,
            audio: &[],
            state,
            dial: self.dial,
            policy: self.policy,
            reversibility: self.reversibility,
            deadline: &clock,
            ask_to: Some(&to),
            correlation: Some(correlation),
        })?;
        crate::llm::decision::questions::validate_unit_decision(
            self.question,
            self.principal,
            &decision,
        )?;
        // Only an image a rung was sent is evidence the decision read; one no
        // rung could take stays out of its receipt (FIX 9903).
        let shown: Vec<EvidenceVersion> = images
            .iter()
            .filter(|image| {
                decision
                    .receipt
                    .images
                    .iter()
                    .any(|pin| pin.name == image.name)
            })
            .map(|image| image.evidence.clone())
            .collect();
        decision.receipt.evidence_versions = sources.iter().cloned().chain(shown).collect();
        Ok(Some(decision))
    }
}

/// A unit the ask left unanswered, with its receipt; none when the unit had
/// no input to read or its state was past the call's bound.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct UnitAbstention {
    /// The unit, as the caller named it.
    pub unit: Value,
    pub decision: Option<TypedDecision>,
    /// The live body the ask read the unit on, when it read one: its decision
    /// names the head version as evidence (FIX 12018).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub judged_live: Option<crate::office_body::LivePin>,
}

/// A unit the ask will not read as given.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct UnitRefusal {
    pub unit: Value,
    pub reason: String,
    /// The live body the ask read the unit on, when it read one (FIX 12018).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub judged_live: Option<crate::office_body::LivePin>,
}

/// What one artifact ask did: the proposal held for Keep (none when no unit
/// was answered), the units left unanswered and those refused.
#[derive(Debug, Clone)]
pub struct ArtifactAskRun {
    pub proposal: Option<super::EditProposal>,
    pub abstained: Vec<UnitAbstention>,
    pub refused: Vec<UnitRefusal>,
    /// The rows the ask's own reads picked (FIX 5455): each version it read,
    /// as its version CLAIM and ASSET, the asked artifact's head and every
    /// folder file's head alike. Ids only.
    pub read_rows: Vec<EntityId>,
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
    /// An office artifact's head version and bytes, and the rows that
    /// version is (its version CLAIM and ASSET, FIX 5455); refused unless the
    /// artifact is a `format` file.
    pub(crate) fn office_head(
        &self,
        artifact: &EntityId,
        format: super::OfficeFormat,
    ) -> Result<(u64, Vec<u8>, Vec<EntityId>)> {
        let head = self
            .blob_artifact_head(artifact)?
            .ok_or(Error::EntityNotFound)?;
        let body = self
            .get_blob_artifact(artifact)?
            .ok_or(Error::EntityNotFound)?;
        if super::OfficeFormat::from_media_type(&body.media_type)? != format {
            return Err(invalid("the artifact is not a file of the asked format"));
        }
        let (bytes, rows) = self
            .read_blob_artifact_version_listing(artifact, head.version)?
            .ok_or(Error::EntityNotFound)?;
        Ok((head.version, bytes, rows))
    }
}
