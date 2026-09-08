//! What a conversion is asked for and what it returns: the request, the refiner's brief
//! and verdict, and the refiner seam.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::CallPurpose;
use crate::skill_hub::HubFile;

/// [`CallPurpose::Other`] name for the refinement tier, so conversion is
/// budgeted and audited as its own class instead of hiding inside extraction's
/// totals (the `actor_session_distill` precedent).
pub const SKILL_CONVERT_CALL_PURPOSE_NAME: &str = "skill_convert_refine";

/// Upper bound on the turns/messages one conversion may select. A selection is
/// a user's gesture at a passage, not a transcript export; the same bound the
/// `actor.*` citation lists carry.
pub const CONVERT_MAX_SOURCE_MESSAGES: usize = 64;

/// Upper bound on the existing skills a refine brief is shown for its near-dup
/// diff. A shortlist the tier can actually read beats a catalogue it skims.
pub const CONVERT_MAX_NEIGHBORS: usize = 8;

/// Upper bound on a refiner's dedup rationale. It is a reason, not a report.
pub const CONVERT_RATIONALE_MAX_BYTES: usize = 1024;

/// Upper bound on the user's optional refinement hint.
pub const CONVERT_HINT_MAX_BYTES: usize = 4096;

/// What the user selected, plus how they want it read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConvertRequest {
    /// TURN or MESSAGE entities, in selection order.
    pub message_refs: Vec<EntityId>,
    /// The user's guidance to the refiner (ARCH-0017's `userInstruction`).
    pub hint: Option<String>,
}

impl ConvertRequest {
    /// Selects messages with no hint.
    #[must_use]
    pub fn new(message_refs: Vec<EntityId>) -> Self {
        Self {
            message_refs,
            hint: None,
        }
    }

    /// Adds the user's refinement hint.
    #[must_use]
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
}

/// Where a conversion landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConvertOutcome {
    /// A new `candidate` SkillRecord.
    Created(EntityId),
    /// These exact bytes are already in the library: the existing holder, not a
    /// second entity.
    DupPointer(EntityId),
    /// Near-duplicate: a `candidate`/`proposed` revision of `existing` awaiting
    /// the admission gate, never an in-place edit of canon.
    MergeProposed {
        existing: EntityId,
        proposal: EntityId,
    },
}

/// One selected utterance, as the refiner sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConvertUtterance {
    /// The TURN or MESSAGE these words came from — the id that lands in
    /// [`PROVENANCE_SOURCE_MESSAGES_KEY`].
    pub source: EntityId,
    pub speaker: Option<String>,
    pub text: Option<String>,
}

/// An existing skill the refiner must diff against before minting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillNeighbor {
    pub entity: EntityId,
    pub skill_id: String,
    pub desc: String,
}

/// What a refinement gets to reason over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillRefineBrief {
    /// The selected words, in selection order.
    pub said: Vec<ConvertUtterance>,
    pub hint: Option<String>,
    /// The nearest existing skills by name/description, nearest first. Possibly
    /// empty — an empty shortlist is the honest answer for a library with
    /// nothing alike in it, and the refiner must not read it as permission to
    /// skip the diff it did not need.
    pub neighbors: Vec<SkillNeighbor>,
}

/// The refiner's near-duplication call. Either answer is receipted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefineVerdict {
    /// Genuinely new, and here is why.
    Mint { justification: String },
    /// A near-duplicate of a skill from [`SkillRefineBrief::neighbors`]: land as
    /// a gated edit proposal against it instead of minting a rival.
    MergeInto {
        existing: EntityId,
        rationale: String,
    },
}

/// A refined SKILL.md-shaped tree plus the record fields it implies.
///
/// The tree is `HubFile`s because the engine has exactly one representation of
/// a skill file tree, and the identity function ([`canonical_skill_tree_hash`])
/// is defined over it. The bytes stay the host's to write to disk — the engine
/// persists the record and the tree's HASH, the same boundary the hub import
/// door draws.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefinedSkill {
    /// Frontmatter `name` (ARCH-0017): lowercase, hyphenated.
    pub skill_id: String,
    /// Frontmatter `description`: what it does AND when to use it.
    pub desc: String,
    /// The SKILL.md-shaped tree.
    pub files: Vec<HubFile>,
    pub verdict: RefineVerdict,
}

/// Refines selected conversation into a skill, or refuses.
///
/// The host implements this against the engine's existing LLM surface under
/// [`skill_convert_call_purpose`]; this module constructs no client (the
/// `dreamer_consolidation` / `SessionActorDistiller` posture). ARCH-0017 pins
/// the system prompt's contract — structure loosely-stated steps, keep the
/// user's voice, and INVENT NOTHING that is not in the source.
pub trait SkillRefiner {
    /// The skill `brief` supports.
    fn refine(&self, brief: &SkillRefineBrief) -> Result<RefinedSkill>;
}

/// The [`CallPurpose`] a refiner's LLM tier must stamp.
#[must_use]
pub fn skill_convert_call_purpose() -> CallPurpose {
    CallPurpose::Other {
        name: SKILL_CONVERT_CALL_PURPOSE_NAME.to_owned(),
    }
}
