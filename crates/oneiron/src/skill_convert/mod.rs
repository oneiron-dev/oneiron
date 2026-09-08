//! Message-to-skill conversion — the user-initiated middle road into the skill
//! library (ARCH-0017, registry OF-206).
//!
//! Three roads reach the SKILL namespace: Dreamer distill, this manual convert,
//! and hub import. ARCH-0053 §6/§7 gives all three ONE lifecycle machine and
//! ONE identity, so this module adds a DOOR, not a second namespace: the user
//! selects turns or messages, a host-supplied LLM tier refines them into a
//! SKILL.md-shaped tree, and the result lands through the ordinary
//! [`Vault::put_skill_record`] path as a `candidate` revision whose canonical
//! content hash enters the SAME content-hash index hub import dedups against.
//!
//! Layering, stated once:
//! - the MECHANICAL dedup tier is exact content hash and nothing else. It runs
//!   before the refiner's verdict is honoured and outranks it;
//! - the LLM tier judges NEAR-duplication, having been shown the nearest
//!   existing skills, and its decision is receipted onto the landed record's
//!   provenance rather than discarded;
//! - the engine never trusts the refiner for identity: the content hash is
//!   recomputed here from the returned tree, exactly as the hub import door
//!   recomputes it from a package.
//!
//! **Registry status flag (OF-206):** the ARCH-0017 page is still stamped
//! `proposed` in the registry. The SOW's acceptance list is what this module
//! implements; the flag is recorded here rather than blocked on, so a later
//! ratification pass can see precisely which door was built ahead of the stamp.
//!
//! **Not a routine (ONE-248).** A skill is procedural MEMORY; a routine is a
//! scheduled ACT. Nothing here imports or mints routine machinery.
//!
//! The convert door is only half the module: the stale fold keeps a converted
//! skill honest when its evidence is deleted, through a reverse source index
//! and a deletion-time sweep that stales every skill citing an erased source.

mod door;
mod provenance;
mod selection;
mod stale;
mod types;

pub use self::door::convert_messages_to_skill;
pub use self::provenance::{
    CONVERT_BIRTH_PATH, PROVENANCE_BIRTH_KEY, PROVENANCE_DEDUP_RATIONALE_KEY,
    PROVENANCE_MERGE_OF_KEY, PROVENANCE_SOURCE_MESSAGES_KEY, source_message_refs,
};
pub use self::stale::{
    STALE_NOTE_DELETED_REFS_KEY, STALE_NOTE_REASON_KEY, STALE_REASON_SOURCE_MESSAGE_DELETED,
    SkillStaleNote, rebuild_skill_source_index, skill_stale_note, skills_dependent_on_message,
};
pub use self::types::{
    CONVERT_HINT_MAX_BYTES, CONVERT_MAX_NEIGHBORS, CONVERT_MAX_SOURCE_MESSAGES,
    CONVERT_RATIONALE_MAX_BYTES, ConvertOutcome, ConvertRequest, ConvertUtterance, RefineVerdict,
    RefinedSkill, SKILL_CONVERT_CALL_PURPOSE_NAME, SkillNeighbor, SkillRefineBrief, SkillRefiner,
    skill_convert_call_purpose,
};

pub(crate) use self::stale::maintain_skill_source_index_for_put;

#[cfg(test)]
mod tests;

// The flat skill_convert.rs module used to provide these names to the sibling test
// module through `use super::*`: its own private crate/std import header, and the
// private index prefix the tests probe directly. After the directory split the
// seam re-imports them so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::stale::SOURCE_INDEX_PREFIX;
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::claim::{ClaimApprovalStatus, ClaimSource};
#[cfg(test)]
use crate::edge::EdgeKind;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::Result;
#[cfg(test)]
use crate::llm::CallPurpose;
#[cfg(test)]
use crate::registry::{ENTITY_TYPE_SKILL, ENTITY_TYPE_TURN};
#[cfg(test)]
use crate::skill::{
    SkillContentHash, SkillDependency, SkillLifecycle, SkillRecord, canonical_skill_tree_hash,
};
#[cfg(test)]
use crate::skill_hub::HubFile;
#[cfg(test)]
use crate::skill_reliability::{ProvenanceTrustClass, SkillReliabilityPosterior};
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use rmpv::Value;
