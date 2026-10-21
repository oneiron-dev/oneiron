//! The skills a card's run loaded (OF-568, FIX 3724): each SKILL revision the
//! pack manifest of the card's attempt pinned, with its instructions whole.
//! The card's reader (after the card's own read check) and the Coach read
//! the same list, and a `skill_edit` draft names one of them as the revision
//! its proposal replaces. The owner's apply door (`apply.rs`) takes exactly
//! the revisions this pack loaded, so the list and the door cannot disagree.

use serde::{Deserialize, Serialize};

use super::AgentHealthCard;
use super::ask::{AgentHealthCoachDraft, AgentHealthCoachRoute};
use crate::attempt_queue::{AttemptId, ManifestEntry};
use crate::registry::ENTITY_TYPE_SKILL;
use crate::skill::{SkillLifecycle, SkillRecord};
use crate::skill_attribution::manifest_entry_names_skill;
use crate::{EntityId, Result, Vault};

/// One skill revision the card's run loaded, as the card's reader and the
/// Coach read it: the target the apply door takes, and what it says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentHealthLoadedSkill {
    /// The SKILL revision, as 32 hex: the apply door's `skill`.
    pub skill: String,
    /// Its stable name, the pack manifest's `skill_id`.
    pub name: String,
    /// The version the pack pinned: the apply door's `version`.
    pub version: String,
    /// Whether it is still the skill's active revision. Only an active one
    /// takes an edit; a superseded one names what the run ran.
    pub active: bool,
    /// Its instructions, whole: what a `skill_edit` replaces.
    pub instructions: String,
}

/// The revision a `skill_edit` draft replaces whole: one the card's run
/// loaded, named as the apply door takes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentHealthSkillTarget {
    /// The SKILL revision, as 32 hex.
    pub skill: String,
    pub version: String,
}

/// The pack the card's run loaded: its attempt receipt's manifest rows and
/// the resident that receipt is bound to.
pub(super) struct RunPack {
    skills: Vec<String>,
    resident: Option<EntityId>,
}

impl RunPack {
    /// The pack of the card's attempt. A card with no attempt, or a run with
    /// no stamped manifest, loaded none.
    pub(super) fn of(vault: &Vault, card: &AgentHealthCard) -> Result<Option<Self>> {
        let Some(attempt) = card.attempt else {
            return Ok(None);
        };
        let attempt = AttemptId::from_bytes(attempt.as_bytes())?;
        let receipt_id = crate::receipt::attempt_pack_receipt_id(&attempt);
        let Some(receipt) = crate::receipt::attempt_pack_receipt(vault, &receipt_id)? else {
            return Ok(None);
        };
        let Some(skills) = receipt.pack_manifest_skills() else {
            return Ok(None);
        };
        Ok(Some(Self {
            skills,
            resident: crate::skill::resident::receipt_resident(vault, &receipt_id)?,
        }))
    }

    /// Whether this pack loaded `record`: its manifest names the skill, and a
    /// fork is the run's resident's own.
    pub(super) fn loaded(&self, record: &SkillRecord) -> Result<bool> {
        if !self
            .skills
            .iter()
            .any(|entry| manifest_entry_names_skill(entry, record))
        {
            return Ok(false);
        }
        let fork_of = crate::skill::resident_of(record)?;
        Ok(fork_of.is_none() || fork_of == self.resident)
    }

    /// Whether a manifest row pinned `record`'s exact version.
    fn pinned(&self, record: &SkillRecord) -> bool {
        self.skills.iter().any(|entry| {
            ManifestEntry::parse_wire_form(entry)
                .is_some_and(|(name, version)| name == record.skill_id && version == record.version)
        })
    }
}

/// Each SKILL revision the card's run loaded, in manifest order: a revision
/// its pack pinned by version, or, for a row stamped with no version, the
/// active revision the apply door takes. Empty when the run loaded none.
///
/// # Errors
///
/// Storage errors; a fork whose owner mark does not read.
pub(super) fn run_skills(
    vault: &Vault,
    card: &AgentHealthCard,
) -> Result<Vec<AgentHealthLoadedSkill>> {
    Ok(run_skills_sourced(vault, card)?.0)
}

/// [`run_skills`] beside the rows it read (FIX 6997): the card's attempt,
/// which its pack receipt is keyed by, and each SKILL revision listed.
///
/// # Errors
///
/// As [`run_skills`].
pub(super) fn run_skills_sourced(
    vault: &Vault,
    card: &AgentHealthCard,
) -> Result<(Vec<AgentHealthLoadedSkill>, Vec<EntityId>)> {
    let Some(pack) = RunPack::of(vault, card)? else {
        return Ok((Vec::new(), Vec::new()));
    };
    let mut rows: Vec<EntityId> = card.attempt.into_iter().collect();
    if pack.skills.is_empty() {
        return Ok((Vec::new(), rows));
    }
    let mut found: Vec<(usize, EntityId, SkillRecord)> = Vec::new();
    for id in vault.entities_by_type(ENTITY_TYPE_SKILL)? {
        let Some(record) = vault.get_skill_record(&id)? else {
            continue;
        };
        let Some(at) = pack
            .skills
            .iter()
            .position(|entry| manifest_entry_names_skill(entry, &record))
        else {
            continue;
        };
        let active = record.lifecycle_status == SkillLifecycle::Active;
        if !(active || pack.pinned(&record)) || !pack.loaded(&record)? {
            continue;
        }
        found.push((at, id, record));
    }
    found.sort_by_key(|(at, id, _)| (*at, *id));
    rows.extend(found.iter().map(|(_, id, _)| *id));
    let skills = found
        .into_iter()
        .map(|(_, id, record)| AgentHealthLoadedSkill {
            skill: id.to_hex(),
            active: record.lifecycle_status == SkillLifecycle::Active,
            name: record.skill_id,
            version: record.version,
            instructions: record.desc,
        })
        .collect();
    Ok((skills, rows))
}

/// Binds a `skill_edit` draft to the revision it replaces: the one it names
/// among `skills`, else the run's only loaded skill. Another route, or a
/// revision the run did not load, binds none.
pub(super) fn bind_target(
    mut draft: AgentHealthCoachDraft,
    skills: &[AgentHealthLoadedSkill],
) -> AgentHealthCoachDraft {
    let named = draft.target.as_ref().and_then(|target| {
        skills.iter().find(|skill| {
            skill.skill.eq_ignore_ascii_case(&target.skill) && skill.version == target.version
        })
    });
    let only = match skills {
        [only] => Some(only),
        _ => None,
    };
    draft.target = named
        .or(only)
        .filter(|_| draft.route == AgentHealthCoachRoute::SkillEdit)
        .map(|skill| AgentHealthSkillTarget {
            skill: skill.skill.clone(),
            version: skill.version.clone(),
        });
    draft
}
