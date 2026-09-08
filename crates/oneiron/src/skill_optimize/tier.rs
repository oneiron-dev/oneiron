//! The fail-closed governance-tier resolver: what the tier axis says about one stored skill, including the positive-evidence legacy default.

use rmpv::Value;

use crate::Vault;
use crate::claim::{ClaimLifecycleStatus, ClaimSource};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::skill::{SkillGovernanceTier, SkillRecord};
use crate::skill_convert::PROVENANCE_BIRTH_KEY;
use crate::skill_hub::PREDICATE_SKILL_HUB_PROVENANCE;

/// What the tier axis says about one stored skill.
///
/// Three answers, not two: "marked standard" and "unmarked but born on an
/// ordinary road" are both eligible, while "unmarked and unexplainable" is a
/// third thing that must not collapse into either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SkillTierVerdict {
    /// The record carries an explicit mark.
    Marked(SkillGovernanceTier),
    /// No mark, and provenance says the record was born on one of the roads
    /// ordinary skills come from (conversation convert, hub import), so the
    /// legacy default is `standard`.
    LegacyStandard,
    /// No mark and provenance cannot say. Never a candidate.
    Ambiguous,
}

impl SkillTierVerdict {
    /// The tier this verdict resolves to, or `None` when it resolves to no
    /// tier at all.
    #[must_use]
    pub const fn tier(self) -> Option<SkillGovernanceTier> {
        match self {
            Self::Marked(tier) => Some(tier),
            Self::LegacyStandard => Some(SkillGovernanceTier::Standard),
            Self::Ambiguous => None,
        }
    }

    /// Whether the automated edit loop may consider this record.
    ///
    /// Fail-closed by shape: only a resolved, unprotected tier passes, so a
    /// future verdict arm is excluded until someone rules on it.
    #[must_use]
    pub const fn optimizable(self) -> bool {
        match self.tier() {
            Some(tier) => !tier.is_protected(),
            None => false,
        }
    }
}

/// Resolves the governance tier of a stored skill, fail-closed.
///
/// See the module header for the table this implements. The provenance halves
/// are POSITIVE evidence, both of them:
/// - conversation convert stamps its birth path on the record itself;
/// - a hub import is vouched for by an active `skill.hub_provenance` alias,
///   which the import door writes — an `Imported` stamp with no such alias is
///   an assertion about a road nobody travelled, so it stays ambiguous.
///
/// # Errors
///
/// [`Error::EntityNotFound`] when `skill` is not a stored SKILL; storage
/// errors.
pub fn skill_governance_tier(vault: &Vault, skill: &EntityId) -> Result<SkillTierVerdict> {
    let record = vault
        .get_skill_record(skill)?
        .ok_or(Error::EntityNotFound)?;
    tier_verdict(vault, skill, &record)
}

pub(super) fn tier_verdict(
    vault: &Vault,
    skill: &EntityId,
    record: &SkillRecord,
) -> Result<SkillTierVerdict> {
    let rtxn = vault.store.env.read_txn()?;
    tier_verdict_in_txn(vault, &rtxn, skill, record)
}

/// The tier rule itself, over a caller's snapshot.
///
/// The write path resolves the tier against its OWN transaction rather than
/// opening a second one: the tier is the last thing checked before a proposal
/// lands, and reading it from a different snapshot than the one the write
/// commits into is exactly the gap an owner's identity-mark could fall through.
pub(super) fn tier_verdict_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
    record: &SkillRecord,
) -> Result<SkillTierVerdict> {
    if let Some(tier) = record.governance_tier {
        return Ok(SkillTierVerdict::Marked(tier));
    }
    if born_on_convert_road(record) {
        return Ok(SkillTierVerdict::LegacyStandard);
    }
    if record.source == ClaimSource::Imported && hub_vouches_in_txn(vault, rtxn, skill)? {
        return Ok(SkillTierVerdict::LegacyStandard);
    }
    Ok(SkillTierVerdict::Ambiguous)
}

/// True when an active `skill.hub_provenance` alias says a hub carried this
/// record here — the positive half of the hub-import road.
fn hub_vouches_in_txn(vault: &Vault, rtxn: &heed::RoTxn<'_>, skill: &EntityId) -> Result<bool> {
    for id in vault.claims_for_subject_in_txn(rtxn, skill)? {
        let Some(body) = vault.get_claim_in_txn(rtxn, &id)? else {
            continue;
        };
        if body.predicate == PREDICATE_SKILL_HUB_PROVENANCE
            && body.lifecycle == ClaimLifecycleStatus::Active
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn born_on_convert_road(record: &SkillRecord) -> bool {
    let Value::Map(entries) = &record.provenance else {
        return false;
    };
    entries.iter().any(|(key, value)| {
        key.as_str() == Some(PROVENANCE_BIRTH_KEY)
            && value.as_str() == Some(crate::skill_convert::CONVERT_BIRTH_PATH)
    })
}
