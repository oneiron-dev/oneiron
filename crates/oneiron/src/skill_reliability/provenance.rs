//! Classifying a stored skill for the prior table: the scan-clearance and hub-vouch reads behind the vetted-import tier.

use crate::Vault;
use crate::claim::{ClaimBody, ClaimSource};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_SKILL;
use crate::skill::{SkillContentHash, SkillRecord, decode_skill_record};
use crate::skill_hub::PREDICATE_SKILL_HUB_PROVENANCE;

use super::codec::map_str;
use super::posterior::{ProvenanceTrustClass, SkillReliabilityPosterior};
use super::read::active_claims_in_txn;

/// `skill.scan_verdict` body keys + the values that decide whether canonical
/// bytes were actually CLEARED. Duplicated rather than imported:
/// `ScanVerdict::as_str` / `SkillGovernance::as_str` are private to
/// `skill_hub`, and the wire spelling is the pinned ABI either way.
const SCAN_VERDICT_KEY: &str = "verdict";

const SCAN_VERDICT_CLEAN: &str = "clean";

const SCAN_GOVERNANCE_KEY: &str = "governance";

const SCAN_GOVERNANCE_PROHIBITED: &str = "prohibited";

/// `skill.hub_provenance` body key naming the bytes a hub alias vouches for.
const HUB_PROVENANCE_CONTENT_HASH_KEY: &str = "contentHash";

// ---------------------------------------------------------------------------
// Priors
// ---------------------------------------------------------------------------

/// Classifies a stored skill for the prior table.
pub fn skill_provenance_trust_class(
    vault: &Vault,
    skill: &EntityId,
) -> Result<ProvenanceTrustClass> {
    let rtxn = vault.store.env.read_txn()?;
    skill_provenance_trust_class_in_txn(vault, &rtxn, skill)
}

fn skill_provenance_trust_class_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
) -> Result<ProvenanceTrustClass> {
    let raw = vault
        .store
        .port_entity_record(rtxn, skill)?
        .ok_or(Error::EntityNotFound)?;
    if raw.entity_type != ENTITY_TYPE_SKILL {
        return Err(super::codec::invalid(
            "skill reliability names a non-skill entity",
        ));
    }
    let record = decode_skill_record(&raw.body)?;
    provenance_trust_class(vault, rtxn, skill, &record)
}

fn provenance_trust_class(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
    record: &SkillRecord,
) -> Result<ProvenanceTrustClass> {
    if record.generated {
        return Ok(ProvenanceTrustClass::Generated);
    }
    if record.source != ClaimSource::Imported {
        return Ok(ProvenanceTrustClass::HumanAuthored);
    }
    let Some(content_hash) = record.content_hash else {
        return Ok(ProvenanceTrustClass::UnvettedImport);
    };
    // The top prior is the VETTED-HUB import (ARCH-0053 §5): a hub carries
    // these bytes AND a scanner cleared them. Both halves are read, because
    // either half alone is a different claim. A clean verdict on bytes no hub
    // vouches for says only "a scanner looked at some bytes" — there is no
    // trust relationship behind it to be optimistic about — and a hub alias
    // over bytes nobody scanned is what `UnvettedImport` NAMES.
    let vetted = hub_vouches_for_content(vault, rtxn, skill, content_hash)?
        && crate::skill_hub::skill_scan_verdicts_for_content_hash_in_store(
            &vault.store,
            rtxn,
            content_hash,
        )?
        .iter()
        .any(scan_verdict_cleared_the_bytes);
    Ok(if vetted {
        ProvenanceTrustClass::VettedImport
    } else {
        ProvenanceTrustClass::UnvettedImport
    })
}

/// True when a scanner receipt actually CLEARED the bytes it names.
///
/// `verdict == clean` alone is not a clearance. `governance` is a separate
/// POLICY axis carried on the same receipt (`skill_hub::SkillGovernance`), and
/// the scan-ingest door validates only the provider text — nothing stops a
/// receipt that pairs a clean scan with `prohibited` governance. Seeding the
/// MOST optimistic prior off bytes the governance axis forbids inverts the
/// table it is keyed by, so a prohibited row clears nothing however clean the
/// scanner found it.
///
/// `riskLevel` and `completeness` are deliberately NOT read here: both are
/// scanner-signal axes the scanner already summarized into `verdict`, so
/// re-judging them would be this module second-guessing the provider.
/// `governance` is the one axis on the row that is NOT the scanner's opinion.
fn scan_verdict_cleared_the_bytes(body: &ClaimBody) -> bool {
    map_str(&body.value, SCAN_VERDICT_KEY) == Some(SCAN_VERDICT_CLEAN)
        && map_str(&body.value, SCAN_GOVERNANCE_KEY) != Some(SCAN_GOVERNANCE_PROHIBITED)
}

/// True when an active `skill.hub_provenance` alias on this skill names exactly
/// these canonical bytes.
///
/// Scan verdicts hang off the content ANCHOR, which is content-global — every
/// holder of the same bytes sees the same verdicts. The provenance row is the
/// per-skill half: it is what says a HUB carried these bytes to this vault.
fn hub_vouches_for_content(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
    content_hash: SkillContentHash,
) -> Result<bool> {
    let hash_hex = content_hash.to_hex();
    for (_, body, _) in active_claims_in_txn(vault, rtxn, skill, PREDICATE_SKILL_HUB_PROVENANCE)? {
        if map_str(&body.value, HUB_PROVENANCE_CONTENT_HASH_KEY) == Some(hash_hex.as_str()) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The prior a skill's posterior starts from, before any attributed outcome.
pub fn skill_reliability_prior(
    vault: &Vault,
    skill: &EntityId,
) -> Result<SkillReliabilityPosterior> {
    let rtxn = vault.store.env.read_txn()?;
    skill_reliability_prior_in_txn(vault, &rtxn, skill)
}

pub(super) fn skill_reliability_prior_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
) -> Result<SkillReliabilityPosterior> {
    skill_provenance_trust_class_in_txn(vault, rtxn, skill)
        .map(SkillReliabilityPosterior::seeded_from_provenance)
}
