//! Classifying a stored skill for the prior table: the scan-clearance and hub-vouch reads behind the vetted-import tier.

use crate::Vault;
use crate::claim::{ClaimBody, ClaimSource};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gate::{ConsolidationReader, claim_consolidation_eligible_in_txn};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_SKILL;
use crate::skill::{SkillContentHash, SkillRecord, decode_skill_record};
use crate::skill_hub::PREDICATE_SKILL_HUB_PROVENANCE;

use super::codec::map_str;
use super::posterior::{ProvenanceTrustClass, SkillReliabilityPosterior};
use super::read::{active_claims_in_txn, posterior_from_estimate, resolved_estimate_in_txn};

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
    skill_provenance_trust_class_sourced_in_txn(vault, rtxn, skill).map(|(class, _)| class)
}

/// [`skill_provenance_trust_class_in_txn`] and the rows its tier stands on
/// (FIX 3515): the SKILL row, and for a vetted import the hub alias and the
/// scan verdict that cleared its bytes.
fn skill_provenance_trust_class_sourced_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
) -> Result<(ProvenanceTrustClass, Vec<EntityId>)> {
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
    let (class, witnesses) = provenance_trust_class(vault, rtxn, skill, &record)?;
    let mut sources = vec![*skill];
    sources.extend(witnesses);
    Ok((class, sources))
}

/// The tier, and for a vetted import the hub alias and the clearing scan
/// verdict it was read from.
fn provenance_trust_class(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
    record: &SkillRecord,
) -> Result<(ProvenanceTrustClass, Vec<EntityId>)> {
    if record.generated {
        return Ok((ProvenanceTrustClass::Generated, Vec::new()));
    }
    if record.source != ClaimSource::Imported {
        return Ok((ProvenanceTrustClass::HumanAuthored, Vec::new()));
    }
    let Some(content_hash) = record.content_hash else {
        return Ok((ProvenanceTrustClass::UnvettedImport, Vec::new()));
    };
    // The top prior is the VETTED-HUB import (ARCH-0053 §5): a hub carries
    // these bytes AND a scanner cleared them. Both halves are read, because
    // either half alone is a different claim. A clean verdict on bytes no hub
    // vouches for says only "a scanner looked at some bytes" — there is no
    // trust relationship behind it to be optimistic about — and a hub alias
    // over bytes nobody scanned is what `UnvettedImport` NAMES.
    // A half awaiting its owner's answer vouches for nothing yet.
    let mut vetted = None;
    if let Some(alias) = hub_alias_for_content(vault, rtxn, skill, content_hash)? {
        for (id, body) in crate::skill_hub::skill_scan_verdict_heads_for_content_hash_in_store(
            &vault.store,
            rtxn,
            content_hash,
        )? {
            if scan_verdict_cleared_the_bytes(&body)
                && claim_consolidation_eligible_in_txn(
                    &vault.store,
                    rtxn,
                    &id,
                    ConsolidationReader::SkillScanPrior,
                )?
            {
                vetted = Some(vec![alias, id]);
                break;
            }
        }
    }
    Ok(match vetted {
        Some(witnesses) => (ProvenanceTrustClass::VettedImport, witnesses),
        None => (ProvenanceTrustClass::UnvettedImport, Vec::new()),
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

/// The active `skill.hub_provenance` alias on this skill that names exactly
/// these canonical bytes, if one does.
///
/// Scan verdicts hang off the content ANCHOR, which is content-global — every
/// holder of the same bytes sees the same verdicts. The provenance row is the
/// per-skill half: it is what says a HUB carried these bytes to this vault.
fn hub_alias_for_content(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
    content_hash: SkillContentHash,
) -> Result<Option<EntityId>> {
    let hash_hex = content_hash.to_hex();
    for (id, body, _) in active_claims_in_txn(vault, rtxn, skill, PREDICATE_SKILL_HUB_PROVENANCE)? {
        if map_str(&body.value, HUB_PROVENANCE_CONTENT_HASH_KEY) == Some(hash_hex.as_str())
            && claim_consolidation_eligible_in_txn(
                &vault.store,
                rtxn,
                &id,
                ConsolidationReader::SkillHubPrior,
            )?
        {
            return Ok(Some(id));
        }
    }
    Ok(None)
}

/// The rows a skill's reliability, as a reader is shown it, stands on
/// (DEC-0005, FIX 3515): the reliability head the posterior read selects, or
/// with none, the rows its prior's tier was read from. A host lists them
/// beside an answer that shows the skill's reliability.
///
/// # Errors
///
/// A read failure, or a skill record or head that does not decode.
pub(crate) fn skill_reliability_sources(vault: &Vault, skill: &EntityId) -> Result<Vec<EntityId>> {
    skill_reliability_with_sources(vault, skill).map(|(_, sources)| sources)
}

/// A skill's posterior as [`super::skill_reliability_posterior`] reads it, or
/// with no measured head its prior, and the rows it stands on, from one
/// snapshot.
fn skill_reliability_with_sources(
    vault: &Vault,
    skill: &EntityId,
) -> Result<(SkillReliabilityPosterior, Vec<EntityId>)> {
    let rtxn = vault.store.env.read_txn()?;
    if let Some(head) = resolved_estimate_in_txn(vault, &rtxn, skill, None)? {
        return Ok((
            posterior_from_estimate(&head.estimate)?,
            vec![head.claim_id],
        ));
    }
    let (class, sources) = skill_provenance_trust_class_sourced_in_txn(vault, &rtxn, skill)?;
    Ok((
        SkillReliabilityPosterior::seeded_from_provenance(class),
        sources,
    ))
}

/// The rows [`skill_reliability_prior`] stands on (FIX 7102): the SKILL row,
/// and for a vetted import the hub alias and the scan verdict that cleared its
/// bytes. The optimize brief unions them into its source set.
pub(crate) fn skill_reliability_prior_rows(
    vault: &Vault,
    skill: &EntityId,
) -> Result<Vec<EntityId>> {
    let rtxn = vault.store.env.read_txn()?;
    skill_provenance_trust_class_sourced_in_txn(vault, &rtxn, skill).map(|(_, rows)| rows)
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
