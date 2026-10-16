//! The table's arms for the skill readers. Each head is a reserved write, so
//! each lands on a claim id whose owner-answer obligation is open.

use super::*;
use crate::skill::{SkillContentHash, SkillLifecycle, SkillRecord};
use crate::skill_hub::{HubPin, HubRef, PREDICATE_SKILL_HUB_PROVENANCE};
use crate::skill_reliability::PREDICATE_SKILL_RELIABILITY;

const HELD: u8 = 0x50;
const SETTLED: u8 = 0x51;
const SKILL: u8 = 0x52;

pub(super) fn put_reserved(vault: &Vault, id: EntityId, body: &ClaimBody) -> Result<()> {
    vault.with_write_txn(|wtxn| vault.put_reserved_claim_in_txn(wtxn, &id, body, test_time(2), 2))
}

pub(super) fn observed(predicate: &str, subject: EntityId, value: Value) -> Result<ClaimBody> {
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        value,
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::Observed);
    Ok(body)
}

fn put_skill(
    vault: &Vault,
    source: ClaimSource,
    hash: Option<SkillContentHash>,
) -> Result<EntityId> {
    let skill = test_id(SKILL);
    let mut record = SkillRecord::new(
        "fixture.skill",
        "fixture",
        "1.0.0",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        source,
        0.5,
        false,
        true,
        Vec::new(),
        Value::Map(vec![(Value::from("source"), Value::from("fixture"))]),
    );
    record.content_hash = hash;
    put_raw_entity_row(
        vault,
        &skill,
        crate::registry::ENTITY_TYPE_SKILL,
        &crate::skill::encode_skill_record(&record)?,
    )?;
    Ok(skill)
}

/// A `skill.reliability` head of Beta(50, 10) citing `cited`, receipts with
/// no local outcome row.
fn put_reliability(vault: &Vault, id: EntityId, skill: EntityId, cited: &[&str]) -> Result<()> {
    let mut body = observed(
        PREDICATE_SKILL_RELIABILITY,
        skill,
        Value::Map(vec![
            (Value::from("alpha"), Value::F32(50.0)),
            (Value::from("beta"), Value::F32(10.0)),
        ]),
    )?;
    body.evidence = Some(Value::Array(
        cited.iter().map(|receipt| Value::from(*receipt)).collect(),
    ));
    put_reserved(vault, id, &body)
}

fn put_hub_alias(
    vault: &Vault,
    id: EntityId,
    skill: EntityId,
    hash: &str,
    hub: &HubRef,
) -> Result<()> {
    let body = observed(
        PREDICATE_SKILL_HUB_PROVENANCE,
        skill,
        Value::Map(vec![
            (Value::from("contentHash"), Value::from(hash)),
            (Value::from("hubRef"), hub.to_value()?),
        ]),
    )?;
    put_reserved(vault, id, &body)
}

fn hub() -> Result<HubRef> {
    HubRef::new(test_id(0x4a), "fixture/skill", HubPin::None)
}

/// A clean scan of `hash` through the scan door; its claim id.
fn put_clean_scan(vault: &Vault, skill: EntityId, hash: SkillContentHash) -> Result<EntityId> {
    use crate::skill_hub::{
        ScanCompleteness, ScanRiskLevel, ScanVerdict, SkillGovernance, SkillScanReceipt,
    };
    let receipt = SkillScanReceipt::new(
        "fixture-scanner",
        1,
        ScanVerdict::Clean,
        ScanRiskLevel::None,
        ScanCompleteness::Complete,
        SkillGovernance::Recommended,
    )?;
    vault.ingest_skill_scan_verdict(&skill, hash, &receipt, test_time(3), 3)?;
    let txn = vault.store.env.read_txn()?;
    let heads = crate::skill_hub::skill_scan_verdict_heads_for_content_hash_in_store(
        &vault.store,
        &txn,
        hash,
    )?;
    let [(scan, _)] = heads.as_slice() else {
        panic!("one scan verdict, found {}", heads.len());
    };
    Ok(*scan)
}

/// A projection neither folds, compares nor supersedes a held head: it
/// projects from the skill's prior until the owner answers.
pub(super) fn reliability_projection(vault: &Vault, reader: ConsolidationReader) -> Result<()> {
    put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id()?,
        &crate::gate::default_policy_manifest()?,
    )?;
    let skill = put_skill(vault, ClaimSource::UserStated, None)?;
    put_reliability(vault, test_id(HELD), skill, &["attempt-receipt:remote-a"])?;
    check_transition(vault, test_id(HELD), reader, |v, _| {
        let projected = crate::skill_reliability::project_skill_reliability_for(v, &skill, 10)?;
        Ok(projected.alpha == 50.0 && projected.beta == 10.0)
    })
}

/// A held head is no posterior.
pub(super) fn reliability_posterior(vault: &Vault, reader: ConsolidationReader) -> Result<()> {
    let skill = put_skill(vault, ClaimSource::UserStated, None)?;
    put_reliability(vault, test_id(HELD), skill, &["attempt-receipt:remote-a"])?;
    check_transition(vault, test_id(HELD), reader, |v, _| {
        Ok(
            crate::skill_reliability::skill_reliability_posterior(v, &skill)?
                .is_some_and(|posterior| posterior.alpha == 50.0 && posterior.beta == 10.0),
        )
    })
}

/// A held hub alias vouches for no import: a cleared scan alone is no vetted
/// prior.
pub(super) fn hub_prior(vault: &Vault, reader: ConsolidationReader) -> Result<()> {
    let hash = SkillContentHash::from_bytes([0x3c; 32]);
    let skill = put_skill(vault, ClaimSource::Imported, Some(hash))?;
    put_hub_alias(vault, test_id(HELD), skill, &hash.to_hex(), &hub()?)?;
    put_clean_scan(vault, skill, hash)?;
    check_transition(vault, test_id(HELD), reader, |v, _| {
        Ok(
            crate::skill_reliability::skill_provenance_trust_class(v, &skill)?
                == crate::skill_reliability::ProvenanceTrustClass::VettedImport,
        )
    })
}

/// A held clean scan vets no import a settled hub alias carried.
pub(super) fn scan_prior(vault: &Vault, reader: ConsolidationReader) -> Result<()> {
    let hash = SkillContentHash::from_bytes([0x3c; 32]);
    let skill = put_skill(vault, ClaimSource::Imported, Some(hash))?;
    put_hub_alias(vault, test_id(SETTLED), skill, &hash.to_hex(), &hub()?)?;
    let scan = put_clean_scan(vault, skill, hash)?;
    check_transition(vault, scan, reader, |v, _| {
        Ok(
            crate::skill_reliability::skill_provenance_trust_class(v, &skill)?
                == crate::skill_reliability::ProvenanceTrustClass::VettedImport,
        )
    })
}

/// An unmarked import whose only hub alias is held is not yet a legacy
/// standard skill.
pub(super) fn optimize_hub_vouch(vault: &Vault, reader: ConsolidationReader) -> Result<()> {
    let hash = SkillContentHash::from_bytes([0x3c; 32]);
    let skill = put_skill(vault, ClaimSource::Imported, Some(hash))?;
    put_hub_alias(vault, test_id(HELD), skill, &hash.to_hex(), &hub()?)?;
    check_transition(vault, test_id(HELD), reader, |v, _| {
        Ok(crate::skill_optimize::skill_governance_tier(v, &skill)?
            == crate::skill_optimize::SkillTierVerdict::LegacyStandard)
    })
}

/// A held head cites no receipts into an optimization brief; a settled head
/// with none stays discoverable beside it.
pub(super) fn optimize_citations(vault: &Vault, reader: ConsolidationReader) -> Result<()> {
    let skill = put_skill(vault, ClaimSource::UserStated, None)?;
    put_reliability(vault, test_id(HELD), skill, &["attempt-receipt:held-head"])?;
    put_reliability(vault, test_id(SETTLED), skill, &[])?;
    check_transition(vault, test_id(HELD), reader, |v, _| {
        Ok(v.skill_optimize_reliability_citations_for_test(&skill)?
            .iter()
            .any(|receipt| receipt == "attempt-receipt:held-head"))
    })
}

/// A held hub alias marks no shipped default present.
pub(super) fn hub_default_presence(vault: &Vault, reader: ConsolidationReader) -> Result<()> {
    let skill = test_id(SKILL);
    put_raw_entity_row(vault, &skill, crate::registry::ENTITY_TYPE_SKILL, b"skill")?;
    let source = HubRef::new(test_id(0x53), "fixture/source", HubPin::None)?;
    put_hub_alias(vault, test_id(HELD), skill, &"00".repeat(32), &source)?;
    check_transition(vault, test_id(HELD), reader, |v, _| {
        v.hub_default_source_present_for_test(&skill, &source)
    })
}
