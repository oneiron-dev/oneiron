//! Propose/stamp amendment transaction: classification, activation, notices, proposal hash.

use sha2::{Digest, Sha256};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::Store;

use super::pack_store::{
    active_compliance_pack_in_txn, encode_pack, invalid_pack, store_active_compliance_pack,
    validate_compliance_pack,
};
use super::rules::{CompliancePack, PROPOSAL_HASH_DOMAIN};

/// The one staged proposal awaiting an owner stamp. Key: `()`.
const PENDING: SideTable<(), CompliancePack, Named> =
    SideTable::new(&side_table::CAMPAIGN_COMPLIANCE_PENDING);
/// The durable activation-notice log, keyed by the activated pack version so
/// one version can never write two notices. Key: `pack_version` (u32
/// big-endian).
const NOTICE: SideTable<[u8; 4], String, Raw> =
    SideTable::new(&side_table::CAMPAIGN_COMPLIANCE_NOTICE);

// ---------------------------------------------------------------------------
// Amendment: tighten auto, loosen or ambiguous waits for the owner stamp
// ---------------------------------------------------------------------------

/// What an amendment does to the pack's strictness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComplianceAmendmentClass {
    /// Provably stricter: rows added, dials tightened, nothing relaxed.
    Tightening,
    /// Policy semantics unchanged; only citations, verification dates, penalty
    /// notes, or the engine-version floor moved.
    MetadataRefresh,
    /// Anything that relaxes the pack, and anything the comparator cannot
    /// order. Free-text requirement edits live here: an unorderable change is
    /// not guessed safe.
    LooseningOrAmbiguous,
}

/// What a proposal did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ComplianceAmendmentOutcome {
    /// Activated immediately, with a durable notice.
    Applied {
        /// The now-active pack version.
        pack_version: u32,
        /// The notice persisted alongside the activation.
        notice: String,
    },
    /// Staged. Nothing changed until an owner stamps this exact hash.
    PendingOwnerStamp {
        /// Canonical hash binding the exact proposed rows and version.
        proposal_hash: [u8; 32],
    },
}

/// Orders `proposed` against `current`.
///
/// # Errors
///
/// [`Error::InvalidConfig`](crate::Error::InvalidConfig) when the proposal is malformed, renames the pack,
/// or fails to advance the pack version.
pub fn classify_compliance_amendment(
    current: &CompliancePack,
    proposed: &CompliancePack,
) -> Result<ComplianceAmendmentClass> {
    validate_compliance_pack(proposed)?;
    if proposed.pack_id != current.pack_id {
        return Err(invalid_pack("an amendment may not rename the pack"));
    }
    if proposed.pack_version <= current.pack_version {
        return Err(invalid_pack("an amendment must advance the pack version"));
    }
    let rows = classify_row_delta(current, proposed);
    let dials = classify_dial_delta(current, proposed);
    Ok(
        match (
            rows.loosened || dials.loosened,
            rows.tightened || dials.tightened,
        ) {
            (true, _) => ComplianceAmendmentClass::LooseningOrAmbiguous,
            (false, true) => ComplianceAmendmentClass::Tightening,
            (false, false) => ComplianceAmendmentClass::MetadataRefresh,
        },
    )
}

#[derive(Debug, Default)]
struct AmendmentDelta {
    loosened: bool,
    tightened: bool,
}

/// A row set is stricter only when every current row survives byte-identically
/// on its semantic axes and the rows added are provably additive. A deleted
/// row, a widened exemption, and any requirement-text edit are all unorderable.
///
/// Adding a row is additive only under a jurisdiction the pack ALREADY seeds.
/// Seeding a NEW one is not: [`trusted_jurisdiction`] trusts any token the pack
/// holds a row for, so the addition takes that token OUT of the unknown
/// disposition and hands it to exactly the rows the proposal supplied — which
/// may be thinner than the strict pole it used to route to. Row addition is
/// therefore not monotone in the selected requirement set, and the case the
/// comparator cannot order waits for the stamp like every other one.
fn classify_row_delta(current: &CompliancePack, proposed: &CompliancePack) -> AmendmentDelta {
    let mut delta = AmendmentDelta::default();
    for row in &current.rows {
        match proposed
            .rows
            .iter()
            .find(|candidate| candidate.key() == row.key())
        {
            Some(candidate) if candidate.semantics() == row.semantics() => {}
            _ => delta.loosened = true,
        }
    }
    for added in proposed
        .rows
        .iter()
        .filter(|row| !current.rows.iter().any(|held| held.key() == row.key()))
    {
        if current
            .rows
            .iter()
            .any(|held| held.jurisdiction == added.jurisdiction)
        {
            delta.tightened = true;
        } else {
            delta.loosened = true;
        }
    }
    delta
}

fn classify_dial_delta(current: &CompliancePack, proposed: &CompliancePack) -> AmendmentDelta {
    let mut delta = AmendmentDelta::default();
    // A longer trust window and a lower confidence floor both admit sends the
    // current pack refuses.
    delta.loosened |= proposed.verified_at_max_age_secs > current.verified_at_max_age_secs;
    delta.loosened |= proposed.jurisdiction_confidence_floor_millis
        < current.jurisdiction_confidence_floor_millis;
    delta.loosened |= proposed.strict_pole_jurisdiction != current.strict_pole_jurisdiction;
    delta.loosened |= current
        .prohibited_list_provenance_classes
        .iter()
        .any(|class| !proposed.prohibited_list_provenance_classes.contains(class));
    delta.loosened |= current
        .conditional_exemption_evidence
        .iter()
        .any(|binding| !proposed.conditional_exemption_evidence.contains(binding));
    delta.tightened |= proposed.verified_at_max_age_secs < current.verified_at_max_age_secs;
    delta.tightened |= proposed.jurisdiction_confidence_floor_millis
        > current.jurisdiction_confidence_floor_millis;
    delta.tightened |= proposed
        .prohibited_list_provenance_classes
        .iter()
        .any(|class| !current.prohibited_list_provenance_classes.contains(class));
    delta
}

/// The only public activation path.
///
/// A provable tightening or a provenance-only refresh activates immediately
/// with a durable notice; anything else is staged behind an owner stamp bound
/// to the exact proposed rows and version.
///
/// # Errors
///
/// The classifier's rejections, plus storage errors.
pub fn propose_compliance_amendment(
    vault: &Vault,
    proposer: EntityId,
    proposed: CompliancePack,
) -> Result<ComplianceAmendmentOutcome> {
    apply_compliance_amendment(vault, &proposer.to_hex(), proposed)
}

/// OF-401's narrow ingestion hook.
///
/// It runs the SAME classifier as every other proposal, so a published update
/// cannot loosen the pack without an owner stamp. This mints no publisher
/// runtime, scheduler, or transport.
///
/// # Errors
///
/// As [`propose_compliance_amendment`].
pub fn ingest_published_compliance_update(
    vault: &Vault,
    proposed: CompliancePack,
) -> Result<ComplianceAmendmentOutcome> {
    apply_compliance_amendment(vault, "publisher-loop", proposed)
}

fn apply_compliance_amendment(
    vault: &Vault,
    proposer: &str,
    proposed: CompliancePack,
) -> Result<ComplianceAmendmentOutcome> {
    let mut wtxn = vault.store.env.write_txn()?;
    let current = active_compliance_pack_in_txn(&vault.store, &wtxn)?;
    let class = classify_compliance_amendment(&current, &proposed)?;
    let outcome = match class {
        ComplianceAmendmentClass::LooseningOrAmbiguous => {
            PENDING.put(&vault.store, &mut wtxn, &(), &proposed)?;
            ComplianceAmendmentOutcome::PendingOwnerStamp {
                proposal_hash: compliance_proposal_hash(&proposed)?,
            }
        }
        ComplianceAmendmentClass::Tightening | ComplianceAmendmentClass::MetadataRefresh => {
            activate_compliance_pack(&vault.store, &mut wtxn, &proposed, class, proposer)?
        }
    };
    wtxn.commit()?;
    Ok(outcome)
}

/// The owner gate: activates the staged proposal iff the stamp binds the exact
/// rows and version that were staged.
///
/// # Errors
///
/// [`Error::InvalidConfig`](crate::Error::InvalidConfig) when nothing is staged, when the hash names
/// different rows or a different version, or when the staged proposal no longer
/// advances the active version.
pub fn stamp_compliance_amendment(
    vault: &Vault,
    owner: EntityId,
    proposal_hash: [u8; 32],
) -> Result<CompliancePack> {
    let mut wtxn = vault.store.env.write_txn()?;
    let Some(pending) = PENDING.get(&vault.store, &wtxn, &())? else {
        return Err(invalid_pack("no amendment is awaiting an owner stamp"));
    };
    if compliance_proposal_hash(&pending)? != proposal_hash {
        return Err(invalid_pack(
            "owner stamp does not bind the staged rows and version",
        ));
    }
    let current = active_compliance_pack_in_txn(&vault.store, &wtxn)?;
    if pending.pack_version <= current.pack_version {
        return Err(invalid_pack("staged amendment no longer advances the pack"));
    }
    activate_compliance_pack(
        &vault.store,
        &mut wtxn,
        &pending,
        ComplianceAmendmentClass::LooseningOrAmbiguous,
        &owner.to_hex(),
    )?;
    PENDING.delete(&vault.store, &mut wtxn, &())?;
    wtxn.commit()?;
    Ok(pending)
}

fn activate_compliance_pack(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    pack: &CompliancePack,
    class: ComplianceAmendmentClass,
    actor: &str,
) -> Result<ComplianceAmendmentOutcome> {
    store_active_compliance_pack(store, wtxn, pack)?;
    let notice = format!(
        "campaign compliance pack {} activated at version {} ({}) by {}; {} rows",
        pack.pack_id,
        pack.pack_version,
        amendment_class_token(class),
        actor,
        pack.rows.len(),
    );
    NOTICE.put(store, wtxn, &pack.pack_version.to_be_bytes(), &notice)?;
    Ok(ComplianceAmendmentOutcome::Applied {
        pack_version: pack.pack_version,
        notice,
    })
}

const fn amendment_class_token(class: ComplianceAmendmentClass) -> &'static str {
    match class {
        ComplianceAmendmentClass::Tightening => "tightening",
        ComplianceAmendmentClass::MetadataRefresh => "metadata refresh",
        ComplianceAmendmentClass::LooseningOrAmbiguous => "owner stamped",
    }
}

/// Every durable activation notice, oldest version first.
///
/// # Errors
///
/// Storage errors, and [`Error::CorruptedIndex`](crate::Error::CorruptedIndex) when a notice is not UTF-8.
pub fn compliance_amendment_notices(vault: &Vault) -> Result<Vec<String>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(NOTICE
        .scan(&vault.store, &rtxn)?
        .into_iter()
        .map(|(_, notice)| notice)
        .collect())
}

/// Canonical hash of a proposal: the exact rows, in a canonical order, plus the
/// pack version and every dial that decides how those rows apply.
///
/// # Errors
///
/// [`Error::InvariantViolation`](crate::Error::InvariantViolation) when the canonical form cannot be encoded.
pub fn compliance_proposal_hash(pack: &CompliancePack) -> Result<[u8; 32]> {
    let mut canonical = pack.clone();
    canonical.rows.sort_by(|left, right| {
        (&left.jurisdiction, &left.channel, left.rule_kind).cmp(&(
            &right.jurisdiction,
            &right.channel,
            right.rule_kind,
        ))
    });
    canonical.prohibited_list_provenance_classes.sort_unstable();
    canonical
        .conditional_exemption_evidence
        .sort_by(|left, right| left.jurisdiction.cmp(&right.jurisdiction));
    let mut hasher = Sha256::new();
    hasher.update(PROPOSAL_HASH_DOMAIN);
    hasher.update(encode_pack(&canonical)?);
    Ok(hasher.finalize().into())
}
