//! Deterministic static skill scanning and the activation risk consult.
//!
//! ONE-1892 gives the landed scan-verdict substrate (`skill_hub`) its first
//! production PRODUCER and its first production CONSUMER:
//!
//! * **Producer** — [`run_static_skill_scan`] is a pure, deterministic pass over
//!   a fetched [`HubPackage`]; the hub import/sync doors run it and ingest its
//!   receipt through the landed [`Vault::ingest_skill_scan_verdict`] door, so
//!   verdict rows exist without any manual ingest call.
//! * **Consumer** — [`scan_gate_for_activation`] reads the content-keyed
//!   verdicts at skill ACTIVATION and returns a POSTURE. It is a dial, never a
//!   wall: the worst posture it can return escalates consent from `auto` to
//!   `proposed` (an owner tap). There is no refusal path in this module.
//!
//! The provider id is pluggable ([`SCAN_PROVIDER_STATIC_V1`]) so hub-side or
//! model-driven scanners join later as ADDITIONAL rows on the same content
//! anchor rather than replacing this one.

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::ClaimApprovalStatus;
use crate::entity_id::EntityId;
use crate::error::{Error, ErrorKind, Result};
use crate::registry::ENTITY_TYPE_SKILL;
use crate::skill::{
    SkillContentHash, SkillLifecycle, SkillRecord, decode_skill_record, encode_skill_record,
};
use crate::skill_hub::{
    HubPackage, ScanCompleteness, ScanRiskLevel, ScanVerdict, SkillGovernance, SkillScanReceipt,
};
use crate::store::Store;

/// Provider id minted by the engine's own deterministic static pass.
///
/// Versioned in the string: a v2 pass with different checks is a DIFFERENT
/// provider, so its rows sit beside the v1 rows instead of silently superseding
/// them under a shared key.
pub const SCAN_PROVIDER_STATIC_V1: &str = "oneiron.static.v1";

/// `vault_meta` key for the activation risk threshold dial.
///
/// The key lives in the owning module rather than `settings.rs` (house pattern,
/// cf. `inbox::INBOX_REVIEW_DIAL_KEY`): `settings.rs` is UI customization, and
/// this is a per-feature policy dial.
pub const SKILL_SCAN_ACTIVATION_RISK_THRESHOLD_KEY: &[u8] =
    b"settings:skill_scan:v1:activation_risk_threshold";

/// Default risk at which activation escalates from `auto` to `proposed`.
///
/// `High` is where the static pass places an embedded-credential finding, so
/// the default dial makes exactly that class ask for an owner tap. Capability
/// breadth (`Low`/`Medium`) is signal recorded on the row, not a consent event.
pub const DEFAULT_ACTIVATION_RISK_THRESHOLD: ScanRiskLevel = ScanRiskLevel::High;

/// The scan budget IS the admission envelope: every byte a hub package can
/// legally carry through the import door is a byte this pass reads.
///
/// An earlier, smaller budget (1 MiB/file) was a detection bypass, not a
/// defense: `HubPackage` admits 16 MiB files, so a credential parked past the
/// prefix rode in with `risk = None` while the receipt claimed only
/// [`ScanCompleteness::Partial`] — and the activation gate reads `riskLevel`
/// alone, so the honest label was inert. Anchoring the budget to the admission
/// caps closes that gap and keeps the work bounded by the same numbers the
/// import door already enforces: nothing importable is scanned partially, and
/// a package too big to import (only reachable by calling this pure pass
/// directly) is still read to the envelope and honestly labelled `Partial`.
const MAX_SCAN_BYTES_PER_FILE: usize = crate::skill_hub::MAX_HUB_FILE_BYTES;
const MAX_SCAN_BYTES_PER_PACKAGE: usize = crate::skill_hub::MAX_HUB_PACKAGE_TOTAL_BYTES;

/// What the activation consult says about one skill's canonical bytes.
///
/// Deliberately two states, neither of which is a refusal: the scan gate can
/// raise the consent bar and nothing more (ARCH anti-safetyism — escalate
/// consent, never block the act).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationPosture {
    /// No verdict at or above the dial: activation may land on `auto`.
    AutoEligible,
    /// A verdict at or above the dial: activation lands `proposed`, so the
    /// owner taps it through.
    ProposedRequired { risk: ScanRiskLevel },
}

impl ActivationPosture {
    /// The approval status an activating record must land with, given what the
    /// caller asked for.
    ///
    /// Only `auto` is escalated. `approved` is already an owner act — rewriting
    /// it to `proposed` would re-ask a question the owner answered — and
    /// `proposed`/`rejected` are at or past the bar already.
    #[must_use]
    pub const fn approval_for(self, requested: ClaimApprovalStatus) -> ClaimApprovalStatus {
        match (self, requested) {
            (Self::ProposedRequired { .. }, ClaimApprovalStatus::Auto) => {
                ClaimApprovalStatus::Proposed
            }
            _ => requested,
        }
    }
}

/// Runs the deterministic static pass over a fetched package.
///
/// Three checks, each contributing to the risk ladder (the receipt carries the
/// MAXIMUM):
///
/// 1. **Embedded credentials** — every package file and the encoded skill
///    record run through the batch credential detector
///    (`batch::secret_scan::scan_metadata_field`, call-reuse: the regex set has
///    exactly one owner). A hit is `High`.
/// 2. **Capability breadth** — a declared `env` requirement asks for the host
///    process's environment, which is where credentials live: `Medium`. A
///    declared bin / MCP / allowed tool is ordinary surface: `Low`.
/// 3. **Structure** — an empty tree has nothing to scan, and a tree past the
///    admission envelope (`MAX_SCAN_BYTES_PER_FILE` per file,
///    `MAX_SCAN_BYTES_PER_PACKAGE` in total) is read only that far; either
///    drops completeness to `Partial`. An importable package is always read in
///    full.
///
/// The verdict axis is `Suspicious` on a credential hit and **`Unknown`
/// otherwise — never `Clean`**. A pattern scan can find known-bad shapes; it
/// cannot establish that bytes are safe, and `Clean` is read downstream as a
/// real clearance (`skill_reliability::provenance_trust_class` seeds its most
/// optimistic prior off it). Only a scanner that actually vets content may
/// claim that, and such a scanner joins as its own provider.
///
/// `Critical` and `Prohibited` are likewise never machine-minted here: the
/// governance axis is policy, and this pass has no policy standing beyond
/// flagging its own finding as `Discouraged`.
pub fn run_static_skill_scan(package: &HubPackage, scanned_at: u64) -> Result<SkillScanReceipt> {
    let mut risk = ScanRiskLevel::None;
    let mut complete = !package.files.is_empty();
    let mut remaining = MAX_SCAN_BYTES_PER_PACKAGE;

    for file in &package.files {
        let budget = MAX_SCAN_BYTES_PER_FILE.min(remaining);
        let scanned = if file.content.len() > budget {
            complete = false;
            &file.content[..budget]
        } else {
            file.content.as_slice()
        };
        remaining -= scanned.len();
        if carries_credential(scanned)? {
            risk = risk.max(ScanRiskLevel::High);
        }
    }
    if carries_credential(&encode_skill_record(&package.record)?)? {
        risk = risk.max(ScanRiskLevel::High);
    }

    let surface = &package.capabilities;
    if !surface.env.is_empty() {
        risk = risk.max(ScanRiskLevel::Medium);
    } else if !(surface.bins.is_empty()
        && surface.mcp.is_empty()
        && surface.allowed_tools.is_empty())
    {
        risk = risk.max(ScanRiskLevel::Low);
    }

    let flagged = risk >= ScanRiskLevel::High;
    SkillScanReceipt::new(
        SCAN_PROVIDER_STATIC_V1,
        scanned_at,
        if flagged {
            ScanVerdict::Suspicious
        } else {
            ScanVerdict::Unknown
        },
        risk,
        if complete {
            ScanCompleteness::Complete
        } else {
            ScanCompleteness::Partial
        },
        if flagged {
            SkillGovernance::Discouraged
        } else {
            SkillGovernance::Recommended
        },
    )
}

/// True when the batch credential detector rejects these bytes.
///
/// The detector's contract is a `Result` — it is built to REFUSE a write — so
/// its rejection is read here as the finding it is. Any other error class is
/// propagated: only the credential rejection is a scan finding.
fn carries_credential(data: &[u8]) -> Result<bool> {
    let text = String::from_utf8_lossy(data);
    match crate::batch::secret_scan::scan_metadata_field(&text) {
        Ok(()) => Ok(false),
        Err(error) if error.kind() == ErrorKind::GateWriteRejected => Ok(true),
        Err(error) => Err(error),
    }
}

/// Reads the activation posture for one skill's canonical bytes.
pub fn scan_gate_for_activation(
    vault: &Vault,
    content_hash: SkillContentHash,
) -> Result<ActivationPosture> {
    let rtxn = vault.store.env.read_txn()?;
    scan_gate_for_activation_in_txn(&vault.store, &rtxn, content_hash)
}

/// [`scan_gate_for_activation`] inside the caller's transaction.
///
/// The activation door consults from INSIDE its write transaction, so a verdict
/// landing between the consult and the write cannot slip an escalation.
///
/// Bytes with NO verdict are `AutoEligible`. Absence of a scan is not evidence
/// of risk, and refusing to activate unscanned bytes would be exactly the wall
/// this gate is specified not to be — the producer is what makes verdicts
/// common, not a block on activation.
pub(crate) fn scan_gate_for_activation_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    content_hash: SkillContentHash,
) -> Result<ActivationPosture> {
    let threshold = activation_risk_threshold_in_txn(store, rtxn)?;
    let mut worst = ScanRiskLevel::None;
    for body in
        crate::skill_hub::skill_scan_verdicts_for_content_hash_in_store(store, rtxn, content_hash)?
    {
        worst = worst.max(crate::skill_hub::scan_verdict_row_risk(&body)?);
    }
    Ok(if worst >= threshold {
        ActivationPosture::ProposedRequired { risk: worst }
    } else {
        ActivationPosture::AutoEligible
    })
}

/// Escalates an activating SKILL body's consent stamp, in place, when the
/// scan gate asks for an owner tap. Reports whether the stamp moved.
///
/// This is the whole consumer arm, and it lives at the batch
/// entity-materialization chokepoint rather than on any typed door: the typed
/// update door is one road to a SKILL body among several — `Vault::put_entity`
/// and `Vault::batch().put` reach the same bytes without passing it, and an
/// activation gate a caller can walk around is not a gate. Every road converges
/// on `apply_put`, so the consult is wired there once.
///
/// Fires ONLY on a transition INTO `active` — the moment a skill becomes
/// loadable canon (`SkillLifecycle::loads_as_canon`) — which covers candidate
/// admission, stale revival, and post-quarantine reactivation alike. Every
/// other write (create, content revision, cache refresh, supersession) is left
/// exactly as the caller wrote it. A stored body that does not decode as a
/// skill record counts as NOT-active, so a legacy-opaque predecessor is an
/// activation to be consulted rather than a hole to slip through.
pub(crate) fn escalate_activation_approval_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
    updated: &mut SkillRecord,
) -> Result<bool> {
    if updated.lifecycle_status != SkillLifecycle::Active
        || updated.approval_status != ClaimApprovalStatus::Auto
    {
        return Ok(false);
    }
    let Some(content_hash) = updated.content_hash else {
        return Ok(false);
    };
    // No stored body is a CREATE, not an activation: the birth law downstream
    // rejects a locally born `active` skill outright, so there is nothing here
    // to escalate.
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(false);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_SKILL {
        return Ok(false);
    }
    let prior_body = &raw[ENTITY_METADATA_HEADER_LEN..];
    if decode_skill_record(prior_body)
        .is_ok_and(|prior| prior.lifecycle_status == SkillLifecycle::Active)
    {
        return Ok(false);
    }
    let posture = scan_gate_for_activation_in_txn(store, rtxn, content_hash)?;
    let escalated = posture.approval_for(updated.approval_status);
    if escalated == updated.approval_status {
        return Ok(false);
    }
    updated.approval_status = escalated;
    Ok(true)
}

/// Reads the persisted activation risk threshold (default: `High`).
pub fn skill_scan_activation_risk_threshold(vault: &Vault) -> Result<ScanRiskLevel> {
    let rtxn = vault.store.env.read_txn()?;
    activation_risk_threshold_in_txn(&vault.store, &rtxn)
}

/// Sets the activation risk threshold dial.
pub fn set_skill_scan_activation_risk_threshold(
    vault: &Vault,
    threshold: ScanRiskLevel,
) -> Result<()> {
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(
            wtxn,
            SKILL_SCAN_ACTIVATION_RISK_THRESHOLD_KEY,
            threshold.as_str().as_bytes(),
        )?;
        Ok(())
    })
}

fn activation_risk_threshold_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
) -> Result<ScanRiskLevel> {
    let Some(raw) = store
        .vault_meta
        .get(rtxn, SKILL_SCAN_ACTIVATION_RISK_THRESHOLD_KEY)?
    else {
        return Ok(DEFAULT_ACTIVATION_RISK_THRESHOLD);
    };
    let token = std::str::from_utf8(&raw)
        .map_err(|_| Error::CorruptedIndex("skill scan activation risk threshold"))?;
    ScanRiskLevel::parse(token).ok_or(Error::CorruptedIndex(
        "skill scan activation risk threshold",
    ))
}

#[cfg(test)]
mod tests;
