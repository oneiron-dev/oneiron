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

use std::borrow::Cow;

use crate::Vault;
use crate::claim::ClaimApprovalStatus;
use crate::error::{Error, ErrorKind, Result};
use crate::skill::{SkillContentHash, SkillLifecycle, SkillRecord, encode_skill_record};
use crate::skill_hub::{
    HubPackage, ScanCompleteness, ScanRiskLevel, ScanVerdict, SkillGovernance, SkillScanReceipt,
};

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

/// Bytes read from any one package file during the static pass.
///
/// A hub file may be up to 16 MiB and a package up to 32 MiB; tokenizing all of
/// that on every import buys little (credentials live near the top of config
/// and script files) and costs real import latency. An oversized file is
/// scanned to this budget and the receipt drops to
/// [`ScanCompleteness::Partial`] — partial coverage, honestly labelled, beats
/// either a silent skip or an unbounded scan.
const MAX_SCAN_BYTES_PER_FILE: usize = 1024 * 1024;

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
/// 3. **Structure** — an empty tree has nothing to scan, and an oversized file
///    is scanned only to [`MAX_SCAN_BYTES_PER_FILE`]; either drops completeness
///    to `Partial`.
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

    for file in &package.files {
        let scanned = match file.content.get(..MAX_SCAN_BYTES_PER_FILE) {
            Some(head) => {
                complete = false;
                head
            }
            None => file.content.as_slice(),
        };
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
    scan_gate_for_activation_in_txn(vault, &rtxn, content_hash)
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
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    content_hash: SkillContentHash,
) -> Result<ActivationPosture> {
    let threshold = activation_risk_threshold_in_txn(vault, rtxn)?;
    let mut worst = ScanRiskLevel::None;
    for body in vault.skill_scan_verdicts_for_content_hash_in_txn(rtxn, content_hash)? {
        worst = worst.max(crate::skill_hub::scan_verdict_row_risk(&body)?);
    }
    Ok(if worst >= threshold {
        ActivationPosture::ProposedRequired { risk: worst }
    } else {
        ActivationPosture::AutoEligible
    })
}

/// The approval an update should land with, once the scan gate has spoken.
///
/// Consults ONLY on a transition INTO `active` — that is the moment a skill
/// becomes loadable canon (`SkillLifecycle::loads_as_canon`), and it covers
/// candidate admission, stale revival, and post-quarantine reactivation alike.
/// Every other update (content revision, cache refresh, supersession) is left
/// exactly as the caller wrote it.
///
/// Returns a borrow on the common path: the escalation clones, nothing else
/// does.
pub(crate) fn consult_activation_scan_gate_in_txn<'a>(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    prior: &SkillRecord,
    updated: &'a SkillRecord,
) -> Result<Cow<'a, SkillRecord>> {
    if prior.lifecycle_status == SkillLifecycle::Active
        || updated.lifecycle_status != SkillLifecycle::Active
        || updated.approval_status != ClaimApprovalStatus::Auto
    {
        return Ok(Cow::Borrowed(updated));
    }
    let Some(content_hash) = updated.content_hash else {
        return Ok(Cow::Borrowed(updated));
    };
    let posture = scan_gate_for_activation_in_txn(vault, rtxn, content_hash)?;
    let escalated = posture.approval_for(updated.approval_status);
    if escalated == updated.approval_status {
        return Ok(Cow::Borrowed(updated));
    }
    let mut record = updated.clone();
    record.approval_status = escalated;
    Ok(Cow::Owned(record))
}

/// Reads the persisted activation risk threshold (default: `High`).
pub fn skill_scan_activation_risk_threshold(vault: &Vault) -> Result<ScanRiskLevel> {
    let rtxn = vault.store.env.read_txn()?;
    activation_risk_threshold_in_txn(vault, &rtxn)
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
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
) -> Result<ScanRiskLevel> {
    let Some(raw) = vault
        .store
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
