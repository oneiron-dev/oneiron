//! A curator rung the owner approved (FIX 3223). A rung on a critical target,
//! or one the Gate parked, lands Proposed in the run tray (ARCH-0026: a
//! critical replacement waits), and the owner's approval of its finding is
//! the one consent it takes. The rung then applies as the Dreamer, once, in
//! one write with the target's before-state as its inverse and the Dreamer's
//! receipt naming the approved revision. It never parks behind a second
//! consent and never stages the target's transition as the embedded owner.
use super::super::applied::{record_approved_in_txn, recorded_in_txn};
use super::super::{CURATOR_FACET, invalid};
use super::{PROPOSAL_PREDICATE, apply_in_txn};
use crate::attempt_queue::AttemptId;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::ports::EntityStoreRead;
use crate::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, EntityId, Result, Vault};

/// Applies the curator findings among `approved` once the owner's approval
/// of them has committed (FIX 470), so a run-tray approval moves its rungs at
/// once rather than at the next nightly pass. Each finding applies in a
/// grouped write of its own, as the nightly pass applies it, through
/// `Vault::apply_approved_curator_in_txn` with no pass attempt: a finding
/// already applied, or one whose target moved, applies nothing. A finding
/// that fails stays approved for the nightly pass to retry, and failures are
/// logged by count and kind alone. The approval never fails here.
pub fn apply_after_consent(vault: &Vault, approved: impl IntoIterator<Item = EntityId>, now: u64) {
    let findings = match curator_findings(vault, approved) {
        Ok(findings) => findings,
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "curator: approved findings were not read; the nightly pass applies them"
            );
            return;
        }
    };
    let mut kinds = Vec::new();
    for proposal in findings {
        if let Err(error) = vault.with_write_txn_grouped(|txn| {
            vault.apply_approved_curator_in_txn(txn, proposal, None, now)
        }) {
            kinds.push(error.kind());
        }
    }
    if !kinds.is_empty() {
        tracing::warn!(
            failed = kinds.len(),
            ?kinds,
            "curator: approved findings did not apply; the nightly pass retries them"
        );
    }
}

/// The curator findings among `ids` that stand approved, read in one
/// snapshot, so an approval that holds none opens no writer.
fn curator_findings(
    vault: &Vault,
    ids: impl IntoIterator<Item = EntityId>,
) -> Result<Vec<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    let mut findings = Vec::new();
    for id in ids {
        if vault.get_claim_in_txn(&txn, &id)?.is_some_and(|body| {
            body.predicate == PROPOSAL_PREDICATE && body.approval == ClaimApprovalStatus::Approved
        }) {
            findings.push(id);
        }
    }
    Ok(findings)
}

impl Vault {
    /// Applies the owner-approved curator finding `proposal` in the caller's
    /// write, as the Dreamer, and records it applied with its inverse and
    /// the Dreamer's receipt. The finding must be the Dreamer's own live
    /// curator finding at Approved and not applied before, and its target
    /// still the live body it graded with no demotion parked on it (one an
    /// earlier pass parked behind its own consent waits there). Returns the
    /// target the rung moved; `None` when any of that fails, so a replayed
    /// pass, or a consent door that runs it after the approval commits in
    /// its own write, applies nothing twice. `attempt` is the curator pass
    /// that applies it, none for a consent door.
    ///
    /// # Errors
    ///
    /// Storage errors, and the rung's own refusals (a rung out of order, a
    /// weakening before the engine's identities are provisioned).
    pub(crate) fn apply_approved_curator_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        proposal: EntityId,
        attempt: Option<AttemptId>,
        now: u64,
    ) -> Result<Option<EntityId>> {
        let dreamer = self.dreamer_authority_in_txn(txn, now)?;
        let Some(finding) = self.get_claim_in_txn(&*txn, &proposal)? else {
            return Ok(None);
        };
        if finding.predicate != PROPOSAL_PREDICATE
            || finding.source != Some(ClaimSource::Generated)
            || finding.lifecycle != ClaimLifecycleStatus::Active
            || finding.approval != ClaimApprovalStatus::Approved
            || crate::claim::session_claim_producer(&finding) != Some(dreamer.entity_ref())
            || recorded_in_txn(self, &*txn, proposal)?
        {
            return Ok(None);
        }
        let value: serde_json::Value =
            serde_json::from_str(finding.value.as_str().ok_or_else(invalid)?)
                .map_err(|_| invalid())?;
        let target = EntityId::from_hex(value["target"].as_str().ok_or_else(invalid)?)?;
        let source_hash = value["source_hash"].as_str().ok_or_else(invalid)?;
        // The target revision the owner approved, consumed once: a body that
        // moved since (this rung applied, or any other write) is left alone.
        let Some(raw) = EntityStoreRead::port_entity_raw(&self.store, &*txn, &target)? else {
            return Ok(None);
        };
        let header = EntityMetadataHeader::parse(&raw).ok_or_else(invalid)?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
            || raw.len() == ENTITY_METADATA_HEADER_LEN
            || blake3::hash(&raw[ENTITY_METADATA_HEADER_LEN..])
                .to_hex()
                .as_str()
                != source_hash
        {
            return Ok(None);
        }
        let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        if body.lifecycle != ClaimLifecycleStatus::Active
            || self.has_deferred_claim_in_txn(&*txn, &target)?
        {
            return Ok(None);
        }
        let inverse = apply_in_txn(self, txn, &value, now)?;
        record_approved_in_txn(
            self,
            txn,
            proposal,
            attempt,
            CURATOR_FACET,
            dreamer,
            inverse,
            now,
        )?;
        Ok(Some(target))
    }
}
