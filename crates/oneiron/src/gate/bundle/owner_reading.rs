//! The checks the owner's bundle door makes on a read before it asks for the
//! person at this device, written once: the settlement makes the same ones
//! again in its write.

use super::*;
use crate::consent::OwnerAuthoredWrite;

impl Vault {
    /// The refusals the owner's resolution of a run's bundle makes before its
    /// first write, on `txn`, in the settlement's order: the owner's proof,
    /// the live group at `expected_bundle_id`, the policy manifest, and the
    /// first member's checks before its replay, which is the settlement's
    /// first write. An approval also makes each policy member's own checks,
    /// which the settlement makes after that member's replay. Answers whether
    /// a live member is a proactivity policy request.
    pub(super) fn read_owner_bundle_resolution_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        owner: &AuthenticatedOwner,
        expected_bundle_id: [u8; 32],
        dreamer_run_id: &str,
        action: GateConsentBundleAction,
    ) -> Result<bool> {
        let (actor, _) = self.bundle_owner_in_txn(txn, owner)?;
        let _ = expected_bundle_id;
        let members = gate_consent_bundle_members_in_txn(&self.store, txn, dreamer_run_id)?;
        let _ = resolve_policy_manifest(&self.store, txn)?;
        // The first member's replay starts the write. Its read checks run first.
        if let Some(entry) = members.first() {
            let (mut body, _, _) = self.bundle_member_before_replay_in_txn(txn, entry)?;
            if action == GateConsentBundleAction::Approve {
                body.approval = ClaimApprovalStatus::Approved;
            }
            let class = BundleSettler::Owner(owner, None).actor_class();
            let _ = bundle_replay_envelope(&body, WriteActor::new(actor, class))?;
        }
        let mut has_policy_request = false;
        for entry in &members {
            if entry.body.predicate == PROACTIVITY_POLICY_REQUEST_PREDICATE {
                has_policy_request = true;
                if action == GateConsentBundleAction::Approve {
                    let id = entry.member.claim_id;
                    let (body, _) = live_claim_parts_in_txn(&self.store, txn, &id)?;
                    let _ = self.bundled_policy_proposal_in_txn(txn, owner, id, &body)?;
                }
            }
        }
        Ok(has_policy_request)
    }

    /// The owner's proof for a bundle settlement, revalidated on `txn`: the
    /// acting owner, and the owner-tier answer where the proof gives one.
    pub(super) fn bundle_owner_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        owner: &AuthenticatedOwner,
    ) -> Result<(EntityId, Option<OwnerAuthoredWrite>)> {
        Ok((
            // The proof is rechecked where the decision commits: an
            // owner whose person, credential or ownership went away
            // while the call waited for the writer decides nothing.
            owner.revalidate_in_txn(self, txn)?,
            // An owner-tier proof answers each member's obligation,
            // for the revision its row showed; a narrower one answers
            // none.
            owner.owner_answer_in_txn(self, txn)?,
        ))
    }

    /// The run's live members, read on `txn`: the group is not empty and its
    /// id is `expected_bundle_id`, the bundle the settler reviewed.
    pub(super) fn live_bundle_group_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        dreamer_run_id: &str,
        expected_bundle_id: [u8; 32],
    ) -> Result<Vec<BundleDigestMember>> {
        let members = gate_consent_bundle_members_in_txn(&self.store, txn, dreamer_run_id)?;
        if members.is_empty() {
            return Err(Error::EntityNotFound);
        }
        let bundle_id = gate_consent_bundle_id(dreamer_run_id, &members);
        if bundle_id != expected_bundle_id {
            // Reported against the lowest-sorted live member: the drift is
            // the group's, and the group is never empty here.
            return Err(Error::Gate(GateError::GateConsentStale {
                claim_id: members[0].member.claim_id,
            }));
        }
        Ok(members)
    }

    /// One member's checks before its replay, on `txn`: its live body and
    /// header, the consent binding its pending row was parked on, and whether
    /// it is a MACHINE claim, which changes only through its signed history.
    pub(super) fn bundle_member_before_replay_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        entry: &BundleDigestMember,
    ) -> Result<(ClaimBody, EntityMetadataHeader, bool)> {
        let id = entry.member.claim_id;
        let (body, header) = live_claim_parts_in_txn(&self.store, txn, &id)?;
        // The digest already bound this body; the consent binding is
        // checked too, so the member is redeemed against the same
        // content-addressed handle the pending row was parked on.
        let (diff_handle, read_frontier_hash) =
            claim_consent_binding_parts(&self.store, txn, &body)?;
        if diff_handle != entry.member.diff_handle
            || read_frontier_hash != entry.member.read_frontier_hash
        {
            return Err(Error::Gate(GateError::GateConsentStale { claim_id: id }));
        }
        // A MACHINE claim changes only through its signed history,
        // whose fold rejects without retracting.
        let machine = crate::authority::machine_claim_needs_history(&self.store, txn, &body)?;
        Ok((body, header, machine))
    }
}

/// The envelope a member's `body` replays under as `actor`. A body with no
/// source is refused.
pub(super) fn bundle_replay_envelope(body: &ClaimBody, actor: WriteActor) -> Result<WriteEnvelope> {
    let source = body.source.ok_or(Error::InvalidClaimBody(
        "gate consent bundle member missing claim source",
    ))?;
    Ok(WriteEnvelope::new(
        actor,
        source,
        WriteProvenance::new(Value::from(GATE_BUNDLE_PROVENANCE))?,
        body.approval,
    ))
}
