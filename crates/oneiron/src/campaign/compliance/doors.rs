//! Caller-bound doors over the existing compliance classifier and stamp writer.

use crate::consent::AuthenticatedOwner;
use crate::gate::{PolicyApprovalCeiling, agent_definition_ceiling_for_actor, resolve_policy_manifest};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::side_table::{self, Named, SideTable};
use crate::{EdgeActorClass, EntityId, WriteActor};

use super::amend::{
    apply_compliance_amendment_in_txn, compliance_amendment_notices_in_txn,
    pending_compliance_pack_in_txn, reject_compliance_amendment_in_txn,
    stamp_compliance_amendment_in_txn,
};
use super::pack_store::{active_compliance_pack_in_txn, invalid_pack};
use super::*;

const RECEIPTS: SideTable<[u8; 16], ComplianceReceipt, Named> =
    SideTable::new(&side_table::CAMPAIGN_COMPLIANCE_RECEIPT);

impl Memory<'_> {
    /// Installs cited rows through the amendment path, not pack-file activation.
    /// Even an owner install leaves a loosening pending an exact-hash approval.
    pub fn compliance_install_as(
        &self,
        owner: &AuthenticatedOwner,
        input: &ComplianceAmendRequest,
    ) -> MemoryResult<ComplianceReceipt> {
        self.with_verified_actor_write_txn(|txn| {
            require_owner(self, owner, txn)?;
            amend_in_txn(self, txn, input, ComplianceOperation::Install, true)
        })
    }

    /// Any authenticated writer may propose; its live actor ceiling still
    /// decides whether a tightening or provenance refresh takes effect now.
    pub fn compliance_amend(&self, input: &ComplianceAmendRequest) -> MemoryResult<ComplianceReceipt> {
        self.with_verified_actor_write_txn(|txn| {
            let vault = self.vault();
            let policy = resolve_policy_manifest(&vault.store, txn)?;
            if policy.is_fail_closed() {
                return Err(MemoryError::new(MEMORY_CODE_FORBIDDEN,
                    "the caller's Gate refused this compliance amendment", &[]));
            }
            let actor = WriteActor::new(self.actor(), self.actor_class());
            let can_activate = policy.actor_ceiling(self.actor_class().gate_actor_class(), Some(&self.actor().to_hex()))
                == PolicyApprovalCeiling::Auto
                && agent_definition_ceiling_for_actor(&vault.store, txn, actor)
                    != Some(PolicyApprovalCeiling::Proposed);
            amend_in_txn(self, txn, input, ComplianceOperation::Amend, can_activate)
        })
    }

    /// Approves only the exact staged rows under a live owner proof.
    pub fn compliance_approve_as(
        &self,
        owner: &AuthenticatedOwner,
        input: &ComplianceApprovalRequest,
    ) -> MemoryResult<ComplianceReceipt> {
        self.with_verified_actor_write_txn(|txn| {
            require_owner(self, owner, txn)?;
            let current = prior_pack(self, txn, input.prior_version)?;
            let hash = parse_hash(&input.proposal_hash)?;
            let pack = stamp_compliance_amendment_in_txn(&self.vault().store, txn, self.actor(), hash)?;
            let class = classify_compliance_amendment(&current, &pack)?;
            let notices = compliance_amendment_notices_in_txn(&self.vault().store, txn)?;
            let notice = notices.last().cloned();
            let mut receipt = new_receipt(self, &current, &pack, ComplianceOperation::Approve,
                ComplianceDisposition::Applied, Some(class))?;
            receipt.notice = notice;
            receipt.owner_stamp = Some(ComplianceOwnerStamp {
                owner_ref: self.actor().to_hex(),
                proposal_hash: receipt.proposal_hash.clone(),
                recorded_at: receipt.recorded_at,
            });
            save_receipt(self, txn, receipt)
        })
    }

    /// Rejects the exact pending proposal without changing active restrictions.
    pub fn compliance_reject_as(
        &self,
        owner: &AuthenticatedOwner,
        input: &ComplianceApprovalRequest,
    ) -> MemoryResult<ComplianceReceipt> {
        self.with_verified_actor_write_txn(|txn| {
            require_owner(self, owner, txn)?;
            let current = prior_pack(self, txn, input.prior_version)?;
            let pack = reject_compliance_amendment_in_txn(&self.vault().store, txn, parse_hash(&input.proposal_hash)?)?;
            let class = if pack.pack_version > current.pack_version {
                Some(classify_compliance_amendment(&current, &pack)?)
            } else {
                None
            };
            let receipt = new_receipt(self, &current, &pack, ComplianceOperation::Reject,
                ComplianceDisposition::Rejected, class)?;
            save_receipt(self, txn, receipt)
        })
    }

    /// Records the human owner's cited verification of existing rows only.
    /// A past timestamp may be explicitly stale; no accelerated clock is used.
    pub fn compliance_verify_as(
        &self,
        owner: &AuthenticatedOwner,
        input: &ComplianceVerifyRequest,
    ) -> MemoryResult<ComplianceReceipt> {
        self.with_verified_actor_write_txn(|txn| {
            require_owner(self, owner, txn)?;
            let mut pack = prior_pack(self, txn, input.prior_version)?;
            if input.rows.is_empty() {
                return Err(MemoryError::bad_request("verification names at least one existing row"));
            }
            let now = crate::unix_seconds_now();
            let mut keys = std::collections::BTreeSet::new();
            for verification in &input.rows {
                if verification.verified_at == 0 || verification.verified_at > now {
                    return Err(MemoryError::bad_request("verified_at is a nonzero past or present Unix second"));
                }
                let key = (verification.jurisdiction.as_str(), verification.channel.as_str(), verification.rule_kind);
                if !keys.insert(key) {
                    return Err(MemoryError::bad_request("verification contains a duplicate rule key"));
                }
                let row = pack.rows.iter_mut().find(|row| row.key() == key)
                    .ok_or_else(|| MemoryError::bad_request("verification rule key is not active"))?;
                if row.version != verification.expected_row_version {
                    return Err(MemoryError::bad_request("expected_row_version does not match the active row"));
                }
                row.source = verification.source.clone();
                row.verified_at = verification.verified_at;
            }
            pack.pack_version = pack.pack_version.checked_add(1)
                .ok_or_else(|| invalid_pack("pack version exhausted"))?;
            amend_in_txn(self, txn,
                &ComplianceAmendRequest { prior_version: input.prior_version, pack },
                ComplianceOperation::Verify, true)
        })
    }

    /// Reads active and pending data plus durable notices and receipts in one snapshot.
    pub fn compliance_result(&self, input: &ComplianceResultRequest) -> MemoryResult<ComplianceResult> {
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        crate::memory::verify_actor_binding_in_txn(vault, &txn, self.actor(), self.actor_class())?;
        let receipts = match &input.receipt_ref {
            Some(reference) => {
                let id = EntityId::from_hex(reference)
                    .map_err(|_| MemoryError::bad_request("receipt_ref is a 32-hex receipt id"))?;
                vec![RECEIPTS.get(&vault.store, &txn, id.as_bytes())?
                    .ok_or(crate::Error::EntityNotFound)?]
            }
            None => RECEIPTS.scan(&vault.store, &txn)?.into_iter().map(|(_, row)| row).collect(),
        };
        let pending = pending_compliance_pack_in_txn(&vault.store, &txn)?.map(|pack| {
            let proposal_hash = hash_hex(&compliance_proposal_hash(&pack)?);
            Ok::<_, crate::Error>(CompliancePendingProposal { pack, proposal_hash })
        }).transpose()?;
        Ok(ComplianceResult {
            active: active_compliance_pack_in_txn(&vault.store, &txn)?,
            pending,
            notices: compliance_amendment_notices_in_txn(&vault.store, &txn)?,
            receipts,
        })
    }
}

fn require_owner(memory: &Memory<'_>, owner: &AuthenticatedOwner, txn: &heed::RoTxn<'_>) -> MemoryResult<()> {
    if owner.revalidate_in_txn(memory.vault(), txn)? != memory.actor()
        || memory.actor_class() != EdgeActorClass::Human
    {
        return Err(MemoryError::new(MEMORY_CODE_FORBIDDEN,
            "compliance owner decisions act as the authenticated owner", &[]));
    }
    Ok(())
}

fn prior_pack(memory: &Memory<'_>, txn: &heed::RoTxn<'_>, prior_version: u32) -> MemoryResult<CompliancePack> {
    let current = active_compliance_pack_in_txn(&memory.vault().store, txn)?;
    if current.pack_version != prior_version {
        return Err(MemoryError::new(crate::memory::MEMORY_CODE_INVALID_STATE,
            "prior_version does not match the active compliance pack", &[]));
    }
    Ok(current)
}

fn amend_in_txn(
    memory: &Memory<'_>,
    txn: &mut heed::RwTxn<'_>,
    input: &ComplianceAmendRequest,
    operation: ComplianceOperation,
    can_activate: bool,
) -> MemoryResult<ComplianceReceipt> {
    let current = prior_pack(memory, txn, input.prior_version)?;
    let (class, outcome) = apply_compliance_amendment_in_txn(
        &memory.vault().store, txn, &memory.actor().to_hex(), &input.pack, can_activate,
    )?;
    let (disposition, notice) = match outcome {
        ComplianceAmendmentOutcome::Applied { notice, .. } => (ComplianceDisposition::Applied, Some(notice)),
        ComplianceAmendmentOutcome::PendingOwnerStamp { .. } => (ComplianceDisposition::PendingOwnerStamp, None),
    };
    let mut receipt = new_receipt(memory, &current, &input.pack, operation, disposition, Some(class))?;
    receipt.notice = notice;
    if !can_activate {
        receipt.reason_codes.push("gate.pending.actor_ceiling".to_owned());
    }
    save_receipt(memory, txn, receipt)
}

fn new_receipt(
    memory: &Memory<'_>,
    current: &CompliancePack,
    proposed: &CompliancePack,
    operation: ComplianceOperation,
    disposition: ComplianceDisposition,
    class: Option<ComplianceAmendmentClass>,
) -> MemoryResult<ComplianceReceipt> {
    let id = memory.vault().store.clock.entity_id()?;
    Ok(ComplianceReceipt {
        receipt_ref: id.to_hex(), operation, disposition,
        prior_version: current.pack_version,
        effective_version: if disposition == ComplianceDisposition::Applied { proposed.pack_version } else { current.pack_version },
        proposed_version: proposed.pack_version,
        class,
        proposal_hash: hash_hex(&compliance_proposal_hash(proposed)?),
        actor_ref: memory.actor().to_hex(), owner_stamp: None, notice: None,
        reason_codes: Vec::new(), recorded_at: crate::unix_seconds_now(),
    })
}

fn save_receipt(memory: &Memory<'_>, txn: &mut heed::RwTxn<'_>, receipt: ComplianceReceipt) -> MemoryResult<ComplianceReceipt> {
    let id = EntityId::from_hex(&receipt.receipt_ref)?;
    RECEIPTS.put(&memory.vault().store, txn, id.as_bytes(), &receipt)?;
    Ok(receipt)
}

fn hash_hex(hash: &[u8; 32]) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_hash(hash: &str) -> MemoryResult<[u8; 32]> {
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return Err(MemoryError::bad_request("proposal_hash is 64 lowercase hex characters"));
    }
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hash[index * 2..index * 2 + 2], 16)
            .map_err(|_| MemoryError::bad_request("invalid proposal_hash"))?;
    }
    Ok(bytes)
}
