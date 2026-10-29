//! The ED-08 issue signature a shipped subject's triage packet earns
//! (FIX 11634), resolved from the packet alone beside the report lane's
//! resolver (`metadata.rs`): the packet is what the signature describes, so
//! its tallies span the packet's receipts, its version and executor are the
//! newest failing receipt's, and its content hash is blake3 over the
//! packet's canonical bytes — the canonical JSON form the engine already
//! writes, no new form. The category is the packet's subject kind: a skill
//! packet stands on the defect shares that charged the skill, an actor
//! packet on the lapse shares that charged the actor. Anything not exactly
//! resolvable — no pinned version that is exactly a `u32`, no executor, no
//! registered stack for it — resolves to no signature: absent, never a
//! guess, and the packet still reaches the owner's inbox.

use super::metadata::{compiled_stack, exact_u32, host_stack_id};
use crate::edit_distance::attribution::{ArtifactPublisher, TriagePacket, TriageSubject};
use crate::edit_distance::publisher::{CountKey, IssueCategory, IssueSignature};
use crate::error::{Error, Result};
use crate::{EntityId, ModelId, Vault};

impl Vault {
    /// Builds the content-free issue signature `packet` earns, read in
    /// `txn`; `None` when the packet's publisher is not shipped or one of
    /// its facts does not resolve exactly.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn packet_issue_signature_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        packet: &TriagePacket,
    ) -> Result<Option<IssueSignature>> {
        if packet.publisher != ArtifactPublisher::Shipped {
            return Ok(None);
        }
        let Ok(artifact) = EntityId::from_hex(&packet.subject) else {
            return Ok(None);
        };
        let (category, version) = match packet.subject_kind {
            TriageSubject::Skill => {
                let version =
                    packet.receipts.iter().rev().find_map(|receipt| {
                        receipt.skill.as_ref().map(|skill| skill.version.as_str())
                    });
                (IssueCategory::SkillDefect, version)
            }
            TriageSubject::Actor => {
                let version = packet
                    .agent_definitions
                    .iter()
                    .rev()
                    .find(|definition| definition.definition == packet.subject)
                    .map(|definition| definition.version.as_str());
                (IssueCategory::ExecutionLapse, version)
            }
        };
        let Some(version) = version.and_then(exact_u32) else {
            return Ok(None);
        };
        let Some(executor) = packet
            .receipts
            .iter()
            .rev()
            .find_map(|receipt| receipt.executor.as_deref())
        else {
            return Ok(None);
        };
        let model_id = match compiled_stack(executor) {
            Some(stack) => Some(stack),
            None => match ModelId::new(executor) {
                Ok(model) => self
                    .model_registry_row_in_txn(txn, &model)?
                    .map(|_| host_stack_id(&model)),
                Err(_) => None,
            },
        };
        let Some(model_id) = model_id else {
            return Ok(None);
        };
        let stacks = self.signature_stacks_in_txn(txn, &model_id)?;
        let judged = u32::try_from(packet.receipts.len()).unwrap_or(u32::MAX);
        let rejected = u32::try_from(
            packet
                .receipts
                .iter()
                .filter(|receipt| receipt.rejected)
                .count(),
        )
        .unwrap_or(u32::MAX);
        let counts = [
            (CountKey::Judged, judged),
            (CountKey::Amended, judged.saturating_sub(rejected)),
            (CountKey::Rejected, rejected),
        ];
        let canonical = crate::llm::canonical_json_bytes(packet)
            .map_err(|_| Error::InvariantViolation("triage packet encode"))?;
        let content_hash = blake3::hash(&canonical).to_hex().to_string();
        Ok(IssueSignature::new(
            category,
            artifact,
            version,
            &stacks,
            &model_id,
            &counts,
            content_hash.as_str(),
        )
        .ok())
    }
}
