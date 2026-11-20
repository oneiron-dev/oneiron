//! The ED-08 issue signature a shipped subject's triage packet earns
//! (FIX 11634), resolved from the packet alone beside the report lane's
//! resolver (`metadata.rs`): the packet is what the signature describes, so
//! its tallies span the packet's receipts, its version and executor are the
//! newest failing receipt's, and its content hash is blake3 over the
//! packet's canonical JSON bytes (the engine's `llm` canonical form). The
//! caller states the category from the packet receipts' judgments: the
//! defect or lapse class a judgment actually charged the subject with, or
//! unclear when none did. The version is the failing runs' own where the
//! packet records it — a skill's attempt-pinned version, a definition's
//! bind-time pin where the run pinned one. Anything not exactly resolvable
//! — no such version that is exactly a `u32`, no executor, no registered
//! stack for it — resolves to no signature: absent, never a guess, and the
//! packet still reaches the owner's inbox.

use super::metadata::{compiled_stack, exact_u32, host_stack_id};
use crate::edit_distance::attribution::{ArtifactPublisher, TriagePacket, TriageSubject};
use crate::edit_distance::publisher::{CountKey, IssueCategory, IssueSignature};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::{EntityId, Vault};
use oneiron_contracts::fingerprint::{LegacyDigest, purposes};
use oneiron_model::llm::ModelId;

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
        category: IssueCategory,
    ) -> Result<Option<IssueSignature>> {
        if packet.publisher != ArtifactPublisher::Shipped {
            return Ok(None);
        }
        let Ok(artifact) = EntityId::from_hex(&packet.subject) else {
            return Ok(None);
        };
        let version = match packet.subject_kind {
            // The run's own attempt-pinned skill version; the live
            // record's version is never presented as the failing run's.
            TriageSubject::Skill => packet.receipts.iter().rev().find_map(|receipt| {
                receipt
                    .skill
                    .as_ref()
                    .filter(|skill| skill.via_attempt)
                    .map(|skill| skill.version.as_str())
            }),
            TriageSubject::Actor => packet
                .agent_definitions
                .iter()
                .rev()
                .find(|definition| definition.definition == packet.subject)
                .map(|definition| definition.version.as_str()),
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
        let content_hash = packet_content_hash(packet)?;
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

/// The content hash of `packet`: plain BLAKE3 of its canonical JSON bytes,
/// lowercase hex. The issue signature row stores it, so it keeps its bytes (K,
/// PLAN-UC-04 stage 6.4).
fn packet_content_hash(packet: &TriagePacket) -> Result<String> {
    let canonical = oneiron_model::llm::canonical_json_bytes(packet)
        .map_err(|_| Error::InvariantViolation("triage packet encode"))?;
    Ok(bytes_to_hex_lower(
        &LegacyDigest::new(purposes::feedback::TRIAGE_PACKET)
            .raw(&canonical)
            .finish(),
    ))
}

/// [`packet_content_hash`], or `None` when the packet does not encode. For the
/// K-proof (`tests/fingerprint_keep_query_swap_piece_packet_repo_digests.rs`).
#[cfg(oneiron_test_support)]
pub(crate) fn packet_content_hash_for_test(packet: &TriagePacket) -> Option<String> {
    packet_content_hash(packet).ok()
}
