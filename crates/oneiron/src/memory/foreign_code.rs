//! Typed foreign code admission. The credential supplies WHO and the read
//! frontier; the sandbox supplies inert deltas, never a vault write.
use serde::{Deserialize, Serialize};

use super::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::code_sandbox::foreign::{ForeignCodeArtifact, execute_foreign_code};
use crate::code_sandbox::{
    SandboxBoundaryContract, SandboxGuestTier, SandboxMountTable, SandboxProposalWrite,
};
use crate::{
    ClaimApprovalStatus, ClaimSource, EntityId, WriteActor, WriteEnvelope, WriteProvenance,
};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForeignCodeRunRequest {
    /// Plain JavaScript for the foreign interpreter, not native code or a host path.
    pub source: String,
    /// Named records to freeze through this credential's scoped read.
    /// Entry N is frozen as JSON at /mnt/workspace/record-N.json.
    /// The answer repeats the reference-to-path mapping.
    #[serde(default)]
    pub reads: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForeignCodeRead {
    pub reference: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForeignCodeOutput {
    pub path: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ForeignCodeTier {
    Foreign,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ForeignCodeApproval {
    Proposed,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ForeignCodeSource {
    Generated,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ForeignCodeEffect {
    FileWrite {
        path: String,
        bytes: Vec<u8>,
    },
    FileEdit {
        path: String,
        base_content_hash: String,
        edit: crate::code_document::CodeFileEdit,
    },
    FileDelete {
        path: String,
    },
    FileRename {
        from: String,
        to: String,
    },
    DirectoryOpaque {
        path: String,
    },
    ClaimCandidate {
        claim: super::ClaimInput,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForeignCodeProposal {
    pub proposal_ref: String,
    pub receipt_ref: String,
    pub actor_ref: String,
    pub source: ForeignCodeSource,
    pub approval: ForeignCodeApproval,
    pub effect: ForeignCodeEffect,
}

/// The public part of the backend's own proof. The complete manifest is
/// retained by the sandbox receipt, not asserted by the calling program.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForeignCodeIsolation {
    pub backend: String,
    pub runtime: String,
    pub image: String,
    pub argv_digest: String,
    pub network: String,
    pub generation: String,
    pub fence_proven: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForeignCodeRunResult {
    pub run_id: String,
    pub actor_ref: String,
    pub tier: ForeignCodeTier,
    pub linked_imports: Vec<String>,
    pub reads: Vec<ForeignCodeRead>,
    pub done: bool,
    pub observation: String,
    pub outputs: Vec<ForeignCodeOutput>,
    pub proposals: Vec<ForeignCodeProposal>,
    pub isolation: ForeignCodeIsolation,
    pub receipt_ref: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StepOutput {
    done: bool,
    #[serde(default)]
    observation: String,
    #[serde(default)]
    outputs: Vec<ForeignCodeOutput>,
}

impl Memory<'_> {
    /// Run source under the foreign contract. No host path, runtime binary,
    /// actor, source stamp, approval or grant is accepted from the wire. Its
    /// proposed files spool on `spool`, the host's measured disk floor; one
    /// that would cross it fails the run as `SANDBOX_PROPOSAL_DISK_FLOOR`
    /// before any receipt (FIX 7650).
    pub fn execute_foreign_code(
        &self,
        input: ForeignCodeRunRequest,
        artifact: ForeignCodeArtifact<'_>,
        budget: crate::code_sandbox::microvm::ExecutionBudget,
        spool: std::sync::Arc<dyn crate::code_sandbox::ProposalSpoolFloor>,
    ) -> MemoryResult<ForeignCodeRunResult> {
        let proof = self.foreign_code_credential()?;
        if input.source.trim().is_empty() {
            return Err(MemoryError::bad_request("foreign source is empty"));
        }
        let workspace = tempfile::tempdir().map_err(crate::Error::from)?;
        let mut reads = Vec::new();
        for (index, reference) in input.reads.into_iter().enumerate() {
            let view = self.get_entity(&reference)?.value.ok_or_else(refused)?;
            let name = format!("record-{index}.json");
            let bytes = serde_json::to_vec(&view)
                .map_err(|_| MemoryError::bad_request("record snapshot cannot be encoded"))?;
            std::fs::write(workspace.path().join(&name), bytes).map_err(crate::Error::from)?;
            reads.push(ForeignCodeRead {
                reference,
                path: format!("/mnt/workspace/{name}"),
            });
        }
        // Never mount a vault, checkout or caller-selected host directory.
        let mounts = SandboxMountTable::new(
            workspace.path(),
            workspace.path(),
            workspace.path(),
            workspace.path(),
        );
        let run_id = EntityId::now();
        let outcome = execute_foreign_code(&input.source, mounts, artifact, budget, spool)?;
        let output: StepOutput = serde_json::from_str(&outcome.result_json)
            .map_err(|_| MemoryError::bad_request("foreign step returned invalid typed output"))?;
        for file in &output.outputs {
            let path = crate::code_sandbox::SandboxVirtualPath::try_new(&file.path)?;
            if path.mount() != crate::code_sandbox::SandboxMount::Outputs {
                return Err(MemoryError::bad_request(
                    "foreign output must name /mnt/outputs",
                ));
            }
        }
        let manifest = outcome.manifest.as_ref().ok_or_else(|| {
            MemoryError::bad_request("foreign execution returned no isolation manifest")
        })?;
        let contract = SandboxBoundaryContract::for_tier(SandboxGuestTier::Foreign);
        let actor_ref = self.actor.to_hex();
        let isolation = ForeignCodeIsolation {
            backend: manifest.backend.clone(),
            runtime: manifest.runtime.clone(),
            image: manifest.image.clone(),
            argv_digest: manifest.argv_digest.clone(),
            network: manifest.network.clone(),
            generation: manifest.generation.clone(),
            fence_proven: !manifest.fence_unproven && manifest.fence_proof.is_some(),
        };
        let (receipt_ref, proposals) = self.with_verified_actor_write_txn(|txn| {
            // Every authority check guarding these receipts shares their writer.
            if !self.vault.capability_slip_is_live_in_txn(txn, proof)? {
                return Err(refused());
            }
            let manifest = serde_json::to_string(&serde_json::json!({
                "run_id": run_id.to_hex(), "actor_ref": actor_ref,
                "source": "generated", "session_manifest": manifest,
            }))
            .map_err(|_| MemoryError::bad_request("foreign manifest cannot be encoded"))?;
            let digest = *blake3::hash(manifest.as_bytes()).as_bytes();
            let receipt_ref = self.vault.append_sandbox_gate_receipt_in_txn(
                txn,
                run_id,
                "session_manifest",
                "recorded",
                manifest,
                digest,
            )?;
            let mut proposals = Vec::new();
            for delta in &outcome.proposals {
                let effect = match delta.write() {
                    SandboxProposalWrite::FileWrite(file) => ForeignCodeEffect::FileWrite {
                        path: file.path.as_str().to_owned(),
                        bytes: file.body.read_range(
                            0,
                            usize::try_from(file.body.len()).map_err(|_| {
                                MemoryError::bad_request("proposal cannot fit on this host")
                            })?,
                        )?,
                    },
                    SandboxProposalWrite::FileEdit(file) => ForeignCodeEffect::FileEdit {
                        path: file.path.as_str().to_owned(),
                        base_content_hash: blake3::Hash::from_bytes(file.base_content_hash)
                            .to_hex()
                            .to_string(),
                        edit: file.edit.clone(),
                    },
                    SandboxProposalWrite::FileDelete(file) => ForeignCodeEffect::FileDelete {
                        path: file.path.as_str().to_owned(),
                    },
                    SandboxProposalWrite::FileRename(file) => ForeignCodeEffect::FileRename {
                        from: file.from.as_str().to_owned(),
                        to: file.to.as_str().to_owned(),
                    },
                    SandboxProposalWrite::DirectoryOpaque(file) => {
                        ForeignCodeEffect::DirectoryOpaque {
                            path: file.path.as_str().to_owned(),
                        }
                    }
                    SandboxProposalWrite::ClaimCandidate(claim) => {
                        let provenance = WriteProvenance::new(rmpv::Value::from(run_id.to_hex()))?;
                        let envelope = WriteEnvelope::new(
                            WriteActor::new(self.actor, self.actor_class),
                            ClaimSource::Generated,
                            provenance,
                            ClaimApprovalStatus::Proposed,
                        );
                        let facet =
                            crate::batch::claim_candidate_apply::claim_candidate_birth_facet(
                                &self.vault.store,
                                txn,
                                &claim.id,
                            )?;
                        let body = (*claim.candidate)
                            .clone()
                            .into_claim_body(&envelope, facet)?;
                        let subject_ref = match body.subject {
                            crate::claim::ClaimSubject::Entity(id) => id.to_hex(),
                            crate::claim::ClaimSubject::Edge {
                                source,
                                kind,
                                target,
                            } => format!(
                                "edge:{}:{}:{}",
                                source.to_hex(),
                                kind as u8,
                                target.to_hex()
                            ),
                        };
                        ForeignCodeEffect::ClaimCandidate {
                            claim: super::ClaimInput {
                                id: Some(claim.id.to_hex()),
                                predicate: body.predicate,
                                subject_ref,
                                value: crate::batch::export::served_messagepack_json(body.value),
                                confidence: body.confidence,
                                source: "generated".to_owned(),
                                world_ref: body.world.map(|id| id.to_hex()),
                                relationship_ref: body.rel.map(|id| id.to_hex()),
                                scope: body
                                    .scope
                                    .map(crate::batch::export::served_messagepack_json),
                                valid_from: body.valid_from,
                                valid_to: body.valid_to,
                                occurred_at: None,
                                learned_at: None,
                                salience: body.salience,
                                // The fields, not the method: `body` is moved out of.
                                confidence_details: Some(crate::claim::ConfidenceDetails {
                                    band: body.confidence_band,
                                    basis: body.confidence_basis,
                                }),
                            },
                        }
                    }
                };
                let mut proposal = ForeignCodeProposal {
                    proposal_ref: delta.id().to_hex(),
                    receipt_ref: String::new(),
                    actor_ref: actor_ref.clone(),
                    source: ForeignCodeSource::Generated,
                    approval: ForeignCodeApproval::Proposed,
                    effect,
                };
                let body = serde_json::to_string(&proposal)
                    .map_err(|_| MemoryError::bad_request("foreign proposal cannot be encoded"))?;
                let digest = *blake3::hash(body.as_bytes()).as_bytes();
                proposal.receipt_ref = self.vault.append_sandbox_gate_receipt_in_txn(
                    txn, run_id, "proposal", "proposed", body, digest,
                )?;
                proposals.push(proposal);
            }
            Ok((receipt_ref, proposals))
        })?;
        self.foreign_code_credential()?;
        Ok(ForeignCodeRunResult {
            run_id: run_id.to_hex(),
            actor_ref,
            tier: ForeignCodeTier::Foreign,
            linked_imports: contract
                .linked_imports()
                .iter()
                .map(|import| import.name().to_owned())
                .collect(),
            reads,
            done: output.done,
            observation: output.observation,
            outputs: output.outputs,
            proposals,
            isolation,
            receipt_ref,
        })
    }

    fn foreign_code_credential(&self) -> MemoryResult<&crate::authority::VerifiedSlip> {
        let proof = self.presented_credential().ok_or_else(refused)?;
        if proof.claims().holder_ref != self.actor.to_hex()
            || proof.claims().actor_class.as_deref() != Some(self.actor_class.gate_actor_class())
            || !(proof.allows_verb("read") || proof.allows_verb("core:read"))
            || !(proof.allows_verb("core:propose")
                || proof.allows_verb("write")
                || proof.allows_verb("core:write"))
            || !self.vault.capability_slip_is_live(proof)?
            || self.vault.credential_read_key(proof)?.is_none()
        {
            return Err(refused());
        }
        Ok(proof)
    }
}

fn refused() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        "foreign code requires its own live read and propose credential",
        &[],
    )
}
