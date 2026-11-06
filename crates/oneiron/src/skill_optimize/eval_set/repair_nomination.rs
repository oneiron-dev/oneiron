//! Scoped discovery of source-declared Repair tasks, without authoring cases.

use serde::{Deserialize, Serialize};

use super::{EvalRepairCasePreparation, EvalRepairTaskSource};
use crate::claim::ScopedReadReceipt;
use crate::ingest::{AG_UI_FILE_PREDICATE, AgUiFileMetadataRead};
use crate::memory::{ClaimListFilter, Memory, MemoryResult};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalRepairNominationRequest {
    /// Optional native claim-list subject filter; None searches all admitted claims.
    pub subject_ref: Option<String>,
    /// Maximum captures, using the ordinary claim-list limit.
    pub limit: usize,
}

/// Metadata and per-declaration results for one discovered capture. An invalid
/// source or task is reported without suppressing other captures or declarations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalRepairSourceNominations {
    pub claim_ref: String,
    pub metadata: MemoryResult<AgUiFileMetadataRead>,
    /// Same order as metadata.source.repair_tasks when metadata is available.
    pub tasks: Vec<MemoryResult<EvalRepairCasePreparation>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalRepairNominations {
    pub sources: Vec<EvalRepairSourceNominations>,
    /// Receipt of discovery only. Each metadata/task read keeps its own receipt.
    pub receipt: ScopedReadReceipt,
}

impl Memory<'_> {
    /// Discover declared tasks through this handle's ordinary Recorded reader,
    /// then compile each exact native pin under the same original credentials.
    /// This returns recipes only; it writes no family, case, label or grant.
    pub fn nominate_eval_repairs(
        &self,
        input: &EvalRepairNominationRequest,
    ) -> MemoryResult<EvalRepairNominations> {
        let discovery = self.claim_list(&ClaimListFilter {
            subject_ref: input.subject_ref.clone(),
            predicate: Some(AG_UI_FILE_PREDICATE.to_owned()),
            lifecycle: None,
            limit: input.limit,
        })?;
        let mut sources = Vec::with_capacity(discovery.value.len());
        for claim in discovery.value {
            let metadata = self.read_ag_ui_file_metadata(&claim.claim_ref);
            let mut tasks = Vec::new();
            if let Ok(read) = &metadata
                && let Some(source) = &read.source
            {
                for declaration in &source.repair_tasks {
                    tasks.push(
                        self.read_eval_repair_task(&EvalRepairTaskSource {
                            claim_ref: source.claim_ref.clone(),
                            source_hash: source.source_hash.clone(),
                            outcome_ordinal: declaration.outcome_ordinal,
                            task_pointer: declaration.task_pointer.clone(),
                            seat: declaration.seat.clone(),
                        })
                        .map(EvalRepairCasePreparation::from),
                    );
                }
            }
            sources.push(EvalRepairSourceNominations {
                claim_ref: claim.claim_ref,
                metadata,
                tasks,
            });
        }
        Ok(EvalRepairNominations {
            sources,
            receipt: discovery.receipt,
        })
    }
}
