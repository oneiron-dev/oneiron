//! Moved from `crates/oneiron/src/skill_hub/pack_catalog/hooks.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::store::pack_hook_proposal::HookOutcomeKind;
pub use crate::store::pack_hook_proposal::HookPhase;
pub use crate::store::pack_hook_proposal::HookRenderClass;
pub use crate::store::pack_hook_proposal::HookSelector;
pub use crate::store::pack_hook_proposal::HookWidening;
pub use crate::store::pack_hook_proposal::PackHookProposal;
pub use crate::store::pack_hook_proposal::PackHookProposalStatus;
use oneiron_base::edge::EdgeActorClass;
use oneiron_base::edge::EdgeKind;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::claim::ClaimApprovalStatus;
use oneiron_contracts::claim::ClaimLifecycleStatus;
use oneiron_contracts::claim::ClaimSource;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use oneiron_contracts::record_layout::EntityMetadataHeader;
use oneiron_contracts::temporal::TimeRange;
use oneiron_store::code_artifact_body::CODE_ARTIFACT_SUMMARY_PROMPT_MAX_BYTES;
use oneiron_store::code_artifact_body::CodeArtifactBody;
use oneiron_store::code_artifact_body::CodeArtifactClass;
use oneiron_store::code_artifact_body::encode_code_artifact_body;
pub use oneiron_store::pack_hook_actor_class::HookActorClass;
use oneiron_store::write_envelope::ClaimCandidate;
use oneiron_store::write_envelope::WriteActor;
use oneiron_store::write_envelope::WriteEnvelope;
use oneiron_store::write_envelope::WriteProvenance;
use oneiron_store::write_envelope::claim_body::ClaimSubject;
use oneiron_store::write_envelope::skill_source::HubFile;
use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

impl HookPhase {
    /// The time budget for one run when HOOK.md names none.
    const fn default_budget_ms(self) -> u32 {
        match self {
            Self::Pre => 50,
            Self::Post => 200,
            Self::Fact => 1_000,
        }
    }
}

impl HookOutcomeKind {
    pub fn applies_in(self, phase: HookPhase) -> bool {
        use HookOutcomeKind::{
            AddBlock, Annotate, Ask, Continue, Effect, Enqueue, Nothing, Propose, Redact, Rewrite,
            Skip,
        };
        match phase {
            HookPhase::Pre => matches!(self, Continue | Rewrite | Skip | Ask | AddBlock),
            HookPhase::Post => matches!(
                self,
                Continue | Annotate | Redact | AddBlock | Propose | Enqueue | Effect
            ),
            HookPhase::Fact => matches!(self, Propose | Enqueue | Effect | AddBlock | Nothing),
        }
    }
}
