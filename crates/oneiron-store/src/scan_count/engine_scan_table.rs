//! Default scan thresholds, including the context-projection-owned threshold.

use crate::scan_kind::{DEFAULT_SCAN_CHECK_THRESHOLD, EngineScan};

pub trait EngineScanThreshold {
    fn default_threshold(self) -> u64;
}

impl EngineScanThreshold for EngineScan {
    /// The threshold the scan asks past while no row is set: the count it
    /// once cut its read short at, or the engine-wide default.
    fn default_threshold(self) -> u64 {
        match self {
            Self::OriginTreeEntries => 100_000,
            Self::OriginTagPeelSteps | Self::GitWirePublications => 64,
            Self::GitWirePlanObjects => 256,
            Self::OriginPublicationObligations => 4096,
            Self::CodeMemorySlotValues
            | Self::CodeMemoryPullSeeds
            | Self::CodeMemoryPullNotes
            | Self::CodeMemoryPullSymbols => 256,
            Self::CodeMemoryAlwaysOnContracts => 8,
            Self::RepoDiffFiles => 1024,
            Self::ClaimVadIncidentEdges | Self::TaskAuthorityFactEdges => 100_000,
            Self::RepoProposalSnapshotRows | Self::RepoSnapshotFiles => 100_000,
            Self::RepoProposalCritiques => 64,
            Self::RepoConflictPaths => 1024,
            Self::RoomRosterMembers
            | Self::DagWalkRecords
            | Self::AudienceEdgeRows
            | Self::RoomAncestryRecords
            | Self::PrivateThreadAncestryRecords => 10_000,
            Self::RetrievalRunRows => 1024,
            Self::CallReceiptRows => 8192,
            Self::BlockedRunReports => 128,
            Self::RoomPolicyRows => 1024,
            Self::RoomThreadHolderRows => 1000,
            Self::ProjectDepthDefaultRows
            | Self::ProjectDepthPolicyRows
            | Self::ProjectDepthSourceAncestors => 4096,
            Self::ProjectDepthPredecessors => 256,
            Self::ProjectDepthContributionBytes => 16 * 1024,
            Self::DispatchAncestorRows => {
                crate::config::context_spec::CONTEXT_PROJECTION_ANCESTOR_CHECK
            }
            Self::LinearProvenanceRows => 200,
            Self::NoteDocumentBytes => 1_048_576,
            Self::NoteDocumentPinRows => 256,
            Self::NoteDocumentAuthorshipRows => 4096,
            Self::AgentDefinitionListEntries => 64,
            Self::AgentBirthSkillRows | Self::AgentBirthClaimOfRows => 100_000,
            Self::SpendAncestorScopes => 256,
            Self::SpendRetryAttempts | Self::SymbolOperationChain => 1024,
            Self::AttemptKindRows | Self::SymbolManifestRows | Self::CodebaseFileRows => 100_000,
            Self::AttemptEventActorBytes => 128,
            Self::AttemptEventNoteBytes => 2048,
            Self::AttendeeIdentityCandidates => 32,
            Self::GuestDisclosureRefs => 16,
            Self::GuestGrantDisclosedRefs => 64,
            Self::DeclaredSymbols => 4096,
            Self::AttendeeIdentityKeyBytes => 128,
            Self::DeclaredSymbolBytes => 1024,
            Self::CommWidenAncestorRows => 256,
            Self::ProjectGoalAxes => 32,
            Self::ProjectGoalPreferences => 64,
            Self::ProjectGoalTextBytes | Self::ProjectSideListEntries => 4096,
            Self::ProjectGoalAxisNameBytes
            | Self::ProjectBodyGoalAxes
            | Self::ProjectProposalEntries => 128,
            Self::ProjectGoalDetailBytes => 1024,
            Self::ProjectAncestryRows => 256,
            Self::ProjectOutstandingCards => 1,
            // The cycle rows ask at their resolved formulas; these are the
            // formulas' shipped factors.
            Self::ProjectCycleWorlds | Self::ProjectCycleAssignments => 64,
            Self::ProjectJointWork => 64 * 64,
            Self::ProjectProposalTextBytes => 16 * 1024,
            Self::ReplyStripRequestedRows | Self::RoomRequestedPageRows | Self::RoomMentions => 256,
            Self::RoomThreadListRows => 64,
            Self::RoomLinkWalkRows | Self::RoomThreadPolicyRows | Self::RoomThreadWaitRows => {
                100_000
            }
            Self::RoomRetryLineageRows => 10_000,
            Self::RoomThreadTokens => 1_000_000,
            Self::ResidentGoalAxes => 32,
            Self::AgentDefinitionIdentityBytes => 256,
            Self::AgentDefinitionDescriptionBytes => 4096,
            Self::AgentDefinitionVersionBytes => 128,
            Self::AgentDefinitionInstructionBytes => 16_384,
            Self::AgentDefinitionReferenceBytes => 256,
            Self::AgentDefinitionVerbatimPinBytes => 1024,
            Self::AgentBirthSourceBytes => 32 * 1024 * 1024,
            Self::TaskPostIntentKeyBytes => 256,
            Self::AudienceCoverDepth
            | Self::ProjectAnchorDepth
            | Self::MachineTransitionFrontier => 64,
            Self::ProjectFoldDepth => 256,
            _ => DEFAULT_SCAN_CHECK_THRESHOLD,
        }
    }
}
