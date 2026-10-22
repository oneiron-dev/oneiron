//! The engine scans whose tables grow with use (rule 5), each with its
//! closed code, the threshold it asks past and its row's tag; split from
//! its parent, which re-exports them.

use super::DEFAULT_SCAN_CHECK_THRESHOLD;

/// Each engine scan whose table grows with use, and so each that once
/// refused past a row count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineScan {
    /// One repository's receive-pack intents: its pending pushes, and any
    /// settled one the scan prunes on its way.
    ReceivePackIntents,
    /// The vault's publication journal, every repository's history.
    PublicationRows,
    /// One repository's visible-ref slots: one per ref name it publishes.
    VisibleRefRows,
    /// One repository's keep-ref owners, every kind.
    KeepOwnerRows,
    /// One entity type's rows in the type index.
    TypeIndexRows,
    /// One learned-at window's rows in the temporal index.
    LearnedRangeRows,
    /// One record's edges of one kind, one way.
    EdgePeerRows,
    /// The local receipt-record index a canonical window capture walks.
    ReceiptRecordRows,
    /// The records of one anchor's supersession chain.
    TimelineRecords,
    /// The gate-decision ledger a gate receipt query walks.
    GateDecisionRows,
    /// One record's edges a scoped reader's admission walks, one way.
    ScopedEdgeRows,
    /// The owner's MACHINE rows a mesh address bind walks for its endpoint.
    MachineRows,
    /// The access grants a companion persona list walks.
    AccessGrantRows,
    /// One seed's inbound mentions a specificity weight counts.
    MentionRows,
    /// The PPR cache's dependency rows a replaced or dead entry's walk reads.
    PprCacheDepRows,
    /// The sync rematerialization markers and quarantine rows a pack's
    /// exclusion index reads.
    PackQuarantineRows,
    /// The legacy lexical-hint claims a target's hint lookup walks.
    LexicalHintRows,
    /// The graduation answer log a gate receipt query projects.
    AnswerReceiptRows,
    /// The proposal artifacts a substitution-mining pass indexes.
    MinerArtifactRows,
    /// The synced edge map's entries an unseated child's parent arbitration
    /// walks.
    ChildOfMapEntries,
    /// The long-interval index a temporal window's spanner scan reads.
    TemporalSpannerRows,
    /// The timeline rows an occurred-range query reads, both halves.
    OccurredRangeRows,
    /// The retrieval run ledger a blend-weight tuning pass walks.
    BlendTuningRuns,
    /// One conversation's peers a Dreamer selection retry reads.
    DreamerRetryPeers,
    /// The pending gate-consent tray a consent list walks.
    PendingGateConsentRows,
    /// The tasks an omitted ask target or task context is resolved from, for
    /// one asking actor.
    TaskCensusRows,
    /// One ask's words.
    AskWordRows,
    /// The room members' tasks a thread census reads, for one reader.
    RoomThreadTasks,
    /// The rows one session's read set holds.
    ReadSetRows,
    /// One room's history rows a message page passes over.
    RoomPageRows,
    /// One room's history rows a liveness snapshot reads.
    RoomHistoryRows,
    /// The TASK rows one board assembly reads.
    TaskBoardRows,
    /// One room's thread-children index rows a hang check walks, for one
    /// room or parent turn.
    RoomThreadChildRows,
    /// The message-to-project origin index rows a hang check walks, for one
    /// message.
    MessageOriginRows,
    /// A thread's bound and moved tasks, counted at bind and conversion.
    ThreadTaskCensus,
    /// The task and ask lists one PROJECT body's normalization reads.
    ProjectTaskRows,
    /// The vault's inbound STOPs this replica has not projected yet, which
    /// each external send reads. A STOP the projector keeps refusing stays.
    PendingCommStops,
    /// The contact claims naming a party, which an external send reads when
    /// a party-wide opt-out stands for its party and no contact row held it.
    PartyContactClaims,
    /// The soft-confirm notice deliveries one retry sweep's page reads,
    /// settled ones included.
    AskSoftConfirmDeliveryRows,
    /// One predicate's claims in the claim projection index, which a weave
    /// report reads whole.
    PredicateClaimRows,
    /// Every edge in the vault, which a vault-wide walk (the owner weave
    /// report's links) reads.
    VaultEdgeRows,
    /// The Dreamer prefilter's skip and round receipt rows a receipt query
    /// walks.
    PrefilterReceiptRows,
    /// One MACHINE claim's handoff chain, packet by packet, which each read
    /// of its whole history walks.
    MachineHandoffChain,
    /// One MACHINE claim's target index: the ids of its birth, transitions
    /// and handoffs.
    MachineHistoryTargetRows,
    /// One claim's incident edges of every kind, one way, which a claim-VAD
    /// consolidation or clear reads.
    ClaimVadIncidentEdges,
    /// The retrieval run ledger a newest-runs read walks, provisional rows
    /// included.
    RetrievalRunRows,
    /// The call receipt ledger a served MCP-refusal detector pass walks
    /// before its time and kind filters.
    CallReceiptRows,
    /// One durable run's blocked-report lineage rows.
    BlockedRunReports,
    /// The Sieve's audit rows an audit read walks before its sampled filter,
    /// rows that fail to decode included.
    SieveAuditRows,
    /// One room's roster, which each write of its body validates whole; its
    /// roles are members.
    RoomRosterMembers,
    /// The records and edges one conversation DAG walk reads: an ancestor
    /// chain, a scope's forks, a thread chain, an adoption pass.
    DagWalkRecords,
    /// One TASK's inbound `ScopedTo` edges its authority fold reads, facts
    /// or not.
    TaskAuthorityFactEdges,
    /// Every TASK row one person's open-ask read walks, for one person.
    OpenAskTaskRows,
    /// One record's edges of one kind, one way, which an audience, ancestry
    /// or enumeration read outside a DAG walk reads whole.
    AudienceEdgeRows,
    /// The records a room lookup walks up from one record.
    RoomAncestryRecords,
    /// The records one private-thread walk reaches from one record: its
    /// places and the sources of its words.
    PrivateThreadAncestryRecords,
    /// One trusted policy manifest's room-policy rows, each fold.
    RoomPolicyRows,
    /// One trusted policy manifest's room-thread holder rows, each fold.
    RoomThreadHolderRows,
    /// The signed creation-default edits a creation-default fold reads.
    ProjectDepthDefaultRows,
    /// One project's stored depth-policy contributions a depth fold reads.
    ProjectDepthPolicyRows,
    /// The default-edit ancestry one pinned birth source's walk reads.
    ProjectDepthSourceAncestors,
    /// One depth-policy edit's predecessors, at its put.
    ProjectDepthPredecessors,
    /// One depth-policy contribution's bytes, at its put.
    ProjectDepthContributionBytes,
    /// The attempt records one dispatch ancestor walk reads, wrappers
    /// included.
    DispatchAncestorRows,
    /// One TASK's Linear mirror event index rows a provenance page reads,
    /// its lookahead row included.
    LinearProvenanceRows,
}

impl EngineScan {
    /// Every scan, the list the check that none refuses for a count reads.
    pub const ALL: [Self; 65] = [
        Self::ReceivePackIntents,
        Self::PublicationRows,
        Self::VisibleRefRows,
        Self::KeepOwnerRows,
        Self::TypeIndexRows,
        Self::LearnedRangeRows,
        Self::EdgePeerRows,
        Self::ReceiptRecordRows,
        Self::TimelineRecords,
        Self::GateDecisionRows,
        Self::ScopedEdgeRows,
        Self::MachineRows,
        Self::AccessGrantRows,
        Self::MentionRows,
        Self::PprCacheDepRows,
        Self::PackQuarantineRows,
        Self::LexicalHintRows,
        Self::AnswerReceiptRows,
        Self::MinerArtifactRows,
        Self::ChildOfMapEntries,
        Self::TemporalSpannerRows,
        Self::OccurredRangeRows,
        Self::BlendTuningRuns,
        Self::DreamerRetryPeers,
        Self::PendingGateConsentRows,
        Self::TaskCensusRows,
        Self::AskWordRows,
        Self::RoomThreadTasks,
        Self::ReadSetRows,
        Self::RoomPageRows,
        Self::RoomHistoryRows,
        Self::TaskBoardRows,
        Self::RoomThreadChildRows,
        Self::MessageOriginRows,
        Self::ThreadTaskCensus,
        Self::ProjectTaskRows,
        Self::PendingCommStops,
        Self::PartyContactClaims,
        Self::AskSoftConfirmDeliveryRows,
        Self::PredicateClaimRows,
        Self::VaultEdgeRows,
        Self::PrefilterReceiptRows,
        Self::MachineHandoffChain,
        Self::MachineHistoryTargetRows,
        Self::ClaimVadIncidentEdges,
        Self::RetrievalRunRows,
        Self::CallReceiptRows,
        Self::BlockedRunReports,
        Self::SieveAuditRows,
        Self::RoomRosterMembers,
        Self::DagWalkRecords,
        Self::TaskAuthorityFactEdges,
        Self::OpenAskTaskRows,
        Self::AudienceEdgeRows,
        Self::RoomAncestryRecords,
        Self::PrivateThreadAncestryRecords,
        Self::RoomPolicyRows,
        Self::RoomThreadHolderRows,
        Self::ProjectDepthDefaultRows,
        Self::ProjectDepthPolicyRows,
        Self::ProjectDepthSourceAncestors,
        Self::ProjectDepthPredecessors,
        Self::ProjectDepthContributionBytes,
        Self::DispatchAncestorRows,
        Self::LinearProvenanceRows,
    ];

    /// The origin's scans, each over one repository or the publication
    /// journal.
    pub const ORIGIN: [Self; 4] = [
        Self::ReceivePackIntents,
        Self::PublicationRows,
        Self::VisibleRefRows,
        Self::KeepOwnerRows,
    ];

    /// The closed code the scan's row, check and log line name it by.
    pub const fn code(self) -> &'static str {
        match self {
            Self::ReceivePackIntents => "receive_pack_intents",
            Self::PublicationRows => "publication_rows",
            Self::VisibleRefRows => "visible_ref_rows",
            Self::KeepOwnerRows => "keep_owner_rows",
            Self::TypeIndexRows => "type_index_rows",
            Self::LearnedRangeRows => "learned_range_rows",
            Self::EdgePeerRows => "edge_peer_rows",
            Self::ReceiptRecordRows => "receipt_record_rows",
            Self::TimelineRecords => "memory_timeline_records",
            Self::GateDecisionRows => "gate_decision_rows",
            Self::ScopedEdgeRows => "scoped_edge_rows",
            Self::MachineRows => "machine_rows",
            Self::AccessGrantRows => "access_grant_rows",
            Self::MentionRows => "mention_rows",
            Self::PprCacheDepRows => "ppr_cache_dep_rows",
            Self::PackQuarantineRows => "pack_quarantine_rows",
            Self::LexicalHintRows => "lexical_hint_rows",
            Self::AnswerReceiptRows => "answer_receipt_rows",
            Self::MinerArtifactRows => "miner_artifact_rows",
            Self::ChildOfMapEntries => "child_of_map_entries",
            Self::TemporalSpannerRows => "temporal_spanner_rows",
            Self::OccurredRangeRows => "occurred_range_rows",
            Self::BlendTuningRuns => "blend_tuning_runs",
            Self::DreamerRetryPeers => "dreamer_retry_peers",
            Self::PendingGateConsentRows => "pending_gate_consent_rows",
            Self::TaskCensusRows => "task_census_rows",
            Self::AskWordRows => "ask_word_rows",
            Self::RoomThreadTasks => "room_thread_tasks",
            Self::ReadSetRows => "read_set_rows",
            Self::RoomPageRows => "room_page_rows",
            Self::RoomHistoryRows => "room_history_rows",
            Self::TaskBoardRows => "task_board_rows",
            Self::RoomThreadChildRows => "room_thread_child_rows",
            Self::MessageOriginRows => "message_origin_rows",
            Self::ThreadTaskCensus => "thread_task_census",
            Self::ProjectTaskRows => "project_task_rows",
            Self::PendingCommStops => "pending_comm_stops",
            Self::PartyContactClaims => "party_contact_claims",
            Self::AskSoftConfirmDeliveryRows => "ask_soft_confirm_delivery_rows",
            Self::PredicateClaimRows => "predicate_claim_rows",
            Self::VaultEdgeRows => "vault_edge_rows",
            Self::PrefilterReceiptRows => "prefilter_receipt_rows",
            Self::MachineHandoffChain => "machine_handoff_chain",
            Self::MachineHistoryTargetRows => "machine_history_target_rows",
            Self::ClaimVadIncidentEdges => "claim_vad_incident_edges",
            Self::RetrievalRunRows => "retrieval_run_rows",
            Self::CallReceiptRows => "call_receipt_rows",
            Self::BlockedRunReports => "blocked_run_reports",
            Self::SieveAuditRows => "sieve_audit_rows",
            Self::RoomRosterMembers => "room_roster_members",
            Self::DagWalkRecords => "dag_walk_records",
            Self::TaskAuthorityFactEdges => "task_authority_fact_edges",
            Self::OpenAskTaskRows => "open_ask_task_rows",
            Self::AudienceEdgeRows => "audience_edge_rows",
            Self::RoomAncestryRecords => "room_ancestry_records",
            Self::PrivateThreadAncestryRecords => "private_thread_ancestry_records",
            Self::RoomPolicyRows => "room_policy_rows",
            Self::RoomThreadHolderRows => "room_thread_holder_rows",
            Self::ProjectDepthDefaultRows => "project_depth_default_rows",
            Self::ProjectDepthPolicyRows => "project_depth_policy_rows",
            Self::ProjectDepthSourceAncestors => "project_depth_source_ancestors",
            Self::ProjectDepthPredecessors => "project_depth_predecessors",
            Self::ProjectDepthContributionBytes => "project_depth_contribution_bytes",
            Self::DispatchAncestorRows => "dispatch_ancestor_rows",
            Self::LinearProvenanceRows => "linear_provenance_rows",
        }
    }

    /// The threshold the scan asks past while no row is set: the count it
    /// once cut its read short at, or the engine-wide default.
    pub(super) const fn default_threshold(self) -> u64 {
        match self {
            Self::ClaimVadIncidentEdges | Self::TaskAuthorityFactEdges => 100_000,
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
                crate::context_projection::CONTEXT_PROJECTION_ANCESTOR_CHECK
            }
            Self::LinearProvenanceRows => 200,
            _ => DEFAULT_SCAN_CHECK_THRESHOLD,
        }
    }

    pub(super) const fn tag(self) -> [u8; 1] {
        [match self {
            Self::ReceivePackIntents => 1,
            Self::PublicationRows => 2,
            Self::VisibleRefRows => 3,
            Self::KeepOwnerRows => 4,
            Self::TypeIndexRows => 16,
            Self::LearnedRangeRows => 17,
            Self::EdgePeerRows => 18,
            Self::ReceiptRecordRows => 19,
            Self::TimelineRecords => 20,
            Self::GateDecisionRows => 21,
            Self::ScopedEdgeRows => 22,
            Self::MachineRows => 23,
            Self::AccessGrantRows => 24,
            Self::MentionRows => 48,
            Self::PprCacheDepRows => 49,
            Self::PackQuarantineRows => 50,
            Self::LexicalHintRows => 51,
            Self::AnswerReceiptRows => 52,
            Self::MinerArtifactRows => 53,
            Self::ChildOfMapEntries => 54,
            Self::TemporalSpannerRows => 55,
            Self::OccurredRangeRows => 56,
            Self::BlendTuningRuns => 57,
            Self::DreamerRetryPeers => 58,
            Self::PendingGateConsentRows => 25,
            Self::TaskCensusRows => 32,
            Self::AskWordRows => 33,
            Self::RoomThreadTasks => 34,
            Self::ReadSetRows => 35,
            Self::RoomPageRows => 36,
            Self::RoomHistoryRows => 37,
            Self::TaskBoardRows => 38,
            Self::RoomThreadChildRows => 39,
            Self::MessageOriginRows => 40,
            Self::ThreadTaskCensus => 41,
            Self::ProjectTaskRows => 42,
            Self::PendingCommStops => 64,
            Self::PartyContactClaims => 65,
            Self::AskSoftConfirmDeliveryRows => 66,
            Self::PredicateClaimRows => 67,
            Self::VaultEdgeRows => 68,
            Self::PrefilterReceiptRows => 69,
            Self::MachineHandoffChain => 70,
            Self::MachineHistoryTargetRows => 71,
            Self::ClaimVadIncidentEdges => 72,
            Self::RetrievalRunRows => 73,
            Self::CallReceiptRows => 74,
            Self::BlockedRunReports => 75,
            Self::SieveAuditRows => 76,
            Self::RoomRosterMembers => 77,
            Self::DagWalkRecords => 78,
            Self::TaskAuthorityFactEdges => 79,
            Self::OpenAskTaskRows => 80,
            Self::AudienceEdgeRows => 81,
            Self::RoomAncestryRecords => 82,
            Self::PrivateThreadAncestryRecords => 83,
            Self::RoomPolicyRows => 84,
            Self::RoomThreadHolderRows => 85,
            Self::ProjectDepthDefaultRows => 86,
            Self::ProjectDepthPolicyRows => 87,
            Self::ProjectDepthSourceAncestors => 88,
            Self::ProjectDepthPredecessors => 89,
            Self::ProjectDepthContributionBytes => 90,
            Self::DispatchAncestorRows => 91,
            Self::LinearProvenanceRows => 92,
        }]
    }
}
