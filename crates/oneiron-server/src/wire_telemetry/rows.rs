//! The `[limits]` rows this server's questions name (moved out of
//! `wire_telemetry.rs` whole, so the telemetry file stays small).

use oneiron::limit_ask::EngineLimit;

/// A `[limits]` row: a bound on work a remote caller can start, set far above
/// fleet scale. Crossing one is a question, never a refusal (OF-520).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LimitRow {
    /// Sockets open at once: the descriptor floor.
    Connections,
    /// `git http-backend` exchanges at once.
    GitExchanges,
    /// LFS transfer workers at once.
    LfsTransfers,
    /// Bytes LFS transfers hold in memory at once.
    LfsMemoryBytes,
    /// Bytes stored LFS objects and uploads in flight come to.
    LfsQuota,
    /// One LFS object's size.
    LfsObjectSize,
    /// `execute_code` runs at once.
    CodeRuns,
    /// Code-mode compaction passes at once.
    CompactionPasses,
    /// Requests the embedder endpoint holds at once.
    EmbedderRequests,
    /// Bytes the embedder endpoint's request bodies hold at once.
    EmbedderBodyBytes,
    /// Bytes the embedder endpoint's answers hold until they are delivered.
    EmbedderAnswerBytes,
    /// Windows and documents one sync socket keeps state for.
    WindowsPerConnection,
    /// Live-query sessions held at once, attached or kept for a reconnect.
    LiveSessions,
    /// Live-query subscriptions open at once.
    LiveSubscriptions,
    /// Message streams one vault holds open at once.
    MessageStreams,
    /// Text documents one vault keeps resident at once.
    LiveDocuments,
    /// Bytes app-tier state retained between frames holds: the presence hub,
    /// live-query retention and residence index projections.
    RetainedMemoryBytes,
    /// Pages one residence index projection is read in.
    ResidenceIndexPages,
    /// Bytes one residence index projection holds.
    ResidenceIndexBytes,
    /// Decision reads the owner's probe route holds at once.
    DecisionReads,
    /// Task work (`can`, `ask`, `wait`, `tasks.answer`) one vault runs at
    /// once; past it, each caller's work waits its fair turn.
    TaskWork,
    /// Booking requests per minute under the owner's slot-list, hold and book
    /// rules: an authenticated caller past one waits for it to open.
    BookingWindows,
    /// Deck and slide renders the host runs at once (FIX 7653); past it,
    /// each caller's render waits its fair turn.
    RendererWork,
    /// Bytes the media replies providers send this server hold at once,
    /// from the first byte read until the decoded answer leaves its adapter
    /// (FIX 8615): past it a reply waits its turn, and one larger than the
    /// whole line runs alone. Never a size refusal.
    MediaReplyBytes,
    /// Bytes the JSON replies a ladder's chat sends read whole hold at once,
    /// until the send ends (FIX 10626): charged as they arrive, never waited
    /// for, a crossing recorded. Never a size refusal.
    ChatReplyBytes,
    /// An engine row on this server's vault (`oneiron::limit_ask`), measured
    /// where the engine serves the work, which carries on past it.
    Engine(EngineLimit),
}
impl LimitRow {
    /// Every row, the list every permit site and byte check is built from.
    pub const ALL: [Self; 25 + EngineLimit::ALL.len()] = [
        Self::Connections,
        Self::GitExchanges,
        Self::LfsTransfers,
        Self::LfsMemoryBytes,
        Self::LfsQuota,
        Self::LfsObjectSize,
        Self::CodeRuns,
        Self::CompactionPasses,
        Self::EmbedderRequests,
        Self::EmbedderBodyBytes,
        Self::EmbedderAnswerBytes,
        Self::WindowsPerConnection,
        Self::LiveSessions,
        Self::LiveSubscriptions,
        Self::MessageStreams,
        Self::LiveDocuments,
        Self::RetainedMemoryBytes,
        Self::ResidenceIndexPages,
        Self::ResidenceIndexBytes,
        Self::DecisionReads,
        Self::TaskWork,
        Self::BookingWindows,
        Self::RendererWork,
        Self::MediaReplyBytes,
        Self::ChatReplyBytes,
        Self::Engine(EngineLimit::KeyedFilterJsonBytes),
        Self::Engine(EngineLimit::CodeResultInlineBytes),
        Self::Engine(EngineLimit::CodeResultDiskFloorBytes),
        Self::Engine(EngineLimit::CodeResultScanBytes),
        Self::Engine(EngineLimit::CodeResultMemoryBytes),
        Self::Engine(EngineLimit::CodeResultSessionMemoryBytes),
        Self::Engine(EngineLimit::ImageRoomBytes),
        Self::Engine(EngineLimit::CodeReaderBacklog),
        Self::Engine(EngineLimit::AskOptions),
        Self::Engine(EngineLimit::AskOptionTextBytes),
        Self::Engine(EngineLimit::AskContextRefs),
        Self::Engine(EngineLimit::AskRecipients),
        Self::Engine(EngineLimit::AskSpecMsgpackBytes),
        Self::Engine(EngineLimit::AskReminders),
        Self::Engine(EngineLimit::AnswerProvenanceRefs),
        Self::Engine(EngineLimit::AskWaitIdentities),
        Self::Engine(EngineLimit::LinePushMonthly),
        Self::Engine(EngineLimit::ImportFolderTextBytes),
        Self::Engine(EngineLimit::ImportFolderNotes),
        Self::Engine(EngineLimit::ImportDecodedMessages),
        Self::Engine(EngineLimit::ImportDecodedBytes),
        Self::Engine(EngineLimit::SignatureDecodeBytes),
        Self::Engine(EngineLimit::PptxCommentPatches),
        Self::Engine(EngineLimit::ImportXlsxLiveCells),
        Self::Engine(EngineLimit::PackScriptOutputBytes),
        Self::Engine(EngineLimit::PackScriptOutputRows),
        Self::Engine(EngineLimit::AttemptManifestEntries),
        Self::Engine(EngineLimit::AttemptCancelReceipts),
        Self::Engine(EngineLimit::AttemptRetryTipRows),
        Self::Engine(EngineLimit::WorkflowSteps),
        Self::Engine(EngineLimit::WorkflowNameBytes),
        Self::Engine(EngineLimit::JudgeRubricBytes),
        Self::Engine(EngineLimit::MaintenanceRowItems),
        Self::Engine(EngineLimit::MaintenanceTextBytes),
        Self::Engine(EngineLimit::MaintenanceScanRows),
        Self::Engine(EngineLimit::JudgeInstructionsBytes),
        Self::Engine(EngineLimit::JudgeReplayTextBytes),
        Self::Engine(EngineLimit::ContributionJudgeTaskBytes),
        Self::Engine(EngineLimit::ContributionJudgeAnswerBytes),
        Self::Engine(EngineLimit::CallableNestDepth),
        Self::Engine(EngineLimit::ExecutorRunSteps),
        Self::Engine(EngineLimit::VoiceReferenceBytes),
        Self::Engine(EngineLimit::EsignPdfBytes),
        Self::Engine(EngineLimit::StateVadTurns),
        Self::Engine(EngineLimit::StateWindowSeconds),
        Self::Engine(EngineLimit::DetectorObservations),
        Self::Engine(EngineLimit::DetectorEvents),
        Self::Engine(EngineLimit::DetectorReceiptRows),
        Self::Engine(EngineLimit::DreamerFactsRows),
        Self::Engine(EngineLimit::HealerProposals),
        Self::Engine(EngineLimit::RepairDiagnosticRefs),
        Self::Engine(EngineLimit::CentroidLabels),
        Self::Engine(EngineLimit::DetectorConsecutive),
        Self::Engine(EngineLimit::DetectorWindowRuns),
        Self::Engine(EngineLimit::BlockedDetailBytes),
        Self::Engine(EngineLimit::SealReferenceBytes),
        Self::Engine(EngineLimit::TripwireThreshold),
        Self::Engine(EngineLimit::EsignSweepDocuments),
        Self::Engine(EngineLimit::EsignSigningPrincipals),
        Self::Engine(EngineLimit::EsignSignatureInputBytes),
        Self::Engine(EngineLimit::EsignSignaturePngBytes),
        Self::Engine(EngineLimit::EsignSignatureDocumentBytes),
        Self::Engine(EngineLimit::EsignSignatureRecipientImages),
        Self::Engine(EngineLimit::EsignBodyBytes),
        Self::Engine(EngineLimit::EsignGeometryBodyBytes),
        Self::Engine(EngineLimit::SealOutputBytes),
        Self::Engine(EngineLimit::SealGrowthBytes),
        Self::Engine(EngineLimit::SealPdfObjects),
        Self::Engine(EngineLimit::SealRawDefinitions),
        Self::Engine(EngineLimit::SealCallFrameBytes),
        Self::Engine(EngineLimit::SealReplyFrameBytes),
        Self::Engine(EngineLimit::SealStructuralWork),
        Self::Engine(EngineLimit::SealRevisions),
        Self::Engine(EngineLimit::SealPrefixBytes),
        Self::Engine(EngineLimit::SealDssDecodeBytes),
        Self::Engine(EngineLimit::SealIdentityAsks),
        Self::Engine(EngineLimit::SealSignAsks),
        Self::Engine(EngineLimit::SealFetchAsks),
        Self::Engine(EngineLimit::SealAsks),
        Self::Engine(EngineLimit::SealAnswerBytes),
        Self::Engine(EngineLimit::SealMemoryAsks),
        Self::Engine(EngineLimit::SealCrlBytes),
        Self::Engine(EngineLimit::SealTsaBytes),
        Self::Engine(EngineLimit::SealReportJsonBytes),
        Self::Engine(EngineLimit::SealPreparedStreamBytes),
        Self::Engine(EngineLimit::SealStreamDecodeBytes),
        Self::Engine(EngineLimit::EsignStreamDecodeBytes),
        Self::Engine(EngineLimit::EsignSealStreamCodecBytes),
        Self::Engine(EngineLimit::SealStreamHeaderTokens),
        Self::Engine(EngineLimit::SealPdfDepth),
        Self::Engine(EngineLimit::SealSecurityNameHops),
        Self::Engine(EngineLimit::SealReferenceHops),
        Self::Engine(EngineLimit::SealDssReferenceWork),
        Self::Engine(EngineLimit::SealFieldTreeWork),
        Self::Engine(EngineLimit::SealContentsBytes),
        Self::Engine(EngineLimit::SealOperationIdBytes),
        Self::Engine(EngineLimit::SealBackendOperationIdBytes),
        Self::Engine(EngineLimit::OrganAsks),
        Self::Engine(EngineLimit::OrganAskPerVerb),
        Self::Engine(EngineLimit::OrganAnswerBytes),
        Self::Engine(EngineLimit::OrganFetchBytes),
        Self::Engine(EngineLimit::OrganFetchRedirects),
        Self::Engine(EngineLimit::OrganAskValueBytes),
        Self::Engine(EngineLimit::OrganFetchPurposeBytes),
        Self::Engine(EngineLimit::OrganOutputBytes),
        Self::Engine(EngineLimit::OrganCallFrameBytes),
        Self::Engine(EngineLimit::OrganReplyFrameBytes),
        Self::Engine(EngineLimit::OrganDetailBytes),
        Self::Engine(EngineLimit::OrganVerbBytes),
        Self::Engine(EngineLimit::OrganOutputNameBytes),
        Self::Engine(EngineLimit::OrganMediaTypeBytes),
        Self::Engine(EngineLimit::OrganFetchOriginBytes),
        Self::Engine(EngineLimit::OrganContentTypeBytes),
        Self::Engine(EngineLimit::OrganNoteItems),
        Self::Engine(EngineLimit::OrganNoteBytes),
        Self::Engine(EngineLimit::OrganLossCodeBytes),
        Self::Engine(EngineLimit::OrganMemoryBytes),
        Self::Engine(EngineLimit::OrganMeshObjectBytes),
        Self::Engine(EngineLimit::OrganMeshStagedBytes),
        Self::Engine(EngineLimit::DeadlineJobsPerCaller),
        Self::Engine(EngineLimit::BackupHandoffPendingBackups),
        Self::Engine(EngineLimit::BackupHandoffPendingBytes),
        Self::Engine(EngineLimit::AuthorityRecordItems),
        Self::Engine(EngineLimit::ConnectorLiveQuestions),
        Self::Engine(EngineLimit::ConnectorReplyContextBytes),
        Self::Engine(EngineLimit::CampaignJudgmentRows),
        Self::Engine(EngineLimit::ConnectorBudgetRows),
        Self::Engine(EngineLimit::ConnectorSuggestedBudgetRows),
        Self::Engine(EngineLimit::ConnectorCharterCaps),
        Self::Engine(EngineLimit::ConnectorCatalogVerbs),
        Self::Engine(EngineLimit::ConnectorDispatchBatch),
        Self::Engine(EngineLimit::IdentityDecisionStateBytes),
        Self::Engine(EngineLimit::IdentityExcerptBytes),
        Self::Engine(EngineLimit::CommunityCacheBytes),
        Self::Engine(EngineLimit::ConnectorManifestEntries),
        Self::Engine(EngineLimit::SharedMergeEvidenceRows),
    ];
    /// The config key that sets the row, or, for the memory the embedder
    /// endpoint sizes for its one model, the name it asks under.
    pub const fn key(self) -> &'static str {
        match self {
            Self::Connections => "limits.max_connections",
            Self::GitExchanges => "limits.git_exchanges",
            Self::LfsTransfers => "limits.lfs_transfers",
            Self::LfsMemoryBytes => "limits.lfs_memory_bytes",
            Self::LfsQuota => "limits.lfs_quota_bytes",
            Self::LfsObjectSize => "max_lfs_object_bytes",
            Self::CodeRuns => "models.code_mode.max_runs",
            // As many passes as runs: at most one per run is in flight.
            Self::CompactionPasses => "models.code_mode.max_runs:compaction",
            Self::EmbedderRequests => "limits.embedder_requests",
            Self::EmbedderBodyBytes => "embedder.serve:body_bytes",
            Self::EmbedderAnswerBytes => "limits.embedder_answer_bytes",
            Self::WindowsPerConnection => "max_windows_per_connection",
            Self::LiveSessions => "limits.live_sessions",
            Self::LiveSubscriptions => "limits.live_subscriptions",
            Self::MessageStreams => "limits.message_streams",
            Self::LiveDocuments => "limits.live_documents",
            Self::RetainedMemoryBytes => "limits.retained_memory_bytes",
            Self::ResidenceIndexPages => "residence_operation_budgets.max_index_pages",
            Self::ResidenceIndexBytes => "residence_operation_budgets.index_cache_bytes",
            Self::DecisionReads => "limits.decision_reads",
            Self::TaskWork => "limits.task_work",
            Self::BookingWindows => "booking.anti_abuse:per_minute",
            Self::RendererWork => "limits.renderer_work",
            Self::MediaReplyBytes => "limits.media_reply_bytes",
            Self::ChatReplyBytes => "limits.chat_reply_bytes",
            Self::Engine(row) => row.key(),
        }
    }
}
