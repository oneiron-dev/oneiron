//! Rule five, checked at every row the code lists (`LimitRow::ALL`): crossed
//! by a burst on one credential, a row turns nobody away and asks whether
//! everything is okay (ARCH-0044 C5, OF-520). The match below has no
//! wildcard, so a row added without a driver does not compile.

use crate::admission::Crossing;
use crate::wire_telemetry::LimitRow;
use oneiron::limit_ask::EngineLimit;

/// Callers per row: enough to cross a bound of one several times over.
const CALLERS: usize = 8;

async fn cross(row: LimitRow) -> Crossing {
    match row {
        LimitRow::Connections => crate::http_listener::tests::cross_the_floor(CALLERS).await,
        LimitRow::GitExchanges => {
            crate::api::git_http::tests_lifetime::cross_the_exchanges(CALLERS).await
        }
        LimitRow::LfsTransfers | LimitRow::LfsQuota | LimitRow::LfsObjectSize => {
            crate::api::git_lfs::tests::cross_the_lfs_row(row, CALLERS).await
        }
        LimitRow::LfsMemoryBytes => crate::api::git_lfs::tests::cross_the_frames(CALLERS).await,
        LimitRow::CodeRuns => super::mcp_code_admission::cross_the_runs(CALLERS).await,
        LimitRow::CompactionPasses => {
            tokio::task::spawn_blocking(|| crate::ai_host::cross_the_passes(CALLERS))
                .await
                .unwrap()
        }
        LimitRow::EmbedderRequests => tokio::task::spawn_blocking(|| {
            crate::embedder::serve::tests::cross_the_requests(CALLERS)
        })
        .await
        .unwrap(),
        LimitRow::EmbedderBodyBytes => {
            tokio::task::spawn_blocking(|| crate::embedder::serve::tests::cross_the_bodies(CALLERS))
                .await
                .unwrap()
        }
        LimitRow::EmbedderAnswerBytes => tokio::task::spawn_blocking(|| {
            crate::embedder::serve::tests::cross_the_answers(CALLERS)
        })
        .await
        .unwrap(),
        LimitRow::WindowsPerConnection => {
            crate::handler::window_row_tests::cross_the_windows(CALLERS).await
        }
        LimitRow::LiveSessions => crate::livequery::rule5_tests::cross_the_sessions(CALLERS).await,
        LimitRow::LiveSubscriptions => {
            crate::livequery::rule5_tests::cross_the_subscriptions(CALLERS).await
        }
        LimitRow::MessageStreams => tokio::task::spawn_blocking(|| {
            crate::server::live_rows_tests::cross_the_streams(CALLERS)
        })
        .await
        .unwrap(),
        LimitRow::LiveDocuments => tokio::task::spawn_blocking(|| {
            crate::server::live_rows_tests::cross_the_documents(CALLERS)
        })
        .await
        .unwrap(),
        LimitRow::RetainedMemoryBytes => {
            crate::livequery::rule5_tests::cross_the_retained_bytes(CALLERS)
        }
        LimitRow::ResidenceIndexPages | LimitRow::ResidenceIndexBytes => {
            crate::livequery::rule5_tests::cross_the_index(row, CALLERS).await
        }
        LimitRow::DecisionReads => {
            crate::api::llm::decision_read::tests::cross_the_decision_reads(CALLERS).await
        }
        LimitRow::BookingWindows => {
            tokio::task::spawn_blocking(|| crate::api::booking::cross_the_booking_windows(CALLERS))
                .await
                .unwrap()
        }
        LimitRow::Engine(EngineLimit::KeyedFilterJsonBytes) => {
            crate::api::facade::tests::cross_the_keyed_filters(CALLERS).await
        }
        // These rows were added while this test target did not compile, and
        // no driver crosses them yet (FIX-LIST T0I-RULE5-DRIVERS). They are
        // named, not matched by a wildcard, so a newer row still fails to
        // compile; until a driver lands, the test is red at the first of them.
        LimitRow::ContextReads
        | LimitRow::TaskWork
        | LimitRow::RendererWork
        | LimitRow::MediaReplyBytes
        | LimitRow::ChatReplyBytes
        | LimitRow::Engine(
            EngineLimit::KeyedNamespaceSegments
            | EngineLimit::KeyedNamespaceBytes
            | EngineLimit::KeyedKeyBytes
            | EngineLimit::BookingEmailBytes
            | EngineLimit::BookingIntakeAnswers
            | EngineLimit::BookingIntakeValueBytes
            | EngineLimit::BookingLocalTimeWindows
            | EngineLimit::ClaimInputJsonBytes
            | EngineLimit::CoreBatchEntities
            | EngineLimit::LegacyBatchEntities
            | EngineLimit::BlobContentBytes
            | EngineLimit::BookingAvailabilityCallsPerMinute
            | EngineLimit::BookingHoldCallsPerMinute
            | EngineLimit::BookingWriteCallsPerMinute
            | EngineLimit::BookingQuarantineCallsPerMinute
            | EngineLimit::CodeResultInlineBytes
            | EngineLimit::CodeResultDiskFloorBytes
            | EngineLimit::CodeResultScanBytes
            | EngineLimit::CodeResultMemoryBytes
            | EngineLimit::CodeResultSessionMemoryBytes
            | EngineLimit::ImageRoomBytes
            | EngineLimit::CodeReaderBacklog
            | EngineLimit::AskOptions
            | EngineLimit::AskOptionTextBytes
            | EngineLimit::AskContextRefs
            | EngineLimit::AskRecipients
            | EngineLimit::AskSpecMsgpackBytes
            | EngineLimit::AskReminders
            | EngineLimit::AnswerProvenanceRefs
            | EngineLimit::AskWaitIdentities
            | EngineLimit::LinePushMonthly
            | EngineLimit::ImportFolderTextBytes
            | EngineLimit::ImportFolderNotes
            | EngineLimit::ImportDecodedMessages
            | EngineLimit::ImportDecodedBytes
            | EngineLimit::WitnessMetadataNodes
            | EngineLimit::WitnessMetadataBytes
            | EngineLimit::SignatureDecodeBytes
            | EngineLimit::PptxCommentPatches
            | EngineLimit::ImportXlsxLiveCells
            | EngineLimit::PackScriptOutputBytes
            | EngineLimit::PackScriptOutputRows
            | EngineLimit::AttemptManifestEntries
            | EngineLimit::AttemptCancelReceipts
            | EngineLimit::AttemptRetryTipRows
            | EngineLimit::WorkflowSteps
            | EngineLimit::WorkflowNameBytes
            | EngineLimit::JudgeRubricBytes
            | EngineLimit::MaintenanceRowItems
            | EngineLimit::MaintenanceTextBytes
            | EngineLimit::MaintenanceScanRows
            | EngineLimit::JudgeInstructionsBytes
            | EngineLimit::JudgeReplayTextBytes
            | EngineLimit::ContributionJudgeTaskBytes
            | EngineLimit::ContributionJudgeAnswerBytes
            | EngineLimit::CallableNestDepth
            | EngineLimit::ExecutorRunSteps
            | EngineLimit::VoiceReferenceBytes
            | EngineLimit::EsignPdfBytes
            | EngineLimit::StateVadTurns
            | EngineLimit::StateWindowSeconds
            | EngineLimit::DetectorObservations
            | EngineLimit::DetectorEvents
            | EngineLimit::DetectorReceiptRows
            | EngineLimit::DreamerFactsRows
            | EngineLimit::HealerProposals
            | EngineLimit::RepairDiagnosticRefs
            | EngineLimit::CentroidLabels
            | EngineLimit::DetectorConsecutive
            | EngineLimit::DetectorWindowRuns
            | EngineLimit::BlockedDetailBytes
            | EngineLimit::SealReferenceBytes
            | EngineLimit::TripwireThreshold
            | EngineLimit::EsignSweepDocuments
            | EngineLimit::EsignSigningPrincipals
            | EngineLimit::EsignSignatureInputBytes
            | EngineLimit::EsignSignatureImageDimensionPx
            | EngineLimit::EsignSignaturePngBytes
            | EngineLimit::EsignSignatureDocumentBytes
            | EngineLimit::EsignSignatureRecipientImages
            | EngineLimit::EsignRejectReasonBytes
            | EngineLimit::EsignEmailFieldBytes
            | EngineLimit::EsignNameFieldBytes
            | EngineLimit::EsignBodyBytes
            | EngineLimit::EsignGeometryBodyBytes
            | EngineLimit::SealOutputBytes
            | EngineLimit::SealGrowthBytes
            | EngineLimit::SealPdfObjects
            | EngineLimit::SealRawDefinitions
            | EngineLimit::SealCallFrameBytes
            | EngineLimit::SealReplyFrameBytes
            | EngineLimit::SealStructuralWork
            | EngineLimit::SealRevisions
            | EngineLimit::SealPrefixBytes
            | EngineLimit::SealDssDecodeBytes
            | EngineLimit::SealIdentityAsks
            | EngineLimit::SealSignAsks
            | EngineLimit::SealFetchAsks
            | EngineLimit::SealAsks
            | EngineLimit::SealAnswerBytes
            | EngineLimit::SealMemoryAsks
            | EngineLimit::SealCrlBytes
            | EngineLimit::SealOcspBytes
            | EngineLimit::SealTsaBytes
            | EngineLimit::SealReportJsonBytes
            | EngineLimit::SealPreparedStreamBytes
            | EngineLimit::SealStreamDecodeBytes
            | EngineLimit::EsignStreamDecodeBytes
            | EngineLimit::EsignSealStreamCodecBytes
            | EngineLimit::SealStreamHeaderTokens
            | EngineLimit::SealPdfDepth
            | EngineLimit::SealSecurityNameHops
            | EngineLimit::SealReferenceHops
            | EngineLimit::SealDssReferenceWork
            | EngineLimit::SealFieldTreeWork
            | EngineLimit::SealContentsBytes
            | EngineLimit::SealOperationIdBytes
            | EngineLimit::SealBackendOperationIdBytes
            | EngineLimit::OrganAsks
            | EngineLimit::OrganAskPerVerb
            | EngineLimit::OrganAnswerBytes
            | EngineLimit::OrganFetchBytes
            | EngineLimit::OrganFetchRedirects
            | EngineLimit::OrganAskValueBytes
            | EngineLimit::OrganFetchPurposeBytes
            | EngineLimit::OrganOutputBytes
            | EngineLimit::OrganCallFrameBytes
            | EngineLimit::OrganReplyFrameBytes
            | EngineLimit::OrganDetailBytes
            | EngineLimit::OrganVerbBytes
            | EngineLimit::OrganOutputNameBytes
            | EngineLimit::OrganMediaTypeBytes
            | EngineLimit::OrganFetchOriginBytes
            | EngineLimit::OrganContentTypeBytes
            | EngineLimit::OrganNoteItems
            | EngineLimit::OrganNoteBytes
            | EngineLimit::OrganLossCodeBytes
            | EngineLimit::OrganMemoryBytes
            | EngineLimit::OrganMeshObjectBytes
            | EngineLimit::OrganMeshStagedBytes
            | EngineLimit::DeadlineJobsPerCaller
            | EngineLimit::BackupHandoffPendingBackups
            | EngineLimit::BackupHandoffPendingBytes
            | EngineLimit::AuthorityRecordItems
            | EngineLimit::ConnectorLiveQuestions
            | EngineLimit::ConnectorReplyContextBytes
            | EngineLimit::CampaignJudgmentRows
            | EngineLimit::ConnectorBudgetRows
            | EngineLimit::ConnectorSuggestedBudgetRows
            | EngineLimit::ConnectorCharterCaps
            | EngineLimit::ConnectorCatalogVerbs
            | EngineLimit::ConnectorDispatchBatch
            | EngineLimit::IdentityDecisionStateBytes
            | EngineLimit::IdentityExcerptBytes
            | EngineLimit::CommunityCacheBytes
            | EngineLimit::ConnectorManifestEntries
            | EngineLimit::SharedMergeEvidenceRows
            | EngineLimit::ContextThirdParties
            | EngineLimit::MemoryPinnedRefs
            | EngineLimit::CodebaseManifestFiles
            | EngineLimit::RecallQueryBytes
            | EngineLimit::RequestedResultRows
            | EngineLimit::TournamentLineageRows
            | EngineLimit::EmbeddingDimensions
            | EngineLimit::MemoryReasonEvidenceRows
            | EngineLimit::MemoryReasonTokens
            | EngineLimit::DecisionQuestionsPerCall
            | EngineLimit::ContextEdgeHops
            | EngineLimit::ContextNeighbors
            | EngineLimit::ContextSelectedEdges,
        ) => {
            unimplemented!("{}: no Rule-5 driver crosses this row yet", row.key())
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_limits_row_queues_its_burst_and_asks() {
    for row in LimitRow::ALL {
        assert_eq!(
            cross(row).await,
            Crossing {
                refused: 0,
                asked: true
            },
            "{}: past the row, work waits its turn and the row asks; nothing is refused",
            row.key()
        );
    }
}
