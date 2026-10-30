//! The owner preflight every host door's verb meets before its door runs.
//! `door_admits` is its call surface.
//! Each door's own facade module defines the proof it admits on; this match only routes to it.
//! The generated `HostDoorRow` names every host door that checks first, so the match has no
//! catch-all arm and a new host door fails to compile until it names its check (FIX 1763).

use oneiron::memory::MemoryResult;

use super::super::host_door_rows::HostDoorRow as Row;
use super::support::{
    MEDIA_OWNERS, VIDEO_JOB_OWNERS, artifact_asker, asking, diary_reader, owner_grade, owner_proof,
    slide_reviewer,
};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The authority check host-door row `verb`'s own door runs first: the
/// owner's proof, a person's proof, a bound principal or an owner-grade
/// credential. The facade runs it before the row's pre chain, so a hook
/// never fires on a call the door refuses; the door runs it again for the
/// proof it acts under. A host door whose table row says
/// `"host_door_precheck": false` has no such check and passes, as does any
/// row that is no host door.
pub(in crate::api::facade) fn door_admits(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<()> {
    // Every other host door names its check below (FIX 1763).
    let Some(row) = Row::from_verb(verb) else {
        return Ok(());
    };
    match row {
        Row::VaultBookingConstraintTurn
        | Row::VaultBookingAvailability
        | Row::VaultBookingBook
        | Row::VaultBookingReschedule
        | Row::VaultBookingCancel => {
            crate::api::facade::owner_binding::host_preflight(server, auth)?;
            crate::api::host_action::require_host_owner_act(server, auth)
                .map(drop)
                .map_err(|error| {
                    crate::api::facade::FacadeApiError::from(error).into_memory_error()
                })
        }
        Row::VaultModelsManifestRead
        | Row::VaultModelsManifestReplace
        | Row::VaultModelsOneironerBind
        | Row::VaultModelsRoutesRead
        | Row::VaultModelsRoutesReplace
        | Row::VaultModelsRolesRead
        | Row::VaultModelsRolesInvoke
        | Row::AiStepsSubmit
        | Row::AiStepsReceipt
        | Row::AiStreamsOpen
        | Row::AiStreamsSubscribe
        | Row::AiStreamsEvents
        | Row::AiStreamsDetach
        | Row::AiStreamsAbort
        | Row::AiStreamsTerminal
        | Row::VaultModelsCatalogRefresh
        | Row::VaultModelsCatalogGet
        | Row::VaultModelsCatalogDiff
        | Row::VaultModelsTrialsNominate
        | Row::VaultModelsTrialsGet
        | Row::VaultModelsTrialsApprove
        | Row::VaultModelsTrialsRun
        | Row::VaultModelsTrialsComplete
        | Row::VaultModelsBindingsPropose
        | Row::VaultModelsBindingsGet
        | Row::VaultModelsBindingsRead
        | Row::VaultModelsBindingsAccept
        | Row::VaultModelsBindingsDeny
        | Row::VaultRunsStep
        | Row::VaultRunsCheckpoint
        | Row::VaultRunsReview
        | Row::VaultRunsSettle
        | Row::VaultRunsSettlement
        | Row::VaultRevertRun
        | Row::AiReply
        | Row::CalendarIcsConfigure
        | Row::CalendarIcsPoll
        | Row::CalendarIcsStatus
        | Row::CalendarConnectorConfigure
        | Row::CalendarConnectorGet
        | Row::CalendarConnectorKill
        | Row::CalendarConnectorPull
        | Row::CalendarConnectorWrite
        | Row::CalendarImipConfigure
        | Row::CalendarImipGet
        | Row::VaultCalendarIcsImport
        | Row::VaultCalendarInstancesMove
        | Row::VaultCalendarOutcomePolicyGet
        | Row::VaultCalendarOutcomePolicySet
        | Row::VaultCalendarCheckInDue
        | Row::VaultCalendarCheckInAnswer
        | Row::VaultCampaignComplianceInstall
        | Row::VaultCampaignComplianceApprove
        | Row::VaultCampaignComplianceReject
        | Row::VaultCampaignComplianceVerify
        | Row::VaultCompanionsAccessRequestsAnswer
        | Row::VaultDisclosureCeilingGet
        | Row::VaultDisclosureCeilingSet
        | Row::VaultDisclosureCeilingClear
        | Row::VaultDisclosureReveals
        | Row::VaultDisclosureRevealsAnswer
        | Row::VaultCommitmentsCreate
        | Row::VaultCommitmentsGet
        | Row::VaultCommitmentsInstances
        | Row::VaultCommitmentsProposals
        | Row::VaultCommitmentsFulfill
        | Row::VaultCommitmentsRelease
        | Row::VaultCommitmentsSupersede
        | Row::VaultPersonasPreview
        | Row::VaultPersonasExport
        | Row::VaultPersonasEdit
        | Row::VaultIdentityMerge
        | Row::VaultIdentitySplit
        | Row::VaultIdentityFacet
        | Row::VaultIdentityAssertDistinct
        | Row::VaultIdentityPropose
        | Row::VaultIdentityUndo
        | Row::VaultIdentityResolve
        | Row::VaultIdentityEventsGet
        | Row::VaultIdentityProposalsResolve
        | Row::VaultIdentityProposalsForPair
        | Row::VaultPacksPreview
        | Row::VaultPacksConnectorPrepare
        | Row::VaultPacksConnectorGet
        | Row::VaultPacksConnectorQualify
        | Row::VaultPacksConnectorAccept
        | Row::VaultPacksConnectorUpdate
        | Row::VaultPacksConnectorGrantsGet
        | Row::VaultPacksConnectorGrantsPut
        | Row::VaultPacksRemove
        | Row::VaultSkillHubsPut
        | Row::VaultSkillHubsGet
        | Row::VaultSkillHubsDefaultGet
        | Row::VaultSkillHubsPublishersAdmit
        | Row::VaultSkillHubsPublishersRevoke
        | Row::VaultSkillHubsRefsGet
        | Row::VaultSkillHubsRefsSet
        | Row::VaultPacksInstall
        | Row::VaultPacksSync
        | Row::VaultPacksGet
        | Row::VaultSkillsBootstrap
        | Row::VaultSkillsRestoredefaults
        | Row::VaultSkillsImport
        | Row::VaultSkillsSync
        | Row::VaultSkillsReceipts
        | Row::VaultSkillsConvert
        | Row::VaultSkillsGet
        | Row::VaultSkillsList
        | Row::VaultSkillsArchive
        | Row::VaultSkillsRestore
        | Row::VaultSkillsRulesSet
        | Row::VaultSkillsCodeAutoInstallSet
        | Row::VaultSkillsPermissionsApprove
        | Row::VaultSkillsOptimizeStart
        | Row::VaultSkillsOptimizeResult
        | Row::VaultProjectsGoalIntakeComplete
        | Row::VaultProjectsGoalGet
        | Row::VaultSkillsOptimizePropose
        | Row::VaultSkillsOptimizeMeasure
        | Row::VaultSkillsOptimizeScore
        | Row::VaultSkillsOptimizeAdmit
        | Row::VaultSkillsOptimizeGoalGet
        | Row::VaultSkillsOptimizeGoalBind
        | Row::VaultSkillsOptimizePreferencesGet
        | Row::VaultSkillsOptimizePreferencesSet
        | Row::VaultSkillsGovernanceGet
        | Row::VaultSkillsGovernanceSet
        | Row::VaultSkillsPackReceipt
        | Row::VaultSkillsOutcomesProject
        | Row::VaultSkillsOutcomesGet
        | Row::VaultSkillsAttributionSettle
        | Row::VaultSkillsAttributionRead
        | Row::VaultSkillsAttributionEvidenceRecord
        | Row::VaultSkillsAttributionProject
        | Row::VaultSkillsAttributionJudgments
        | Row::VaultSkillsAttributionProposals
        | Row::VaultSkillsAttributionPositiveRetire
        | Row::VaultPacksHooksBind
        | Row::VaultPacksHooksList
        | Row::VaultPacksHooksGrantSet
        | Row::VaultPacksHooksGrantGet
        | Row::VaultPacksHooksQualify
        | Row::VaultConnectorsProxyAdmit
        | Row::VaultConnectorsProxyRevokeWrite
        | Row::VaultConnectorsSubscriptionsPut
        | Row::VaultConnectorsSubscriptionsList
        | Row::VaultConnectorsSubscriptionsRevoke
        | Row::VaultAuthorityAudit
        | Row::VaultAuthorityHistoryExport
        | Row::VaultAuthorityHistoryImport
        | Row::VaultAuthorityClockRepair
        | Row::VaultMeshPathReceipts
        | Row::VaultMeshIdentity
        | Row::VaultMeshBindMachine
        | Row::VaultMeshSetAlpnGrant
        | Row::VaultMeshRevokeMachine
        | Row::VaultMeshDial
        | Row::HostCompact
        | Row::HostWake
        | Row::HostBudgetHit
        | Row::VaultHooksReplay
        | Row::VaultHooksRegenDue
        | Row::VaultHooksRegenGet
        | Row::VaultHooksRegenAdopt
        | Row::VaultLensesActivate
        | Row::VaultLensesDeactivate
        | Row::VaultAuthorityHandoffAlarms
        | Row::VaultAuthorityHandoffAlarmsAcknowledge
        | Row::VaultRecordsEraseSweep
        | Row::VaultCleanupRun
        | Row::VaultCleanupReview
        | Row::VaultCleanupDecide
        | Row::VaultEntitiesMention
        | Row::VaultPeopleCreate
        | Row::VaultEntitiesLookBeforeMint
        | Row::VaultIdentityMention
        | Row::SelfIdentityAnswer
        | Row::VaultLegalHoldsPlace
        | Row::VaultLegalHoldsWiden
        | Row::VaultLegalHoldsList
        | Row::VaultLegalHoldsLog
        | Row::VaultLegalHoldsLiftAndErase
        | Row::VaultAgentsGrantsMint
        | Row::VaultAgentsGrantsRevoke
        | Row::VaultRepoGitPushMint
        | Row::VaultRepoGitPushRevoke
        | Row::VaultRepoAnchorBind
        | Row::VaultAgentsBase
        | Row::VaultResidenceMode
        | Row::VaultResidenceOpen
        | Row::VaultResidenceIndex
        | Row::VaultResidencePrune
        | Row::VaultResidenceDirectives
        | Row::VaultCourtesyDeleteSend
        | Row::VaultCourtesyDeleteSent
        | Row::VaultCourtesyDeleteIncoming
        | Row::VaultCourtesyDeleteAnswer
        | Row::VaultDecisionsBandsRead
        | Row::VaultDecisionsBandsLearn
        | Row::VaultDecisionsBandsEnforce
        | Row::VaultRetrievalAgingGet
        | Row::VaultRetrievalAgingConfigure
        | Row::VaultRetrievalWeightsGet
        | Row::VaultRetrievalWeightsConfigure
        | Row::VaultRetrievalHydeConfigure
        | Row::VaultRetrievalHydeGet
        | Row::VaultAffectClaimsConsolidate
        | Row::VaultWireHealthThresholdsGet
        | Row::VaultWireHealthThresholdsSet
        | Row::VaultAffectCopingRecord
        | Row::VaultAffectCopingUpdate
        | Row::VaultAffectCopingAggregate
        | Row::VaultAffectWellnessPolicyGet
        | Row::VaultAffectWellnessPolicyConfigure
        | Row::VaultAffectWellnessDerive
        | Row::VaultAffectWellnessGet
        | Row::VaultSlimPolicy
        | Row::VaultSlimState
        | Row::VaultSlimResumeStep
        | Row::VaultSlimDropHeavy
        | Row::VaultSlimResume
        | Row::VaultRetrievalRecall
        | Row::VaultVectorsPut
        | Row::VaultRetrievalRuns
        | Row::VaultRetrievalRun
        | Row::VaultRetrievalTurn
        | Row::VaultRetrievalOutcomesPut
        | Row::VaultRetrievalOutcomesEnd
        | Row::VaultRetrievalTrace
        | Row::VaultRetrievalExport
        | Row::VaultRetrievalReplay
        | Row::VaultRetrievalPolicyGet
        | Row::VaultRetrievalPolicyPin
        | Row::VaultRetrievalPolicyTrain
        | Row::VaultRetrievalPolicyEvaluate
        | Row::VaultRetrievalPolicyAdmit
        | Row::VaultRetrievalPolicyUpdate
        | Row::VaultLearningRead
        | Row::VaultLearningProjection
        | Row::VaultSealConfess
        | Row::VaultSealAudit
        | Row::VaultSealReceipt
        | Row::VaultSealPending
        | Row::VaultSealRun
        | Row::VaultSealComplete
        | Row::VaultSettingsLearning
        | Row::VaultSettingsLearningPut
        | Row::VaultSettingsLearningClear
        | Row::VaultWidenProposals
        | Row::VaultWidenProposalsApprove
        | Row::VaultWidenProposalsDecline
        | Row::VaultCraftCandidates
        | Row::VaultCraftCandidatesAnswer
        | Row::VaultMemorySignalExtraction
        | Row::VaultMemorySignalExtractionResult
        | Row::FeedbackPreview
        | Row::FeedbackSend
        | Row::VaultReportsDisclosure
        | Row::VaultReportsRoute
        | Row::VaultReportsOutbound
        | Row::VaultWritesCriticalConfirmPending
        | Row::VaultWritesCriticalConfirmClear
        | Row::VaultWritesCriticalConfirmDecline
        | Row::VaultWritesCriticalConfirmReceipt
        | Row::VaultClaimsReview
        | Row::VaultClaimsSettle
        | Row::VaultPacksSectionsGrant
        | Row::VaultPacksSectionsRevoke
        | Row::VaultPacksSectionsSuggestionsGet
        | Row::VaultPacksSectionsSuggestionsSet
        | Row::VaultClaimsVet
        | Row::VaultClaimsVetting
        | Row::VaultConsolidationPromote
        | Row::VaultConsolidationEvidence
        | Row::VaultConsolidationPin
        | Row::VaultConsolidationFrontier
        | Row::VaultConsolidationAccounting
        | Row::VaultSieveEvidence
        | Row::VaultSieveEvidenceReplay
        | Row::VaultSieveCadence
        | Row::VaultSieveSettlements
        | Row::VaultSieveSettlementsGet
        | Row::VaultSieveQueue
        | Row::VaultSieveRetained
        | Row::VaultSieveReceipts
        | Row::VaultSievePolicy
        | Row::VaultSievePolicySet
        | Row::VaultSieveRecipePolicy
        | Row::VaultSieveRecipePolicySet
        | Row::VaultSieveLease
        | Row::VaultSieveLeaseRefill
        | Row::VaultFreeTimePolicyGet
        | Row::VaultFreeTimePolicySet
        | Row::VaultFreeTimeCycles
        | Row::VaultFreeTimeCycle
        | Row::VaultSettingsWakePolicySet
        | Row::VaultAgentsCreate
        | Row::VaultAgentsUpdate
        | Row::VaultAgentsGet
        | Row::VaultAgentsDreamingGet
        | Row::VaultAgentsDreamingSet
        | Row::VaultStandingBlocksConfigure
        | Row::VaultStandingBlocksReconfigure
        | Row::VaultStandingBlocksGet
        | Row::VaultStandingBlocksList
        | Row::VaultWorkflowsSave
        | Row::VaultWorkflowsUpdate
        | Row::VaultWorkflowsGet
        | Row::VaultWorkflowsDispatch
        | Row::VaultWorkflowsStatus
        | Row::VaultTaskTypesPin
        | Row::VaultTaskTypesGet
        | Row::VaultAgentsSpawnGet
        | Row::VaultAgentsSpawn
        | Row::VaultTasksCancelForce
        | Row::VaultRunsBranchesGet
        | Row::VaultConsultsGet
        | Row::VaultConsolidationHomeGet
        | Row::VaultConsolidationHomePick
        | Row::VaultConsolidationLineage
        | Row::VaultConsolidationCandidateDecisions
        | Row::VaultWorkspaceRoster
        | Row::VaultBookingPageToken
        | Row::VaultChannelIdentitiesProvision
        | Row::VaultChannelIdentitiesBind
        | Row::VaultChannelIdentitiesFulfill
        | Row::VaultChannelIdentitiesRotate
        | Row::VaultChannelIdentitiesRelease
        | Row::VaultChannelIdentitiesRouteInbound
        | Row::VaultDeliveryWindowPolicyPut
        | Row::VaultDeliveryWindowPolicyRetract
        | Row::VaultPolicyOwnerGet
        | Row::VaultPolicyOwnerConfigure
        | Row::VaultPolicyOwnerRowChange
        | Row::VaultConsentApproveOnce
        | Row::VaultConnectorsCallsApproveOnce
        | Row::VaultConnectorsSlatesRedraft
        | Row::VaultConnectorsSlatesScopeOutcome
        | Row::VaultConnectorsSlatesRevisionOffers
        | Row::VaultConnectorsSlatesDeferRevision
        | Row::VaultConnectorsSlatesAcceptRevision
        | Row::VaultConnectorsSlatesReaskIssuer
        | Row::VaultConsentDeny
        | Row::VaultConsentFailureSignalsHeld
        | Row::VaultConsentCreateStandingGrant
        | Row::VaultConsentRegistry
        | Row::VaultConsentRevoke
        | Row::VaultConsentBypassGrantWarning
        | Row::VaultConsentCreateBypassGrant
        | Row::VaultConsentActiveBypassGrants
        | Row::VaultConsentBypassedEffectReceipts
        | Row::VaultConsentGraduationPolicy
        | Row::VaultConsentGraduationPolicySet
        | Row::VaultConsentGraduationPolicyClear
        | Row::VaultConsentGraduationStats
        | Row::VaultConsentGraduationOutcome
        | Row::VaultConsentGraduationOffers
        | Row::VaultConsentGraduationAnswer
        | Row::VaultConsentGraduationTrustTable
        | Row::VaultConsentGraduationSettingsUnpin
        | Row::VaultConsentGraduationDemote
        | Row::VaultGatePolicyGet
        | Row::VaultGateCheckerGet
        | Row::VaultGateCheckerSet
        | Row::VaultEmbeddingSpacesList
        | Row::VaultEmbeddingSpacesDeclare
        | Row::VaultEmbeddingSpacesBind
        | Row::VaultEmbeddingSpacesOneSpace
        | Row::VaultEmbeddingSpacesRetire
        | Row::VaultEmbeddingSpacesMove
        | Row::VaultEmbeddingSpacesMoveCheck
        | Row::VaultEmbeddingSpacesMoveApprove
        | Row::VaultEmbeddingSpacesMoveUndo
        | Row::VaultEmbeddingSpacesMoveAbandon
        | Row::VaultEmbeddingSpacesProbesList
        | Row::VaultEmbeddingSpacesProbesPut
        | Row::VaultEmbeddingSpacesProbesDelete
        | Row::VaultFanoutResume
        | Row::VaultFanoutAck
        | Row::VaultFederationCoreferenceLink
        | Row::VaultFederationCoreferenceConfirm
        | Row::VaultFederationCoreferenceShareConsent
        | Row::VaultFederationCoreferenceUnlink
        | Row::VaultFederationBurstIngress
        | Row::VaultFederationBurstDisposition
        | Row::VaultFederationBurstReplay
        | Row::VaultFederationBurstBaseline
        | Row::VaultFederationBurstPolicy
        | Row::VaultFederationBurstPolicySet
        | Row::VaultFederationBurstReview
        | Row::VaultFederationBurstReviewRelease
        | Row::VaultFederationBurstReviewReject
        | Row::VaultFederationConnectIdentity
        | Row::VaultFederationConnectGrantsMint
        | Row::VaultFederationConnectOffer
        | Row::VaultFederationConnectAccept
        | Row::VaultFederationConnectNarrow
        | Row::VaultFederationConnectRescopeOffer
        | Row::VaultFederationConnectRescopeAccept
        | Row::VaultFederationConnectDisconnect
        | Row::VaultFederationConnectExport
        | Row::VaultFederationConnectRejoin
        | Row::VaultGuestsShare
        | Row::VaultGuestsReshare
        | Row::VaultGuestsRevoke
        | Row::VaultGuestsMintSlip
        | Row::VaultSupportGrantsMint
        | Row::VaultSupportGrantsList
        | Row::VaultSupportGrantsRevoke
        | Row::VaultFilesSourcesAttach
        | Row::VaultFilesSourcesRescan
        | Row::VaultFilesSourcesDetach
        | Row::VaultFilesSourcesList
        | Row::VaultFilesSourcesFiles
        | Row::VaultProjectsConfirm
        | Row::VaultWeaveOwnerLinkWrong
        | Row::VaultWeaveOwnerItemWrong
        | Row::VaultWeaveEnqueue
        | Row::VaultWeaveSchedulesList
        | Row::VaultWeaveSchedulesPut
        | Row::VaultWeaveSchedulesClear
        | Row::VaultWeaveSettingChangesList
        | Row::VaultWeaveSettingChangesAnswer
        | Row::VaultWeaveSettingChangesUndo
        | Row::VaultWeaveDigestFeedbackPut
        | Row::VaultWeaveOwnerDigestRender
        | Row::VaultInboxConcernsReview
        | Row::VaultInboxLens
        | Row::VaultInboxGroups
        | Row::VaultBudgetsLeaseOpen
        | Row::VaultBudgetsLease
        | Row::VaultBudgetsLeaseTopUp
        | Row::VaultBudgetsHold
        | Row::VaultBudgetsHoldResume
        | Row::VaultBudgetsLocal
        | Row::VaultBudgetsReservations
        | Row::VaultBudgetsSettlements
        | Row::VaultBudgetsRsiConfigure
        | Row::VaultBudgetsRsi
        | Row::VaultBudgetsRsiTopUp
        | Row::VaultBudgetsRsiHold
        | Row::VaultBudgetsRsiHoldResume
        | Row::VaultRunnersSeatsQuotas
        | Row::VaultRunnersSeatsTopUp
        | Row::VaultRunnersSeatsResume
        | Row::VaultResearchEvaluateSplit
        | Row::VaultResearchCreateChild
        | Row::VaultEvalsInventory
        | Row::VaultEvalsCohortsSetup
        | Row::VaultEvalsAuthorNow
        | Row::VaultEvalsAuthoringResult
        | Row::VaultEvalsFamilies
        | Row::VaultEvalsFamiliesAssign
        | Row::VaultEvalsCases
        | Row::VaultEvalsCasesRecord
        | Row::VaultEvalsCohorts
        | Row::VaultEvalsCohortsOpen
        | Row::VaultEvalsExposure
        | Row::VaultEvalsSufficiency
        | Row::VaultEvalsLabelsBlocked
        | Row::VaultEvalsLabelsPick
        | Row::VaultCoachTrainingOffers
        | Row::VaultCoachTrainingOffersGet
        | Row::VaultCoachTrainingOffersTrigger
        | Row::VaultCoachTrainingOffersResult
        | Row::VaultCoachTrainingOffersAnswer
        | Row::VaultCoachTrainingOffersUndo
        | Row::VaultCoachTrainingOffersCandidates
        | Row::VaultCoachTrainingOffersCandidatesPrepare
        | Row::VaultCoachTrainingOffersPilotsPrepare
        | Row::VaultCoachTrainingOffersPilotsComplete
        | Row::VaultCoachTrainingOffersPilotsGet
        | Row::VaultCoachTrainingOffersSources
        | Row::VaultCodeSymbolsDeclare
        | Row::VaultCodeSymbolsRenew
        | Row::VaultCodeSymbolsRelease
        | Row::VaultCodeProposalSubmit
        | Row::VaultCodeConflictRecord
        | Row::VaultCodeConflictView
        | Row::VaultCodeProposalResolve
        | Row::VaultCodeProposalReview
        | Row::VaultCodeProposalSettle
        | Row::VaultCodeProposalSettlement
        | Row::VaultCodeOplog
        | Row::VaultResultsStatus
        | Row::VaultResultsRecover
        | Row::VaultResultsRead
        | Row::VaultResultsSlice
        | Row::VaultCodeModelHealCount
        | Row::VaultCodeTypeDiagnostics
        | Row::VaultCodeWaitsResolve
        | Row::VaultCodeWaitsReceipt
        | Row::VaultCodeExport
        | Row::VaultCodeImport
        | Row::VaultCodeReposGet
        | Row::VaultCodeForksGet
        | Row::VaultCodeIngressGet
        | Row::VaultCodeOriginRegister
        | Row::VaultCodeOriginMirrorGet
        | Row::VaultCodeOriginMirrorPlan
        | Row::VaultCodeOriginMirrorSet
        | Row::VaultCodeOriginMirrorStrategy
        | Row::VaultCodeOriginMirrorClear
        | Row::VaultCodeOriginMirrorPush
        | Row::VaultCodeOriginAuthorityGet
        | Row::VaultCodeOriginAuthoritySet
        | Row::VaultCodeOriginPublications
        | Row::VaultCodeCheckoutBind
        | Row::VaultArtifactsKeepOutline
        | Row::VaultArtifactsDeclineOutline
        | Row::VaultArtifactsPublishApproval
        | Row::VaultArtifactsPointer
        | Row::VaultArtifactsUnpublish
        | Row::VaultArtifactsLinkToken
        | Row::VaultArtifactsLivePreviewRegister
        | Row::VaultArtifactsLivePreviewClose
        | Row::VaultArtifactsLivePreviewInvite
        | Row::VaultArtifactsLivePreviewRevokeInvite
        | Row::VaultArtifactsLivePreviewShare
        | Row::VaultArtifactsLivePreviewRevokeShare
        | Row::VaultCodeViewsMaterialize
        | Row::VaultCodeViewsGet
        | Row::VaultCodeViewsRead
        | Row::VaultCodeViewsAction
        | Row::VaultCodeViewsBuild
        | Row::VaultCodeCacheGet
        | Row::VaultCodeCacheReuse
        | Row::VaultCodeSnapshotsIngest
        | Row::VaultCodeSnapshotsGet
        | Row::VaultCodeSnapshotsRead
        | Row::VaultCodeSymbolsDefinitions
        | Row::VaultCodeMergeQueueEnqueue
        | Row::VaultCodeMergeQueueStage
        | Row::VaultCodeMergeQueueObserve
        | Row::VaultCodeMergeQueueRequeueSurvivors
        | Row::VaultCodeMergeQueueLandReviewed
        | Row::VaultCodeMergeQueueSettleSlow
        | Row::VaultCodeMergeQueueRecover
        | Row::VaultCodeMergeQueueInit
        | Row::VaultCodeMergeQueueCheck
        | Row::VaultCodeMergeQueueDiagnose
        | Row::VaultCodeMergeQueueCheckStatus
        | Row::VaultCodeChecksGet
        | Row::VaultCodeMergeQueueExportGreen
        | Row::VaultTrustedContactsTierSet
        | Row::VaultOrgAdminConfigure
        | Row::VaultSharedPolicyGet
        | Row::VaultSharedPolicyChange
        | Row::VaultSharedPolicyChanges
        | Row::VaultRootsRequestsCreate
        | Row::VaultRootsRequestsList
        | Row::VaultOwnerWorkGet
        | Row::VaultTasksCommWidenRevoke
        | Row::VaultNotesHistoryPurge
        | Row::VaultNotesHistoryPurgeExecute
        | Row::VaultNotesHistoryPurgeReceipts
        | Row::VaultRunsProgramHoldRelease
        | Row::AiVoiceAsrOpen
        | Row::AiVoiceAsrHypothesis
        | Row::AiVoiceAsrFinalize
        | Row::AiVoiceAsrClose
        | Row::AiVoiceStart
        | Row::AiVoiceAudio
        | Row::AiVoiceEvents
        | Row::AiVoiceAck
        | Row::AiVoiceUsage
        | Row::AiVoiceTool
        | Row::AiVoiceEnd
        | Row::AiVoiceClose
        | Row::VaultSecretsRegister
        | Row::VaultSecretsRotate
        | Row::VaultSecretsRewrap
        | Row::VaultSecretsRevoke
        | Row::VaultSecretsCustodyGet
        | Row::VaultSecretsCustodySubmit
        | Row::VaultCustodyMembersDrainBegin
        | Row::VaultCustodyMembersDrainCommit
        | Row::VaultCustodyMembersDrainFolder
        | Row::VaultCustodyMembersReenrol
        | Row::VaultMessageStreamsRefused => owner_proof(auth, server, verb).map(drop),
        Row::VaultSharedProposeDelete
        | Row::VaultSharedProposeTransfer
        | Row::VaultSharedProposeRemoveOwner
        | Row::VaultSharedExecute
        | Row::VaultSharedReceipt
        | Row::VaultSharedOutcomes
        | Row::VaultMembersDelegate
        | Row::VaultMembersAdd
        | Row::VaultMembersChange
        | Row::VaultMembersRemove
        | Row::VaultMembersLeave
        | Row::VaultMembersInvitations
        | Row::VaultMembersAccept
        | Row::VaultMembersDecline
        | Row::VaultMembersWithdrawInvitation
        | Row::VaultMembersInvitationSlip
        | Row::VaultSharedObject
        | Row::VaultSharedWithdrawObjection
        | Row::VaultSharedStarted
        | Row::VaultSharedMatured
        | Row::VaultSharedEraseAsk
        | Row::VaultSharedEraseAsks
        | Row::VaultSharedCloseEraseAsk
        | Row::VaultRecordsErasePreview
        | Row::VaultRecordsEraseConfirm
        | Row::VaultWorkspaceEstablish
        | Row::VaultWorkspaceMembersOnboard
        | Row::VaultTrustedContactsList
        | Row::VaultTrustedContactsConsent
        | Row::VaultTrustedContactsRevoke
        | Row::VaultSharedPolicyPropose
        | Row::VaultSharedPolicyAnswer => {
            crate::api::facade::shared_act_doors::person(server, auth, verb).map(drop)
        }
        // The voice bank's rows (FIX 4393): a live person on their own proof,
        // owner or not, or a designed voice's creator on its own credential;
        // the bank binds each act to the voice's subject or creator.
        Row::VaultVoicesPacksPut
        | Row::VaultVoicesRenderConsent
        | Row::VaultVoicesTargetsProvision
        | Row::VaultVoicesTargetsEvict
        | Row::VaultVoicesInspect
        | Row::VaultVoicesLineage => {
            crate::api::facade::voice_bank_doors::voice_bank_admits(server, auth, verb)
        }
        // The exact publish rows (FIX 6866): the owner, or a bound principal
        // whose one Grant the engine door admits in its own snapshot.
        Row::VaultCodeOriginPublishRequest
        | Row::VaultCodeOriginPublishReview
        | Row::VaultCodeOriginPublishGet
        | Row::VaultCodeOriginPublishApprove
        | Row::VaultCodeOriginPublishExecute
        | Row::VaultCodeOriginPublishCancel => {
            crate::api::facade::origin_publish_doors::publish_admits(server, auth, verb)
        }
        // The outside import rows (FIX 6871): a bound principal; the engine
        // door admits the owner or the push's own standing.
        Row::VaultCodeImportsCreate | Row::VaultCodeImportsGet => {
            crate::api::facade::code_import_doors::imports_admit(server, auth, verb)
        }
        // The exact export preview rows (FIX 6869, G4 PR3): a live Owner, or a
        // bound principal whose one Grant the engine door admits.
        Row::VaultCodeExportPreview | Row::VaultCodeExportPreviewRead => {
            crate::api::facade::origin_doors::preview_admits(server, auth, verb)
        }
        // The vault's review policy rows (FIX 8268): a live Owner, or a bound
        // principal whose one Grant the engine door admits.
        Row::VaultCodeMergeQueueReviewPolicyGet | Row::VaultCodeMergeQueueReviewPolicySet => {
            crate::api::facade::merge_queue_checker_doors::review_policy_admits(server, auth, verb)
        }
        // A member's own TASK-bound workflow run (FIX 5316): a live person on
        // their own slip, bound to it, as the door acts under.
        Row::VaultWorkflowsDispatchBound => {
            crate::api::facade::agent_definition_doors::member_proof(server, auth, verb).map(drop)
        }
        // The off-record session rows admit their session's manager: the
        // owner, or a person or agent who starts and keeps their own
        // (WILL-PLAN L13 row 03). Each door binds the stretch for them again.
        Row::VaultOffRecordStart
        | Row::VaultOffRecordStatus
        | Row::VaultOffRecordWitness
        | Row::VaultOffRecordDiscard
        | Row::VaultOffRecordRecall
        | Row::VaultOffRecordNotesCreate
        | Row::VaultOffRecordClaimsUpsert
        | Row::SelfOffRecordExecute
        | Row::SelfOffRecordResultsList
        | Row::SelfOffRecordResultsRead
        | Row::SelfOffRecordWaitsGet
        | Row::SelfOffRecordWaitsAnswer => {
            crate::api::facade::off_record_doors::off_record_admits(server, auth, verb)
        }
        Row::VaultOffRecordRoomsStart
        | Row::VaultOffRecordRoomsStatus
        | Row::VaultOffRecordRoomsWitness
        | Row::VaultOffRecordRoomsSave
        | Row::VaultOffRecordRoomsSaveFromHere
        | Row::VaultOffRecordRoomsSuggestSave
        | Row::VaultOffRecordRoomsConfirmSave
        | Row::VaultOffRecordRoomsDeclineSave
        | Row::VaultOffRecordRoomsExport => {
            crate::api::facade::off_record_room_doors::off_record_room_admits(auth, verb)
        }
        Row::VaultGuestsExportEnvelope => {
            crate::api::facade::guest_document_doors::guest_document_reader(server, auth).map(drop)
        }
        Row::ExecuteCode => {
            crate::api::facade::foreign_code_doors::foreign_code_admits(server, auth)
        }
        Row::SelfSavedQueryEvaluate => crate::api::facade::saved_query_doors::admits(server, auth),
        // The access request answer (FIX 1379): the owner, or the person or
        // agent a request asks, on their own proof.
        Row::SelfGrantsAnswer => {
            crate::api::facade::grants_doors::answer_admits(server, auth, verb)
        }
        Row::SelfCredentialAttenuate => {
            crate::api::facade::credential_doors::holder(auth).map(drop)
        }
        Row::VaultArtifactsReviewSlides => slide_reviewer(server, auth).map(drop),
        Row::VaultArtifactsAsk | Row::VaultArtifactsAdmit => artifact_asker(server, auth).map(drop),
        Row::SelfMemoryDiaryQuery => diary_reader(server, auth).map(drop),
        Row::VaultDecisionsAsksAnswer
        | Row::VaultDecisionsAsksClimb
        | Row::SelfDecisionsAsks
        | Row::VaultFanoutResumeAs => {
            crate::api::facade::decision_ask_doors::holder(auth, verb).map(drop)
        }
        Row::VaultRetrievalHydePending
        | Row::VaultRetrievalHydeComplete
        | Row::VaultRetrievalHydeReceipt => {
            crate::api::facade::hyde_doors::hyde_caller(server, auth).map(drop)
        }
        Row::Fetch | Row::Crawl => crate::api::facade::facade_actor(server, auth)
            .map(drop)
            .map_err(crate::api::facade::FacadeApiError::into_memory_error),
        Row::AiVerdict => asking(auth, server).map(drop),
        // The pack setup doors (OF-378) and the pack put: the owner's proof,
        // or an agent acting for the owner (an agent puts `local` alone).
        Row::VaultPacksPut
        | Row::VaultPacksSetupPrepare
        | Row::VaultPacksSetupGet
        | Row::VaultPacksSetupAnswer
        | Row::VaultPacksSetupVerify => super::packs::setup_admits(server, auth, verb),
        Row::AiImage | Row::AiSpeech | Row::AiTranscribe | Row::AiEmbed | Row::AiVideo => {
            owner_grade(auth, MEDIA_OWNERS)
        }
        Row::AiVideoPoll | Row::AiVideoCancel => owner_grade(auth, VIDEO_JOB_OWNERS),
        // The rows that left the owner-only list for a caller's own act
        // (`owner_binding::caller_bound_admits`).
        Row::VaultTrustedContactsName
        | Row::VaultTrustedContactsDialSet
        | Row::VaultTrustedContactsConcernAsks
        | Row::VaultTrustedContactsConcernAuthorize
        | Row::VaultTrustedContactsConcernPropose
        | Row::VaultSkillsOptimizeTradeoffAsks
        | Row::VaultSkillsOptimizeTradeoffAsksPick
        | Row::VaultSkillsFork
        | Row::VaultGatePolicyPut
        | Row::VaultArtifactsPublish
        | Row::VaultArtifactsRepoint
        | Row::VaultUsageEventsUndecodable
        | Row::VaultUsageEventsRemoveUndecodable
        | Row::VaultUsageRepairReceipts => {
            crate::api::facade::owner_binding::caller_bound_admits(server, auth, verb)
                .unwrap_or(Ok(()))
        }
    }
}
