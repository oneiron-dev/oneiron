//! The owner preflight every host door's verb meets before its door runs.
//! `door_admits` is its call surface.
//! Each door's own facade module defines the proof it admits on; this match only routes to it.
//! The generated `HostDoorRow` names every host door, so the match has no catch-all arm and a
//! new host door fails to compile until it is placed in one (FIX 1763).

use oneiron::memory::MemoryResult;

use super::super::host_door_rows::HostDoorRow as Row;
use super::support::{
    MEDIA_OWNERS, VIDEO_JOB_OWNERS, artifact_asker, asking, diary_reader, owner_grade, owner_proof,
    slide_reviewer,
};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

#[macro_use]
mod owner_proof_rows;

/// The authority check host-door row `verb`'s own door runs first: the
/// owner's proof, a person's proof, a bound principal or an owner-grade
/// credential. The facade runs it before the row's pre chain, so a hook
/// never fires on a call the door refuses; the door runs it again for the
/// proof it acts under. A host door whose door has no such check passes
/// in its own arm, and so does any row that is no host door.
pub(in crate::api::facade) fn door_admits(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<()> {
    // Every host door is placed in one arm below (FIX 1763).
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
        owner_proof_rows!() => owner_proof(auth, server, verb).map(drop),
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
        // The host doors whose door checks no caller before the row's hooks:
        // they pass. A new host door is placed here or beside its check.
        Row::SelfFocusWakes
        | Row::VaultShapeApply
        | Row::VaultShapeGroups
        | Row::VaultShapeGroupsResolve
        | Row::TasksWave
        | Row::VaultFanoutSpawn
        | Row::VaultBudgetsResidentShares
        | Row::VaultBudgetsResidentSharesSet
        | Row::VaultClusterPropose
        | Row::VaultClusterMerge
        | Row::VaultClusterSplit
        | Row::VaultClusterResolveProposal
        | Row::VaultExportTransferRead
        | Row::VaultExportTransferRelease
        | Row::SelfActor
        | Row::VaultExplainMemory
        | Row::VaultExplainGate
        | Row::VaultCampaignStageEvidence
        | Row::VaultWeaveDigest
        | Row::VaultWeaveLens
        | Row::VaultWeaveLinkWrong
        | Row::VaultWeaveItemWrong
        | Row::VaultInboxGroupsResolve
        | Row::VaultSkillsOptimizeTradeoffAsksResolve
        | Row::VaultPacksSectionsPropose
        | Row::VaultPacksSectionsList
        | Row::VaultPacksSectionsSuggest
        | Row::AiChatCompletions
        | Row::VaultConnectorsSlatesNarrow
        | Row::VaultOutboxDivergedList
        | Row::VaultOutboxDivergedAnswer
        | Row::VaultSharedDeletion
        | Row::VaultOrgAdminPowers
        | Row::VaultTrustedContactsConcernDeliver
        | Row::VaultRootsRequestsCancel
        | Row::VaultPolicyOutboundDecide
        | Row::VaultPolicyRelayDecide
        | Row::VaultSecretsLiftHistory
        | Row::VaultSettingsInferenceDefaults
        | Row::VaultSettingsInferenceDefaultsReplace
        | Row::VaultLensesSelect
        | Row::VaultLensesResolve
        | Row::VaultLensesResultSetAction
        | Row::VaultLensesDefault
        | Row::SelfUse
        | Row::SelfSecretsMaterialize
        | Row::SelfSecretsRenew
        | Row::SelfSecretsTeardown
        | Row::SelfSecretsUse
        | Row::VaultSharesRevoke
        | Row::VaultSharesView
        | Row::VaultArtifactsLivePreviewRead
        | Row::VaultCodeCheckoutClaim
        | Row::VaultCodeCheckoutGet
        | Row::VaultCodeCheckoutRenew
        | Row::VaultCodeCheckoutReclaim
        | Row::VaultCodeCheckoutTakeover
        | Row::VaultCodeCheckoutPublish
        | Row::VaultCodeCheckoutSettle
        | Row::VaultCodeCheckoutTeardown
        | Row::VaultConnectorsReadGrantsGrant
        | Row::VaultConnectorsReadGrantsRevoke
        | Row::VaultRepoSnapshotsGet
        | Row::VaultRepoSnapshotsRead
        | Row::VaultRepoSymbolsDefinitions
        | Row::VaultRepoViewsGet
        | Row::VaultRepoViewsRead
        | Row::VaultRepoMergeQueueObserve
        | Row::VaultRepoSnapshotsIngest
        | Row::VaultRepoWorkOpen
        | Row::VaultRepoSymbolsDeclare
        | Row::VaultRepoSymbolsRenew
        | Row::VaultRepoSymbolsRelease
        | Row::VaultRepoProposalSubmit
        | Row::VaultRepoMergeQueueEnqueue
        | Row::VaultRepoCheckoutBind
        | Row::VaultRepoExport
        | Row::VaultCriticReview
        | Row::VaultMessagesReact
        | Row::VaultSettingsWebConnector
        | Row::VaultSettingsWebConnectorReplace
        | Row::VaultConnectorsWebUsage
        | Row::AiAnonymousChat
        | Row::VaultModelsTrialsResendArm
        | Row::AiOptions
        | Row::AiAskImage
        | Row::VaultGraphAsk
        | Row::VaultGraphAdmit
        | Row::VaultQuestionsCreate
        | Row::VaultQuestionsEdit
        | Row::VaultQuestionsPause
        | Row::VaultQuestionsBackfill
        | Row::VaultQuestionsRead
        | Row::VaultQuestionsOutcomeWindows
        | Row::VaultQuestionsAnswers
        | Row::VaultQuestionsRefresh
        | Row::VaultQuestionsOutcomes
        | Row::VaultQuestionsOutcomesProject
        | Row::VaultQuestionsSchedule
        | Row::VaultDecisionsAsksConfirmGrant
        | Row::ConnectorCall
        | Row::VaultConversationsTurnsCreate
        | Row::VaultConversationsRecordsAppend
        | Row::VaultBatch
        | Row::VaultArtifactsBodyDeckPreview
        | Row::VaultTurnProgramsAdmission
        | Row::VaultRunsProgram
        | Row::VaultRunsProgramStep
        | Row::VaultRunsProgramCheckpoint
        | Row::VaultFreeTimePolicySetAs
        | Row::VaultChannelIdentitiesSelectionUpdate
        | Row::VaultSummariesCreate
        | Row::VaultSummariesKeep
        | Row::VaultSummariesEdit
        | Row::VaultSummariesPatch
        | Row::VaultSummariesRegenerate
        | Row::VaultSummariesProposalsMerge
        | Row::VaultSummariesProposalsSwitch
        | Row::VaultSummariesProposalsReject
        | Row::VaultNotesFollowCitation
        | Row::VaultNotesEditorBind
        | Row::VaultNotesEditorClose
        | Row::VaultTasksLinearMappingEdit
        | Row::SelfRunAttach
        | Row::SelfFoldsDescribe
        | Row::SelfHistory
        | Row::ConnectorAnswer
        | Row::SelfBrowserOpen
        | Row::SelfBrowserObserve
        | Row::SelfBrowserFind
        | Row::SelfBrowserClick
        | Row::SelfBrowserClickAt
        | Row::SelfBrowserType
        | Row::SelfBrowserSelect
        | Row::SelfBrowserWaitFor
        | Row::SelfBrowserExpect
        | Row::SelfBrowserScreenshot
        | Row::SelfBrowserView
        | Row::SelfBrowserCrop
        | Row::SelfBrowserZoom
        | Row::SelfBrowserBatch
        | Row::SelfBrowserLibraryFind
        | Row::SelfBrowserLibraryDraft
        | Row::SelfBrowserDemonstrationStart
        | Row::SelfBrowserDemonstrationStop
        | Row::SelfBrowserLibraryPropose
        | Row::SelfBrowserLibraryRetire
        | Row::SelfBrowserLibraryRetired
        | Row::SelfBrowserLibraryRun
        | Row::SelfBrowserHandover
        | Row::SelfBrowserSwitchEngine
        | Row::VaultClaimsSupersede
        | Row::SelfFold
        | Row::SelfCompact
        | Row::SelfUnfold
        | Row::SelfFolds
        | Row::TasksRefuse
        | Row::SelfReportBlocked
        | Row::SelfAgentsSpawn
        | Row::SelfLeaderSplit
        | Row::SelfSkillsCall
        | Row::SelfFocusRefresh
        | Row::SelfFocusSubscribe
        | Row::SelfFocusUnsubscribe => Ok(()),
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
