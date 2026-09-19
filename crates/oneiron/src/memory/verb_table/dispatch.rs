//! Typed adapters for signatures that borrow or take more than one argument.
use super::super::caps::{
    check_batch_len, check_claim_input, check_limit, check_payload_bytes, check_query,
    check_witness_turn,
};
use super::super::support::resolve_entity_ref;
use super::*;
use crate::note::TakeTarget;
use crate::temporal::TimeRange;

pub(super) fn witness(memory: &Memory<'_>, body: WitnessTurn) -> MemoryResult<WitnessReceipt> {
    let turn = body;
    check_witness_turn(&turn)?;
    memory.witness(&turn)
}

pub(super) fn commit(memory: &Memory<'_>, body: CommitRequest) -> MemoryResult<Vec<CommitReceipt>> {
    check_batch_len("claims", body.claims.len())?;
    for claim in &body.claims {
        check_claim_input(claim)?;
    }
    memory.commit(&body.claims)
}

pub(super) fn claim_upsert(memory: &Memory<'_>, body: ClaimInput) -> MemoryResult<CommitReceipt> {
    let claim = body;
    check_claim_input(&claim)?;
    memory.claim_upsert(&claim)
}

pub(super) fn remember(memory: &Memory<'_>, body: ClaimInput) -> MemoryResult<CommitReceipt> {
    let claim = body;
    check_claim_input(&claim)?;
    memory.remember(&claim)
}

pub(super) fn claim_retract(
    memory: &Memory<'_>,
    body: ClaimRefRequest,
) -> MemoryResult<CommitReceipt> {
    memory.claim_retract(&body.claim_ref)
}

pub(super) fn forget(
    memory: &Memory<'_>,
    body: ForgetSelector,
) -> MemoryResult<Vec<CommitReceipt>> {
    let selector = body;
    memory.forget(&selector)
}

pub(super) fn claim_list(
    memory: &Memory<'_>,
    body: ClaimListFilter,
) -> MemoryResult<Vec<ClaimView>> {
    let filter = body;
    check_limit(filter.limit)?;
    memory.claim_list(&filter)
}

pub(super) fn claim_history(
    memory: &Memory<'_>,
    body: ClaimRefRequest,
) -> MemoryResult<Vec<ClaimView>> {
    memory.claim_history(&body.claim_ref)
}

pub(super) fn safe_delete(
    memory: &Memory<'_>,
    body: SafeDeleteRequest,
) -> MemoryResult<DeleteReceipt> {
    memory.safe_delete(&body.entity_ref, body.reason)
}

pub(super) fn pending_writes(
    memory: &Memory<'_>,
    body: LimitRequest,
) -> MemoryResult<Vec<PendingWrite>> {
    check_limit(body.limit)?;
    memory.pending_writes(body.limit)
}

pub(super) fn receipts(
    memory: &Memory<'_>,
    body: LimitRequest,
) -> MemoryResult<Vec<MemoryReceipt>> {
    check_limit(body.limit)?;
    memory.receipts(body.limit)
}

pub(super) fn hydrate(memory: &Memory<'_>, body: HydrateRequest) -> MemoryResult<Vec<EntityView>> {
    check_batch_len("refs", body.refs.len())?;
    memory.hydrate(&body.refs)
}

pub(super) fn get_entity(
    memory: &Memory<'_>,
    body: EntityRefRequest,
) -> MemoryResult<Option<EntityView>> {
    memory.get_entity(&body.entity_ref)
}

pub(super) fn query_bm25(memory: &Memory<'_>, body: QueryRequest) -> MemoryResult<Vec<LexicalHit>> {
    check_query(&body.query)?;
    check_limit(body.limit)?;
    memory.query_bm25(&body.query, body.limit)
}

pub(super) fn neighbors(
    memory: &Memory<'_>,
    body: NeighborsRequest,
) -> MemoryResult<Vec<NeighborHit>> {
    check_limit(body.opts.limit)?;
    memory.neighbors(&body.entity_ref, &body.opts)
}

pub(super) fn recall_view(
    memory: &Memory<'_>,
    body: RecallViewRequest,
) -> MemoryResult<MemoryPack> {
    check_query(&body.query)?;
    check_limit(body.limit)?;
    memory.recall_view(
        &body.query,
        &body.scope,
        body.kind.as_deref(),
        body.predicate.as_deref(),
        body.limit,
    )
}

pub(super) fn recall(memory: &Memory<'_>, body: RecallRequestDto) -> MemoryResult<MemoryPack> {
    check_query(&body.query)?;
    let limit = body.limit.unwrap_or(10);
    check_limit(limit)?;
    memory.recall(
        &body.query,
        body.effort.unwrap_or(Effort::Standard),
        &body.scope.unwrap_or_default(),
        limit,
        body.format.as_deref(),
        None,
    )
}

pub(super) fn put_structural(
    memory: &Memory<'_>,
    body: StructuralPutInput,
) -> MemoryResult<EntityRefReceipt> {
    let input = body;
    check_payload_bytes(
        "structural body",
        serde_json::to_vec(&input.body)
            .map(|bytes| bytes.len())
            .unwrap_or(0),
    )?;
    memory.put_structural(&input)
}

pub(super) fn put_habit_checkin(
    memory: &Memory<'_>,
    body: HabitCheckinInput,
) -> MemoryResult<EntityRefReceipt> {
    let input = body;
    memory.put_habit_checkin(&input)
}

pub(super) fn put_companion_record(
    memory: &Memory<'_>,
    body: CompanionRecordInput,
) -> MemoryResult<EntityRefReceipt> {
    let input = body;
    memory.put_companion_record(&input)
}

pub(super) fn admit_imported_claim(
    memory: &Memory<'_>,
    body: AdmitImportedClaimInput,
) -> MemoryResult<CommitReceipt> {
    let input = body;
    memory.admit_imported_claim(&input)
}

pub(super) fn put_blob_artifact(
    memory: &Memory<'_>,
    body: BlobArtifactInput,
) -> MemoryResult<EntityRefReceipt> {
    let input = body;
    memory.put_blob_artifact(&input)
}

pub(super) fn append_blob_version(
    memory: &Memory<'_>,
    body: AppendBlobVersionRequest,
) -> MemoryResult<BlobVersionView> {
    use base64::Engine as _;

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(body.content_base64.as_bytes())
        .map_err(|_| {
            MemoryError::bad_request_with(
                "blob content is not valid base64",
                &["Send the raw version bytes base64-encoded."],
            )
        })?;
    memory.append_blob_version(
        &body.artifact_ref,
        &bytes,
        body.run_ref.as_deref(),
        body.occurred_at,
        body.learned_at,
    )
}

pub(super) fn read_blob_version(
    memory: &Memory<'_>,
    body: ReadBlobVersionRequest,
) -> MemoryResult<BlobBytesResponse> {
    use base64::Engine as _;
    let bytes = memory.read_blob_version(&body.artifact_ref, body.version)?;
    Ok(BlobBytesResponse {
        content_base64: bytes.map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes)),
    })
}

pub(super) fn author_take(
    memory: &Memory<'_>,
    body: AuthorTakeRequest,
) -> MemoryResult<EntityRefReceipt> {
    check_payload_bytes("take markdown", body.markdown.len())?;
    let target_id = resolve_entity_ref(memory.vault(), &body.target_ref)?;
    let target = match body.target_kind.as_str() {
        "subject" => TakeTarget::Subject(target_id),
        "claim" => TakeTarget::Claim(target_id),
        other => {
            return Err(MemoryError::bad_request_with(
                format!("unknown take target kind {other:?}"),
                &["Use one of: subject, claim."],
            ));
        }
    };
    memory.author_take(target, body.markdown)
}

pub(super) fn schedule_outbound(
    memory: &Memory<'_>,
    body: ScheduleOutboundRequest,
) -> MemoryResult<OutboundIntentReceipt> {
    let context = body.context.unwrap_or_default().into_engine()?;
    memory.schedule_outbound_with_context(&body.draft, &context)
}

pub(super) fn calendar_read(
    memory: &Memory<'_>,
    body: CalendarReadRequest,
) -> MemoryResult<Option<CalendarEventView>> {
    let req = body;
    memory.calendar_read(&req)
}

pub(super) fn calendar_search(
    memory: &Memory<'_>,
    body: CalendarSearchRequest,
) -> MemoryResult<Vec<CalendarEventView>> {
    let req = body;
    memory.calendar_search(&req)
}

pub(super) fn calendar_freebusy(
    memory: &Memory<'_>,
    body: CalendarFreebusyRequest,
) -> MemoryResult<CalendarFreebusyDto> {
    memory.calendar_freebusy(
        &body.calendars,
        TimeRange {
            start: body.start,
            end: body.end,
        },
    )
}

pub(super) fn calendar_invite(
    memory: &Memory<'_>,
    body: CalendarInviteSurfaceInput,
) -> MemoryResult<OutboundIntentReceipt> {
    let input = body;
    memory.calendar_invite(&input)
}

pub(super) fn enqueue_consolidation(
    memory: &Memory<'_>,
    body: ConsolidationAttemptInput,
) -> MemoryResult<DreamerAttemptRef> {
    let input = body;
    memory.enqueue_consolidation(&input)
}

pub(super) fn dreamer_attempt_status(
    memory: &Memory<'_>,
    body: JobRefRequest,
) -> MemoryResult<Option<DreamerAttemptView>> {
    memory.dreamer_attempt_status(&body.job_ref)
}

pub(super) fn seed_claims(
    memory: &Memory<'_>,
    body: CommitRequest,
) -> MemoryResult<Vec<CommitReceipt>> {
    check_batch_len("claims", body.claims.len())?;
    for claim in &body.claims {
        check_claim_input(claim)?;
    }
    memory.seed_claims(&body.claims)
}

pub(super) fn ask(memory: &Memory<'_>, body: AskRequest) -> MemoryResult<ChatResponse> {
    memory.ask(&body)
}

pub(super) fn search(memory: &Memory<'_>, body: SearchRequest) -> MemoryResult<Vec<SearchHit>> {
    memory.search(&body)
}

pub(super) fn execute(memory: &Memory<'_>, body: ExecuteRequest) -> MemoryResult<ExecuteResponse> {
    memory.execute(&body)
}

pub(super) fn grant_artifact_publish(
    memory: &Memory<'_>,
    body: GrantArtifactPublishRequest,
) -> MemoryResult<GrantArtifactPublishResponse> {
    let grantee = resolve_entity_ref(memory.vault(), &body.grantee_ref)?;
    let id = memory.grant_artifact_publish(&body.artifact, grantee, body.now)?;
    Ok(GrantArtifactPublishResponse {
        grant_ref: id.to_hex(),
    })
}

pub(super) fn approve_gmail_message(
    memory: &Memory<'_>,
    body: ApproveGmailMessageRequest,
) -> MemoryResult<UnitResponse> {
    let identity = resolve_entity_ref(memory.vault(), &body.identity_ref)?;
    memory.approve_gmail_message(&body.intent_ref, identity, &body.message)?;
    Ok(UnitResponse { ok: true })
}

pub(super) fn record_emergency_instruction(
    memory: &Memory<'_>,
    body: EmergencyInstructionInput,
) -> MemoryResult<crate::booking::emergency_reschedule::OwnerInstructionRecord> {
    let input = body;
    memory.record_emergency_instruction(&input)
}

pub(super) fn query(
    memory: &Memory<'_>,
    body: CoreQueryRequest,
) -> MemoryResult<CoreQueryResponse> {
    memory.query_plan(&body)
}

pub(super) fn context_pack(
    memory: &Memory<'_>,
    body: CoreContextPackRequest,
) -> MemoryResult<CoreContextPackResponse> {
    memory.context_pack_plan(&body)
}

pub(super) fn campaign_create(
    memory: &Memory<'_>,
    body: CampaignCreateRequest,
) -> MemoryResult<CampaignRecordDto> {
    super::domains::call(
        memory,
        crate::campaign::surface::CampaignSurfaceVerb::CampaignCreate,
        &body,
    )
}

pub(super) fn campaign_read(
    memory: &Memory<'_>,
    body: CampaignRefRequest,
) -> MemoryResult<RecordLookup<CampaignRecordDto>> {
    super::domains::call(
        memory,
        crate::campaign::surface::CampaignSurfaceVerb::CampaignRead,
        &body,
    )
}

pub(super) fn campaign_update(
    memory: &Memory<'_>,
    body: CampaignUpdateRequest,
) -> MemoryResult<CampaignRecordDto> {
    super::domains::call(
        memory,
        crate::campaign::surface::CampaignSurfaceVerb::CampaignUpdate,
        &body,
    )
}

pub(super) fn campaign_archive(
    memory: &Memory<'_>,
    body: CampaignArchiveRequest,
) -> MemoryResult<CampaignRecordDto> {
    super::domains::call(
        memory,
        crate::campaign::surface::CampaignSurfaceVerb::CampaignArchive,
        &body,
    )
}

pub(super) fn campaign_members(
    memory: &Memory<'_>,
    body: CampaignMembersRequest,
) -> MemoryResult<MembershipPageDto> {
    super::domains::call(
        memory,
        crate::campaign::surface::CampaignSurfaceVerb::CampaignMembers,
        &body,
    )
}

pub(super) fn saved_query_create(
    memory: &Memory<'_>,
    body: SavedQueryCreateRequest,
) -> MemoryResult<SavedQueryRecordDto> {
    super::domains::call(
        memory,
        crate::campaign::surface::CampaignSurfaceVerb::SavedQueryCreate,
        &body,
    )
}

pub(super) fn saved_query_read(
    memory: &Memory<'_>,
    body: SavedQueryRefRequest,
) -> MemoryResult<RecordLookup<SavedQueryRecordDto>> {
    super::domains::call(
        memory,
        crate::campaign::surface::CampaignSurfaceVerb::SavedQueryRead,
        &body,
    )
}

pub(super) fn saved_query_update(
    memory: &Memory<'_>,
    body: SavedQueryUpdateRequest,
) -> MemoryResult<SavedQueryRecordDto> {
    super::domains::call(
        memory,
        crate::campaign::surface::CampaignSurfaceVerb::SavedQueryUpdate,
        &body,
    )
}

pub(super) fn saved_query_archive(
    memory: &Memory<'_>,
    body: SavedQueryArchiveRequest,
) -> MemoryResult<SavedQueryRecordDto> {
    super::domains::call(
        memory,
        crate::campaign::surface::CampaignSurfaceVerb::SavedQueryArchive,
        &body,
    )
}

pub(super) fn saved_query_members(
    memory: &Memory<'_>,
    body: SavedQueryMembersRequest,
) -> MemoryResult<MembershipPageDto> {
    super::domains::call(
        memory,
        crate::campaign::surface::CampaignSurfaceVerb::SavedQueryMembers,
        &body,
    )
}

pub(super) fn set_expression_preference(
    memory: &Memory<'_>,
    body: SetExpressionPreferenceRequest,
) -> MemoryResult<ExpressionPreferenceReceiptDto> {
    super::expression::set(memory, body)
}

pub(super) fn retract_expression_preference(
    memory: &Memory<'_>,
    body: ClaimRefRequest,
) -> MemoryResult<UnitResponse> {
    super::expression::retract(memory, body)
}

pub(super) fn expression_preferences(
    memory: &Memory<'_>,
    body: ExpressionPreferencesRequest,
) -> MemoryResult<ExpressionPreferenceViewDto> {
    super::expression::read(memory, body)
}

pub(super) fn plan_emergency_reschedule(
    memory: &Memory<'_>,
    body: PlanEmergencyRescheduleRequest,
) -> MemoryResult<EmergencyBatchPlanDto> {
    let calendars = body
        .calendars
        .into_iter()
        .map(|(owner, calendars)| Ok((resolve_entity_ref(memory.vault(), &owner)?, calendars)))
        .collect::<MemoryResult<Vec<_>>>()?;
    let result = memory.plan_emergency_reschedule(&body.request, &calendars, body.now_utc)?;
    Ok(EmergencyBatchPlanDto {
        plans: result.plans,
        refusals: result
            .refusals
            .into_iter()
            .map(|(id, reason)| (id.to_hex(), reason))
            .collect(),
    })
}

pub(super) fn schedule_outbound_with_context(
    memory: &Memory<'_>,
    body: ScheduleOutboundRequest,
) -> MemoryResult<OutboundIntentReceipt> {
    schedule_outbound(memory, body)
}

pub(super) fn react_to_message(
    memory: &Memory<'_>,
    body: ReactToMessageInput,
) -> MemoryResult<ReactionReceipt> {
    memory.react_to_message(body)
}
pub(super) fn reaction_pills(
    memory: &Memory<'_>,
    body: ReactionPillsRequest,
) -> MemoryResult<Vec<crate::conversation::reaction::ReactionGrouping>> {
    memory.reaction_pills(&body.message_refs, body.viewer_ref)
}
pub(super) fn reactions_since(
    memory: &Memory<'_>,
    body: ReactionsSinceRequest,
) -> MemoryResult<Vec<crate::conversation::reaction::ReactionSignal>> {
    memory.reactions_since(body.person_ref, body.since)
}
pub(super) fn reactions_outbound(
    memory: &Memory<'_>,
    body: EntityRefRequest,
) -> MemoryResult<crate::conversation::reaction::ReactionsOutbound> {
    memory.reactions_outbound(&body.entity_ref)
}
pub(super) fn ingest_mirrored_reaction(
    memory: &Memory<'_>,
    body: MirroredReactionRequest,
) -> MemoryResult<ReactionReceipt> {
    memory.ingest_mirrored_reaction(
        &body.message_ref,
        &body.by_ref,
        &body.glyph,
        body.at,
        body.ext,
    )
}

pub(super) fn artifact_birth(
    memory: &Memory<'_>,
    body: EntityRefRequest,
) -> MemoryResult<Option<ArtifactBirthView>> {
    memory.artifact_birth(&body.entity_ref)
}
pub(super) fn artifacts_born_from(
    memory: &Memory<'_>,
    body: ArtifactsBornFromRequest,
) -> MemoryResult<Vec<ArtifactBirthView>> {
    check_limit(body.limit)?;
    memory.artifacts_born_from(&body.trigger_kind, &body.trigger_ref, body.limit)
}
