// The single typed SDK verb declaration. Included by engine and bindings.
facade_verb_table! {
    Witness => {
        method: witness, wire: "witness", sdk: "witness", scope: Write,
        request: WitnessTurn, response: WitnessReceipt,
        doc: "Witnesses one conversational turn.",
    }
    Commit => {
        method: commit, wire: "commit", sdk: "commit", scope: Write,
        request: CommitRequest, response: Vec<CommitReceipt>,
        doc: "Commits claims, one individually gated write per element.",
    }
    ClaimUpsert => {
        method: claim_upsert, wire: "claim_upsert", sdk: "claimUpsert", scope: Write,
        request: ClaimInput, response: CommitReceipt,
        doc: "Upserts one claim with single-cardinality auto-supersede.",
    }
    Remember => {
        method: remember, wire: "remember", sdk: "remember", scope: Write,
        request: ClaimInput, response: CommitReceipt,
        doc: "Typed remember: claimUpsert with auto-supersede.",
    }
    ClaimRetract => {
        method: claim_retract, wire: "claim_retract", sdk: "claimRetract", scope: Write,
        request: ClaimRefRequest, response: CommitReceipt,
        doc: "Retracts an active claim by ref.",
    }
    Forget => {
        method: forget, wire: "forget", sdk: "forget", scope: Write,
        request: ForgetSelector, response: Vec<CommitReceipt>,
        doc: "Typed forget: retract-with-receipt by short ref or subject+predicate.",
    }
    ClaimList => {
        method: claim_list, wire: "claim_list", sdk: "claimList", scope: Read,
        request: ClaimListFilter, response: Vec<ClaimView>,
        doc: "Lists claims by subject/predicate/lifecycle, bounded by limit.",
    }
    ClaimHistory => {
        method: claim_history, wire: "claim_history", sdk: "claimHistory", scope: Read,
        request: ClaimRefRequest, response: Vec<ClaimView>,
        doc: "Supersession timeline for one claim, oldest first.",
    }
    SafeDelete => {
        method: safe_delete, wire: "safe_delete", sdk: "safeDelete", scope: Write,
        request: SafeDeleteRequest, response: DeleteReceipt,
        doc: "Deletes an entity under a named reason, with a receipt.",
    }
    PendingWrites => {
        method: pending_writes, wire: "pending_writes", sdk: "pendingWrites", scope: Read,
        request: LimitRequest, response: Vec<PendingWrite>,
        doc: "Pending gated writes awaiting consent.",
    }
    Receipts => {
        method: receipts, wire: "receipts", sdk: "receipts", scope: Read,
        request: LimitRequest, response: Vec<MemoryReceipt>,
        doc: "Gate decision receipts, newest first.",
    }
    Hydrate => {
        method: hydrate, wire: "hydrate", sdk: "hydrate", scope: Read,
        request: HydrateRequest, response: Vec<EntityView>,
        doc: "Reads entities as typed views.",
    }
    GetEntity => {
        method: get_entity, wire: "get_entity", sdk: "getEntity", scope: Read,
        request: EntityRefRequest, response: Option<EntityView>,
        doc: "Reads one entity as a typed view.",
    }
    QueryBm25 => {
        method: query_bm25, wire: "query_bm25", sdk: "queryBm25", scope: Read,
        request: QueryRequest, response: Vec<LexicalHit>,
        doc: "BM25 text search, engine-scored.",
    }
    Neighbors => {
        method: neighbors, wire: "neighbors", sdk: "neighbors", scope: Read,
        request: NeighborsRequest, response: Vec<NeighborHit>,
        doc: "Bounded graph neighborhood of one entity.",
    }
    RecallView => {
        method: recall_view, wire: "recall_view", sdk: "recallView", scope: Read,
        request: RecallViewRequest, response: MemoryPack,
        doc: "Minimal recall for an exact-world view, with kind/predicate narrowing.",
    }
    Recall => {
        method: recall, wire: "recall", sdk: "recall", scope: Read,
        request: RecallRequestDto, response: MemoryPack,
        doc: "Effort-dialed retrieval into a memory pack.",
    }
    PutStructural => {
        method: put_structural, wire: "put_structural", sdk: "putStructural", scope: Write,
        request: StructuralPutInput, response: EntityRefReceipt,
        doc: "Structural create carrying text-index fields and edges.",
    }
    PutHabitCheckin => {
        method: put_habit_checkin, wire: "put_habit_checkin", sdk: "putHabitCheckin", scope: Write,
        request: HabitCheckinInput, response: EntityRefReceipt,
        doc: "Appends one habit check-in child.",
    }
    PutCompanionRecord => {
        method: put_companion_record, wire: "put_companion_record", sdk: "putCompanionRecord", scope: Write,
        request: CompanionRecordInput, response: EntityRefReceipt,
        doc: "Registers a companion persona record.",
    }
    AdmitImportedClaim => {
        method: admit_imported_claim, wire: "admit_imported_claim", sdk: "admitImportedClaim", scope: Write,
        request: AdmitImportedClaimInput, response: CommitReceipt,
        doc: "Admits one imported-evidence claim (typed receipt).",
    }
    PutBlobArtifact => {
        method: put_blob_artifact, wire: "put_blob_artifact", sdk: "putBlobArtifact", scope: Write,
        request: BlobArtifactInput, response: EntityRefReceipt,
        doc: "Registers one blob artifact.",
    }
    AppendBlobVersion => {
        method: append_blob_version, wire: "append_blob_version", sdk: "appendBlobVersion", scope: Write,
        request: AppendBlobVersionRequest, response: BlobVersionView,
        doc: "Appends one blob artifact version (base64 bytes).",
    }
    ReadBlobVersion => {
        method: read_blob_version, wire: "read_blob_version", sdk: "readBlobVersion", scope: Read,
        request: ReadBlobVersionRequest, response: BlobBytesResponse,
        doc: "Reads one blob artifact version (base64 bytes).",
    }
    AuthorTake => {
        method: author_take, wire: "author_take", sdk: "authorTake", scope: Write,
        request: AuthorTakeRequest, response: EntityRefReceipt,
        doc: "Appends one attributed opinion-take note beside a target.",
    }
    ScheduleOutbound => {
        method: schedule_outbound, wire: "schedule_outbound", sdk: "scheduleOutbound", scope: Write,
        request: ScheduleOutboundRequest, response: OutboundIntentReceipt,
        doc: "Schedules one connector-send task through the OF-327 chokepoint.",
    }
    CalendarRead => {
        method: calendar_read, wire: "calendar_read", sdk: "calendarRead", scope: Read,
        request: CalendarReadRequest, response: Option<CalendarEventView>,
        doc: "Reads one calendar event under the caller read scope.",
    }
    CalendarSearch => {
        method: calendar_search, wire: "calendar_search", sdk: "calendarSearch", scope: Read,
        request: CalendarSearchRequest, response: Vec<CalendarEventView>,
        doc: "Searches calendar events under the caller read scope.",
    }
    CalendarFreebusy => {
        method: calendar_freebusy, wire: "calendar_freebusy", sdk: "calendarFreebusy", scope: Read,
        request: CalendarFreebusyRequest, response: CalendarFreebusyDto,
        doc: "Busy-only occupancy over a range, source-redacted.",
    }
    CalendarInvite => {
        method: calendar_invite, wire: "calendar_invite", sdk: "calendarInvite", scope: Write,
        request: CalendarInviteSurfaceInput, response: OutboundIntentReceipt,
        doc: "Schedules one iMIP-shaped calendar invite through the outbound gate.",
    }
    EnqueueConsolidation => {
        method: enqueue_consolidation, wire: "enqueue_consolidation", sdk: "enqueueConsolidation", scope: Write,
        request: ConsolidationAttemptInput, response: DreamerAttemptRef,
        doc: "Enqueues one Dreamer consolidation attempt.",
    }
    DreamerAttemptStatus => {
        method: dreamer_attempt_status, wire: "dreamer_attempt_status", sdk: "dreamerAttemptStatus", scope: Read,
        request: JobRefRequest, response: Option<DreamerAttemptView>,
        doc: "Poll-model view of one Dreamer attempt.",
    }
    SeedClaims => {
        method: seed_claims, wire: "seed_claims", sdk: "seedClaims", scope: Write,
        request: CommitRequest, response: Vec<CommitReceipt>,
        doc: "Seeds claims as proposed writes.",
    }
    Ask => {
        method: ask, wire: "ask", sdk: "ask", scope: Read,
        request: AskRequest, response: ChatResponse,
        doc: "Extractive minimal-depth answer over ranked recall (no composer).",
    }
    Search => {
        method: search, wire: "search", sdk: "search", scope: Read,
        request: SearchRequest, response: Vec<SearchHit>,
        doc: "Typed SDK stub-documentation search over this verb table.",
    }
    Execute => {
        method: execute, wire: "execute", sdk: "execute", scope: Read,
        request: ExecuteRequest, response: ExecuteResponse,
        doc: "Evaluates a bounded typed read program in one host call.",
    }
    GrantArtifactPublish => {
        method: grant_artifact_publish, wire: "grant_artifact_publish", sdk: "grantArtifactPublish", scope: Write,
        request: GrantArtifactPublishRequest, response: GrantArtifactPublishResponse,
        doc: "Grants an actor auto-publish on one artifact.",
    }
    ApproveGmailMessage => {
        method: approve_gmail_message, wire: "approve_gmail_message", sdk: "approveGmailMessage", scope: Write,
        request: ApproveGmailMessageRequest, response: UnitResponse,
        doc: "Records one human per-message approval for a delegated Gmail send.",
    }
    RecordEmergencyInstruction => {
        method: record_emergency_instruction, wire: "record_emergency_instruction", sdk: "recordEmergencyInstruction", scope: Write,
        request: EmergencyInstructionInput, response: crate::booking::emergency_reschedule::OwnerInstructionRecord,
        doc: "Logs the lane-owned emergency stamp under the owner-verb checks.",
    }
    Query => {
        method: query, wire: "query", sdk: "query", scope: Read,
        request: CoreQueryRequest, response: CoreQueryResponse,
        doc: "Executes one actor-scoped query plan.",
    }
    ContextPack => {
        method: context_pack, wire: "context_pack", sdk: "contextPack", scope: Read,
        request: CoreContextPackRequest, response: CoreContextPackResponse,
        doc: "Executes one actor-scoped context-pack plan.",
    }
    CampaignCreate => {
        method: campaign_create, wire: "campaign_create", sdk: "campaignCreate", scope: Write,
        request: CampaignCreateRequest, response: CampaignRecordDto,
        doc: "Creates one owner-bound Campaign record or membership page.",
    }
    CampaignRead => {
        method: campaign_read, wire: "campaign_read", sdk: "campaignRead", scope: Read,
        request: CampaignRefRequest, response: RecordLookup<CampaignRecordDto>,
        doc: "Reads one owner-bound Campaign record or membership page.",
    }
    CampaignUpdate => {
        method: campaign_update, wire: "campaign_update", sdk: "campaignUpdate", scope: Write,
        request: CampaignUpdateRequest, response: CampaignRecordDto,
        doc: "Updates one owner-bound Campaign record or membership page.",
    }
    CampaignArchive => {
        method: campaign_archive, wire: "campaign_archive", sdk: "campaignArchive", scope: Write,
        request: CampaignArchiveRequest, response: CampaignRecordDto,
        doc: "Archives one owner-bound Campaign record or membership page.",
    }
    CampaignMembers => {
        method: campaign_members, wire: "campaign_members", sdk: "campaignMembers", scope: Read,
        request: CampaignMembersRequest, response: MembershipPageDto,
        doc: "Lists members of one owner-bound Campaign record or membership page.",
    }
    SavedQueryCreate => {
        method: saved_query_create, wire: "saved_query_create", sdk: "savedQueryCreate", scope: Write,
        request: SavedQueryCreateRequest, response: SavedQueryRecordDto,
        doc: "Creates one owner-bound SavedQuery record or membership page.",
    }
    SavedQueryRead => {
        method: saved_query_read, wire: "saved_query_read", sdk: "savedQueryRead", scope: Read,
        request: SavedQueryRefRequest, response: RecordLookup<SavedQueryRecordDto>,
        doc: "Reads one owner-bound SavedQuery record or membership page.",
    }
    SavedQueryUpdate => {
        method: saved_query_update, wire: "saved_query_update", sdk: "savedQueryUpdate", scope: Write,
        request: SavedQueryUpdateRequest, response: SavedQueryRecordDto,
        doc: "Updates one owner-bound SavedQuery record or membership page.",
    }
    SavedQueryArchive => {
        method: saved_query_archive, wire: "saved_query_archive", sdk: "savedQueryArchive", scope: Write,
        request: SavedQueryArchiveRequest, response: SavedQueryRecordDto,
        doc: "Archives one owner-bound SavedQuery record or membership page.",
    }
    SavedQueryMembers => {
        method: saved_query_members, wire: "saved_query_members", sdk: "savedQueryMembers", scope: Read,
        request: SavedQueryMembersRequest, response: MembershipPageDto,
        doc: "Lists members of one owner-bound SavedQuery record or membership page.",
    }
    SetExpressionPreference => {
        method: set_expression_preference, wire: "set_expression_preference", sdk: "setExpressionPreference", scope: Write,
        request: SetExpressionPreferenceRequest, response: ExpressionPreferenceReceiptDto,
        doc: "Writes a typed expression preference with full supersession receipts.",
    }

    RetractExpressionPreference => {
        method: retract_expression_preference, wire: "retract_expression_preference", sdk: "retractExpressionPreference", scope: Write,
        request: ClaimRefRequest, response: UnitResponse,
        doc: "Retracts a preference and restores its eligible predecessor.",
    }

    ExpressionPreferences => {
        method: expression_preferences, wire: "expression_preferences", sdk: "expressionPreferences", scope: Read,
        request: ExpressionPreferencesRequest, response: ExpressionPreferenceViewDto,
        doc: "Reads preferences in force for a subject at an instant.",
    }

    PlanEmergencyReschedule => {
        method: plan_emergency_reschedule, wire: "plan_emergency_reschedule", sdk: "planEmergencyReschedule", scope: Write,
        request: PlanEmergencyRescheduleRequest, response: EmergencyBatchPlanDto,
        doc: "Persists an owner-authorized emergency rescheduling plan.",
    }

    ScheduleOutboundWithContext => {
        method: schedule_outbound_with_context, wire: "schedule_outbound_with_context", sdk: "scheduleOutboundWithContext", scope: Write,
        request: ScheduleOutboundRequest, response: OutboundIntentReceipt,
        doc: "Schedules an outbound draft with explicit host timing context.",
    }

    ReactToMessage => {
        method: react_to_message, wire: "react_to_message", sdk: "reactToMessage", scope: Write,
        request: ReactToMessageInput, response: ReactionReceipt,
        doc: "Toggles one glyph as the verified actor on a readable message.",
    }
    ReactionPills => {
        method: reaction_pills, wire: "reaction_pills", sdk: "reactionPills", scope: Read,
        request: ReactionPillsRequest, response: Vec<crate::conversation::reaction::ReactionGrouping>,
        doc: "Reads grouped reactions for at most 50 messages in one batched read.",
    }
    ReactionsSince => {
        method: reactions_since, wire: "reactions_since", sdk: "reactionsSince", scope: Read,
        request: ReactionsSinceRequest, response: Vec<crate::conversation::reaction::ReactionSignal>,
        doc: "Reads the bound person's reaction signals since a timestamp.",
    }
    ReactionsOutbound => {
        method: reactions_outbound, wire: "reactions_outbound", sdk: "reactionsOutbound", scope: Read,
        request: EntityRefRequest, response: crate::conversation::reaction::ReactionsOutbound,
        doc: "Reads a room's capability-derived reaction outbound posture.",
    }
    IngestMirroredReaction => {
        method: ingest_mirrored_reaction, wire: "ingest_mirrored_reaction", sdk: "ingestMirroredReaction", scope: Write,
        request: MirroredReactionRequest, response: ReactionReceipt,
        doc: "System-adapter-only idempotent mirrored reaction ingestion.",
    }
    ArtifactBirth => {
        method: artifact_birth, wire: "artifact_birth", sdk: "artifactBirth", scope: Read,
        request: EntityRefRequest, response: Option<ArtifactBirthView>,
        doc: "Reads an artifact's immutable task/run/skill/input provenance.",
    }
    ArtifactsBornFrom => {
        method: artifacts_born_from, wire: "artifacts_born_from", sdk: "artifactsBornFrom", scope: Read,
        request: ArtifactsBornFromRequest, response: Vec<ArtifactBirthView>,
        doc: "Lists bounded artifact outputs of a task, run, skill or ask from the same ledger.",
    }
}
