## crate
crates/oneiron-server

## allowed
crates/oneiron-server/src/api.rs
crates/oneiron-server/src/api/context_pack.rs
crates/oneiron-server/src/api/conversations.rs
crates/oneiron-server/src/api/core.rs
crates/oneiron-server/src/api/memory.rs
crates/oneiron-server/src/api/run_tree.rs
crates/oneiron-server/src/api/tests.rs

## forbid

## anchors
fn	-	api_routes	-	crates/oneiron-server/src/api.rs
struct	-	ApiDoc	-	crates/oneiron-server/src/api.rs

## uniqueness
crates/oneiron-server/src/api.rs
crates/oneiron-server/src/api/*.rs

## error-literal

## decl
+ pub ( crate ) async fn advance_eiri_session_rag_state ( vault : & oneiron :: Vault , scope_id : & str , session_id : & str , pack : & oneiron :: ContextPack , evidence : & CoreContextPackEvidence ) -> oneiron :: EiriSessionRagState
+ pub ( crate ) async fn context_pack ( headers : HeaderMap , State ( server ) : State < Arc < SyncServer > > , payload : Result < Json < ContextPackRequest > , JsonRejection > ) -> Result < Json < CoreContextPackResponse > , ApiError >
+ pub ( crate ) async fn core_batch ( auth : CoreAuth , State ( server ) : State < Arc < SyncServer > > , payload : Result < Json < CoreBatchRequest > , JsonRejection > ) -> Result < Json < CoreBatchResponse > , EnvelopedApiError >
+ pub ( crate ) async fn core_batch_short_id_hydrate ( auth : CoreAuth , State ( server ) : State < Arc < SyncServer > > , payload : Result < Json < CoreBatchShortIdHydrateRequest > , JsonRejection > ) -> Result < Json < CoreBatchShortIdHydrateResponse > , EnvelopedApiError >
+ pub ( crate ) async fn core_context_pack ( auth : CoreAuth , State ( server ) : State < Arc < SyncServer > > , payload : Result < Json < CoreContextPackRequest > , JsonRejection > ) -> Result < Json < CoreContextPackResponse > , EnvelopedApiError >
+ pub ( crate ) async fn core_hydrate ( auth : CoreAuth , State ( server ) : State < Arc < SyncServer > > , payload : Result < Json < CoreHydrateRequest > , JsonRejection > ) -> Result < Json < CoreHydrateResponse > , EnvelopedApiError >
+ pub ( crate ) async fn core_memory_timeline ( auth : CoreAuth , State ( server ) : State < Arc < SyncServer > > , Path ( id_hex ) : Path < String > , query : Result < Query < ViewQuery > , QueryRejection > ) -> Result < Json < CoreMemoryTimelineResponse > , EnvelopedApiError >
+ pub ( crate ) async fn core_memory_verb ( auth : CoreAuth , State ( server ) : State < Arc < SyncServer > > , Path ( verb_name ) : Path < String > , payload : Result < Json < CoreMemoryVerbRequest > , JsonRejection > ) -> Result < Json < CoreMemoryVerbResponse > , EnvelopedApiError >
+ pub ( crate ) async fn core_query ( auth : CoreAuth , State ( server ) : State < Arc < SyncServer > > , payload : Result < Json < CoreQueryRequest > , JsonRejection > ) -> Result < Json < SearchResponse > , EnvelopedApiError >
+ pub ( crate ) async fn core_run_tree ( auth : CoreAuth , State ( server ) : State < Arc < SyncServer > > , query : Result < Query < CoreRunTreeQuery > , QueryRejection > ) -> Result < Json < CoreRunTreeResponse > , EnvelopedApiError >
+ pub ( crate ) async fn core_run_tree_intervene ( auth : CoreAuth , State ( server ) : State < Arc < SyncServer > > , payload : Result < Json < CoreRunTreeInterventionRequest > , JsonRejection > ) -> Result < Json < CoreRunTreeInterventionResponse > , EnvelopedApiError >
+ pub ( crate ) async fn core_run_tree_observe ( auth : CoreAuth , State ( server ) : State < Arc < SyncServer > > , query : Result < Query < CoreRunTreeQuery > , QueryRejection > ) -> Result < Json < CoreRunTreeResponse > , EnvelopedApiError >
+ pub ( crate ) async fn create_core_conversation ( auth : CoreAuth , State ( server ) : State < Arc < SyncServer > > , payload : Result < Json < CoreCreateEntityRequest > , JsonRejection > ) -> Result < Json < CoreEntityWriteResponse > , EnvelopedApiError >
+ pub ( crate ) async fn create_core_conversation_turn ( auth : CoreAuth , State ( server ) : State < Arc < SyncServer > > , Path ( conversation_id ) : Path < String > , payload : Result < Json < CoreCreateTurnRequest > , JsonRejection > ) -> Result < Json < CoreEntityWriteResponse > , EnvelopedApiError >
+ pub ( crate ) async fn current_eiri_session_rag_state ( vault : & oneiron :: Vault , scope_id : & str ) -> oneiron :: EiriSessionRagState
+ pub ( crate ) async fn get_core_outbound_capability ( auth : CoreAuth , Path ( connector ) : Path < String > ) -> Result < Json < & ' static oneiron :: OutboundCapabilityManifest > , EnvelopedApiError >
+ pub ( crate ) async fn get_core_outbound_verb_contract ( auth : CoreAuth , Path ( ( connector , verb ) ) : Path < ( String , String ) > ) -> Result < Json < & ' static oneiron :: OutboundVerbContract > , EnvelopedApiError >
+ pub ( crate ) async fn get_core_turn ( auth : CoreAuth , State ( server ) : State < Arc < SyncServer > > , Path ( turn_id ) : Path < String > , query : Result < Query < ViewQuery > , QueryRejection > ) -> Result < Json < Value > , EnvelopedApiError >
+ pub ( crate ) async fn list_core_conversation_turns ( auth : CoreAuth , State ( server ) : State < Arc < SyncServer > > , Path ( conversation_id ) : Path < String > , query : Result < Query < CoreListQuery > , QueryRejection > ) -> Result < Json < SearchResponse > , EnvelopedApiError >
+ pub ( crate ) async fn list_core_conversations ( auth : CoreAuth , State ( server ) : State < Arc < SyncServer > > , query : Result < Query < CoreListQuery > , QueryRejection > ) -> Result < Json < SearchResponse > , EnvelopedApiError >
+ pub ( crate ) async fn list_core_outbound_capabilities ( auth : CoreAuth ) -> Result < Json < & ' static [ oneiron :: OutboundCapabilityManifest ] > , EnvelopedApiError >
+ pub ( crate ) async fn run_context_pack_builder ( vault : & oneiron :: Vault , scoped_read : & oneiron :: claim :: ScopedRead < ' _ > , builder : oneiron :: ContextPackBuilder < ' _ > , projection : oneiron :: serialize :: SerializeConfig , response_limits : ContextPackResponseLimits , error_context : & ' static str , eiri_context : Option < EiriContextV4Request > ) -> Result < CoreContextPackResponse , ApiError >
+ pub ( crate ) const ANNOUNCEMENT_STATUS_ACTIVE : & str
+ pub ( crate ) const ANNOUNCEMENT_STATUS_CORRECTED : & str
+ pub ( crate ) const ANNOUNCEMENT_STATUS_RETRACTED : & str
+ pub ( crate ) const CORE_MAX_BATCH_ENTITIES : usize
+ pub ( crate ) const CORE_MAX_LIST_LIMIT : usize
+ pub ( crate ) const CORE_RUN_TREE_RUN_ID_MAX_BYTES : usize
+ pub ( crate ) const EIRI_SESSION_RAG_LAST_RESULT_IDS_MAX : usize
+ pub ( crate ) const EIRI_SESSION_RAG_SESSION_ID_MAX_BYTES : usize
+ pub ( crate ) const EIRI_SESSION_RAG_STATE_MAX_ENTRIES : usize
+ pub ( crate ) const PLATFORM_ANNOUNCEMENT_MESSAGE_TYPE : & str
+ pub ( crate ) const PLATFORM_ANNOUNCEMENT_VOICE : & str
+ pub ( crate ) const SHARED_EIRI_SESSION_SCOPE_IDS : & [ & str ]
+ pub ( crate ) enum CoreContextPackStateKind
+ pub ( crate ) enum CoreContextPackStateReason
+ pub ( crate ) enum CoreEiriMemoryBoardSlot
+ pub ( crate ) enum CoreEiriMemoryBoardSource
+ pub ( crate ) enum CoreHydrateDeletionReason
+ pub ( crate ) enum CoreHydrateDeletionSource
+ pub ( crate ) enum CoreHydrateStatus
+ pub ( crate ) enum CoreMemoryOperationKind
+ pub ( crate ) enum CoreMemoryTimelineRecordState
+ pub ( crate ) enum CoreMemoryVerbDeleteReason
+ pub ( crate ) enum CoreRunTreeEventKind
+ pub ( crate ) enum CoreRunTreeInterventionEffect
+ pub ( crate ) enum CoreRunTreeInterventionKind
+ pub ( crate ) enum CoreRunTreeRepair
+ pub ( crate ) enum CoreRunTreeStatus
+ pub ( crate ) enum CoreShortIdHydrateErrorKind
+ pub ( crate ) enum CoreShortIdHydrateOutcome
+ pub ( crate ) fn announcement_original_text ( object : & serde_json :: Map < String , Value > ) -> Option < & str >
+ pub ( crate ) fn announcement_status ( object : & serde_json :: Map < String , Value > ) -> & ' static str
+ pub ( crate ) fn apply_context_pack_budget < ' a > ( mut builder : oneiron :: ContextPackBuilder < ' a > , budget : Option < & ContextPackBudgetControls > , top_level_max_item_tokens : usize , scoped_candidate_limit : usize , result_limit : usize , default_selected_edges : usize ) -> Result < ( oneiron :: ContextPackBuilder < ' a > , oneiron :: ContextPackRetrievalBudget , ) , ApiError , >
+ pub ( crate ) fn apply_context_pack_policy < ' a > ( mut builder : oneiron :: ContextPackBuilder < ' a > , policy : Option < & ContextPackPolicyControls > ) -> Result < oneiron :: ContextPackBuilder < ' a > , ApiError >
+ pub ( crate ) fn apply_context_pack_response_limits ( pack : & mut oneiron :: ContextPack , limits : ContextPackResponseLimits )
+ pub ( crate ) fn apply_context_pack_response_retrieval_budget ( pack : & mut oneiron :: ContextPack , budget : oneiron :: ContextPackRetrievalBudget )
+ pub ( crate ) fn apply_context_pack_time < ' a > ( mut builder : oneiron :: ContextPackBuilder < ' a > , time : Option < & ContextPackTimeControls > ) -> Result < oneiron :: ContextPackBuilder < ' a > , ApiError >
+ pub ( crate ) fn collect_live_entity_page < F > ( vault : & oneiron :: Vault , after : Option < oneiron :: EntityId > , limit : usize , mut fetch : F ) -> Result < ( Vec < oneiron :: EntityId > , Option < String > ) , EnvelopedApiError > where F : FnMut ( Option < & oneiron :: EntityId > , usize ) -> Result < Vec < oneiron :: EntityId > , EnvelopedApiError > ,
+ pub ( crate ) fn companion_scope_resolution_authorized ( vault : & oneiron :: Vault , companion_auth : Option < & CoreAuth > , person_ref : Option < oneiron :: EntityId > , persona_ref : Option < oneiron :: EntityId > ) -> Result < bool , ApiError >
+ pub ( crate ) fn companion_scope_wire ( scope : & oneiron :: CompanionScope ) -> & ' static str
+ pub ( crate ) fn context_pack_json_projection_config ( view : View , budget : Option < & ContextPackBudgetControls > , top_level_max_item_tokens : usize ) -> oneiron :: serialize :: SerializeConfig
+ pub ( crate ) fn core_body_for_write < ' a > ( entity_type : u8 , body : & ' a Value ) -> Cow < ' a , Value >
+ pub ( crate ) fn core_context_edge ( edge : oneiron :: EdgeInfo ) -> CoreContextEdge
+ pub ( crate ) fn core_context_entity ( entity : oneiron :: ContextEntity ) -> CoreContextEntity
+ pub ( crate ) fn core_context_pack_evidence ( vault : & oneiron :: Vault , run_id : Option < oneiron :: RetrievalRunId > ) -> Result < CoreContextPackEvidence , ApiError >
+ pub ( crate ) fn core_context_pack_evidence_for_results ( mut evidence : CoreContextPackEvidence , results : & [ oneiron :: ContextEntity ] ) -> CoreContextPackEvidence
+ pub ( crate ) fn core_context_pack_response ( pack : oneiron :: ContextPack , evidence : CoreContextPackEvidence , context_version : Option < String > , memory_board : Option < oneiron :: EiriMemoryBoard > , session_rag : Option < oneiron :: EiriSessionRagState > ) -> CoreContextPackResponse
+ pub ( crate ) fn core_context_pack_score_component ( component : oneiron :: RetrievalScoreComponent ) -> CoreContextPackScoreComponent
+ pub ( crate ) fn core_context_pack_score_evidence ( score : oneiron :: RetrievalScoreBreakdown ) -> CoreContextPackScoreEvidence
+ pub ( crate ) fn core_context_pack_state ( empty : Option < & oneiron :: EmptyContext > ) -> CoreContextPackState
+ pub ( crate ) fn core_context_pack_state_reason ( reason : oneiron :: EmptyReason ) -> CoreContextPackStateReason
+ pub ( crate ) fn core_context_pack_stats ( stats : oneiron :: PackStats ) -> CoreContextPackStats
+ pub ( crate ) fn core_entity_timestamps ( occurred_start : Option < u64 > , occurred_end : Option < u64 > , learned_at : Option < u64 > ) -> Result < CoreEntityTimestamps , ApiError >
+ pub ( crate ) fn core_hydrate_deletion_metadata ( deletion : oneiron :: HydratedShortIdDeletion ) -> CoreHydrateDeletionMetadata
+ pub ( crate ) fn core_list_conversation_turns ( vault : & oneiron :: Vault , conversation : & oneiron :: EntityId , params : CoreListQuery ) -> Result < Json < SearchResponse > , EnvelopedApiError >
+ pub ( crate ) fn core_list_entities_by_type ( vault : & oneiron :: Vault , entity_type : u8 , params : CoreListQuery ) -> Result < Json < SearchResponse > , EnvelopedApiError >
+ pub ( crate ) fn core_list_limit ( limit : usize ) -> usize
+ pub ( crate ) fn core_memory_delete_reason ( verb : oneiron :: NamedMemoryVerb , requested : Option < CoreMemoryVerbDeleteReason > ) -> Result < ( oneiron :: DeleteReason , CoreMemoryVerbDeleteReason ) , ApiError >
+ pub ( crate ) fn core_memory_operation_kind ( kind : oneiron :: MemoryOperationKind ) -> CoreMemoryOperationKind
+ pub ( crate ) fn core_memory_timeline_response ( vault : & oneiron :: Vault , timeline : oneiron :: MemoryTimeline , view : View ) -> Result < CoreMemoryTimelineResponse , ApiError >
+ pub ( crate ) fn core_memory_timeline_state ( state : oneiron :: MemoryTimelineRecordState ) -> CoreMemoryTimelineRecordState
+ pub ( crate ) fn core_run_tree_event ( event : oneiron :: RunTreeEvent ) -> CoreRunTreeEvent
+ pub ( crate ) fn core_run_tree_event_kind ( kind : oneiron :: RunTreeEventKind ) -> CoreRunTreeEventKind
+ pub ( crate ) fn core_run_tree_intervention_effect ( effect : oneiron :: JobInterventionEffect ) -> CoreRunTreeInterventionEffect
+ pub ( crate ) fn core_run_tree_node ( node : oneiron :: RunTreeNode ) -> CoreRunTreeNode
+ pub ( crate ) fn core_run_tree_repair ( repair : oneiron :: RunTreeRepair ) -> CoreRunTreeRepair
+ pub ( crate ) fn core_run_tree_response ( tree : oneiron :: RunTree ) -> CoreRunTreeResponse
+ pub ( crate ) fn core_run_tree_status ( status : oneiron :: RunTreeStatus ) -> CoreRunTreeStatus
+ pub ( crate ) fn core_text_fields ( text : Option < & [ CoreTextField ] > , body : & Value ) -> Vec < ( String , String ) >
+ pub ( crate ) fn count_live_conversation_turns ( vault : & oneiron :: Vault , conversation : & oneiron :: EntityId ) -> Result < u64 , EnvelopedApiError >
+ pub ( crate ) fn count_live_entities_by_type ( vault : & oneiron :: Vault , entity_type : u8 ) -> Result < u64 , EnvelopedApiError >
+ pub ( crate ) fn default_context_neighbors ( ) -> usize
+ pub ( crate ) fn default_true ( ) -> bool
+ pub ( crate ) fn eiri_memory_board_budget ( controls : Option < & EiriMemoryBoardControls > , limit : usize , default_selected_edges : usize ) -> oneiron :: EiriMemoryBoardBudget
+ pub ( crate ) fn eiri_session_rag_key ( vault : & oneiron :: Vault , scope_id : & str , session_id : & str ) -> String
+ pub ( crate ) fn eiri_session_rag_scope_key ( vault : & oneiron :: Vault , scope_id : & str ) -> String
+ pub ( crate ) fn eiri_session_rag_store ( ) -> & ' static Mutex < EiriSessionRagStore >
+ pub ( crate ) fn encode_core_body ( body : & Value ) -> Result < Vec < u8 > , ApiError >
+ pub ( crate ) fn field_profile_for_view ( view : View ) -> oneiron :: FieldProfile
+ pub ( crate ) fn hydrate_short_id_response ( scoped_read : & oneiron :: claim :: ScopedRead < ' _ > , short_id : String , content_hash : u8 , view : View ) -> Result < Option < CoreHydrateResponse > , ApiError >
+ pub ( crate ) fn is_deleted_shell_for_core_list ( vault : & oneiron :: Vault , id : & oneiron :: EntityId ) -> Result < bool , ApiError >
+ pub ( crate ) fn is_platform_announcement_body ( object : & serde_json :: Map < String , Value > ) -> bool
+ pub ( crate ) fn is_shared_eiri_session_scope_id ( session_scope_id : & str ) -> bool
+ pub ( crate ) fn job_intervention_kind ( kind : CoreRunTreeInterventionKind ) -> oneiron :: JobInterventionKind
+ pub ( crate ) fn non_empty_query ( query : Option < & str > ) -> Option < & str >
+ pub ( crate ) fn normalize_platform_announcement_body ( body : & Value ) -> Cow < ' _ , Value >
+ pub ( crate ) fn object_bool_field ( object : & serde_json :: Map < String , Value > , keys : & [ & str ] ) -> Option < bool >
+ pub ( crate ) fn object_string_field < ' a > ( object : & ' a serde_json :: Map < String , Value > , keys : & [ & str ] ) -> Option < & ' a str >
+ pub ( crate ) fn outbound_capability_error ( error : & oneiron :: UnsupportedOutboundCapability ) -> ApiError
+ pub ( crate ) fn parse_companion_ref ( value : Option < & str > , field : & ' static str ) -> Result < ( Option < String > , Option < oneiron :: EntityId > ) , ApiError >
+ pub ( crate ) fn parse_job_id_param ( value : & str , field : & ' static str ) -> Result < oneiron :: JobId , ApiError >
+ pub ( crate ) fn parse_required_entity_id ( value : Option < & str > , field : & ' static str ) -> Result < oneiron :: EntityId , ApiError >
+ pub ( crate ) fn parse_short_ref ( reference : & str ) -> Result < ( String , u8 ) , ApiError >
+ pub ( crate ) fn parse_short_ref_parts ( short_id : & str , content_hash : & str ) -> Result < ( String , u8 ) , ApiError >
+ pub ( crate ) fn parse_short_ref_request ( req : & CoreHydrateRequest ) -> Result < ( String , u8 ) , ApiError >
+ pub ( crate ) fn project_core_entity ( vault : & oneiron :: Vault , id : & oneiron :: EntityId , view : View ) -> Result < Json < Value > , EnvelopedApiError >
+ pub ( crate ) fn project_entity_ids ( vault : & oneiron :: Vault , ids : Vec < oneiron :: EntityId > , view : View ) -> Result < Vec < Value > , ApiError >
+ pub ( crate ) fn resolve_context_pack_retrieval_budgets ( retrieval : Option < & ContextPackRetrievalBudgetControls > , result_limit : usize , scoped_candidate_limit : usize , default_selected_edges : usize ) -> ( oneiron :: ContextPackRetrievalBudget , oneiron :: ContextPackRetrievalBudget , )
+ pub ( crate ) fn resolve_eiri_companion_assembly ( vault : & oneiron :: Vault , companion : Option < & EiriCompanionControls > , session_id : & str , companion_auth : Option < & CoreAuth > ) -> Result < oneiron :: EiriCompanionAssembly , ApiError >
+ pub ( crate ) fn resolve_eiri_context_v4_request ( vault : & oneiron :: Vault , context_version : Option < & str > , memory_board : Option < & EiriMemoryBoardControls > , session_rag : Option < & EiriSessionRagControls > , companion : Option < & EiriCompanionControls > , budget_shape : ( usize , usize ) , identity : EiriContextV4Identity < ' _ > ) -> Result < Option < EiriContextV4Request > , ApiError >
+ pub ( crate ) fn resolved_context_pack_depth ( depth : Option < & ContextPackDepthControls > , edge_hop : u32 , max_neighbors : usize ) -> ( u32 , & ' static str , usize , & ' static str )
+ pub ( crate ) fn retrieval_signal_name ( signal : oneiron :: RetrievalSignal ) -> & ' static str
+ pub ( crate ) fn run_core_query ( scoped_read : & oneiron :: claim :: ScopedRead < ' _ > , query : Option < & str > , vector : Option < & [ f32 ] > , limit : usize ) -> oneiron :: Result < Vec < oneiron :: ScoredEntity > >
+ pub ( crate ) fn scrub_context_pack_visible_stats ( pack : & mut oneiron :: ContextPack )
+ pub ( crate ) fn signal_name ( signal : oneiron :: Signal ) -> & ' static str
+ pub ( crate ) fn stage_core_entity_put < ' a > ( batch : oneiron :: BatchBuilder < ' a > , id : & oneiron :: EntityId , entity_type : u8 , timestamps : CoreEntityTimestamps , body : & Value , text : Option < & [ CoreTextField ] > ) -> Result < oneiron :: BatchBuilder < ' a > , ApiError >
+ pub ( crate ) fn validate_context_pack_depth ( edge_hop : u32 , edge_hop_field : & ' static str , max_neighbors : usize , max_neighbors_field : & ' static str ) -> Result < ( ) , ApiError >
+ pub ( crate ) fn validate_core_query_seeds ( query : Option < & str > , vector : Option < & [ f32 ] > ) -> Result < ( ) , ApiError >
+ pub ( crate ) fn validate_core_run_tree_query ( params : & CoreRunTreeQuery ) -> Result < ( ) , ApiError >
+ pub ( crate ) fn validate_eiri_session_id ( session_id : & str , field : & ' static str ) -> Result < ( ) , ApiError >
+ pub ( crate ) fn widen_context_pack_retrieval_budget ( budget : oneiron :: ContextPackRetrievalBudget , scoped_candidate_limit : usize ) -> oneiron :: ContextPackRetrievalBudget
+ pub ( crate ) fn write_core_entity ( vault : & oneiron :: Vault , input : CoreEntityWriteInput < ' _ > ) -> Result < Json < CoreEntityWriteResponse > , EnvelopedApiError >
+ pub ( crate ) static EIRI_SESSION_RAG_STATE : OnceLock < Mutex < EiriSessionRagStore > >
+ pub ( crate ) struct ContextPackBudgetControls
+ pub ( crate ) struct ContextPackDepthControls
+ pub ( crate ) struct ContextPackPolicyControls
+ pub ( crate ) struct ContextPackRequest
+ pub ( crate ) struct ContextPackResponseLimits
+ pub ( crate ) struct ContextPackRetrievalBudgetControls
+ pub ( crate ) struct ContextPackTimeControls
+ pub ( crate ) struct CoreBatchEntityInput
+ pub ( crate ) struct CoreBatchEntityResult
+ pub ( crate ) struct CoreBatchRequest
+ pub ( crate ) struct CoreBatchResponse
+ pub ( crate ) struct CoreBatchShortIdHydrateItem
+ pub ( crate ) struct CoreBatchShortIdHydrateRequest
+ pub ( crate ) struct CoreBatchShortIdHydrateResponse
+ pub ( crate ) struct CoreContextEdge
+ pub ( crate ) struct CoreContextEntity
+ pub ( crate ) struct CoreContextPackEvidence
+ pub ( crate ) struct CoreContextPackItemAccounting
+ pub ( crate ) struct CoreContextPackRequest
+ pub ( crate ) struct CoreContextPackResponse
+ pub ( crate ) struct CoreContextPackScoreComponent
+ pub ( crate ) struct CoreContextPackScoreEvidence
+ pub ( crate ) struct CoreContextPackState
+ pub ( crate ) struct CoreContextPackStats
+ pub ( crate ) struct CoreCreateEntityRequest
+ pub ( crate ) struct CoreCreateTurnRequest
+ pub ( crate ) struct CoreEiriCompanionAssembly
+ pub ( crate ) struct CoreEiriMemoryBoard
+ pub ( crate ) struct CoreEiriMemoryBoardBudget
+ pub ( crate ) struct CoreEiriMemoryBoardRow
+ pub ( crate ) struct CoreEiriSessionRagState
+ pub ( crate ) struct CoreEntityTimestamps
+ pub ( crate ) struct CoreEntityWriteInput < ' a >
+ pub ( crate ) struct CoreEntityWriteResponse
+ pub ( crate ) struct CoreHydrateDeletionMetadata
+ pub ( crate ) struct CoreHydrateRequest
+ pub ( crate ) struct CoreHydrateResponse
+ pub ( crate ) struct CoreListQuery
+ pub ( crate ) struct CoreMemoryTimelineRecord
+ pub ( crate ) struct CoreMemoryTimelineResponse
+ pub ( crate ) struct CoreMemoryVerbDeleteOutcome
+ pub ( crate ) struct CoreMemoryVerbRequest
+ pub ( crate ) struct CoreMemoryVerbResponse
+ pub ( crate ) struct CoreQueryRequest
+ pub ( crate ) struct CoreRunTreeEvent
+ pub ( crate ) struct CoreRunTreeFailure
+ pub ( crate ) struct CoreRunTreeInterventionRequest
+ pub ( crate ) struct CoreRunTreeInterventionResponse
+ pub ( crate ) struct CoreRunTreeNode
+ pub ( crate ) struct CoreRunTreeQuery
+ pub ( crate ) struct CoreRunTreeResponse
+ pub ( crate ) struct CoreRunTreeTimestamps
+ pub ( crate ) struct CoreShortIdHydrateError
+ pub ( crate ) struct CoreTextField
+ pub ( crate ) struct EiriCompanionControls
+ pub ( crate ) struct EiriContextV4Identity < ' a >
+ pub ( crate ) struct EiriContextV4Request
+ pub ( crate ) struct EiriMemoryBoardControls
+ pub ( crate ) struct EiriMemoryBoardSlotControls
+ pub ( crate ) struct EiriSessionRagControls
+ pub ( crate ) struct EiriSessionRagStore
+ pub ( crate ) use self :: context_pack :: *
+ pub ( crate ) use self :: conversations :: *
+ pub ( crate ) use self :: core :: *
+ pub ( crate ) use self :: memory :: *
+ pub ( crate ) use self :: run_tree :: *

## impl-delta
- crates/oneiron-server/src/api.rs	impl EiriSessionRagStore
+ crates/oneiron-server/src/api/context_pack.rs	impl EiriSessionRagStore
## frag-edit
crates/oneiron-server/src/api.rs	include_str!("../tests/fixtures/v1_core_openapi_contract.snapshot.json");	include_str!("../../tests/fixtures/v1_core_openapi_contract.snapshot.json");
crates/oneiron-server/src/api.rs	include_str!("../tests/fixtures/v1_core_success_contract.snapshot.json");	include_str!("../../tests/fixtures/v1_core_success_contract.snapshot.json");
crates/oneiron-server/src/api.rs	include_str!("../tests/fixtures/v1_core_error_contract.snapshot.json");	include_str!("../../tests/fixtures/v1_core_error_contract.snapshot.json");
