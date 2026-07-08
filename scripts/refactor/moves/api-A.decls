## crate
crates/oneiron-server

## allowed
crates/oneiron-server/src/api.rs
crates/oneiron-server/src/api/artifacts.rs
crates/oneiron-server/src/api/companion.rs
crates/oneiron-server/src/api/consumer_usage.rs
crates/oneiron-server/src/api/discover.rs
crates/oneiron-server/src/api/entity.rs
crates/oneiron-server/src/api/lease.rs
crates/oneiron-server/src/api/mcp_gateway.rs
crates/oneiron-server/src/api/openapi.rs
crates/oneiron-server/src/api/resume.rs
crates/oneiron-server/src/api/search.rs
crates/oneiron-server/src/api/vad.rs

## forbid

## anchors
fn	-	api_routes	-	crates/oneiron-server/src/api.rs
struct	-	ApiDoc	-	crates/oneiron-server/src/api.rs

## uniqueness
crates/oneiron-server/src/api.rs
crates/oneiron-server/src/api/*.rs

## error-literal

## decl
+ pub ( crate ) async fn annotate_turn_vad ( auth : CoreAuth , State ( server ) : State < Arc < SyncServer > > , payload : Result < Json < TurnVadAnnotateRequest > , JsonRejection > ) -> Result < Json < TurnVadAnnotateResponse > , EnvelopedApiError >
+ pub ( crate ) async fn create_companion_access_grant ( auth : CoreAuth , State ( server ) : State < Arc < SyncServer > > , payload : Result < Json < CompanionCreateAccessGrantRequest > , JsonRejection > ) -> Result < Json < CompanionAccessGrantResponse > , EnvelopedApiError >
+ pub ( crate ) async fn create_companion_register_record ( auth : CoreAuth , State ( server ) : State < Arc < SyncServer > > , payload : Result < Json < CompanionRegisterCreateRecordRequest > , JsonRejection > ) -> Result < Json < CompanionRegisterRecordResponse > , EnvelopedApiError >
+ pub ( crate ) async fn discover ( headers : HeaderMap , State ( server ) : State < Arc < SyncServer > > ) -> Result < Json < DiscoverResponse > , ApiError >
+ pub ( crate ) async fn end_companion_register_relationship ( auth : CoreAuth , State ( server ) : State < Arc < SyncServer > > , Path ( record_id ) : Path < String > , payload : Result < Json < CompanionEndRelationshipRequest > , JsonRejection > ) -> Result < Json < CompanionEndRelationshipResponse > , EnvelopedApiError >
+ pub ( crate ) async fn get_companion_profile ( auth : CoreAuth , State ( server ) : State < Arc < SyncServer > > , Path ( persona_ref ) : Path < String > , query : Result < Query < CompanionProfileQuery > , QueryRejection > ) -> Result < Json < CompanionProfileResponse > , EnvelopedApiError >
+ pub ( crate ) async fn get_companion_register_record ( auth : CoreAuth , State ( server ) : State < Arc < SyncServer > > , Path ( record_id ) : Path < String > ) -> Result < Json < CompanionRegisterRecordResponse > , EnvelopedApiError >
+ pub ( crate ) async fn get_consumer_usage ( headers : HeaderMap , State ( server ) : State < Arc < SyncServer > > , query : Result < Query < ConsumerUsageQuery > , QueryRejection > ) -> Result < Json < ConsumerUsageState > , ApiError >
+ pub ( crate ) async fn get_consumer_usage_details ( headers : HeaderMap , State ( server ) : State < Arc < SyncServer > > , query : Result < Query < ConsumerUsageQuery > , QueryRejection > ) -> Result < Json < ConsumerUsageDetails > , ApiError >
+ pub ( crate ) async fn get_edges ( headers : HeaderMap , State ( server ) : State < Arc < SyncServer > > , Path ( id_hex ) : Path < String > , query : Result < Query < ViewQuery > , QueryRejection > ) -> Result < Json < Vec < Value > > , ApiError >
+ pub ( crate ) async fn get_entity ( headers : HeaderMap , State ( server ) : State < Arc < SyncServer > > , Path ( id_hex ) : Path < String > , query : Result < Query < ViewQuery > , QueryRejection > ) -> Result < Response , ApiError >
+ pub ( crate ) async fn get_usage_rollup ( headers : HeaderMap , State ( server ) : State < Arc < SyncServer > > , Path ( tenant_id ) : Path < String > , query : Result < Query < UsageRollupQuery > , QueryRejection > ) -> Result < Json < UsageRollup > , ApiError >
+ pub ( crate ) async fn handle_mcp_request ( headers : & HeaderMap , server : & Arc < SyncServer > , request : McpJsonRpcRequest ) -> Result < Value , McpGatewayError >
+ pub ( crate ) async fn lease_revoke ( headers : HeaderMap , State ( server ) : State < Arc < SyncServer > > , Json ( req ) : Json < LeaseRevokeRequest > ) -> Result < Json < LeaseRevokeResponse > , ApiError >
+ pub ( crate ) async fn mcp_gateway ( headers : HeaderMap , State ( server ) : State < Arc < SyncServer > > , body : Bytes ) -> impl IntoResponse
+ pub ( crate ) async fn openapi_json ( headers : HeaderMap , State ( server ) : State < Arc < SyncServer > > ) -> Result < Json < Value > , ApiError >
+ pub ( crate ) async fn read_turn_vad_annotation ( auth : CoreAuth , State ( server ) : State < Arc < SyncServer > > , query : Result < Query < TurnVadAnnotateQuery > , QueryRejection > ) -> Result < Json < TurnVadAnnotateResponse > , EnvelopedApiError >
+ pub ( crate ) async fn record_usage_event ( headers : HeaderMap , State ( server ) : State < Arc < SyncServer > > , Json ( event ) : Json < UsageEvent > ) -> Result < Json < UsageRecordResult > , ApiError >
+ pub ( crate ) async fn refresh_companion_profile ( auth : CoreAuth , State ( server ) : State < Arc < SyncServer > > , Path ( persona_ref ) : Path < String > , query : Result < Query < CompanionProfileQuery > , QueryRejection > , headers : HeaderMap , payload : Result < Bytes , BytesRejection > ) -> Result < Json < CompanionProfileResponse > , EnvelopedApiError >
+ pub ( crate ) async fn resolve_mcp_gateway_actor ( headers : & HeaderMap , server : & Arc < SyncServer > ) -> Result < McpResolvedActor , McpGatewayError >
+ pub ( crate ) async fn resume ( headers : HeaderMap , State ( server ) : State < Arc < SyncServer > > ) -> Result < Json < ResumeBundle > , ApiError >
+ pub ( crate ) async fn resume_bundle ( server : & SyncServer , caller : & str ) -> Result < ResumeBundle , ApiError >
+ pub ( crate ) async fn resume_session_context ( server : & SyncServer , caller : & str ) -> Result < SessionContext , ApiError >
+ pub ( crate ) async fn retire_companion_register_record ( auth : CoreAuth , State ( server ) : State < Arc < SyncServer > > , Path ( record_id ) : Path < String > , payload : Result < Json < CompanionRegisterRetireRecordRequest > , JsonRejection > ) -> Result < Json < CompanionRegisterRecordResponse > , EnvelopedApiError >
+ pub ( crate ) async fn revoke_companion_access_grant ( auth : CoreAuth , State ( server ) : State < Arc < SyncServer > > , Path ( grant_id ) : Path < String > , payload : Result < Json < CompanionRevokeAccessGrantRequest > , JsonRejection > ) -> Result < Json < CompanionAccessGrantResponse > , EnvelopedApiError >
+ pub ( crate ) async fn search_text ( headers : HeaderMap , State ( server ) : State < Arc < SyncServer > > , query : Result < Query < TextSearchQuery > , QueryRejection > ) -> Result < Json < SearchResponse > , ApiError >
+ pub ( crate ) async fn search_vector ( headers : HeaderMap , State ( server ) : State < Arc < SyncServer > > , query : Result < Query < VectorSearchQuery > , QueryRejection > ) -> Result < Json < SearchResponse > , ApiError >
+ pub ( crate ) async fn serve_artifact_path ( headers : HeaderMap , State ( server ) : State < Arc < SyncServer > > , Path ( ( artifact , path ) ) : Path < ( String , String ) > , Query ( query ) : Query < ArtifactServeQuery > ) -> Result < Response , EnvelopedApiError >
+ pub ( crate ) async fn serve_artifact_root ( headers : HeaderMap , OriginalUri ( uri ) : OriginalUri , State ( server ) : State < Arc < SyncServer > > , Path ( artifact ) : Path < String > , Query ( query ) : Query < ArtifactServeQuery > ) -> Result < Response , EnvelopedApiError >
+ pub ( crate ) async fn skills_pack ( headers : HeaderMap , State ( server ) : State < Arc < SyncServer > > ) -> Result < impl IntoResponse , ApiError >
+ pub ( crate ) async fn top_up_consumer ( headers : HeaderMap , State ( server ) : State < Arc < SyncServer > > , request : Result < Json < ConsumerTopUpRequest > , JsonRejection > ) -> Result < Json < ConsumerTopUpState > , ApiError >
+ pub ( crate ) async fn update_companion_register_record ( auth : CoreAuth , State ( server ) : State < Arc < SyncServer > > , Path ( record_id ) : Path < String > , payload : Result < Json < CompanionRegisterUpdateRecordRequest > , JsonRejection > ) -> Result < Json < CompanionRegisterRecordResponse > , EnvelopedApiError >
+ pub ( crate ) const ARTIFACT_CONTENT_SECURITY_POLICY : & str
+ pub ( crate ) const ARTIFACT_IMMUTABLE_CACHE_CONTROL : & str
+ pub ( crate ) const ARTIFACT_POINTER_CACHE_CONTROL : & str
+ pub ( crate ) const CAPABILITIES : & [ & str ]
+ pub ( crate ) const CAPABILITY_MODES : & [ & str ]
+ pub ( crate ) const EFFECTIVE_AUTH_SCOPES : & [ & str ]
+ pub ( crate ) const MCP_CREDENTIAL_HEADER : & str
+ pub ( crate ) const MCP_PROTOCOL_VERSION : & str
+ pub ( crate ) const RESUME_NOTIFICATION_LIMIT : usize
+ pub ( crate ) const RESUME_NOTIFICATION_SCAN_LIMIT : usize
+ pub ( crate ) const SKILL_PACK_ENDPOINT : & str
+ pub ( crate ) const SKILL_PACK_FORMAT : & str
+ pub ( crate ) const SKILL_PACK_LAYER_BOUNDARY : & str
+ pub ( crate ) const SKILL_PACK_LOAD_HINT : & str
+ pub ( crate ) const SKILL_PACK_MIME_TYPE : & str
+ pub ( crate ) const SKILL_PACK_NAME : & str
+ pub ( crate ) const SKILL_PACK_RESOLUTION : & str
+ pub ( crate ) const SUPPORTED_FORMATS : & [ & str ]
+ pub ( crate ) enum TurnVadAnnotationSource
+ pub ( crate ) fn add_security_scheme ( spec : & mut Value )
+ pub ( crate ) fn artifact_cache_control ( selector : oneiron :: ArtifactSnapshotSelector ) -> & ' static str
+ pub ( crate ) fn artifact_content_type ( path : & str ) -> & ' static str
+ pub ( crate ) fn artifact_file_response ( file : oneiron :: ArtifactServedFile , request_headers : & HeaderMap ) -> Result < Response , EnvelopedApiError >
+ pub ( crate ) fn artifact_root_redirect_response ( uri : & Uri ) -> Result < Response , EnvelopedApiError >
+ pub ( crate ) fn artifact_snapshot_selector ( query : & ArtifactServeQuery ) -> Result < oneiron :: ArtifactSnapshotSelector , EnvelopedApiError >
+ pub ( crate ) fn auth_bound_principal_ref ( auth : & CoreAuth ) -> Result < Option < oneiron :: EntityId > , ApiError >
+ pub ( crate ) fn caller_marker_contains ( value : Option < & Value > , caller : & str ) -> bool
+ pub ( crate ) fn companion_access_denied ( ) -> EnvelopedApiError
+ pub ( crate ) fn companion_access_grant_response ( id : & oneiron :: EntityId , grant : & oneiron :: AccessGrant ) -> CompanionAccessGrantResponse
+ pub ( crate ) fn companion_create_error ( error : oneiron :: Error ) -> EnvelopedApiError
+ pub ( crate ) fn companion_engine_error ( message : & ' static str , error : oneiron :: Error ) -> EnvelopedApiError
+ pub ( crate ) fn companion_goodbye_artifact_hook_payload ( outcome : Option < oneiron :: EnqueueCompanionTaskOutcome > , ended_badly : bool , already_ended : bool ) -> CompanionGoodbyeArtifactHookPayload
+ pub ( crate ) fn companion_profile_access ( server : & SyncServer , principal_ref : & oneiron :: EntityId , person_ref : & oneiron :: EntityId , persona_ref : & oneiron :: EntityId ) -> Result < CompanionProfileAccess , EnvelopedApiError >
+ pub ( crate ) fn companion_profile_drift_anchors ( previous_source_revision_ids : & [ oneiron :: EntityId ] , selected_source_revision_ids : & [ oneiron :: EntityId ] ) -> Vec < CompanionProfileDriftAnchor >
+ pub ( crate ) fn companion_profile_payload ( profile : & oneiron :: PsychProfile ) -> CompanionProfilePayload
+ pub ( crate ) fn companion_profile_principal_ref ( auth : & CoreAuth , requested : Option < oneiron :: EntityId > ) -> Result < oneiron :: EntityId , ApiError >
+ pub ( crate ) fn companion_profile_response_state ( server : & SyncServer , persona_ref : & oneiron :: EntityId , person_ref : & oneiron :: EntityId , access : CompanionProfileAccess , selected_source_revision_ids : Option < & [ oneiron :: EntityId ] > ) -> Result < CompanionProfileResponse , EnvelopedApiError >
+ pub ( crate ) fn companion_profile_stale_reason ( reason : & oneiron :: PsychProfileStaleReason ) -> CompanionProfileStaleReasonPayload
+ pub ( crate ) fn companion_register_actor_class ( value : u8 ) -> Result < oneiron :: EdgeActorClass , ApiError >
+ pub ( crate ) fn companion_register_approval_from_wire ( value : & str ) -> Result < oneiron :: ClaimApprovalStatus , ApiError >
+ pub ( crate ) fn companion_register_engine_error ( message : & ' static str , error : oneiron :: Error ) -> EnvelopedApiError
+ pub ( crate ) fn companion_register_export_from_wire ( value : & str ) -> Result < oneiron :: CompanionExportClassification , ApiError >
+ pub ( crate ) fn companion_register_kind_from_wire ( value : & str , field : & ' static str ) -> Result < oneiron :: CompanionRecordKind , ApiError >
+ pub ( crate ) fn companion_register_lifecycle_from_wire ( value : & str ) -> Result < oneiron :: ClaimLifecycleStatus , ApiError >
+ pub ( crate ) fn companion_register_provenance_from_payload ( payload : & CompanionRegisterProvenancePayload ) -> Result < oneiron :: CompanionProvenance , ApiError >
+ pub ( crate ) fn companion_register_record_from_payload ( payload : & CompanionRegisterRecordPayload ) -> Result < oneiron :: CompanionRecord , ApiError >
+ pub ( crate ) fn companion_register_record_payload ( record : & oneiron :: CompanionRecord ) -> CompanionRegisterRecordPayload
+ pub ( crate ) fn companion_register_record_response ( id : & oneiron :: EntityId , record : & oneiron :: CompanionRecord ) -> CompanionRegisterRecordResponse
+ pub ( crate ) fn companion_register_scope_from_payload ( payload : & CompanionRegisterScopePayload ) -> Result < oneiron :: CompanionScope , ApiError >
+ pub ( crate ) fn companion_register_scope_payload ( scope : & oneiron :: CompanionScope ) -> CompanionRegisterScopePayload
+ pub ( crate ) fn companion_register_source_from_wire ( value : & str ) -> Result < oneiron :: ClaimSource , ApiError >
+ pub ( crate ) fn companion_register_subject_from_payload ( payload : & CompanionRegisterSubjectPayload ) -> Result < oneiron :: CompanionSubject , ApiError >
+ pub ( crate ) fn companion_register_subject_payload ( subject : & oneiron :: CompanionSubject ) -> CompanionRegisterSubjectPayload
+ pub ( crate ) fn companion_scope_entity_refs ( scope : & CompanionAccessGrantScopePayload ) -> Result < ( oneiron :: EntityId , oneiron :: EntityId ) , ApiError >
+ pub ( crate ) fn companion_scope_response ( person_ref : & oneiron :: EntityId , persona_ref : & oneiron :: EntityId ) -> CompanionAccessGrantScopePayload
+ pub ( crate ) fn consumer_top_up_idempotency_conflict_error ( idempotency_key : & str ) -> ApiError
+ pub ( crate ) fn current_resume_budget ( _server : & SyncServer ) -> ResumeBudget
+ pub ( crate ) fn discover_response ( server : & SyncServer ) -> Result < DiscoverResponse , ApiError >
+ pub ( crate ) fn discovered_entities ( ids : & [ oneiron :: EntityId ] , entity_type : u8 ) -> Vec < DiscoveredEntity >
+ pub ( crate ) fn ensure_mcp_actor_matches ( args : & McpValidatedToolArgs , resolved : & McpResolvedActor ) -> Result < ( ) , McpGatewayError >
+ pub ( crate ) fn entity_ids_hex ( ids : & [ oneiron :: EntityId ] ) -> Vec < String >
+ pub ( crate ) fn execute_mcp_edit ( server : & SyncServer , args : McpEditToolArgs , actor : & McpResolvedActor ) -> Result < Value , McpGatewayError >
+ pub ( crate ) fn execute_mcp_nav ( server : & SyncServer , args : crate :: mcp :: McpNavToolArgs , actor : & McpResolvedActor ) -> Result < Value , McpGatewayError >
+ pub ( crate ) fn execute_mcp_propose_claim ( server : & SyncServer , args : & McpEditToolArgs , actor : & McpResolvedActor ) -> Result < Value , McpGatewayError >
+ pub ( crate ) fn execute_mcp_proposed_control_record ( server : & SyncServer , args : & McpEditToolArgs , actor : & McpResolvedActor ) -> Result < Value , McpGatewayError >
+ pub ( crate ) fn execute_mcp_read ( server : & SyncServer , args : crate :: mcp :: McpReadToolArgs , actor : & McpResolvedActor ) -> Result < Value , McpGatewayError >
+ pub ( crate ) fn execute_mcp_tool ( server : & SyncServer , args : McpValidatedToolArgs , actor : & McpResolvedActor ) -> Result < Value , McpGatewayError >
+ pub ( crate ) fn feature_flags ( ) -> FeatureFlags
+ pub ( crate ) fn fill_schema_description_gaps ( spec : & mut Value )
+ pub ( crate ) fn is_agent_visible_entity_type ( entity_type : u8 ) -> bool
+ pub ( crate ) fn mark_entity_response_as_binary ( spec : & mut Value )
+ pub ( crate ) fn mcp_actor_class_wire ( actor_class : McpActorClass ) -> & ' static str
+ pub ( crate ) fn mcp_actor_resolution_error ( error : McpConnectorActorResolutionError ) -> McpGatewayError
+ pub ( crate ) fn mcp_actor_result ( actor : & McpResolvedActor ) -> Value
+ pub ( crate ) fn mcp_api_error ( error : ApiError ) -> McpGatewayError
+ pub ( crate ) fn mcp_ask_result ( args : McpAskToolArgs , actor : & McpResolvedActor ) -> Value
+ pub ( crate ) fn mcp_claim_candidate_from_args ( args : & McpEditToolArgs ) -> Result < oneiron :: ClaimCandidate , McpGatewayError >
+ pub ( crate ) fn mcp_claim_subject ( subject : Option < & crate :: mcp :: McpEditSubject > ) -> Result < oneiron :: ClaimSubject , McpGatewayError >
+ pub ( crate ) fn mcp_connector_credential ( headers : & HeaderMap ) -> Result < String , McpGatewayError >
+ pub ( crate ) fn mcp_control_record_candidate ( args : & McpEditToolArgs , actor : & McpResolvedActor , lifecycle : & ' static str ) -> Result < oneiron :: ClaimCandidate , McpGatewayError >
+ pub ( crate ) fn mcp_edit_lifecycle ( verb : McpEditVerb ) -> & ' static str
+ pub ( crate ) fn mcp_edit_receipt ( args : & McpEditToolArgs , actor : & McpResolvedActor , proposal_id : Option < oneiron :: EntityId > , status : & ' static str , lifecycle : & ' static str , message : & ' static str ) -> Value
+ pub ( crate ) fn mcp_edit_verb_name ( verb : McpEditVerb ) -> & ' static str
+ pub ( crate ) fn mcp_engine_error ( context : & ' static str , error : oneiron :: Error ) -> McpGatewayError
+ pub ( crate ) fn mcp_error_response ( id : Value , error : McpGatewayError ) -> Value
+ pub ( crate ) fn mcp_existing_edit_receipt ( server : & SyncServer , args : & McpEditToolArgs , actor : & McpResolvedActor , id : oneiron :: EntityId , lifecycle : & ' static str , message : & ' static str ) -> Result < Option < Value > , McpGatewayError >
+ pub ( crate ) fn mcp_idempotency_entity_id ( namespace : & ' static str , args : & McpEditToolArgs , actor : & McpResolvedActor ) -> oneiron :: EntityId
+ pub ( crate ) fn mcp_params < T : DeserializeOwned > ( params : Option < Value > , field : & ' static str ) -> Result < T , McpGatewayError >
+ pub ( crate ) fn mcp_required_f32 ( value : Option < f32 > , field : & ' static str ) -> Result < f32 , McpGatewayError >
+ pub ( crate ) fn mcp_required_json < ' a > ( value : Option < & ' a Value > , field : & ' static str ) -> Result < & ' a Value , McpGatewayError >
+ pub ( crate ) fn mcp_required_str < ' a > ( value : Option < & ' a str > , field : & ' static str ) -> Result < & ' a str , McpGatewayError >
+ pub ( crate ) fn mcp_routed_ask_result ( args : McpRoutedAskToolArgs , actor : & McpResolvedActor ) -> Value
+ pub ( crate ) fn mcp_scoped_read < ' a > ( vault : & ' a oneiron :: Vault , actor : & McpResolvedActor ) -> Result < oneiron :: claim :: ScopedRead < ' a > , McpGatewayError >
+ pub ( crate ) fn mcp_text_content ( text : impl Into < String > ) -> Value
+ pub ( crate ) fn mcp_tool_validation_error ( error : McpToolValidationError ) -> McpGatewayError
+ pub ( crate ) fn mcp_validated_actor ( args : & McpValidatedToolArgs ) -> & McpActorMetadata
+ pub ( crate ) fn mcp_write_envelope ( args : & McpEditToolArgs , actor : & McpResolvedActor , lifecycle : & ' static str ) -> Result < oneiron :: WriteEnvelope , McpGatewayError >
+ pub ( crate ) fn merge_error_components ( spec : & mut Value )
+ pub ( crate ) fn non_empty_source_revision_ids ( ids : Vec < oneiron :: EntityId > ) -> Option < Vec < oneiron :: EntityId > >
+ pub ( crate ) fn normalize_artifact_route_path ( route_path : & str ) -> String
+ pub ( crate ) fn notification_already_surfaced ( body : & Value , caller : & str ) -> bool
+ pub ( crate ) fn notification_body_json ( raw_body : & [ u8 ] ) -> Option < Value >
+ pub ( crate ) fn notification_scoped_to_caller ( body : & Value , caller : & str ) -> bool
+ pub ( crate ) fn openapi_document ( ) -> Value
+ pub ( crate ) fn optional_companion_profile_refresh_request ( headers : & HeaderMap , payload : Result < Bytes , BytesRejection > ) -> Result < CompanionProfileRefreshRequest , ApiError >
+ pub ( crate ) fn outbound_capability_discovery ( ) -> OutboundCapabilityDiscovery
+ pub ( crate ) fn parse_source_revision_ids < T > ( values : impl IntoIterator < Item = T > ) -> Result < Vec < oneiron :: EntityId > , ApiError > where T : AsRef < str > ,
+ pub ( crate ) fn parse_source_revision_ids_body ( raw : Option < Vec < String > > ) -> Result < Option < Vec < oneiron :: EntityId > > , ApiError >
+ pub ( crate ) fn parse_source_revision_ids_query ( raw : Option < & str > ) -> Result < Option < Vec < oneiron :: EntityId > > , ApiError >
+ pub ( crate ) fn pending_notifications ( server : & SyncServer , caller : & str ) -> Result < Vec < NotificationItem > , ApiError >
+ pub ( crate ) fn pending_unprocessed_items ( _server : & SyncServer , _caller : & str ) -> Vec < UnprocessedItem >
+ pub ( crate ) fn predicate_namespaces ( vault : & oneiron :: Vault , claim_ids : & [ oneiron :: EntityId ] ) -> Result < Vec < String > , ApiError >
+ pub ( crate ) fn project_scoped_search_result ( scoped_read : & oneiron :: claim :: ScopedRead < ' _ > , result : oneiron :: ScoredEntity , view : View ) -> oneiron :: Result < Option < Value > >
+ pub ( crate ) fn rate_limit_status ( config : & SyncServerConfig ) -> RateLimitStatus
+ pub ( crate ) fn request_etag_matches ( headers : & HeaderMap , etag : & str ) -> bool
+ pub ( crate ) fn require_companion_access_grant_write ( auth : & CoreAuth ) -> Result < ( ) , ApiError >
+ pub ( crate ) fn require_companion_access_grant_write_for_principal ( auth : & CoreAuth , principal_ref : & oneiron :: EntityId ) -> Result < ( ) , ApiError >
+ pub ( crate ) fn require_companion_profile_read ( auth : & CoreAuth ) -> Result < ( ) , ApiError >
+ pub ( crate ) fn require_message_in_turn ( server : & SyncServer , turn_id : & oneiron :: EntityId , message_id : & oneiron :: EntityId ) -> Result < ( ) , ApiError >
+ pub ( crate ) fn resume_caller ( headers : & HeaderMap ) -> String
+ pub ( crate ) fn runtime_health_status_for_config ( config : & SyncServerConfig ) -> RuntimeHealthStatus
+ pub ( crate ) fn runtime_status_for_config ( config : & SyncServerConfig ) -> RuntimeStatus
+ pub ( crate ) fn same_source_revision_selection ( left : & [ oneiron :: EntityId ] , right : & [ oneiron :: EntityId ] ) -> bool
+ pub ( crate ) fn search_fetch_limit ( count_mode : CountMode , page_limit : usize ) -> usize
+ pub ( crate ) fn search_meta ( count_mode : CountMode , estimated_total : usize ) -> ResponseMeta
+ pub ( crate ) fn search_response ( scoped_read : & oneiron :: claim :: ScopedRead < ' _ > , results : Vec < oneiron :: ScoredEntity > , view : View , page_limit : usize ) -> Result < Vec < Value > , ApiError >
+ pub ( crate ) fn select_refresh_source_revision_ids ( body_source_revision_ids : Option < Vec < oneiron :: EntityId > > , query_source_revision_ids : Option < Vec < oneiron :: EntityId > > ) -> Result < Option < Vec < oneiron :: EntityId > > , ApiError >
+ pub ( crate ) fn serve_artifact_file ( server : Arc < SyncServer > , artifact : String , route_path : & str , query : ArtifactServeQuery , request_headers : & HeaderMap ) -> Result < Response , EnvelopedApiError >
+ pub ( crate ) fn set_schema_property_description ( spec : & mut Value , schema_name : & str , property_name : & str , description : & str )
+ pub ( crate ) fn skill_pack_discovery ( ) -> SkillPackDiscovery
+ pub ( crate ) fn supported_formats ( ) -> Vec < & ' static str >
+ pub ( crate ) fn usage_error ( error : UsageError ) -> ApiError
+ pub ( crate ) fn usage_mode_for_event ( config : & SyncServerConfig , event : & UsageEvent ) -> Result < UsageMode , ApiError >
+ pub ( crate ) fn vad_annotation_core_error ( error : oneiron :: Error ) -> ApiError
+ pub ( crate ) fn validate_companion_register_scope_export ( scope : & oneiron :: CompanionScope , export : oneiron :: CompanionExportClassification ) -> Result < ( ) , ApiError >
+ pub ( crate ) struct ArtifactServeQuery
+ pub ( crate ) struct BoundContext
+ pub ( crate ) struct CompanionAccessGrantResponse
+ pub ( crate ) struct CompanionAccessGrantScopePayload
+ pub ( crate ) struct CompanionCreateAccessGrantRequest
+ pub ( crate ) struct CompanionEndRelationshipRequest
+ pub ( crate ) struct CompanionEndRelationshipResponse
+ pub ( crate ) struct CompanionGoodbyeArtifactHookPayload
+ pub ( crate ) struct CompanionProfileAccess
+ pub ( crate ) struct CompanionProfileConfidencePayload
+ pub ( crate ) struct CompanionProfileDriftAnchor
+ pub ( crate ) struct CompanionProfileNextAction
+ pub ( crate ) struct CompanionProfilePayload
+ pub ( crate ) struct CompanionProfileQuery
+ pub ( crate ) struct CompanionProfileRefreshRequest
+ pub ( crate ) struct CompanionProfileResponse
+ pub ( crate ) struct CompanionProfileStaleReasonPayload
+ pub ( crate ) struct CompanionRegisterCreateRecordRequest
+ pub ( crate ) struct CompanionRegisterProvenancePayload
+ pub ( crate ) struct CompanionRegisterRecordPayload
+ pub ( crate ) struct CompanionRegisterRecordResponse
+ pub ( crate ) struct CompanionRegisterRelationshipRefPayload
+ pub ( crate ) struct CompanionRegisterRetireRecordRequest
+ pub ( crate ) struct CompanionRegisterScopePayload
+ pub ( crate ) struct CompanionRegisterSubjectPayload
+ pub ( crate ) struct CompanionRegisterUpdateRecordRequest
+ pub ( crate ) struct CompanionRevokeAccessGrantRequest
+ pub ( crate ) struct ConsumerUsageQuery
+ pub ( crate ) struct DiscoverResponse
+ pub ( crate ) struct DiscoveredEntity
+ pub ( crate ) struct EdgeResult
+ pub ( crate ) struct FeatureFlags
+ pub ( crate ) struct LeaseRevokeRequest
+ pub ( crate ) struct LeaseRevokeResponse
+ pub ( crate ) struct McpGatewayError
+ pub ( crate ) struct McpJsonRpcRequest
+ pub ( crate ) struct McpToolCallParams
+ pub ( crate ) struct OutboundCapabilityDiscovery
+ pub ( crate ) struct OutboundConnectorManifestSummary
+ pub ( crate ) struct RateLimitStatus
+ pub ( crate ) struct SearchResult
+ pub ( crate ) struct SkillPackDiscovery
+ pub ( crate ) struct TextSearchQuery
+ pub ( crate ) struct TurnVadAnnotateQuery
+ pub ( crate ) struct TurnVadAnnotateRequest
+ pub ( crate ) struct TurnVadAnnotateResponse
+ pub ( crate ) struct UsageRollupQuery
+ pub ( crate ) struct VadPayload
+ pub ( crate ) struct VectorSearchQuery
+ pub ( crate ) type SearchResponse
+ pub ( crate ) use self :: artifacts :: *
+ pub ( crate ) use self :: companion :: *
+ pub ( crate ) use self :: consumer_usage :: *
+ pub ( crate ) use self :: discover :: *
+ pub ( crate ) use self :: entity :: *
+ pub ( crate ) use self :: lease :: *
+ pub ( crate ) use self :: mcp_gateway :: *
+ pub ( crate ) use self :: openapi :: *
+ pub ( crate ) use self :: resume :: *
+ pub ( crate ) use self :: search :: *
+ pub ( crate ) use self :: vad :: *

## impl-delta
- crates/oneiron-server/src/api.rs	impl From < TurnVadAnnotationSource > for VadAnnotationSource
- crates/oneiron-server/src/api.rs	impl From < Vad > for VadPayload
- crates/oneiron-server/src/api.rs	impl From < VadAnnotationSource > for TurnVadAnnotationSource
- crates/oneiron-server/src/api.rs	impl McpGatewayError
- crates/oneiron-server/src/api.rs	impl TurnVadAnnotateResponse
- crates/oneiron-server/src/api.rs	impl VadPayload
+ crates/oneiron-server/src/api/mcp_gateway.rs	impl McpGatewayError
+ crates/oneiron-server/src/api/vad.rs	impl From < TurnVadAnnotationSource > for VadAnnotationSource
+ crates/oneiron-server/src/api/vad.rs	impl From < Vad > for VadPayload
+ crates/oneiron-server/src/api/vad.rs	impl From < VadAnnotationSource > for TurnVadAnnotationSource
+ crates/oneiron-server/src/api/vad.rs	impl TurnVadAnnotateResponse
+ crates/oneiron-server/src/api/vad.rs	impl VadPayload
