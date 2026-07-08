## crate
crates/oneiron

## flat-name-check
yes

## allowed
crates/oneiron-bench/src/beam.rs
crates/oneiron-bench/src/retrieval_trace_export.rs
crates/oneiron-server/src/api.rs
crates/oneiron-server/src/handler/tests.rs
crates/oneiron-server/src/projection.rs
crates/oneiron-server/src/projection/tests.rs
crates/oneiron-server/tests/core_discover.rs
crates/oneiron-server/tests/ws_sync.rs
crates/oneiron/src/access_grant/tests.rs
crates/oneiron/src/agent_def.rs
crates/oneiron/src/agent_def/tests.rs
crates/oneiron/src/anchored_annotation.rs
crates/oneiron/src/anchored_annotation/tests.rs
crates/oneiron/src/batch.rs
crates/oneiron/src/batch/tests.rs
crates/oneiron/src/blob_artifact.rs
crates/oneiron/src/blob_artifact/tests.rs
crates/oneiron/src/bm25.rs
crates/oneiron/src/bm25/tests.rs
crates/oneiron/src/channel_identity/tests.rs
crates/oneiron/src/channel_identity_lifecycle.rs
crates/oneiron/src/channel_identity_lifecycle/tests.rs
crates/oneiron/src/claim.rs
crates/oneiron/src/code_artifact.rs
crates/oneiron/src/code_revision.rs
crates/oneiron/src/code_revision/tests.rs
crates/oneiron/src/code_symbol.rs
crates/oneiron/src/code_symbol/tests.rs
crates/oneiron/src/codebase.rs
crates/oneiron/src/codebase/tests.rs
crates/oneiron/src/companion.rs
crates/oneiron/src/companion/tests.rs
crates/oneiron/src/context_pack.rs
crates/oneiron/src/context_pack/tests.rs
crates/oneiron/src/counterparty_contact/tests.rs
crates/oneiron/src/critic/tests.rs
crates/oneiron/src/deletion.rs
crates/oneiron/src/dreamer_runner.rs
crates/oneiron/src/dreamer_runner/tests.rs
crates/oneiron/src/dreamer_tournament/tests.rs
crates/oneiron/src/edit_settle.rs
crates/oneiron/src/edit_settle/tests.rs
crates/oneiron/src/embed.rs
crates/oneiron/src/embed/tests.rs
crates/oneiron/src/error.rs
crates/oneiron/src/federation/tests.rs
crates/oneiron/src/gate.rs
crates/oneiron/src/gate/tests.rs
crates/oneiron/src/graph_fs.rs
crates/oneiron/src/graph_fs/tests.rs
crates/oneiron/src/inbox.rs
crates/oneiron/src/inbox/tests.rs
crates/oneiron/src/ingest/tests.rs
crates/oneiron/src/lens/tests.rs
crates/oneiron/src/lib.rs
crates/oneiron/src/off_record/tests.rs
crates/oneiron/src/outbound/tests.rs
crates/oneiron/src/persona_snapshot.rs
crates/oneiron/src/persona_snapshot/tests.rs
crates/oneiron/src/pipeline.rs
crates/oneiron/src/pipeline/tests.rs
crates/oneiron/src/policy_model/tests.rs
crates/oneiron/src/ppr.rs
crates/oneiron/src/provenance.rs
crates/oneiron/src/psych_profile.rs
crates/oneiron/src/psych_profile/tests.rs
crates/oneiron/src/receipt.rs
crates/oneiron/src/receipt/tests.rs
crates/oneiron/src/registry.rs
crates/oneiron/src/repo_mutation.rs
crates/oneiron/src/repo_mutation/tests.rs
crates/oneiron/src/serialize.rs
crates/oneiron/src/skill.rs
crates/oneiron/src/skill/tests.rs
crates/oneiron/src/store.rs
crates/oneiron/src/sweep.rs
crates/oneiron/src/sync/bridge.rs
crates/oneiron/src/sync/bridge/tests.rs
crates/oneiron/src/sync/client/tests.rs
crates/oneiron/src/sync/quarantine/tests.rs
crates/oneiron/src/sync/queue/tests.rs
crates/oneiron/src/sync/selector.rs
crates/oneiron/src/sync/selector/tests.rs
crates/oneiron/src/sync/window.rs
crates/oneiron/src/tests.rs
crates/oneiron/src/tests_bug.rs
crates/oneiron/src/types.rs
crates/oneiron/src/vault.rs
crates/oneiron/src/vault/tests.rs
crates/oneiron/tests/gate_regression.rs
crates/oneiron/tests/sync_bridge.rs
crates/oneiron/tests/sync_convergence_props.rs
crates/oneiron/tests/sync_delete_propagation.rs
crates/oneiron/tests/sync_edge_kind_gating.rs
crates/oneiron/tests/sync_harness/mod.rs
crates/oneiron/tests/sync_quarantine.rs
crates/oneiron/tests/sync_receipt_replay.rs
crates/oneiron/tests/sync_remat_correctness.rs
crates/oneiron/tests/sync_replay_reason.rs
crates/oneiron/tests/sync_sweep_executor.rs

## error-literal
crates/oneiron/src/registry.rs

## decl
+ pub mod registry
+ pub use crate :: registry :: { ENTITY_TYPE_ACCESS_GRANT , ENTITY_TYPE_AUTHORITY_LOG , ENTITY_TYPE_CHANNEL_IDENTITY , ENTITY_TYPE_CODE_ARTIFACT , ENTITY_TYPE_CODE_SYMBOL , ENTITY_TYPE_COUNTERPARTY_CONTACT , ENTITY_TYPE_FEDERATION_GRANT , ENTITY_TYPE_OUTBOUND_GRANT , ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT , ENTITY_TYPE_PSYCH_PROFILE , StructuralKindRegistration , TypeByteBand }
+ pub use crate :: types :: { Bm25RankProfile , ClaimCandidate , ContextEntity , ContextPack , ContextPackRetrievalBudget , DecodedEdgeValue , EIRI_CONTEXT_VERSION_V4 , EdgeActorClass , EdgeConfirmationStatus , EdgeInfo , EdgeKind , EdgeProvenanceFlags , EdgeValueLayout , EiriCompanionAssembly , EiriMemoryBoard , EiriMemoryBoardBudget , EiriMemoryBoardRow , EiriMemoryBoardSlot , EiriMemoryBoardSource , EiriSessionRagState , EmptyContext , EmptyReason , EntityId , FieldProfile , HnswConfig , HydratedShortIdDeletion , HydratedShortIdDeletionReason , HydratedShortIdDeletionSource , MemoryOperationKind , MemoryTimeline , MemoryTimelineRecord , MemoryTimelineRecordState , NamedMemoryVerb , NotificationItem , PackFormat , PackItemTokenStats , PackSectionTokenStats , PackStats , PackTokenStats , ResumeBudget , ResumeBundle , ScoredEntity , SessionContext , Signal , TemporalAnchorMode , TemporalGranularity , TextAnalyzerConfig , TextIndexOptions , TimeRange , TokenAllocation , UnprocessedItem , Vad , VadAnnotation , VadAnnotationSource , VadComponent , VaultConfig , WriteActor , WriteEnvelope , WriteProvenance }
- pub use crate :: types :: { Bm25RankProfile , ClaimCandidate , ContextEntity , ContextPack , ContextPackRetrievalBudget , DecodedEdgeValue , EIRI_CONTEXT_VERSION_V4 , ENTITY_TYPE_ACCESS_GRANT , ENTITY_TYPE_AUTHORITY_LOG , ENTITY_TYPE_CHANNEL_IDENTITY , ENTITY_TYPE_CODE_ARTIFACT , ENTITY_TYPE_CODE_SYMBOL , ENTITY_TYPE_COUNTERPARTY_CONTACT , ENTITY_TYPE_FEDERATION_GRANT , ENTITY_TYPE_OUTBOUND_GRANT , ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT , ENTITY_TYPE_PSYCH_PROFILE , EdgeActorClass , EdgeConfirmationStatus , EdgeInfo , EdgeKind , EdgeProvenanceFlags , EdgeValueLayout , EiriCompanionAssembly , EiriMemoryBoard , EiriMemoryBoardBudget , EiriMemoryBoardRow , EiriMemoryBoardSlot , EiriMemoryBoardSource , EiriSessionRagState , EmptyContext , EmptyReason , EntityId , FieldProfile , HnswConfig , HydratedShortIdDeletion , HydratedShortIdDeletionReason , HydratedShortIdDeletionSource , MemoryOperationKind , MemoryTimeline , MemoryTimelineRecord , MemoryTimelineRecordState , NamedMemoryVerb , NotificationItem , PackFormat , PackItemTokenStats , PackSectionTokenStats , PackStats , PackTokenStats , ResumeBudget , ResumeBundle , ScoredEntity , SessionContext , Signal , StructuralKindRegistration , TemporalAnchorMode , TemporalGranularity , TextAnalyzerConfig , TextIndexOptions , TimeRange , TokenAllocation , TypeByteBand , UnprocessedItem , Vad , VadAnnotation , VadAnnotationSource , VadComponent , VaultConfig , WriteActor , WriteEnvelope , WriteProvenance }

## impl-delta

## edit
crates/oneiron-bench/src/beam.rs	const BENCH_CONTRACT_ENTITY_TYPE: u8 = oneiron::types::ENTITY_TYPE_TURN;	const BENCH_CONTRACT_ENTITY_TYPE: u8 = oneiron::registry::ENTITY_TYPE_TURN;
crates/oneiron-bench/src/retrieval_trace_export.rs	oneiron::types::ENTITY_TYPE_SUMMARY,	oneiron::registry::ENTITY_TYPE_SUMMARY,
crates/oneiron-server/src/api.rs	oneiron::types::ENTITY_TYPE_CLAIM => claim_ids.extend(ids),	oneiron::registry::ENTITY_TYPE_CLAIM => claim_ids.extend(ids),
crates/oneiron-server/src/api.rs	oneiron::types::ENTITY_TYPE_PERSON => {	oneiron::registry::ENTITY_TYPE_PERSON => {
crates/oneiron-server/src/api.rs	oneiron::types::ENTITY_TYPE_CONVERSATION => {	oneiron::registry::ENTITY_TYPE_CONVERSATION => {
crates/oneiron-server/src/api.rs	oneiron::types::ENTITY_TYPE_CLAIM => (&mut claims, budget.claims),	oneiron::registry::ENTITY_TYPE_CLAIM => (&mut claims, budget.claims),
crates/oneiron-server/src/api.rs	oneiron::types::ENTITY_TYPE_TURN => (&mut turns, budget.turns),	oneiron::registry::ENTITY_TYPE_TURN => (&mut turns, budget.turns),
crates/oneiron-server/src/api.rs	oneiron::types::ENTITY_TYPE_SUMMARY => (&mut summaries, budget.summaries),	oneiron::registry::ENTITY_TYPE_SUMMARY => (&mut summaries, budget.summaries),
crates/oneiron-server/src/api.rs	oneiron::types::ENTITY_TYPE_FACET => (&mut facets, budget.facets),	oneiron::registry::ENTITY_TYPE_FACET => (&mut facets, budget.facets),
crates/oneiron-server/src/api.rs	oneiron::types::ENTITY_TYPE_CLAIM,	oneiron::registry::ENTITY_TYPE_CLAIM,
crates/oneiron-server/src/api.rs	entity(claim_a, oneiron::types::ENTITY_TYPE_CLAIM),	entity(claim_a, oneiron::registry::ENTITY_TYPE_CLAIM),
crates/oneiron-server/src/api.rs	entity(claim_b, oneiron::types::ENTITY_TYPE_CLAIM),	entity(claim_b, oneiron::registry::ENTITY_TYPE_CLAIM),
crates/oneiron-server/src/api.rs	entity(neighbor, oneiron::types::ENTITY_TYPE_SUMMARY),	entity(neighbor, oneiron::registry::ENTITY_TYPE_SUMMARY),
crates/oneiron-server/src/api.rs	oneiron::types::ENTITY_TYPE_SUMMARY,	oneiron::registry::ENTITY_TYPE_SUMMARY,
crates/oneiron-server/src/api.rs	oneiron::types::ENTITY_TYPE_CLAIM,	oneiron::registry::ENTITY_TYPE_CLAIM,
crates/oneiron-server/src/api.rs	oneiron::EdgeActorClass::Human => oneiron::types::ENTITY_TYPE_PERSON,	oneiron::EdgeActorClass::Human => oneiron::registry::ENTITY_TYPE_PERSON,
crates/oneiron-server/src/api.rs	oneiron::EdgeActorClass::Agent => oneiron::types::ENTITY_TYPE_MACHINE,	oneiron::EdgeActorClass::Agent => oneiron::registry::ENTITY_TYPE_MACHINE,
crates/oneiron-server/src/api.rs	oneiron::EdgeActorClass::System => oneiron::types::ENTITY_TYPE_MACHINE,	oneiron::EdgeActorClass::System => oneiron::registry::ENTITY_TYPE_MACHINE,
crates/oneiron-server/src/api.rs	oneiron::types::ENTITY_TYPE_PERSON,	oneiron::registry::ENTITY_TYPE_PERSON,
crates/oneiron-server/src/api.rs	oneiron::types::ENTITY_TYPE_PERSON,	oneiron::registry::ENTITY_TYPE_PERSON,
crates/oneiron-server/src/api.rs	oneiron::types::ENTITY_TYPE_PERSON,	oneiron::registry::ENTITY_TYPE_PERSON,
crates/oneiron-server/src/api.rs	oneiron::types::ENTITY_TYPE_PERSON,	oneiron::registry::ENTITY_TYPE_PERSON,
crates/oneiron-server/src/api.rs	oneiron::types::ENTITY_TYPE_TURN,	oneiron::registry::ENTITY_TYPE_TURN,
crates/oneiron-server/src/api.rs	oneiron::types::ENTITY_TYPE_PERSON,	oneiron::registry::ENTITY_TYPE_PERSON,
crates/oneiron-server/src/api.rs	oneiron::types::ENTITY_TYPE_PERSON,	oneiron::registry::ENTITY_TYPE_PERSON,
crates/oneiron-server/src/api.rs	oneiron::types::ENTITY_TYPE_SUMMARY,	oneiron::registry::ENTITY_TYPE_SUMMARY,
crates/oneiron-server/src/api.rs	oneiron::types::ENTITY_TYPE_ASSET_TEXT,	oneiron::registry::ENTITY_TYPE_ASSET_TEXT,
crates/oneiron-server/src/api.rs	Value::from(oneiron::types::ENTITY_TYPE_ASSET_TEXT)	Value::from(oneiron::registry::ENTITY_TYPE_ASSET_TEXT)
crates/oneiron-server/src/api.rs	Value::from(oneiron::types::ENTITY_TYPE_ASSET_TEXT)	Value::from(oneiron::registry::ENTITY_TYPE_ASSET_TEXT)
crates/oneiron-server/src/handler/tests.rs	oneiron::types::ENTITY_TYPE_FACET,	oneiron::registry::ENTITY_TYPE_FACET,
crates/oneiron-server/src/handler/tests.rs	oneiron::types::ENTITY_TYPE_FACET,	oneiron::registry::ENTITY_TYPE_FACET,
crates/oneiron-server/src/handler/tests.rs	oneiron::types::ENTITY_TYPE_CLAIM,	oneiron::registry::ENTITY_TYPE_CLAIM,
crates/oneiron-server/src/handler/tests.rs	oneiron::types::ENTITY_TYPE_CLAIM,	oneiron::registry::ENTITY_TYPE_CLAIM,
crates/oneiron-server/src/handler/tests.rs	oneiron::types::ENTITY_TYPE_PERSON,	oneiron::registry::ENTITY_TYPE_PERSON,
crates/oneiron-server/src/handler/tests.rs	oneiron::types::ENTITY_TYPE_FACET,	oneiron::registry::ENTITY_TYPE_FACET,
crates/oneiron-server/src/handler/tests.rs	oneiron::types::ENTITY_TYPE_CLAIM,	oneiron::registry::ENTITY_TYPE_CLAIM,
crates/oneiron/src/batch.rs	} if *entity_type == crate::types::ENTITY_TYPE_CLAIM && !*allow_reserved_predicate => {	} if *entity_type == crate::registry::ENTITY_TYPE_CLAIM && !*allow_reserved_predicate => {
crates/oneiron/src/batch.rs	entity_type: crate::types::ENTITY_TYPE_CLAIM,	entity_type: crate::registry::ENTITY_TYPE_CLAIM,
crates/oneiron/src/batch.rs	crate::types::ENTITY_TYPE_CLAIM => {	crate::registry::ENTITY_TYPE_CLAIM => {
crates/oneiron/src/batch.rs	|| entity_type != crate::types::ENTITY_TYPE_CLAIM	|| entity_type != crate::registry::ENTITY_TYPE_CLAIM
crates/oneiron/src/batch.rs	crate::types::ENTITY_TYPE_POLICY_MANIFEST	crate::registry::ENTITY_TYPE_POLICY_MANIFEST
crates/oneiron/src/batch.rs	if entity_type == crate::types::ENTITY_TYPE_CLAIM	if entity_type == crate::registry::ENTITY_TYPE_CLAIM
crates/oneiron/src/batch.rs	if entity_type == crate::types::ENTITY_TYPE_CLAIM {	if entity_type == crate::registry::ENTITY_TYPE_CLAIM {
crates/oneiron/src/batch.rs	*entity_type == crate::types::ENTITY_TYPE_CLAIM	*entity_type == crate::registry::ENTITY_TYPE_CLAIM
crates/oneiron/src/batch.rs	} if *entity_type == crate::types::ENTITY_TYPE_CLAIM	} if *entity_type == crate::registry::ENTITY_TYPE_CLAIM
crates/oneiron/src/batch.rs	} if *entity_type == crate::types::ENTITY_TYPE_CLAIM	} if *entity_type == crate::registry::ENTITY_TYPE_CLAIM
crates/oneiron/src/batch.rs	crate::types::ENTITY_TYPE_CLAIM,	crate::registry::ENTITY_TYPE_CLAIM,
crates/oneiron/src/batch.rs	if entity_type == crate::types::ENTITY_TYPE_CLAIM {	if entity_type == crate::registry::ENTITY_TYPE_CLAIM {
crates/oneiron/src/batch.rs	if target_header.entity_type != crate::types::ENTITY_TYPE_CLAIM {	if target_header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
crates/oneiron/src/batch.rs	} else if entity_type == crate::types::ENTITY_TYPE_CODE_ARTIFACT {	} else if entity_type == crate::registry::ENTITY_TYPE_CODE_ARTIFACT {
crates/oneiron/src/batch.rs	} else if entity_type == crate::types::ENTITY_TYPE_BLOB_ARTIFACT {	} else if entity_type == crate::registry::ENTITY_TYPE_BLOB_ARTIFACT {
crates/oneiron/src/batch.rs	} else if entity_type == crate::types::ENTITY_TYPE_AUTHORITY_LOG {	} else if entity_type == crate::registry::ENTITY_TYPE_AUTHORITY_LOG {
crates/oneiron/src/batch.rs	} else if entity_type == crate::types::ENTITY_TYPE_FEDERATION_GRANT {	} else if entity_type == crate::registry::ENTITY_TYPE_FEDERATION_GRANT {
crates/oneiron/src/batch.rs	} else if entity_type == crate::types::ENTITY_TYPE_ACCESS_GRANT {	} else if entity_type == crate::registry::ENTITY_TYPE_ACCESS_GRANT {
crates/oneiron/src/batch.rs	let authority_first_seen_key = if entity_type == crate::types::ENTITY_TYPE_AUTHORITY_LOG {	let authority_first_seen_key = if entity_type == crate::registry::ENTITY_TYPE_AUTHORITY_LOG {
crates/oneiron/src/batch.rs	if old_type == crate::types::ENTITY_TYPE_CODE_ARTIFACT && body_changed {	if old_type == crate::registry::ENTITY_TYPE_CODE_ARTIFACT && body_changed {
crates/oneiron/src/batch.rs	if old_type == crate::types::ENTITY_TYPE_CODE_ARTIFACT	if old_type == crate::registry::ENTITY_TYPE_CODE_ARTIFACT
crates/oneiron/src/batch.rs	if entity_type == crate::types::ENTITY_TYPE_CLAIM && !is_lexical_query_hint_claim {	if entity_type == crate::registry::ENTITY_TYPE_CLAIM && !is_lexical_query_hint_claim {
crates/oneiron/src/batch.rs	if header.entity_type != crate::types::ENTITY_TYPE_CLAIM {	if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
crates/oneiron/src/batch.rs	prefix.push(crate::types::ENTITY_TYPE_CLAIM);	prefix.push(crate::registry::ENTITY_TYPE_CLAIM);
crates/oneiron/src/batch.rs	Ok(header.entity_type == crate::types::ENTITY_TYPE_CLAIM)	Ok(header.entity_type == crate::registry::ENTITY_TYPE_CLAIM)
crates/oneiron/src/batch.rs	if header.entity_type != crate::types::ENTITY_TYPE_CLAIM {	if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
crates/oneiron/src/bm25.rs	if header.entity_type != crate::types::ENTITY_TYPE_CLAIM {	if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
crates/oneiron/src/bm25.rs	if header.entity_type != crate::types::ENTITY_TYPE_CLAIM {	if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
crates/oneiron/src/companion.rs	pub const ENTITY_TYPE_COMPANION_REGISTER: u8 = crate::types::TYPE_BYTE_BAND_COMPANION_START;	pub const ENTITY_TYPE_COMPANION_REGISTER: u8 = crate::registry::TYPE_BYTE_BAND_COMPANION_START;
crates/oneiron/src/context_pack/tests.rs	crate::types::ENTITY_TYPE_TURN,	crate::registry::ENTITY_TYPE_TURN,
crates/oneiron/src/context_pack/tests.rs	crate::types::ENTITY_TYPE_PERSON,	crate::registry::ENTITY_TYPE_PERSON,
crates/oneiron/src/context_pack/tests.rs	crate::types::ENTITY_TYPE_PERSON,	crate::registry::ENTITY_TYPE_PERSON,
crates/oneiron/src/context_pack/tests.rs	crate::types::ENTITY_TYPE_TURN,	crate::registry::ENTITY_TYPE_TURN,
crates/oneiron/src/context_pack/tests.rs	crate::types::ENTITY_TYPE_TURN,	crate::registry::ENTITY_TYPE_TURN,
crates/oneiron/src/context_pack/tests.rs	crate::types::ENTITY_TYPE_FACET,	crate::registry::ENTITY_TYPE_FACET,
crates/oneiron/src/context_pack/tests.rs	crate::types::ENTITY_TYPE_SUMMARY,	crate::registry::ENTITY_TYPE_SUMMARY,
crates/oneiron/src/context_pack/tests.rs	crate::types::ENTITY_TYPE_SUMMARY,	crate::registry::ENTITY_TYPE_SUMMARY,
crates/oneiron/src/context_pack/tests.rs	crate::types::ENTITY_TYPE_TURN,	crate::registry::ENTITY_TYPE_TURN,
crates/oneiron/src/context_pack/tests.rs	crate::types::ENTITY_TYPE_PERSON,	crate::registry::ENTITY_TYPE_PERSON,
crates/oneiron/src/context_pack/tests.rs	crate::types::ENTITY_TYPE_PERSON,	crate::registry::ENTITY_TYPE_PERSON,
crates/oneiron/src/context_pack/tests.rs	crate::types::ENTITY_TYPE_PERSON,	crate::registry::ENTITY_TYPE_PERSON,
crates/oneiron/src/context_pack/tests.rs	crate::types::ENTITY_TYPE_PERSON,	crate::registry::ENTITY_TYPE_PERSON,
crates/oneiron/src/context_pack/tests.rs	crate::types::ENTITY_TYPE_TURN,	crate::registry::ENTITY_TYPE_TURN,
crates/oneiron/src/context_pack/tests.rs	crate::types::ENTITY_TYPE_TURN,	crate::registry::ENTITY_TYPE_TURN,
crates/oneiron/src/context_pack/tests.rs	crate::types::ENTITY_TYPE_PERSON,	crate::registry::ENTITY_TYPE_PERSON,
crates/oneiron/src/context_pack/tests.rs	crate::types::ENTITY_TYPE_TURN,	crate::registry::ENTITY_TYPE_TURN,
crates/oneiron/src/critic/tests.rs	crate::types::ENTITY_TYPE_TASK,	crate::registry::ENTITY_TYPE_TASK,
crates/oneiron/src/deletion.rs	header[0] = crate::types::ENTITY_TYPE_REDACTION_AUDIT;	header[0] = crate::registry::ENTITY_TYPE_REDACTION_AUDIT;
crates/oneiron/src/embed.rs	if header.entity_type != crate::types::ENTITY_TYPE_CLAIM {	if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
crates/oneiron/src/gate/tests.rs	payload.push(crate::types::ENTITY_TYPE_AUTHORITY_LOG);	payload.push(crate::registry::ENTITY_TYPE_AUTHORITY_LOG);
crates/oneiron/src/gate/tests.rs	payload.push(crate::types::ENTITY_TYPE_CLAIM);	payload.push(crate::registry::ENTITY_TYPE_CLAIM);
crates/oneiron/src/gate/tests.rs	let type_key = Store::encode_type_key(crate::types::ENTITY_TYPE_CLAIM, id);	let type_key = Store::encode_type_key(crate::registry::ENTITY_TYPE_CLAIM, id);
crates/oneiron/src/gate/tests.rs	crate::types::ENTITY_TYPE_PERSON,	crate::registry::ENTITY_TYPE_PERSON,
crates/oneiron/src/gate/tests.rs	blob.push(crate::types::ENTITY_TYPE_CLAIM);	blob.push(crate::registry::ENTITY_TYPE_CLAIM);
crates/oneiron/src/gate/tests.rs	crate::types::ENTITY_TYPE_PERSON,	crate::registry::ENTITY_TYPE_PERSON,
crates/oneiron/src/gate/tests.rs	crate::types::ENTITY_TYPE_PERSON,	crate::registry::ENTITY_TYPE_PERSON,
crates/oneiron/src/gate/tests.rs	assert_eq!(hydrated.entity_type, crate::types::ENTITY_TYPE_CLAIM);	assert_eq!(hydrated.entity_type, crate::registry::ENTITY_TYPE_CLAIM);
crates/oneiron/src/gate/tests.rs	crate::types::ENTITY_TYPE_TURN,	crate::registry::ENTITY_TYPE_TURN,
crates/oneiron/src/gate/tests.rs	crate::types::ENTITY_TYPE_PERSON,	crate::registry::ENTITY_TYPE_PERSON,
crates/oneiron/src/gate/tests.rs	crate::types::ENTITY_TYPE_FACET,	crate::registry::ENTITY_TYPE_FACET,
crates/oneiron/src/gate/tests.rs	crate::types::ENTITY_TYPE_PERSON,	crate::registry::ENTITY_TYPE_PERSON,
crates/oneiron/src/gate/tests.rs	crate::types::ENTITY_TYPE_PERSON,	crate::registry::ENTITY_TYPE_PERSON,
crates/oneiron/src/gate/tests.rs	crate::types::ENTITY_TYPE_TURN,	crate::registry::ENTITY_TYPE_TURN,
crates/oneiron/src/gate/tests.rs	crate::types::ENTITY_TYPE_PERSON,	crate::registry::ENTITY_TYPE_PERSON,
crates/oneiron/src/gate/tests.rs	entity(kept_seed, crate::types::ENTITY_TYPE_TURN, 1.0),	entity(kept_seed, crate::registry::ENTITY_TYPE_TURN, 1.0),
crates/oneiron/src/gate/tests.rs	entity(denied_seed, crate::types::ENTITY_TYPE_CLAIM, 0.9),	entity(denied_seed, crate::registry::ENTITY_TYPE_CLAIM, 0.9),
crates/oneiron/src/gate/tests.rs	crate::types::ENTITY_TYPE_PERSON,	crate::registry::ENTITY_TYPE_PERSON,
crates/oneiron/src/gate/tests.rs	crate::types::ENTITY_TYPE_PERSON,	crate::registry::ENTITY_TYPE_PERSON,
crates/oneiron/src/gate/tests.rs	crate::types::ENTITY_TYPE_FACET,	crate::registry::ENTITY_TYPE_FACET,
crates/oneiron/src/gate/tests.rs	crate::types::ENTITY_TYPE_TURN,	crate::registry::ENTITY_TYPE_TURN,
crates/oneiron/src/gate/tests.rs	crate::types::ENTITY_TYPE_FACET,	crate::registry::ENTITY_TYPE_FACET,
crates/oneiron/src/gate/tests.rs	crate::types::ENTITY_TYPE_TASK_LIST,	crate::registry::ENTITY_TYPE_TASK_LIST,
crates/oneiron/src/gate/tests.rs	.put_replicated(&id, crate::types::ENTITY_TYPE_CLAIM, test_time(5), 5, &data)	.put_replicated(&id, crate::registry::ENTITY_TYPE_CLAIM, test_time(5), 5, &data)
crates/oneiron/src/gate/tests.rs	.put_replicated(&id, crate::types::ENTITY_TYPE_CLAIM, test_time(5), 5, &data)	.put_replicated(&id, crate::registry::ENTITY_TYPE_CLAIM, test_time(5), 5, &data)
crates/oneiron/src/gate/tests.rs	crate::types::ENTITY_TYPE_CLAIM,	crate::registry::ENTITY_TYPE_CLAIM,
crates/oneiron/src/gate/tests.rs	crate::types::ENTITY_TYPE_CLAIM,	crate::registry::ENTITY_TYPE_CLAIM,
crates/oneiron/src/graph_fs/tests.rs	entity_type: crate::types::ENTITY_TYPE_POLICY_MANIFEST,	entity_type: crate::registry::ENTITY_TYPE_POLICY_MANIFEST,
crates/oneiron/src/lens/tests.rs	crate::types::ENTITY_TYPE_PERSON,	crate::registry::ENTITY_TYPE_PERSON,
crates/oneiron/src/pipeline/tests.rs	(crate::types::ENTITY_TYPE_SESSION, 28.0),	(crate::registry::ENTITY_TYPE_SESSION, 28.0),
crates/oneiron/src/pipeline/tests.rs	(crate::types::ENTITY_TYPE_MESSAGE, 28.0),	(crate::registry::ENTITY_TYPE_MESSAGE, 28.0),
crates/oneiron/src/pipeline/tests.rs	(crate::types::ENTITY_TYPE_PERSON, 365.0),	(crate::registry::ENTITY_TYPE_PERSON, 365.0),
crates/oneiron/src/pipeline/tests.rs	(crate::types::ENTITY_TYPE_RELATIONSHIP, 180.0),	(crate::registry::ENTITY_TYPE_RELATIONSHIP, 180.0),
crates/oneiron/src/pipeline/tests.rs	(crate::types::ENTITY_TYPE_SKILL, 90.0),	(crate::registry::ENTITY_TYPE_SKILL, 90.0),
crates/oneiron/src/pipeline/tests.rs	(crate::types::ENTITY_TYPE_PLACE, 180.0),	(crate::registry::ENTITY_TYPE_PLACE, 180.0),
crates/oneiron/src/pipeline/tests.rs	(crate::types::ENTITY_TYPE_ASSET_TEXT, 90.0),	(crate::registry::ENTITY_TYPE_ASSET_TEXT, 90.0),
crates/oneiron/src/pipeline/tests.rs	(crate::types::ENTITY_TYPE_CONVERSATION, 30.0),	(crate::registry::ENTITY_TYPE_CONVERSATION, 30.0),
crates/oneiron/src/pipeline/tests.rs	(crate::types::ENTITY_TYPE_ORG, 180.0),	(crate::registry::ENTITY_TYPE_ORG, 180.0),
crates/oneiron/src/pipeline/tests.rs	(crate::types::ENTITY_TYPE_WORLD, 180.0),	(crate::registry::ENTITY_TYPE_WORLD, 180.0),
crates/oneiron/src/pipeline/tests.rs	(crate::types::ENTITY_TYPE_ASSET, 90.0),	(crate::registry::ENTITY_TYPE_ASSET, 90.0),
crates/oneiron/src/pipeline/tests.rs	(crate::types::ENTITY_TYPE_NOTIFICATION, 7.0),	(crate::registry::ENTITY_TYPE_NOTIFICATION, 7.0),
crates/oneiron/src/pipeline/tests.rs	(crate::types::ENTITY_TYPE_TASK_LIST, 30.0),	(crate::registry::ENTITY_TYPE_TASK_LIST, 30.0),
crates/oneiron/src/pipeline/tests.rs	(crate::types::ENTITY_TYPE_TASK, 30.0),	(crate::registry::ENTITY_TYPE_TASK, 30.0),
crates/oneiron/src/pipeline/tests.rs	(crate::types::ENTITY_TYPE_MACHINE, 180.0),	(crate::registry::ENTITY_TYPE_MACHINE, 180.0),
crates/oneiron/src/pipeline/tests.rs	(crate::types::ENTITY_TYPE_CODE_ARTIFACT, 90.0),	(crate::registry::ENTITY_TYPE_CODE_ARTIFACT, 90.0),
crates/oneiron/src/pipeline/tests.rs	(crate::types::ENTITY_TYPE_REDACTION_AUDIT, 365.0),	(crate::registry::ENTITY_TYPE_REDACTION_AUDIT, 365.0),
crates/oneiron/src/pipeline/tests.rs	(crate::types::ENTITY_TYPE_MODEL, 180.0),	(crate::registry::ENTITY_TYPE_MODEL, 180.0),
crates/oneiron/src/pipeline/tests.rs	(crate::types::ENTITY_TYPE_POLICY_MANIFEST, 365.0),	(crate::registry::ENTITY_TYPE_POLICY_MANIFEST, 365.0),
crates/oneiron/src/pipeline/tests.rs	(crate::types::ENTITY_TYPE_FEDERATION_GRANT, 365.0),	(crate::registry::ENTITY_TYPE_FEDERATION_GRANT, 365.0),
crates/oneiron/src/pipeline/tests.rs	(crate::types::ENTITY_TYPE_ACCESS_GRANT, 365.0),	(crate::registry::ENTITY_TYPE_ACCESS_GRANT, 365.0),
crates/oneiron/src/pipeline/tests.rs	(crate::types::ENTITY_TYPE_COUNTERPARTY_CONTACT, 365.0),	(crate::registry::ENTITY_TYPE_COUNTERPARTY_CONTACT, 365.0),
crates/oneiron/src/pipeline/tests.rs	(crate::types::ENTITY_TYPE_OUTBOUND_GRANT, 365.0),	(crate::registry::ENTITY_TYPE_OUTBOUND_GRANT, 365.0),
crates/oneiron/src/pipeline/tests.rs	(crate::types::ENTITY_TYPE_PSYCH_PROFILE, 365.0),	(crate::registry::ENTITY_TYPE_PSYCH_PROFILE, 365.0),
crates/oneiron/src/pipeline/tests.rs	retrieval_recency_half_life_days_for_type(crate::types::ENTITY_TYPE_PERSON)	retrieval_recency_half_life_days_for_type(crate::registry::ENTITY_TYPE_PERSON)
crates/oneiron/src/receipt/tests.rs	crate::types::ENTITY_TYPE_CLAIM	crate::registry::ENTITY_TYPE_CLAIM
crates/oneiron/src/receipt/tests.rs	crate::types::ENTITY_TYPE_SUMMARY	crate::registry::ENTITY_TYPE_SUMMARY
crates/oneiron/src/store.rs	const POST_DYNAMIC_STATIC_KIND_BYTES: &[u8] = &[crate::types::ENTITY_TYPE_BLOB_ARTIFACT];	const POST_DYNAMIC_STATIC_KIND_BYTES: &[u8] = &[crate::registry::ENTITY_TYPE_BLOB_ARTIFACT];
crates/oneiron/src/sync/bridge.rs	let quota_debit = if header.entity_type == crate::types::ENTITY_TYPE_REDACTION_AUDIT {	let quota_debit = if header.entity_type == crate::registry::ENTITY_TYPE_REDACTION_AUDIT {
crates/oneiron/src/sync/bridge/tests.rs	crate::types::ENTITY_TYPE_CLAIM,	crate::registry::ENTITY_TYPE_CLAIM,
crates/oneiron/src/sync/window.rs	blob.first().copied() == Some(crate::types::ENTITY_TYPE_REDACTION_AUDIT);	blob.first().copied() == Some(crate::registry::ENTITY_TYPE_REDACTION_AUDIT);
crates/oneiron/src/sync/window.rs	if header.entity_type == crate::types::ENTITY_TYPE_REDACTION_AUDIT	if header.entity_type == crate::registry::ENTITY_TYPE_REDACTION_AUDIT
crates/oneiron/src/sync/window.rs	let result = if header.entity_type == crate::types::ENTITY_TYPE_REDACTION_AUDIT {	let result = if header.entity_type == crate::registry::ENTITY_TYPE_REDACTION_AUDIT {
crates/oneiron/src/sync/window.rs	return raw.first().copied() == Some(crate::types::ENTITY_TYPE_REDACTION_AUDIT);	return raw.first().copied() == Some(crate::registry::ENTITY_TYPE_REDACTION_AUDIT);
crates/oneiron/src/sync/window.rs	if header.entity_type != crate::types::ENTITY_TYPE_REDACTION_AUDIT {	if header.entity_type != crate::registry::ENTITY_TYPE_REDACTION_AUDIT {
crates/oneiron/src/tests.rs	crate::types::ENTITY_TYPE_CLAIM,	crate::registry::ENTITY_TYPE_CLAIM,
crates/oneiron/src/tests.rs	crate::types::ENTITY_TYPE_CLAIM,	crate::registry::ENTITY_TYPE_CLAIM,
crates/oneiron/src/tests.rs	crate::types::ENTITY_TYPE_CLAIM,	crate::registry::ENTITY_TYPE_CLAIM,
crates/oneiron/src/tests.rs	crate::types::ENTITY_TYPE_CLAIM,	crate::registry::ENTITY_TYPE_CLAIM,
crates/oneiron/src/tests.rs	crate::types::ENTITY_TYPE_CLAIM,	crate::registry::ENTITY_TYPE_CLAIM,
crates/oneiron/src/vault/tests.rs	vault.count_entities_by_type(crate::types::ENTITY_TYPE_MACHINE)?,	vault.count_entities_by_type(crate::registry::ENTITY_TYPE_MACHINE)?,
crates/oneiron/tests/sync_harness/mod.rs	.entities_by_type(oneiron::types::ENTITY_TYPE_REDACTION_AUDIT)	.entities_by_type(oneiron::registry::ENTITY_TYPE_REDACTION_AUDIT)
crates/oneiron/tests/sync_sweep_executor.rs	.entities_by_type(oneiron::types::ENTITY_TYPE_REDACTION_AUDIT)	.entities_by_type(oneiron::registry::ENTITY_TYPE_REDACTION_AUDIT)
crates/oneiron/tests/sync_sweep_executor.rs	.entities_by_type(oneiron::types::ENTITY_TYPE_REDACTION_AUDIT)	.entities_by_type(oneiron::registry::ENTITY_TYPE_REDACTION_AUDIT)
crates/oneiron/src/pipeline/tests.rs	use crate::types::{ENTITY_TYPE_EVENT, ENTITY_TYPE_FACET, ENTITY_TYPE_TURN};	use crate::registry::{ENTITY_TYPE_EVENT, ENTITY_TYPE_FACET, ENTITY_TYPE_TURN};
crates/oneiron/src/repo_mutation/tests.rs	use crate::types::ENTITY_TYPE_TASK;	use crate::registry::ENTITY_TYPE_TASK;
crates/oneiron-server/src/projection/tests.rs	use oneiron::types::ENTITY_TYPE_REGISTRY;	use oneiron::registry::ENTITY_TYPE_REGISTRY;
crates/oneiron/tests/gate_regression.rs	use oneiron::types::{ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST};	use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST};
crates/oneiron/tests/sync_edge_kind_gating.rs	use oneiron::types::ENTITY_TYPE_POLICY_MANIFEST;	use oneiron::registry::ENTITY_TYPE_POLICY_MANIFEST;

## frag-edit

## comment
crates/oneiron/src/types.rs:72-76	crates/oneiron/src/registry.rs
crates/oneiron/src/types.rs:83-85	crates/oneiron/src/registry.rs

## add
crates/oneiron/src/registry.rs	//! Entity-type registry: type bytes, bands, classification, the registry array + lookups/validators.
