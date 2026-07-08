## crate
crates/oneiron

## flat-name-check
yes

## allowed
crates/oneiron/src/access_grant.rs
crates/oneiron/src/affect.rs
crates/oneiron/src/affect/coping.rs
crates/oneiron/src/agent_def.rs
crates/oneiron/src/analyzer/manifest.rs
crates/oneiron/src/anchored_annotation.rs
crates/oneiron/src/artifact_hosting.rs
crates/oneiron/src/batch.rs
crates/oneiron/src/batch/export/tests.rs
crates/oneiron/src/batch/secret_scan.rs
crates/oneiron/src/blob_artifact.rs
crates/oneiron/src/bm25.rs
crates/oneiron/src/channel_identity.rs
crates/oneiron/src/channel_identity_lifecycle.rs
crates/oneiron/src/channel_identity_lifecycle/tests.rs
crates/oneiron/src/channel_identity_provider.rs
crates/oneiron/src/claim.rs
crates/oneiron/src/code_artifact.rs
crates/oneiron/src/code_revision.rs
crates/oneiron/src/code_run.rs
crates/oneiron/src/code_symbol.rs
crates/oneiron/src/codebase.rs
crates/oneiron/src/companion.rs
crates/oneiron/src/context_pack.rs
crates/oneiron/src/counterparty_contact.rs
crates/oneiron/src/critic.rs
crates/oneiron/src/deletion.rs
crates/oneiron/src/delivery_window/tests.rs
crates/oneiron/src/dreamer_runner.rs
crates/oneiron/src/dreamer_tournament.rs
crates/oneiron/src/edit_roundtrip.rs
crates/oneiron/src/edit_settle.rs
crates/oneiron/src/embed.rs
crates/oneiron/src/embed/tests.rs
crates/oneiron/src/engine_executor.rs
crates/oneiron/src/entity_id.rs
crates/oneiron/src/error.rs
crates/oneiron/src/federation.rs
crates/oneiron/src/fusion.rs
crates/oneiron/src/gate.rs
crates/oneiron/src/graph_fs.rs
crates/oneiron/src/hnsw.rs
crates/oneiron/src/identity_reputation.rs
crates/oneiron/src/inbox.rs
crates/oneiron/src/ingest.rs
crates/oneiron/src/lens.rs
crates/oneiron/src/lib.rs
crates/oneiron/src/llm.rs
crates/oneiron/src/maintain.rs
crates/oneiron/src/maintain/tests.rs
crates/oneiron/src/off_record.rs
crates/oneiron/src/outbound.rs
crates/oneiron/src/outbound/tests.rs
crates/oneiron/src/outbound_grant.rs
crates/oneiron/src/persona_snapshot.rs
crates/oneiron/src/pipeline.rs
crates/oneiron/src/policy_model.rs
crates/oneiron/src/policy_model/tests.rs
crates/oneiron/src/ppr.rs
crates/oneiron/src/prompt.rs
crates/oneiron/src/provenance.rs
crates/oneiron/src/psych_profile.rs
crates/oneiron/src/receipt.rs
crates/oneiron/src/repo_mutation.rs
crates/oneiron/src/run_tree.rs
crates/oneiron/src/run_tree/tests.rs
crates/oneiron/src/serialize/tests.rs
crates/oneiron/src/settings.rs
crates/oneiron/src/skill.rs
crates/oneiron/src/store.rs
crates/oneiron/src/store/tests.rs
crates/oneiron/src/surface_event.rs
crates/oneiron/src/sweep.rs
crates/oneiron/src/sync/bridge.rs
crates/oneiron/src/sync/client/tests.rs
crates/oneiron/src/sync/convergence_props_internal.rs
crates/oneiron/src/sync/lease.rs
crates/oneiron/src/sync/loro_support.rs
crates/oneiron/src/sync/quarantine.rs
crates/oneiron/src/sync/quarantine/tests.rs
crates/oneiron/src/sync/queue.rs
crates/oneiron/src/sync/quota.rs
crates/oneiron/src/sync/selector.rs
crates/oneiron/src/sync/window.rs
crates/oneiron/src/tests.rs
crates/oneiron/src/types.rs
crates/oneiron/src/vault.rs

## error-literal
crates/oneiron/src/entity_id.rs

## decl
+ pub mod entity_id
+ pub use crate :: entity_id :: { EntityId }
+ pub use crate :: types :: { Bm25RankProfile , ClaimCandidate , ContextEntity , ContextPack , ContextPackRetrievalBudget , DecodedEdgeValue , EIRI_CONTEXT_VERSION_V4 , EdgeActorClass , EdgeConfirmationStatus , EdgeInfo , EdgeKind , EdgeProvenanceFlags , EdgeValueLayout , EiriCompanionAssembly , EiriMemoryBoard , EiriMemoryBoardBudget , EiriMemoryBoardRow , EiriMemoryBoardSlot , EiriMemoryBoardSource , EiriSessionRagState , EmptyContext , EmptyReason , FieldProfile , HnswConfig , HydratedShortIdDeletion , HydratedShortIdDeletionReason , HydratedShortIdDeletionSource , MemoryOperationKind , MemoryTimeline , MemoryTimelineRecord , MemoryTimelineRecordState , NamedMemoryVerb , NotificationItem , PackFormat , PackItemTokenStats , PackSectionTokenStats , PackStats , PackTokenStats , ResumeBudget , ResumeBundle , ScoredEntity , SessionContext , Signal , TemporalAnchorMode , TemporalGranularity , TextAnalyzerConfig , TextIndexOptions , TimeRange , TokenAllocation , UnprocessedItem , Vad , VadAnnotation , VadAnnotationSource , VadComponent , VaultConfig , WriteActor , WriteEnvelope , WriteProvenance }
- pub use crate :: types :: { Bm25RankProfile , ClaimCandidate , ContextEntity , ContextPack , ContextPackRetrievalBudget , DecodedEdgeValue , EIRI_CONTEXT_VERSION_V4 , EdgeActorClass , EdgeConfirmationStatus , EdgeInfo , EdgeKind , EdgeProvenanceFlags , EdgeValueLayout , EiriCompanionAssembly , EiriMemoryBoard , EiriMemoryBoardBudget , EiriMemoryBoardRow , EiriMemoryBoardSlot , EiriMemoryBoardSource , EiriSessionRagState , EmptyContext , EmptyReason , EntityId , FieldProfile , HnswConfig , HydratedShortIdDeletion , HydratedShortIdDeletionReason , HydratedShortIdDeletionSource , MemoryOperationKind , MemoryTimeline , MemoryTimelineRecord , MemoryTimelineRecordState , NamedMemoryVerb , NotificationItem , PackFormat , PackItemTokenStats , PackSectionTokenStats , PackStats , PackTokenStats , ResumeBudget , ResumeBundle , ScoredEntity , SessionContext , Signal , TemporalAnchorMode , TemporalGranularity , TextAnalyzerConfig , TextIndexOptions , TimeRange , TokenAllocation , UnprocessedItem , Vad , VadAnnotation , VadAnnotationSource , VadComponent , VaultConfig , WriteActor , WriteEnvelope , WriteProvenance }

## impl-delta
- crates/oneiron/src/types.rs	impl EntityId
- crates/oneiron/src/types.rs	impl ForeignWorldId
- crates/oneiron/src/types.rs	impl LocalWorldId
- crates/oneiron/src/types.rs	impl TryFrom < EntityId > for ForeignWorldId
- crates/oneiron/src/types.rs	impl TryFrom < EntityId > for LocalWorldId
+ crates/oneiron/src/entity_id.rs	impl EntityId
+ crates/oneiron/src/entity_id.rs	impl ForeignWorldId
+ crates/oneiron/src/entity_id.rs	impl LocalWorldId
+ crates/oneiron/src/entity_id.rs	impl TryFrom < EntityId > for ForeignWorldId
+ crates/oneiron/src/entity_id.rs	impl TryFrom < EntityId > for LocalWorldId

## edit
crates/oneiron/src/batch/secret_scan.rs	id: crate::types::EntityId::now(),	id: crate::entity_id::EntityId::now(),
crates/oneiron/src/code_run.rs	crate::types::bytes_to_hex_lower(&raw_sha256)	crate::entity_id::bytes_to_hex_lower(&raw_sha256)
crates/oneiron/src/code_run.rs	crate::types::bytes_to_hex_lower(&output.raw_sha256)	crate::entity_id::bytes_to_hex_lower(&output.raw_sha256)
crates/oneiron/src/companion.rs	if bytes.len() != crate::types::ENTITY_ID_LEN {	if bytes.len() != crate::entity_id::ENTITY_ID_LEN {
crates/oneiron/src/companion.rs	let mut arr = [0_u8; crate::types::ENTITY_ID_LEN];	let mut arr = [0_u8; crate::entity_id::ENTITY_ID_LEN];
crates/oneiron/src/run_tree/tests.rs	crate::types::bytes_to_hex_lower(id.as_bytes())	crate::entity_id::bytes_to_hex_lower(id.as_bytes())
crates/oneiron/src/sync/quarantine.rs	) -> Option<crate::types::EntityId> {	) -> Option<crate::entity_id::EntityId> {
crates/oneiron/src/sync/quarantine.rs	QuarantineContainer::Entities => crate::types::EntityId::from_hex(crdt_key).ok(),	QuarantineContainer::Entities => crate::entity_id::EntityId::from_hex(crdt_key).ok(),
crates/oneiron/src/sync/quarantine.rs	pub(crate) fn remat_marker_key(window_key: &str, id: &crate::types::EntityId) -> String {	pub(crate) fn remat_marker_key(window_key: &str, id: &crate::entity_id::EntityId) -> String {
crates/oneiron/src/sync/quarantine.rs	fn replay_remat_marker_provenance_key(window_key: &str, id: &crate::types::EntityId) -> String {	fn replay_remat_marker_provenance_key(window_key: &str, id: &crate::entity_id::EntityId) -> String {
crates/oneiron/src/sync/quarantine.rs	id: &crate::types::EntityId,	id: &crate::entity_id::EntityId,
crates/oneiron/src/sync/quarantine.rs	id: &crate::types::EntityId,	id: &crate::entity_id::EntityId,
crates/oneiron/src/sync/quarantine.rs	id: &crate::types::EntityId,	id: &crate::entity_id::EntityId,
crates/oneiron/src/sync/quarantine.rs	id: &crate::types::EntityId,	id: &crate::entity_id::EntityId,
crates/oneiron/src/sync/quarantine.rs	id: &crate::types::EntityId,	id: &crate::entity_id::EntityId,
crates/oneiron/src/sync/quarantine.rs	id: &crate::types::EntityId,	id: &crate::entity_id::EntityId,
crates/oneiron/src/sync/quarantine.rs	id: &crate::types::EntityId,	id: &crate::entity_id::EntityId,
crates/oneiron/src/sync/quarantine.rs	pub(crate) fn reassert_marker_key(window_key: &str, id: &crate::types::EntityId) -> String {	pub(crate) fn reassert_marker_key(window_key: &str, id: &crate::entity_id::EntityId) -> String {
crates/oneiron/src/sync/quarantine.rs	id: &crate::types::EntityId,	id: &crate::entity_id::EntityId,
crates/oneiron/src/sync/quarantine.rs	type ReassertMarker = (String, crate::types::EntityId, Vec<u8>);	type ReassertMarker = (String, crate::entity_id::EntityId, Vec<u8>);
crates/oneiron/src/sync/quarantine.rs	match crate::types::EntityId::from_hex(hex) {	match crate::entity_id::EntityId::from_hex(hex) {
crates/oneiron/src/sync/quarantine.rs	id: &crate::types::EntityId,	id: &crate::entity_id::EntityId,
crates/oneiron/src/tests.rs	crate::types::bytes_to_hex_lower(&[0x61; 16])	crate::entity_id::bytes_to_hex_lower(&[0x61; 16])
crates/oneiron/src/tests.rs	crate::types::bytes_to_hex_lower(&[0x62; 16])	crate::entity_id::bytes_to_hex_lower(&[0x62; 16])
crates/oneiron/src/access_grant.rs	use crate::types::EntityId;	use crate::entity_id::EntityId;
crates/oneiron/src/analyzer/manifest.rs	use crate::types::bytes_to_hex_lower;	use crate::entity_id::bytes_to_hex_lower;
crates/oneiron/src/artifact_hosting.rs	use crate::types::EntityId;	use crate::entity_id::EntityId;
crates/oneiron/src/channel_identity.rs	use crate::types::EntityId;	use crate::entity_id::EntityId;
crates/oneiron/src/channel_identity_provider.rs	use crate::types::{EntityId, bytes_to_hex_lower};	use crate::entity_id::{EntityId, bytes_to_hex_lower};
crates/oneiron/src/counterparty_contact.rs	use crate::types::{ENTITY_ID_LEN, EntityId};	use crate::entity_id::{ENTITY_ID_LEN, EntityId};
crates/oneiron/src/critic.rs	use crate::types::EntityId;	use crate::entity_id::EntityId;
crates/oneiron/src/deletion.rs	use crate::types::EntityId;	use crate::entity_id::EntityId;
crates/oneiron/src/delivery_window/tests.rs	use crate::types::EntityId;	use crate::entity_id::EntityId;
crates/oneiron/src/edit_roundtrip.rs	use crate::types::EntityId;	use crate::entity_id::EntityId;
crates/oneiron/src/embed.rs	use crate::types::EntityId;	use crate::entity_id::EntityId;
crates/oneiron/src/federation.rs	use crate::types::EntityId;	use crate::entity_id::EntityId;
crates/oneiron/src/identity_reputation.rs	use crate::types::EntityId;	use crate::entity_id::EntityId;
crates/oneiron/src/llm.rs	use crate::types::bytes_to_hex_lower;	use crate::entity_id::bytes_to_hex_lower;
crates/oneiron/src/maintain.rs	use crate::types::{EntityId, parse_entity_id};	use crate::entity_id::{EntityId, parse_entity_id};
crates/oneiron/src/off_record.rs	use crate::types::EntityId;	use crate::entity_id::EntityId;
crates/oneiron/src/outbound.rs	use crate::types::EntityId;	use crate::entity_id::EntityId;
crates/oneiron/src/outbound_grant.rs	use crate::types::{ENTITY_ID_LEN, EntityId};	use crate::entity_id::{ENTITY_ID_LEN, EntityId};
crates/oneiron/src/policy_model.rs	use crate::types::bytes_to_hex_lower;	use crate::entity_id::bytes_to_hex_lower;
crates/oneiron/src/prompt.rs	use crate::types::bytes_to_hex_lower;	use crate::entity_id::bytes_to_hex_lower;
crates/oneiron/src/run_tree.rs	use crate::types::bytes_to_hex_lower;	use crate::entity_id::bytes_to_hex_lower;
crates/oneiron/src/settings.rs	use crate::types::EntityId;	use crate::entity_id::EntityId;
crates/oneiron/src/surface_event.rs	use crate::types::EntityId;	use crate::entity_id::EntityId;
crates/oneiron/src/sync/lease.rs	use crate::types::EntityId;	use crate::entity_id::EntityId;
crates/oneiron/src/sync/loro_support.rs	use crate::types::EntityId;	use crate::entity_id::EntityId;
crates/oneiron/src/sync/queue.rs	use crate::types::EntityId;	use crate::entity_id::EntityId;
crates/oneiron/src/sync/quota.rs	use crate::types::bytes_to_hex_lower;	use crate::entity_id::bytes_to_hex_lower;

## frag-edit
crates/oneiron/src/types.rs	/// use oneiron::types::{EntityId, ForeignWorldId};	/// use oneiron::entity_id::{EntityId, ForeignWorldId};

## comment

## add
crates/oneiron/src/entity_id.rs	//! `EntityId` + world-id newtypes + id parsing/hex.
crates/oneiron/src/entity_id.rs	#[cfg(test)]
crates/oneiron/src/entity_id.rs	mod tests {
crates/oneiron/src/entity_id.rs	}
