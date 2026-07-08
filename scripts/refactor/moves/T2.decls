## crate
crates/oneiron

## flat-name-check
yes

## allowed
crates/oneiron/src/access_grant.rs
crates/oneiron/src/analyzer/manifest.rs
crates/oneiron/src/artifact_hosting.rs
crates/oneiron/src/channel_identity.rs
crates/oneiron/src/code_run.rs
crates/oneiron/src/critic.rs
crates/oneiron/src/deletion.rs
crates/oneiron/src/delivery_window.rs
crates/oneiron/src/edit_roundtrip.rs
crates/oneiron/src/embed.rs
crates/oneiron/src/entity_id.rs
crates/oneiron/src/federation.rs
crates/oneiron/src/identity_reputation.rs
crates/oneiron/src/lib.rs
crates/oneiron/src/llm.rs
crates/oneiron/src/off_record.rs
crates/oneiron/src/outbound.rs
crates/oneiron/src/policy_model.rs
crates/oneiron/src/prompt.rs
crates/oneiron/src/run_tree.rs
crates/oneiron/src/secret_scan.rs
crates/oneiron/src/settings.rs
crates/oneiron/src/surface_event.rs
crates/oneiron/src/sync/lease.rs
crates/oneiron/src/sync/loro_support.rs
crates/oneiron/src/sync/quarantine.rs
crates/oneiron/src/sync/queue.rs
crates/oneiron/src/sync/quota.rs
crates/oneiron/src/sync/window.rs
crates/oneiron/src/tests.rs
crates/oneiron/src/types.rs

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
crates/oneiron/src/code_run.rs	crate::types::bytes_to_hex_lower(&raw_sha256)	crate::entity_id::bytes_to_hex_lower(&raw_sha256)
crates/oneiron/src/code_run.rs	crate::types::bytes_to_hex_lower(&output.raw_sha256)	crate::entity_id::bytes_to_hex_lower(&output.raw_sha256)
crates/oneiron/src/run_tree.rs	crate::types::bytes_to_hex_lower(id.as_bytes())	crate::entity_id::bytes_to_hex_lower(id.as_bytes())
crates/oneiron/src/secret_scan.rs	id: crate::types::EntityId::now(),	id: crate::entity_id::EntityId::now(),
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

## frag-edit
crates/oneiron/src/types.rs	/// use oneiron::types::{EntityId, ForeignWorldId};	/// use oneiron::entity_id::{EntityId, ForeignWorldId};

## comment

## add
crates/oneiron/src/entity_id.rs	//! `EntityId` + world-id newtypes + id parsing/hex.
crates/oneiron/src/entity_id.rs	#[cfg(test)]
crates/oneiron/src/entity_id.rs	mod tests {
crates/oneiron/src/entity_id.rs	}
