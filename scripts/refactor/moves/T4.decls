## crate
crates/oneiron

## flat-name-check
yes

## allowed
crates/oneiron/src/claim.rs
crates/oneiron/src/context_pack.rs
crates/oneiron/src/edge.rs
crates/oneiron/src/lib.rs
crates/oneiron/src/pipeline.rs
crates/oneiron/src/ppr.rs
crates/oneiron/src/sync/bridge.rs
crates/oneiron/src/sync/quarantine.rs
crates/oneiron/src/types.rs
crates/oneiron/src/vault.rs

## error-literal
crates/oneiron/src/edge.rs

## decl
+ pub mod edge
+ pub use crate :: edge :: { DecodedEdgeValue , EdgeActorClass , EdgeConfirmationStatus , EdgeInfo , EdgeKind , EdgeProvenanceFlags , EdgeValueLayout }
+ pub use crate :: types :: { Bm25RankProfile , ClaimCandidate , ContextEntity , ContextPack , ContextPackRetrievalBudget , EIRI_CONTEXT_VERSION_V4 , EiriCompanionAssembly , EiriMemoryBoard , EiriMemoryBoardBudget , EiriMemoryBoardRow , EiriMemoryBoardSlot , EiriMemoryBoardSource , EiriSessionRagState , EmptyContext , EmptyReason , FieldProfile , HnswConfig , HydratedShortIdDeletion , HydratedShortIdDeletionReason , HydratedShortIdDeletionSource , MemoryOperationKind , MemoryTimeline , MemoryTimelineRecord , MemoryTimelineRecordState , NamedMemoryVerb , NotificationItem , PackFormat , PackItemTokenStats , PackSectionTokenStats , PackStats , PackTokenStats , ResumeBudget , ResumeBundle , ScoredEntity , SessionContext , Signal , TemporalAnchorMode , TemporalGranularity , TextAnalyzerConfig , TextIndexOptions , TimeRange , TokenAllocation , UnprocessedItem , VaultConfig , WriteActor , WriteEnvelope , WriteProvenance }
- pub use crate :: types :: { Bm25RankProfile , ClaimCandidate , ContextEntity , ContextPack , ContextPackRetrievalBudget , DecodedEdgeValue , EIRI_CONTEXT_VERSION_V4 , EdgeActorClass , EdgeConfirmationStatus , EdgeInfo , EdgeKind , EdgeProvenanceFlags , EdgeValueLayout , EiriCompanionAssembly , EiriMemoryBoard , EiriMemoryBoardBudget , EiriMemoryBoardRow , EiriMemoryBoardSlot , EiriMemoryBoardSource , EiriSessionRagState , EmptyContext , EmptyReason , FieldProfile , HnswConfig , HydratedShortIdDeletion , HydratedShortIdDeletionReason , HydratedShortIdDeletionSource , MemoryOperationKind , MemoryTimeline , MemoryTimelineRecord , MemoryTimelineRecordState , NamedMemoryVerb , NotificationItem , PackFormat , PackItemTokenStats , PackSectionTokenStats , PackStats , PackTokenStats , ResumeBudget , ResumeBundle , ScoredEntity , SessionContext , Signal , TemporalAnchorMode , TemporalGranularity , TextAnalyzerConfig , TextIndexOptions , TimeRange , TokenAllocation , UnprocessedItem , VaultConfig , WriteActor , WriteEnvelope , WriteProvenance }

## impl-delta
- crates/oneiron/src/types.rs	impl EdgeActorClass
- crates/oneiron/src/types.rs	impl EdgeConfirmationStatus
- crates/oneiron/src/types.rs	impl EdgeKind
- crates/oneiron/src/types.rs	impl EdgeValueLayout
- crates/oneiron/src/types.rs	impl StrictEdgeRecord
+ crates/oneiron/src/edge.rs	impl EdgeActorClass
+ crates/oneiron/src/edge.rs	impl EdgeConfirmationStatus
+ crates/oneiron/src/edge.rs	impl EdgeKind
+ crates/oneiron/src/edge.rs	impl EdgeValueLayout
+ crates/oneiron/src/edge.rs	impl StrictEdgeRecord

## edit
crates/oneiron/src/context_pack.rs	vault.put_edge(&src, crate::types::EdgeKind::Supports, &tgt, 0.7)?;	vault.put_edge(&src, crate::edge::EdgeKind::Supports, &tgt, 0.7)?;
crates/oneiron/src/context_pack.rs	assert_eq!(edges[0].kind, crate::types::EdgeKind::Supports);	assert_eq!(edges[0].kind, crate::edge::EdgeKind::Supports);
crates/oneiron/src/context_pack.rs	vault.put_edge(&src, crate::types::EdgeKind::Supports, &healthy, 0.7)?;	vault.put_edge(&src, crate::edge::EdgeKind::Supports, &healthy, 0.7)?;
crates/oneiron/src/context_pack.rs	let key = Store::encode_edge_key(&src, crate::types::EdgeKind::Mentions, &tgt);	let key = Store::encode_edge_key(&src, crate::edge::EdgeKind::Mentions, &tgt);
crates/oneiron/src/context_pack.rs	let value = crate::types::encode_edge_value(	let value = crate::edge::encode_edge_value(
crates/oneiron/src/context_pack.rs	crate::types::EdgeKind::Mentions,	crate::edge::EdgeKind::Mentions,
crates/oneiron/src/context_pack.rs	let key = Store::encode_edge_key(&small_src, crate::types::EdgeKind::Mentions, &target);	let key = Store::encode_edge_key(&small_src, crate::edge::EdgeKind::Mentions, &target);
crates/oneiron/src/context_pack.rs	Store::encode_edge_key(&bounded_src, crate::types::EdgeKind::Mentions, &target);	Store::encode_edge_key(&bounded_src, crate::edge::EdgeKind::Mentions, &target);
crates/oneiron/src/context_pack.rs	crate::types::EdgeKind::Mentions,	crate::edge::EdgeKind::Mentions,
crates/oneiron/src/context_pack.rs	vault.put_edge(&root, crate::types::EdgeKind::Supports, &neighbor, 1.0)?;	vault.put_edge(&root, crate::edge::EdgeKind::Supports, &neighbor, 1.0)?;
crates/oneiron/src/context_pack.rs	let key = Store::encode_edge_key(&root, crate::types::EdgeKind::Mentions, &tgt);	let key = Store::encode_edge_key(&root, crate::edge::EdgeKind::Mentions, &tgt);
crates/oneiron/src/context_pack.rs	Store::encode_edge_key(&src, crate::types::EdgeKind::Supports, &tgt).to_vec();	Store::encode_edge_key(&src, crate::edge::EdgeKind::Supports, &tgt).to_vec();
crates/oneiron/src/context_pack.rs	Store::encode_edge_key(&src, crate::types::EdgeKind::ChildOf, &tgt).to_vec();	Store::encode_edge_key(&src, crate::edge::EdgeKind::ChildOf, &tgt).to_vec();
crates/oneiron/src/context_pack.rs	truncated_key.push(crate::types::EdgeKind::Supports as u8);	truncated_key.push(crate::edge::EdgeKind::Supports as u8);
crates/oneiron/src/context_pack.rs	reserved_target_key.push(crate::types::EdgeKind::Supports as u8);	reserved_target_key.push(crate::edge::EdgeKind::Supports as u8);
crates/oneiron/src/context_pack.rs	crate::types::EdgeKind::HasFacet,	crate::edge::EdgeKind::HasFacet,
crates/oneiron/src/context_pack.rs	assert_eq!(edges[0].kind, crate::types::EdgeKind::HasFacet);	assert_eq!(edges[0].kind, crate::edge::EdgeKind::HasFacet);
crates/oneiron/src/context_pack.rs	vault.put_edge(&a, crate::types::EdgeKind::Supports, &b, 1.0)?;	vault.put_edge(&a, crate::edge::EdgeKind::Supports, &b, 1.0)?;
crates/oneiron/src/context_pack.rs	vault.put_edge(&b, crate::types::EdgeKind::Supports, &c, 1.0)?;	vault.put_edge(&b, crate::edge::EdgeKind::Supports, &c, 1.0)?;
crates/oneiron/src/context_pack.rs	vault.put_edge(&root, crate::types::EdgeKind::Mentions, &id, 1.0)?;	vault.put_edge(&root, crate::edge::EdgeKind::Mentions, &id, 1.0)?;
crates/oneiron/src/context_pack.rs	vault.put_edge(&root, crate::types::EdgeKind::Mentions, &strongest, 0.9)?;	vault.put_edge(&root, crate::edge::EdgeKind::Mentions, &strongest, 0.9)?;
crates/oneiron/src/context_pack.rs	vault.put_edge(&root, crate::types::EdgeKind::Mentions, &weaker, 0.8)?;	vault.put_edge(&root, crate::edge::EdgeKind::Mentions, &weaker, 0.8)?;
crates/oneiron/src/context_pack.rs	vault.put_edge(&root, crate::types::EdgeKind::Mentions, &id, weight)?;	vault.put_edge(&root, crate::edge::EdgeKind::Mentions, &id, weight)?;
crates/oneiron/src/context_pack.rs	vault.put_edge(&root, crate::types::EdgeKind::Supports, &child, 1.0)?;	vault.put_edge(&root, crate::edge::EdgeKind::Supports, &child, 1.0)?;
crates/oneiron/src/context_pack.rs	vault.put_edge(&a, crate::types::EdgeKind::Supports, &retracted, 0.9)?;	vault.put_edge(&a, crate::edge::EdgeKind::Supports, &retracted, 0.9)?;
crates/oneiron/src/context_pack.rs	vault.put_edge(&a, crate::types::EdgeKind::ClaimOf, &proposed, 1.0)?;	vault.put_edge(&a, crate::edge::EdgeKind::ClaimOf, &proposed, 1.0)?;
crates/oneiron/src/context_pack.rs	vault.put_edge(&a, crate::types::EdgeKind::Supports, &person, 0.8)?;	vault.put_edge(&a, crate::edge::EdgeKind::Supports, &person, 0.8)?;
crates/oneiron/src/context_pack.rs	kind: crate::types::EdgeKind::Supports,	kind: crate::edge::EdgeKind::Supports,
crates/oneiron/src/context_pack.rs	kind: crate::types::EdgeKind::Supports,	kind: crate::edge::EdgeKind::Supports,
crates/oneiron/src/context_pack.rs	vault.put_edge(&source, crate::types::EdgeKind::Supports, &target, 0.7)?;	vault.put_edge(&source, crate::edge::EdgeKind::Supports, &target, 0.7)?;
crates/oneiron/src/context_pack.rs	vault.put_edge(&source, crate::types::EdgeKind::Supports, &target, 0.7)?;	vault.put_edge(&source, crate::edge::EdgeKind::Supports, &target, 0.7)?;
crates/oneiron/src/context_pack.rs	vault.put_edge(&a, crate::types::EdgeKind::Supports, &bad, 0.9)?;	vault.put_edge(&a, crate::edge::EdgeKind::Supports, &bad, 0.9)?;
crates/oneiron/src/context_pack.rs	vault.put_edge(&a, crate::types::EdgeKind::Supports, &b, 0.9)?;	vault.put_edge(&a, crate::edge::EdgeKind::Supports, &b, 0.9)?;
crates/oneiron/src/context_pack.rs	vault.put_edge(&root, crate::types::EdgeKind::ChildOf, &child_of_tgt, 1.0)?;	vault.put_edge(&root, crate::edge::EdgeKind::ChildOf, &child_of_tgt, 1.0)?;
crates/oneiron/src/context_pack.rs	crate::types::EdgeKind::AssignedTo,	crate::edge::EdgeKind::AssignedTo,
crates/oneiron/src/context_pack.rs	vault.put_edge(&root, crate::types::EdgeKind::Opposes, &opposes_tgt, 0.5)?;	vault.put_edge(&root, crate::edge::EdgeKind::Opposes, &opposes_tgt, 0.5)?;
crates/oneiron/src/context_pack.rs	let plant = |tgt: &EntityId, status: crate::types::EdgeConfirmationStatus| -> Result<()> {	let plant = |tgt: &EntityId, status: crate::edge::EdgeConfirmationStatus| -> Result<()> {
crates/oneiron/src/context_pack.rs	let key = Store::encode_edge_key(&root, crate::types::EdgeKind::Supports, tgt);	let key = Store::encode_edge_key(&root, crate::edge::EdgeKind::Supports, tgt);
crates/oneiron/src/context_pack.rs	let value = crate::types::encode_edge_value(	let value = crate::edge::encode_edge_value(
crates/oneiron/src/context_pack.rs	crate::types::EdgeKind::Supports,	crate::edge::EdgeKind::Supports,
crates/oneiron/src/context_pack.rs	Some(crate::types::EdgeProvenanceFlags {	Some(crate::edge::EdgeProvenanceFlags {
crates/oneiron/src/context_pack.rs	actor_class: crate::types::EdgeActorClass::Human,	actor_class: crate::edge::EdgeActorClass::Human,
crates/oneiron/src/context_pack.rs	crate::types::EdgeConfirmationStatus::Retracted,	crate::edge::EdgeConfirmationStatus::Retracted,
crates/oneiron/src/context_pack.rs	crate::types::EdgeConfirmationStatus::Confirmed,	crate::edge::EdgeConfirmationStatus::Confirmed,
crates/oneiron/src/context_pack.rs	vault.put_edge(&live, crate::types::EdgeKind::Supports, &dead_neighbor, 0.9)?;	vault.put_edge(&live, crate::edge::EdgeKind::Supports, &dead_neighbor, 0.9)?;
crates/oneiron/src/context_pack.rs	vault.put_edge(&result, crate::types::EdgeKind::Supports, &neighbor, 1.0)?;	vault.put_edge(&result, crate::edge::EdgeKind::Supports, &neighbor, 1.0)?;
crates/oneiron/src/pipeline.rs	.edge(&a, crate::types::EdgeKind::Supports, &b, 1.0)	.edge(&a, crate::edge::EdgeKind::Supports, &b, 1.0)
crates/oneiron/src/pipeline.rs	.edge(&a, crate::types::EdgeKind::Supports, &b, 1.0)	.edge(&a, crate::edge::EdgeKind::Supports, &b, 1.0)
crates/oneiron/src/pipeline.rs	.edge(&a, crate::types::EdgeKind::Supports, &b, 1.0)	.edge(&a, crate::edge::EdgeKind::Supports, &b, 1.0)
crates/oneiron/src/sync/bridge.rs	crate::types::EdgeActorClass::Human,	crate::edge::EdgeActorClass::Human,
crates/oneiron/src/sync/quarantine.rs	let kind = crate::types::EdgeKind::Mentions;	let kind = crate::edge::EdgeKind::Mentions;
crates/oneiron/src/sync/quarantine.rs	crate::types::EdgeKind::Mentions,	crate::edge::EdgeKind::Mentions,
crates/oneiron/src/sync/quarantine.rs	let kind = crate::types::EdgeKind::Mentions;	let kind = crate::edge::EdgeKind::Mentions;
crates/oneiron/src/sync/quarantine.rs	let kind = crate::types::EdgeKind::Mentions;	let kind = crate::edge::EdgeKind::Mentions;
crates/oneiron/src/sync/quarantine.rs	let kind = crate::types::EdgeKind::Mentions;	let kind = crate::edge::EdgeKind::Mentions;
crates/oneiron/src/sync/quarantine.rs	let kind = crate::types::EdgeKind::Mentions;	let kind = crate::edge::EdgeKind::Mentions;
crates/oneiron/src/sync/quarantine.rs	let kind = crate::types::EdgeKind::Mentions;	let kind = crate::edge::EdgeKind::Mentions;
crates/oneiron/src/vault.rs	/// Compatibility wrapper over [`crate::types::parse_strict_edge_record`] so	/// Compatibility wrapper over [`crate::edge::parse_strict_edge_record`] so

## frag-edit

## comment

## add
crates/oneiron/src/edge.rs	//! Edge kinds, layouts, value codec, strict edge-record parsing, `EdgeInfo`.
crates/oneiron/src/edge.rs	#[cfg(test)]
crates/oneiron/src/edge.rs	mod tests {
crates/oneiron/src/edge.rs	}
