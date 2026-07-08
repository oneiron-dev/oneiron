## crate
crates/oneiron

## flat-name-check
yes

## allowed
crates/oneiron/src/affect.rs
crates/oneiron/src/context_pack.rs
crates/oneiron/src/lib.rs
crates/oneiron/src/sync/quarantine.rs
crates/oneiron/src/types.rs

## error-literal
crates/oneiron/src/affect.rs

## decl
+ pub use crate :: affect :: { AFFECT_TRIGGER_PREDICATE , AffectTriggerValue , CLAIM_VAD_REAPPRAISAL_PREDICATE , ClaimVadConsolidation , ClaimVadReappraisal , ClaimVadTurnEvidence , Vad , VadAnnotation , VadAnnotationSource , VadComponent , VadDelta , affect_trigger_claim_candidate , affect_trigger_value , decode_affect_trigger_claim , decode_affect_trigger_value }
+ pub use crate :: types :: { Bm25RankProfile , ClaimCandidate , ContextEntity , ContextPack , ContextPackRetrievalBudget , DecodedEdgeValue , EIRI_CONTEXT_VERSION_V4 , EdgeActorClass , EdgeConfirmationStatus , EdgeInfo , EdgeKind , EdgeProvenanceFlags , EdgeValueLayout , EiriCompanionAssembly , EiriMemoryBoard , EiriMemoryBoardBudget , EiriMemoryBoardRow , EiriMemoryBoardSlot , EiriMemoryBoardSource , EiriSessionRagState , EmptyContext , EmptyReason , FieldProfile , HnswConfig , HydratedShortIdDeletion , HydratedShortIdDeletionReason , HydratedShortIdDeletionSource , MemoryOperationKind , MemoryTimeline , MemoryTimelineRecord , MemoryTimelineRecordState , NamedMemoryVerb , NotificationItem , PackFormat , PackItemTokenStats , PackSectionTokenStats , PackStats , PackTokenStats , ResumeBudget , ResumeBundle , ScoredEntity , SessionContext , Signal , TemporalAnchorMode , TemporalGranularity , TextAnalyzerConfig , TextIndexOptions , TimeRange , TokenAllocation , UnprocessedItem , VaultConfig , WriteActor , WriteEnvelope , WriteProvenance }
- pub use crate :: affect :: { AFFECT_TRIGGER_PREDICATE , AffectTriggerValue , CLAIM_VAD_REAPPRAISAL_PREDICATE , ClaimVadConsolidation , ClaimVadReappraisal , ClaimVadTurnEvidence , VadDelta , affect_trigger_claim_candidate , affect_trigger_value , decode_affect_trigger_claim , decode_affect_trigger_value }
- pub use crate :: types :: { Bm25RankProfile , ClaimCandidate , ContextEntity , ContextPack , ContextPackRetrievalBudget , DecodedEdgeValue , EIRI_CONTEXT_VERSION_V4 , EdgeActorClass , EdgeConfirmationStatus , EdgeInfo , EdgeKind , EdgeProvenanceFlags , EdgeValueLayout , EiriCompanionAssembly , EiriMemoryBoard , EiriMemoryBoardBudget , EiriMemoryBoardRow , EiriMemoryBoardSlot , EiriMemoryBoardSource , EiriSessionRagState , EmptyContext , EmptyReason , FieldProfile , HnswConfig , HydratedShortIdDeletion , HydratedShortIdDeletionReason , HydratedShortIdDeletionSource , MemoryOperationKind , MemoryTimeline , MemoryTimelineRecord , MemoryTimelineRecordState , NamedMemoryVerb , NotificationItem , PackFormat , PackItemTokenStats , PackSectionTokenStats , PackStats , PackTokenStats , ResumeBudget , ResumeBundle , ScoredEntity , SessionContext , Signal , TemporalAnchorMode , TemporalGranularity , TextAnalyzerConfig , TextIndexOptions , TimeRange , TokenAllocation , UnprocessedItem , Vad , VadAnnotation , VadAnnotationSource , VadComponent , VaultConfig , WriteActor , WriteEnvelope , WriteProvenance }

## impl-delta
- crates/oneiron/src/types.rs	impl Vad
- crates/oneiron/src/types.rs	impl VadAnnotation
- crates/oneiron/src/types.rs	impl VadAnnotationSource
+ crates/oneiron/src/affect.rs	impl Vad
+ crates/oneiron/src/affect.rs	impl VadAnnotation
+ crates/oneiron/src/affect.rs	impl VadAnnotationSource

## edit
crates/oneiron/src/context_pack.rs	crate::types::Vad::NEUTRAL,	crate::affect::Vad::NEUTRAL,
crates/oneiron/src/context_pack.rs	crate::types::Vad {	crate::affect::Vad {
crates/oneiron/src/context_pack.rs	crate::types::Vad::NEUTRAL,	crate::affect::Vad::NEUTRAL,
crates/oneiron/src/sync/quarantine.rs	Some(crate::types::Vad::NEUTRAL),	Some(crate::affect::Vad::NEUTRAL),
crates/oneiron/src/sync/quarantine.rs	Some(crate::types::Vad::NEUTRAL),	Some(crate::affect::Vad::NEUTRAL),

## frag-edit

## comment

## add
