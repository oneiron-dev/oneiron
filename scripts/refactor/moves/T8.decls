## crate
crates/oneiron

## flat-name-check
yes

## allowed
crates/oneiron-bench/src/beam.rs
crates/oneiron-server/src/api.rs
crates/oneiron/src/bm25.rs
crates/oneiron/src/claim.rs
crates/oneiron/src/code_symbol.rs
crates/oneiron/src/codebase/tests.rs
crates/oneiron/src/context_pack.rs
crates/oneiron/src/context_pack/tests.rs
crates/oneiron/src/fusion.rs
crates/oneiron/src/gate/tests.rs
crates/oneiron/src/hnsw.rs
crates/oneiron/src/lib.rs
crates/oneiron/src/pipeline.rs
crates/oneiron/src/ppr.rs
crates/oneiron/src/psych_profile/tests.rs
crates/oneiron/src/serialize.rs
crates/oneiron/src/serialize/tests.rs
crates/oneiron/src/store.rs
crates/oneiron/src/types.rs
crates/oneiron/src/vault.rs

## error-literal
crates/oneiron/src/context_pack.rs
crates/oneiron/src/pipeline.rs
crates/oneiron/src/types.rs

## decl
+ pub use crate :: context_pack :: { ContextEntity , ContextPack , ContextPackBuilder , ContextPackRetrievalBudget , EmptyContext , EmptyReason , FieldProfile , PackFormat , PackItemTokenStats , PackSectionTokenStats , PackStats , PackTokenStats , SerializedContextPack , TokenAllocation }
+ pub use crate :: pipeline :: { DEFAULT_RECENCY_HALF_LIFE_DAYS , FacetMode , PendingVectorEmbedding , PipelineBuilder , RetrievalWithPendingVectors , RetrievalWithTelemetry , ScoredEntity , Signal , WorldScope }
+ pub use crate :: types :: { EIRI_CONTEXT_VERSION_V4 , EiriCompanionAssembly , EiriMemoryBoard , EiriMemoryBoardBudget , EiriMemoryBoardRow , EiriMemoryBoardSlot , EiriMemoryBoardSource , EiriSessionRagState , HydratedShortIdDeletion , HydratedShortIdDeletionReason , HydratedShortIdDeletionSource , MemoryOperationKind , MemoryTimeline , MemoryTimelineRecord , MemoryTimelineRecordState , NamedMemoryVerb , NotificationItem , ResumeBudget , ResumeBundle , SessionContext , UnprocessedItem }
- pub use crate :: context_pack :: { ContextPackBuilder , SerializedContextPack }
- pub use crate :: pipeline :: { DEFAULT_RECENCY_HALF_LIFE_DAYS , FacetMode , PendingVectorEmbedding , PipelineBuilder , RetrievalWithPendingVectors , RetrievalWithTelemetry , WorldScope }
- pub use crate :: types :: { ContextEntity , ContextPack , ContextPackRetrievalBudget , EIRI_CONTEXT_VERSION_V4 , EiriCompanionAssembly , EiriMemoryBoard , EiriMemoryBoardBudget , EiriMemoryBoardRow , EiriMemoryBoardSlot , EiriMemoryBoardSource , EiriSessionRagState , EmptyContext , EmptyReason , FieldProfile , HydratedShortIdDeletion , HydratedShortIdDeletionReason , HydratedShortIdDeletionSource , MemoryOperationKind , MemoryTimeline , MemoryTimelineRecord , MemoryTimelineRecordState , NamedMemoryVerb , NotificationItem , PackFormat , PackItemTokenStats , PackSectionTokenStats , PackStats , PackTokenStats , ResumeBudget , ResumeBundle , ScoredEntity , SessionContext , Signal , TokenAllocation , UnprocessedItem }

## impl-delta
- crates/oneiron/src/types.rs	impl ContextPackRetrievalBudget
- crates/oneiron/src/types.rs	impl Default for TokenAllocation
- crates/oneiron/src/types.rs	impl PackItemAccounting
- crates/oneiron/src/types.rs	impl PackItemAccountingReason
+ crates/oneiron/src/context_pack.rs	impl ContextPackRetrievalBudget
+ crates/oneiron/src/context_pack.rs	impl Default for TokenAllocation
+ crates/oneiron/src/context_pack.rs	impl PackItemAccounting
+ crates/oneiron/src/context_pack.rs	impl PackItemAccountingReason

## edit
crates/oneiron-server/src/api.rs	items_truncated: oneiron::types::PackItemAccounting::item_budget(),	items_truncated: oneiron::context_pack::PackItemAccounting::item_budget(),
crates/oneiron-server/src/api.rs	items_dropped: oneiron::types::PackItemAccounting::token_budget(),	items_dropped: oneiron::context_pack::PackItemAccounting::token_budget(),
crates/oneiron/src/context_pack.rs	tokens: crate::types::PackTokenStats::default(),	tokens: crate::context_pack::PackTokenStats::default(),
crates/oneiron/src/context_pack.rs	items_truncated: crate::types::PackItemAccounting::item_budget(),	items_truncated: crate::context_pack::PackItemAccounting::item_budget(),
crates/oneiron/src/context_pack.rs	items_dropped: crate::types::PackItemAccounting::token_budget(),	items_dropped: crate::context_pack::PackItemAccounting::token_budget(),
crates/oneiron/src/context_pack.rs	crate::types::PackItemAccountingReason::TokenBudget => {	crate::context_pack::PackItemAccountingReason::TokenBudget => {
crates/oneiron/src/context_pack.rs	crate::types::PackItemAccountingReason::ItemBudget => {	crate::context_pack::PackItemAccountingReason::ItemBudget => {
crates/oneiron/src/context_pack/tests.rs	tokens: crate::types::PackTokenStats::default(),	tokens: crate::context_pack::PackTokenStats::default(),
crates/oneiron/src/context_pack/tests.rs	items_truncated: crate::types::PackItemAccounting::item_budget(),	items_truncated: crate::context_pack::PackItemAccounting::item_budget(),
crates/oneiron/src/context_pack/tests.rs	items_dropped: crate::types::PackItemAccounting::token_budget(),	items_dropped: crate::context_pack::PackItemAccounting::token_budget(),
crates/oneiron/src/gate/tests.rs	.retrieval_budget(crate::types::ContextPackRetrievalBudget::new(	.retrieval_budget(crate::context_pack::ContextPackRetrievalBudget::new(
crates/oneiron/src/serialize.rs	stats.items_dropped.reason = crate::types::PackItemAccountingReason::ItemBudget;	stats.items_dropped.reason = crate::context_pack::PackItemAccountingReason::ItemBudget;
crates/oneiron/src/serialize.rs	prepared.stats.items_dropped.reason = crate::types::PackItemAccountingReason::TokenBudget;	prepared.stats.items_dropped.reason = crate::context_pack::PackItemAccountingReason::TokenBudget;
crates/oneiron/src/serialize.rs	fn item_accounting_json(accounting: crate::types::PackItemAccounting) -> Value {	fn item_accounting_json(accounting: crate::context_pack::PackItemAccounting) -> Value {
crates/oneiron/src/serialize/tests.rs	tokens: crate::types::PackTokenStats::default(),	tokens: crate::context_pack::PackTokenStats::default(),
crates/oneiron/src/serialize/tests.rs	items_truncated: crate::types::PackItemAccounting::item_budget(),	items_truncated: crate::context_pack::PackItemAccounting::item_budget(),
crates/oneiron/src/serialize/tests.rs	items_dropped: crate::types::PackItemAccounting::token_budget(),	items_dropped: crate::context_pack::PackItemAccounting::token_budget(),
crates/oneiron/src/serialize/tests.rs	tokens: crate::types::PackTokenStats::default(),	tokens: crate::context_pack::PackTokenStats::default(),
crates/oneiron/src/serialize/tests.rs	items_truncated: crate::types::PackItemAccounting::item_budget(),	items_truncated: crate::context_pack::PackItemAccounting::item_budget(),
crates/oneiron/src/serialize/tests.rs	items_dropped: crate::types::PackItemAccounting::token_budget(),	items_dropped: crate::context_pack::PackItemAccounting::token_budget(),
crates/oneiron/src/serialize/tests.rs	tokens: crate::types::PackTokenStats::default(),	tokens: crate::context_pack::PackTokenStats::default(),
crates/oneiron/src/serialize/tests.rs	items_truncated: crate::types::PackItemAccounting::item_budget(),	items_truncated: crate::context_pack::PackItemAccounting::item_budget(),
crates/oneiron/src/serialize/tests.rs	items_dropped: crate::types::PackItemAccounting::token_budget(),	items_dropped: crate::context_pack::PackItemAccounting::token_budget(),
crates/oneiron/src/psych_profile/tests.rs	use crate::types::ContextEntity;	use crate::context_pack::ContextEntity;

## frag-edit

## comment

## add
