## crate
crates/oneiron

## flat-name-check
yes

## allowed
crates/oneiron-server/src/api.rs
crates/oneiron/src/lens.rs
crates/oneiron/src/lib.rs
crates/oneiron/src/sync/bridge.rs
crates/oneiron/src/sync/selector.rs
crates/oneiron/src/sync/window.rs
crates/oneiron/src/temporal.rs
crates/oneiron/src/types.rs
crates/oneiron/tests/sync_sweep_executor.rs
crates/oneiron/tests/sync_window_manager.rs

## error-literal
crates/oneiron/src/temporal.rs

## decl
+ pub mod temporal
+ pub use crate :: temporal :: { TemporalAnchorMode , TemporalGranularity , TimeRange }
+ pub use crate :: types :: { Bm25RankProfile , ContextEntity , ContextPack , ContextPackRetrievalBudget , EIRI_CONTEXT_VERSION_V4 , EiriCompanionAssembly , EiriMemoryBoard , EiriMemoryBoardBudget , EiriMemoryBoardRow , EiriMemoryBoardSlot , EiriMemoryBoardSource , EiriSessionRagState , EmptyContext , EmptyReason , FieldProfile , HnswConfig , HydratedShortIdDeletion , HydratedShortIdDeletionReason , HydratedShortIdDeletionSource , MemoryOperationKind , MemoryTimeline , MemoryTimelineRecord , MemoryTimelineRecordState , NamedMemoryVerb , NotificationItem , PackFormat , PackItemTokenStats , PackSectionTokenStats , PackStats , PackTokenStats , ResumeBudget , ResumeBundle , ScoredEntity , SessionContext , Signal , TextAnalyzerConfig , TextIndexOptions , TokenAllocation , UnprocessedItem , VaultConfig }
- pub use crate :: types :: { Bm25RankProfile , ContextEntity , ContextPack , ContextPackRetrievalBudget , EIRI_CONTEXT_VERSION_V4 , EiriCompanionAssembly , EiriMemoryBoard , EiriMemoryBoardBudget , EiriMemoryBoardRow , EiriMemoryBoardSlot , EiriMemoryBoardSource , EiriSessionRagState , EmptyContext , EmptyReason , FieldProfile , HnswConfig , HydratedShortIdDeletion , HydratedShortIdDeletionReason , HydratedShortIdDeletionSource , MemoryOperationKind , MemoryTimeline , MemoryTimelineRecord , MemoryTimelineRecordState , NamedMemoryVerb , NotificationItem , PackFormat , PackItemTokenStats , PackSectionTokenStats , PackStats , PackTokenStats , ResumeBudget , ResumeBundle , ScoredEntity , SessionContext , Signal , TemporalAnchorMode , TemporalGranularity , TextAnalyzerConfig , TextIndexOptions , TimeRange , TokenAllocation , UnprocessedItem , VaultConfig }

## impl-delta
- crates/oneiron/src/types.rs	impl TemporalExpression
- crates/oneiron/src/types.rs	impl TemporalGranularity
+ crates/oneiron/src/temporal.rs	impl TemporalExpression
+ crates/oneiron/src/temporal.rs	impl TemporalGranularity

## edit
crates/oneiron-server/src/api.rs	oneiron::types::TemporalExpressionParseError::Unsupported {	oneiron::temporal::TemporalExpressionParseError::Unsupported {
crates/oneiron/src/lens.rs	crate::types::TimeRange { start: 1, end: 1 },	crate::temporal::TimeRange { start: 1, end: 1 },
crates/oneiron/src/lens.rs	vault.put_claim(id, &body, crate::types::TimeRange { start: 1, end: 1 }, 2)	vault.put_claim(id, &body, crate::temporal::TimeRange { start: 1, end: 1 }, 2)
crates/oneiron/src/sync/bridge.rs	crate::types::TimeRange {	crate::temporal::TimeRange {
crates/oneiron/src/sync/selector.rs	crate::types::TimeRange {	crate::temporal::TimeRange {
crates/oneiron/src/sync/window.rs	crate::types::TimeRange {	crate::temporal::TimeRange {
crates/oneiron/src/sync/window.rs	crate::types::TimeRange {	crate::temporal::TimeRange {
crates/oneiron/src/sync/window.rs	crate::types::TimeRange {	crate::temporal::TimeRange {

## frag-edit

## comment

## add
crates/oneiron/src/temporal.rs	//! `TimeRange`, temporal expressions/parsing, granularity/anchor enums.
crates/oneiron/src/temporal.rs	#[cfg(test)]
crates/oneiron/src/temporal.rs	mod tests {
crates/oneiron/src/temporal.rs	}
