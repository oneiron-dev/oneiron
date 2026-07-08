## crate
crates/oneiron

## flat-name-check
yes

## allowed
crates/oneiron-server/src/api.rs
crates/oneiron/src/agent_def.rs
crates/oneiron/src/anchored_annotation.rs
crates/oneiron/src/artifact_hosting/tests.rs
crates/oneiron/src/batch.rs
crates/oneiron/src/blob_artifact.rs
crates/oneiron/src/bm25/tests.rs
crates/oneiron/src/channel_identity/tests.rs
crates/oneiron/src/code_artifact.rs
crates/oneiron/src/code_revision/tests.rs
crates/oneiron/src/code_symbol.rs
crates/oneiron/src/code_symbol/tests.rs
crates/oneiron/src/codebase.rs
crates/oneiron/src/codebase/tests.rs
crates/oneiron/src/companion/tests.rs
crates/oneiron/src/context_pack.rs
crates/oneiron/src/context_pack/tests.rs
crates/oneiron/src/critic/tests.rs
crates/oneiron/src/dreamer_runner.rs
crates/oneiron/src/dreamer_tournament.rs
crates/oneiron/src/edit_settle.rs
crates/oneiron/src/embed/tests.rs
crates/oneiron/src/error.rs
crates/oneiron/src/gate/tests.rs
crates/oneiron/src/graph_fs/tests.rs
crates/oneiron/src/hnsw/tests.rs
crates/oneiron/src/inbox.rs
crates/oneiron/src/ingest.rs
crates/oneiron/src/lens/tests.rs
crates/oneiron/src/lib.rs
crates/oneiron/src/maintain/tests.rs
crates/oneiron/src/off_record/tests.rs
crates/oneiron/src/persona_snapshot.rs
crates/oneiron/src/pipeline.rs
crates/oneiron/src/psych_profile.rs
crates/oneiron/src/repo_mutation.rs
crates/oneiron/src/skill.rs
crates/oneiron/src/store/tests.rs
crates/oneiron/src/sweep/tests.rs
crates/oneiron/src/sync/bridge.rs
crates/oneiron/src/sync/bridge/tests.rs
crates/oneiron/src/sync/client/tests.rs
crates/oneiron/src/sync/convergence_props_internal.rs
crates/oneiron/src/sync/quarantine/tests.rs
crates/oneiron/src/sync/queue/tests.rs
crates/oneiron/src/sync/selector.rs
crates/oneiron/src/sync/selector/tests.rs
crates/oneiron/src/sync/window.rs
crates/oneiron/src/temporal.rs
crates/oneiron/src/types.rs
crates/oneiron/src/vault.rs
crates/oneiron/src/vault/tests.rs
crates/oneiron/tests/sync_bridge.rs
crates/oneiron/tests/sync_byzantine_lww.rs
crates/oneiron/tests/sync_delete_propagation.rs
crates/oneiron/tests/sync_harness/mod.rs
crates/oneiron/tests/sync_quarantine.rs
crates/oneiron/tests/sync_receipt_replay.rs
crates/oneiron/tests/sync_remat_correctness.rs
crates/oneiron/tests/sync_replay_reason.rs
crates/oneiron/tests/sync_sweep_executor.rs
crates/oneiron/tests/sync_tombstone_v2.rs
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
crates/oneiron/src/lens/tests.rs	crate::types::TimeRange { start: 1, end: 1 },	crate::temporal::TimeRange { start: 1, end: 1 },
crates/oneiron/src/lens/tests.rs	vault.put_claim(id, &body, crate::types::TimeRange { start: 1, end: 1 }, 2)	vault.put_claim(id, &body, crate::temporal::TimeRange { start: 1, end: 1 }, 2)
crates/oneiron/src/sync/bridge.rs	crate::types::TimeRange {	crate::temporal::TimeRange {
crates/oneiron/src/sync/selector.rs	crate::types::TimeRange {	crate::temporal::TimeRange {
crates/oneiron/src/sync/window.rs	crate::types::TimeRange {	crate::temporal::TimeRange {
crates/oneiron/src/sync/window.rs	crate::types::TimeRange {	crate::temporal::TimeRange {
crates/oneiron/src/sync/window.rs	crate::types::TimeRange {	crate::temporal::TimeRange {
crates/oneiron/tests/sync_sweep_executor.rs	use oneiron::types::TimeRange;	use oneiron::temporal::TimeRange;
crates/oneiron/tests/sync_window_manager.rs	use oneiron::types::TimeRange;	use oneiron::temporal::TimeRange;

## frag-edit

## comment

## add
crates/oneiron/src/temporal.rs	//! `TimeRange`, temporal expressions/parsing, granularity/anchor enums.
crates/oneiron/src/temporal.rs	#[cfg(test)]
crates/oneiron/src/temporal.rs	mod tests {
crates/oneiron/src/temporal.rs	}
