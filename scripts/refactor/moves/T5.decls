## crate
crates/oneiron

## flat-name-check
yes

## allowed
crates/oneiron/src/affect.rs
crates/oneiron/src/affect/coping.rs
crates/oneiron/src/anchored_annotation.rs
crates/oneiron/src/batch.rs
crates/oneiron/src/batch/export/tests.rs
crates/oneiron/src/batch/tests.rs
crates/oneiron/src/blob_artifact.rs
crates/oneiron/src/bm25/tests.rs
crates/oneiron/src/code_run.rs
crates/oneiron/src/codebase/tests.rs
crates/oneiron/src/companion.rs
crates/oneiron/src/companion/tests.rs
crates/oneiron/src/dreamer_runner.rs
crates/oneiron/src/dreamer_runner/tests.rs
crates/oneiron/src/dreamer_tournament.rs
crates/oneiron/src/dreamer_tournament/tests.rs
crates/oneiron/src/edit_settle.rs
crates/oneiron/src/edit_settle/tests.rs
crates/oneiron/src/gate.rs
crates/oneiron/src/gate/tests.rs
crates/oneiron/src/inbox/tests.rs
crates/oneiron/src/ingest.rs
crates/oneiron/src/ingest/tests.rs
crates/oneiron/src/lib.rs
crates/oneiron/src/receipt/tests.rs
crates/oneiron/src/types.rs
crates/oneiron/src/vault.rs
crates/oneiron/src/write_envelope.rs

## error-literal
crates/oneiron/src/write_envelope.rs

## decl
+ pub mod write_envelope
+ pub use crate :: types :: { Bm25RankProfile , ContextEntity , ContextPack , ContextPackRetrievalBudget , EIRI_CONTEXT_VERSION_V4 , EiriCompanionAssembly , EiriMemoryBoard , EiriMemoryBoardBudget , EiriMemoryBoardRow , EiriMemoryBoardSlot , EiriMemoryBoardSource , EiriSessionRagState , EmptyContext , EmptyReason , FieldProfile , HnswConfig , HydratedShortIdDeletion , HydratedShortIdDeletionReason , HydratedShortIdDeletionSource , MemoryOperationKind , MemoryTimeline , MemoryTimelineRecord , MemoryTimelineRecordState , NamedMemoryVerb , NotificationItem , PackFormat , PackItemTokenStats , PackSectionTokenStats , PackStats , PackTokenStats , ResumeBudget , ResumeBundle , ScoredEntity , SessionContext , Signal , TemporalAnchorMode , TemporalGranularity , TextAnalyzerConfig , TextIndexOptions , TimeRange , TokenAllocation , UnprocessedItem , VaultConfig }
+ pub use crate :: write_envelope :: { ClaimCandidate , WriteActor , WriteEnvelope , WriteProvenance }
- pub use crate :: types :: { Bm25RankProfile , ClaimCandidate , ContextEntity , ContextPack , ContextPackRetrievalBudget , EIRI_CONTEXT_VERSION_V4 , EiriCompanionAssembly , EiriMemoryBoard , EiriMemoryBoardBudget , EiriMemoryBoardRow , EiriMemoryBoardSlot , EiriMemoryBoardSource , EiriSessionRagState , EmptyContext , EmptyReason , FieldProfile , HnswConfig , HydratedShortIdDeletion , HydratedShortIdDeletionReason , HydratedShortIdDeletionSource , MemoryOperationKind , MemoryTimeline , MemoryTimelineRecord , MemoryTimelineRecordState , NamedMemoryVerb , NotificationItem , PackFormat , PackItemTokenStats , PackSectionTokenStats , PackStats , PackTokenStats , ResumeBudget , ResumeBundle , ScoredEntity , SessionContext , Signal , TemporalAnchorMode , TemporalGranularity , TextAnalyzerConfig , TextIndexOptions , TimeRange , TokenAllocation , UnprocessedItem , VaultConfig , WriteActor , WriteEnvelope , WriteProvenance }

## impl-delta
- crates/oneiron/src/types.rs	impl ClaimCandidate
- crates/oneiron/src/types.rs	impl WriteActor
- crates/oneiron/src/types.rs	impl WriteEnvelope
- crates/oneiron/src/types.rs	impl WriteProvenance
+ crates/oneiron/src/write_envelope.rs	impl ClaimCandidate
+ crates/oneiron/src/write_envelope.rs	impl WriteActor
+ crates/oneiron/src/write_envelope.rs	impl WriteEnvelope
+ crates/oneiron/src/write_envelope.rs	impl WriteProvenance

## edit
crates/oneiron/src/code_run.rs	body.evidence = Some(crate::types::write_envelope_evidence(envelope, None));	body.evidence = Some(crate::write_envelope::write_envelope_evidence(envelope, None));
crates/oneiron/src/dreamer_runner/tests.rs	let candidate = crate::types::ClaimCandidate::new(	let candidate = crate::write_envelope::ClaimCandidate::new(
crates/oneiron/src/dreamer_runner/tests.rs	let candidate = crate::types::ClaimCandidate::new(	let candidate = crate::write_envelope::ClaimCandidate::new(
crates/oneiron/src/inbox/tests.rs	let candidate = crate::types::ClaimCandidate::new(	let candidate = crate::write_envelope::ClaimCandidate::new(
crates/oneiron/src/inbox/tests.rs	let candidate = crate::types::ClaimCandidate::new(	let candidate = crate::write_envelope::ClaimCandidate::new(
crates/oneiron/src/inbox/tests.rs	let candidate = crate::types::ClaimCandidate::new(	let candidate = crate::write_envelope::ClaimCandidate::new(
crates/oneiron/src/ingest/tests.rs	crate::types::WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY,	crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY,

## frag-edit

## comment

## add
crates/oneiron/src/write_envelope.rs	//! Write-path stamping: `WriteActor`/`WriteProvenance`/`WriteEnvelope`/`ClaimCandidate` + evidence stamping.
