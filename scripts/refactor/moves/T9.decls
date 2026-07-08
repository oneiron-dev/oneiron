## crate
crates/oneiron

## flat-name-check
yes

## allowed
crates/oneiron/src/context_pack.rs
crates/oneiron/src/eiri.rs
crates/oneiron/src/lib.rs
crates/oneiron/src/receipt.rs
crates/oneiron/src/receipt/tests.rs
crates/oneiron/src/serialize.rs
crates/oneiron/src/types.rs

## error-literal
crates/oneiron/src/eiri.rs

## decl
+ pub mod eiri
+ pub use crate :: eiri :: { EIRI_CONTEXT_VERSION_V4 , EiriCompanionAssembly , EiriMemoryBoard , EiriMemoryBoardBudget , EiriMemoryBoardRow , EiriMemoryBoardSlot , EiriMemoryBoardSource , EiriSessionRagState , NotificationItem , ResumeBudget , ResumeBundle , SessionContext , UnprocessedItem }
+ pub use crate :: types :: { HydratedShortIdDeletion , HydratedShortIdDeletionReason , HydratedShortIdDeletionSource , MemoryOperationKind , MemoryTimeline , MemoryTimelineRecord , MemoryTimelineRecordState , NamedMemoryVerb }
- pub use crate :: types :: { EIRI_CONTEXT_VERSION_V4 , EiriCompanionAssembly , EiriMemoryBoard , EiriMemoryBoardBudget , EiriMemoryBoardRow , EiriMemoryBoardSlot , EiriMemoryBoardSource , EiriSessionRagState , HydratedShortIdDeletion , HydratedShortIdDeletionReason , HydratedShortIdDeletionSource , MemoryOperationKind , MemoryTimeline , MemoryTimelineRecord , MemoryTimelineRecordState , NamedMemoryVerb , NotificationItem , ResumeBudget , ResumeBundle , SessionContext , UnprocessedItem }

## impl-delta
- crates/oneiron/src/types.rs	impl Default for EiriSessionRagState
- crates/oneiron/src/types.rs	impl EiriMemoryBoardBudget
- crates/oneiron/src/types.rs	impl EiriMemoryBoardSlot
- crates/oneiron/src/types.rs	impl EiriMemoryBoardSource
- crates/oneiron/src/types.rs	impl EiriSessionRagState
- crates/oneiron/src/types.rs	impl ResumeBudget
- crates/oneiron/src/types.rs	impl ResumeBundle
+ crates/oneiron/src/eiri.rs	impl Default for EiriSessionRagState
+ crates/oneiron/src/eiri.rs	impl EiriMemoryBoardBudget
+ crates/oneiron/src/eiri.rs	impl EiriMemoryBoardSlot
+ crates/oneiron/src/eiri.rs	impl EiriMemoryBoardSource
+ crates/oneiron/src/eiri.rs	impl EiriSessionRagState
+ crates/oneiron/src/eiri.rs	impl ResumeBudget
+ crates/oneiron/src/eiri.rs	impl ResumeBundle

## edit

## frag-edit

## comment

## add
crates/oneiron/src/eiri.rs	//! Eiri Context v4 board + session-RAG + companion resume wire types.
