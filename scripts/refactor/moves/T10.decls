## crate
crates/oneiron

## flat-name-check
yes

## allowed
crates/oneiron/src/claim.rs
crates/oneiron/src/deletion.rs
crates/oneiron/src/gate/tests.rs
crates/oneiron/src/lib.rs
crates/oneiron/src/types.rs
crates/oneiron/src/vault.rs

## error-literal
crates/oneiron/src/deletion.rs

## decl
+ pub use crate :: deletion :: { DecodedTombstoneValue , DeleteEntityOutcome , DeleteReason , HydratedShortIdDeletion , HydratedShortIdDeletionReason , HydratedShortIdDeletionSource , MemoryOperationKind , MemoryTimeline , MemoryTimelineRecord , MemoryTimelineRecordState , NamedMemoryVerb , TOMBSTONE_VALUE_LEGACY_LEN , TOMBSTONE_VALUE_V2_LEN , TombstoneReason , TombstoneValueV2 , decode_tombstone_value }
- pub use crate :: deletion :: { DecodedTombstoneValue , DeleteEntityOutcome , DeleteReason , TOMBSTONE_VALUE_LEGACY_LEN , TOMBSTONE_VALUE_V2_LEN , TombstoneReason , TombstoneValueV2 , decode_tombstone_value }
- pub use crate :: types :: { HydratedShortIdDeletion , HydratedShortIdDeletionReason , HydratedShortIdDeletionSource , MemoryOperationKind , MemoryTimeline , MemoryTimelineRecord , MemoryTimelineRecordState , NamedMemoryVerb }

## impl-delta
- crates/oneiron/src/types.rs	impl NamedMemoryVerb
+ crates/oneiron/src/deletion.rs	impl NamedMemoryVerb

## edit
crates/oneiron/src/gate/tests.rs	crate::types::HydratedShortIdDeletionSource::DanglingShortId	crate::deletion::HydratedShortIdDeletionSource::DanglingShortId
crates/oneiron/src/gate/tests.rs	crate::types::HydratedShortIdDeletionSource::Tombstone	crate::deletion::HydratedShortIdDeletionSource::Tombstone
crates/oneiron/src/gate/tests.rs	| crate::types::HydratedShortIdDeletionSource::PendingTombstone	| crate::deletion::HydratedShortIdDeletionSource::PendingTombstone
crates/oneiron/src/gate/tests.rs	Some(crate::types::HydratedShortIdDeletionReason::UserDelete)	Some(crate::deletion::HydratedShortIdDeletionReason::UserDelete)

## frag-edit

## comment

## add
