## crate
crates/oneiron

## flat-name-check
yes

## allowed
crates/oneiron-server/src/api.rs
crates/oneiron-server/src/projection.rs
crates/oneiron/src/batch.rs
crates/oneiron/src/companion.rs
crates/oneiron/src/context_pack.rs
crates/oneiron/src/export.rs
crates/oneiron/src/lib.rs
crates/oneiron/src/persona_snapshot.rs
crates/oneiron/src/tests.rs
crates/oneiron/src/receipt/tests.rs
crates/oneiron/src/sync/bridge/tests.rs
crates/oneiron/src/sync/window/tests.rs
crates/oneiron/src/persona_snapshot/tests.rs
crates/oneiron/src/psych_profile.rs
crates/oneiron/src/receipt.rs
crates/oneiron/src/serialize.rs
crates/oneiron/src/serialize/tests.rs
crates/oneiron/src/store.rs
crates/oneiron/src/sync/bridge.rs
crates/oneiron/src/sync/selector.rs
crates/oneiron/src/sync/selector/tests.rs
crates/oneiron/src/sync/window.rs
crates/oneiron/src/types.rs
crates/oneiron/src/vault.rs

## consumer-exempt
crates/oneiron/src/types.rs

## decl
+ pub use crate :: companion :: { COMPANION_TASK_JOB_KIND , COMPANION_TASK_PAYLOAD_KEYS , COMPANION_TASK_PAYLOAD_SCHEMA_VERSION , ClaimCompanionTask , ClaimCompanionTaskOutcome , CompanionExportClassification , CompanionExpression , CompanionExpressionRegister , CompanionProvenance , CompanionQueue , CompanionRecord , CompanionRecordKey , CompanionRecordKind , CompanionRegister , CompanionScope , CompanionScopeResolution , CompanionScopeResolutionSource , CompanionSubject , CompanionTask , CompanionTaskKind , CompanionTaskStatus , CompleteCompanionTask , CompleteCompanionTaskOutcome , ENTITY_TYPE_COMPANION_REGISTER , EndCompanionRelationship , EndCompanionRelationshipOutcome , EnqueueCompanionTask , EnqueueCompanionTaskOutcome , FailCompanionTask , FailCompanionTaskOutcome , RetryCompanionTask , RetryCompanionTaskOutcome , companion_value_from_json , companion_value_to_json , decode_companion_record_body , decode_companion_task_payload , encode_companion_record_body , encode_companion_task_payload }
+ pub use crate :: psych_profile :: { PSYCH_PROFILE_BODY_KEYS , PSYCH_PROFILE_SCHEMA_VERSION , PsychProfile , PsychProfileConfidence , PsychProfileSnapshotStatus , PsychProfileStaleReason , PsychProfileState , decode_psych_profile_body , encode_psych_profile_body }
+ pub use crate :: types :: { Bm25RankProfile , ClaimCandidate , ContextEntity , ContextPack , ContextPackRetrievalBudget , DecodedEdgeValue , EIRI_CONTEXT_VERSION_V4 , ENTITY_TYPE_ACCESS_GRANT , ENTITY_TYPE_AUTHORITY_LOG , ENTITY_TYPE_CHANNEL_IDENTITY , ENTITY_TYPE_CODE_ARTIFACT , ENTITY_TYPE_CODE_SYMBOL , ENTITY_TYPE_COUNTERPARTY_CONTACT , ENTITY_TYPE_FEDERATION_GRANT , ENTITY_TYPE_OUTBOUND_GRANT , ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT , ENTITY_TYPE_PSYCH_PROFILE , EdgeActorClass , EdgeConfirmationStatus , EdgeInfo , EdgeKind , EdgeProvenanceFlags , EdgeValueLayout , EiriCompanionAssembly , EiriMemoryBoard , EiriMemoryBoardBudget , EiriMemoryBoardRow , EiriMemoryBoardSlot , EiriMemoryBoardSource , EiriSessionRagState , EmptyContext , EmptyReason , EntityId , FieldProfile , HnswConfig , HydratedShortIdDeletion , HydratedShortIdDeletionReason , HydratedShortIdDeletionSource , MemoryOperationKind , MemoryTimeline , MemoryTimelineRecord , MemoryTimelineRecordState , NamedMemoryVerb , NotificationItem , PackFormat , PackItemTokenStats , PackSectionTokenStats , PackStats , PackTokenStats , ResumeBudget , ResumeBundle , ScoredEntity , SessionContext , Signal , StructuralKindRegistration , TemporalAnchorMode , TemporalGranularity , TextAnalyzerConfig , TextIndexOptions , TimeRange , TokenAllocation , TypeByteBand , UnprocessedItem , Vad , VadAnnotation , VadAnnotationSource , VadComponent , VaultConfig , WriteActor , WriteEnvelope , WriteProvenance }
- pub use companion :: { COMPANION_RECORD_BODY_KEYS , COMPANION_RECORD_SCHEMA_VERSION , COMPANION_REGISTER_PACK_ID , COMPANION_REGISTER_SHORT_ID_PREFIX , COMPANION_TASK_JOB_KIND , COMPANION_TASK_PAYLOAD_KEYS , COMPANION_TASK_PAYLOAD_SCHEMA_VERSION , ClaimCompanionTask , ClaimCompanionTaskOutcome , CompanionExportClassification , CompanionExpression , CompanionExpressionRegister , CompanionProvenance , CompanionQueue , CompanionRecord , CompanionRecordKey , CompanionRecordKind , CompanionRegister , CompanionScope , CompanionScopeResolution , CompanionScopeResolutionSource , CompanionSubject , CompanionTask , CompanionTaskKind , CompanionTaskStatus , CompleteCompanionTask , CompleteCompanionTaskOutcome , ENTITY_TYPE_COMPANION_REGISTER , EndCompanionRelationship , EndCompanionRelationshipOutcome , EnqueueCompanionTask , EnqueueCompanionTaskOutcome , FailCompanionTask , FailCompanionTaskOutcome , RetryCompanionTask , RetryCompanionTaskOutcome , companion_value_from_json , companion_value_to_json , decode_companion_record_body , decode_companion_task_payload , encode_companion_record_body , encode_companion_task_payload }
- pub use crate :: types :: { Bm25RankProfile , COMPANION_TASK_JOB_KIND , COMPANION_TASK_PAYLOAD_KEYS , COMPANION_TASK_PAYLOAD_SCHEMA_VERSION , ClaimCandidate , ClaimCompanionTask , ClaimCompanionTaskOutcome , CompanionExportClassification , CompanionExpression , CompanionExpressionRegister , CompanionProvenance , CompanionQueue , CompanionRecord , CompanionRecordKey , CompanionRecordKind , CompanionRegister , CompanionScope , CompanionScopeResolution , CompanionScopeResolutionSource , CompanionSubject , CompanionTask , CompanionTaskKind , CompanionTaskStatus , CompleteCompanionTask , CompleteCompanionTaskOutcome , ContextEntity , ContextPack , ContextPackRetrievalBudget , DecodedEdgeValue , EIRI_CONTEXT_VERSION_V4 , ENTITY_TYPE_ACCESS_GRANT , ENTITY_TYPE_AUTHORITY_LOG , ENTITY_TYPE_CHANNEL_IDENTITY , ENTITY_TYPE_CODE_ARTIFACT , ENTITY_TYPE_CODE_SYMBOL , ENTITY_TYPE_COMPANION_REGISTER , ENTITY_TYPE_COUNTERPARTY_CONTACT , ENTITY_TYPE_FEDERATION_GRANT , ENTITY_TYPE_OUTBOUND_GRANT , ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT , ENTITY_TYPE_PSYCH_PROFILE , EdgeActorClass , EdgeConfirmationStatus , EdgeInfo , EdgeKind , EdgeProvenanceFlags , EdgeValueLayout , EiriCompanionAssembly , EiriMemoryBoard , EiriMemoryBoardBudget , EiriMemoryBoardRow , EiriMemoryBoardSlot , EiriMemoryBoardSource , EiriSessionRagState , EmptyContext , EmptyReason , EndCompanionRelationship , EndCompanionRelationshipOutcome , EnqueueCompanionTask , EnqueueCompanionTaskOutcome , EntityId , FailCompanionTask , FailCompanionTaskOutcome , FieldProfile , HnswConfig , HydratedShortIdDeletion , HydratedShortIdDeletionReason , HydratedShortIdDeletionSource , MemoryOperationKind , MemoryTimeline , MemoryTimelineRecord , MemoryTimelineRecordState , NamedMemoryVerb , NotificationItem , PackFormat , PackItemTokenStats , PackSectionTokenStats , PackStats , PackTokenStats , ResumeBudget , ResumeBundle , RetryCompanionTask , RetryCompanionTaskOutcome , ScoredEntity , SessionContext , Signal , StructuralKindRegistration , TemporalAnchorMode , TemporalGranularity , TextAnalyzerConfig , TextIndexOptions , TimeRange , TokenAllocation , TypeByteBand , UnprocessedItem , Vad , VadAnnotation , VadAnnotationSource , VadComponent , VaultConfig , WriteActor , WriteEnvelope , WriteProvenance , companion_value_from_json , companion_value_to_json , decode_companion_record_body , decode_companion_task_payload , encode_companion_record_body , encode_companion_task_payload }
- pub use crate :: types :: { PSYCH_PROFILE_BODY_KEYS , PSYCH_PROFILE_SCHEMA_VERSION , PsychProfile , PsychProfileConfidence , PsychProfileSnapshotStatus , PsychProfileStaleReason , PsychProfileState , decode_psych_profile_body , encode_psych_profile_body }
- pub use psych_profile :: { PSYCH_PROFILE_BODY_KEYS , PSYCH_PROFILE_SCHEMA_VERSION , PsychProfile , PsychProfileConfidence , PsychProfileSnapshotStatus , PsychProfileStaleReason , PsychProfileState , decode_psych_profile_body , encode_psych_profile_body }

## edit
crates/oneiron-server/src/api.rs	oneiron::types::psych_profile::psych_mirror_drift_anchor_events(	oneiron::psych_profile::psych_mirror_drift_anchor_events(
crates/oneiron/src/batch.rs	crate::types::psych_profile::validate_psych_profile_body_bytes(data)?;	crate::psych_profile::validate_psych_profile_body_bytes(data)?;
crates/oneiron/src/batch.rs	use crate::types::companion::{CompanionLifecycleEvent, CompanionLifecycleEventKind};	use crate::companion::{CompanionLifecycleEvent, CompanionLifecycleEventKind};
crates/oneiron/src/companion.rs	if bytes.len() != super::ENTITY_ID_LEN {	if bytes.len() != crate::types::ENTITY_ID_LEN {
crates/oneiron/src/companion.rs	let mut arr = [0_u8; super::ENTITY_ID_LEN];	let mut arr = [0_u8; crate::types::ENTITY_ID_LEN];
crates/oneiron/src/companion.rs	pub const ENTITY_TYPE_COMPANION_REGISTER: u8 = super::TYPE_BYTE_BAND_COMPANION_START;	pub const ENTITY_TYPE_COMPANION_REGISTER: u8 = crate::types::TYPE_BYTE_BAND_COMPANION_START;
crates/oneiron/src/companion.rs	use super::{EdgeActorClass, EntityId, WriteEnvelope};	use crate::types::{EdgeActorClass, EntityId, WriteEnvelope};
crates/oneiron/src/context_pack.rs	use crate::types::psych_profile::{PsychMirrorSourceCandidate, psych_mirror_text_entropy};	use crate::psych_profile::{PsychMirrorSourceCandidate, psych_mirror_text_entropy};
crates/oneiron/src/persona_snapshot.rs	let crate::types::companion::CompanionSubject::Relationship {	let crate::companion::CompanionSubject::Relationship {
crates/oneiron/src/persona_snapshot/tests.rs	use crate::types::companion::{	use crate::companion::{
crates/oneiron/src/persona_snapshot.rs	use crate::types::companion::{CompanionExportClassification, CompanionRecordKind, CompanionScope};	use crate::companion::{CompanionExportClassification, CompanionRecordKind, CompanionScope};
crates/oneiron/src/psych_profile.rs	use super::{ENTITY_TYPE_PSYCH_PROFILE, EntityId, TimeRange};	use crate::types::{ENTITY_TYPE_PSYCH_PROFILE, EntityId, TimeRange};
crates/oneiron/src/serialize.rs	crate::types::psych_profile::PSYCH_PROFILE_FIELDS_FULL	crate::psych_profile::PSYCH_PROFILE_FIELDS_FULL
crates/oneiron/src/serialize.rs	crate::types::psych_profile::PSYCH_PROFILE_FIELDS_MINIMAL	crate::psych_profile::PSYCH_PROFILE_FIELDS_MINIMAL
crates/oneiron/src/serialize.rs	crate::types::psych_profile::PSYCH_PROFILE_FIELDS_STANDARD	crate::psych_profile::PSYCH_PROFILE_FIELDS_STANDARD
crates/oneiron/src/serialize/tests.rs	serde_json::json!(crate::types::COMPANION_RECORD_SCHEMA_VERSION)	serde_json::json!(crate::companion::COMPANION_RECORD_SCHEMA_VERSION)
crates/oneiron/src/serialize/tests.rs	serde_json::json!(crate::types::COMPANION_RECORD_SCHEMA_VERSION),	serde_json::json!(crate::companion::COMPANION_RECORD_SCHEMA_VERSION),
crates/oneiron/src/serialize/tests.rs	crate::types::psych_profile::PSYCH_PROFILE_FIELDS_MINIMAL	crate::psych_profile::PSYCH_PROFILE_FIELDS_MINIMAL
crates/oneiron/src/sync/selector/tests.rs	let ev = crate::types::companion::CompanionLifecycleEvent::superseded(1_772_400_000);	let ev = crate::companion::CompanionLifecycleEvent::superseded(1_772_400_000);
crates/oneiron/src/sync/selector/tests.rs	let ev = crate::types::companion::CompanionLifecycleEvent::retired(1_772_400_000);	let ev = crate::companion::CompanionLifecycleEvent::retired(1_772_400_000);
crates/oneiron/src/vault.rs	let ev = crate::types::companion::CompanionLifecycleEvent::created(learned_at);	let ev = crate::companion::CompanionLifecycleEvent::created(learned_at);
crates/oneiron/src/vault.rs	use crate::types::companion::CompanionLifecycleEvent;	use crate::companion::CompanionLifecycleEvent;

## add
crates/oneiron/src/types.rs	use crate::companion::{COMPANION_REGISTER_SHORT_ID_PREFIX, ENTITY_TYPE_COMPANION_REGISTER};
