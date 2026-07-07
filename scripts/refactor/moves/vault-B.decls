## crate
crates/oneiron

## allowed
crates/oneiron/src/vault.rs
crates/oneiron/src/vault/affect.rs
crates/oneiron/src/vault/claim.rs
crates/oneiron/src/vault/deletion.rs
crates/oneiron/src/vault/provenance.rs
crates/oneiron/src/vault/tests.rs

## forbid

## anchors
struct	-	Vault	-	crates/oneiron/src/vault.rs
method	impl Vault	open	-	crates/oneiron/src/vault.rs
impl	-	impl ActorBound<'_>	-	crates/oneiron/src/vault.rs

## uniqueness

## error-literal

## decl
+ pub ( crate ) fn closed_claim_put_payload ( claim : & StoredProvenanceClaim , closed_record : & EdgeProvenanceClaimBody , lifecycle : ClaimLifecycleStatus ) -> Result < ( TimeRange , u64 , ClaimBody , Vec < u8 > ) >
+ pub ( crate ) fn decode_vad_annotation_claim_body_if_present ( raw : & [ u8 ] ) -> Result < Option < ClaimBody > >
+ pub ( crate ) fn memory_timeline_record_cmp ( left : & MemoryTimelineRecord , right : & MemoryTimelineRecord ) -> std :: cmp :: Ordering
+ pub ( crate ) fn sweep_extras ( captured : Option < & CapturedProvenanceDelete > ) -> HardEraseSweepExtras
+ pub ( crate ) fn vad_annotation_claim_body ( id : & EntityId , annotation : & VadAnnotation ) -> ClaimBody
+ pub ( crate ) fn vad_annotation_claim_matches_subject ( store : & Store , rtxn : & heed :: RoTxn < ' _ > , claim_id : & EntityId , annotated_id : & EntityId ) -> Result < bool >
+ pub ( crate ) fn vad_annotation_delete_scope_exists_in_txn ( store : & Store , txn : & heed :: RoTxn < ' _ > , id : & EntityId ) -> Result < bool >
+ pub ( crate ) fn vad_annotation_f32 ( value : & Value ) -> Result < f32 >
+ pub ( crate ) fn vad_annotation_from_value ( value : & Value ) -> Result < VadAnnotation >
+ pub ( crate ) fn vad_annotation_source_from_str ( value : & str ) -> Result < VadAnnotationSource >
+ pub ( crate ) fn vad_annotation_value ( annotation : & VadAnnotation ) -> Value
+ pub ( crate ) struct StoredProvenanceClaim
+ pub ( crate ) use self :: affect :: { VadAnnotationCleanup , decode_vad_annotation_claim_body_if_present , delete_vad_annotation_metadata_for_type_in_txn , delete_vad_annotation_metadata_in_txn , vad_annotation_claim_body , vad_annotation_claim_id , vad_annotation_claim_matches_subject , vad_annotation_delete_scope_exists_in_txn , vad_annotation_f32 , vad_annotation_from_value , vad_annotation_meta_key , vad_annotation_source_from_str , vad_annotation_value }
+ pub ( crate ) use self :: deletion :: { is_delete_protected_engine_record , memory_timeline_record_cmp , sweep_extras }
+ pub ( crate ) use self :: provenance :: { StoredProvenanceClaim , closed_claim_put_payload }

## impl-delta
- crates/oneiron/src/vault.rs	impl StoredProvenanceClaim
- crates/oneiron/src/vault.rs	impl VadAnnotationCleanup
+ crates/oneiron/src/vault/affect.rs	impl VadAnnotationCleanup
+ crates/oneiron/src/vault/affect.rs	impl Vault
+ crates/oneiron/src/vault/claim.rs	impl Vault
+ crates/oneiron/src/vault/deletion.rs	impl Vault
+ crates/oneiron/src/vault/provenance.rs	impl StoredProvenanceClaim
+ crates/oneiron/src/vault/provenance.rs	impl Vault
