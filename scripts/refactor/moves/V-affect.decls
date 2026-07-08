## crate
crates/oneiron

## allowed
crates/oneiron/src/affect.rs
crates/oneiron/src/batch.rs
crates/oneiron/src/tests.rs
crates/oneiron/src/vault.rs

## anchors
struct	-	Vault	-	crates/oneiron/src/vault.rs
method	impl Vault	open	-	crates/oneiron/src/vault.rs
impl	-	impl ActorBound<'_>	-	crates/oneiron/src/vault.rs

## decl
+ pub ( crate ) fn vad_annotation_delete_scope_exists_in_txn ( store : & Store , txn : & heed :: RoTxn < ' _ > , id : & EntityId ) -> Result < bool >

## impl-delta
- crates/oneiron/src/vault.rs	impl VadAnnotationCleanup
+ crates/oneiron/src/affect.rs	impl VadAnnotationCleanup
+ crates/oneiron/src/affect.rs	impl Vault

## edit
crates/oneiron/src/batch.rs	let cleanup = crate::vault::delete_vad_annotation_metadata_in_txn(store, wtxn, id)?;	let cleanup = crate::affect::delete_vad_annotation_metadata_in_txn(store, wtxn, id)?;
crates/oneiron/src/batch.rs	let mut cleanup = crate::vault::VadAnnotationCleanup::default();	let mut cleanup = crate::affect::VadAnnotationCleanup::default();
crates/oneiron/src/batch.rs	crate::vault::delete_vad_annotation_metadata_for_type_in_txn(	crate::affect::delete_vad_annotation_metadata_for_type_in_txn(
crates/oneiron/src/tests.rs	use crate::vault::{vad_annotation_claim_id, vad_annotation_meta_key};	use crate::affect::{vad_annotation_claim_id, vad_annotation_meta_key};

## frag-edit

## add
crates/oneiron/src/affect.rs	impl Vault {
crates/oneiron/src/affect.rs	}
