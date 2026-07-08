## crate
crates/oneiron

## allowed
crates/oneiron/src/batch.rs
crates/oneiron/src/companion.rs
crates/oneiron/src/vault.rs

## anchors
struct	-	Vault	-	crates/oneiron/src/vault.rs
method	impl Vault	open	-	crates/oneiron/src/vault.rs
impl	-	impl ActorBound<'_>	-	crates/oneiron/src/vault.rs

## decl

## impl-delta
+ crates/oneiron/src/companion.rs	impl Vault

## edit
crates/oneiron/src/batch.rs	let lookup = crate::vault::companion_record_key_lookup_in_txn(	let lookup = crate::companion::companion_record_key_lookup_in_txn(

## frag-edit

## add
crates/oneiron/src/companion.rs	impl Vault {
crates/oneiron/src/companion.rs	}
