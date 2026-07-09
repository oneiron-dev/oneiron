## crate
crates/oneiron

## allowed
crates/oneiron/src/provenance.rs
crates/oneiron/src/vault.rs

## anchors
struct	-	Vault	-	crates/oneiron/src/vault.rs
method	impl Vault	open	-	crates/oneiron/src/vault.rs
impl	-	impl ActorBound<'_>	-	crates/oneiron/src/vault.rs

## decl

## impl-delta
- crates/oneiron/src/vault.rs	impl StoredProvenanceClaim
+ crates/oneiron/src/provenance.rs	impl StoredProvenanceClaim
+ crates/oneiron/src/provenance.rs	impl Vault

## edit

## frag-edit

## add
crates/oneiron/src/provenance.rs	impl Vault {
crates/oneiron/src/provenance.rs	}
