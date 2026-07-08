## crate
crates/oneiron

## allowed
crates/oneiron/src/vault.rs
crates/oneiron/src/claim.rs

## anchors
struct	-	Vault	-	crates/oneiron/src/vault.rs
method	impl Vault	open	-	crates/oneiron/src/vault.rs
impl	-	impl ActorBound<'_>	-	crates/oneiron/src/vault.rs

## impl-delta
+ crates/oneiron/src/claim.rs	impl Vault

## add
crates/oneiron/src/claim.rs	impl Vault {
crates/oneiron/src/claim.rs	}
