## crate
crates/oneiron

## allowed
crates/oneiron/src/vault.rs
crates/oneiron/src/channel_identity.rs

## anchors
struct	-	Vault	-	crates/oneiron/src/vault.rs
method	impl Vault	open	-	crates/oneiron/src/vault.rs
impl	-	impl ActorBound<'_>	-	crates/oneiron/src/vault.rs

## impl-delta
+ crates/oneiron/src/channel_identity.rs	impl Vault

## add
crates/oneiron/src/channel_identity.rs	impl Vault {
crates/oneiron/src/channel_identity.rs	}
