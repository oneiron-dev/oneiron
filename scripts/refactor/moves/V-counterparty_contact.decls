## crate
crates/oneiron

## allowed
crates/oneiron/src/vault.rs
crates/oneiron/src/counterparty_contact.rs

## anchors
struct	-	Vault	-	crates/oneiron/src/vault.rs
method	impl Vault	open	-	crates/oneiron/src/vault.rs
impl	-	impl ActorBound<'_>	-	crates/oneiron/src/vault.rs

## impl-delta
+ crates/oneiron/src/counterparty_contact.rs	impl Vault

## add
crates/oneiron/src/counterparty_contact.rs	impl Vault {
crates/oneiron/src/counterparty_contact.rs	}
