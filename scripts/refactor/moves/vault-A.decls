## crate
crates/oneiron

## allowed
crates/oneiron/src/vault.rs
crates/oneiron/src/vault/access_grant.rs
crates/oneiron/src/vault/authority.rs
crates/oneiron/src/vault/channel_identity.rs
crates/oneiron/src/vault/companion.rs
crates/oneiron/src/vault/counterparty_contact.rs
crates/oneiron/src/vault/habit.rs
crates/oneiron/src/vault/outbound_grant.rs

## forbid

## anchors
struct	-	Vault	-	crates/oneiron/src/vault.rs
method	impl Vault	open	-	crates/oneiron/src/vault.rs
impl	-	impl ActorBound<'_>	-	crates/oneiron/src/vault.rs

## uniqueness

## error-literal

## decl
+ pub ( crate ) use self :: companion :: { companion_record_any_id_for_key_in_txn , companion_record_id_for_key_in_txn , companion_record_key_lookup_in_txn }

## impl-delta
+ crates/oneiron/src/vault/access_grant.rs	impl Vault
+ crates/oneiron/src/vault/authority.rs	impl Vault
+ crates/oneiron/src/vault/channel_identity.rs	impl Vault
+ crates/oneiron/src/vault/companion.rs	impl Vault
+ crates/oneiron/src/vault/counterparty_contact.rs	impl Vault
+ crates/oneiron/src/vault/habit.rs	impl Vault
+ crates/oneiron/src/vault/outbound_grant.rs	impl Vault
