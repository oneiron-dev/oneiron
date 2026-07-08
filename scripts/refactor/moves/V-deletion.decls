## crate
crates/oneiron

## allowed
crates/oneiron/src/deletion.rs
crates/oneiron/src/off_record.rs
crates/oneiron/src/tests.rs
crates/oneiron/src/vault.rs

## anchors
struct	-	Vault	-	crates/oneiron/src/vault.rs
method	impl Vault	open	-	crates/oneiron/src/vault.rs
impl	-	impl ActorBound<'_>	-	crates/oneiron/src/vault.rs

## decl
+ pub ( crate ) fn entity_deletion_metadata ( & self , id : & EntityId , learned_at : u64 ) -> Result < Option < HydratedShortIdDeletion > >

## impl-delta
+ crates/oneiron/src/deletion.rs	impl Vault

## edit
crates/oneiron/src/off_record.rs	&& crate::vault::is_delete_protected_engine_record(entity_type)	&& crate::deletion::is_delete_protected_engine_record(entity_type)
crates/oneiron/src/tests.rs	crate::vault::install_after_header_read_signal(tx);	crate::deletion::install_after_header_read_signal(tx);

## frag-edit

## add
crates/oneiron/src/deletion.rs	impl Vault {
crates/oneiron/src/deletion.rs	}
