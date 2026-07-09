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
+ pub ( crate ) fn flags ( & self ) -> EdgeProvenanceFlags
+ pub ( crate ) fn live_edge_provenance_claims_in_txn ( & self , txn : & heed :: RoTxn < ' _ > , subject : & EdgeRef , exclude : Option < & EntityId > ) -> Result < Vec < StoredProvenanceClaim > >
+ pub ( crate ) fn precedence ( & self ) -> ProvenancePrecedence
+ pub ( crate ) fn retracted_edge_provenance_claims_in_txn ( & self , txn : & heed :: RoTxn < ' _ > , subject : & EdgeRef , exclude : Option < & EntityId > ) -> Result < Vec < StoredProvenanceClaim > >
+ pub ( crate ) struct StoredProvenanceClaim

## impl-delta
+ crates/oneiron/src/deletion.rs	impl Vault

## edit
crates/oneiron/src/off_record.rs	&& crate::vault::is_delete_protected_engine_record(entity_type)	&& crate::deletion::is_delete_protected_engine_record(entity_type)
crates/oneiron/src/tests.rs	crate::vault::install_after_header_read_signal(tx);	crate::deletion::install_after_header_read_signal(tx);
crates/oneiron/src/vault.rs	fn live_edge_provenance_claims_in_txn(	pub(crate) fn live_edge_provenance_claims_in_txn(
crates/oneiron/src/vault.rs	fn retracted_edge_provenance_claims_in_txn(	pub(crate) fn retracted_edge_provenance_claims_in_txn(
crates/oneiron/src/vault.rs	struct StoredProvenanceClaim {	pub(crate) struct StoredProvenanceClaim {
crates/oneiron/src/vault.rs	fn precedence(&self) -> ProvenancePrecedence {	pub(crate) fn precedence(&self) -> ProvenancePrecedence {
crates/oneiron/src/vault.rs	fn flags(&self) -> EdgeProvenanceFlags {	pub(crate) fn flags(&self) -> EdgeProvenanceFlags {

## frag-edit
crates/oneiron/src/vault.rs	actor_class: EdgeActorClass,	pub(crate) actor_class: EdgeActorClass,

## add
crates/oneiron/src/deletion.rs	impl Vault {
crates/oneiron/src/deletion.rs	}
