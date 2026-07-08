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
+ pub ( crate ) fn flags ( & self ) -> EdgeProvenanceFlags
+ pub ( crate ) fn live_edge_provenance_claims_in_txn ( & self , txn : & heed :: RoTxn < ' _ > , subject : & EdgeRef , exclude : Option < & EntityId > ) -> Result < Vec < StoredProvenanceClaim > >
+ pub ( crate ) fn precedence ( & self ) -> ProvenancePrecedence
+ pub ( crate ) fn retracted_edge_provenance_claims_in_txn ( & self , txn : & heed :: RoTxn < ' _ > , subject : & EdgeRef , exclude : Option < & EntityId > ) -> Result < Vec < StoredProvenanceClaim > >
+ pub ( crate ) struct StoredProvenanceClaim

## impl-delta
- crates/oneiron/src/vault.rs	impl StoredProvenanceClaim
+ crates/oneiron/src/provenance.rs	impl StoredProvenanceClaim
+ crates/oneiron/src/provenance.rs	impl Vault

## edit

## frag-edit
crates/oneiron/src/vault.rs	fn precedence(&self) -> ProvenancePrecedence {	pub(crate) fn precedence(&self) -> ProvenancePrecedence {
crates/oneiron/src/vault.rs	fn flags(&self) -> EdgeProvenanceFlags {	pub(crate) fn flags(&self) -> EdgeProvenanceFlags {

## add
crates/oneiron/src/provenance.rs	impl Vault {
crates/oneiron/src/provenance.rs	}
