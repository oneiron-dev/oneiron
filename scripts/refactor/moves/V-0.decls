## crate
crates/oneiron

## allowed
crates/oneiron/src/vault.rs

## anchors
struct	-	Vault	-	crates/oneiron/src/vault.rs
method	impl Vault	open	-	crates/oneiron/src/vault.rs
impl	-	impl ActorBound<'_>	-	crates/oneiron/src/vault.rs

## decl
+ pub ( crate ) const CLAIM_OF_DEFAULT_WEIGHT : f32
+ pub ( crate ) const MAX_EDGE_QUERY_RESULTS : usize
+ pub ( crate ) const SUPERSEDES_DEFAULT_WEIGHT : f32
+ pub ( crate ) fn edge_kind_prefix ( id : & EntityId , kind : EdgeKind ) -> [ u8 ; EDGE_KIND_PREFIX_LEN ]
+ pub ( crate ) fn entity_id_from_type_index_key ( key : & [ u8 ] ) -> Result < EntityId >
+ pub ( crate ) fn filtered_edge_peers ( & self , rtxn : & heed :: RoTxn < ' _ > , db : & Database < Bytes , Bytes > , prefix_id : & EntityId , kind : EdgeKind , peer_type : Option < u8 > , overflow_context : & ' static str ) -> Result < Vec < EntityId > >
+ pub ( crate ) fn live_window ( & self , key : & crate :: sync :: WindowKey ) -> Option < ( std :: sync :: Arc < crate :: sync :: window :: LoadedWindow > , std :: sync :: Arc < crate :: sync :: bridge :: Materializer > , ) >
+ pub ( crate ) fn read_entity_header ( & self , id : & EntityId ) -> Result < Option < EntityMetadataHeader > >
+ pub ( crate ) fn require_key_len ( key : & [ u8 ] , expected : usize , context : & ' static str ) -> Result < ( ) >

## edit
crates/oneiron/src/vault.rs	fn edge_kind_prefix(id: &EntityId, kind: EdgeKind) -> [u8; EDGE_KIND_PREFIX_LEN] {	pub(crate) fn edge_kind_prefix(id: &EntityId, kind: EdgeKind) -> [u8; EDGE_KIND_PREFIX_LEN] {
crates/oneiron/src/vault.rs	fn require_key_len(key: &[u8], expected: usize, context: &'static str) -> Result<()> {	pub(crate) fn require_key_len(key: &[u8], expected: usize, context: &'static str) -> Result<()> {
crates/oneiron/src/vault.rs	fn entity_id_from_type_index_key(key: &[u8]) -> Result<EntityId> {	pub(crate) fn entity_id_from_type_index_key(key: &[u8]) -> Result<EntityId> {
crates/oneiron/src/vault.rs	const CLAIM_OF_DEFAULT_WEIGHT: f32 = match EdgeKind::ClaimOf.default_weight() {	pub(crate) const CLAIM_OF_DEFAULT_WEIGHT: f32 = match EdgeKind::ClaimOf.default_weight() {
crates/oneiron/src/vault.rs	const SUPERSEDES_DEFAULT_WEIGHT: f32 = match EdgeKind::Supersedes.default_weight() {	pub(crate) const SUPERSEDES_DEFAULT_WEIGHT: f32 = match EdgeKind::Supersedes.default_weight() {
crates/oneiron/src/vault.rs	const MAX_EDGE_QUERY_RESULTS: usize = 100_000;	pub(crate) const MAX_EDGE_QUERY_RESULTS: usize = 100_000;
crates/oneiron/src/vault.rs	fn read_entity_header(&self, id: &EntityId) -> Result<Option<EntityMetadataHeader>> {	pub(crate) fn read_entity_header(&self, id: &EntityId) -> Result<Option<EntityMetadataHeader>> {
crates/oneiron/src/vault.rs	fn live_window(	pub(crate) fn live_window(
crates/oneiron/src/vault.rs	fn filtered_edge_peers(	pub(crate) fn filtered_edge_peers(
