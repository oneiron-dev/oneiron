## crate
crates/oneiron

## flat-name-check
yes

## allowed
crates/oneiron/src/agent_def/tests.rs
crates/oneiron/src/batch.rs
crates/oneiron/src/bm25.rs
crates/oneiron/src/config.rs
crates/oneiron/src/context_pack.rs
crates/oneiron/src/edit_settle/tests.rs
crates/oneiron/src/gate.rs
crates/oneiron/src/hnsw.rs
crates/oneiron/src/identity.rs
crates/oneiron/src/lens.rs
crates/oneiron/src/lib.rs
crates/oneiron/src/maintain.rs
crates/oneiron/src/pipeline.rs
crates/oneiron/src/ppr.rs
crates/oneiron/src/store.rs
crates/oneiron/src/surface_event.rs
crates/oneiron/src/sync/client.rs
crates/oneiron/src/sync/connection.rs
crates/oneiron/src/sync/convergence_props_internal.rs
crates/oneiron/src/sync/lease.rs
crates/oneiron/src/sync/manager.rs
crates/oneiron/src/sync/quota.rs
crates/oneiron/src/sync/server_state.rs
crates/oneiron/src/types.rs
crates/oneiron/src/vault.rs

## error-literal
crates/oneiron/src/config.rs

## decl
+ pub mod config
+ pub use crate :: config :: { Bm25RankProfile , HnswConfig , TextAnalyzerConfig , TextIndexOptions , VaultConfig }
+ pub use crate :: types :: { ContextEntity , ContextPack , ContextPackRetrievalBudget , EIRI_CONTEXT_VERSION_V4 , EiriCompanionAssembly , EiriMemoryBoard , EiriMemoryBoardBudget , EiriMemoryBoardRow , EiriMemoryBoardSlot , EiriMemoryBoardSource , EiriSessionRagState , EmptyContext , EmptyReason , FieldProfile , HydratedShortIdDeletion , HydratedShortIdDeletionReason , HydratedShortIdDeletionSource , MemoryOperationKind , MemoryTimeline , MemoryTimelineRecord , MemoryTimelineRecordState , NamedMemoryVerb , NotificationItem , PackFormat , PackItemTokenStats , PackSectionTokenStats , PackStats , PackTokenStats , ResumeBudget , ResumeBundle , ScoredEntity , SessionContext , Signal , TokenAllocation , UnprocessedItem }
- pub use crate :: types :: { Bm25RankProfile , ContextEntity , ContextPack , ContextPackRetrievalBudget , EIRI_CONTEXT_VERSION_V4 , EiriCompanionAssembly , EiriMemoryBoard , EiriMemoryBoardBudget , EiriMemoryBoardRow , EiriMemoryBoardSlot , EiriMemoryBoardSource , EiriSessionRagState , EmptyContext , EmptyReason , FieldProfile , HnswConfig , HydratedShortIdDeletion , HydratedShortIdDeletionReason , HydratedShortIdDeletionSource , MemoryOperationKind , MemoryTimeline , MemoryTimelineRecord , MemoryTimelineRecordState , NamedMemoryVerb , NotificationItem , PackFormat , PackItemTokenStats , PackSectionTokenStats , PackStats , PackTokenStats , ResumeBudget , ResumeBundle , ScoredEntity , SessionContext , Signal , TextAnalyzerConfig , TextIndexOptions , TokenAllocation , UnprocessedItem , VaultConfig }

## impl-delta
- crates/oneiron/src/types.rs	impl Bm25RankProfile
- crates/oneiron/src/types.rs	impl Default for Bm25RankProfile
- crates/oneiron/src/types.rs	impl Default for HnswConfig
- crates/oneiron/src/types.rs	impl Default for VaultConfig
- crates/oneiron/src/types.rs	impl VaultConfig
+ crates/oneiron/src/config.rs	impl Bm25RankProfile
+ crates/oneiron/src/config.rs	impl Default for Bm25RankProfile
+ crates/oneiron/src/config.rs	impl Default for HnswConfig
+ crates/oneiron/src/config.rs	impl Default for VaultConfig
+ crates/oneiron/src/config.rs	impl VaultConfig

## edit
crates/oneiron/src/batch.rs	config: &crate::types::VaultConfig,	config: &crate::config::VaultConfig,
crates/oneiron/src/batch.rs	config: &crate::types::VaultConfig,	config: &crate::config::VaultConfig,
crates/oneiron/src/batch.rs	config: &crate::types::VaultConfig,	config: &crate::config::VaultConfig,
crates/oneiron/src/bm25.rs	text_analyzer: crate::types::TextAnalyzerConfig::default(),	text_analyzer: crate::config::TextAnalyzerConfig::default(),
crates/oneiron/src/bm25.rs	crate::types::Bm25RankProfile::default().with_formula(Bm25Formula::Plus { delta: 1.0 });	crate::config::Bm25RankProfile::default().with_formula(Bm25Formula::Plus { delta: 1.0 });
crates/oneiron/src/bm25.rs	let c = crate::types::Bm25RankProfile::default().to_bm25_config()?;	let c = crate::config::Bm25RankProfile::default().to_bm25_config()?;
crates/oneiron/src/bm25.rs	let default_profile = crate::types::Bm25RankProfile::default();	let default_profile = crate::config::Bm25RankProfile::default();
crates/oneiron/src/bm25.rs	let stem_zero = crate::types::Bm25RankProfile::default()	let stem_zero = crate::config::Bm25RankProfile::default()
crates/oneiron/src/bm25.rs	let all_zero = crate::types::Bm25RankProfile::default()	let all_zero = crate::config::Bm25RankProfile::default()
crates/oneiron/src/bm25.rs	let stem_zero = crate::types::Bm25RankProfile::default()	let stem_zero = crate::config::Bm25RankProfile::default()
crates/oneiron/src/bm25.rs	let legal = crate::types::Bm25RankProfile::default()	let legal = crate::config::Bm25RankProfile::default()
crates/oneiron/src/context_pack.rs	text_analyzer: crate::types::TextAnalyzerConfig::default(),	text_analyzer: crate::config::TextAnalyzerConfig::default(),
crates/oneiron/src/gate.rs	let vault = crate::Vault::open(tmp.path(), crate::types::VaultConfig::default())	let vault = crate::Vault::open(tmp.path(), crate::config::VaultConfig::default())
crates/oneiron/src/gate.rs	let mut config = crate::types::VaultConfig::device();	let mut config = crate::config::VaultConfig::device();
crates/oneiron/src/gate.rs	let reopened = crate::Vault::open(tmp.path(), crate::types::VaultConfig::default())?;	let reopened = crate::Vault::open(tmp.path(), crate::config::VaultConfig::default())?;
crates/oneiron/src/lens.rs	crate::test_util::open_test_vault_with(crate::types::VaultConfig::default())	crate::test_util::open_test_vault_with(crate::config::VaultConfig::default())
crates/oneiron/src/maintain.rs	text_analyzer: crate::types::TextAnalyzerConfig::default(),	text_analyzer: crate::config::TextAnalyzerConfig::default(),
crates/oneiron/src/pipeline.rs	rank_profile: Option<crate::types::Bm25RankProfile>,	rank_profile: Option<crate::config::Bm25RankProfile>,
crates/oneiron/src/pipeline.rs	pub fn rank_profile(mut self, profile: crate::types::Bm25RankProfile) -> Self {	pub fn rank_profile(mut self, profile: crate::config::Bm25RankProfile) -> Self {
crates/oneiron/src/pipeline.rs	text_analyzer: crate::types::TextAnalyzerConfig::default(),	text_analyzer: crate::config::TextAnalyzerConfig::default(),
crates/oneiron/src/pipeline.rs	crate::types::Bm25RankProfile::default()	crate::config::Bm25RankProfile::default()
crates/oneiron/src/ppr.rs	text_analyzer: crate::types::TextAnalyzerConfig::default(),	text_analyzer: crate::config::TextAnalyzerConfig::default(),
crates/oneiron/src/store.rs	//! [`VaultConfig::skip_text_index_manifest_check`]: crate::types::VaultConfig::skip_text_index_manifest_check	//! [`VaultConfig::skip_text_index_manifest_check`]: crate::config::VaultConfig::skip_text_index_manifest_check
crates/oneiron/src/sync/client.rs	let config = crate::types::VaultConfig::device();	let config = crate::config::VaultConfig::device();
crates/oneiron/src/vault.rs	&crate::types::Bm25RankProfile::default(),	&crate::config::Bm25RankProfile::default(),
crates/oneiron/src/vault.rs	profile: &crate::types::Bm25RankProfile,	profile: &crate::config::Bm25RankProfile,
crates/oneiron/src/vault.rs	profile: &crate::types::Bm25RankProfile,	profile: &crate::config::Bm25RankProfile,
crates/oneiron/src/ppr.rs	use crate::types::VaultConfig;	use crate::config::VaultConfig;

## frag-edit

## comment

## add
crates/oneiron/src/config.rs	//! Caller-facing runtime configuration: `VaultConfig` + `HnswConfig` + `TextAnalyzerConfig` + `TextIndexOptions` + `Bm25RankProfile`.
