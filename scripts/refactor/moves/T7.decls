## crate
crates/oneiron

## flat-name-check
yes

## allowed
crates/oneiron/src/agent_def/tests.rs
crates/oneiron/src/anchored_annotation/tests.rs
crates/oneiron/src/artifact_hosting/tests.rs
crates/oneiron/src/batch.rs
crates/oneiron/src/batch/tests.rs
crates/oneiron/src/blob_artifact/tests.rs
crates/oneiron/src/bm25/tests.rs
crates/oneiron/src/channel_identity/tests.rs
crates/oneiron/src/channel_identity_lifecycle/tests.rs
crates/oneiron/src/code_artifact.rs
crates/oneiron/src/code_revision/tests.rs
crates/oneiron/src/code_symbol/tests.rs
crates/oneiron/src/codebase/tests.rs
crates/oneiron/src/config.rs
crates/oneiron/src/context_pack/tests.rs
crates/oneiron/src/critic/tests.rs
crates/oneiron/src/dreamer_runner/tests.rs
crates/oneiron/src/dreamer_tournament/tests.rs
crates/oneiron/src/edit_settle/tests.rs
crates/oneiron/src/embed/tests.rs
crates/oneiron/src/gate/tests.rs
crates/oneiron/src/graph_fs/tests.rs
crates/oneiron/src/hnsw.rs
crates/oneiron/src/hnsw/tests.rs
crates/oneiron/src/identity.rs
crates/oneiron/src/inbox/tests.rs
crates/oneiron/src/ingest/tests.rs
crates/oneiron/src/lens/tests.rs
crates/oneiron/src/lib.rs
crates/oneiron/src/maintain/tests.rs
crates/oneiron/src/off_record/tests.rs
crates/oneiron/src/outbound/tests.rs
crates/oneiron/src/persona_snapshot/tests.rs
crates/oneiron/src/pipeline.rs
crates/oneiron/src/pipeline/tests.rs
crates/oneiron/src/policy_model/tests.rs
crates/oneiron/src/ppr.rs
crates/oneiron/src/ppr/tests.rs
crates/oneiron/src/psych_profile/tests.rs
crates/oneiron/src/receipt/tests.rs
crates/oneiron/src/skill/tests.rs
crates/oneiron/src/store.rs
crates/oneiron/src/surface_event/tests.rs
crates/oneiron/src/sweep/tests.rs
crates/oneiron/src/sync/bridge/tests.rs
crates/oneiron/src/sync/client/tests.rs
crates/oneiron/src/sync/connection/tests.rs
crates/oneiron/src/sync/convergence_props_internal.rs
crates/oneiron/src/sync/lease/tests.rs
crates/oneiron/src/sync/manager/tests.rs
crates/oneiron/src/sync/quarantine/tests.rs
crates/oneiron/src/sync/queue/tests.rs
crates/oneiron/src/sync/quota/tests.rs
crates/oneiron/src/sync/server_state.rs
crates/oneiron/src/sync/window/tests.rs
crates/oneiron/src/types.rs
crates/oneiron/src/vault.rs
crates/oneiron/src/vault/tests.rs

## error-literal
crates/oneiron/src/config.rs

## decl
+ pub mod config
+ pub use crate :: config :: { Bm25RankProfile , HnswConfig , TextAnalyzerConfig , TextIndexOptions , VaultConfig }
+ pub use crate :: types :: { ContextEntity , ContextPack , ContextPackRetrievalBudget , EIRI_CONTEXT_VERSION_V4 , EiriCompanionAssembly , EiriMemoryBoard , EiriMemoryBoardBudget , EiriMemoryBoardRow , EiriMemoryBoardSlot , EiriMemoryBoardSource , EiriSessionRagState , EmptyContext , EmptyReason , FieldProfile , HydratedShortIdDeletion , HydratedShortIdDeletionReason , HydratedShortIdDeletionSource , MemoryOperationKind , MemoryTimeline , MemoryTimelineRecord , MemoryTimelineRecordState , NamedMemoryVerb , NotificationItem , PackFormat , PackItemTokenStats , PackSectionTokenStats , PackStats , PackTokenStats , ResumeBudget , ResumeBundle , ScoredEntity , SessionContext , Signal , TokenAllocation , UnprocessedItem }
- pub use crate :: types :: { Bm25RankProfile , ContextEntity , ContextPack , ContextPackRetrievalBudget , EIRI_CONTEXT_VERSION_V4 , EiriCompanionAssembly , EiriMemoryBoard , EiriMemoryBoardBudget , EiriMemoryBoardRow , EiriMemoryBoardSlot , EiriMemoryBoardSource , EiriSessionRagState , EmptyContext , EmptyReason , FieldProfile , HnswConfig , HydratedShortIdDeletion , HydratedShortIdDeletionReason , HydratedShortIdDeletionSource , MemoryOperationKind , MemoryTimeline , MemoryTimelineRecord , MemoryTimelineRecordState , NamedMemoryVerb , NotificationItem , PackFormat , PackItemTokenStats , PackSectionTokenStats , PackStats , PackTokenStats , ResumeBudget , ResumeBundle , ScoredEntity , SessionContext , Signal , TextAnalyzerConfig , TextIndexOptions , TokenAllocation , UnprocessedItem , VaultConfig }
+ pub ( crate ) fn apply_ops ( store : & Store , config : & crate :: config :: VaultConfig , analyzer : & crate :: analyzer :: MultilingualAnalyzer , wtxn : & mut RwTxn < ' _ > , ops : Vec < BatchOp > , text_index_trusted : bool , record_gate_decisions : bool , persist_gate_pending_consent : bool ) -> Result < ( ) >
+ pub ( crate ) fn apply_ops_with_gate_mode ( store : & Store , config : & crate :: config :: VaultConfig , analyzer : & crate :: analyzer :: MultilingualAnalyzer , wtxn : & mut RwTxn < ' _ > , ops : Vec < BatchOp > , text_index_trusted : bool , gate_mode : ApplyOpsGateMode ) -> Result < ( ) >
+ pub fn rank_profile ( mut self , profile : crate :: config :: Bm25RankProfile ) -> Self
+ pub fn search_text_with_profile ( & self , query : & str , limit : usize , profile : & crate :: config :: Bm25RankProfile ) -> Result < Vec < ScoredEntity > >
+ pub fn search_text_with_profile_and_telemetry ( & self , query : & str , limit : usize , profile : & crate :: config :: Bm25RankProfile ) -> Result < RetrievalWithTelemetry < Vec < ScoredEntity > > >
- pub ( crate ) fn apply_ops ( store : & Store , config : & crate :: types :: VaultConfig , analyzer : & crate :: analyzer :: MultilingualAnalyzer , wtxn : & mut RwTxn < ' _ > , ops : Vec < BatchOp > , text_index_trusted : bool , record_gate_decisions : bool , persist_gate_pending_consent : bool ) -> Result < ( ) >
- pub ( crate ) fn apply_ops_with_gate_mode ( store : & Store , config : & crate :: types :: VaultConfig , analyzer : & crate :: analyzer :: MultilingualAnalyzer , wtxn : & mut RwTxn < ' _ > , ops : Vec < BatchOp > , text_index_trusted : bool , gate_mode : ApplyOpsGateMode ) -> Result < ( ) >
- pub fn rank_profile ( mut self , profile : crate :: types :: Bm25RankProfile ) -> Self
- pub fn search_text_with_profile ( & self , query : & str , limit : usize , profile : & crate :: types :: Bm25RankProfile ) -> Result < Vec < ScoredEntity > >
- pub fn search_text_with_profile_and_telemetry ( & self , query : & str , limit : usize , profile : & crate :: types :: Bm25RankProfile ) -> Result < RetrievalWithTelemetry < Vec < ScoredEntity > > >

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
crates/oneiron/src/bm25/tests.rs	text_analyzer: crate::types::TextAnalyzerConfig::default(),	text_analyzer: crate::config::TextAnalyzerConfig::default(),
crates/oneiron/src/bm25/tests.rs	crate::types::Bm25RankProfile::default().with_formula(Bm25Formula::Plus { delta: 1.0 });	crate::config::Bm25RankProfile::default().with_formula(Bm25Formula::Plus { delta: 1.0 });
crates/oneiron/src/bm25/tests.rs	let c = crate::types::Bm25RankProfile::default().to_bm25_config()?;	let c = crate::config::Bm25RankProfile::default().to_bm25_config()?;
crates/oneiron/src/bm25/tests.rs	let default_profile = crate::types::Bm25RankProfile::default();	let default_profile = crate::config::Bm25RankProfile::default();
crates/oneiron/src/bm25/tests.rs	crate::types::Bm25RankProfile::default().with_channel_weight(AnalyzerChannel::Stem, 0.0);	crate::config::Bm25RankProfile::default().with_channel_weight(AnalyzerChannel::Stem, 0.0);
crates/oneiron/src/bm25/tests.rs	let all_zero = crate::types::Bm25RankProfile::default()	let all_zero = crate::config::Bm25RankProfile::default()
crates/oneiron/src/bm25/tests.rs	crate::types::Bm25RankProfile::default().with_channel_weight(AnalyzerChannel::Stem, 0.0);	crate::config::Bm25RankProfile::default().with_channel_weight(AnalyzerChannel::Stem, 0.0);
crates/oneiron/src/bm25/tests.rs	let legal = crate::types::Bm25RankProfile::default()	let legal = crate::config::Bm25RankProfile::default()
crates/oneiron/src/context_pack/tests.rs	text_analyzer: crate::types::TextAnalyzerConfig::default(),	text_analyzer: crate::config::TextAnalyzerConfig::default(),
crates/oneiron/src/gate/tests.rs	crate::Vault::open(tmp.path(), crate::types::VaultConfig::default()).expect("open vault");	crate::Vault::open(tmp.path(), crate::config::VaultConfig::default()).expect("open vault");
crates/oneiron/src/gate/tests.rs	let mut config = crate::types::VaultConfig::device();	let mut config = crate::config::VaultConfig::device();
crates/oneiron/src/gate/tests.rs	let reopened = crate::Vault::open(tmp.path(), crate::types::VaultConfig::default())?;	let reopened = crate::Vault::open(tmp.path(), crate::config::VaultConfig::default())?;
crates/oneiron/src/lens/tests.rs	crate::test_util::open_test_vault_with(crate::types::VaultConfig::default())	crate::test_util::open_test_vault_with(crate::config::VaultConfig::default())
crates/oneiron/src/maintain/tests.rs	text_analyzer: crate::types::TextAnalyzerConfig::default(),	text_analyzer: crate::config::TextAnalyzerConfig::default(),
crates/oneiron/src/pipeline.rs	rank_profile: Option<crate::types::Bm25RankProfile>,	rank_profile: Option<crate::config::Bm25RankProfile>,
crates/oneiron/src/pipeline.rs	pub fn rank_profile(mut self, profile: crate::types::Bm25RankProfile) -> Self {	pub fn rank_profile(mut self, profile: crate::config::Bm25RankProfile) -> Self {
crates/oneiron/src/pipeline/tests.rs	text_analyzer: crate::types::TextAnalyzerConfig::default(),	text_analyzer: crate::config::TextAnalyzerConfig::default(),
crates/oneiron/src/pipeline/tests.rs	crate::types::Bm25RankProfile::default()	crate::config::Bm25RankProfile::default()
crates/oneiron/src/ppr/tests.rs	text_analyzer: crate::types::TextAnalyzerConfig::default(),	text_analyzer: crate::config::TextAnalyzerConfig::default(),
crates/oneiron/src/store.rs	//! [`VaultConfig::skip_text_index_manifest_check`]: crate::types::VaultConfig::skip_text_index_manifest_check	//! [`VaultConfig::skip_text_index_manifest_check`]: crate::config::VaultConfig::skip_text_index_manifest_check
crates/oneiron/src/sync/client/tests.rs	let config = crate::types::VaultConfig::device();	let config = crate::config::VaultConfig::device();
crates/oneiron/src/vault.rs	&crate::types::Bm25RankProfile::default(),	&crate::config::Bm25RankProfile::default(),
crates/oneiron/src/vault.rs	profile: &crate::types::Bm25RankProfile,	profile: &crate::config::Bm25RankProfile,
crates/oneiron/src/vault.rs	profile: &crate::types::Bm25RankProfile,	profile: &crate::config::Bm25RankProfile,
crates/oneiron/src/pipeline/tests.rs	use crate::types::{HnswConfig, VaultConfig};	use crate::config::{HnswConfig, VaultConfig};
crates/oneiron/src/ppr.rs	use crate::types::VaultConfig;	use crate::config::VaultConfig;
crates/oneiron/src/surface_event/tests.rs	use crate::types::VaultConfig;	use crate::config::VaultConfig;
crates/oneiron/src/sync/connection/tests.rs	use crate::types::VaultConfig;	use crate::config::VaultConfig;
crates/oneiron/src/sync/lease/tests.rs	use crate::types::VaultConfig;	use crate::config::VaultConfig;
crates/oneiron/src/sync/manager/tests.rs	use crate::types::VaultConfig;	use crate::config::VaultConfig;
crates/oneiron/src/sync/quota/tests.rs	use crate::types::VaultConfig;	use crate::config::VaultConfig;

## frag-edit

## comment

## add
crates/oneiron/src/config.rs	//! Caller-facing runtime configuration: `VaultConfig` + `HnswConfig` + `TextAnalyzerConfig` + `TextIndexOptions` + `Bm25RankProfile`.
