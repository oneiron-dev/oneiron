//! The host doors of the verb-table rows only a server's own state answers:
//! the owner's `vault.packs.put`, `vault.hooks.replay` and
//! `vault.authority.audit`, the `ai.*` model calls past text, and
//! `ai.verdict` through the host's decision ladder. The
//! generated HTTP facade handler and the MCP dispatcher both call these, so
//! a tool call, a code-mode call and an SDK call meet one admission.
//!
//! The owner's pack, subscription, setup, audit, mesh and lens doors list
//! their rows (`host_door_lists`): each lists the rows its answer is read
//! from, and none for the state that lives in side tables or the authority
//! log, which hold no row.
//!
//! The `ai.*` doors admit as `/v1/ai/<operation>` does (api/ai/media.rs):
//! the call is the owner's, the vault's inference policy admits its model,
//! then its seat's ladder admits, sends and settles each rung it reaches.

mod admission;
mod artifacts_audit;
mod diary;
mod media;
mod packs;
pub(super) mod support;
mod verdict_hooks;

pub(super) use self::admission::*;
pub(crate) use self::artifacts_audit::*;
pub(crate) use self::diary::*;
pub(crate) use self::media::*;
pub(crate) use self::packs::*;
pub(crate) use self::support::*;
pub(crate) use self::verdict_hooks::*;

// The signed authority history doors, under the audit door's owner proof.
pub(crate) use super::artifact_hosting_doors::*;
pub(crate) use super::authority_history_doors::*;
pub(crate) use super::deck_creation_doors::*;
// The run-bound board STREAM doors (DOOR-121), likewise.
pub(crate) use super::board_stream_doors::*;
pub(crate) use super::booking_doors::*;
pub(crate) use super::browser_doors::*;
pub(crate) use super::calendar_doors::*;
pub(crate) use super::campaign_doors::*;
pub(crate) use super::compliance_doors::*;
pub(crate) use super::credential_doors::*;
pub(crate) use super::saved_query_doors::*;
pub(crate) use crate::api::anonymous_chat::ai_anonymous_chat;

// The shared-vault doors live beside these; the generated callers name them here.
pub(crate) use super::agent_definition_doors::*;
// The owner's agent grant doors (FIX 5628) too.
pub(crate) use super::agent_grant_doors::*;
// The owner's git_push Grant doors (FIX 6867, G1-PUSH) too.
pub(crate) use super::git_push_doors::*;
// The public run repo doors (FIX 6867, G1 PR3b): no owner proof, so none is
// in the owner preflight below.
pub(crate) use super::repo_doors::*;
pub(crate) use super::shared_act_doors::*;
pub(crate) use super::shared_admin_doors::*;
// The shared-vault invitation doors (OF-531) too.
pub(crate) use super::shared_member_doors::*;
// The shared-act policy doors (DOOR-129) too.
pub(crate) use super::shared_policy_doors::*;
// The trusted-contact doors (DOOR-140, OF-527) too.
pub(crate) use super::trusted_contact_doors::*;
// The voice-bank doors (DOOR-143, FIX 4393) too.
pub(crate) use super::voice_bank_doors::*;
// The owner's legal-hold doors (OF-470) too.
pub(crate) use super::asr_doors::*;
pub(crate) use super::cleanup_doors::*;
pub(crate) use super::clustering_doors::*;
pub(crate) use super::extraction_doors::*;
pub(crate) use super::identity_doors::*;
pub(crate) use super::legal_hold_doors::*;
pub(crate) use super::linear_doors::*;
pub(crate) use super::live_run_doors::*;
pub(crate) use super::live_voice_doors::*;
pub(crate) use super::mesh_doors::*;
pub(crate) use super::model_catalog_doors::*;
pub(crate) use super::model_manifest_doors::*;
pub(crate) use super::model_step_doors::*;
pub(crate) use super::model_stream_doors::*;
// The owner's committed-run reads (DOOR-141 A/B), likewise.
pub(crate) use super::run_read_doors::*;
// A turn program's reads (DOOR-141 PR3a), on the caller's own lane.
pub(crate) use super::program_read_doors::*;
pub(crate) use super::run_review_doors::*;
pub(crate) use super::sieve_observation_doors::*;
pub(crate) use super::skill_attribution_doors::*;
pub(crate) use super::skill_execution_doors::*;
// The owner's courtesy delete doors (OF-273) too.
pub(crate) use super::courtesy_delete_doors::*;
// The owner's guest revoke door (OF-232) too.
pub(crate) use super::coreference_doors::*;
// The owner's subject-bound feedback and report doors, likewise.
pub(crate) use super::federation_burst_doors::*;
pub(crate) use super::federation_connect_doors::*;
pub(crate) use super::feedback_doors::*;
// The owner's Files world source doors (FIX 6942), likewise.
pub(crate) use super::files_doors::*;
pub(crate) use super::goal_optimize_doors::*;
pub(crate) use super::guest_document_doors::*;
pub(crate) use super::guest_doors::*;
pub(crate) use super::hub_doors::*;
pub(crate) use super::identity_topology_doors::*;
pub(crate) use super::skill_default_doors::*;
pub(crate) use super::skill_doors::*;
// The owner's support grant doors (OF-606), as the guest ones are.
pub(crate) use super::support_grant_doors::*;
// The owner's residence doors (OF-534), likewise.
pub(crate) use super::fold_doors::*;
pub(crate) use super::foreign_code_doors::*;
pub(crate) use super::note_doors::*;
pub(crate) use super::off_record_doors::*;
pub(crate) use super::off_record_room_doors::*;
// The owner's pack preview door (FIX 5493), likewise.
pub(crate) use super::pack_preview_doors::*;
pub(crate) use super::persona_doors::*;
pub(crate) use super::residence_doors::*;
pub(crate) use super::summary_doors::*;
// The weave lens's human doors, likewise.
pub(crate) use super::weave_doors::*;
pub(crate) use super::web_fetch_doors::*;
// The graph ask and standing-question doors (OF-506), likewise.
pub(crate) use super::graph_ask_doors::*;
// The share doors past create (OF-491), likewise.
pub(crate) use super::share_doors::*;
// The role-holder decision-ask doors (OF-493), likewise.
pub(crate) use super::decision_ask_doors::*;
pub(crate) use super::decision_band_doors::*;
pub(crate) use super::disclosure_doors::*;
// The vault shape's apply door (ARCH-0070), likewise.
pub(crate) use super::vault_shape_doors::*;
// The owner's embedding-space doors (OF-370), likewise.
pub(crate) use super::embedding_space_doors::*;
// The owner's fan-out ruling doors (OF-393), likewise.
pub(crate) use super::budget_doors::*;
pub(crate) use super::fanout_doors::*;
pub(crate) use super::runner_seat_doors::*;
// The owner's learned-setting doors, likewise.
pub(crate) use super::learning_doors::*;
pub(crate) use super::seal_doors::*;
pub(crate) use super::setting_doors::*;
pub(crate) use super::slim_doors::*;
// The owner's historical secret lift sweep door (OF-067), likewise.
pub(crate) use super::secret_lift_doors::*;
// The usage repair doors (FIX 6476), likewise.
pub(crate) use super::usage_repair_doors::*;
// The owner's root wave door (OF-427), likewise.
pub(crate) use super::wave_doors::*;
// The owner's context-widen proposal doors (OF-568), likewise.
pub(crate) use super::widen_proposal_doors::*;
pub(crate) use super::wire_health_doors::*;
// The owner's craft-candidate review doors (OF-490), likewise.
pub(crate) use super::craft_candidate_doors::*;
// The app's policy-action doors (OF-181), likewise.
pub(crate) use super::channel_doors::*;
pub(crate) use super::consent_doors::*;
pub(crate) use super::content_policy_doors::*;
pub(crate) use super::gate_policy_doors::*;
pub(crate) use super::graduation_doors::*;
pub(crate) use super::policy_doors::*;
// The owner's origin and checkout doors (DOOR-139), likewise.
pub(crate) use super::checkout_doors::*;
pub(crate) use super::origin_doors::*;
// The exact publish doors (FIX 6866): the owner, or one Grant's holder.
pub(crate) use super::origin_publish_doors::*;
// The outside import doors (FIX 6871): the owner, or the push's standing.
pub(crate) use super::code_import_doors::*;
// The owner's code snapshot doors (DOOR-118), likewise.
pub(crate) use super::code_view_doors::*;
pub(crate) use super::codebase_doors::*;
// The owner's task-type tree doors (DOOR-111) and run doors (DOOR-100),
// likewise.
pub(crate) use super::coordination_doors::*;
// The generic connector call's door (ONE-2510), likewise.
pub(crate) use super::connector_call_doors::*;
pub(crate) use super::connector_pack_doors::*;
pub(crate) use super::connector_revision_doors::*;
pub(crate) use super::connector_slate_doors::*;
// The owner's witness-read grant revoke (FIX 10895), likewise.
pub(crate) use super::connector_witness_read_doors::*;
pub(crate) use super::proxy_doors::*;
pub(crate) use crate::api::openai_proxy::ai_chat_completions;
// The secret use door, whose connector.call sends (OF-560), likewise.
pub(crate) use super::secret_use_doors::*;
// An agent run's secret grant doors (DOOR-124), likewise.
pub(crate) use super::secret_grant_doors::*;
// The message reaction door (OF-181), likewise.
pub(crate) use super::reaction_doors::*;
pub(crate) use super::reply_doors::*;
pub(crate) use super::result_doors::*;
// The core write doors (OF-181), likewise.
pub(crate) use super::core_write_doors::*;
// The critic review door (OF-352), likewise.
pub(crate) use super::critic_review_doors::*;
// The owner's campaign split evaluation door (FIX 655), likewise.
pub(crate) use super::affect_doors::*;
pub(crate) use super::aging_doors::*;
pub(crate) use super::campaign_split_doors::*;
pub(crate) use super::coach_offer_doors::*;
pub(crate) use super::eval_doors::*;
pub(crate) use super::hyde_doors::*;
pub(crate) use super::research_doors::*;
pub(crate) use super::retrieval_doors::*;
pub(crate) use super::vector_doors::*;
// The owner's project-card tap door (OF-501), likewise.
pub(crate) use super::project_card_doors::*;
// The owner's proposed-claim review and settle doors (DOOR-115), likewise.
pub(crate) use super::claim_settle_doors::*;
// The plugin Context Board section doors (DOOR-112), likewise.
pub(crate) use super::commitment_doors::*;
pub(crate) use super::consolidation_doors::*;
pub(crate) use super::critical_confirm_doors::*;
pub(crate) use super::plugin_section_doors::*;
// The owner's sieve interest-queue, policy and lease doors (DOOR-130), likewise.
pub(crate) use super::sieve_doors::*;
// The owner's free-time policy, cycle and cycle-sheet doors (FIX 4453), likewise.
pub(crate) use super::free_time_doors::*;
// The owner's standing-block and dreaming-choice doors (DOOR-134), likewise.
pub(crate) use super::standing_doors::*;
// The owner's symbol lease, proposal submit and oplog doors (DOOR-137), likewise.
pub(crate) use super::code_doors::*;
// The owner's per-model code-run heal count door (DOOR-093), likewise.
pub(crate) use super::code_run_doors::*;
// The owner's code consent wait answer and receipt doors (DOOR-079), likewise.
pub(crate) use super::code_wait_doors::*;
// The owner's hook regeneration due, record and adopt doors (DOOR-077), likewise.
pub(crate) use super::hook_regen_doors::*;
pub(crate) use super::host_trigger_doors::*;
// The owner's speculative merge queue doors (DOOR-132), likewise.
pub(crate) use super::merge_queue_doors::*;
// The owner's merge queue checker doors (FIX 6868), likewise.
pub(crate) use super::merge_queue_checker_doors::*;
// The owner's root-request cancel door (FIX 5586), likewise.
pub(crate) use super::root_request_doors::*;
// The default lens's door, which holds its card's frame (OF-181), likewise.
pub(crate) use super::lens_selection_doors::*;
pub(crate) use super::ui_action_routes::vault_lenses_default;
// The explain receipts' doors (OF-278), beside their HTTP routes, likewise.
pub(crate) use crate::api::context_board::{vault_explain_gate, vault_explain_memory};
