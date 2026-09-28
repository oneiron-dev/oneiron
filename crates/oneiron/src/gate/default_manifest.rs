use rmpv::Value;

use crate::channel_identity::{
    ACT_CLASS_CHANNEL_IDENTITY_OUTBOUND_SEND, ChannelIdentityShape,
    DEFAULT_CHANNEL_IDENTITY_QUARANTINE_MIN_SECS, SUBJECT_CLASS_SELF_HELD,
    WAIT_CLASS_CHANNEL_IDENTITY_QUARANTINE,
};
use crate::claim::{ClaimSource, UNSTAMPED_CLAIM_SENSITIVITY_BAND};
use crate::commitment_schedule::commitment_projection_actor;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::provenance::PREDICATE_EDGE_PROVENANCE;

use super::class_policy::ActPosture;
use super::constants::{
    ACT_POLICY_CLASS_KEY, ACT_POLICY_POSTURE_KEY, ACT_POLICY_SUBJECT_CLASS_KEY, ACTOR_CEILING_KEY,
    ACTOR_CLASS_KEY, ACTOR_REF_KEY, ATTRIBUTION_PRECEDENCE_KEY, ATTRIBUTION_REASON_MAX_BYTES_KEY,
    ATTRIBUTION_RECEIPTS_PER_PASS_KEY, AXIS_CRITICALITY_KEY, AXIS_SENSITIVITY_KEY,
    GATE_RETENTION_HOLDER_OVERRIDE_CEILING_KEY, GATE_RETENTION_HORIZON_SECS_KEY,
    GATE_RETENTION_MAX_SWEEP_ROWS_KEY, GATE_RETENTION_PRECEDENCE_KEY, LOCAL_WRITE_ACTOR_CLASS,
    POLICY_ACT_POLICY_KEY, POLICY_ACTOR_CEILINGS_KEY, POLICY_ATTRIBUTION_LIMITS_KEY,
    POLICY_CONNECTOR_CLASS_CARRY_KEY, POLICY_CONNECTOR_CLASS_PRECEDENCE_KEY,
    POLICY_CONNECTOR_CLASS_ROLE_KEY, POLICY_DEFAULTS_KEY, POLICY_GATE_DECISION_RETENTION_KEY,
    POLICY_HOSTED_TTS_KEY, POLICY_MIN_ENGINE_VERSION_KEY, POLICY_ON_BUDGET_EXHAUSTED_KEY,
    POLICY_OWNER_POLICY_ENABLED_KEY, POLICY_OWNER_POLICY_ROWS_KEY, POLICY_PACK_ID_KEY,
    POLICY_PACK_VERSION_KEY, POLICY_PPTX_COMMENT_LIMITS_KEY, POLICY_RULES_KEY,
    POLICY_SCHEMA_VERSION, POLICY_SCHEMA_VERSION_KEY, POLICY_SHEET_ANSWER_LIMITS_KEY,
    POLICY_SHEET_ANSWER_PRECEDENCE_KEY, POLICY_SIGNATURES_KEY, POLICY_SLIDE_REVIEW_KEY,
    POLICY_SOURCE_TRUST_KEY, POLICY_TEACHER_PROBE_KEY, POLICY_WAIT_POLICY_KEY,
    POLICY_WEAVE_CORRECTION_POLICY_KEY, RULE_AXES_KEY, RULE_EXACT_KEY, RULE_PREFIX_KEY,
    SIGNATURE_ALG_KEY, SIGNATURE_KEY_ID_KEY, SIGNATURE_SIG_KEY,
    SOURCE_TRUST_MAX_AUTO_SENSITIVITY_KEY, SOURCE_TRUST_RECEIPTED_KEY, SOURCE_TRUST_WARNED_KEY,
    WAIT_POLICY_CLASS_KEY, WAIT_POLICY_MIN_SECS_KEY,
};
use super::definition_ceiling::first_party_connector_actor_ref;
use super::pack_install_policy::{KEY as PACK_INSTALL_POLICY_KEY, PackInstallPolicy};
use super::resolution::{
    DEFAULT_ATTRIBUTION_REASON_MAX_BYTES, DEFAULT_ATTRIBUTION_RECEIPTS_PER_PASS,
};
use super::retrieval_retention::{RETRIEVAL_RETENTION_ROWS_KEY, default_retrieval_retention_rows};

const DEFAULT_POLICY_MANIFEST_ID: [u8; ENTITY_ID_LEN] = [0xD7; ENTITY_ID_LEN];
/// Seeded policy data, not a project-constructor or dispatch constant.
pub(crate) const SEEDED_PROJECT_DEPTH_DEFAULT: u8 = 10;
pub(crate) const SEEDED_PROJECT_DEPTH_MAX: u8 = 16;

pub(crate) const fn seeded_project_depth_default() -> u8 {
    SEEDED_PROJECT_DEPTH_DEFAULT
}
pub(crate) const DEFAULT_POLICY_MANIFEST_TIMESTAMP: u64 = 0;

/// Shipped policy data; organ users resolve this row or supply their own
/// positive budgets. No fallback numbers live in the XML/ZIP implementation.
pub(in crate::gate) fn default_docedit_resource_row() -> Value {
    Value::Map(vec![
        (
            Value::from("archive_bytes"),
            Value::from(512 * 1024 * 1024u64),
        ),
        (Value::from("entries"), Value::from(10_000u64)),
        (Value::from("part_bytes"), Value::from(64 * 1024 * 1024u64)),
        (
            Value::from("expanded_bytes"),
            Value::from(512 * 1024 * 1024u64),
        ),
        (Value::from("xml_depth"), Value::from(256u64)),
        (Value::from("xml_nodes"), Value::from(1_000_000u64)),
    ])
}

pub(crate) fn default_policy_manifest_id() -> Result<EntityId> {
    EntityId::from_bytes(DEFAULT_POLICY_MANIFEST_ID)
        .map_err(|_| Error::InvariantViolation("invalid default policy manifest id"))
}

// One row per default policy entry: the manifest is a data table, and splitting it would scatter one manifest.
#[allow(clippy::too_many_lines)]
pub(crate) fn default_policy_manifest() -> Vec<u8> {
    let first_party_actor_ref = first_party_connector_actor_ref();
    // Per a provisional architectural ruling (owner batch pending): the
    // commitment projector's actor id is derived, not authored, so the row is
    // computed here rather than pinned as a hex literal. If the domain constant
    // behind the derivation ever moves, the row dangles and mints pend —
    // fail-closed, never silently re-aimed.
    let commitment_projection_actor_ref = commitment_projection_actor().entity_ref().to_hex();
    let manifest = Value::Map(vec![
        (
            Value::from(POLICY_SCHEMA_VERSION_KEY),
            Value::from(POLICY_SCHEMA_VERSION),
        ),
        (
            Value::from(super::constants::POLICY_ASK_POLICY_KEY),
            super::ask_policy::AskOperationalPolicy::default_manifest_value(),
        ),
        (
            Value::from("retry_source_policy"),
            Value::Array(vec![Value::Map(vec![
                (Value::from("selector"), Value::from("vault")),
                (Value::from("max_sources"), Value::from(1_024_u64)),
                (Value::from("precedence"), Value::from("nested_narrowing")),
            ])]),
        ),
        (
            Value::from(POLICY_PACK_ID_KEY),
            Value::from("oneiron-default-policy"),
        ),
        (
            Value::from("project_depth_default"),
            Value::from(SEEDED_PROJECT_DEPTH_DEFAULT),
        ),
        (
            Value::from("project_depth_max"),
            Value::from(SEEDED_PROJECT_DEPTH_MAX),
        ),
        (
            Value::from(crate::skill_optimize::policy::MANIFEST_KEY),
            Value::Map(vec![
                (Value::from("ask_minutes"), Value::from(1)),
                (Value::from("max_context_bytes"), Value::from(512)),
            ]),
        ),
        (Value::from(POLICY_PACK_VERSION_KEY), Value::from("v1")),
        (
            Value::from(super::voice_serving::KEY),
            super::voice_serving::VoiceServingRows::seeded(),
        ),
        (
            Value::from(POLICY_WEAVE_CORRECTION_POLICY_KEY),
            Value::Map(vec![
                (Value::from("vault_max"), Value::from(10_000)),
                (Value::from("default"), Value::from(10_000)),
                (Value::from("holders"), Value::Map(Vec::new())),
                (
                    Value::from("precedence"),
                    Value::from("holder_then_default"),
                ),
            ]),
        ),
        (
            Value::from(POLICY_MIN_ENGINE_VERSION_KEY),
            Value::from(env!("CARGO_PKG_VERSION")),
        ),
        (Value::from("room_thread"), room_thread_default_row()),
        (
            Value::from(super::carry_forward_policy::KEY),
            Value::Map(vec![
                (Value::from("precedence"), Value::from("nested_narrowing")),
                (
                    Value::from("vault"),
                    Value::Map(vec![
                        (
                            Value::from("ordinary"),
                            Value::F32(super::carry_forward_policy::DEFAULT_ORDINARY),
                        ),
                        (
                            Value::from("care"),
                            Value::F32(super::carry_forward_policy::DEFAULT_CARE),
                        ),
                    ]),
                ),
            ]),
        ),
        (
            Value::from(POLICY_DEFAULTS_KEY),
            Value::Map(vec![
                (Value::from(AXIS_CRITICALITY_KEY), Value::from("critical")),
                (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
            ]),
        ),
        // Shipped voice-reference limits are editable policy data. Owner packs
        // replace named defaults; the default precedence keeps holders under
        // the vault ceiling and narrows multiple trusted contributions.
        (
            Value::from("voice_ref_limits"),
            Value::Map(vec![
                (Value::from("precedence"), Value::from("nested_narrowing")),
                (
                    Value::from("vault"),
                    Value::Map(vec![
                        (Value::from("max_clips_per_pack"), Value::from(32u64)),
                        (
                            Value::from("max_audio_bytes_per_pack"),
                            Value::from(16u64 * 1024 * 1024),
                        ),
                        (Value::from("max_register_bytes"), Value::from(128u64)),
                        (Value::from("max_transcript_bytes"), Value::from(16_384u64)),
                        (
                            Value::from("max_design_vendor_bytes"),
                            Value::from(4_096u64),
                        ),
                        (
                            Value::from("max_vendor_voice_id_bytes"),
                            Value::from(4_096u64),
                        ),
                    ]),
                ),
            ]),
        ),
        (
            Value::from("goal_limits"),
            crate::workspace_roster::GoalLimits::default().encode(),
        ),
        (
            Value::from(POLICY_RULES_KEY),
            Value::Array(vec![
                Value::Map(vec![
                    (Value::from(RULE_PREFIX_KEY), Value::from("profile.")),
                    (
                        Value::from(RULE_AXES_KEY),
                        Value::Map(vec![
                            (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                            (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                        ]),
                    ),
                ]),
                // Conversation append is ordinary authored content. Generated
                // auto still requires an actor-bound source-trust permit.
                Value::Map(vec![
                    (
                        Value::from(RULE_PREFIX_KEY),
                        Value::from("conversation.append_record"),
                    ),
                    (Value::from(RULE_EXACT_KEY), Value::Boolean(true)),
                    (
                        Value::from(RULE_AXES_KEY),
                        Value::Map(vec![
                            (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                            (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                        ]),
                    ),
                ]),
                Value::Map(vec![
                    (
                        Value::from(RULE_PREFIX_KEY),
                        Value::from(crate::commitment::PREDICATE_COMMITMENT_RECORD),
                    ),
                    (Value::from(RULE_EXACT_KEY), Value::Boolean(true)),
                    (
                        Value::from(RULE_AXES_KEY),
                        Value::Map(vec![
                            (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                            (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                        ]),
                    ),
                ]),
                // A goal-intake candidate still needs a human-authenticated
                // write door; the ordinary claim gate must not strand that
                // confirmed interview at the unrelated critical-consent floor.
                Value::Map(vec![
                    (
                        Value::from(RULE_PREFIX_KEY),
                        Value::from("project.goal_intake"),
                    ),
                    (Value::from(RULE_EXACT_KEY), Value::Boolean(true)),
                    (
                        Value::from(RULE_AXES_KEY),
                        Value::Map(vec![
                            (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                            (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                        ]),
                    ),
                ]),
                // A delivered-send receipt projects this non-restrictive
                // standing fact. Keep the rule exact: comm.opt_out still
                // inherits the critical floor and cannot auto-widen consent.
                Value::Map(vec![
                    (
                        Value::from(RULE_PREFIX_KEY),
                        Value::from(crate::comm::PREDICATE_COMM_LAST_TOUCH),
                    ),
                    (Value::from(RULE_EXACT_KEY), Value::Boolean(true)),
                    (
                        Value::from(RULE_AXES_KEY),
                        Value::Map(vec![
                            (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                            (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                        ]),
                    ),
                ]),
                Value::Map(vec![
                    (Value::from(RULE_PREFIX_KEY), Value::from("calendar.")),
                    (
                        Value::from(RULE_AXES_KEY),
                        Value::Map(vec![
                            (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                            (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                        ]),
                    ),
                ]),
                Value::Map(vec![
                    (Value::from(RULE_PREFIX_KEY), Value::from("booking.")),
                    (
                        Value::from(RULE_AXES_KEY),
                        Value::Map(vec![
                            (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                            (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                        ]),
                    ),
                ]),
                Value::Map(vec![
                    (Value::from(RULE_PREFIX_KEY), Value::from("affect.vad")),
                    (Value::from(RULE_EXACT_KEY), Value::Boolean(true)),
                    (
                        Value::from(RULE_AXES_KEY),
                        Value::Map(vec![
                            (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                            (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                        ]),
                    ),
                ]),
                // A recorder's own segment descriptor: span, channel count,
                // AEC mode, device. It says what the captured bytes ARE, never
                // what was said in them, so it carries no transcript content
                // and reads `normal` on both axes — the same standing as the
                // VAD row above. Exact-keyed: `voice.transcript` and any
                // `voice.segment.*` refinement inherit nothing and stay at the
                // fail-closed default.
                Value::Map(vec![
                    (
                        Value::from(RULE_PREFIX_KEY),
                        Value::from(crate::voice_segment::PREDICATE_VOICE_SEGMENT),
                    ),
                    (Value::from(RULE_EXACT_KEY), Value::Boolean(true)),
                    (
                        Value::from(RULE_AXES_KEY),
                        Value::Map(vec![
                            (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                            (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                        ]),
                    ),
                ]),
                Value::Map(vec![
                    (
                        Value::from(RULE_PREFIX_KEY),
                        Value::from(crate::skill_hub::PREDICATE_SKILL_SCAN_VERDICT),
                    ),
                    (Value::from(RULE_EXACT_KEY), Value::Boolean(true)),
                    (
                        Value::from(RULE_AXES_KEY),
                        Value::Map(vec![
                            (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                            (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                        ]),
                    ),
                ]),
                Value::Map(vec![
                    (
                        Value::from(RULE_PREFIX_KEY),
                        Value::from(crate::skill_hub::PREDICATE_SKILL_HUB_PROVENANCE),
                    ),
                    (Value::from(RULE_EXACT_KEY), Value::Boolean(true)),
                    (
                        Value::from(RULE_AXES_KEY),
                        Value::Map(vec![
                            (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                            (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                        ]),
                    ),
                ]),
                Value::Map(vec![
                    (
                        Value::from(RULE_PREFIX_KEY),
                        Value::from(crate::skill_hub::PREDICATE_SKILL_HUB_UPDATE_PROPOSAL),
                    ),
                    (Value::from(RULE_EXACT_KEY), Value::Boolean(true)),
                    (
                        Value::from(RULE_AXES_KEY),
                        Value::Map(vec![
                            (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                            (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                        ]),
                    ),
                ]),
                Value::Map(vec![
                    (
                        Value::from(RULE_PREFIX_KEY),
                        Value::from(crate::provider_confidence::PREDICATE_ACTOR_CONFIDENCE_PRIOR),
                    ),
                    (Value::from(RULE_EXACT_KEY), Value::Boolean(true)),
                    (
                        Value::from(RULE_AXES_KEY),
                        Value::Map(vec![
                            (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                            (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                        ]),
                    ),
                ]),
                Value::Map(vec![
                    (
                        Value::from(RULE_PREFIX_KEY),
                        Value::from(crate::provider_confidence::PREDICATE_PROVIDER_ENRICHMENT),
                    ),
                    (Value::from(RULE_EXACT_KEY), Value::Boolean(true)),
                    (
                        Value::from(RULE_AXES_KEY),
                        Value::Map(vec![
                            (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                            (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                        ]),
                    ),
                ]),
                Value::Map(vec![
                    (
                        Value::from(RULE_PREFIX_KEY),
                        Value::from(PREDICATE_EDGE_PROVENANCE),
                    ),
                    (
                        Value::from(RULE_AXES_KEY),
                        Value::Map(vec![
                            (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                            (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                        ]),
                    ),
                ]),
            ]),
        ),
        (
            Value::from(POLICY_ACTOR_CEILINGS_KEY),
            Value::Array(vec![
                Value::Map(vec![
                    (
                        Value::from(ACTOR_CLASS_KEY),
                        Value::from(LOCAL_WRITE_ACTOR_CLASS),
                    ),
                    (Value::from(ACTOR_CEILING_KEY), Value::from("auto")),
                ]),
                Value::Map(vec![
                    (Value::from(ACTOR_CLASS_KEY), Value::from("human")),
                    (Value::from(ACTOR_CEILING_KEY), Value::from("auto")),
                ]),
                Value::Map(vec![
                    (Value::from(ACTOR_CLASS_KEY), Value::from("agent")),
                    (
                        Value::from(ACTOR_REF_KEY),
                        Value::from(first_party_actor_ref),
                    ),
                    (Value::from(ACTOR_CEILING_KEY), Value::from("auto")),
                ]),
                // Per a provisional architectural ruling (owner batch
                // pending): the commitment projector writes engine-derived
                // occurrences of an obligation the owner already consented to
                // when the series was written, under a System actor. The row is
                // keyed to that ONE derived actor id — class `system` as a whole
                // keeps default-deny, so no other present or future system actor
                // inherits this grant.
                //
                // Reversal: delete this row and the `generated` source-trust row
                // below; projection mints pend again (fail-closed), and claims
                // already auto-approved stand as written history.
                Value::Map(vec![
                    (Value::from(ACTOR_CLASS_KEY), Value::from("system")),
                    (
                        Value::from(ACTOR_REF_KEY),
                        Value::from(commitment_projection_actor_ref.clone()),
                    ),
                    (Value::from(ACTOR_CEILING_KEY), Value::from("auto")),
                ]),
            ]),
        ),
        (
            Value::from(POLICY_SOURCE_TRUST_KEY),
            Value::Map(vec![
                (
                    Value::from(ClaimSource::ToolOutput.as_str()),
                    Value::Map(vec![
                        (
                            Value::from(SOURCE_TRUST_MAX_AUTO_SENSITIVITY_KEY),
                            Value::from(0_u64),
                        ),
                        (
                            Value::from(SOURCE_TRUST_RECEIPTED_KEY),
                            Value::Boolean(true),
                        ),
                        (Value::from(SOURCE_TRUST_WARNED_KEY), Value::Boolean(true)),
                    ]),
                ),
                // Per a provisional architectural ruling (owner batch
                // pending): `Generated` demands an explicit auto permit,
                // so without this row every deterministic projection write pends
                // on source trust. The cap is exact parity with the band the
                // minted claims actually carry — the projector stamps no scope
                // sensitivity, so they read at the unstamped floor — and NOT one
                // band of headroom: a `Generated` claim one band above this cap
                // still pends, keeping the sensitivity ladder intact.
                // `receipted`/`warned` keep every auto-approved projection write
                // surfaced rather than passing silently.
                //
                // `actor_ref` is what makes the row NARROW (ONE-1749), and it is
                // load-bearing rather than decorative: the cap alone cannot
                // narrow anything here, because it sits exactly AT the unstamped
                // provenance floor every unstamped claim reads. Unbound, this
                // row auto-approved every `Generated` write in the vault — code
                // emissions, dreamer output, agent projections — and collapsed
                // the class's default-deny. Keyed to the ONE derived projection
                // actor, the permit answers that writer and nobody else; every
                // other `Generated` writer reads the class as having no row and
                // keeps pending on `gate.pending.source_trust`. Same shape and
                // same reason as the actor-keyed `system` ceiling row above.
                //
                // Reversal: delete this row and the `system` actor-ceiling row
                // above; projection mints pend again (fail-closed).
                (
                    Value::from(ClaimSource::Generated.as_str()),
                    Value::Map(vec![
                        (
                            Value::from(ACTOR_REF_KEY),
                            Value::from(commitment_projection_actor_ref),
                        ),
                        (
                            Value::from(SOURCE_TRUST_MAX_AUTO_SENSITIVITY_KEY),
                            Value::from(u64::from(UNSTAMPED_CLAIM_SENSITIVITY_BAND)),
                        ),
                        (
                            Value::from(SOURCE_TRUST_RECEIPTED_KEY),
                            Value::Boolean(true),
                        ),
                        (Value::from(SOURCE_TRUST_WARNED_KEY), Value::Boolean(true)),
                    ]),
                ),
            ]),
        ),
        // Hosted render resource limits are shipped POLICY rows, not adapter
        // constants. Holder rows in other trusted manifests can narrow them.
        (
            Value::from(POLICY_HOSTED_TTS_KEY),
            Value::Map(vec![
                (Value::from("precedence"), Value::from("nested_narrowing")),
                (
                    Value::from("rows"),
                    Value::Array(
                        ["cartesia", "elevenlabs_flash"]
                            .into_iter()
                            .map(|provider| {
                                Value::Map(vec![
                                    (Value::from("provider"), Value::from(provider)),
                                    (Value::from("scope"), Value::from("vault")),
                                    (Value::from("max_text_bytes"), Value::from(8_192_u64)),
                                    (
                                        Value::from("max_pcm_fragment_bytes"),
                                        Value::from(2_097_152_u64),
                                    ),
                                ])
                            })
                            .collect(),
                    ),
                ),
            ]),
        ),
        (
            Value::from(PACK_INSTALL_POLICY_KEY),
            PackInstallPolicy::shipped().encode(),
        ),
        // OF-379 compilation is policy, not a Rust-owned language heuristic.
        // A holder row can narrow this vault row, never widen it.
        (
            Value::from("compilation_policy"),
            Value::Map(vec![
                (
                    Value::from("precedence"),
                    Value::from("nested_narrowing_holder_capped_at_vault"),
                ),
                (
                    Value::from("order"),
                    Value::Array(vec![
                        Value::from("style_rule"),
                        Value::from("charter_line"),
                        Value::from("brief_update"),
                        Value::from("ban"),
                    ]),
                ),
                (
                    Value::from("rows"),
                    Value::Array(vec![Value::Map(vec![(
                        Value::from("routes"),
                        Value::Array(vec![
                            compilation_route(
                                "style_rule",
                                "expression.style:",
                                true,
                                "",
                                "",
                                true,
                            ),
                            compilation_route("charter_line", "charter:", true, "", "", false),
                            compilation_route("brief_update", "brief:", true, "", "", false),
                            compilation_route("ban", "", false, "never ", "never ", false),
                        ]),
                    )])]),
                ),
            ]),
        ),
        (
            Value::from(RETRIEVAL_RETENTION_ROWS_KEY),
            default_retrieval_retention_rows(),
        ),
        attribution_limits_default_entry(),
        (
            Value::from(crate::federation::grant_policy::ROWS_KEY),
            federation_grant_default_rows(),
        ),
        (
            Value::from(POLICY_CONNECTOR_CLASS_ROLE_KEY),
            Value::from("vault"),
        ),
        (
            Value::from(POLICY_CONNECTOR_CLASS_PRECEDENCE_KEY),
            Value::from("nested"),
        ),
        (
            Value::from(POLICY_CONNECTOR_CLASS_CARRY_KEY),
            Value::Array(vec![
                Value::Array(vec![Value::from("public"), Value::from("personal")]),
                Value::Array(vec![Value::from("public"), Value::from("secret")]),
                Value::Array(vec![Value::from("personal"), Value::from("secret")]),
            ]),
        ),
        teacher_probe_default_entry(),
        (
            Value::from(POLICY_SHEET_ANSWER_PRECEDENCE_KEY),
            Value::Map(vec![(
                Value::from("mode"),
                Value::from("nested_narrowing_holder_capped_at_vault"),
            )]),
        ),
        (
            Value::from(POLICY_SHEET_ANSWER_LIMITS_KEY),
            Value::Array(vec![Value::Map(vec![(
                Value::from("max_count"),
                Value::from(4096u64),
            )])]),
        ),
        (
            Value::from(super::constants::POLICY_DOCEDIT_RESOURCE_KEY),
            default_docedit_resource_row(),
        ),
        (
            Value::from("experiment_selection"),
            default_experiment_selection_rows(),
        ),
        (
            Value::from(POLICY_ON_BUDGET_EXHAUSTED_KEY),
            Value::from("suspend"),
        ),
        super::room_policy::default_entry(),
        default_gate_decision_retention_entry(),
        (
            Value::from(POLICY_PPTX_COMMENT_LIMITS_KEY),
            crate::edit_roundtrip::pptx::PptxOperationalLimits::default().policy_row(),
        ),
        (
            Value::from(POLICY_SLIDE_REVIEW_KEY),
            crate::llm::decision::SlideReviewPolicy::default_rows(),
        ),
        super::docx_budget::default_entry(),
        (
            Value::from("booking_conversion"),
            Value::Array(vec![
                rmpv::ext::to_value(
                    serde_json::to_value(crate::booking::BookingConversionPolicyRow {
                        scope: crate::booking::BookingPolicyScope::Vault,
                        holder_ref: None,
                        policy: crate::booking::BookingConversionPolicy::default(),
                    })
                    .expect("default booking conversion row encodes"),
                )
                .expect("default booking conversion JSON becomes MessagePack"),
            ]),
        ),
        // The owner policy plane ships OFF with zero rows: a fresh vault
        // classifies nothing and calls no safeguard model until its owner
        // opts in and writes their own rows.
        (
            Value::from(POLICY_OWNER_POLICY_ENABLED_KEY),
            Value::Boolean(false),
        ),
        (
            Value::from(POLICY_OWNER_POLICY_ROWS_KEY),
            Value::Array(Vec::new()),
        ),
        // GATE-009: the restrictive STARTING values for the two class
        // tables ship here, in the vault-resident default manifest, rather
        // than as engine constants (DEC-0005; owner rule 2026-09-27). Both
        // rows state today's behavior — they change nothing on a fresh vault
        // and everything about who owns the decision.
        wait_policy_default_entry(),
        act_policy_default_entry(),
        (
            Value::from(POLICY_SIGNATURES_KEY),
            Value::Array(vec![Value::Map(vec![
                (Value::from(SIGNATURE_ALG_KEY), Value::from("ed25519")),
                (Value::from(SIGNATURE_KEY_ID_KEY), Value::from("owner")),
                (
                    Value::from(SIGNATURE_SIG_KEY),
                    Value::from("first-party-agent-auto"),
                ),
            ])]),
        ),
    ]);
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &manifest).expect("encode default policy manifest");
    data
}

/// Shipped project-room thread liveness data: base budgets, the vault
/// ceiling, precedence and allowed fills.
fn room_thread_default_row() -> Value {
    Value::Map(vec![
        (
            Value::from("base"),
            Value::Map(vec![
                (Value::from("fresh_for_secs"), Value::from(7 * 86_400_u64)),
                (Value::from("rows_per_list"), Value::from(8)),
                (Value::from("tokens_per_list"), Value::from(512)),
                (Value::from("fill"), Value::from("stage")),
                (Value::from("waits_per_thread"), Value::from(8)),
            ]),
        ),
        (
            Value::from("vault_ceiling"),
            Value::Map(vec![
                (Value::from("fresh_for_secs"), Value::from(30 * 86_400_u64)),
                (Value::from("rows_per_list"), Value::from(1_000)),
                (Value::from("tokens_per_list"), Value::from(65_536)),
                (Value::from("fill"), Value::from("stage")),
                (Value::from("waits_per_thread"), Value::from(128)),
            ]),
        ),
        (Value::from("precedence"), Value::from("nested_narrowing")),
        (
            Value::from("allowed_fills"),
            Value::Array(vec![
                Value::from("recency"),
                Value::from("nudge_due"),
                Value::from("stage"),
            ]),
        ),
        (Value::from("holder_rows"), Value::Array(Vec::new())),
    ])
}

/// The shipped attribution limits: precedence and the two byte/count caps.
fn attribution_limits_default_entry() -> (Value, Value) {
    (
        Value::from(POLICY_ATTRIBUTION_LIMITS_KEY),
        Value::Map(vec![
            (
                Value::from(ATTRIBUTION_PRECEDENCE_KEY),
                Value::from("nested_narrowing"),
            ),
            (
                Value::from(ATTRIBUTION_REASON_MAX_BYTES_KEY),
                Value::from(DEFAULT_ATTRIBUTION_REASON_MAX_BYTES),
            ),
            (
                Value::from(ATTRIBUTION_RECEIPTS_PER_PASS_KEY),
                Value::from(DEFAULT_ATTRIBUTION_RECEIPTS_PER_PASS),
            ),
        ]),
    )
}

/// The shipped teacher probe floor, with no holder rows.
fn teacher_probe_default_entry() -> (Value, Value) {
    (
        Value::from(POLICY_TEACHER_PROBE_KEY),
        Value::Map(vec![
            (
                Value::from("probe_id"),
                Value::from(crate::llm::manifest::TEACHER_PROBE_ID),
            ),
            (Value::from("min_f1_millionths"), Value::from(800_000_u64)),
            (Value::from("holders"), Value::Array(Vec::new())),
        ]),
    )
}

/// The shipped `wait_policy` entry (GATE-009): today's quarantine floor as
/// vault-resident data.
fn wait_policy_default_entry() -> (Value, Value) {
    let rows = Value::Array(vec![Value::Map(vec![
        (
            Value::from(WAIT_POLICY_CLASS_KEY),
            Value::from(WAIT_CLASS_CHANNEL_IDENTITY_QUARANTINE),
        ),
        (
            Value::from(WAIT_POLICY_MIN_SECS_KEY),
            Value::from(DEFAULT_CHANNEL_IDENTITY_QUARANTINE_MIN_SECS),
        ),
    ])]);
    (Value::from(POLICY_WAIT_POLICY_KEY), rows)
}

/// The shipped `act_policy` entry (GATE-009): the starting outbound posture
/// for each channel identity subject class.
fn act_policy_default_entry() -> (Value, Value) {
    let rows = Value::Array(vec![
        // A delegated row is the member's own mailbox under an OAuth
        // grant. ARCH-0063 R3 says identity picks the STARTING posture
        // only and a grant may authorize send-as-owner, so the ban is
        // a default and not a class property. Raising this row to
        // `require_capability` does not by itself enable sending: the
        // grant must carry an outbound scope, and the read-only scope
        // classes cannot express one.
        Value::Map(vec![
            (
                Value::from(ACT_POLICY_CLASS_KEY),
                Value::from(ACT_CLASS_CHANNEL_IDENTITY_OUTBOUND_SEND),
            ),
            (
                Value::from(ACT_POLICY_SUBJECT_CLASS_KEY),
                Value::from(ChannelIdentityShape::DelegatedGrant.as_str()),
            ),
            (
                Value::from(ACT_POLICY_POSTURE_KEY),
                Value::from(ActPosture::Deny.as_str()),
            ),
        ]),
        // A self-held row is an account the product minted, so the
        // class is not barred; the substrate check still asks whether
        // this row is live.
        Value::Map(vec![
            (
                Value::from(ACT_POLICY_CLASS_KEY),
                Value::from(ACT_CLASS_CHANNEL_IDENTITY_OUTBOUND_SEND),
            ),
            (
                Value::from(ACT_POLICY_SUBJECT_CLASS_KEY),
                Value::from(SUBJECT_CLASS_SELF_HELD),
            ),
            (
                Value::from(ACT_POLICY_POSTURE_KEY),
                Value::from(ActPosture::RequireCapability.as_str()),
            ),
        ]),
    ]);
    (Value::from(POLICY_ACT_POLICY_KEY), rows)
}

/// Engine-authored vault policy DATA for grant creation. The grant codec and
/// write gate do not consult this list; they resolve the stored manifest rows
/// in the same writer that mints each membership grant.
/// A fresh vault never age-prunes its gate decisions. Only the owner can
/// replace this null horizon with a positive retention period.
fn default_gate_decision_retention_entry() -> (Value, Value) {
    (
        Value::from(POLICY_GATE_DECISION_RETENTION_KEY),
        Value::Map(vec![
            (Value::from(GATE_RETENTION_HORIZON_SECS_KEY), Value::Nil),
            (
                Value::from(GATE_RETENTION_MAX_SWEEP_ROWS_KEY),
                Value::from(256_u64),
            ),
            (
                Value::from(GATE_RETENTION_PRECEDENCE_KEY),
                Value::from("nested_narrowing"),
            ),
            (
                Value::from(GATE_RETENTION_HOLDER_OVERRIDE_CEILING_KEY),
                Value::from("vault"),
            ),
            (Value::from("rows"), Value::Array(Vec::new())),
        ]),
    )
}

fn federation_grant_default_rows() -> Value {
    use crate::federation::grant_policy::{GrantPolicyRow as Row, encode_row};
    use crate::federation::{FederationGrantRole as Role, Scope, ScopeAxis};
    let scope = |verbs: &[&str]| {
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
        scope
    };
    Value::Array(
        [
            Row::PrecedenceNestedNarrowing,
            Row::RoleDefault {
                role: Role::Owner,
                scope: Scope::top(),
            },
            Row::RoleDefault {
                role: Role::Admin,
                scope: scope(&[
                    "read",
                    "write",
                    "admin",
                    "org:add-member",
                    "org:remove-member",
                    "org:assign-role",
                    "org:reset-shared-project-access",
                ]),
            },
            Row::RoleDefault {
                role: Role::Member,
                scope: scope(&["read", "write"]),
            },
            Row::RoleDefault {
                role: Role::Viewer,
                scope: scope(&["read"]),
            },
            Row::RoleDefault {
                role: Role::Delegate,
                scope: scope(&["read"]),
            },
        ]
        .iter()
        .map(|row| encode_row(row).expect("default grant policy row"))
        .collect(),
    )
}

/// Shipped OF-379 row data. Engines read these selectors through the same
/// validated manifest path as owner-edited rows.
fn compilation_route(
    family: &str,
    scope_prefix: &str,
    require_scope_suffix: bool,
    to_prefix: &str,
    from_not_prefix: &str,
    style_atom: bool,
) -> Value {
    Value::Map(vec![
        (Value::from("family"), Value::from(family)),
        (Value::from("enabled"), Value::Boolean(true)),
        (Value::from("scope_prefix"), Value::from(scope_prefix)),
        (
            Value::from("scope_not_prefixes"),
            Value::Array(if family == "ban" {
                vec![
                    Value::from("expression.style:"),
                    Value::from("charter:"),
                    Value::from("brief:"),
                ]
            } else {
                Vec::new()
            }),
        ),
        (
            Value::from("require_scope_suffix"),
            Value::Boolean(require_scope_suffix),
        ),
        (Value::from("to_prefix"), Value::from(to_prefix)),
        (Value::from("from_not_prefix"), Value::from(from_not_prefix)),
        (Value::from("style_atom"), Value::Boolean(style_atom)),
    ])
}

/// The vault-wide search policy ships as data, not a Rust threshold or
/// hard-coded stagnation branch. The manifest resolver composes edits by scope.
fn default_experiment_selection_rows() -> Value {
    let rows: Vec<crate::autoreason_campaign::selection::SelectionPolicyRow> =
        serde_json::from_str(include_str!(
            "../autoreason_campaign/selection_defaults.json"
        ))
        .expect("valid shipped experiment selection rows");
    let bytes = rmp_serde::to_vec_named(&rows).expect("encode shipped experiment selection rows");
    rmpv::decode::read_value(&mut bytes.as_slice())
        .expect("decode shipped experiment selection rows")
}
