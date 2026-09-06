use crate::entity_id::ENTITY_ID_LEN;

pub(super) const POLICY_SCHEMA_VERSION_KEY: &str = "schema_version";
pub(crate) const POLICY_SCHEMA_VERSION: &str = "1.1";
pub(super) const POLICY_PACK_ID_KEY: &str = "pack_id";
pub(super) const POLICY_PACK_VERSION_KEY: &str = "pack_version";
pub(super) const POLICY_MIN_ENGINE_VERSION_KEY: &str = "min_engine_version";
pub(super) const POLICY_DEFAULTS_KEY: &str = "defaults";
pub(super) const POLICY_RULES_KEY: &str = "rules";
pub(super) const POLICY_ACTOR_CEILINGS_KEY: &str = "actor_ceilings";
pub(crate) const POLICY_DELEGATED_GRANTS_KEY: &str = "delegated_grants";
pub(crate) const MAX_DELEGATION_DEPTH: u8 = 8;
pub(super) const POLICY_SOURCE_TRUST_KEY: &str = "source_trust";
pub(super) const POLICY_SCOPED_GRANTS_KEY: &str = "scoped_grants";
pub(super) const POLICY_SIGNATURE_KEY: &str = "signature";
pub(super) const POLICY_SIGNATURES_KEY: &str = "signatures";
pub(super) const POLICY_ON_BUDGET_EXHAUSTED_KEY: &str = "on_budget_exhausted";
/// Optional TOP-LEVEL manifest key (never a rule-scoped axis) carrying the
/// vault's posture toward a send to an opted-out counterparty that carries no
/// `comm.send_override`: `escalate` (the default when the key is absent
/// anywhere) holds the send for the owner, `allow_with_receipt` sends it
/// immediately with the opt-out receipt trail.
///
/// It is DEC-0005 policy data, so it resolves restrictively across matching
/// packs — any pack saying `escalate` wins — and it is hashed into
/// `hash_policy_frontier_v0`, because a posture change moves gate outcomes and
/// must invalidate standing grants exactly like every other frontier input. An
/// unrecognized token fails the whole manifest closed at parse time, in the
/// same class as an invalid `on_budget_exhausted` token.
pub(super) const POLICY_COMM_OPT_OUT_POSTURE_KEY: &str = "comm_opt_out_posture";
/// Optional top-level manifest key whose value is an ordered MessagePack
/// array of row maps. Each row selects exactly one call set — one `purpose`
/// string (a pinned `CallPurpose` snake-case name, or any other non-empty
/// string for `CallPurpose::Other { name }`) or one `actor` ref (the
/// canonical lowercase 32-hex form of `WriteActor::entity_ref().to_hex()`) —
/// and carries a `floor`, a `cap`, or both, as unsigned 64-bit integers in
/// the LLM budget meter's units.
///
/// A floor is a non-borrowable reservation only matching calls may draw, and
/// a cap is conjunctive admission policy a matching call must fit under every
/// instance of. Both directions are deliberate policy rather than capacity
/// tuning: floors strand budget on quiet days, and caps refuse matching work
/// while the pool still has room. An absent key and an explicit empty array
/// resolve identically to the plain single-pool meter.
///
/// Rows are data the manifest authors; the engine installs no rows of its
/// own and gives no purpose an implicit reservation. Two shapes a manifest
/// may author (the numbers are illustrative, never engine defaults):
///
/// ```text
/// # Consolidation is guaranteed a reserved slice.
/// { purpose: "consolidation", floor: 200_000 }
///
/// # One autonomous agent is guaranteed a slice but cannot consume the vault.
/// { actor: "<canonical-actor-ref>", floor: 50_000, cap: 150_000 }
/// ```
pub(super) const POLICY_BUDGET_POLICY_KEY: &str = "budget_policy";
pub(super) const BUDGET_POLICY_PURPOSE_KEY: &str = "purpose";
pub(super) const BUDGET_POLICY_ACTOR_KEY: &str = "actor";
pub(super) const BUDGET_POLICY_FLOOR_KEY: &str = "floor";
pub(super) const BUDGET_POLICY_CAP_KEY: &str = "cap";
pub(crate) const POLICY_OWNER_POLICY_ROWS_KEY: &str = "owner_policy_rows";
pub(crate) const POLICY_OWNER_POLICY_ENABLED_KEY: &str = "owner_policy_enabled";
/// The owner plane's POLICY DOCUMENT: the text the vault owner wrote, sent to
/// their safeguard model verbatim as the system message. Absent by default —
/// the engine ships no document of its own, and a plane with none is inactive
/// for model classification however many rows it carries.
pub(crate) const POLICY_OWNER_POLICY_DOCUMENT_KEY: &str = "owner_policy_document";
/// Which answer shape the owner's document instructed their model to produce.
/// The engine reads the answer under this declaration and cannot guess it.
pub(crate) const POLICY_OWNER_POLICY_OUTPUT_CONTRACT_KEY: &str = "owner_policy_output_contract";
/// The owner plane's PATTERN RULES. An ordered array of row maps carrying
/// `id`, `pattern`, `category` and an optional `role`. Absent by default: the
/// engine ships no patterns, and an owner who writes none has none.
pub(crate) const POLICY_OWNER_POLICY_PATTERNS_KEY: &str = "owner_policy_patterns";
pub(super) const POLICY_PATTERN_ID_KEY: &str = "id";
pub(super) const POLICY_PATTERN_PATTERN_KEY: &str = "pattern";
pub(super) const POLICY_PATTERN_CATEGORY_KEY: &str = "category";
pub(super) const POLICY_PATTERN_ROLE_KEY: &str = "role";
/// Retired key, still ACCEPTED AND IGNORED on decode.
///
/// The engine floor it configured is gone, but every vault created before that
/// removal has this key persisted in its stored default manifest. Decode
/// rejects unrecognized top-level keys by design, and a rejected manifest sets
/// `malformed_manifest_seen`, which fails the whole gate closed — and the
/// on-open reseed cannot repair it, because that path bails out precisely when
/// a loaded manifest forces fail-closed. Dropping this name from the allowlist
/// therefore bricks every pre-existing vault on upgrade. It stays listed, and
/// nothing reads its value.
pub(crate) const POLICY_LEGAL_FLOOR_ROWS_KEY: &str = "legal_floor_rows";

pub(super) const AXIS_CRITICALITY_KEY: &str = "criticality";
pub(super) const AXIS_SENSITIVITY_KEY: &str = "sensitivity";
pub(super) const RULE_PREFIX_KEY: &str = "prefix";
pub(super) const RULE_EXACT_KEY: &str = "exact";
pub(super) const RULE_AXES_KEY: &str = "axes";
pub(super) const ACTOR_CLASS_KEY: &str = "actor_class";
pub(super) const ACTOR_REF_KEY: &str = "actor_ref";
pub(super) const DREAMER_PROVENANCE_RUN_ID_KEY: &str = "run_id";
pub(super) const DREAMER_PROVENANCE_RUN_KEY: &str = "run";
pub(super) const DREAMER_PROVENANCE_RUNNER_KEY: &str = "runner";
pub(super) const DREAMER_PROVENANCE_SURFACE_KEY: &str = "surface";
pub(super) const ACTOR_CEILING_KEY: &str = "ceiling";
pub(super) const SOURCE_TRUST_MAX_AUTO_SENSITIVITY_KEY: &str = "max_auto_sensitivity";
pub(super) const SOURCE_TRUST_AUTO_KEY: &str = "auto";
pub(super) const SOURCE_TRUST_RECEIPTED_KEY: &str = "receipted";
pub(super) const SOURCE_TRUST_WARNED_KEY: &str = "warned";
pub(super) const GRANT_EFFECTOR_KEY: &str = "effector";
pub(super) const GRANT_SCOPE_KEY: &str = "scope";
pub(super) const GRANT_BUDGET_KEY: &str = "budget";
pub(super) const GRANT_RECEIPT_REQUIRED_KEY: &str = "receipt_required";
pub(crate) const SCOPED_READ_EFFECTOR_CORE_READ: &str = "core:read";
pub(super) const SCOPED_READ_EFFECTOR_ONEIRON_READ: &str = "oneiron.read";
pub(super) const EXTERNAL_EFFECT_EFFECTOR_PREFIX: &str = "external:";
pub(super) const EXTERNAL_EFFECT_EFFECTOR_LONG_PREFIX: &str = "external_effect:";
pub(super) const EXTERNAL_EFFECT_SCOPE_VERB_KEY: &str = "verb";
pub(super) const EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY: &str = "channel";
pub(super) const EXTERNAL_EFFECT_SCOPE_CHANNEL_REF_KEY: &str = "channel_ref";
pub(super) const EXTERNAL_EFFECT_SCOPE_CHANNEL_REF_CAMEL_KEY: &str = "channelRef";
pub(super) const EXTERNAL_EFFECT_SCOPE_POLICY_RISK_KEY: &str = "policy_risk";
pub(super) const EXTERNAL_EFFECT_SCOPE_POLICY_RISK_CAMEL_KEY: &str = "policyRisk";
pub(super) const EXTERNAL_EFFECT_WILDCARD: &str = "*";
pub(super) const SIGNATURE_ALG_KEY: &str = "alg";
pub(super) const SIGNATURE_KEY_ID_KEY: &str = "key_id";
pub(super) const SIGNATURE_SIG_KEY: &str = "sig";
pub(super) const SIGNATURE_SIGNATURE_KEY: &str = "signature";
pub(crate) const POLICY_ROW_REF_KEY: &str = "row_ref";
pub(crate) const POLICY_ROW_TEXT_KEY: &str = "text";
pub(crate) const POLICY_ROW_ACTIVE_KEY: &str = "active";
pub(crate) const POLICY_ROW_ACTION_KEY: &str = "action";
pub(crate) const POLICY_ROW_WORLD_REF_KEY: &str = "world_ref";
// Legacy generic claim puts do not carry an actor-bound handle yet. Treat
// those local storage doors as first-party engine writes until a future
// actor-bound generic claim API can supply per-caller Gate inputs.
pub(super) const LOCAL_WRITE_ACTOR_CLASS: &str = "first_party";
pub(super) const LOCAL_WRITE_ACTOR_ENTITY_REF: [u8; ENTITY_ID_LEN] = [0x47; ENTITY_ID_LEN];
pub(crate) const FIRST_PARTY_EIRI_CONNECTOR_ACTOR_ID: [u8; ENTITY_ID_LEN] = [0xE1; ENTITY_ID_LEN];
