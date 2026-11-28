//! SIDE-1 dispositions: which canonical side tables the whole-vault archive retains as
//! inert copies, which it declares omitted, and which travel under another archive section.

use super::ImportOmissionReason;
use crate::side_table::SideTableDecl;

/// What the whole-vault archive does with one side table's rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArchiveSideDisposition {
    /// Carried as an inert retained copy, which no live reader reads.
    Retained,
    /// Left out of the archive and named in the manifest with its reason.
    Omitted(ImportOmissionReason),
}

/// The decided side tables in TSV order, each retained or omitted.
pub(crate) const SIDE_TABLE_DISPOSITIONS: &[(&str, ArchiveSideDisposition)] = &[
    ("ACCESS_GRANT_OWNER_ACT", ArchiveSideDisposition::Retained),
    ("AGENT_DEF_POWER_GRANT", ArchiveSideDisposition::Retained),
    (
        "ATTEMPT_HOLD_OVERRIDE_RECEIPT",
        ArchiveSideDisposition::Retained,
    ),
    ("ATTEMPT_PACK_RECEIPT", ArchiveSideDisposition::Retained),
    (
        "AUTHORITY_WITHDRAWN_GRANT",
        ArchiveSideDisposition::Retained,
    ),
    ("BOARD_LAYOUT_SETTINGS", ArchiveSideDisposition::Retained),
    ("BUDGET_HOST_ACCOUNT", ArchiveSideDisposition::Retained),
    ("BUDGET_RESIDENT_SHARE", ArchiveSideDisposition::Retained),
    ("BUDGET_RSI_LINE", ArchiveSideDisposition::Retained),
    ("CALL_RECEIPT", ArchiveSideDisposition::Retained),
    (
        "CAMPAIGN_COMPLIANCE_RECEIPT",
        ArchiveSideDisposition::Retained,
    ),
    (
        "CAMPAIGN_HOUSE_VOICE_GUIDE",
        ArchiveSideDisposition::Retained,
    ),
    ("CHECK_IN_RECEIPT", ArchiveSideDisposition::Retained),
    (
        "COACH_TOPOLOGY_AUDIT_INTENT",
        ArchiveSideDisposition::Omitted(ImportOmissionReason::EngineAttestationNotRestored),
    ),
    (
        "COACH_TOPOLOGY_AUDIT_RESULT",
        ArchiveSideDisposition::Omitted(ImportOmissionReason::EngineAttestationNotRestored),
    ),
    (
        "COACH_TOPOLOGY_AUDIT_SELECTION",
        ArchiveSideDisposition::Omitted(ImportOmissionReason::EngineAttestationNotRestored),
    ),
    (
        "COMM_SKIPPED_SEND_RECEIPT",
        ArchiveSideDisposition::Omitted(ImportOmissionReason::LocalProjectionNotRestored),
    ),
    (
        "COMPACTION_CONVERSATION_RECEIPT",
        ArchiveSideDisposition::Retained,
    ),
    ("CONNECTOR_GRANT_SLATE", ArchiveSideDisposition::Retained),
    (
        "CONSENT_APPROVE_ONCE_MARKER",
        ArchiveSideDisposition::Retained,
    ),
    ("CONSENT_STANDING_GRANT", ArchiveSideDisposition::Retained),
    ("CONSENT_WIDEN_PROPOSAL", ArchiveSideDisposition::Retained),
    (
        "CONVERSATION_MEMBERSHIP_ROW",
        ArchiveSideDisposition::Retained,
    ),
    (
        "CONVERSATION_MEMBERSHIP_SEQ",
        ArchiveSideDisposition::Retained,
    ),
    ("CONVERSATION_ROLE_GRANT", ArchiveSideDisposition::Retained),
    ("DRAFTER_POLICY", ArchiveSideDisposition::Retained),
    (
        "DREAMER_BUDGET_STEP_CHARGE",
        ArchiveSideDisposition::Omitted(ImportOmissionReason::LocalProjectionNotRestored),
    ),
    (
        "DREAMER_CONSOLIDATION_STRENGTH_POLICY",
        ArchiveSideDisposition::Retained,
    ),
    ("DREAMER_FREE_TIME_POLICY", ArchiveSideDisposition::Retained),
    (
        "DREAMER_FREE_TIME_RECEIPT",
        ArchiveSideDisposition::Retained,
    ),
    ("DREAMER_PROJECTOR_POLICY", ArchiveSideDisposition::Retained),
    (
        "DREAMER_SIEVE_AUDIT",
        ArchiveSideDisposition::Omitted(ImportOmissionReason::EngineAttestationNotRestored),
    ),
    ("DREAMER_SIEVE_POLICY", ArchiveSideDisposition::Retained),
    ("DREAMER_WAKE_POLICY", ArchiveSideDisposition::Retained),
    (
        "EDIT_DISTANCE_ESCALATION_POLICY",
        ArchiveSideDisposition::Retained,
    ),
    (
        "EDIT_DISTANCE_JUDGE_AUDIT",
        ArchiveSideDisposition::Omitted(ImportOmissionReason::EngineAttestationNotRestored),
    ),
    ("ENTITY_DOC_PURGE_RECEIPT", ArchiveSideDisposition::Retained),
    ("ENTITY_DOC_RECEIPT", ArchiveSideDisposition::Retained),
    ("ESIGN_AUDIT", ArchiveSideDisposition::Retained),
    ("ESIGN_IMAGE_BYTES_BUDGET", ArchiveSideDisposition::Retained),
    // The lane economy's tables (FIX LANE-ECONOMY-TABLES-ARCHIVE-CLASS): no landing group, so
    // every door, the owner's restore too, keeps them inert and no restore reopens a line, an
    // arm, a hold or an intent.
    ("EXPERIMENT_ARM", ArchiveSideDisposition::Retained),
    ("EXPERIMENT_ARM_UNIT", ArchiveSideDisposition::Retained),
    ("EXPORT_RECEIPT", ArchiveSideDisposition::Retained),
    (
        "FEDERATION_ENGINE_DEFAULT_GRANT",
        ArchiveSideDisposition::Omitted(ImportOmissionReason::LocalAuthorityNotRestored),
    ),
    (
        "FEDERATION_PARKED_FACET_RECEIPT",
        ArchiveSideDisposition::Omitted(ImportOmissionReason::LocalHistoryNotRestored),
    ),
    ("GATE_DECISION_LEDGER", ArchiveSideDisposition::Retained),
    (
        "GENUI_VOICE_GRANT_OFFER",
        ArchiveSideDisposition::Omitted(ImportOmissionReason::LocalAuthorityNotRestored),
    ),
    // The lane economy's sibling tables (FIX LANE-ECONOMY-SIBLING-TABLES-ARCHIVE-CLASS), here
    // and with the JOB_ and WORK_ORDER entries below: no landing group either, so no restore
    // reopens a job, a dispatch, an observation, an order or an approval, puts back a machine's
    // answer, or widens what an agent may start.
    ("GPU_ALLOCATION_NODE", ArchiveSideDisposition::Retained),
    ("GPU_JOB", ArchiveSideDisposition::Retained),
    ("GPU_JOB_ALLOWANCE", ArchiveSideDisposition::Retained),
    ("GPU_LINE", ArchiveSideDisposition::Retained),
    ("GPU_LINE_PERIOD", ArchiveSideDisposition::Retained),
    (
        "HEALER_OVERSIGHT_RECEIPT",
        ArchiveSideDisposition::Omitted(ImportOmissionReason::EngineAttestationNotRestored),
    ),
    ("HOME_HANDOFF_RECEIPT", ArchiveSideDisposition::Retained),
    ("HOOKS_GRANT", ArchiveSideDisposition::Retained),
    ("HOOKS_RECEIPT", ArchiveSideDisposition::Retained),
    ("HOOKS_REGEN_RECEIPT", ArchiveSideDisposition::Retained),
    ("HOUSE_LINK_RECEIPT", ArchiveSideDisposition::Retained),
    ("INQUIRY_RECEIPT", ArchiveSideDisposition::Retained),
    ("JOB_DISPATCH", ArchiveSideDisposition::Retained),
    ("JOB_OBSERVATION", ArchiveSideDisposition::Retained),
    ("JOB_WORKLOAD", ArchiveSideDisposition::Retained),
    ("LANE_ECONOMY_INTENT", ArchiveSideDisposition::Retained),
    ("LEARNING_SETTING", ArchiveSideDisposition::Retained),
    ("LEGAL_HOLD_EVENT", ArchiveSideDisposition::Retained),
    ("LEGAL_HOLD_ROW", ArchiveSideDisposition::Retained),
    ("LEGAL_HOLD_SEALED_RECORD", ArchiveSideDisposition::Retained),
    (
        "MAIL_PACK_COMPLIANCE_SETTING",
        ArchiveSideDisposition::Retained,
    ),
    ("MESSAGE_STREAM_POLICY", ArchiveSideDisposition::Retained),
    ("MESSAGE_STREAM_RECEIPT", ArchiveSideDisposition::Retained),
    ("MODEL_OWNER_FALLBACK", ArchiveSideDisposition::Retained),
    (
        "NON_BASE_WORLD_CLAIM_FRACTION",
        ArchiveSideDisposition::Retained,
    ),
    ("NOTE_RECEIPT", ArchiveSideDisposition::Retained),
    ("OFF_RECORD_COPY_RECEIPT", ArchiveSideDisposition::Retained),
    (
        "OFF_RECORD_PROMOTE_RECEIPT",
        ArchiveSideDisposition::Retained,
    ),
    ("ORG_ADMIN_POLICY", ArchiveSideDisposition::Retained),
    ("ORIGIN_LFS_PATH_POLICY", ArchiveSideDisposition::Retained),
    ("OUTBOUND_DIRECT_RECEIPT", ArchiveSideDisposition::Retained),
    (
        "OUTBOUND_GRANT_CHANNEL_IDENTITY_USAGE",
        ArchiveSideDisposition::Retained,
    ),
    (
        "OWNER_POLICY_CHANGE_EVENT",
        ArchiveSideDisposition::Retained,
    ),
    (
        "OWNER_POLICY_SECRET_SCAN_MODE",
        ArchiveSideDisposition::Retained,
    ),
    (
        "OWNER_POLICY_SECRET_SCAN_RECEIPT",
        ArchiveSideDisposition::Retained,
    ),
    (
        "OWNER_POLICY_WORLD_PRIVACY_RECEIPT",
        ArchiveSideDisposition::Retained,
    ),
    (
        "OWNER_POLICY_WORLD_PRIVACY_REQUEST",
        ArchiveSideDisposition::Retained,
    ),
    (
        "OWNER_POLICY_WORLD_PRIVACY_UNANIMITY",
        ArchiveSideDisposition::Retained,
    ),
    (
        "OWNER_POLICY_WORLD_PRIVACY_UNANIMITY_OFF",
        ArchiveSideDisposition::Retained,
    ),
    ("PENDING_GATE_CONSENT", ArchiveSideDisposition::Retained),
    ("PERSON_BILLING_ACCOUNT", ArchiveSideDisposition::Retained),
    ("POLICY_HOLD_QUEUE", ArchiveSideDisposition::Retained),
    ("POLICY_SETTING_ACT", ArchiveSideDisposition::Retained),
    (
        "PORTS_DEPENDENT_WALK_POLICY",
        ArchiveSideDisposition::Retained,
    ),
    ("PROJECT_HISTORY_POLICY", ArchiveSideDisposition::Retained),
    ("PROPOSAL_RECEIPT_HISTORY", ArchiveSideDisposition::Retained),
    ("READ_SHAPE_PINS", ArchiveSideDisposition::Retained),
    ("RETRIEVAL_POLICY_PINS", ArchiveSideDisposition::Retained),
    (
        "ROOM_THREADS_ADMIN_DELETE",
        ArchiveSideDisposition::Retained,
    ),
    (
        "ROOM_THREADS_ADMIN_WALK_IN",
        ArchiveSideDisposition::Retained,
    ),
    (
        "SECRET_LEASE_GRANT",
        ArchiveSideDisposition::Omitted(ImportOmissionReason::LocalAuthorityNotRestored),
    ),
    ("SECRET_LIFT_RECEIPT", ArchiveSideDisposition::Retained),
    ("SECRET_ROTATION_RECEIPT", ArchiveSideDisposition::Retained),
    (
        "SEND_RECEIPT_ATTEMPT_AUDIT",
        ArchiveSideDisposition::Retained,
    ),
    ("SEND_RECEIPT_SUMMARY", ArchiveSideDisposition::Retained),
    ("SETTING", ArchiveSideDisposition::Retained),
    ("SETTING_CHANGE", ArchiveSideDisposition::Retained),
    ("SETTING_CHANGE_NEXT", ArchiveSideDisposition::Retained),
    ("SETTING_CONTENT", ArchiveSideDisposition::Retained),
    ("SHARED_ACT_POLICY_CHANGE", ArchiveSideDisposition::Retained),
    (
        "SKILL_ATTRIBUTION_AUDIT",
        ArchiveSideDisposition::Omitted(ImportOmissionReason::EngineAttestationNotRestored),
    ),
    (
        "SKILL_ATTRIBUTION_DECISION_RECEIPTS",
        ArchiveSideDisposition::Omitted(ImportOmissionReason::EngineAttestationNotRestored),
    ),
    (
        "SKILL_HUB_ADMISSION_RECEIPT",
        ArchiveSideDisposition::Omitted(ImportOmissionReason::ForeignSkillSignalNotRestored),
    ),
    (
        "SKILL_HUB_IMPORT_RECEIPT",
        ArchiveSideDisposition::Omitted(ImportOmissionReason::ForeignSkillSignalNotRestored),
    ),
    (
        "SKILL_OPTIMIZE_EVAL_CUT_AUDIT",
        ArchiveSideDisposition::Omitted(ImportOmissionReason::EngineAttestationNotRestored),
    ),
    ("SKILL_RESIDENT_RECEIPT", ArchiveSideDisposition::Retained),
    ("SNAPSHOT_READ_SETTINGS", ArchiveSideDisposition::Retained),
    ("SOURCE_AUDIENCE_POLICY", ArchiveSideDisposition::Retained),
    (
        "SOURCE_AUDIENCE_POLICY_WAKE",
        ArchiveSideDisposition::Omitted(ImportOmissionReason::LocalProjectionNotRestored),
    ),
    (
        "SOURCE_AUDIENCE_POLICY_WINDOW",
        ArchiveSideDisposition::Omitted(ImportOmissionReason::LocalProjectionNotRestored),
    ),
    (
        "SYNC_MESH_PATH_RECEIPT",
        ArchiveSideDisposition::Omitted(ImportOmissionReason::LocalActorConfigurationNotRestored),
    ),
    (
        "SYNC_RESIDENCE_BUNDLE_COMMIT_RECEIPT",
        ArchiveSideDisposition::Omitted(ImportOmissionReason::LocalProjectionNotRestored),
    ),
    // PREDICTED-BOARD-SEED-SIGNAL: the home's touch log, a board's reports among it, travels as
    // any vault row does; an import keeps it inert, so no prediction seeds from it there.
    (
        "SYNC_RESIDENCE_MACHINE_TOUCH",
        ArchiveSideDisposition::Retained,
    ),
    (
        "SYNC_SHARED_LEAVE_RECEIPT",
        ArchiveSideDisposition::Retained,
    ),
    ("TASK_LIFECYCLE_RECEIPT", ArchiveSideDisposition::Retained),
    ("TEAM_RECEIPT", ArchiveSideDisposition::Retained),
    ("TYPED_BODY_RECEIPT", ArchiveSideDisposition::Retained),
    ("UNDO_SEND_SETTING", ArchiveSideDisposition::Retained),
    (
        "VAULT_IMPORT_RECEIPT",
        ArchiveSideDisposition::Omitted(ImportOmissionReason::LocalHistoryNotRestored),
    ),
    ("VOICE_IDENTITY_CONSENT", ArchiveSideDisposition::Retained),
    (
        "VOICE_IDENTITY_CONSENT_VOID",
        ArchiveSideDisposition::Retained,
    ),
    (
        "VOICE_IDENTITY_WITHDRAWAL_REQUESTED_AT",
        ArchiveSideDisposition::Retained,
    ),
    ("VOICE_REF_RENDER_CONSENT", ArchiveSideDisposition::Retained),
    ("WEAVE_DIGEST_SCHEDULE", ArchiveSideDisposition::Retained),
    ("WEAVE_DIGEST_SETTINGS", ArchiveSideDisposition::Retained),
    (
        "WEAVE_DIGEST_SETTING_CHANGE",
        ArchiveSideDisposition::Retained,
    ),
    ("WEB_CONNECTOR_SETTING", ArchiveSideDisposition::Retained),
    ("WORK_ORDER", ArchiveSideDisposition::Retained),
];

/// The canonical tables other archive sections carry, with the section that carries each.
#[cfg(oneiron_test_support)]
pub(crate) const OTHER_ARCHIVE_SECTION_TABLES: &[(&str, &str)] = &[
    ("EMBEDDING_SPACE", "embedding_space"),
    ("EMBEDDING_SLOT", "slot_binding"),
    ("COMPACTION_EPOCH_FLOOR", "epoch_floor"),
    ("PROVENANCE_ROW_BIRTH", "row_birth"),
    ("CODE_RUN_READER_FOLD", "run.receipts"),
];

/// Every retained table's declaration, in disposition order.
pub(crate) fn retained_decls() -> impl Iterator<Item = &'static SideTableDecl> {
    SIDE_TABLE_DISPOSITIONS
        .iter()
        .filter(|(_, disposition)| matches!(disposition, ArchiveSideDisposition::Retained))
        .filter_map(|(name, _)| crate::side_table::declared().find(|decl| decl.name == *name))
}

/// Every omitted table's declaration with its reason, in disposition order.
pub(crate) fn omitted_decls() -> impl Iterator<Item = (&'static SideTableDecl, ImportOmissionReason)>
{
    SIDE_TABLE_DISPOSITIONS
        .iter()
        .filter_map(|(name, disposition)| match disposition {
            ArchiveSideDisposition::Omitted(reason) => crate::side_table::declared()
                .find(|decl| decl.name == *name)
                .map(|decl| (decl, *reason)),
            ArchiveSideDisposition::Retained => None,
        })
}

/// The retained table `name`'s declaration, or `None` when no retained table is so named.
pub(crate) fn retained_decl(name: &str) -> Option<&'static SideTableDecl> {
    if !SIDE_TABLE_DISPOSITIONS.iter().any(|(known, disposition)| {
        *known == name && matches!(disposition, ArchiveSideDisposition::Retained)
    }) {
        return None;
    }
    crate::side_table::declared().find(|decl| decl.name == name)
}
