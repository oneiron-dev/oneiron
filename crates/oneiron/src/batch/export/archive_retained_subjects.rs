//! The records each retained side table's rows are about, so that the whole-vault export
//! withholds a row, live or inert, whose record it keeps out (FIX
//! WHOLE-VAULT-EXPORT-RETAINED-ROWS-OF-WITHHELD-RECORDS).
//!
//! A row is about a record when its key names that record, or when the record's own delete drops
//! the row by what its value names: a NOTE's landing receipts, a TASK's lifecycle receipts, a
//! setting change whose scope, values or reason name a record, a voice subject's render
//! decision. Every retained table states its rule in [`RETAINED_SUBJECT_RULES`], and a
//! compile-time check refuses a retained table with no rule, or with two.

use self::RetainedSubjectRule::{
    Evidence, HexIds, KeyAndValue, NoRecord, ParsedKey, RawIds, Value,
};
use super::archive_side_dispositions::{ArchiveSideDisposition, SIDE_TABLE_DISPOSITIONS};
use crate::entity_id::EntityId;

/// Which records one retained table's rows are about.
#[derive(Debug, Clone, Copy)]
pub(crate) enum RetainedSubjectRule {
    /// None: the key is a sequence, a digest, a receipt, request or hold id, a name or a
    /// singleton, and no record's delete drops the row by what its value names. Actor and other
    /// references in such a row are the census row's (FIX PERSON-ID-REFERENCE-RECORD-KIND-CENSUS).
    NoRecord,
    /// Custody or retirement evidence that names a record and travels whatever the export keeps
    /// out: a legal hold's rows (the hold's own row names its targets, and the owner's restore
    /// rebuilds the target index from it) and a withdrawn federation grant's marker (a dropped
    /// marker could let the grant act again).
    Evidence,
    /// A key of exactly `len` bytes with a raw 16-byte record id at each offset in `ids`.
    RawIds { len: usize, ids: &'static [usize] },
    /// A key of exactly `len` bytes with a 32-character lower-case hex record id at each offset
    /// in `ids`.
    HexIds { len: usize, ids: &'static [usize] },
    /// The records a variable key names, read by its table's own key parser; `None` when the
    /// bytes read as no key of the table.
    ParsedKey(fn(&[u8]) -> Option<Vec<EntityId>>),
    /// The records whose delete drops the row, read from its value by the table's owner; `None`
    /// when the bytes do not read as the table's value.
    Value(fn(&[u8]) -> Option<Vec<EntityId>>),
    /// The records a row's key and value name together, read by the table's owner, which also
    /// checks that they agree; `None` when the bytes do not read as one row of the table.
    KeyAndValue(fn(&[u8], &[u8]) -> Option<Vec<EntityId>>),
}

/// A key that is one record id.
const ONE_ID: RetainedSubjectRule = RawIds { len: 16, ids: &[0] };
/// A key that is a record id and a big-endian u64 (a sequence or a commit peer).
const ID_AND_U64: RetainedSubjectRule = RawIds { len: 24, ids: &[0] };
/// A key that is a record id and a 16-byte side id that names no record: a change or receipt id,
/// or a digest.
const ID_AND_SIDE_ID: RetainedSubjectRule = RawIds { len: 32, ids: &[0] };
/// A key that is an `EntityDocument` owner and a receipt id, both lower-case hex, with a colon
/// between them (`HexPair`).
const HEX_PAIR_OWNER: RetainedSubjectRule = HexIds { len: 65, ids: &[0] };

/// Every retained table's subject rule, in disposition order. The rules match the key types and
/// owners in the read leg's table map (lanes/kimi/OPUS-EXPORTDOORS/retainedrows-legs/map).
pub(crate) const RETAINED_SUBJECT_RULES: &[(&str, RetainedSubjectRule)] = &[
    ("ACCESS_GRANT_OWNER_ACT", NoRecord),
    ("AGENT_DEF_POWER_GRANT", ParsedKey(power_grant_key_records)),
    ("ATTEMPT_HOLD_OVERRIDE_RECEIPT", NoRecord),
    ("ATTEMPT_PACK_RECEIPT", NoRecord),
    ("AUTHORITY_WITHDRAWN_GRANT", Evidence),
    ("BOARD_LAYOUT_SETTINGS", NoRecord),
    ("BUDGET_HOST_ACCOUNT", NoRecord),
    ("BUDGET_RESIDENT_SHARE", ONE_ID),
    ("BUDGET_RSI_LINE", NoRecord),
    ("CALL_RECEIPT", NoRecord),
    ("CAMPAIGN_COMPLIANCE_RECEIPT", NoRecord),
    // Vault-wide: the house voice guide marker travels even when its NOTE was deleted.
    ("CAMPAIGN_HOUSE_VOICE_GUIDE", NoRecord),
    ("CHECK_IN_RECEIPT", NoRecord),
    ("COMPACTION_CONVERSATION_RECEIPT", ONE_ID),
    ("CONNECTOR_GRANT_SLATE", NoRecord),
    ("CONSENT_APPROVE_ONCE_MARKER", NoRecord),
    ("CONSENT_STANDING_GRANT", NoRecord),
    ("CONSENT_WIDEN_PROPOSAL", NoRecord),
    // The room, then the PERSON, actor and handoff entities its value names.
    (
        "CONVERSATION_MEMBERSHIP_ROW",
        KeyAndValue(membership_row_records),
    ),
    ("CONVERSATION_MEMBERSHIP_SEQ", ONE_ID),
    // The room, then the grantee PERSON.
    (
        "CONVERSATION_ROLE_GRANT",
        RawIds {
            len: 32,
            ids: &[0, 16],
        },
    ),
    ("DRAFTER_POLICY", NoRecord),
    ("DREAMER_CONSOLIDATION_STRENGTH_POLICY", NoRecord),
    ("DREAMER_FREE_TIME_POLICY", ONE_ID),
    // The AGENT_DEF, then the cycle and item side ids.
    ("DREAMER_FREE_TIME_RECEIPT", RawIds { len: 48, ids: &[0] }),
    ("DREAMER_PROJECTOR_POLICY", NoRecord),
    ("DREAMER_SIEVE_POLICY", NoRecord),
    ("DREAMER_WAKE_POLICY", NoRecord),
    // A remembered policy's governed scope (e.g. `consult:<actor hex>:<brief>`) and answerer.
    (
        "EDIT_DISTANCE_ESCALATION_POLICY",
        Value(standing_policy_records),
    ),
    ("ENTITY_DOC_PURGE_RECEIPT", HEX_PAIR_OWNER),
    ("ENTITY_DOC_RECEIPT", HEX_PAIR_OWNER),
    ("ESIGN_AUDIT", ID_AND_U64),
    ("ESIGN_IMAGE_BYTES_BUDGET", ONE_ID),
    // An arm's side id; a unit's arm, rung, unit digest and attempt. An actor erase rewrites
    // the row and drops none (`experiment_arm::erase_arm_actor_in_txn`,
    // `gpu_line::claim::erase_claim_actor_in_txn`).
    ("EXPERIMENT_ARM", NoRecord),
    ("EXPERIMENT_ARM_UNIT", NoRecord),
    ("EXPORT_RECEIPT", NoRecord),
    ("GATE_DECISION_LEDGER", NoRecord),
    // A generation, then the answering MACHINE and the allocation id, which names a GPU
    // line's lane project.
    (
        "GPU_ALLOCATION_NODE",
        ParsedKey(allocation_node_key_records),
    ),
    // A job's side id. An actor erase rewrites the row and drops none
    // (`gpu_job::erase_job_starter_in_txn`).
    ("GPU_JOB", NoRecord),
    // The FEDERATION_GRANT, which the value repeats; the agent's erase drops the row.
    ("GPU_JOB_ALLOWANCE", KeyAndValue(allowance_records)),
    // The lane project; a period's lane project and big-endian u32 index. A period row whose
    // cohort seed is still sealed is withheld apart from this rule
    // (`archive_retained_side_rows::retained_row_withheld`).
    ("GPU_LINE", ONE_ID),
    ("GPU_LINE_PERIOD", RawIds { len: 20, ids: &[0] }),
    ("HOME_HANDOFF_RECEIPT", NoRecord),
    ("HOOKS_GRANT", ONE_ID),
    ("HOOKS_RECEIPT", NoRecord),
    ("HOOKS_REGEN_RECEIPT", NoRecord),
    // The house, then the receipt id; the value names the binder, the same house and the org.
    (
        "HOUSE_LINK_RECEIPT",
        KeyAndValue(house_link_receipt_records),
    ),
    ("INQUIRY_RECEIPT", NoRecord),
    // A chunk's idempotency key (the job's side id and the chunk index); a pin digest. The
    // MACHINE a dispatch or an observation names drops neither, and an actor erase rewrites a
    // workload and drops none (`job_workload::erase_workload_actor_in_txn`).
    ("JOB_DISPATCH", NoRecord),
    ("JOB_OBSERVATION", NoRecord),
    ("JOB_WORKLOAD", NoRecord),
    // A digest key; the asker's erase drops the row.
    ("LANE_ECONOMY_INTENT", Value(lane_intent_records)),
    ("LEARNING_SETTING", ParsedKey(learning_setting_key_records)),
    ("LEGAL_HOLD_EVENT", Evidence),
    ("LEGAL_HOLD_ROW", Evidence),
    ("LEGAL_HOLD_SEALED_RECORD", Evidence),
    ("MAIL_PACK_COMPLIANCE_SETTING", NoRecord),
    ("MESSAGE_STREAM_POLICY", NoRecord),
    ("MESSAGE_STREAM_RECEIPT", ONE_ID),
    ("MODEL_OWNER_FALLBACK", NoRecord),
    ("NON_BASE_WORLD_CLAIM_FRACTION", NoRecord),
    ("NOTE_RECEIPT", Value(note_receipt_records)),
    ("OFF_RECORD_COPY_RECEIPT", ONE_ID),
    ("OFF_RECORD_PROMOTE_RECEIPT", ONE_ID),
    ("ORG_ADMIN_POLICY", HexIds { len: 32, ids: &[0] }),
    ("ORIGIN_LFS_PATH_POLICY", NoRecord),
    ("OUTBOUND_DIRECT_RECEIPT", NoRecord),
    ("OUTBOUND_GRANT_CHANNEL_IDENTITY_USAGE", NoRecord),
    ("OWNER_POLICY_CHANGE_EVENT", NoRecord),
    ("OWNER_POLICY_SECRET_SCAN_MODE", NoRecord),
    ("OWNER_POLICY_SECRET_SCAN_RECEIPT", NoRecord),
    ("OWNER_POLICY_WORLD_PRIVACY_RECEIPT", NoRecord),
    ("OWNER_POLICY_WORLD_PRIVACY_REQUEST", NoRecord),
    ("OWNER_POLICY_WORLD_PRIVACY_UNANIMITY", NoRecord),
    ("OWNER_POLICY_WORLD_PRIVACY_UNANIMITY_OFF", NoRecord),
    ("PENDING_GATE_CONSENT", ONE_ID),
    ("PERSON_BILLING_ACCOUNT", ONE_ID),
    ("POLICY_HOLD_QUEUE", NoRecord),
    ("POLICY_SETTING_ACT", NoRecord),
    ("PORTS_DEPENDENT_WALK_POLICY", NoRecord),
    ("PROJECT_HISTORY_POLICY", NoRecord),
    // The actor, a colon, then its big-endian submission count.
    ("PROPOSAL_RECEIPT_HISTORY", RawIds { len: 25, ids: &[0] }),
    ("READ_SHAPE_PINS", NoRecord),
    ("RETRIEVAL_POLICY_PINS", NoRecord),
    ("ROOM_THREADS_ADMIN_DELETE", NoRecord),
    ("ROOM_THREADS_ADMIN_WALK_IN", NoRecord),
    ("SECRET_LIFT_RECEIPT", NoRecord),
    ("SECRET_ROTATION_RECEIPT", NoRecord),
    // The TASK, then a 32-byte digest of the receipt id.
    ("SEND_RECEIPT_ATTEMPT_AUDIT", RawIds { len: 48, ids: &[0] }),
    ("SEND_RECEIPT_SUMMARY", ONE_ID),
    ("SETTING", ParsedKey(setting_key_records)),
    (
        "SETTING_CHANGE",
        Value(crate::setting::setting_change_records),
    ),
    ("SETTING_CHANGE_NEXT", NoRecord),
    ("SETTING_CONTENT", ParsedKey(setting_key_records)),
    ("SHARED_ACT_POLICY_CHANGE", NoRecord),
    ("SKILL_RESIDENT_RECEIPT", NoRecord),
    ("SNAPSHOT_READ_SETTINGS", NoRecord),
    ("SOURCE_AUDIENCE_POLICY", NoRecord),
    // A key of the machine's hex id, then the touched item's.
    (
        "SYNC_RESIDENCE_MACHINE_TOUCH",
        HexIds {
            len: 64,
            ids: &[0, 32],
        },
    ),
    ("SYNC_SHARED_LEAVE_RECEIPT", NoRecord),
    (
        "TASK_LIFECYCLE_RECEIPT",
        Value(crate::task_verb::lifecycle_receipt_records),
    ),
    ("TEAM_RECEIPT", NoRecord),
    ("TYPED_BODY_RECEIPT", ID_AND_U64),
    ("UNDO_SEND_SETTING", NoRecord),
    // The consent's subject PERSON, then a 16-byte digest of the event id.
    ("VOICE_IDENTITY_CONSENT", ID_AND_SIDE_ID),
    // The voided grant's subject PERSON, then a 16-byte digest of the (grant, withdrawal) pair.
    ("VOICE_IDENTITY_CONSENT_VOID", ID_AND_SIDE_ID),
    // The withdrawal's subject PERSON, then a 16-byte digest of the withdrawal's event id.
    ("VOICE_IDENTITY_WITHDRAWAL_REQUESTED_AT", ID_AND_SIDE_ID),
    ("VOICE_REF_RENDER_CONSENT", Value(render_consent_records)),
    // A reader tag byte, then the reader's PERSON or AGENT_DEF.
    ("WEAVE_DIGEST_SCHEDULE", RawIds { len: 17, ids: &[1] }),
    ("WEAVE_DIGEST_SETTINGS", ONE_ID),
    // The owner, then the change id.
    ("WEAVE_DIGEST_SETTING_CHANGE", ID_AND_SIDE_ID),
    ("WEB_CONNECTOR_SETTING", NoRecord),
    // An order's side id. An actor erase rewrites the order and drops none
    // (`work_order::erase_order_actor_in_txn`).
    ("WORK_ORDER", NoRecord),
];

impl RetainedSubjectRule {
    /// The records one row of the rule's table is about, from its stored key suffix and value
    /// bytes; empty for a row about none, `None` for bytes the rule cannot read, which the export
    /// withholds rather than send a row whose record it cannot name.
    pub(crate) fn records(self, key: &[u8], value: &[u8]) -> Option<Vec<EntityId>> {
        match self {
            NoRecord | Evidence => Some(Vec::new()),
            RawIds { len, ids } if key.len() == len => {
                ids.iter().map(|at| raw_id_at(key, *at)).collect()
            }
            HexIds { len, ids } if key.len() == len => {
                ids.iter().map(|at| hex_id_at(key, *at)).collect()
            }
            RawIds { .. } | HexIds { .. } => None,
            ParsedKey(read) => read(key),
            Value(read) => read(value),
            KeyAndValue(read) => read(key, value),
        }
    }
}

/// The subject rule of retained table `name`; `None` for a name no retained table bears.
pub(crate) fn retained_subject_rule(name: &str) -> Option<RetainedSubjectRule> {
    RETAINED_SUBJECT_RULES
        .iter()
        .find(|(known, _)| *known == name)
        .map(|(_, rule)| *rule)
}

/// The records an export judges a retained row by: every record `records` names, except that a live
/// membership ledger row is judged by its room alone, as before. Inert copies are also judged by
/// the people they name, so a former member's delete never withholds a live room's ledger
/// (REVIEW-10618 round 2 P1-2).
pub(super) fn judged_records<'a>(
    table: &str,
    inert: bool,
    records: &'a [EntityId],
) -> &'a [EntityId] {
    if !inert && table == crate::side_table::CONVERSATION_MEMBERSHIP_ROW.name {
        return records.get(..1).unwrap_or(records);
    }
    records
}

/// Whether record `id` was hard-deleted here (its dt: marker stands), so an export keeps an
/// inert copy about it out (FIX HARD-DELETE-RETAINED-ARCHIVE-ROW-OUTLIVES-RECORD).
pub(super) fn hard_deleted(
    vault: &crate::Vault,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> crate::error::Result<bool> {
    crate::ports::TombstoneStoreRead::port_deletion_marked(
        &vault.store,
        rtxn,
        crate::ports::DeletionMarker::HardDelete,
        id,
    )
}

/// The 16 id bytes at `at`, unchecked for the reserved patterns: no stored record bears one,
/// so the lookup of such an id finds nothing to keep out.
fn raw_id_at(key: &[u8], at: usize) -> Option<EntityId> {
    let bytes: [u8; 16] = key.get(at..at + 16)?.try_into().ok()?;
    Some(EntityId::from_bytes_unchecked(bytes))
}

/// The 32 lower-case hex characters at `at`, as the id they spell.
fn hex_id_at(key: &[u8], at: usize) -> Option<EntityId> {
    let text = std::str::from_utf8(key.get(at..at + 32)?).ok()?;
    let bytes = oneiron_hex::decode::<16>(text)?;
    Some(EntityId::from_bytes_unchecked(bytes))
}

/// The holder an `AGENT_DEF_POWER_GRANT` key names after its tag byte, when that holder is a
/// record: tag 0 an AGENT_DEF, tag 2 a reader TASK; tag 1 a dispatched attempt, which is none
/// (`agent_def::powers::decode_power_grant_target`).
fn power_grant_key_records(key: &[u8]) -> Option<Vec<EntityId>> {
    if key.len() != 17 {
        return None;
    }
    match key[0] {
        0 | 2 => raw_id_at(key, 1).map(|holder| vec![holder]),
        1 => Some(Vec::new()),
        _ => None,
    }
}

/// The record a `SETTING` or `SETTING_CONTENT` key is scoped to: a world, project, sub-project,
/// thread, goal, agent, person or repo; none for the vault or a task type.
fn setting_key_records(key: &[u8]) -> Option<Vec<EntityId>> {
    let row_key = oneiron_setting_contract::RowKey::decode(key)?;
    Some(row_key.scope.entity().into_iter().collect())
}

/// The goal or project a `LEARNING_SETTING` key is scoped to; none for the vault or a type node.
fn learning_setting_key_records(key: &[u8]) -> Option<Vec<EntityId>> {
    use crate::learning_setting::SettingScope;
    let (_, _, scope) = crate::learning_setting::parse_row_key(std::str::from_utf8(key).ok()?)?;
    Some(match scope {
        SettingScope::Goal(id) | SettingScope::Project(id) => vec![id],
        SettingScope::Vault | SettingScope::Type(_) => Vec::new(),
    })
}

/// The NOTE a stored landing receipt moved the head of.
fn note_receipt_records(value: &[u8]) -> Option<Vec<EntityId>> {
    crate::note::landing_receipt_note(value).map(|note| vec![note])
}

/// The binder, house and org a stored house link receipt names, its key's house the same.
fn house_link_receipt_records(key: &[u8], value: &[u8]) -> Option<Vec<EntityId>> {
    crate::workspace_roster::house_link_receipt_records(key, value)
}

/// The records a stored standing escalation policy names in its governed scopes and answerers.
fn standing_policy_records(value: &[u8]) -> Option<Vec<EntityId>> {
    crate::edit_distance::escalation::standing_policy_records(value)
}

/// The MACHINE a stored allocation answer's key names, and the lane project of its GPU line's
/// allocation id.
fn allocation_node_key_records(key: &[u8]) -> Option<Vec<EntityId>> {
    crate::gpu_line::allocation_node_key_records(key)
}

/// The Grant a stored GPU job allowance is keyed by, its value the same, and the agent whose
/// erase drops the row.
fn allowance_records(key: &[u8], value: &[u8]) -> Option<Vec<EntityId>> {
    crate::gpu_job::allowance_row_records(key, value)
}

/// The asker of a stored lane-economy intent, whose erase drops the row.
fn lane_intent_records(value: &[u8]) -> Option<Vec<EntityId>> {
    crate::gpu_line::intent_row_asker(value).map(|asker| vec![asker])
}

/// The voice subject a stored render decision is about.
fn render_consent_records(value: &[u8]) -> Option<Vec<EntityId>> {
    crate::voice_identity::ref_bank::render_consent_subject(value).map(|subject| vec![subject])
}

/// The room a membership ledger row's key names, then the entities its value names
/// (`conversation::membership_row_named_entities`); `None` for a key that is not a room and
/// ordinal, or a value that does not read as a row (REVIEW-10618 P1-2).
fn membership_row_records(key: &[u8], value: &[u8]) -> Option<Vec<EntityId>> {
    if key.len() != 24 {
        return None;
    }
    let mut records = vec![raw_id_at(key, 0)?];
    records.extend(crate::conversation::membership_row_named_entities(value)?);
    Some(records)
}

/// Whether `left` and `right` are the same name, for the compile-time check.
const fn same_name(left: &str, right: &str) -> bool {
    let (left, right) = (left.as_bytes(), right.as_bytes());
    if left.len() != right.len() {
        return false;
    }
    let mut at = 0;
    while at < left.len() {
        if left[at] != right[at] {
            return false;
        }
        at += 1;
    }
    true
}

/// How many rules name `name`.
const fn rules_naming(name: &str) -> usize {
    let mut count = 0;
    let mut at = 0;
    while at < RETAINED_SUBJECT_RULES.len() {
        if same_name(RETAINED_SUBJECT_RULES[at].0, name) {
            count += 1;
        }
        at += 1;
    }
    count
}

/// Whether every offset in `ids` leaves room for an id of `width` bytes in a key of `len`.
const fn ids_fit(len: usize, ids: &[usize], width: usize) -> bool {
    let mut at = 0;
    while at < ids.len() {
        if ids[at] + width > len {
            return false;
        }
        at += 1;
    }
    true
}

/// Whether every retained table has exactly one rule, every other decided table none, every rule
/// names a decided table, and every fixed-width rule's ids fit its key.
const fn rules_cover_the_retained_tables() -> bool {
    let mut decided = 0;
    let mut at = 0;
    while at < SIDE_TABLE_DISPOSITIONS.len() {
        let (name, disposition) = SIDE_TABLE_DISPOSITIONS[at];
        let retained = matches!(disposition, ArchiveSideDisposition::Retained);
        if rules_naming(name) != retained as usize {
            return false;
        }
        decided += retained as usize;
        at += 1;
    }
    let mut at = 0;
    while at < RETAINED_SUBJECT_RULES.len() {
        let fits = match RETAINED_SUBJECT_RULES[at].1 {
            RawIds { len, ids } => ids_fit(len, ids, 16),
            HexIds { len, ids } => ids_fit(len, ids, 32),
            NoRecord | Evidence | ParsedKey(_) | Value(_) | KeyAndValue(_) => true,
        };
        if !fits {
            return false;
        }
        at += 1;
    }
    decided == RETAINED_SUBJECT_RULES.len()
}

const _: () = assert!(
    rules_cover_the_retained_tables(),
    "RETAINED_SUBJECT_RULES must give each retained side table exactly one subject rule"
);
