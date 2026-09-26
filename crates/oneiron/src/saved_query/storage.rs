use crate::ports::EntityStoreRead;
use serde_json::{Map as JsonMap, Value};

use crate::Vault;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::campaign::CRM_PACK_ID;
use crate::campaign::claims::{CampaignMemberValue, encode_campaign_member_value};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, CodecError, LegacyJson, Raw, RawValue, SideKey, SideTable};
use crate::temporal::TimeRange;

use super::definition::{
    QueryScope, SAVED_QUERY_SHORT_ID_PREFIX, SavedQueryDefinition, SavedQueryRecord,
};
use super::evidence::{EVIDENCE_HASH_LEN, MatchVerdict, VerdictMemoKey, VerdictMemoRow};
use super::filter::{FilterAst, MatcherSpec, parse_filter_ast};
use super::membership::{MembershipCause, MembershipEvent, MembershipTransition};
use super::pack_drift::{PackDrift, PackMigrationMap};
use super::support::{canonical_json_bytes, hex_lower, invalid, parse_entity_ref};

/// Node-local fast-path watermark for one `(query, entity)` pair's last-applied epoch.
pub(super) const WATERMARK: SideTable<(EntityId, EntityId), Watermark, Raw> =
    SideTable::new(&side_table::SAVED_QUERY_WATERMARK);

pub(super) struct Watermark {
    pub(super) epoch: u64,
    pub(super) content: [u8; EVIDENCE_HASH_LEN],
}

impl RawValue for Watermark {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_watermark(self.epoch, &self.content))
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let (epoch, content) = decode_watermark(bytes)?;
        Ok(Self { epoch, content })
    }
}

/// Durable append-only membership-transition event history, keyed by
/// `(query, entity, epoch)` so a prefix scan over `(query, entity)` returns
/// history in epoch order.
pub(super) const MEMBERSHIP_EVENTS: SideTable<(EntityId, EntityId, u64), MembershipEvent, Raw> =
    SideTable::new(&side_table::SAVED_QUERY_MEMBERSHIP_EVENT);

impl RawValue for MembershipEvent {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_event(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode_event(bytes)?)
    }
}

/// The `(query, entity)` key prefix selecting one pair's whole event history.
pub(super) fn event_pair_prefix(query_ref: &EntityId, entity_ref: &EntityId) -> Vec<u8> {
    let mut prefix = query_ref.as_bytes().to_vec();
    prefix.extend_from_slice(entity_ref.as_bytes());
    prefix
}

/// Cached match-evaluator verdict for one `(query, entity, evidence)` triple.
pub(super) const MEMOS: SideTable<VerdictMemoKey, VerdictMemoRow, Raw> =
    SideTable::new(&side_table::SAVED_QUERY_MEMO);

impl SideKey for VerdictMemoKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.query_ref.as_bytes());
        out.extend_from_slice(self.entity_ref.as_bytes());
        out.extend_from_slice(&self.evidence_hash);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (query_ref, rest) = bytes.split_at_checked(16)?;
        let (entity_ref, evidence_hash) = rest.split_at_checked(16)?;
        Some(Self {
            query_ref: EntityId::from_bytes(query_ref.try_into().ok()?).ok()?,
            entity_ref: EntityId::from_bytes(entity_ref.try_into().ok()?).ok()?,
            evidence_hash: evidence_hash.try_into().ok()?,
        })
    }
}

impl RawValue for VerdictMemoRow {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_memo_row(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode_memo_row(bytes)?)
    }
}

/// Operator-supplied predicate rewrite map for one pack move, keyed by
/// `{from_pack_id}@{from_version}->{to_pack_id}@{to_version}`.
pub(super) const PACK_MIGRATION_MAPS: SideTable<String, PackMigrationMap, LegacyJson> =
    SideTable::new(&side_table::SAVED_QUERY_PACK_MIGRATION_MAP);

pub(super) fn migration_map_key(drift: &PackDrift) -> String {
    format!(
        "{}@{}->{}@{}",
        drift.from_pack_id, drift.from_version, drift.to_pack_id, drift.to_version
    )
}

/// Receipt of one pack-drift repair action, keyed by its own id.
pub(super) const REPAIRS: SideTable<EntityId, RepairReceipt, Raw> =
    SideTable::new(&side_table::SAVED_QUERY_REPAIR);

pub(super) struct RepairReceipt {
    pub(super) query_ref: EntityId,
    pub(super) summary: String,
    pub(super) recorded_at: u64,
    pub(super) drift: PackDrift,
}

impl RawValue for RepairReceipt {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut row = JsonMap::new();
        row.insert(
            "query_ref".to_owned(),
            Value::String(self.query_ref.to_hex()),
        );
        row.insert("summary".to_owned(), Value::String(self.summary.clone()));
        row.insert("recorded_at".to_owned(), Value::from(self.recorded_at));
        row.insert(
            "drift".to_owned(),
            serde_json::to_value(&self.drift)
                .map_err(|_| Error::InvariantViolation("pack drift encode failed"))?,
        );
        Ok(canonical_json_bytes(&Value::Object(row))?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        const CONTEXT: &str = "saved query repair receipt";
        let value = parse_row(bytes, CONTEXT)?;
        Ok(Self {
            query_ref: required_entity_ref(&value, "query_ref", CONTEXT)?,
            summary: required_string(&value, "summary", CONTEXT)?,
            recorded_at: required_u64(&value, "recorded_at", CONTEXT)?,
            drift: serde_json::from_value(
                value
                    .get("drift")
                    .cloned()
                    .ok_or(Error::CorruptedIndex(CONTEXT))?,
            )
            .map_err(|_| Error::CorruptedIndex(CONTEXT))?,
        })
    }
}

/// Watermark rows are `epoch || content digest`.
const WATERMARK_ROW_LEN: usize = 8 + EVIDENCE_HASH_LEN;

/// The type byte this vault assigned the SAVED_QUERY kind at pack registration.
///
/// Resolved from the vault-scoped registry rather than a constant: the byte is
/// caller-assigned per vault, and this module owns none. A vault that never
/// installed the CRM pack has no namespace to write into, which is a
/// configuration error, not a silent sidecar fallback.
pub(super) fn saved_query_type_byte(vault: &Vault) -> Result<u8> {
    vault
        .structural_kind_registrations()
        .into_iter()
        .find(|registration| {
            registration.short_id_prefix == SAVED_QUERY_SHORT_ID_PREFIX
                && registration.pack == CRM_PACK_ID
        })
        .map(|registration| registration.type_byte)
        .ok_or_else(|| invalid("saved query kind is not registered in this vault"))
}

/// Reads the SAVED_QUERY entity body through the caller's transaction.
pub(super) fn load_record_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query_ref: EntityId,
    kind: u8,
) -> Result<Option<SavedQueryRecord>> {
    let Some(raw) = vault
        .store
        .port_entity_record(txn, &query_ref)?
        .map(|row| row.encode())
    else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("saved query entity header"));
    };
    if header.entity_type != kind {
        return Ok(None);
    }
    decode_record(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
}

pub(super) fn load_record(vault: &Vault, query_ref: EntityId) -> Result<Option<SavedQueryRecord>> {
    let kind = saved_query_type_byte(vault)?;
    let rtxn = vault.store.env.read_txn()?;
    load_record_in_txn(vault, &rtxn, query_ref, kind)
}

/// Writes the definition through the batch put chokepoint, in the caller's
/// transaction, so the definition replicates like every other entity.
pub(super) fn store_record_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &SavedQueryRecord,
    kind: u8,
) -> Result<()> {
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        wtxn,
        vec![BatchOp::Put {
            id: record.query_ref,
            entity_type: kind,
            occurred: TimeRange {
                start: record.created_at,
                end: record.updated_at,
            },
            learned_at: record.updated_at,
            data: encode_record(record)?,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }],
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
        false,
        false,
    )
}

pub(super) fn read_watermark(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    query_ref: EntityId,
    entity_ref: EntityId,
) -> Result<Option<(u64, [u8; EVIDENCE_HASH_LEN])>> {
    Ok(WATERMARK
        .get(&vault.store, rtxn, &(query_ref, entity_ref))?
        .map(|watermark| (watermark.epoch, watermark.content)))
}

pub(super) fn encode_watermark(epoch: u64, content: &[u8; EVIDENCE_HASH_LEN]) -> Vec<u8> {
    let mut row = Vec::with_capacity(WATERMARK_ROW_LEN);
    row.extend_from_slice(&epoch.to_be_bytes());
    row.extend_from_slice(content);
    row
}

pub(super) fn decode_watermark(raw: &[u8]) -> Result<(u64, [u8; EVIDENCE_HASH_LEN])> {
    if raw.len() != WATERMARK_ROW_LEN {
        return Err(Error::CorruptedIndex("saved query epoch watermark"));
    }
    let (epoch, content) = raw.split_at(8);
    let epoch = u64::from_be_bytes(
        epoch
            .try_into()
            .map_err(|_| Error::CorruptedIndex("saved query epoch watermark"))?,
    );
    let content = content
        .try_into()
        .map_err(|_| Error::CorruptedIndex("saved query epoch watermark"))?;
    Ok((epoch, content))
}

fn encode_record(record: &SavedQueryRecord) -> Result<Vec<u8>> {
    let mut root = JsonMap::new();
    root.insert(
        "query_ref".to_owned(),
        Value::String(record.query_ref.to_hex()),
    );
    root.insert(
        "definition".to_owned(),
        definition_to_json(&record.definition)?,
    );
    root.insert("created_at".to_owned(), Value::from(record.created_at));
    root.insert("updated_at".to_owned(), Value::from(record.updated_at));
    canonical_json_bytes(&Value::Object(root))
}

fn decode_record(raw: &[u8]) -> Result<SavedQueryRecord> {
    let value = parse_row(raw, "saved query record")?;
    Ok(SavedQueryRecord {
        query_ref: required_entity_ref(&value, "query_ref", "saved query record")?,
        definition: definition_from_json(
            value
                .get("definition")
                .ok_or(Error::CorruptedIndex("saved query record"))?,
        )?,
        created_at: required_u64(&value, "created_at", "saved query record")?,
        updated_at: required_u64(&value, "updated_at", "saved query record")?,
    })
}

pub(super) fn definition_to_json(definition: &SavedQueryDefinition) -> Result<Value> {
    let mut root = JsonMap::new();
    root.insert(
        "schema_version".to_owned(),
        Value::from(definition.schema_version),
    );
    root.insert(
        "owner_actor".to_owned(),
        Value::String(definition.owner_actor.to_hex()),
    );
    root.insert("scope".to_owned(), scope_to_json(&definition.scope));
    root.insert(
        "definition_version".to_owned(),
        Value::from(definition.definition_version),
    );
    root.insert("filter".to_owned(), filter_to_json(&definition.filter));
    root.insert("matcher".to_owned(), matcher_to_json(&definition.matcher));
    root.insert(
        "eval".to_owned(),
        serde_json::to_value(definition.eval)
            .map_err(|_| Error::InvariantViolation("saved query eval policy encode failed"))?,
    );
    root.insert(
        "lifecycle".to_owned(),
        serde_json::to_value(&definition.lifecycle)
            .map_err(|_| Error::InvariantViolation("saved query lifecycle encode failed"))?,
    );
    Ok(Value::Object(root))
}

pub(super) fn definition_from_json(value: &Value) -> Result<SavedQueryDefinition> {
    const CONTEXT: &str = "saved query definition";
    let scope = value.get("scope").ok_or(Error::CorruptedIndex(CONTEXT))?;
    Ok(SavedQueryDefinition {
        schema_version: u32::try_from(required_u64(value, "schema_version", CONTEXT)?)
            .map_err(|_| Error::CorruptedIndex(CONTEXT))?,
        owner_actor: required_entity_ref(value, "owner_actor", CONTEXT)?,
        scope: scope_from_json(scope)?,
        definition_version: required_u64(value, "definition_version", CONTEXT)?,
        filter: parse_filter_ast(value.get("filter").ok_or(Error::CorruptedIndex(CONTEXT))?)
            .map_err(|_| Error::CorruptedIndex(CONTEXT))?,
        matcher: matcher_from_json(value.get("matcher").ok_or(Error::CorruptedIndex(CONTEXT))?)?,
        eval: serde_json::from_value(
            value
                .get("eval")
                .cloned()
                .ok_or(Error::CorruptedIndex(CONTEXT))?,
        )
        .map_err(|_| Error::CorruptedIndex(CONTEXT))?,
        lifecycle: serde_json::from_value(
            value
                .get("lifecycle")
                .cloned()
                .ok_or(Error::CorruptedIndex(CONTEXT))?,
        )
        .map_err(|_| Error::CorruptedIndex(CONTEXT))?,
    })
}

fn scope_to_json(scope: &QueryScope) -> Value {
    let mut root = JsonMap::new();
    root.insert(
        "worlds".to_owned(),
        Value::Array(
            scope
                .worlds
                .iter()
                .map(|world| Value::String(world.to_hex()))
                .collect(),
        ),
    );
    root.insert(
        "facets".to_owned(),
        Value::Array(
            scope
                .facets
                .iter()
                .map(|facet| Value::String(facet.clone()))
                .collect(),
        ),
    );
    Value::Object(root)
}

fn scope_from_json(value: &Value) -> Result<QueryScope> {
    const CONTEXT: &str = "saved query scope";
    let worlds = value
        .get("worlds")
        .and_then(Value::as_array)
        .ok_or(Error::CorruptedIndex(CONTEXT))?
        .iter()
        .map(|world| parse_entity_ref(world).map_err(|_| Error::CorruptedIndex(CONTEXT)))
        .collect::<Result<Vec<_>>>()?;
    let facets = value
        .get("facets")
        .and_then(Value::as_array)
        .ok_or(Error::CorruptedIndex(CONTEXT))?
        .iter()
        .map(|facet| {
            facet
                .as_str()
                .map(str::to_owned)
                .ok_or(Error::CorruptedIndex(CONTEXT))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(QueryScope { worlds, facets })
}

fn filter_to_json(ast: &FilterAst) -> Value {
    let mut root = JsonMap::new();
    match ast {
        FilterAst::TaskOwner { owner } => {
            root.insert("op".to_owned(), Value::String("task_owner".to_owned()));
            root.insert("owner".to_owned(), Value::String(owner.to_hex()));
        }
        FilterAst::All { terms } | FilterAst::Any { terms } => {
            root.insert(
                "op".to_owned(),
                Value::String(
                    if matches!(ast, FilterAst::All { .. }) {
                        "all"
                    } else {
                        "any"
                    }
                    .to_owned(),
                ),
            );
            root.insert(
                "terms".to_owned(),
                Value::Array(terms.iter().map(filter_to_json).collect()),
            );
        }
        FilterAst::Not { term } => {
            root.insert("op".to_owned(), Value::String("not".to_owned()));
            root.insert("term".to_owned(), filter_to_json(term));
        }
        FilterAst::Claim {
            predicate,
            cmp,
            value,
        } => {
            root.insert("op".to_owned(), Value::String("claim".to_owned()));
            root.insert("predicate".to_owned(), Value::String(predicate.clone()));
            root.insert("cmp".to_owned(), Value::String(cmp.as_str().to_owned()));
            root.insert("value".to_owned(), value.clone());
        }
        FilterAst::EdgeExists { edge_kind, target } => {
            root.insert("op".to_owned(), Value::String("edge_exists".to_owned()));
            root.insert("edge_kind".to_owned(), Value::String(edge_kind.clone()));
            root.insert(
                "target".to_owned(),
                target.map_or(Value::Null, |id| Value::String(id.to_hex())),
            );
        }
    }
    Value::Object(root)
}

pub(super) fn matcher_to_json(matcher: &MatcherSpec) -> Value {
    let mut root = JsonMap::new();
    match matcher {
        MatcherSpec::Hard { expression } => {
            root.insert("kind".to_owned(), Value::String("hard".to_owned()));
            root.insert("expression".to_owned(), filter_to_json(expression));
        }
        MatcherSpec::SemanticThreshold {
            exemplar_ref,
            minimum_similarity_micros,
        } => {
            root.insert(
                "kind".to_owned(),
                Value::String("semantic_threshold".to_owned()),
            );
            root.insert(
                "exemplar_ref".to_owned(),
                Value::String(exemplar_ref.to_hex()),
            );
            root.insert(
                "minimum_similarity_micros".to_owned(),
                Value::from(*minimum_similarity_micros),
            );
        }
        MatcherSpec::LlmJudge {
            model_id,
            rubric,
            rubric_version,
        } => {
            root.insert("kind".to_owned(), Value::String("llm_judge".to_owned()));
            root.insert("model_id".to_owned(), Value::String(model_id.clone()));
            root.insert("rubric".to_owned(), rubric.clone());
            root.insert(
                "rubric_version".to_owned(),
                Value::String(rubric_version.clone()),
            );
        }
    }
    Value::Object(root)
}

fn matcher_from_json(value: &Value) -> Result<MatcherSpec> {
    const CONTEXT: &str = "saved query matcher";
    match value.get("kind").and_then(Value::as_str) {
        Some("hard") => Ok(MatcherSpec::Hard {
            expression: parse_filter_ast(
                value
                    .get("expression")
                    .ok_or(Error::CorruptedIndex(CONTEXT))?,
            )
            .map_err(|_| Error::CorruptedIndex(CONTEXT))?,
        }),
        Some("semantic_threshold") => Ok(MatcherSpec::SemanticThreshold {
            exemplar_ref: required_entity_ref(value, "exemplar_ref", CONTEXT)?,
            minimum_similarity_micros: u32::try_from(required_u64(
                value,
                "minimum_similarity_micros",
                CONTEXT,
            )?)
            .map_err(|_| Error::CorruptedIndex(CONTEXT))?,
        }),
        Some("llm_judge") => Ok(MatcherSpec::LlmJudge {
            model_id: required_string(value, "model_id", CONTEXT)?,
            rubric: value
                .get("rubric")
                .cloned()
                .ok_or(Error::CorruptedIndex(CONTEXT))?,
            rubric_version: required_string(value, "rubric_version", CONTEXT)?,
        }),
        _ => Err(Error::CorruptedIndex(CONTEXT)),
    }
}

pub(super) fn encode_memo_row(row: &VerdictMemoRow) -> Result<Vec<u8>> {
    let mut root = JsonMap::new();
    root.insert(
        "query_ref".to_owned(),
        Value::String(row.key.query_ref.to_hex()),
    );
    root.insert(
        "entity_ref".to_owned(),
        Value::String(row.key.entity_ref.to_hex()),
    );
    root.insert(
        "evidence_hash".to_owned(),
        Value::String(hex_lower(&row.key.evidence_hash)),
    );
    root.insert(
        "definition_version".to_owned(),
        Value::from(row.definition_version),
    );
    root.insert(
        "verdict".to_owned(),
        Value::String(row.verdict.as_str().to_owned()),
    );
    root.insert("why".to_owned(), Value::String(row.why.clone()));
    root.insert(
        "envelope".to_owned(),
        serde_json::to_value(&row.envelope)
            .map_err(|_| Error::InvariantViolation("saved query envelope encode failed"))?,
    );
    root.insert("evaluated_at".to_owned(), Value::from(row.evaluated_at));
    canonical_json_bytes(&Value::Object(root))
}

pub(super) fn decode_memo_row(raw: &[u8]) -> Result<VerdictMemoRow> {
    const CONTEXT: &str = "saved query verdict memo";
    let value = parse_row(raw, CONTEXT)?;
    Ok(VerdictMemoRow {
        key: VerdictMemoKey {
            query_ref: required_entity_ref(&value, "query_ref", CONTEXT)?,
            entity_ref: required_entity_ref(&value, "entity_ref", CONTEXT)?,
            evidence_hash: required_hash(&value, "evidence_hash", CONTEXT)?,
        },
        definition_version: required_u64(&value, "definition_version", CONTEXT)?,
        verdict: MatchVerdict::parse(&required_string(&value, "verdict", CONTEXT)?)
            .ok_or(Error::CorruptedIndex(CONTEXT))?,
        why: required_string(&value, "why", CONTEXT)?,
        envelope: serde_json::from_value(
            value
                .get("envelope")
                .cloned()
                .ok_or(Error::CorruptedIndex(CONTEXT))?,
        )
        .map_err(|_| Error::CorruptedIndex(CONTEXT))?,
        evaluated_at: required_u64(&value, "evaluated_at", CONTEXT)?,
    })
}

pub(super) fn encode_event(event: &MembershipEvent) -> Result<Vec<u8>> {
    let mut root = JsonMap::new();
    root.insert(
        "query_ref".to_owned(),
        Value::String(event.query_ref.to_hex()),
    );
    root.insert(
        "campaign_ref".to_owned(),
        Value::String(event.campaign_ref.to_hex()),
    );
    root.insert(
        "entity_ref".to_owned(),
        Value::String(event.entity_ref.to_hex()),
    );
    root.insert("epoch".to_owned(), Value::from(event.epoch));
    root.insert("valid_at".to_owned(), Value::from(event.valid_at));
    root.insert("detected_at".to_owned(), Value::from(event.detected_at));
    root.insert(
        "transition".to_owned(),
        Value::String(event.transition.as_str().to_owned()),
    );
    root.insert(
        "cause".to_owned(),
        Value::String(event.cause.as_str().to_owned()),
    );
    root.insert(
        "evidence_hash".to_owned(),
        Value::String(hex_lower(&event.evidence_hash)),
    );
    canonical_json_bytes(&Value::Object(root))
}

pub(super) fn decode_event(raw: &[u8]) -> Result<MembershipEvent> {
    const CONTEXT: &str = "saved query membership event";
    let value = parse_row(raw, CONTEXT)?;
    Ok(MembershipEvent {
        query_ref: required_entity_ref(&value, "query_ref", CONTEXT)?,
        campaign_ref: required_entity_ref(&value, "campaign_ref", CONTEXT)?,
        entity_ref: required_entity_ref(&value, "entity_ref", CONTEXT)?,
        epoch: required_u64(&value, "epoch", CONTEXT)?,
        valid_at: required_u64(&value, "valid_at", CONTEXT)?,
        detected_at: required_u64(&value, "detected_at", CONTEXT)?,
        transition: MembershipTransition::parse(&required_string(&value, "transition", CONTEXT)?)
            .ok_or(Error::CorruptedIndex(CONTEXT))?,
        cause: MembershipCause::parse(&required_string(&value, "cause", CONTEXT)?)
            .ok_or(Error::CorruptedIndex(CONTEXT))?,
        evidence_hash: required_hash(&value, "evidence_hash", CONTEXT)?,
    })
}

pub(super) fn encode_member_value_bytes(value: &CampaignMemberValue) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &encode_campaign_member_value(value))
        .map_err(|_| Error::InvariantViolation("campaign member value encode failed"))?;
    Ok(out)
}

fn parse_row(raw: &[u8], context: &'static str) -> Result<Value> {
    serde_json::from_slice(raw).map_err(|_| Error::CorruptedIndex(context))
}

fn required_string(value: &Value, key: &str, context: &'static str) -> Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(Error::CorruptedIndex(context))
}

fn required_u64(value: &Value, key: &str, context: &'static str) -> Result<u64> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(Error::CorruptedIndex(context))
}

fn required_entity_ref(value: &Value, key: &str, context: &'static str) -> Result<EntityId> {
    let hex = required_string(value, key, context)?;
    EntityId::from_hex(&hex).map_err(|_| Error::CorruptedIndex(context))
}

fn required_hash(
    value: &Value,
    key: &str,
    context: &'static str,
) -> Result<[u8; EVIDENCE_HASH_LEN]> {
    let hex = required_string(value, key, context)?;
    if hex.len() != EVIDENCE_HASH_LEN * 2 {
        return Err(Error::CorruptedIndex(context));
    }
    let mut bytes = [0u8; EVIDENCE_HASH_LEN];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = u8::from_str_radix(
            hex.get(index * 2..index * 2 + 2)
                .ok_or(Error::CorruptedIndex(context))?,
            16,
        )
        .map_err(|_| Error::CorruptedIndex(context))?;
    }
    Ok(bytes)
}
