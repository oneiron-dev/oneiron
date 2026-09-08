//! Campaign record types, lifecycle operations, and vault storage.

use serde_json::Value;

use super::codec_json::campaign_record_to_json;
use super::parse::invalid;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::campaign::{CAMPAIGN_SHORT_ID_PREFIX, CRM_PACK_ID};
use crate::error::{Error, Result};
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};

/// CAMPAIGN definition schema version.
pub const CAMPAIGN_SCHEMA_VERSION: u32 = 1;

/// Longest accepted campaign name, in bytes.
///
/// Names are stored in the entity body and echoed by every read, so an
/// unbounded one is an unbounded row.
pub const CAMPAIGN_NAME_MAX_BYTES: usize = 200;

/// Lifecycle state of a campaign.
///
/// Mirrors [`SavedQueryLifecycle`]'s archive-is-a-transition rule; a campaign
/// has no paused state because it holds no evaluator to pause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CampaignLifecycle {
    /// Addressable and mutable.
    Active,
    /// Retired. Still readable; never re-opened.
    Archived,
}

impl CampaignLifecycle {
    /// Wire token for this state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Archived => "archived",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "archived" => Some(Self::Archived),
            _ => None,
        }
    }
}

/// A versioned campaign definition.
///
/// Not serde-derived for the same reason [`SavedQueryDefinition`](crate::saved_query::SavedQueryDefinition) is not:
/// [`EntityId`] has no serde impl, so entity references cross the wire as
/// canonical hex through [`campaign_record_to_json`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CampaignDefinition {
    /// Definition schema version.
    pub schema_version: u32,
    /// The principal that owns this campaign.
    pub owner_actor: EntityId,
    /// Operator-facing name.
    pub name: String,
    /// Monotonic version, incremented by every accepted write.
    pub definition_version: u64,
    /// Lifecycle state.
    pub lifecycle: CampaignLifecycle,
}

/// A stored campaign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CampaignRecord {
    /// Identity of the campaign.
    pub campaign_ref: EntityId,
    /// Current definition.
    pub definition: CampaignDefinition,
    /// Creation time.
    pub created_at: u64,
    /// Last accepted write.
    pub updated_at: u64,
}

/// Create request. There is no owner field: the owner is bound from the
/// authenticated principal at the write boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateCampaignRequest {
    /// Definition schema version.
    pub schema_version: u32,
    /// Operator-facing name.
    pub name: String,
}

/// Update request. Also carries no owner field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateCampaignRequest {
    /// Version the caller believes is current; the compare half of the CAS.
    pub expected_definition_version: u64,
    /// Replacement name.
    pub name: String,
}

/// Creates a campaign owned by the authenticated principal.
///
/// `owner_actor` is set from `authenticated_principal` and from nowhere else —
/// [`CreateCampaignRequest`] has no owner field, so an untrusted request cannot
/// name a different owner even by accident. The CA-02 idiom, deliberately: two
/// CRM records that behave differently at their write boundary would be two
/// contracts to keep straight.
///
/// # Errors
///
/// [`Error::InvalidConfig`] when the definition fails validation or the CAMPAIGN
/// kind is not registered in this vault; storage errors propagate unchanged.
pub fn create_campaign(
    vault: &Vault,
    authenticated_principal: EntityId,
    request: &CreateCampaignRequest,
    now: u64,
) -> Result<CampaignRecord> {
    let definition = CampaignDefinition {
        schema_version: request.schema_version,
        owner_actor: authenticated_principal,
        name: request.name.clone(),
        definition_version: 1,
        lifecycle: CampaignLifecycle::Active,
    };
    validate_campaign_definition(&definition)?;
    let record = CampaignRecord {
        campaign_ref: EntityId::now(),
        definition,
        created_at: now,
        updated_at: now,
    };
    let kind = campaign_type_byte(vault)?;
    vault.with_write_txn(|wtxn| store_campaign_in_txn(vault, wtxn, &record, kind))?;
    Ok(record)
}

/// Reads a campaign the principal owns.
///
/// A principal that does not own the campaign gets `Ok(None)` — the same answer
/// as a campaign that does not exist. Ownership is not a filter applied after
/// the caller already learned the row exists; it IS the read.
///
/// # Errors
///
/// Storage or decode errors propagate unchanged.
pub fn read_campaign(
    vault: &Vault,
    authenticated_principal: EntityId,
    campaign_ref: EntityId,
) -> Result<Option<CampaignRecord>> {
    Ok(load_campaign(vault, campaign_ref)?
        .filter(|record| record.definition.owner_actor == authenticated_principal))
}

/// Replaces a campaign's definition under a version CAS.
///
/// The compare and the write share ONE write transaction, for the reason CA-02
/// spells out: a compare performed before the writer transaction opens is not a
/// compare, and the lost update it admits is silent.
///
/// # Errors
///
/// [`Error::EntityNotFound`] when the campaign is absent OR owned by another
/// principal, [`Error::ConcurrentWrite`] when the expected version is not
/// current, and [`Error::InvalidConfig`] when the replacement fails validation.
pub fn update_campaign(
    vault: &Vault,
    authenticated_principal: EntityId,
    campaign_ref: EntityId,
    request: &UpdateCampaignRequest,
    now: u64,
) -> Result<CampaignRecord> {
    let kind = campaign_type_byte(vault)?;
    vault.with_write_txn(|wtxn| {
        let mut record =
            owned_campaign_in_txn(vault, wtxn, authenticated_principal, campaign_ref, kind)?;
        require_expected_campaign_version(&record, request.expected_definition_version)?;
        let definition = CampaignDefinition {
            schema_version: record.definition.schema_version,
            owner_actor: record.definition.owner_actor,
            name: request.name.clone(),
            definition_version: next_campaign_version(record.definition.definition_version)?,
            lifecycle: record.definition.lifecycle,
        };
        validate_campaign_definition(&definition)?;
        record.definition = definition;
        record.updated_at = now;
        store_campaign_in_txn(vault, wtxn, &record, kind)?;
        Ok(record)
    })
}

/// Archives a campaign. A lifecycle transition, never a delete: the record stays
/// readable, and its cohort's `campaign.member` claims keep resolving.
///
/// # Errors
///
/// [`Error::EntityNotFound`] when the campaign is absent or owned by another
/// principal; [`Error::ConcurrentWrite`] when the expected version is stale.
pub fn archive_campaign(
    vault: &Vault,
    authenticated_principal: EntityId,
    campaign_ref: EntityId,
    expected_definition_version: u64,
    now: u64,
) -> Result<CampaignRecord> {
    let kind = campaign_type_byte(vault)?;
    vault.with_write_txn(|wtxn| {
        let mut record =
            owned_campaign_in_txn(vault, wtxn, authenticated_principal, campaign_ref, kind)?;
        require_expected_campaign_version(&record, expected_definition_version)?;
        record.definition.definition_version =
            next_campaign_version(record.definition.definition_version)?;
        record.definition.lifecycle = CampaignLifecycle::Archived;
        record.updated_at = now;
        store_campaign_in_txn(vault, wtxn, &record, kind)?;
        Ok(record)
    })
}

fn validate_campaign_definition(definition: &CampaignDefinition) -> Result<()> {
    if definition.schema_version != CAMPAIGN_SCHEMA_VERSION {
        return Err(invalid("campaign schema_version is unsupported"));
    }
    let name = definition.name.trim();
    if name.is_empty() {
        return Err(invalid("campaign name must not be blank"));
    }
    if definition.name.len() > CAMPAIGN_NAME_MAX_BYTES {
        return Err(invalid("campaign name exceeds the maximum length"));
    }
    if definition.name.chars().any(char::is_control) {
        return Err(invalid("campaign name must not contain control characters"));
    }
    Ok(())
}

/// Loads a campaign the principal owns THROUGH the caller's transaction, or
/// reports it as absent. Ownership is part of the read, not a post-filter.
fn owned_campaign_in_txn(
    vault: &Vault,
    wtxn: &heed::RwTxn<'_>,
    authenticated_principal: EntityId,
    campaign_ref: EntityId,
    kind: u8,
) -> Result<CampaignRecord> {
    load_campaign_in_txn(vault, wtxn, campaign_ref, kind)?
        .filter(|record| record.definition.owner_actor == authenticated_principal)
        .ok_or(Error::EntityNotFound)
}

fn require_expected_campaign_version(record: &CampaignRecord, expected: u64) -> Result<()> {
    if record.definition.definition_version == expected {
        return Ok(());
    }
    Err(Error::ConcurrentWrite(
        "campaign definition version is not current",
    ))
}

fn next_campaign_version(current: u64) -> Result<u64> {
    current
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("campaign definition version"))
}

/// The vault-scoped CAMPAIGN type byte, assigned at pack registration.
fn campaign_type_byte(vault: &Vault) -> Result<u8> {
    vault
        .structural_kind_registrations()
        .into_iter()
        .find(|registration| {
            registration.short_id_prefix == CAMPAIGN_SHORT_ID_PREFIX
                && registration.pack == CRM_PACK_ID
        })
        .map(|registration| registration.type_byte)
        .ok_or_else(|| invalid("campaign kind is not registered in this vault"))
}

fn load_campaign(vault: &Vault, campaign_ref: EntityId) -> Result<Option<CampaignRecord>> {
    let kind = campaign_type_byte(vault)?;
    let rtxn = vault.store.env.read_txn()?;
    load_campaign_in_txn(vault, &rtxn, campaign_ref, kind)
}

fn load_campaign_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    campaign_ref: EntityId,
    kind: u8,
) -> Result<Option<CampaignRecord>> {
    let Some(raw) = vault.store.entities.get(txn, campaign_ref.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("campaign entity header"));
    };
    if header.entity_type != kind {
        return Ok(None);
    }
    decode_campaign_record(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
}

/// Writes the definition through the batch put chokepoint, in the caller's
/// transaction, so a campaign replicates like every other entity.
fn store_campaign_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &CampaignRecord,
    kind: u8,
) -> Result<()> {
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        wtxn,
        vec![BatchOp::Put {
            id: record.campaign_ref,
            entity_type: kind,
            occurred: TimeRange {
                start: record.created_at,
                end: record.updated_at,
            },
            learned_at: record.updated_at,
            data: encode_campaign_record(record)?,
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

fn encode_campaign_record(record: &CampaignRecord) -> Result<Vec<u8>> {
    serde_json::to_vec(&campaign_record_to_json(record))
        .map_err(|_| invalid("campaign record could not be encoded"))
}

fn decode_campaign_record(raw: &[u8]) -> Result<CampaignRecord> {
    let value: Value =
        serde_json::from_slice(raw).map_err(|_| Error::CorruptedIndex("campaign record"))?;
    let corrupt = || Error::CorruptedIndex("campaign record");
    let definition = value.get("definition").ok_or_else(corrupt)?;
    Ok(CampaignRecord {
        campaign_ref: stored_entity_ref(&value, "campaign_ref")?,
        definition: CampaignDefinition {
            schema_version: u32::try_from(stored_u64(definition, "schema_version")?)
                .map_err(|_| corrupt())?,
            owner_actor: stored_entity_ref(definition, "owner_actor")?,
            name: definition
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(corrupt)?
                .to_owned(),
            definition_version: stored_u64(definition, "definition_version")?,
            lifecycle: definition
                .get("lifecycle")
                .and_then(Value::as_str)
                .and_then(CampaignLifecycle::parse)
                .ok_or_else(corrupt)?,
        },
        created_at: stored_u64(&value, "created_at")?,
        updated_at: stored_u64(&value, "updated_at")?,
    })
}

fn stored_entity_ref(value: &Value, field: &str) -> Result<EntityId> {
    value
        .get(field)
        .and_then(Value::as_str)
        .and_then(|hex| EntityId::from_hex(hex).ok())
        .ok_or(Error::CorruptedIndex("campaign record"))
}

fn stored_u64(value: &Value, field: &str) -> Result<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(Error::CorruptedIndex("campaign record"))
}
