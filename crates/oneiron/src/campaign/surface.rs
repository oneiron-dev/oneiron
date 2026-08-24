//! CA-07's SDK surface: one `self.*` verb vocabulary over the CRM pack.
//!
//! This module is the ONLY place the campaign and saved-query domain APIs are
//! given transport-shaped names. Both reach — the HTTP routers in
//! `oneiron-server` and the MCP gateway's existing generic dialect — call
//! `invoke_campaign_surface` and serialize the same `SurfaceReply`, so the
//! transports own no campaign semantics and cannot drift from each other.
//!
//! Three laws shape everything below.
//!
//! * **The verb list is closed.** `CAMPAIGN_SELF_VERBS` is the whole
//!   vocabulary; `CampaignSurfaceVerb::parse` admits nothing else, so an
//!   unknown or prefix-confusable name is a typed rejection rather than a
//!   silently-routed call.
//! * **`owner_actor` comes from the bound actor.** Every write is dispatched
//!   through the caller's `Memory`, whose actor is the authenticated
//!   principal, and no create/update request type carries an owner field. A
//!   caller payload therefore cannot select another actor even by accident.
//! * **Archive is a lifecycle transition.** Neither family gains a hard-delete
//!   verb: an archived record stays addressable, which is what makes it
//!   auditable (ARCH-0059).
//!
//! CA-00 minted CAMPAIGN's structural kind and stopped there — the pack's
//! ratified separation law is that a campaign never stores a member list, so
//! there was no campaign record for a cohort to hang off. The minimal record
//! below (identity, name, version, lifecycle) is that missing half, deliberately
//! kept to what an addressable, versioned, archivable campaign needs. Membership
//! stays where CA-01 put it: `campaign.member` claims on the PERSON.

use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value};

use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::campaign::claims::{PREDICATE_CAMPAIGN_MEMBER, decode_campaign_member_value};
use crate::campaign::{CAMPAIGN_SHORT_ID_PREFIX, CRM_PACK_ID};
use crate::claim::ClaimLifecycleStatus;
use crate::claim::ClaimSubject;
use crate::error::{Error, Result};
use crate::facade::{FacadeError, FacadeResult, Memory};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::saved_query::{
    CreateSavedQueryRequest, EvalMode, EvalPolicy, FilterAst, MatcherSpec, MembershipEvent,
    MembershipTransition, QueryScope, SAVED_QUERY_SCHEMA_VERSION, SavedQueryLifecycle,
    SavedQueryRecord, UpdateSavedQueryRequest, membership_events, parse_filter_ast,
};
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};

// ---------------------------------------------------------------------------
// The closed verb vocabulary
// ---------------------------------------------------------------------------

/// `self.*` verb: create a CAMPAIGN owned by the authenticated principal.
pub const SELF_CAMPAIGN_CREATE: &str = "self.campaign.create";
/// `self.*` verb: read one CAMPAIGN the principal owns.
pub const SELF_CAMPAIGN_READ: &str = "self.campaign.read";
/// `self.*` verb: replace a CAMPAIGN's definition under a version CAS.
pub const SELF_CAMPAIGN_UPDATE: &str = "self.campaign.update";
/// `self.*` verb: archive a CAMPAIGN — a lifecycle transition, never a delete.
pub const SELF_CAMPAIGN_ARCHIVE: &str = "self.campaign.archive";
/// `self.*` verb: page a CAMPAIGN's cohort, read-only.
pub const SELF_CAMPAIGN_MEMBERS: &str = "self.campaign.members";
/// `self.*` verb: create a SAVED_QUERY owned by the authenticated principal.
pub const SELF_SAVED_QUERY_CREATE: &str = "self.saved_query.create";
/// `self.*` verb: read one SAVED_QUERY the principal owns.
pub const SELF_SAVED_QUERY_READ: &str = "self.saved_query.read";
/// `self.*` verb: replace a SAVED_QUERY's definition under a version CAS.
pub const SELF_SAVED_QUERY_UPDATE: &str = "self.saved_query.update";
/// `self.*` verb: archive a SAVED_QUERY — a lifecycle transition.
pub const SELF_SAVED_QUERY_ARCHIVE: &str = "self.saved_query.archive";
/// `self.*` verb: page a SAVED_QUERY's derived membership, read-only.
pub const SELF_SAVED_QUERY_MEMBERS: &str = "self.saved_query.members";

/// The whole surface vocabulary, in dispatch order.
///
/// Discovery advertises exactly this slice, and [`CampaignSurfaceVerb::parse`]
/// admits exactly these strings, so a verb that exists is discoverable and a
/// verb that is discoverable is callable.
pub const CAMPAIGN_SELF_VERBS: &[&str] = &[
    SELF_CAMPAIGN_CREATE,
    SELF_CAMPAIGN_READ,
    SELF_CAMPAIGN_UPDATE,
    SELF_CAMPAIGN_ARCHIVE,
    SELF_CAMPAIGN_MEMBERS,
    SELF_SAVED_QUERY_CREATE,
    SELF_SAVED_QUERY_READ,
    SELF_SAVED_QUERY_UPDATE,
    SELF_SAVED_QUERY_ARCHIVE,
    SELF_SAVED_QUERY_MEMBERS,
];

/// A parsed surface verb.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CampaignSurfaceVerb {
    /// [`SELF_CAMPAIGN_CREATE`].
    CampaignCreate,
    /// [`SELF_CAMPAIGN_READ`].
    CampaignRead,
    /// [`SELF_CAMPAIGN_UPDATE`].
    CampaignUpdate,
    /// [`SELF_CAMPAIGN_ARCHIVE`].
    CampaignArchive,
    /// [`SELF_CAMPAIGN_MEMBERS`].
    CampaignMembers,
    /// [`SELF_SAVED_QUERY_CREATE`].
    SavedQueryCreate,
    /// [`SELF_SAVED_QUERY_READ`].
    SavedQueryRead,
    /// [`SELF_SAVED_QUERY_UPDATE`].
    SavedQueryUpdate,
    /// [`SELF_SAVED_QUERY_ARCHIVE`].
    SavedQueryArchive,
    /// [`SELF_SAVED_QUERY_MEMBERS`].
    SavedQueryMembers,
}

impl CampaignSurfaceVerb {
    /// Every verb, in the order [`CAMPAIGN_SELF_VERBS`] advertises them.
    pub const ALL: [Self; 10] = [
        Self::CampaignCreate,
        Self::CampaignRead,
        Self::CampaignUpdate,
        Self::CampaignArchive,
        Self::CampaignMembers,
        Self::SavedQueryCreate,
        Self::SavedQueryRead,
        Self::SavedQueryUpdate,
        Self::SavedQueryArchive,
        Self::SavedQueryMembers,
    ];

    /// Parses a verb name against the closed list.
    ///
    /// Exact equality, deliberately: a prefix, a suffix, or a case variant of a
    /// real verb is not a real verb. Nothing here trims or normalizes, so the
    /// string a caller sent is the string that must match.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|verb| verb.as_str() == value)
    }

    /// The wire name of this verb.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CampaignCreate => SELF_CAMPAIGN_CREATE,
            Self::CampaignRead => SELF_CAMPAIGN_READ,
            Self::CampaignUpdate => SELF_CAMPAIGN_UPDATE,
            Self::CampaignArchive => SELF_CAMPAIGN_ARCHIVE,
            Self::CampaignMembers => SELF_CAMPAIGN_MEMBERS,
            Self::SavedQueryCreate => SELF_SAVED_QUERY_CREATE,
            Self::SavedQueryRead => SELF_SAVED_QUERY_READ,
            Self::SavedQueryUpdate => SELF_SAVED_QUERY_UPDATE,
            Self::SavedQueryArchive => SELF_SAVED_QUERY_ARCHIVE,
            Self::SavedQueryMembers => SELF_SAVED_QUERY_MEMBERS,
        }
    }

    /// Whether this verb mutates durable state.
    ///
    /// Membership verbs are reads even though they are named after a cohort:
    /// they project the enrollment CA-03 already wrote and enqueue nothing.
    #[must_use]
    pub const fn is_write(self) -> bool {
        matches!(
            self,
            Self::CampaignCreate
                | Self::CampaignUpdate
                | Self::CampaignArchive
                | Self::SavedQueryCreate
                | Self::SavedQueryUpdate
                | Self::SavedQueryArchive
        )
    }
}

/// One surface invocation: a verb name and its JSON body.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SurfaceCall {
    /// Verb name; must be one of [`CAMPAIGN_SELF_VERBS`].
    pub verb: String,
    /// Verb-specific request body.
    pub body: Value,
}

/// One surface result, echoing the verb that produced it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SurfaceReply {
    /// Canonical verb name.
    pub verb: String,
    /// Verb-specific response body.
    pub body: Value,
}

// ---------------------------------------------------------------------------
// The CAMPAIGN record
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Membership projections
// ---------------------------------------------------------------------------

/// Page size used when a caller passes `limit = 0`.
pub const MEMBERSHIP_PAGE_DEFAULT_LIMIT: u32 = 50;

/// Hard ceiling on one membership page.
pub const MEMBERSHIP_PAGE_MAX_LIMIT: u32 = 200;

/// One page request against a campaign's or a query's membership.
///
/// `owner_ref` is the CAMPAIGN for [`read_campaign_members`] and the
/// SAVED_QUERY for [`read_saved_query_members`]. `at_epoch`, when present,
/// reads the cohort as of that membership epoch — the bitemporal read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipReadRequest {
    /// The campaign or saved query whose membership is being paged.
    pub owner_ref: EntityId,
    /// Opaque cursor from a prior page's `next_cursor`.
    pub cursor: Option<String>,
    /// Requested page size; `0` means [`MEMBERSHIP_PAGE_DEFAULT_LIMIT`] and
    /// anything above [`MEMBERSHIP_PAGE_MAX_LIMIT`] is clamped to it.
    pub limit: u32,
    /// Optional epoch ceiling; events after it are not folded into the row.
    pub at_epoch: Option<u64>,
}

/// One entity's membership, folded from its entered/exited history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipRow {
    /// The member.
    pub entity_ref: EntityId,
    /// `entered` or `exited` — the direction of the newest folded event.
    pub state: String,
    /// Valid time of the newest `entered` event.
    pub entered_valid: u64,
    /// Detection time of the newest `entered` event.
    pub entered_detected: u64,
    /// Valid time of the newest `exited` event, when the row is currently out.
    pub exited_valid: Option<u64>,
    /// Detection time of the newest `exited` event, when the row is currently
    /// out.
    pub exited_detected: Option<u64>,
    /// `data_change`, `scope_change`, or `definition_change`, exactly as CA-02
    /// produced it for the newest folded event.
    pub cause: Option<String>,
}

/// One page of membership rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipPage {
    /// Rows in stable cursor order.
    pub rows: Vec<MembershipRow>,
    /// Cursor for the next page; `None` when the page is the last one.
    pub next_cursor: Option<String>,
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Executes one surface call against the caller's bound facade.
///
/// The single door both transports share. Verb resolution happens here and
/// nowhere else, so the HTTP routers and the MCP gateway cannot disagree about
/// what a verb means — the only thing a transport chooses is how it built the
/// [`SurfaceCall`].
///
/// # Errors
///
/// A verb outside [`CAMPAIGN_SELF_VERBS`] and every malformed body are
/// `BAD_REQUEST`; the domain's own not-found, stale-version, and gate outcomes
/// propagate through [`FacadeError`] unchanged.
pub fn invoke_campaign_surface(
    facade: &Memory<'_>,
    call: SurfaceCall,
) -> FacadeResult<SurfaceReply> {
    let verb = CampaignSurfaceVerb::parse(&call.verb).ok_or_else(|| {
        FacadeError::bad_request_with(
            format!("{:?} is not a campaign surface verb", call.verb),
            &["Call one of the verbs advertised in CAMPAIGN_SELF_VERBS."],
        )
    })?;
    let body = call.body;
    let now = crate::unix_seconds_now();
    let payload = match verb {
        CampaignSurfaceVerb::CampaignCreate => {
            let request = parse_create_campaign_request(&body)?;
            campaign_record_to_json(&facade.campaign_create(&request, now)?)
        }
        CampaignSurfaceVerb::CampaignRead => {
            let campaign_ref = required_entity_ref(&body, "campaign_ref")?;
            optional_record_json(
                facade.campaign_read(campaign_ref)?.as_ref(),
                campaign_record_to_json,
            )
        }
        CampaignSurfaceVerb::CampaignUpdate => {
            let campaign_ref = required_entity_ref(&body, "campaign_ref")?;
            let request = parse_update_campaign_request(&body)?;
            campaign_record_to_json(&facade.campaign_update(campaign_ref, &request, now)?)
        }
        CampaignSurfaceVerb::CampaignArchive => {
            let campaign_ref = required_entity_ref(&body, "campaign_ref")?;
            let expected = required_u64(&body, "expected_definition_version")?;
            campaign_record_to_json(&facade.campaign_archive(campaign_ref, expected, now)?)
        }
        CampaignSurfaceVerb::CampaignMembers => {
            let request = parse_membership_request(&body, "campaign_ref")?;
            membership_page_to_json(&facade.campaign_members(&request)?)
        }
        CampaignSurfaceVerb::SavedQueryCreate => {
            let request = parse_create_saved_query_request(&body)?;
            saved_query_record_to_json(&facade.saved_query_create(&request, now)?)
        }
        CampaignSurfaceVerb::SavedQueryRead => {
            let query_ref = required_entity_ref(&body, "query_ref")?;
            optional_record_json(
                facade.saved_query_read(query_ref)?.as_ref(),
                saved_query_record_to_json,
            )
        }
        CampaignSurfaceVerb::SavedQueryUpdate => {
            let query_ref = required_entity_ref(&body, "query_ref")?;
            let request = parse_update_saved_query_request(&body)?;
            saved_query_record_to_json(&facade.saved_query_update(query_ref, &request, now)?)
        }
        CampaignSurfaceVerb::SavedQueryArchive => {
            let query_ref = required_entity_ref(&body, "query_ref")?;
            let expected = required_u64(&body, "expected_definition_version")?;
            saved_query_record_to_json(&facade.saved_query_archive(query_ref, expected, now)?)
        }
        CampaignSurfaceVerb::SavedQueryMembers => {
            let request = parse_membership_request(&body, "query_ref")?;
            membership_page_to_json(&facade.saved_query_members(&request)?)
        }
    };
    Ok(SurfaceReply {
        verb: verb.as_str().to_owned(),
        body: payload,
    })
}

/// Wraps a read result so "absent" and "present" have one shape.
fn optional_record_json<T>(record: Option<&T>, encode: impl FnOnce(&T) -> Value) -> Value {
    let mut root = JsonMap::new();
    root.insert("found".to_owned(), Value::Bool(record.is_some()));
    root.insert("record".to_owned(), record.map_or(Value::Null, encode));
    Value::Object(root)
}

// ---------------------------------------------------------------------------
// CAMPAIGN lifecycle
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Membership reads
// ---------------------------------------------------------------------------

/// Pages a campaign's cohort.
///
/// Read-only by construction: it opens no write transaction, mints no claim, and
/// enqueues no attempt. The cohort is CA-01's live `campaign.member` heads, and
/// each row's bitemporal fields come from CA-02's entered/exited event history
/// for the `(source query, entity)` pair the head names — so the projection
/// reports exactly what the enrollment writer recorded and nothing it inferred.
///
/// # Errors
///
/// Storage and decode errors propagate; a malformed cursor is
/// [`Error::InvalidKey`].
pub fn read_campaign_members(vault: &Vault, req: &MembershipReadRequest) -> Result<MembershipPage> {
    membership_page(vault, req, MembershipOwner::Campaign)
}

/// Pages the membership one saved query derived.
///
/// The query-side twin of [`read_campaign_members`], with the same read-only
/// guarantee and the same event source; only the filter axis differs.
///
/// # Errors
///
/// Storage and decode errors propagate; a malformed cursor is
/// [`Error::InvalidKey`].
pub fn read_saved_query_members(
    vault: &Vault,
    req: &MembershipReadRequest,
) -> Result<MembershipPage> {
    membership_page(vault, req, MembershipOwner::SavedQuery)
}

/// Which axis of a `campaign.member` head `owner_ref` selects on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MembershipOwner {
    /// `owner_ref` is the CAMPAIGN the head is scoped to.
    Campaign,
    /// `owner_ref` is the SAVED_QUERY the head was derived from.
    SavedQuery,
}

/// One `(entity, query, campaign)` membership head, in cursor order.
struct MembershipHead {
    entity_ref: EntityId,
    query_ref: EntityId,
    campaign_ref: EntityId,
}

impl MembershipHead {
    /// The opaque cursor token for this head.
    ///
    /// The full triple, not just `entity_ref`: one entity can hold heads in
    /// several campaigns derived from one query, so an entity-only cursor could
    /// skip or repeat a row at a page boundary.
    fn cursor(&self) -> String {
        format!(
            "{}{}{}",
            self.entity_ref.to_hex(),
            self.query_ref.to_hex(),
            self.campaign_ref.to_hex()
        )
    }
}

fn membership_page(
    vault: &Vault,
    req: &MembershipReadRequest,
    owner: MembershipOwner,
) -> Result<MembershipPage> {
    let limit = effective_limit(req.limit);
    if let Some(cursor) = req.cursor.as_deref() {
        validate_cursor(cursor)?;
    }
    let mut heads = membership_heads(vault, req.owner_ref, owner)?;
    // Sorted on the same triple the cursor encodes, so "everything after the
    // cursor" is a total order and a page boundary is stable across calls.
    heads.sort_unstable_by_key(|head| {
        (
            *head.entity_ref.as_bytes(),
            *head.query_ref.as_bytes(),
            *head.campaign_ref.as_bytes(),
        )
    });

    let mut rows = Vec::new();
    let mut last_token = None;
    let mut has_more = false;
    for head in heads {
        let token = head.cursor();
        if req
            .cursor
            .as_deref()
            .is_some_and(|cursor| token.as_str() <= cursor)
        {
            continue;
        }
        if rows.len() as u32 >= limit {
            has_more = true;
            break;
        }
        let events = membership_events(vault, head.query_ref, head.entity_ref)?;
        if let Some(row) = fold_membership_events(&head, &events, req.at_epoch) {
            rows.push(row);
        }
        // Advanced for every head the loop CONSUMED, not only for the ones that
        // produced a row: a head whose history folds to nothing is still done,
        // and re-offering it on the next page would stall a caller that pages
        // through a cohort of them.
        last_token = Some(token);
    }
    // A cursor is emitted only when an unvisited head remains. A page that
    // exhausted the scan reports `None`, so "keep paging while next_cursor is
    // Some" terminates instead of looping on an empty tail.
    Ok(MembershipPage {
        rows,
        next_cursor: has_more.then_some(last_token).flatten(),
    })
}

const fn effective_limit(requested: u32) -> u32 {
    if requested == 0 {
        MEMBERSHIP_PAGE_DEFAULT_LIMIT
    } else if requested > MEMBERSHIP_PAGE_MAX_LIMIT {
        MEMBERSHIP_PAGE_MAX_LIMIT
    } else {
        requested
    }
}

/// A cursor is exactly three hex entity ids. Rejecting a malformed one is the
/// difference between "you asked for a page that does not exist" and silently
/// returning page one under a caller that believes it is paging.
fn validate_cursor(cursor: &str) -> Result<()> {
    const CURSOR_LEN: usize = 96;
    if cursor.len() != CURSOR_LEN || !cursor.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::InvalidKey);
    }
    Ok(())
}

/// Every live `campaign.member` head matching `owner_ref` on the chosen axis.
///
/// CA-01 owns the head, and its value carries both the campaign it is scoped to
/// and the query that derived it, so one predicate scan answers both directions.
/// The CRM pack registers no membership index of its own — `registry.rs` is a
/// hard non-claim for this lane — so this walks the CLAIM type index the way
/// `/api/core/discover` walks it. Output is bounded by the page limit; the scan
/// is not, and an index is the honest follow-up if cohorts get large.
fn membership_heads(
    vault: &Vault,
    owner_ref: EntityId,
    owner: MembershipOwner,
) -> Result<Vec<MembershipHead>> {
    let mut heads = Vec::new();
    for claim_id in vault.entities_by_type(ENTITY_TYPE_CLAIM)? {
        let Some(body) = vault.get_claim(&claim_id)? else {
            continue;
        };
        if body.predicate != PREDICATE_CAMPAIGN_MEMBER
            || body.lifecycle != ClaimLifecycleStatus::Active
        {
            continue;
        }
        let ClaimSubject::Entity(entity_ref) = body.subject else {
            continue;
        };
        let value = decode_campaign_member_value(&body.value)?;
        // A head with no derivation was not written by CA-03's consequence
        // writer, so there is no `(query, entity)` history to fold and no
        // honest bitemporal row to emit.
        let Some(derivation) = value.derivation else {
            continue;
        };
        let matches = match owner {
            MembershipOwner::Campaign => value.campaign == owner_ref,
            MembershipOwner::SavedQuery => derivation.source_query == owner_ref,
        };
        if matches {
            heads.push(MembershipHead {
                entity_ref,
                query_ref: derivation.source_query,
                campaign_ref: value.campaign,
            });
        }
    }
    Ok(heads)
}

/// Folds one head's history into a single row.
///
/// The event log is keyed `(query, entity)` and one such pair can hold heads in
/// SEVERAL campaigns, so the history handed in is the union across them and only
/// the events carrying this head's `campaign_ref` are this head's. Folding the
/// union would let one campaign's exit end a membership in another.
///
/// `entered_*` always report the newest ENTRY, even when the entity has since
/// exited, so a caller can tell "left after a long membership" from "left
/// immediately". `exited_*` are populated only when the newest event is an exit:
/// a re-entry supersedes the prior exit rather than leaving a stale end date on
/// a live member.
fn fold_membership_events(
    head: &MembershipHead,
    events: &[MembershipEvent],
    at_epoch: Option<u64>,
) -> Option<MembershipRow> {
    let mut entered: Option<&MembershipEvent> = None;
    let mut latest: Option<&MembershipEvent> = None;
    for event in events {
        if event.campaign_ref != head.campaign_ref {
            continue;
        }
        if at_epoch.is_some_and(|ceiling| event.epoch > ceiling) {
            continue;
        }
        if event.transition == MembershipTransition::Entered {
            entered = Some(event);
        }
        latest = Some(event);
    }
    let latest = latest?;
    let entered = entered?;
    let exited = (latest.transition == MembershipTransition::Exited).then_some(latest);
    Some(MembershipRow {
        entity_ref: head.entity_ref,
        state: latest.transition.as_str().to_owned(),
        entered_valid: entered.valid_at,
        entered_detected: entered.detected_at,
        exited_valid: exited.map(|event| event.valid_at),
        exited_detected: exited.map(|event| event.detected_at),
        cause: Some(latest.cause.as_str().to_owned()),
    })
}

// ---------------------------------------------------------------------------
// JSON encoding
// ---------------------------------------------------------------------------

/// Encodes a campaign record for the wire.
#[must_use]
pub fn campaign_record_to_json(record: &CampaignRecord) -> Value {
    let mut definition = JsonMap::new();
    definition.insert(
        "schema_version".to_owned(),
        Value::from(record.definition.schema_version),
    );
    definition.insert(
        "owner_actor".to_owned(),
        Value::String(record.definition.owner_actor.to_hex()),
    );
    definition.insert(
        "name".to_owned(),
        Value::String(record.definition.name.clone()),
    );
    definition.insert(
        "definition_version".to_owned(),
        Value::from(record.definition.definition_version),
    );
    definition.insert(
        "lifecycle".to_owned(),
        Value::String(record.definition.lifecycle.as_str().to_owned()),
    );

    let mut root = JsonMap::new();
    root.insert(
        "campaign_ref".to_owned(),
        Value::String(record.campaign_ref.to_hex()),
    );
    root.insert("definition".to_owned(), Value::Object(definition));
    root.insert("created_at".to_owned(), Value::from(record.created_at));
    root.insert("updated_at".to_owned(), Value::from(record.updated_at));
    Value::Object(root)
}

/// Encodes a saved-query record for the wire.
///
/// Hand-written for the reason [`SavedQueryDefinition`](crate::saved_query::SavedQueryDefinition) documents: its types
/// carry [`EntityId`]s and are deliberately not serde-derived, and
/// `saved_query.rs` is a CA-07 non-claim, so this surface converts CA-02's types
/// rather than changing them.
#[must_use]
pub fn saved_query_record_to_json(record: &SavedQueryRecord) -> Value {
    let mut definition = JsonMap::new();
    definition.insert(
        "schema_version".to_owned(),
        Value::from(record.definition.schema_version),
    );
    definition.insert(
        "owner_actor".to_owned(),
        Value::String(record.definition.owner_actor.to_hex()),
    );
    definition.insert("scope".to_owned(), scope_to_json(&record.definition.scope));
    definition.insert(
        "definition_version".to_owned(),
        Value::from(record.definition.definition_version),
    );
    definition.insert(
        "filter".to_owned(),
        filter_to_json(&record.definition.filter),
    );
    definition.insert(
        "matcher".to_owned(),
        matcher_to_json(&record.definition.matcher),
    );
    definition.insert("eval".to_owned(), eval_to_json(record.definition.eval));
    definition.insert(
        "lifecycle".to_owned(),
        saved_query_lifecycle_to_json(&record.definition.lifecycle),
    );

    let mut root = JsonMap::new();
    root.insert(
        "query_ref".to_owned(),
        Value::String(record.query_ref.to_hex()),
    );
    root.insert("definition".to_owned(), Value::Object(definition));
    root.insert("created_at".to_owned(), Value::from(record.created_at));
    root.insert("updated_at".to_owned(), Value::from(record.updated_at));
    Value::Object(root)
}

fn saved_query_lifecycle_to_json(lifecycle: &SavedQueryLifecycle) -> Value {
    let mut root = JsonMap::new();
    match lifecycle {
        SavedQueryLifecycle::Active => {
            root.insert("state".to_owned(), Value::String("active".to_owned()));
        }
        SavedQueryLifecycle::Paused { error } => {
            root.insert("state".to_owned(), Value::String("paused".to_owned()));
            root.insert("error".to_owned(), Value::String(error.clone()));
        }
        SavedQueryLifecycle::Archived => {
            root.insert("state".to_owned(), Value::String("archived".to_owned()));
        }
    }
    Value::Object(root)
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

fn filter_to_json(filter: &FilterAst) -> Value {
    let mut root = JsonMap::new();
    match filter {
        FilterAst::All { terms } | FilterAst::Any { terms } => {
            let op = if matches!(filter, FilterAst::All { .. }) {
                "all"
            } else {
                "any"
            };
            root.insert("op".to_owned(), Value::String(op.to_owned()));
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

fn matcher_to_json(matcher: &MatcherSpec) -> Value {
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

fn eval_to_json(eval: EvalPolicy) -> Value {
    let mut root = JsonMap::new();
    root.insert(
        "mode".to_owned(),
        Value::String(eval.mode.as_str().to_owned()),
    );
    root.insert(
        "max_entities_per_wake".to_owned(),
        Value::from(eval.max_entities_per_wake),
    );
    root.insert(
        "max_judges_per_wake".to_owned(),
        Value::from(eval.max_judges_per_wake),
    );
    Value::Object(root)
}

fn membership_page_to_json(page: &MembershipPage) -> Value {
    let mut root = JsonMap::new();
    root.insert(
        "rows".to_owned(),
        Value::Array(page.rows.iter().map(membership_row_to_json).collect()),
    );
    root.insert(
        "next_cursor".to_owned(),
        page.next_cursor
            .as_ref()
            .map_or(Value::Null, |cursor| Value::String(cursor.clone())),
    );
    Value::Object(root)
}

fn membership_row_to_json(row: &MembershipRow) -> Value {
    let mut root = JsonMap::new();
    root.insert(
        "entity_ref".to_owned(),
        Value::String(row.entity_ref.to_hex()),
    );
    root.insert("state".to_owned(), Value::String(row.state.clone()));
    root.insert("entered_valid".to_owned(), Value::from(row.entered_valid));
    root.insert(
        "entered_detected".to_owned(),
        Value::from(row.entered_detected),
    );
    root.insert(
        "exited_valid".to_owned(),
        row.exited_valid.map_or(Value::Null, Value::from),
    );
    root.insert(
        "exited_detected".to_owned(),
        row.exited_detected.map_or(Value::Null, Value::from),
    );
    root.insert(
        "cause".to_owned(),
        row.cause
            .as_ref()
            .map_or(Value::Null, |cause| Value::String(cause.clone())),
    );
    Value::Object(root)
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

// ---------------------------------------------------------------------------
// JSON decoding of request bodies
// ---------------------------------------------------------------------------

fn parse_create_campaign_request(body: &Value) -> FacadeResult<CreateCampaignRequest> {
    Ok(CreateCampaignRequest {
        schema_version: optional_u32(body, "schema_version")?.unwrap_or(CAMPAIGN_SCHEMA_VERSION),
        name: required_string(body, "name")?,
    })
}

fn parse_update_campaign_request(body: &Value) -> FacadeResult<UpdateCampaignRequest> {
    Ok(UpdateCampaignRequest {
        expected_definition_version: required_u64(body, "expected_definition_version")?,
        name: required_string(body, "name")?,
    })
}

fn parse_create_saved_query_request(body: &Value) -> FacadeResult<CreateSavedQueryRequest> {
    Ok(CreateSavedQueryRequest {
        schema_version: optional_u32(body, "schema_version")?.unwrap_or(SAVED_QUERY_SCHEMA_VERSION),
        scope: parse_scope(body)?,
        filter: parse_filter(body)?,
        matcher: parse_matcher(body)?,
        eval: parse_eval(body)?,
    })
}

fn parse_update_saved_query_request(body: &Value) -> FacadeResult<UpdateSavedQueryRequest> {
    Ok(UpdateSavedQueryRequest {
        expected_definition_version: required_u64(body, "expected_definition_version")?,
        scope: parse_scope(body)?,
        filter: parse_filter(body)?,
        matcher: parse_matcher(body)?,
        eval: parse_eval(body)?,
    })
}

fn parse_membership_request(body: &Value, ref_field: &str) -> FacadeResult<MembershipReadRequest> {
    Ok(MembershipReadRequest {
        owner_ref: required_entity_ref(body, ref_field)?,
        cursor: match body.get("cursor") {
            None | Some(Value::Null) => None,
            Some(value) => Some(
                value
                    .as_str()
                    .ok_or_else(|| field_error("cursor", "must be a string"))?
                    .to_owned(),
            ),
        },
        limit: optional_u32(body, "limit")?.unwrap_or(0),
        at_epoch: optional_u64(body, "at_epoch")?,
    })
}

fn parse_scope(body: &Value) -> FacadeResult<QueryScope> {
    let Some(raw) = body.get("scope").filter(|value| !value.is_null()) else {
        return Ok(QueryScope::default());
    };
    // An empty axis means UNRESTRICTED in [`QueryScope`], so a non-object scope
    // cannot be read as "no fields present": `"scope": "sales"` would silently
    // widen the query to every world and facet instead of being refused.
    if !raw.is_object() {
        return Err(field_error("scope", "must be an object"));
    }
    let worlds = match raw.get("worlds") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .and_then(|hex| EntityId::from_hex(hex).ok())
                    .ok_or_else(|| field_error("scope.worlds", "must be 32-hex entity ids"))
            })
            .collect::<FacadeResult<Vec<_>>>()?,
        Some(_) => return Err(field_error("scope.worlds", "must be an array")),
    };
    let facets = match raw.get("facets") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| field_error("scope.facets", "must be strings"))
            })
            .collect::<FacadeResult<Vec<_>>>()?,
        Some(_) => return Err(field_error("scope.facets", "must be an array")),
    };
    Ok(QueryScope { worlds, facets })
}

/// Parses a stage-1 filter through CA-02's own door.
///
/// [`parse_filter_ast`] is the only place ranked and global-relative operators
/// are named and refused, so routing through it is what keeps a `top_k` filter
/// from entering by the SDK when it cannot enter by the engine.
fn parse_filter(body: &Value) -> FacadeResult<FilterAst> {
    let raw = body
        .get("filter")
        .ok_or_else(|| field_error("filter", "is required"))?;
    Ok(parse_filter_ast(raw)?)
}

fn parse_matcher(body: &Value) -> FacadeResult<MatcherSpec> {
    let raw = body
        .get("matcher")
        .ok_or_else(|| field_error("matcher", "is required"))?;
    let kind = raw
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| field_error("matcher.kind", "is required"))?;
    match kind {
        "hard" => Ok(MatcherSpec::Hard {
            expression: parse_filter_ast(
                raw.get("expression")
                    .ok_or_else(|| field_error("matcher.expression", "is required"))?,
            )?,
        }),
        "semantic_threshold" => Ok(MatcherSpec::SemanticThreshold {
            exemplar_ref: raw
                .get("exemplar_ref")
                .and_then(Value::as_str)
                .and_then(|hex| EntityId::from_hex(hex).ok())
                .ok_or_else(|| field_error("matcher.exemplar_ref", "must be a 32-hex entity id"))?,
            minimum_similarity_micros: raw
                .get("minimum_similarity_micros")
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| field_error("matcher.minimum_similarity_micros", "must be a u32"))?,
        }),
        "llm_judge" => Ok(MatcherSpec::LlmJudge {
            model_id: raw
                .get("model_id")
                .and_then(Value::as_str)
                .ok_or_else(|| field_error("matcher.model_id", "is required"))?
                .to_owned(),
            rubric: raw.get("rubric").cloned().unwrap_or(Value::Null),
            rubric_version: raw
                .get("rubric_version")
                .and_then(Value::as_str)
                .ok_or_else(|| field_error("matcher.rubric_version", "is required"))?
                .to_owned(),
        }),
        other => Err(field_error(
            "matcher.kind",
            &format!("{other:?} is not one of hard, semantic_threshold, llm_judge"),
        )),
    }
}

fn parse_eval(body: &Value) -> FacadeResult<EvalPolicy> {
    let raw = body
        .get("eval")
        .ok_or_else(|| field_error("eval", "is required"))?;
    Ok(EvalPolicy {
        mode: raw
            .get("mode")
            .and_then(Value::as_str)
            .and_then(EvalMode::parse)
            .ok_or_else(|| field_error("eval.mode", "must be reactive, wake, or manual"))?,
        max_entities_per_wake: required_u32(raw, "max_entities_per_wake")?,
        max_judges_per_wake: required_u32(raw, "max_judges_per_wake")?,
    })
}

fn required_entity_ref(body: &Value, field: &str) -> FacadeResult<EntityId> {
    body.get(field)
        .and_then(Value::as_str)
        .and_then(|hex| EntityId::from_hex(hex).ok())
        .ok_or_else(|| field_error(field, "must be a 32-character hex entity id"))
}

fn required_string(body: &Value, field: &str) -> FacadeResult<String> {
    body.get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| field_error(field, "must be a string"))
}

fn required_u64(body: &Value, field: &str) -> FacadeResult<u64> {
    body.get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| field_error(field, "must be a non-negative integer"))
}

fn required_u32(body: &Value, field: &str) -> FacadeResult<u32> {
    required_u64(body, field)?
        .try_into()
        .map_err(|_| field_error(field, "must fit in a u32"))
}

fn optional_u64(body: &Value, field: &str) -> FacadeResult<Option<u64>> {
    match body.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| field_error(field, "must be a non-negative integer")),
    }
}

fn optional_u32(body: &Value, field: &str) -> FacadeResult<Option<u32>> {
    optional_u64(body, field)?
        .map(|value| u32::try_from(value).map_err(|_| field_error(field, "must fit in a u32")))
        .transpose()
}

fn field_error(field: &str, requirement: &str) -> FacadeError {
    FacadeError::bad_request(format!("campaign surface field {field} {requirement}"))
}

fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EdgeActorClass;
    use crate::campaign::claims::{CampaignMemberChannel, CampaignMemberState};
    use crate::campaign::register_crm_pack;
    use crate::config::VaultConfig;
    use crate::registry::ENTITY_TYPE_PERSON;
    use crate::saved_query::{
        MembershipCause, MembershipCommitOutcome, MembershipWritePlan, commit_membership_plan,
        derived_member_value,
    };

    // Free dynamic slots in the compiled-product zone. 100-106 are statically
    // allocated after byte-space v3, so the CRM pack registers above them.
    const CAMPAIGN_BYTE: u8 = 107;
    const SAVED_QUERY_BYTE: u8 = 108;

    /// Unseeded, like CA-01's and CA-02's oracles: the default policy manifest
    /// declares axes for `profile.`, `calendar.`, `booking.`, and `affect.vad`
    /// only, so every CRM predicate falls to the manifest's `critical` default
    /// and a `campaign.member` write is held PENDING at the criticality floor.
    /// The projection under test reads heads CA-03 already wrote, so the
    /// fixture writes them the way CA-02's own oracle does.
    fn oracle_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open_unseeded_for_test(dir.path(), VaultConfig::device())
            .expect("open unseeded vault");
        register_crm_pack(&vault, CAMPAIGN_BYTE, SAVED_QUERY_BYTE).expect("register CRM pack");
        (dir, vault)
    }

    fn test_id(seed: u8) -> EntityId {
        EntityId::from_bytes([seed; 16]).expect("seeded id")
    }

    fn put_person(vault: &Vault, id: EntityId) {
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"campaign surface person",
            )
            .expect("put person");
    }

    /// One `(query, campaign)` pair, so a fixture can spell a transition
    /// without restating the two refs it never varies.
    struct Cohort<'v> {
        vault: &'v Vault,
        query: EntityId,
        campaign: EntityId,
    }

    impl Cohort<'_> {
        fn commit(
            &self,
            person: EntityId,
            epoch: u64,
            transition: MembershipTransition,
            cause: MembershipCause,
            at: u64,
        ) {
            let event = MembershipEvent {
                query_ref: self.query,
                campaign_ref: self.campaign,
                entity_ref: person,
                epoch,
                valid_at: at,
                detected_at: at + 1,
                transition,
                cause,
                evidence_hash: [u8::try_from(epoch % 251).unwrap_or_default(); 32],
            };
            let state = match transition {
                MembershipTransition::Entered => CampaignMemberState::Enrolled,
                MembershipTransition::Exited => CampaignMemberState::Exited,
            };
            let plan = MembershipWritePlan {
                value: derived_member_value(
                    &event,
                    state,
                    vec![CampaignMemberChannel {
                        channel: "email".to_owned(),
                        basis_evidence: test_id(0xE1),
                        sender_ref: test_id(0xE2),
                    }],
                ),
                event,
            };
            assert_eq!(
                commit_membership_plan(self.vault, &plan, at + 1).expect("commit plan"),
                MembershipCommitOutcome::Applied
            );
        }
    }

    /// A minimal but REAL create request: the filter and matcher go through
    /// CA-02's own `parse_filter_ast`, so the fixture cannot admit an
    /// expression the engine would refuse.
    fn saved_query_request() -> CreateSavedQueryRequest {
        let claim = |predicate: &str| {
            parse_filter_ast(&serde_json::json!({
                "op": "claim",
                "predicate": predicate,
                "cmp": "eq",
                "value": "vp",
            }))
            .expect("stage-1 filter")
        };
        CreateSavedQueryRequest {
            schema_version: SAVED_QUERY_SCHEMA_VERSION,
            scope: QueryScope::default(),
            filter: claim("profile.seniority"),
            matcher: MatcherSpec::Hard {
                expression: claim("profile.headcount"),
            },
            eval: EvalPolicy {
                mode: EvalMode::Manual,
                max_entities_per_wake: 8,
                max_judges_per_wake: 4,
            },
        }
    }

    fn request(owner: EntityId, limit: u32) -> MembershipReadRequest {
        MembershipReadRequest {
            owner_ref: owner,
            cursor: None,
            limit,
            at_epoch: None,
        }
    }

    /// Every entity in the vault, so "this read wrote nothing" is checkable
    /// rather than asserted.
    fn fingerprint(vault: &Vault) -> Vec<(u8, [u8; 16])> {
        let mut rows = Vec::new();
        for entity_type in u8::MIN..=u8::MAX {
            for id in vault.entities_by_type(entity_type).unwrap_or_default() {
                rows.push((entity_type, *id.as_bytes()));
            }
        }
        rows.sort_unstable();
        rows
    }

    /// Pages are stable, bounded, and gap-free across a cursor boundary.
    #[test]
    fn campaign_membership_reads_are_paginated_and_read_only() {
        let (_dir, vault) = oracle_vault();
        let (query, campaign) = (test_id(0x31), test_id(0x30));
        let cohort = Cohort {
            vault: &vault,
            query,
            campaign,
        };
        let people = [test_id(0x41), test_id(0x42), test_id(0x43)];
        for (index, person) in people.iter().enumerate() {
            put_person(&vault, *person);
            cohort.commit(
                *person,
                1,
                MembershipTransition::Entered,
                MembershipCause::DataChange,
                100 + index as u64,
            );
        }
        let ordered: Vec<EntityId> = people.to_vec();

        // A page wide enough for the cohort carries all of it, in entity order,
        // and reports no successor.
        let full = read_campaign_members(&vault, &request(campaign, 10)).expect("full page");
        assert_eq!(
            full.rows
                .iter()
                .map(|row| row.entity_ref)
                .collect::<Vec<_>>(),
            ordered
        );
        assert!(full.next_cursor.is_none());

        // Bitemporal fields are the committed event's, not the read's clock.
        assert_eq!(full.rows[0].state, "entered");
        assert_eq!(full.rows[0].cause.as_deref(), Some("data_change"));
        assert_eq!(full.rows[0].entered_valid, 100);
        assert_eq!(full.rows[0].entered_detected, 101);
        assert_eq!(full.rows[0].exited_valid, None);
        assert_eq!(full.rows[0].exited_detected, None);

        // limit=2 splits it; the cursor resumes exactly where page one stopped.
        let first = read_campaign_members(&vault, &request(campaign, 2)).expect("page one");
        assert_eq!(first.rows.len(), 2);
        let cursor = first.next_cursor.clone().expect("a successor page");
        let second = read_campaign_members(
            &vault,
            &MembershipReadRequest {
                cursor: Some(cursor),
                ..request(campaign, 2)
            },
        )
        .expect("page two");
        assert_eq!(second.rows.len(), 1);
        assert!(second.next_cursor.is_none());
        let paged: Vec<EntityId> = first
            .rows
            .iter()
            .chain(second.rows.iter())
            .map(|row| row.entity_ref)
            .collect();
        assert_eq!(paged, ordered, "paging must neither skip nor repeat a row");

        // Repeating a page is idempotent — the cursor is a position, not a
        // consumed token.
        assert_eq!(
            read_campaign_members(&vault, &request(campaign, 2)).expect("replay"),
            first
        );

        // `limit = 0` means the default, and an over-large limit is clamped
        // rather than refused.
        assert_eq!(
            read_campaign_members(&vault, &request(campaign, 0))
                .expect("default limit")
                .rows
                .len(),
            people.len()
        );
        assert_eq!(
            read_campaign_members(
                &vault,
                &request(campaign, MEMBERSHIP_PAGE_MAX_LIMIT + 10_000)
            )
            .expect("clamped limit")
            .rows
            .len(),
            people.len()
        );

        // A malformed cursor is a typed rejection, never a silent page one.
        for malformed in ["", "nonsense", &"a".repeat(95), &"g".repeat(96)] {
            assert!(
                read_campaign_members(
                    &vault,
                    &MembershipReadRequest {
                        cursor: Some(malformed.to_owned()),
                        ..request(campaign, 2)
                    },
                )
                .is_err(),
                "{malformed:?} must not read as page one"
            );
        }

        // Another campaign's cohort is not this one's.
        assert!(
            read_campaign_members(&vault, &request(test_id(0x39), 10))
                .expect("empty cohort")
                .rows
                .is_empty()
        );

        // Nothing in any of that wrote a claim, an attempt row, or an entity.
        let before = fingerprint(&vault);
        let _ = read_campaign_members(&vault, &request(campaign, 1)).expect("read");
        let _ = read_saved_query_members(&vault, &request(query, 1)).expect("read");
        assert_eq!(fingerprint(&vault), before);
    }

    /// Causes survive verbatim, and an epoch ceiling reads the cohort as it
    /// stood at that epoch.
    #[test]
    fn saved_query_membership_reads_preserve_causes() {
        let (_dir, vault) = oracle_vault();
        let (query, campaign, person) = (test_id(0x51), test_id(0x50), test_id(0x52));
        put_person(&vault, person);
        let cohort = Cohort {
            vault: &vault,
            query,
            campaign,
        };

        // One entity, three epochs, the closed cause set in full.
        cohort.commit(
            person,
            1,
            MembershipTransition::Entered,
            MembershipCause::DataChange,
            200,
        );
        cohort.commit(
            person,
            2,
            MembershipTransition::Exited,
            MembershipCause::ScopeChange,
            300,
        );
        cohort.commit(
            person,
            3,
            MembershipTransition::Entered,
            MembershipCause::DefinitionChange,
            400,
        );

        let at = |epoch: Option<u64>| {
            read_saved_query_members(
                &vault,
                &MembershipReadRequest {
                    at_epoch: epoch,
                    ..request(query, 10)
                },
            )
            .expect("membership page")
            .rows
            .first()
            .cloned()
            .expect("one row")
        };

        let now = at(None);
        assert_eq!(now.state, "entered");
        assert_eq!(now.cause.as_deref(), Some("definition_change"));
        assert_eq!(now.entered_valid, 400);
        assert_eq!(now.entered_detected, 401);
        assert_eq!(now.exited_valid, None);

        // As of epoch 2 the entity was OUT — and the row still reports when it
        // had entered, so a departure keeps its history instead of erasing it.
        let mid = at(Some(2));
        assert_eq!(mid.state, "exited");
        assert_eq!(mid.cause.as_deref(), Some("scope_change"));
        assert_eq!(mid.entered_valid, 200);
        assert_eq!(mid.exited_valid, Some(300));
        assert_eq!(mid.exited_detected, Some(301));

        let start = at(Some(1));
        assert_eq!(start.state, "entered");
        assert_eq!(start.cause.as_deref(), Some("data_change"));
        assert_eq!(start.exited_valid, None);

        // An epoch below the first transition has nothing to fold.
        assert!(
            read_saved_query_members(
                &vault,
                &MembershipReadRequest {
                    at_epoch: Some(0),
                    ..request(query, 10)
                },
            )
            .expect("page")
            .rows
            .is_empty()
        );

        // Every cause the projection can emit is one of CA-02's three tokens,
        // spelled by CA-02 rather than restated here.
        for cause in MembershipCause::ALL {
            assert!(["data_change", "scope_change", "definition_change"].contains(&cause.as_str()));
        }

        // The campaign axis of the same head projects identically: one fold,
        // two selectors.
        assert_eq!(
            read_campaign_members(&vault, &request(campaign, 10))
                .expect("campaign page")
                .rows,
            vec![now]
        );
    }

    /// One `(query, entity)` pair can hold heads in several campaigns. Each row
    /// folds only the events of ITS campaign.
    #[test]
    fn membership_rows_fold_only_their_own_campaigns_events() {
        let (_dir, vault) = oracle_vault();
        let query = test_id(0x61);
        let (first, second) = (test_id(0x60), test_id(0x62));
        let person = test_id(0x63);
        put_person(&vault, person);
        let in_first = Cohort {
            vault: &vault,
            query,
            campaign: first,
        };
        let in_second = Cohort {
            vault: &vault,
            query,
            campaign: second,
        };

        // The event log is keyed `(query, entity)`, so these three transitions
        // share ONE history across two campaigns — and the epoch is monotonic
        // over that shared history, not per campaign.
        in_first.commit(
            person,
            1,
            MembershipTransition::Entered,
            MembershipCause::DataChange,
            100,
        );
        in_second.commit(
            person,
            2,
            MembershipTransition::Entered,
            MembershipCause::ScopeChange,
            200,
        );
        in_second.commit(
            person,
            3,
            MembershipTransition::Exited,
            MembershipCause::DefinitionChange,
            300,
        );

        // The first campaign never saw the exit: its member is still enrolled,
        // on its own entry's clock and its own cause.
        let still_in = read_campaign_members(&vault, &request(first, 10)).expect("first cohort");
        assert_eq!(still_in.rows.len(), 1);
        assert_eq!(still_in.rows[0].state, "entered");
        assert_eq!(still_in.rows[0].cause.as_deref(), Some("data_change"));
        assert_eq!(still_in.rows[0].entered_valid, 100);
        assert_eq!(still_in.rows[0].exited_valid, None);

        // The second did, and dates the entry from its OWN entry event rather
        // than from the first campaign's.
        let left = read_campaign_members(&vault, &request(second, 10)).expect("second cohort");
        assert_eq!(left.rows.len(), 1);
        assert_eq!(left.rows[0].state, "exited");
        assert_eq!(left.rows[0].cause.as_deref(), Some("definition_change"));
        assert_eq!(left.rows[0].entered_valid, 200);
        assert_eq!(left.rows[0].exited_valid, Some(300));

        // The query axis pages both heads, each folded against its own
        // campaign, so the derived cohort is not one campaign's state twice.
        let derived = read_saved_query_members(&vault, &request(query, 10)).expect("query cohort");
        let mut states: Vec<&str> = derived
            .rows
            .iter()
            .map(|row| row.state.as_str())
            .collect::<Vec<_>>();
        states.sort_unstable();
        assert_eq!(states, ["entered", "exited"]);
    }

    /// A membership page is the owner's cohort, not any admitted caller's.
    #[test]
    fn membership_reads_are_scoped_to_the_owning_principal() {
        let (_dir, vault) = oracle_vault();
        let (owner, intruder, person) = (test_id(0x71), test_id(0x72), test_id(0x73));
        for actor in [owner, intruder, person] {
            put_person(&vault, actor);
        }

        let owner_facade = vault.memory_facade(owner, EdgeActorClass::Human);
        let campaign = owner_facade
            .campaign_create(
                &CreateCampaignRequest {
                    schema_version: CAMPAIGN_SCHEMA_VERSION,
                    name: "owned cohort".to_owned(),
                },
                10,
            )
            .expect("create campaign")
            .campaign_ref;
        let query = owner_facade
            .saved_query_create(&saved_query_request(), 10)
            .expect("create saved query")
            .query_ref;
        Cohort {
            vault: &vault,
            query,
            campaign,
        }
        .commit(
            person,
            1,
            MembershipTransition::Entered,
            MembershipCause::DataChange,
            100,
        );

        // The owner pages their own cohort on both axes.
        assert_eq!(
            owner_facade
                .campaign_members(&request(campaign, 10))
                .expect("owner campaign page")
                .rows
                .len(),
            1
        );
        assert_eq!(
            owner_facade
                .saved_query_members(&request(query, 10))
                .expect("owner query page")
                .rows
                .len(),
            1
        );

        // Another admitted principal holding the same well-formed refs pages
        // nothing: absent-or-not-yours is ONE answer here, exactly as it is for
        // the record reads.
        let intruder_facade = vault.memory_facade(intruder, EdgeActorClass::Human);
        assert!(
            intruder_facade
                .campaign_members(&request(campaign, 10))
                .expect("foreign campaign page")
                .rows
                .is_empty(),
            "a campaign's cohort must not page for a principal that does not own it"
        );
        assert!(
            intruder_facade
                .saved_query_members(&request(query, 10))
                .expect("foreign query page")
                .rows
                .is_empty(),
            "a query's cohort must not page for a principal that does not own it"
        );
    }

    /// A `scope` that is not an object is a field error, never an unrestricted
    /// query: every axis of [`QueryScope`] reads empty as "no restriction".
    #[test]
    fn scope_must_be_an_object() {
        for malformed in [
            serde_json::json!("sales"),
            serde_json::json!(7),
            serde_json::json!(["sales"]),
            serde_json::json!(true),
        ] {
            let body = serde_json::json!({ "scope": malformed });
            assert!(
                parse_scope(&body).is_err(),
                "{malformed} must not widen the query to every world and facet"
            );
        }
        // Absent and null still mean the default scope, which CA-02 documents.
        assert_eq!(
            parse_scope(&serde_json::json!({})).expect("absent scope"),
            QueryScope::default()
        );
        assert_eq!(
            parse_scope(&serde_json::json!({ "scope": Value::Null })).expect("null scope"),
            QueryScope::default()
        );
    }
}
