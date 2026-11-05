//! Campaign record types, lifecycle operations, and vault storage.

use crate::ports::EntityStoreRead;
use serde_json::Value;

use crate::edge::EdgeActorClass;
use crate::gate::{
    ExternalEffectGateInput, ExternalEffectPolicyRisk, GateActor, GateProvenanceHandles,
};
use crate::llm::decision::{
    AnswerContract, AskRole, AskTo, DecisionAnswer, DecisionAsk, DecisionRung, HolderKind,
    HumanAskReason, HumanDecisionRequest, ProviderPin, catalogue::CAMPAIGN_COMPLAINT_PAUSE,
};

use super::codec_json::campaign_record_to_json;
use super::parse::invalid;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::campaign::presets::{
    SnoozePolicyData, default_reply_snooze_policy, validate_snooze_policy,
};
use crate::campaign::{CAMPAIGN_SHORT_ID_PREFIX, CRM_PACK_ID};
use crate::error::{Error, Result};
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};

pub use crate::memory::campaign_records::CAMPAIGN_SCHEMA_VERSION;
pub use crate::memory::campaign_records::CampaignDefinition;
pub use crate::memory::campaign_records::CampaignLifecycle;
pub use crate::memory::campaign_records::CampaignRecord;
pub use crate::memory::campaign_records::CreateCampaignRequest;
pub use crate::memory::campaign_records::UpdateCampaignRequest;

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
    let reply_snooze_policy = match &request.reply_snooze_policy {
        Some(policy) => policy.clone(),
        None => default_reply_snooze_policy()?,
    };
    let definition = CampaignDefinition {
        schema_version: request.schema_version,
        owner_actor: authenticated_principal,
        name: request.name.clone(),
        definition_version: 1,
        lifecycle: CampaignLifecycle::Draft,
        reply_snooze_policy,
    };
    validate_campaign_definition(&definition)?;
    let record = CampaignRecord {
        campaign_ref: vault.store.clock.entity_id()?,
        definition,
        created_at: now,
        updated_at: now,
    };
    let kind = campaign_type_byte(vault)?;
    vault.with_write_txn_grouped(|wtxn| store_campaign_in_txn(vault, wtxn, &record, kind))?;
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
    vault.with_write_txn_grouped(|wtxn| {
        let mut record =
            owned_campaign_in_txn(vault, wtxn, authenticated_principal, campaign_ref, kind)?;
        require_expected_campaign_version(&record, request.expected_definition_version)?;
        if record.definition.lifecycle == CampaignLifecycle::Archived {
            return Err(invalid("an archived campaign is read-only"));
        }
        let definition = CampaignDefinition {
            schema_version: record.definition.schema_version,
            owner_actor: record.definition.owner_actor,
            name: request.name.clone(),
            definition_version: next_campaign_version(record.definition.definition_version)?,
            lifecycle: record.definition.lifecycle,
            reply_snooze_policy: request
                .reply_snooze_policy
                .clone()
                .unwrap_or_else(|| record.definition.reply_snooze_policy.clone()),
        };
        validate_campaign_definition(&definition)?;
        record.definition = definition;
        record.updated_at = now;
        store_campaign_in_txn(vault, wtxn, &record, kind)?;
        Ok(record)
    })
}

/// Launches a Draft campaign, or resumes a Paused one, under its owner's
/// actor class. A person who owns the campaign always can. An agent needs a
/// live Grant naming `launch` in this campaign's brief. Moved programs bump
/// their definition versions, so callers re-read them after this transition.
///
/// # Errors
///
/// [`Error::EntityNotFound`] when the campaign is absent or owned by another
/// principal, [`Error::ConcurrentWrite`] when the expected version is stale,
/// and [`Error::InvalidConfig`] when an agent has no covering launch Grant or
/// the campaign is Archived.
pub fn launch_campaign(
    vault: &Vault,
    authenticated_principal: EntityId,
    actor_class: EdgeActorClass,
    campaign_ref: EntityId,
    expected_definition_version: u64,
    now: u64,
) -> Result<CampaignRecord> {
    let kind = campaign_type_byte(vault)?;
    vault.with_write_txn_grouped(|wtxn| {
        let mut record =
            owned_campaign_in_txn(vault, wtxn, authenticated_principal, campaign_ref, kind)?;
        require_expected_campaign_version(&record, expected_definition_version)?;
        match actor_class {
            EdgeActorClass::Human => {}
            EdgeActorClass::Agent => {
                let effect = ExternalEffectGateInput {
                    actor: GateActor {
                        actor_class: actor_class.gate_actor_class().to_owned(),
                        actor_ref: Some(authenticated_principal.to_hex()),
                        delegation_grant_ref: None,
                    },
                    provenance: GateProvenanceHandles {
                        actor_entity_ref: Some(authenticated_principal),
                        ..GateProvenanceHandles::default()
                    },
                    verb: "launch".to_owned(),
                    channel: "campaign".to_owned(),
                    channel_identity_ref: None,
                    counterparty: None,
                    brief_ref: Some(campaign_ref.to_hex()),
                    send_ref: None,
                    standing_grant_ref: None,
                    scoped_mcp_call: None,
                    counterparty_first_touch: None,
                    counterparty_opted_out: false,
                    counterparty_opt_out_receipt_reason: None,
                    has_opted_in: false,
                    has_permission: false,
                    policy_risk: ExternalEffectPolicyRisk::Normal,
                    send_autonomy: None,
                };
                let policy = crate::gate::resolve_policy_manifest(&vault.store, wtxn)?;
                if crate::gate::live_grant_covering_effect_in_txn(
                    &vault.store,
                    wtxn,
                    &effect,
                    &policy,
                )?
                .is_none()
                {
                    return Err(invalid(
                        "campaign launch requires a grant naming campaign launch",
                    ));
                }
            }
            EdgeActorClass::System => {
                return Err(invalid("campaign launch requires a person or an agent"));
            }
        }
        match record.definition.lifecycle {
            CampaignLifecycle::Active => return Ok(record),
            CampaignLifecycle::Draft | CampaignLifecycle::Paused => {}
            CampaignLifecycle::Archived => {
                return Err(invalid("an archived campaign cannot launch"));
            }
        }
        record.definition.definition_version =
            next_campaign_version(record.definition.definition_version)?;
        record.definition.lifecycle = CampaignLifecycle::Active;
        record.updated_at = now;
        store_campaign_in_txn(vault, wtxn, &record, kind)?;
        crate::campaign::enrollment::transition_campaign_programs_in_txn(
            vault,
            wtxn,
            campaign_ref,
            CampaignLifecycle::Active,
            now,
        )?;
        Ok(record)
    })
}

/// The queue identity for complaint-pause questions. Its model string also
/// keeps unrelated decision asks out of the resume hook below.
pub(crate) const CAMPAIGN_COMPLAINT_PAUSE_QUEUE: &str = "campaign.complaint_pause";
const CAMPAIGN_COMPLAINT_PAUSE_QUEUE_VERSION: &str = "1";

fn complaint_pause_request(
    record: &CampaignRecord,
    identity_ref: EntityId,
    evidence_ref: EntityId,
    complaint_rate: f64,
    threshold_ppm: u32,
) -> Result<(HumanDecisionRequest, Value)> {
    let campaign_ref = record.campaign_ref;
    let campaign_hex = campaign_ref.to_hex();
    let observed_ppm = (complaint_rate * 1_000_000.0).round() as u32;
    // Fixed wording and stable evidence make repeated webhooks one ask. The
    // first ask keeps its rate snapshot; later observations never change the key.
    let question = CAMPAIGN_COMPLAINT_PAUSE.question(
        &[campaign_hex.as_bytes()],
        "This campaign reached its complaint threshold. Resume it?".to_owned(),
        AnswerContract::Noul,
    )?;
    let state = serde_json::json!({
        "campaign_ref": campaign_hex,
        "identity_ref": identity_ref.to_hex(),
        "evidence_ref": evidence_ref.to_hex(),
        "complaint_rate_ppm": observed_ppm,
        "threshold_ppm": threshold_ppm,
    });
    let request = HumanDecisionRequest {
        question,
        principal: record.definition.owner_actor,
        evidence: vec![campaign_ref, identity_ref],
        reason: HumanAskReason::OwnerSelected,
        prior: None,
        prior_provider: None,
        queue_pin: ProviderPin {
            rung: DecisionRung::Human,
            model: CAMPAIGN_COMPLAINT_PAUSE_QUEUE.to_owned(),
            version: CAMPAIGN_COMPLAINT_PAUSE_QUEUE_VERSION.to_owned(),
        },
        to: AskTo::owner(),
        correlation: Some(campaign_ref),
    };
    Ok((request, state))
}

/// Pauses the Active campaign named by a webhook when its post-signal complaint
/// rate reaches the active CRM/compliance pack's dial, and queues the one owner
/// question in the same write. A Paused campaign keeps its existing open ask's
/// sequence without another version bump; an erased answer permits a fresh ask.
/// Programs moved by this transition bump their own definition versions.
/// Draft, Archived and unknown campaigns do nothing. Other health caps stay unchanged.
pub(crate) fn project_campaign_complaint_pause_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    campaign_ref: Option<EntityId>,
    identity_ref: EntityId,
    evidence_ref: EntityId,
    complaint_rate: f64,
) -> Result<Option<u64>> {
    let Some(campaign_ref) = campaign_ref else {
        return Ok(None);
    };
    let kind = campaign_type_byte(vault)?;
    let Some(mut record) = load_campaign_in_txn(vault, wtxn, campaign_ref, kind)? else {
        return Ok(None);
    };
    if matches!(
        record.definition.lifecycle,
        CampaignLifecycle::Draft | CampaignLifecycle::Archived
    ) {
        return Ok(None);
    }
    let threshold_ppm = crate::campaign::compliance::campaign_complaint_pause_threshold_ppm_in_txn(
        &vault.store,
        wtxn,
    )?;
    let (request, state) = complaint_pause_request(
        &record,
        identity_ref,
        evidence_ref,
        complaint_rate,
        threshold_ppm,
    )?;
    if record.definition.lifecycle == CampaignLifecycle::Paused {
        let Some(prior) = vault.decision_ask_for_in_txn(
            wtxn,
            &request.question,
            request.principal,
            &request.evidence,
            &request.to,
            request.correlation,
        )?
        else {
            return Ok(None);
        };
        if prior.is_open() {
            return Ok(Some(prior.seq));
        }
        if prior
            .answer
            .as_ref()
            .is_some_and(|answer| answer.by.id().is_none())
        {
            return Ok(Some(vault.queue_decision_ask_in_txn(
                wtxn,
                &request,
                Some(&state),
            )?));
        }
        return Ok(None);
    }
    if complaint_rate < threshold_ppm as f64 / 1_000_000.0 {
        return Ok(None);
    }
    record.definition.definition_version =
        next_campaign_version(record.definition.definition_version)?;
    record.definition.lifecycle = CampaignLifecycle::Paused;
    record.updated_at = vault.store.clock.now_recorded_at();
    store_campaign_in_txn(vault, wtxn, &record, kind)?;
    crate::campaign::enrollment::transition_campaign_programs_in_txn(
        vault,
        wtxn,
        campaign_ref,
        CampaignLifecycle::Paused,
        record.updated_at,
    )?;
    let ask_seq = vault.queue_decision_ask_in_txn(wtxn, &request, Some(&state))?;
    Ok(Some(ask_seq))
}

/// Applies an answered complaint-pause question in the answer's own write:
/// a live owner person's yes resumes that Paused campaign; no leaves it paused.
/// Every other answerer, question family and lifecycle state is untouched.
/// Programs moved by the resume bump their own definition versions.
pub(crate) fn apply_campaign_complaint_answer_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    ask: &DecisionAsk,
) -> Result<()> {
    if ask.queue_pin.model != CAMPAIGN_COMPLAINT_PAUSE_QUEUE {
        return Ok(());
    }
    let Some(campaign_ref) = ask.correlation else {
        return Ok(());
    };
    let Some(answer) = &ask.answer else {
        return Ok(());
    };
    if answer.by.id().is_none()
        || answer.role != AskRole::Owner
        || answer.kind != HolderKind::Person
        || !matches!(&answer.answer, DecisionAnswer::Noul(true))
    {
        return Ok(());
    }
    let kind = campaign_type_byte(vault)?;
    let Some(mut record) = load_campaign_in_txn(vault, wtxn, campaign_ref, kind)? else {
        return Ok(());
    };
    if record.definition.lifecycle != CampaignLifecycle::Paused {
        return Ok(());
    }
    record.definition.definition_version =
        next_campaign_version(record.definition.definition_version)?;
    record.definition.lifecycle = CampaignLifecycle::Active;
    record.updated_at = answer.answered_at;
    store_campaign_in_txn(vault, wtxn, &record, kind)?;
    crate::campaign::enrollment::transition_campaign_programs_in_txn(
        vault,
        wtxn,
        campaign_ref,
        CampaignLifecycle::Active,
        answer.answered_at,
    )
}

/// Archives a campaign and its authored programs. A lifecycle transition,
/// never a delete: the records stay readable, the cohort's `campaign.member`
/// claims keep resolving, and moved programs bump their definition versions.
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
    vault.with_write_txn_grouped(|wtxn| {
        let mut record =
            owned_campaign_in_txn(vault, wtxn, authenticated_principal, campaign_ref, kind)?;
        require_expected_campaign_version(&record, expected_definition_version)?;
        if record.definition.lifecycle == CampaignLifecycle::Archived {
            return Err(invalid("an archived campaign cannot archive again"));
        }
        record.definition.definition_version =
            next_campaign_version(record.definition.definition_version)?;
        record.definition.lifecycle = CampaignLifecycle::Archived;
        record.updated_at = now;
        store_campaign_in_txn(vault, wtxn, &record, kind)?;
        crate::campaign::enrollment::transition_campaign_programs_in_txn(
            vault,
            wtxn,
            campaign_ref,
            CampaignLifecycle::Archived,
            now,
        )?;
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
    if definition.name.chars().any(char::is_control) {
        return Err(invalid("campaign name must not contain control characters"));
    }
    validate_snooze_policy(&definition.reply_snooze_policy)
}

/// Loads a campaign the principal owns THROUGH the caller's transaction, or
/// reports it as absent. Ownership is part of the read, not a post-filter.
pub(crate) fn owned_campaign_in_txn(
    vault: &Vault,
    wtxn: &heed::RoTxn<'_>,
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
pub(crate) fn campaign_type_byte(vault: &Vault) -> Result<u8> {
    registered_campaign_type_byte(vault)
        .ok_or_else(|| invalid("campaign kind is not registered in this vault"))
}

fn registered_campaign_type_byte(vault: &Vault) -> Option<u8> {
    vault
        .structural_kind_registrations()
        .into_iter()
        .find(|registration| {
            registration.short_id_prefix == CAMPAIGN_SHORT_ID_PREFIX
                && registration.pack == CRM_PACK_ID
        })
        .map(|registration| registration.type_byte)
}

fn load_campaign(vault: &Vault, campaign_ref: EntityId) -> Result<Option<CampaignRecord>> {
    let kind = campaign_type_byte(vault)?;
    let rtxn = vault.store.env.read_txn()?;
    load_campaign_in_txn(vault, &rtxn, campaign_ref, kind)
}

/// The stored campaign at `campaign_ref`, whoever owns it, or `None` when the
/// vault holds none there or registers no campaign kind at all. An engine read
/// for engine policy, never a caller's read.
pub(crate) fn load_registered_campaign(
    vault: &Vault,
    campaign_ref: EntityId,
) -> Result<Option<CampaignRecord>> {
    let Some(kind) = registered_campaign_type_byte(vault) else {
        return Ok(None);
    };
    let rtxn = vault.store.env.read_txn()?;
    load_campaign_in_txn(vault, &rtxn, campaign_ref, kind)
}

pub(crate) fn load_campaign_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    campaign_ref: EntityId,
    kind: u8,
) -> Result<Option<CampaignRecord>> {
    let Some(raw) = vault
        .store
        .port_entity_record(txn, &campaign_ref)?
        .map(|row| row.encode())
    else {
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
            row_version: None,
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
            reply_snooze_policy: definition
                .get("reply_snooze_policy")
                .cloned()
                .and_then(|policy| serde_json::from_value(policy).ok())
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
