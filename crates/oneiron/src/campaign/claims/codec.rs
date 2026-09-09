//! MessagePack codecs, write-door validator, and map/key/token toolkit.

use rmpv::Value;

use crate::claim::{ClaimBody, ClaimSubject};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::types::*;

pub(super) const KEY_CAMPAIGN: &str = "campaign";

pub(super) const KEY_STATE: &str = "state";

pub(super) const KEY_CHANNELS: &str = "channels";

pub(super) const KEY_DERIVATION: &str = "derivation";

pub(super) const KEY_KIND: &str = "kind";

pub(super) const KEY_UNTIL: &str = "until";

pub(super) const KEY_NEW_TRIGGER: &str = "new_trigger";

pub(super) const KEY_CHANNEL: &str = "channel";

pub(super) const KEY_BASIS_EVIDENCE: &str = "basis_evidence";

pub(super) const KEY_SENDER_REF: &str = "sender_ref";

pub(super) const KEY_SOURCE_QUERY: &str = "source_query";

pub(super) const KEY_EVIDENCE_HASH: &str = "evidence_hash";

pub(super) const KEY_EPOCH: &str = "epoch";

pub(super) const KEY_ICP_SCOPE: &str = "icp_scope";

pub(super) const KEY_VERDICT: &str = "verdict";

pub(super) const KEY_CAMPAIGN_REF: &str = "campaign_ref";

pub(super) const KEY_STAGE: &str = "stage";

pub(super) const KEY_EVIDENCE_CLASS: &str = "evidence_class";

pub(super) const KEY_EVIDENCE_REFS: &str = "evidence_refs";

pub(super) const KEY_BASIS: &str = "basis";

pub(super) const KEY_RECORDED_AT: &str = "recorded_at";

pub(super) const KEY_SCOPE: &str = "scope";

pub(super) const KEY_BOUNCE: &str = "bounce";

pub(super) const KEY_OCCURRED_AT: &str = "occurred_at";

pub(super) const KEY_JURISDICTION: &str = "jurisdiction";

pub(super) const KEY_OBSERVED_AT: &str = "observed_at";

/// Upper bound for every bounded text field in these families.
const MAX_TEXT_BYTES: usize = 512;

/// Cohort derivation hashes are SHA-256 sized.
pub(super) const EVIDENCE_HASH_LEN: usize = 32;

/// Validates one CRM-pack claim subject and value shape.
///
/// Structural only: campaign/ICP/evidence references are shape-checked, never
/// resolved. Every value is an exact key set with no extras and no back-compat
/// defaults — these families are greenfield, so there is no legacy shape to
/// admit.
pub(crate) fn validate_campaign_pack_claim_structure(body: &ClaimBody) -> Result<()> {
    if !matches!(body.subject, ClaimSubject::Entity(_)) {
        return Err(invalid_claim(
            "campaign pack claim subject must be an entity",
        ));
    }
    match body.predicate.as_str() {
        PREDICATE_CAMPAIGN_MEMBER => decode_campaign_member_value(&body.value).map(|_| ()),
        PREDICATE_CRM_FIT => decode_crm_fit_value(&body.value).map(|_| ()),
        PREDICATE_CRM_STAGE => decode_crm_stage_value(&body.value).map(|_| ()),
        PREDICATE_COMM_DO_NOT_CONTACT => decode_do_not_contact_value(&body.value).map(|_| ()),
        PREDICATE_COMM_BOUNCE => decode_comm_bounce_value(&body.value).map(|_| ()),
        PREDICATE_COMM_JURISDICTION => {
            // Provenance for a projector-written external fact is not optional:
            // a jurisdiction with no evidence cannot be re-derived or disputed.
            if body.evidence.is_none() {
                return Err(invalid_claim("comm.jurisdiction requires claim evidence"));
            }
            decode_comm_jurisdiction_value(&body.value).map(|_| ())
        }
        _ => Err(invalid_claim("unknown campaign pack claim predicate")),
    }
}

/// Encodes a [`CampaignMemberValue`] into the exact wire map
/// `decode_campaign_member_value` accepts.
///
/// The CA-owned write half of the codec. ONE-1773's saved-query writer composes
/// its membership value from the typed struct through this door instead of
/// re-spelling this module's private MessagePack key literals — a second
/// spelling of one schema is drift with a delay fuse.
///
/// Deliberately infallible. Shape law (a paused row needs a wake condition, a
/// membership needs at least one channel) is enforced once, at the write door,
/// by `validate_campaign_pack_claim_structure`; re-checking it here would be
/// a second authority that can disagree with the first.
#[must_use]
pub fn encode_campaign_member_value(value: &CampaignMemberValue) -> Value {
    let mut entries = vec![
        (Value::from(KEY_CAMPAIGN), entity_ref_value(&value.campaign)),
        (Value::from(KEY_STATE), encode_member_state(value.state)),
        (
            Value::from(KEY_CHANNELS),
            Value::Array(value.channels.iter().map(encode_member_channel).collect()),
        ),
    ];
    if let Some(derivation) = &value.derivation {
        entries.push((
            Value::from(KEY_DERIVATION),
            encode_member_derivation(derivation),
        ));
    }
    Value::Map(entries)
}

fn encode_member_state(state: CampaignMemberState) -> Value {
    let mut entries = vec![(Value::from(KEY_KIND), Value::from(state.as_str()))];
    if let CampaignMemberState::Paused { until, new_trigger } = state {
        if let Some(until) = until {
            entries.push((Value::from(KEY_UNTIL), Value::from(until)));
        }
        if let Some(new_trigger) = new_trigger {
            entries.push((Value::from(KEY_NEW_TRIGGER), Value::from(new_trigger)));
        }
    }
    Value::Map(entries)
}

fn encode_member_channel(channel: &CampaignMemberChannel) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_CHANNEL),
            Value::from(channel.channel.as_str()),
        ),
        (
            Value::from(KEY_BASIS_EVIDENCE),
            entity_ref_value(&channel.basis_evidence),
        ),
        (
            Value::from(KEY_SENDER_REF),
            entity_ref_value(&channel.sender_ref),
        ),
    ])
}

fn encode_member_derivation(derivation: &CampaignMemberDerivation) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_SOURCE_QUERY),
            entity_ref_value(&derivation.source_query),
        ),
        (
            Value::from(KEY_EVIDENCE_HASH),
            Value::Binary(derivation.evidence_hash.to_vec()),
        ),
        (Value::from(KEY_EPOCH), Value::from(derivation.epoch)),
    ])
}

/// Decodes a `campaign.member` value.
pub(crate) fn decode_campaign_member_value(value: &Value) -> Result<CampaignMemberValue> {
    let entries = value_map(value)?;
    validate_keys(
        entries,
        &[KEY_CAMPAIGN, KEY_STATE, KEY_CHANNELS, KEY_DERIVATION],
        &[KEY_CAMPAIGN, KEY_STATE, KEY_CHANNELS],
    )?;
    Ok(CampaignMemberValue {
        campaign: required_entity_ref(entries, KEY_CAMPAIGN)?,
        state: decode_member_state(required_value(entries, KEY_STATE)?)?,
        channels: decode_member_channels(required_value(entries, KEY_CHANNELS)?)?,
        derivation: optional_value(entries, KEY_DERIVATION)?
            .map(decode_member_derivation)
            .transpose()?,
    })
}

fn decode_member_state(value: &Value) -> Result<CampaignMemberState> {
    let entries = value_map(value)?;
    match required_string(entries, KEY_KIND)? {
        "enrolled" => {
            validate_keys(entries, &[KEY_KIND], &[KEY_KIND])?;
            Ok(CampaignMemberState::Enrolled)
        }
        "exited" => {
            validate_keys(entries, &[KEY_KIND], &[KEY_KIND])?;
            Ok(CampaignMemberState::Exited)
        }
        "suppressed" => {
            validate_keys(entries, &[KEY_KIND], &[KEY_KIND])?;
            Ok(CampaignMemberState::Suppressed)
        }
        "paused" => {
            validate_keys(
                entries,
                &[KEY_KIND, KEY_UNTIL, KEY_NEW_TRIGGER],
                &[KEY_KIND],
            )?;
            let until = optional_value(entries, KEY_UNTIL)?
                .map(|value| {
                    value
                        .as_u64()
                        .ok_or_else(|| invalid_claim("campaign.member until must be an integer"))
                })
                .transpose()?;
            let new_trigger = optional_value(entries, KEY_NEW_TRIGGER)?
                .map(|value| {
                    value.as_bool().ok_or_else(|| {
                        invalid_claim("campaign.member new_trigger must be a boolean")
                    })
                })
                .transpose()?;
            // A paused row with neither wake condition never wakes: it is an
            // exit that still counts as membership.
            if until.is_none() && new_trigger.is_none() {
                return Err(invalid_claim(
                    "campaign.member paused requires until or new_trigger",
                ));
            }
            Ok(CampaignMemberState::Paused { until, new_trigger })
        }
        _ => Err(invalid_claim("campaign.member state kind is invalid")),
    }
}

fn decode_member_channels(value: &Value) -> Result<Vec<CampaignMemberChannel>> {
    let Value::Array(rows) = value else {
        return Err(invalid_claim("campaign.member channels must be an array"));
    };
    // A membership with no channel is a cohort row nothing can act on.
    if rows.is_empty() {
        return Err(invalid_claim("campaign.member channels must be non-empty"));
    }
    let mut channels = Vec::with_capacity(rows.len());
    for row in rows {
        let entries = value_map(row)?;
        let keys = [KEY_CHANNEL, KEY_BASIS_EVIDENCE, KEY_SENDER_REF];
        validate_keys(entries, &keys, &keys)?;
        let channel = required_string(entries, KEY_CHANNEL)?;
        validate_channel(channel)?;
        // The collection is a SET: two rows for one channel would make the
        // consent basis and the sticky sender ambiguous.
        if channels
            .iter()
            .any(|existing: &CampaignMemberChannel| existing.channel == channel)
        {
            return Err(invalid_claim("campaign.member channels must be unique"));
        }
        channels.push(CampaignMemberChannel {
            channel: channel.to_owned(),
            basis_evidence: required_entity_ref(entries, KEY_BASIS_EVIDENCE)?,
            sender_ref: required_entity_ref(entries, KEY_SENDER_REF)?,
        });
    }
    Ok(channels)
}

fn decode_member_derivation(value: &Value) -> Result<CampaignMemberDerivation> {
    let entries = value_map(value)?;
    let keys = [KEY_SOURCE_QUERY, KEY_EVIDENCE_HASH, KEY_EPOCH];
    validate_keys(entries, &keys, &keys)?;
    Ok(CampaignMemberDerivation {
        source_query: required_entity_ref(entries, KEY_SOURCE_QUERY)?,
        evidence_hash: required_evidence_hash(entries, KEY_EVIDENCE_HASH)?,
        epoch: required_u64(entries, KEY_EPOCH)?,
    })
}

/// Decodes a `crm.fit` value.
pub(crate) fn decode_crm_fit_value(value: &Value) -> Result<CrmFitValue> {
    let entries = value_map(value)?;
    let keys = [KEY_ICP_SCOPE, KEY_VERDICT];
    validate_keys(entries, &keys, &keys)?;
    Ok(CrmFitValue {
        icp_scope: required_entity_ref(entries, KEY_ICP_SCOPE)?,
        verdict: CrmFitVerdict::parse(required_string(entries, KEY_VERDICT)?)
            .ok_or_else(|| invalid_claim("crm.fit verdict is invalid"))?,
    })
}

/// Encodes a [`CrmStageValue`] into the exact wire map
/// `decode_crm_stage_value` accepts.
///
/// The CA-owned write half of the codec, and the only way ONE-1775's stage
/// projector builds a `crm.stage` value: `CrmStageValue` is not serde-derived
/// ([`EntityId`] has no serde impl), so without this door a stage writer would
/// have to re-spell this module's private key literals and the canonical-hex
/// entity-reference rule.
///
/// Deliberately infallible, for the same reason as
/// [`encode_campaign_member_value`]: the non-empty-evidence law lives at the
/// write door, not in a second place that can drift from it.
#[must_use]
pub fn encode_crm_stage_value(value: &CrmStageValue) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_CAMPAIGN_REF),
            entity_ref_value(&value.campaign_ref),
        ),
        (Value::from(KEY_STAGE), Value::from(value.stage.0.as_str())),
        (
            Value::from(KEY_EVIDENCE_CLASS),
            Value::from(value.evidence_class.as_str()),
        ),
        (
            Value::from(KEY_EVIDENCE_REFS),
            Value::Array(value.evidence_refs.iter().map(entity_ref_value).collect()),
        ),
        (Value::from(KEY_BASIS), Value::from(value.basis.as_str())),
        (Value::from(KEY_RECORDED_AT), Value::from(value.recorded_at)),
    ])
}

/// Decodes a `crm.stage` value into [`CrmStageValue`], the exact inverse of
/// [`encode_crm_stage_value`].
///
/// The CA-owned read half of the codec, public for the same reason its encoder
/// is: `CrmStageValue` is not serde-derived ([`EntityId`] has no serde impl),
/// so a caller holding a `crm.stage` body from `Vault::get_claim` would
/// otherwise have to re-spell this module's private key literals and the
/// canonical-hex entity-reference rule to read the stage, its basis, or the
/// claims it cites.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] for a value that is not a map, an unknown,
/// missing or duplicated key, a stage token past the bounded-text limit, an
/// `evidence_refs` that is not a non-empty array of canonical-hex entity
/// references, an unparsable `evidence_class` or `basis`, or a
/// `recorded_at` that is not an unsigned integer.
pub fn decode_crm_stage_value(value: &Value) -> Result<CrmStageValue> {
    let entries = value_map(value)?;
    let keys = [
        KEY_CAMPAIGN_REF,
        KEY_STAGE,
        KEY_EVIDENCE_CLASS,
        KEY_EVIDENCE_REFS,
        KEY_BASIS,
        KEY_RECORDED_AT,
    ];
    validate_keys(entries, &keys, &keys)?;
    let stage = required_string(entries, KEY_STAGE)?;
    validate_bounded_text(stage)?;
    let Value::Array(refs) = required_value(entries, KEY_EVIDENCE_REFS)? else {
        return Err(invalid_claim("crm.stage evidence_refs must be an array"));
    };
    // A stage transition with no evidence is a guess wearing a fact's clothes.
    if refs.is_empty() {
        return Err(invalid_claim("crm.stage evidence_refs must be non-empty"));
    }
    let evidence_refs = refs
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| invalid_claim("crm.stage evidence ref must be a string"))
                .and_then(parse_entity_ref)
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(CrmStageValue {
        campaign_ref: required_entity_ref(entries, KEY_CAMPAIGN_REF)?,
        stage: StageKey(stage.to_owned()),
        evidence_class: StageEvidenceClass::parse(required_string(entries, KEY_EVIDENCE_CLASS)?)
            .ok_or_else(|| invalid_claim("crm.stage evidence_class is invalid"))?,
        evidence_refs,
        basis: EvidenceBasis::parse(required_string(entries, KEY_BASIS)?)
            .ok_or_else(|| invalid_claim("crm.stage basis is invalid"))?,
        recorded_at: required_u64(entries, KEY_RECORDED_AT)?,
    })
}

/// Encodes a [`CommDoNotContactValue`] into the exact wire map
/// `decode_do_not_contact_value` accepts.
///
/// The CA-owned write half of the codec, for the same reason
/// [`encode_campaign_member_value`] exists: ONE-1776's suppression writer would
/// otherwise re-spell this module's private key literals, and a second spelling
/// of one schema is drift with a delay fuse. `channel: None` ELIDES the key
/// rather than writing a null — absent is what "every channel" means here.
///
/// Deliberately infallible: normalization law lives at the write door in
/// `validate_campaign_pack_claim_structure`, not in a second authority.
#[must_use]
pub fn encode_do_not_contact_value(value: &CommDoNotContactValue) -> Value {
    let mut entries = Vec::with_capacity(2);
    if let Some(channel) = &value.channel {
        entries.push((Value::from(KEY_CHANNEL), Value::from(channel.as_str())));
    }
    entries.push((Value::from(KEY_SCOPE), Value::from(value.scope.as_str())));
    Value::Map(entries)
}

/// Decodes a `comm.do_not_contact` value.
pub(crate) fn decode_do_not_contact_value(value: &Value) -> Result<CommDoNotContactValue> {
    let entries = value_map(value)?;
    validate_keys(entries, &[KEY_CHANNEL, KEY_SCOPE], &[KEY_SCOPE])?;
    let channel = optional_string(entries, KEY_CHANNEL)?;
    if let Some(channel) = channel {
        validate_channel(channel)?;
    }
    let scope = required_string(entries, KEY_SCOPE)?;
    validate_scope(scope)?;
    Ok(CommDoNotContactValue {
        channel: channel.map(str::to_owned),
        scope: scope.to_owned(),
    })
}

/// Encodes a [`CommBounceValue`] into the exact wire map
/// `decode_comm_bounce_value` accepts.
///
/// The CA-owned write half of the codec. ONE-1776's webhook projector composes
/// the bounce fact through this door instead of re-spelling the key literals.
#[must_use]
pub fn encode_comm_bounce_value(value: &CommBounceValue) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_CHANNEL),
            Value::from(value.channel.as_str()),
        ),
        (Value::from(KEY_BOUNCE), Value::from(value.bounce.as_str())),
        (
            Value::from(KEY_SENDER_REF),
            entity_ref_value(&value.sender_ref),
        ),
        (Value::from(KEY_OCCURRED_AT), Value::from(value.occurred_at)),
    ])
}

/// Decodes a `comm.bounce` value.
pub(crate) fn decode_comm_bounce_value(value: &Value) -> Result<CommBounceValue> {
    let entries = value_map(value)?;
    let keys = [KEY_CHANNEL, KEY_BOUNCE, KEY_SENDER_REF, KEY_OCCURRED_AT];
    validate_keys(entries, &keys, &keys)?;
    let channel = required_string(entries, KEY_CHANNEL)?;
    validate_channel(channel)?;
    Ok(CommBounceValue {
        channel: channel.to_owned(),
        bounce: BounceKind::parse(required_string(entries, KEY_BOUNCE)?)
            .ok_or_else(|| invalid_claim("comm.bounce bounce is invalid"))?,
        sender_ref: required_entity_ref(entries, KEY_SENDER_REF)?,
        occurred_at: required_u64(entries, KEY_OCCURRED_AT)?,
    })
}

/// Decodes a `comm.jurisdiction` value.
pub(crate) fn decode_comm_jurisdiction_value(value: &Value) -> Result<CommJurisdictionValue> {
    let entries = value_map(value)?;
    let keys = [KEY_JURISDICTION, KEY_OBSERVED_AT];
    validate_keys(entries, &keys, &keys)?;
    let jurisdiction = required_string(entries, KEY_JURISDICTION)?;
    validate_bounded_text(jurisdiction)?;
    Ok(CommJurisdictionValue {
        jurisdiction: jurisdiction.to_owned(),
        observed_at: required_u64(entries, KEY_OBSERVED_AT)?,
    })
}

fn value_map(value: &Value) -> Result<&[(Value, Value)]> {
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(invalid_claim("campaign pack claim value must be a map")),
    }
}

fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    let mut matches = entries
        .iter()
        .filter_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value));
    let value = matches
        .next()
        .ok_or_else(|| invalid_claim("campaign pack value missing required key"))?;
    if matches.next().is_some() {
        return Err(invalid_claim("campaign pack value contains duplicate key"));
    }
    Ok(value)
}

fn optional_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<Option<&'a Value>> {
    let mut matches = entries
        .iter()
        .filter_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value));
    let value = matches.next();
    if matches.next().is_some() {
        return Err(invalid_claim("campaign pack value contains duplicate key"));
    }
    Ok(value)
}

fn required_string<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a str> {
    required_value(entries, key)?
        .as_str()
        .ok_or_else(|| invalid_claim("campaign pack value string invalid"))
}

fn optional_string<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<Option<&'a str>> {
    optional_value(entries, key)?
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| invalid_claim("campaign pack value string invalid"))
        })
        .transpose()
}

fn required_u64(entries: &[(Value, Value)], key: &str) -> Result<u64> {
    required_value(entries, key)?
        .as_u64()
        .ok_or_else(|| invalid_claim("campaign pack value integer invalid"))
}

fn required_entity_ref(entries: &[(Value, Value)], key: &str) -> Result<EntityId> {
    parse_entity_ref(required_string(entries, key)?)
}

/// The write counterpart of [`parse_entity_ref`]: canonical hex, the one wire
/// form an identity has.
fn entity_ref_value(id: &EntityId) -> Value {
    Value::from(id.to_hex())
}

fn parse_entity_ref(hex: &str) -> Result<EntityId> {
    let id = EntityId::from_hex(hex)
        .map_err(|_| invalid_claim("campaign pack entity reference invalid"))?;
    // Reject non-canonical spellings so one identity has one wire form.
    if id.to_hex() != hex {
        return Err(invalid_claim("campaign pack entity reference invalid"));
    }
    Ok(id)
}

fn required_evidence_hash(
    entries: &[(Value, Value)],
    key: &str,
) -> Result<[u8; EVIDENCE_HASH_LEN]> {
    let Value::Binary(bytes) = required_value(entries, key)? else {
        return Err(invalid_claim("campaign pack evidence_hash must be binary"));
    };
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_claim("campaign pack evidence_hash must be 32 bytes"))
}

/// Rejects extra keys, missing required keys, non-string keys, and duplicates.
///
/// `allowed` is the full key set; `required` is the subset that must be
/// present. These families are greenfield, so the two differ only where the
/// field is genuinely optional (`derivation`, paused wake fields, DNC channel).
fn validate_keys(entries: &[(Value, Value)], allowed: &[&str], required: &[&str]) -> Result<()> {
    if entries.len() > allowed.len() {
        return Err(invalid_claim("campaign pack value key set invalid"));
    }
    if entries
        .iter()
        .any(|(key, _)| key.as_str().is_none_or(|key| !allowed.contains(&key)))
    {
        return Err(invalid_claim("campaign pack value key set invalid"));
    }
    for key in required {
        required_value(entries, key)?;
    }
    Ok(())
}

/// Bounded, non-empty, control-character-free text.
fn validate_bounded_text(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES {
        return Err(invalid_claim("campaign pack text field length invalid"));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid_claim(
            "campaign pack text field has control characters",
        ));
    }
    Ok(())
}

/// Channel tokens are stored already-normalized, mirroring the `comm.*`
/// `channel_class` rule. Normalizing at the write door is what lets matching
/// compare bytes instead of guessing at equivalence.
fn validate_channel(value: &str) -> Result<()> {
    validate_bounded_text(value)?;
    if value != normalize_token(value) {
        return Err(invalid_claim("campaign pack channel must be normalized"));
    }
    Ok(())
}

/// Scope tokens follow the channel rule; [`DO_NOT_CONTACT_SCOPE_ALL`] is just
/// the wildcard member of the same normalized space.
fn validate_scope(value: &str) -> Result<()> {
    validate_bounded_text(value)?;
    if value != normalize_token(value) {
        return Err(invalid_claim("campaign pack scope must be normalized"));
    }
    Ok(())
}

/// Normalizes a channel or scope token to the one spelling these families
/// store.
///
/// Exported so a CA writer normalizes through the SAME rule the validator
/// enforces. A writer that re-spelled `trim().to_ascii_lowercase()` locally
/// would keep working until this rule changed, and then write tokens the write
/// door rejects.
#[must_use]
pub fn normalize_campaign_pack_token(value: &str) -> String {
    normalize_token(value)
}

pub(super) fn normalize_token(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

pub(super) fn invalid_claim(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}
