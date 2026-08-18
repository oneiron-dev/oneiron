//! Commitment claim substrate (CMT-1).
//!
//! Commitments are stored as typed `commitment.*` CLAIM entities. CMT-1 keeps
//! the obligation fact, strength tier, status, opaque schedule payload, and
//! birth provenance in one atomic bitemporal claim; schedule evaluation,
//! wakes, and projections are handled by later CMT tickets.

use std::sync::atomic::Ordering;

use rmpv::Value;

use crate::batch::{ApplyOpsGateMode, BatchOp, EntityMetadataHeader, apply_ops_with_gate_mode};
use crate::claim::{ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::temporal::TimeRange;
use crate::vault::Vault;
use crate::write_envelope::{ClaimCandidate, WriteEnvelope};

/// Current `commitment.record` value schema version.
pub const COMMITMENT_VALUE_SCHEMA_VERSION: u64 = 1;

/// Pinned `commitment.*` claim predicates for CMT-1.
pub const COMMITMENT_CLAIM_PREDICATES: [&str; 1] = [PREDICATE_COMMITMENT_RECORD];

/// The atomic commitment fact record.
pub const PREDICATE_COMMITMENT_RECORD: &str = "commitment.record";

/// Pinned top-level MessagePack key set for `commitment.record` values.
pub const COMMITMENT_VALUE_KEYS: [&str; 8] = [
    "schema_version",
    "obligor",
    "beneficiary",
    "content",
    "schedule",
    "strength",
    "status",
    "birth_provenance",
];

const KEY_SCHEMA_VERSION: &str = COMMITMENT_VALUE_KEYS[0];
const KEY_OBLIGOR: &str = COMMITMENT_VALUE_KEYS[1];
const KEY_BENEFICIARY: &str = COMMITMENT_VALUE_KEYS[2];
const KEY_CONTENT: &str = COMMITMENT_VALUE_KEYS[3];
const KEY_SCHEDULE: &str = COMMITMENT_VALUE_KEYS[4];
const KEY_STRENGTH: &str = COMMITMENT_VALUE_KEYS[5];
const KEY_STATUS: &str = COMMITMENT_VALUE_KEYS[6];
const KEY_BIRTH_PROVENANCE: &str = COMMITMENT_VALUE_KEYS[7];

const COMMITMENT_OBLIGOR_KEYS: [&str; 2] = ["kind", "entity_ref"];
const KEY_OBLIGOR_KIND: &str = COMMITMENT_OBLIGOR_KEYS[0];
const KEY_OBLIGOR_ENTITY_REF: &str = COMMITMENT_OBLIGOR_KEYS[1];

const COMMITMENT_CONTENT_KEYS: [&str; 2] = ["text", "payload_ref"];
const KEY_CONTENT_TEXT: &str = COMMITMENT_CONTENT_KEYS[0];
const KEY_CONTENT_PAYLOAD_REF: &str = COMMITMENT_CONTENT_KEYS[1];

const COMMITMENT_BIRTH_PROVENANCE_KEYS: [&str; 2] = ["kind", "reference"];
const KEY_BIRTH_KIND: &str = COMMITMENT_BIRTH_PROVENANCE_KEYS[0];
const KEY_BIRTH_REFERENCE: &str = COMMITMENT_BIRTH_PROVENANCE_KEYS[1];

const MAX_COMMITMENT_TEXT_BYTES: usize = 8 * 1024;
const MAX_COMMITMENT_PAYLOAD_REF_BYTES: usize = 1024;
const MAX_COMMITMENT_BIRTH_REFERENCE_BYTES: usize = 1024;

/// The class of actor that owes the commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CommitmentObligorKind {
    Owner,
    Agent,
    ThirdParty,
}

impl CommitmentObligorKind {
    /// Stable on-disk string for this obligor class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Agent => "agent",
            Self::ThirdParty => "third_party",
        }
    }

    /// Parses a pinned obligor class string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "owner" => Some(Self::Owner),
            "agent" => Some(Self::Agent),
            "third_party" => Some(Self::ThirdParty),
            _ => None,
        }
    }
}

/// Who owes the commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CommitmentObligor {
    pub kind: CommitmentObligorKind,
    pub entity_ref: EntityId,
}

impl CommitmentObligor {
    /// Creates an obligor reference.
    #[must_use]
    pub const fn new(kind: CommitmentObligorKind, entity_ref: EntityId) -> Self {
        Self { kind, entity_ref }
    }
}

/// What is promised.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CommitmentContent {
    pub text: String,
    pub payload_ref: Option<String>,
}

impl CommitmentContent {
    /// Creates text content with an optional host-local typed payload ref.
    pub fn new(text: impl Into<String>, payload_ref: Option<String>) -> Result<Self> {
        let content = Self {
            text: text.into(),
            payload_ref,
        };
        content.validate()?;
        Ok(content)
    }

    fn validate(&self) -> Result<()> {
        validate_non_empty_bounded(
            &self.text,
            MAX_COMMITMENT_TEXT_BYTES,
            "commitment content text must be non-empty and bounded",
        )?;
        if let Some(payload_ref) = &self.payload_ref {
            validate_non_empty_bounded(
                payload_ref,
                MAX_COMMITMENT_PAYLOAD_REF_BYTES,
                "commitment content payload_ref must be non-empty and bounded",
            )?;
        }
        Ok(())
    }
}

/// Commitment strength tier. The tier is the future wake dial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CommitmentStrength {
    StatedIntention,
    Decision,
    Commitment,
}

impl CommitmentStrength {
    /// Stable on-disk string for this tier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StatedIntention => "stated_intention",
            Self::Decision => "decision",
            Self::Commitment => "commitment",
        }
    }

    /// Parses a pinned strength tier.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "stated_intention" => Some(Self::StatedIntention),
            "decision" => Some(Self::Decision),
            "commitment" => Some(Self::Commitment),
            _ => None,
        }
    }

    /// Resolves extractor proposal vs explicit user override.
    ///
    /// Agent-owed commitments are always full `commitment` strength. For other
    /// obligors, an explicit user statement overrides the extractor proposal.
    #[must_use]
    pub const fn resolve(
        obligor_kind: CommitmentObligorKind,
        extractor_proposal: Self,
        explicit_user_override: Option<Self>,
    ) -> Self {
        if matches!(obligor_kind, CommitmentObligorKind::Agent) {
            Self::Commitment
        } else if let Some(user_override) = explicit_user_override {
            user_override
        } else {
            extractor_proposal
        }
    }
}

/// Commitment status. CMT-1 ships explicit fulfill/release/supersede verbs;
/// lapse storage is present for the later CMT lapse path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CommitmentStatus {
    Open,
    Fulfilled,
    Released,
    Lapsed,
    Superseded,
}

impl CommitmentStatus {
    /// Stable on-disk string for this status.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Fulfilled => "fulfilled",
            Self::Released => "released",
            Self::Lapsed => "lapsed",
            Self::Superseded => "superseded",
        }
    }

    /// Parses a pinned status string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "open" => Some(Self::Open),
            "fulfilled" => Some(Self::Fulfilled),
            "released" => Some(Self::Released),
            "lapsed" => Some(Self::Lapsed),
            "superseded" => Some(Self::Superseded),
            _ => None,
        }
    }

    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(self, Self::Open)
            && matches!(
                next,
                Self::Fulfilled | Self::Released | Self::Lapsed | Self::Superseded
            )
    }
}

/// Origin category for a commitment birth event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CommitmentBirthKind {
    RunTreeNode,
    Brief,
    SurfaceAction,
}

impl CommitmentBirthKind {
    /// Stable on-disk string for this birth category.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RunTreeNode => "run_tree_node",
            Self::Brief => "brief",
            Self::SurfaceAction => "surface_action",
        }
    }

    /// Parses a pinned birth category string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "run_tree_node" => Some(Self::RunTreeNode),
            "brief" => Some(Self::Brief),
            "surface_action" => Some(Self::SurfaceAction),
            _ => None,
        }
    }
}

/// Provenance for the moment that created the commitment fact.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CommitmentBirthProvenance {
    pub kind: CommitmentBirthKind,
    pub reference: String,
}

impl CommitmentBirthProvenance {
    /// Creates a birth provenance reference.
    pub fn new(kind: CommitmentBirthKind, reference: impl Into<String>) -> Result<Self> {
        let birth = Self {
            kind,
            reference: reference.into(),
        };
        birth.validate()?;
        Ok(birth)
    }

    fn validate(&self) -> Result<()> {
        validate_non_empty_bounded(
            &self.reference,
            MAX_COMMITMENT_BIRTH_REFERENCE_BYTES,
            "commitment birth provenance reference must be non-empty and bounded",
        )
    }
}

/// Decoded `commitment.record` value.
#[derive(Debug, Clone, PartialEq)]
pub struct CommitmentRecord {
    pub obligor: CommitmentObligor,
    pub beneficiary: EntityId,
    pub content: CommitmentContent,
    /// Opaque CMT schedule payload. CMT-1 stores and gates it, but does not
    /// parse or evaluate it.
    pub schedule: Value,
    pub strength: CommitmentStrength,
    pub status: CommitmentStatus,
    pub birth_provenance: CommitmentBirthProvenance,
}

impl CommitmentRecord {
    /// Creates a commitment record. Agent-owed records are normalized to full
    /// `commitment` strength before validation.
    pub fn new(
        obligor: CommitmentObligor,
        beneficiary: EntityId,
        content: CommitmentContent,
        schedule: Value,
        strength: CommitmentStrength,
        status: CommitmentStatus,
        birth_provenance: CommitmentBirthProvenance,
    ) -> Result<Self> {
        let strength = CommitmentStrength::resolve(obligor.kind, strength, None);
        let record = Self {
            obligor,
            beneficiary,
            content,
            schedule,
            strength,
            status,
            birth_provenance,
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates CMT-1 record invariants.
    pub fn validate(&self) -> Result<()> {
        self.content.validate()?;
        self.birth_provenance.validate()?;
        if matches!(self.schedule, Value::Nil) {
            return Err(Error::InvalidClaimBody(
                "commitment schedule payload must be present",
            ));
        }
        if self.obligor.kind == CommitmentObligorKind::Agent
            && self.strength != CommitmentStrength::Commitment
        {
            return Err(Error::InvalidClaimBody(
                "agent-owed commitments must have commitment strength",
            ));
        }
        Ok(())
    }
}

/// Returns whether `predicate` belongs to the commitment claim family.
#[must_use]
pub fn is_commitment_claim_predicate(predicate: &str) -> bool {
    COMMITMENT_CLAIM_PREDICATES.contains(&predicate)
}

/// Builds a typed `commitment.record` claim candidate for the obligor entity.
pub fn commitment_claim_candidate(record: &CommitmentRecord) -> Result<ClaimCandidate> {
    if record.status != CommitmentStatus::Open {
        return Err(Error::InvalidClaimBody(
            "commitment candidate must be open at birth",
        ));
    }
    commitment_claim_candidate_with_confidence(record, 1.0)
}

/// Encodes a commitment record value in canonical MessagePack field order.
pub fn encode_commitment_value(record: &CommitmentRecord) -> Result<Value> {
    record.validate()?;
    Ok(Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(COMMITMENT_VALUE_SCHEMA_VERSION),
        ),
        (Value::from(KEY_OBLIGOR), encode_obligor(record.obligor)),
        (
            Value::from(KEY_BENEFICIARY),
            Value::from(record.beneficiary.to_hex()),
        ),
        (Value::from(KEY_CONTENT), encode_content(&record.content)),
        (Value::from(KEY_SCHEDULE), record.schedule.clone()),
        (
            Value::from(KEY_STRENGTH),
            Value::from(record.strength.as_str()),
        ),
        (Value::from(KEY_STATUS), Value::from(record.status.as_str())),
        (
            Value::from(KEY_BIRTH_PROVENANCE),
            encode_birth_provenance(&record.birth_provenance),
        ),
    ]))
}

/// Decodes and validates a `commitment.record` value.
pub fn decode_commitment_value(value: &Value) -> Result<CommitmentRecord> {
    let Value::Map(entries) = value else {
        return Err(invalid_commitment_value());
    };
    validate_keys(entries, &COMMITMENT_VALUE_KEYS)?;

    if required_value(entries, KEY_SCHEMA_VERSION)?.as_u64()
        != Some(COMMITMENT_VALUE_SCHEMA_VERSION)
    {
        return Err(invalid_commitment_value());
    }

    let obligor = decode_obligor(required_value(entries, KEY_OBLIGOR)?)?;
    let beneficiary = decode_entity_ref(required_value(entries, KEY_BENEFICIARY)?)?;
    let content = decode_content(required_value(entries, KEY_CONTENT)?)?;
    let schedule = required_value(entries, KEY_SCHEDULE)?.clone();
    let strength = CommitmentStrength::parse(required_string(entries, KEY_STRENGTH)?)
        .ok_or_else(invalid_commitment_value)?;
    let status = CommitmentStatus::parse(required_string(entries, KEY_STATUS)?)
        .ok_or_else(invalid_commitment_value)?;
    let birth_provenance = decode_birth_provenance(required_value(entries, KEY_BIRTH_PROVENANCE)?)?;
    let record = CommitmentRecord {
        obligor,
        beneficiary,
        content,
        schedule,
        strength,
        status,
        birth_provenance,
    };
    record.validate()?;
    Ok(record)
}

/// Decodes a claim body as a commitment when its predicate belongs to this
/// family. Other predicates return `Ok(None)`.
pub fn decode_commitment_claim(body: &ClaimBody) -> Result<Option<CommitmentRecord>> {
    if !is_commitment_claim_predicate(&body.predicate) {
        return Ok(None);
    }
    validate_commitment_claim_structure(body)?;
    decode_commitment_value(&body.value).map(Some)
}

/// Validates one `commitment.*` claim body.
pub(crate) fn validate_commitment_claim_structure(body: &ClaimBody) -> Result<()> {
    if !is_commitment_claim_predicate(&body.predicate) {
        return Err(Error::InvalidClaimBody(
            "unknown commitment claim predicate",
        ));
    }
    let ClaimSubject::Entity(subject) = body.subject else {
        return Err(Error::InvalidClaimBody(
            "commitment claim subject must be an entity",
        ));
    };
    let (Some(valid_from), Some(valid_to)) = (body.valid_from, body.valid_to) else {
        return Err(Error::InvalidClaimBody(
            "commitment claim must carry valid-time from/to",
        ));
    };
    if body.lifecycle == ClaimLifecycleStatus::Active && valid_to < valid_from {
        return Err(Error::InvalidClaimBody(
            "commitment claim valid-time is inverted",
        ));
    }
    let record = decode_commitment_value(&body.value)?;
    if subject != record.obligor.entity_ref {
        return Err(Error::InvalidClaimBody(
            "commitment claim subject must match obligor entity_ref",
        ));
    }
    Ok(())
}

impl Vault {
    /// Writes a new open `commitment.record` claim using the gated claim
    /// candidate path. `valid_time` is the due/active valid-time; `learned_at`
    /// is the transaction-time.
    pub fn put_commitment_claim(
        &self,
        id: &EntityId,
        record: &CommitmentRecord,
        envelope: &WriteEnvelope,
        valid_time: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        if record.status != CommitmentStatus::Open {
            return Err(Error::InvalidClaimBody(
                "new commitment status must be open",
            ));
        }
        let candidate = commitment_claim_candidate(record)?
            .with_validity(Some(valid_time.start), Some(valid_time.end));
        self.apply_commitment_candidate(id, candidate, envelope, valid_time, learned_at)
    }

    /// Reads a `commitment.record` claim. Missing claims return `Ok(None)`;
    /// non-commitment CLAIM entities fail typed.
    pub fn get_commitment_claim(&self, id: &EntityId) -> Result<Option<CommitmentRecord>> {
        let Some(body) = self.get_claim(id)? else {
            return Ok(None);
        };
        decode_commitment_claim(&body)?
            .ok_or(Error::InvalidClaimBody(
                "claim predicate is not commitment.record",
            ))
            .map(Some)
    }

    /// Marks an open commitment fulfilled through the gated write path.
    pub fn fulfill_commitment(
        &self,
        id: &EntityId,
        envelope: &WriteEnvelope,
        learned_at: u64,
    ) -> Result<()> {
        self.update_commitment_status(id, CommitmentStatus::Fulfilled, envelope, learned_at)
    }

    /// Marks an open commitment released through the gated write path.
    pub fn release_commitment(
        &self,
        id: &EntityId,
        envelope: &WriteEnvelope,
        learned_at: u64,
    ) -> Result<()> {
        self.update_commitment_status(id, CommitmentStatus::Released, envelope, learned_at)
    }

    /// Marks an open commitment superseded through the gated write path.
    pub fn supersede_commitment(
        &self,
        id: &EntityId,
        envelope: &WriteEnvelope,
        learned_at: u64,
    ) -> Result<()> {
        self.update_commitment_status(id, CommitmentStatus::Superseded, envelope, learned_at)
    }

    fn update_commitment_status(
        &self,
        id: &EntityId,
        next: CommitmentStatus,
        envelope: &WriteEnvelope,
        learned_at: u64,
    ) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        // Ground the named target and rewrite it in one transaction.
        let body = self.require_named_claim_target_active_in(&wtxn, id)?;
        if body.predicate != PREDICATE_COMMITMENT_RECORD {
            return Err(Error::InvalidClaimBody(
                "claim predicate is not commitment.record",
            ));
        }
        let raw = self
            .store
            .entities
            .get(&wtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header = EntityMetadataHeader::parse(raw.as_ref())
            .ok_or(Error::CorruptedIndex("entity header"))?;
        let mut record = decode_commitment_value(&body.value)?;
        if !record.status.can_transition_to(next) {
            return Err(Error::InvalidClaimBody(
                "commitment status transition requires open source status",
            ));
        }
        record.status = next;

        let candidate = commitment_claim_candidate_from_body(&body, &record)?;
        apply_commitment_ops(
            self,
            &mut wtxn,
            *id,
            candidate,
            envelope,
            TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
            learned_at,
        )?;
        wtxn.commit()?;
        Ok(())
    }

    fn apply_commitment_candidate(
        &self,
        id: &EntityId,
        candidate: ClaimCandidate,
        envelope: &WriteEnvelope,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        if self.store.entities.get(&wtxn, id.as_bytes())?.is_some() {
            return Err(Error::InvalidClaimBody(
                "commitment claim id already exists",
            ));
        }
        apply_commitment_ops(
            self, &mut wtxn, *id, candidate, envelope, occurred, learned_at,
        )?;
        wtxn.commit()?;
        Ok(())
    }
}

fn commitment_claim_candidate_with_confidence(
    record: &CommitmentRecord,
    confidence: f32,
) -> Result<ClaimCandidate> {
    Ok(ClaimCandidate::new(
        PREDICATE_COMMITMENT_RECORD,
        ClaimSubject::Entity(record.obligor.entity_ref),
        encode_commitment_value(record)?,
        confidence,
    ))
}

fn commitment_claim_candidate_from_body(
    body: &ClaimBody,
    record: &CommitmentRecord,
) -> Result<ClaimCandidate> {
    let mut candidate = commitment_claim_candidate_with_confidence(record, body.confidence)?
        .with_validity(body.valid_from, body.valid_to);
    if let Some(salience) = body.salience {
        candidate = candidate.with_salience(salience);
    }
    if let Some(world) = body.world {
        candidate = candidate.with_world(world);
    }
    if let Some(scope) = &body.scope {
        candidate = candidate.with_scope(scope.clone());
    }
    if body.stale {
        candidate = candidate.with_stale(true);
    }
    Ok(candidate)
}

fn apply_commitment_ops(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: EntityId,
    candidate: ClaimCandidate,
    envelope: &WriteEnvelope,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<()> {
    apply_ops_with_gate_mode(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        wtxn,
        vec![
            BatchOp::ClaimCandidate {
                id,
                candidate: Box::new(candidate),
                envelope: envelope.clone(),
                occurred,
                learned_at,
                internal_lexical_query_hint: false,
            },
            BatchOp::ReconcileLexicalQueryHints {
                source: id,
                keep: Vec::new(),
            },
        ],
        vault.text_index_trusted.load(Ordering::Acquire),
        ApplyOpsGateMode::new(true, true).with_source_in_gate_input(),
    )
}

fn encode_obligor(obligor: CommitmentObligor) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_OBLIGOR_KIND),
            Value::from(obligor.kind.as_str()),
        ),
        (
            Value::from(KEY_OBLIGOR_ENTITY_REF),
            Value::from(obligor.entity_ref.to_hex()),
        ),
    ])
}

fn decode_obligor(value: &Value) -> Result<CommitmentObligor> {
    let Value::Map(entries) = value else {
        return Err(invalid_commitment_value());
    };
    validate_keys(entries, &COMMITMENT_OBLIGOR_KEYS)?;
    let kind = CommitmentObligorKind::parse(required_string(entries, KEY_OBLIGOR_KIND)?)
        .ok_or_else(invalid_commitment_value)?;
    let entity_ref = decode_entity_ref(required_value(entries, KEY_OBLIGOR_ENTITY_REF)?)?;
    Ok(CommitmentObligor { kind, entity_ref })
}

fn encode_content(content: &CommitmentContent) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_CONTENT_TEXT),
            Value::from(content.text.as_str()),
        ),
        (
            Value::from(KEY_CONTENT_PAYLOAD_REF),
            content
                .payload_ref
                .as_deref()
                .map_or(Value::Nil, Value::from),
        ),
    ])
}

fn decode_content(value: &Value) -> Result<CommitmentContent> {
    let Value::Map(entries) = value else {
        return Err(invalid_commitment_value());
    };
    validate_keys(entries, &COMMITMENT_CONTENT_KEYS)?;
    let text = required_string(entries, KEY_CONTENT_TEXT)?.to_owned();
    let payload_ref_value = required_value(entries, KEY_CONTENT_PAYLOAD_REF)?;
    let payload_ref = if matches!(payload_ref_value, Value::Nil) {
        None
    } else {
        Some(
            payload_ref_value
                .as_str()
                .ok_or_else(invalid_commitment_value)?
                .to_owned(),
        )
    };
    CommitmentContent::new(text, payload_ref)
}

fn encode_birth_provenance(birth: &CommitmentBirthProvenance) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_BIRTH_KIND),
            Value::from(birth.kind.as_str()),
        ),
        (
            Value::from(KEY_BIRTH_REFERENCE),
            Value::from(birth.reference.as_str()),
        ),
    ])
}

fn decode_birth_provenance(value: &Value) -> Result<CommitmentBirthProvenance> {
    let Value::Map(entries) = value else {
        return Err(invalid_commitment_value());
    };
    validate_keys(entries, &COMMITMENT_BIRTH_PROVENANCE_KEYS)?;
    let kind = CommitmentBirthKind::parse(required_string(entries, KEY_BIRTH_KIND)?)
        .ok_or_else(invalid_commitment_value)?;
    CommitmentBirthProvenance::new(kind, required_string(entries, KEY_BIRTH_REFERENCE)?)
}

fn decode_entity_ref(value: &Value) -> Result<EntityId> {
    value
        .as_str()
        .ok_or_else(invalid_commitment_value)
        .and_then(|hex| EntityId::from_hex(hex).map_err(|_| invalid_commitment_value()))
}

fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
        .ok_or_else(invalid_commitment_value)
}

fn required_string<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a str> {
    required_value(entries, key)?
        .as_str()
        .ok_or_else(invalid_commitment_value)
}

fn validate_keys(entries: &[(Value, Value)], keys: &[&str]) -> Result<()> {
    let mut seen = vec![false; keys.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or_else(invalid_commitment_value)?;
        let Some(index) = keys.iter().position(|known| *known == key) else {
            return Err(invalid_commitment_value());
        };
        if seen[index] {
            return Err(invalid_commitment_value());
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|value| value) {
        Ok(())
    } else {
        Err(invalid_commitment_value())
    }
}

fn validate_non_empty_bounded(value: &str, max_bytes: usize, reason: &'static str) -> Result<()> {
    if value.trim().is_empty() || value.len() > max_bytes {
        Err(Error::InvalidClaimBody(reason))
    } else {
        Ok(())
    }
}

fn invalid_commitment_value() -> Error {
    Error::InvalidClaimBody("commitment record value failed validation")
}

#[cfg(test)]
mod tests {
    use rmpv::Value;

    use super::*;
    use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
    use crate::claim::{ClaimApprovalStatus, ClaimSource};
    use crate::config::{HnswConfig, VaultConfig};
    use crate::edge::EdgeActorClass;
    use crate::receipt::{ReceiptKind, ReceiptQuery};
    use crate::registry::{ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON};
    use crate::write_envelope::{WriteActor, WriteProvenance};

    fn temp_vault() -> Result<(tempfile::TempDir, Vault)> {
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.map_size = 64 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = Some("test/model@v1".to_owned());
        config.max_readers = 16;
        config.hnsw = HnswConfig::default();
        let vault = Vault::open(dir.path(), config)?;
        Ok((dir, vault))
    }

    fn time(start: u64, end: u64) -> TimeRange {
        TimeRange { start, end }
    }

    fn schedule(due: u64) -> Value {
        Value::Map(vec![
            (Value::from("kind"), Value::from("once")),
            (Value::from("due"), Value::from(due)),
        ])
    }

    fn seed_entities(vault: &Vault, ids: &[EntityId]) -> Result<()> {
        for id in ids {
            vault.put_entity(id, ENTITY_TYPE_PERSON, time(1, 1), 1, b"person")?;
        }
        Ok(())
    }

    fn seed_agent(vault: &Vault, id: &EntityId) -> Result<()> {
        vault.put_entity(id, ENTITY_TYPE_MACHINE, time(1, 1), 1, b"agent")
    }

    fn envelope(actor: EntityId) -> Result<WriteEnvelope> {
        Ok(WriteEnvelope::new(
            WriteActor::new(actor, EdgeActorClass::Human),
            ClaimSource::UserStated,
            WriteProvenance::new(Value::from("test commitment write"))?,
            ClaimApprovalStatus::Auto,
        ))
    }

    fn record(
        obligor: EntityId,
        beneficiary: EntityId,
        strength: CommitmentStrength,
    ) -> Result<CommitmentRecord> {
        CommitmentRecord::new(
            CommitmentObligor::new(CommitmentObligorKind::Owner, obligor),
            beneficiary,
            CommitmentContent::new("send the signed document", Some("payload:doc-1".to_owned()))?,
            schedule(10_000),
            strength,
            CommitmentStatus::Open,
            CommitmentBirthProvenance::new(CommitmentBirthKind::RunTreeNode, "run:turn-7")?,
        )
    }

    #[test]
    fn commitment_status_verbs_round_trip_and_emit_gate_receipts() -> Result<()> {
        let (_dir, vault) = temp_vault()?;
        let actor = crate::test_util::entity(0x51);
        let beneficiary = crate::test_util::entity(0xE2);
        seed_entities(&vault, &[actor, beneficiary])?;
        let envelope = envelope(actor)?;

        let fulfilled = crate::test_util::entity(0xB1);
        vault.put_commitment_claim(
            &fulfilled,
            &record(actor, beneficiary, CommitmentStrength::Commitment)?,
            &envelope,
            time(100, 200),
            300,
        )?;
        vault.fulfill_commitment(&fulfilled, &envelope, 301)?;
        assert_eq!(
            vault
                .get_commitment_claim(&fulfilled)?
                .expect("fulfilled commitment")
                .status,
            CommitmentStatus::Fulfilled
        );

        let released = crate::test_util::entity(0xB2);
        vault.put_commitment_claim(
            &released,
            &record(actor, beneficiary, CommitmentStrength::Decision)?,
            &envelope,
            time(110, 210),
            310,
        )?;
        vault.release_commitment(&released, &envelope, 311)?;
        assert_eq!(
            vault
                .get_commitment_claim(&released)?
                .expect("released commitment")
                .status,
            CommitmentStatus::Released
        );

        let superseded = crate::test_util::entity(0xB3);
        vault.put_commitment_claim(
            &superseded,
            &record(actor, beneficiary, CommitmentStrength::StatedIntention)?,
            &envelope,
            time(120, 220),
            320,
        )?;
        vault.supersede_commitment(&superseded, &envelope, 321)?;
        assert_eq!(
            vault
                .get_commitment_claim(&superseded)?
                .expect("superseded commitment")
                .status,
            CommitmentStatus::Superseded
        );

        let receipts = vault.receipts(ReceiptQuery::new(20).with_kind(ReceiptKind::Gate))?;
        for id in [fulfilled, released, superseded] {
            let trigger = format!("claim:{}", id.to_hex());
            assert!(
                receipts.iter().any(|receipt| {
                    receipt.trigger_ref.as_deref() == Some(trigger.as_str())
                        && receipt.outcome == "allow"
                }),
                "missing allow gate receipt for {trigger}"
            );
        }
        Ok(())
    }

    #[test]
    fn retro_dated_commitment_keeps_valid_time_and_learned_time_separate() -> Result<()> {
        let (_dir, vault) = temp_vault()?;
        let actor = crate::test_util::entity(0xC1);
        let beneficiary = crate::test_util::entity(0xC2);
        seed_entities(&vault, &[actor, beneficiary])?;
        let id = crate::test_util::entity(0xC3);
        let due_time = time(1_700_000_000, 1_700_000_000);
        let learned_at = 1_700_604_800;
        vault.put_commitment_claim(
            &id,
            &record(actor, beneficiary, CommitmentStrength::Commitment)?,
            &envelope(actor)?,
            due_time,
            learned_at,
        )?;

        let raw = vault.get_raw(&id)?.expect("raw commitment");
        let header = EntityMetadataHeader::parse(&raw).expect("entity header");
        assert_eq!(header.occurred_start, due_time.start);
        assert_eq!(header.occurred_end, due_time.end);
        assert_eq!(header.learned_at, learned_at);
        let stored = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], false)?;
        assert_eq!(stored.valid_from, Some(due_time.start));
        assert_eq!(stored.valid_to, Some(due_time.end));
        Ok(())
    }

    #[test]
    fn user_strength_override_beats_extractor_and_agent_owed_is_commitment() -> Result<()> {
        let owner_strength = CommitmentStrength::resolve(
            CommitmentObligorKind::Owner,
            CommitmentStrength::StatedIntention,
            Some(CommitmentStrength::Decision),
        );
        assert_eq!(owner_strength, CommitmentStrength::Decision);

        let agent_strength = CommitmentStrength::resolve(
            CommitmentObligorKind::Agent,
            CommitmentStrength::StatedIntention,
            Some(CommitmentStrength::Decision),
        );
        assert_eq!(agent_strength, CommitmentStrength::Commitment);

        let (_dir, vault) = temp_vault()?;
        let owner = crate::test_util::entity(0xD1);
        let beneficiary = crate::test_util::entity(0xD2);
        let agent = crate::test_util::entity(0xD3);
        seed_entities(&vault, &[owner, beneficiary])?;
        seed_agent(&vault, &agent)?;

        let owner_id = crate::test_util::entity(0xD4);
        let owner_record = record(owner, beneficiary, owner_strength)?;
        vault.put_commitment_claim(
            &owner_id,
            &owner_record,
            &envelope(owner)?,
            time(400, 500),
            600,
        )?;
        assert_eq!(
            vault
                .get_commitment_claim(&owner_id)?
                .expect("owner commitment")
                .strength,
            CommitmentStrength::Decision
        );

        let agent_record = CommitmentRecord::new(
            CommitmentObligor::new(CommitmentObligorKind::Agent, agent),
            owner,
            CommitmentContent::new("check in on Friday", None)?,
            schedule(700),
            CommitmentStrength::StatedIntention,
            CommitmentStatus::Open,
            CommitmentBirthProvenance::new(CommitmentBirthKind::Brief, "brief:check-in")?,
        )?;
        assert_eq!(agent_record.strength, CommitmentStrength::Commitment);
        Ok(())
    }

    fn value_bytes(value: &Value) -> Vec<u8> {
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, value).expect("encode MessagePack value");
        bytes
    }

    #[test]
    fn commitment_value_round_trips_closed_schema() -> Result<()> {
        let record = record(
            crate::test_util::entity(0x61),
            crate::test_util::entity(0x62),
            CommitmentStrength::Decision,
        )?;
        let value = encode_commitment_value(&record)?;
        assert_eq!(decode_commitment_value(&value)?, record);
        let Value::Map(entries) = value.clone() else {
            unreachable!()
        };
        for malformed in [
            Value::Map(entries[..7].to_vec()),
            Value::Map({
                let mut rows = entries.clone();
                rows.push((Value::from("extra"), Value::Nil));
                rows
            }),
            Value::Map({
                let mut rows = entries.clone();
                rows.push(rows[0].clone());
                rows
            }),
        ] {
            assert!(matches!(
                decode_commitment_value(&malformed),
                Err(Error::InvalidClaimBody(
                    "commitment record value failed validation"
                ))
            ));
        }
        Ok(())
    }

    #[test]
    fn commitment_status_transition_matrix_is_closed() {
        let statuses = [
            CommitmentStatus::Open,
            CommitmentStatus::Fulfilled,
            CommitmentStatus::Released,
            CommitmentStatus::Lapsed,
            CommitmentStatus::Superseded,
        ];
        for from in statuses {
            for to in statuses {
                assert_eq!(
                    from.can_transition_to(to),
                    matches!(
                        (from, to),
                        (
                            CommitmentStatus::Open,
                            CommitmentStatus::Fulfilled
                                | CommitmentStatus::Released
                                | CommitmentStatus::Lapsed
                                | CommitmentStatus::Superseded
                        )
                    )
                );
            }
        }
    }

    #[test]
    fn terminal_candidate_and_strength_rules_are_enforced() -> Result<()> {
        let obligor = crate::test_util::entity(0x63);
        let beneficiary = crate::test_util::entity(0x64);
        let terminal = CommitmentRecord::new(
            CommitmentObligor::new(CommitmentObligorKind::Owner, obligor),
            beneficiary,
            CommitmentContent::new("x", None)?,
            schedule(9),
            CommitmentStrength::Decision,
            CommitmentStatus::Fulfilled,
            CommitmentBirthProvenance::new(CommitmentBirthKind::Brief, "b")?,
        )?;
        assert!(matches!(
            commitment_claim_candidate(&terminal),
            Err(Error::InvalidClaimBody(
                "commitment candidate must be open at birth"
            ))
        ));
        assert_eq!(
            CommitmentStrength::resolve(
                CommitmentObligorKind::Owner,
                CommitmentStrength::Decision,
                None
            ),
            CommitmentStrength::Decision
        );
        assert_eq!(
            CommitmentStrength::resolve(
                CommitmentObligorKind::Agent,
                CommitmentStrength::Decision,
                None
            ),
            CommitmentStrength::Commitment
        );
        Ok(())
    }

    #[test]
    fn opaque_schedule_round_trips_byte_identical() -> Result<()> {
        let actor = crate::test_util::entity(0x65);
        let schedule = Value::Map(vec![(
            Value::from("unknown"),
            Value::Array(vec![Value::from(1), Value::from("nested")]),
        )]);
        let expected = value_bytes(&schedule);
        let rec = CommitmentRecord::new(
            CommitmentObligor::new(CommitmentObligorKind::Owner, actor),
            crate::test_util::entity(0x66),
            CommitmentContent::new("x", None)?,
            schedule,
            CommitmentStrength::Decision,
            CommitmentStatus::Open,
            CommitmentBirthProvenance::new(CommitmentBirthKind::Brief, "b")?,
        )?;
        assert_eq!(
            value_bytes(&decode_commitment_value(&encode_commitment_value(&rec)?)?.schedule),
            expected
        );
        Ok(())
    }

    #[test]
    fn duplicate_id_is_immutable_and_absent_write_does_not_receipt() -> Result<()> {
        let (_dir, vault) = temp_vault()?;
        let actor = crate::test_util::entity(0x67);
        let beneficiary = crate::test_util::entity(0x68);
        let id = crate::test_util::entity(0x69);
        seed_entities(&vault, &[actor, beneficiary])?;
        let env = envelope(actor)?;
        vault.put_commitment_claim(
            &id,
            &record(actor, beneficiary, CommitmentStrength::Decision)?,
            &env,
            time(1, 2),
            3,
        )?;
        let raw = vault.get_raw(&id)?;
        let receipts = vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?;
        assert!(matches!(
            vault.put_commitment_claim(
                &id,
                &record(actor, beneficiary, CommitmentStrength::Decision)?,
                &env,
                time(1, 2),
                4
            ),
            Err(Error::InvalidClaimBody(
                "commitment claim id already exists"
            ))
        ));
        assert_eq!(vault.get_raw(&id)?, raw);
        assert_eq!(
            vault
                .receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?
                .len(),
            receipts.len()
        );
        Ok(())
    }

    #[test]
    fn superseding_future_due_commitment_via_generic_lifecycle_succeeds() -> Result<()> {
        let (_dir, vault) = temp_vault()?;
        let actor = crate::test_util::entity(0x6A);
        let beneficiary = crate::test_util::entity(0x6B);
        let old = crate::test_util::entity(0x6C);
        let successor = crate::test_util::entity(0x6D);
        seed_entities(&vault, &[actor, beneficiary])?;
        let rec = record(actor, beneficiary, CommitmentStrength::Decision)?;
        vault.put_commitment_claim(&old, &rec, &envelope(actor)?, time(100, 200), 1)?;
        vault.put_commitment_claim(&successor, &rec, &envelope(actor)?, time(100, 200), 2)?;
        vault.supersede_claim(&successor, &old, 50)?;
        assert_eq!(
            vault.get_claim(&old)?.expect("old").lifecycle,
            ClaimLifecycleStatus::Superseded
        );
        Ok(())
    }

    #[test]
    fn commitment_claim_structure_requires_entity_obligor_and_valid_time() -> Result<()> {
        let obligor = crate::test_util::entity(0x71);
        let beneficiary = crate::test_util::entity(0x72);
        let record = record(obligor, beneficiary, CommitmentStrength::Decision)?;
        let mut body = crate::claim::ClaimBody::new(
            PREDICATE_COMMITMENT_RECORD,
            crate::claim::ClaimSubject::Entity(beneficiary),
            encode_commitment_value(&record)?,
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.valid_from = Some(20);
        body.valid_to = Some(30);
        assert!(matches!(
            validate_commitment_claim_structure(&body),
            Err(Error::InvalidClaimBody(
                "commitment claim subject must match obligor entity_ref"
            ))
        ));

        body.subject = crate::claim::ClaimSubject::Entity(obligor);
        for lifecycle in [
            ClaimLifecycleStatus::Active,
            ClaimLifecycleStatus::Superseded,
            ClaimLifecycleStatus::Retracted,
        ] {
            body.lifecycle = lifecycle;
            body.valid_from = None;
            assert!(matches!(
                validate_commitment_claim_structure(&body),
                Err(Error::InvalidClaimBody(
                    "commitment claim must carry valid-time from/to"
                ))
            ));
            body.valid_from = Some(30);
            body.valid_to = None;
            assert!(matches!(
                validate_commitment_claim_structure(&body),
                Err(Error::InvalidClaimBody(
                    "commitment claim must carry valid-time from/to"
                ))
            ));
        }
        body.valid_from = Some(30);
        body.valid_to = Some(20);
        body.lifecycle = ClaimLifecycleStatus::Active;
        assert!(matches!(
            validate_commitment_claim_structure(&body),
            Err(Error::InvalidClaimBody(
                "commitment claim valid-time is inverted"
            ))
        ));
        body.lifecycle = ClaimLifecycleStatus::Superseded;
        assert!(validate_commitment_claim_structure(&body).is_ok());
        Ok(())
    }

    #[test]
    fn put_commitment_claim_accepts_future_valid_time_and_stores_metadata() -> Result<()> {
        let (_dir, vault) = temp_vault()?;
        let actor = crate::test_util::entity(0x73);
        let beneficiary = crate::test_util::entity(0x74);
        let id = crate::test_util::entity(0x75);
        seed_entities(&vault, &[actor, beneficiary])?;
        vault.put_commitment_claim(
            &id,
            &record(actor, beneficiary, CommitmentStrength::Decision)?,
            &envelope(actor)?,
            time(1_000, 1_100),
            100,
        )?;
        let body = vault.get_claim(&id)?.expect("future commitment claim");
        assert_eq!(body.valid_from, Some(1_000));
        assert_eq!(body.valid_to, Some(1_100));
        let raw = vault.get_raw(&id)?.expect("future commitment raw");
        let header = EntityMetadataHeader::parse(&raw).expect("entity header");
        assert_eq!(header.occurred_start, 1_000);
        assert_eq!(header.occurred_end, 1_100);
        assert_eq!(header.learned_at, 100);
        Ok(())
    }

    #[test]
    fn extractor_strength_is_used_without_explicit_override() {
        assert_eq!(
            CommitmentStrength::resolve(
                CommitmentObligorKind::ThirdParty,
                CommitmentStrength::Decision,
                None,
            ),
            CommitmentStrength::Decision
        );
    }

    #[test]
    fn agent_obligor_is_always_commitment_strength() -> Result<()> {
        let agent = crate::test_util::entity(0x76);
        let beneficiary = crate::test_util::entity(0x77);
        let record = CommitmentRecord::new(
            CommitmentObligor::new(CommitmentObligorKind::Agent, agent),
            beneficiary,
            CommitmentContent::new("x", None)?,
            schedule(1),
            CommitmentStrength::StatedIntention,
            CommitmentStatus::Open,
            CommitmentBirthProvenance::new(CommitmentBirthKind::Brief, "brief:x")?,
        )?;
        assert_eq!(record.strength, CommitmentStrength::Commitment);
        let mut encoded = encode_commitment_value(&record)?;
        let Value::Map(entries) = &mut encoded else {
            unreachable!()
        };
        let (_, strength) = entries
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("strength"))
            .expect("strength field");
        *strength = Value::from("decision");
        assert!(matches!(
            decode_commitment_value(&encoded),
            Err(Error::InvalidClaimBody(
                "agent-owed commitments must have commitment strength"
            ))
        ));
        Ok(())
    }

    #[test]
    fn terminal_status_retry_adds_no_receipt() -> Result<()> {
        let (_dir, vault) = temp_vault()?;
        let actor = crate::test_util::entity(0x78);
        let beneficiary = crate::test_util::entity(0x79);
        seed_entities(&vault, &[actor, beneficiary])?;
        let env = envelope(actor)?;
        for (id, first, retry) in [
            (
                crate::test_util::entity(0x7A),
                CommitmentStatus::Fulfilled,
                CommitmentStatus::Fulfilled,
            ),
            (
                crate::test_util::entity(0x7B),
                CommitmentStatus::Released,
                CommitmentStatus::Released,
            ),
            (
                crate::test_util::entity(0x7C),
                CommitmentStatus::Superseded,
                CommitmentStatus::Superseded,
            ),
        ] {
            vault.put_commitment_claim(
                &id,
                &record(actor, beneficiary, CommitmentStrength::Decision)?,
                &env,
                time(10, 20),
                1,
            )?;
            match first {
                CommitmentStatus::Fulfilled => vault.fulfill_commitment(&id, &env, 2)?,
                CommitmentStatus::Released => vault.release_commitment(&id, &env, 2)?,
                CommitmentStatus::Superseded => vault.supersede_commitment(&id, &env, 2)?,
                _ => unreachable!(),
            }
            let before = vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?;
            let result = match retry {
                CommitmentStatus::Fulfilled => vault.fulfill_commitment(&id, &env, 3),
                CommitmentStatus::Released => vault.release_commitment(&id, &env, 3),
                CommitmentStatus::Superseded => vault.supersede_commitment(&id, &env, 3),
                _ => unreachable!(),
            };
            assert!(matches!(
                result,
                Err(Error::InvalidClaimBody(
                    "commitment status transition requires open source status"
                ))
            ));
            let after = vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?;
            assert_eq!(after.len(), before.len());
            assert_eq!(
                after
                    .iter()
                    .map(|receipt| &receipt.receipt_id)
                    .collect::<Vec<_>>(),
                before
                    .iter()
                    .map(|receipt| &receipt.receipt_id)
                    .collect::<Vec<_>>()
            );
        }
        Ok(())
    }

    #[test]
    fn stale_fulfill_returns_write_verb_target_stale() -> Result<()> {
        let (_dir, vault) = temp_vault()?;
        let actor = crate::test_util::entity(0x81);
        let beneficiary = crate::test_util::entity(0x82);
        let stale_id = crate::test_util::entity(0x83);
        let successor = crate::test_util::entity(0x84);
        seed_entities(&vault, &[actor, beneficiary])?;
        let env = envelope(actor)?;
        let rec = record(actor, beneficiary, CommitmentStrength::Decision)?;
        vault.put_commitment_claim(&stale_id, &rec, &env, time(1_000, 1_100), 10)?;
        vault.put_commitment_claim(&successor, &rec, &env, time(1_000, 1_100), 11)?;
        vault.supersede_claim(&successor, &stale_id, 50)?;
        let expected = vault
            .require_named_claim_target_active(&stale_id)
            .expect_err("stale target");
        let old_raw = vault.get_raw(&stale_id)?;
        let successor_raw = vault.get_raw(&successor)?;
        let receipts = vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?;
        let err = vault
            .fulfill_commitment(&stale_id, &env, 60)
            .expect_err("stale fulfill");
        assert!(
            matches!(err, Error::WriteVerbTargetStale { target, lifecycle: ClaimLifecycleStatus::Superseded, successor_short_id } if target == stale_id && successor_short_id.contains(':'))
        );
        assert_eq!(vault.get_raw(&stale_id)?, old_raw);
        assert_eq!(vault.get_raw(&successor)?, successor_raw);
        assert_eq!(
            vault.get_claim(&stale_id)?.expect("stale").lifecycle,
            ClaimLifecycleStatus::Superseded
        );
        assert_eq!(
            vault
                .get_commitment_claim(&successor)?
                .expect("successor")
                .status,
            CommitmentStatus::Open
        );
        let after = vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?;
        assert_eq!(after.len(), receipts.len());
        assert_eq!(
            after.iter().map(|r| &r.receipt_id).collect::<Vec<_>>(),
            receipts.iter().map(|r| &r.receipt_id).collect::<Vec<_>>()
        );
        Ok(())
    }

    #[test]
    fn stale_release_returns_write_verb_target_stale() -> Result<()> {
        let (_dir, vault) = temp_vault()?;
        let actor = crate::test_util::entity(0x85);
        let beneficiary = crate::test_util::entity(0x86);
        let stale_id = crate::test_util::entity(0x87);
        let successor = crate::test_util::entity(0x88);
        seed_entities(&vault, &[actor, beneficiary])?;
        let env = envelope(actor)?;
        let rec = record(actor, beneficiary, CommitmentStrength::Decision)?;
        vault.put_commitment_claim(&stale_id, &rec, &env, time(1_000, 1_100), 10)?;
        vault.put_commitment_claim(&successor, &rec, &env, time(1_000, 1_100), 11)?;
        vault.supersede_claim(&successor, &stale_id, 50)?;
        let expected = vault
            .require_named_claim_target_active(&stale_id)
            .expect_err("stale target");
        let old_raw = vault.get_raw(&stale_id)?;
        let successor_raw = vault.get_raw(&successor)?;
        let receipts = vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?;
        let err = vault
            .release_commitment(&stale_id, &env, 60)
            .expect_err("stale release");
        assert!(
            matches!(err, Error::WriteVerbTargetStale { target, lifecycle: ClaimLifecycleStatus::Superseded, successor_short_id } if target == stale_id && successor_short_id.contains(':'))
        );
        assert_eq!(vault.get_raw(&stale_id)?, old_raw);
        assert_eq!(vault.get_raw(&successor)?, successor_raw);
        assert_eq!(
            vault.get_claim(&stale_id)?.expect("stale").lifecycle,
            ClaimLifecycleStatus::Superseded
        );
        assert_eq!(
            vault
                .get_commitment_claim(&successor)?
                .expect("successor")
                .status,
            CommitmentStatus::Open
        );
        let after = vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?;
        assert_eq!(after.len(), receipts.len());
        assert_eq!(
            after.iter().map(|r| &r.receipt_id).collect::<Vec<_>>(),
            receipts.iter().map(|r| &r.receipt_id).collect::<Vec<_>>()
        );
        Ok(())
    }

    #[test]
    fn stale_supersede_returns_write_verb_target_stale() -> Result<()> {
        let (_dir, vault) = temp_vault()?;
        let actor = crate::test_util::entity(0x89);
        let beneficiary = crate::test_util::entity(0x8A);
        let stale_id = crate::test_util::entity(0x8B);
        let successor = crate::test_util::entity(0x8C);
        seed_entities(&vault, &[actor, beneficiary])?;
        let env = envelope(actor)?;
        let rec = record(actor, beneficiary, CommitmentStrength::Decision)?;
        vault.put_commitment_claim(&stale_id, &rec, &env, time(1_000, 1_100), 10)?;
        vault.put_commitment_claim(&successor, &rec, &env, time(1_000, 1_100), 11)?;
        vault.supersede_claim(&successor, &stale_id, 50)?;
        let expected = vault
            .require_named_claim_target_active(&stale_id)
            .expect_err("stale target");
        let old_raw = vault.get_raw(&stale_id)?;
        let successor_raw = vault.get_raw(&successor)?;
        let receipts = vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?;
        let err = vault
            .supersede_commitment(&stale_id, &env, 60)
            .expect_err("stale supersede");
        assert!(
            matches!(err, Error::WriteVerbTargetStale { target, lifecycle: ClaimLifecycleStatus::Superseded, successor_short_id } if target == stale_id && successor_short_id.contains(':'))
        );
        assert_eq!(vault.get_raw(&stale_id)?, old_raw);
        assert_eq!(vault.get_raw(&successor)?, successor_raw);
        assert_eq!(
            vault.get_claim(&stale_id)?.expect("stale").lifecycle,
            ClaimLifecycleStatus::Superseded
        );
        assert_eq!(
            vault
                .get_commitment_claim(&successor)?
                .expect("successor")
                .status,
            CommitmentStatus::Open
        );
        let after = vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?;
        assert_eq!(after.len(), receipts.len());
        assert_eq!(
            after.iter().map(|r| &r.receipt_id).collect::<Vec<_>>(),
            receipts.iter().map(|r| &r.receipt_id).collect::<Vec<_>>()
        );
        Ok(())
    }

    #[test]
    fn status_verbs_reject_non_commitment_claims_without_rewriting() -> Result<()> {
        let (_dir, vault) = temp_vault()?;
        let actor = crate::test_util::entity(0x91);
        let beneficiary = crate::test_util::entity(0x92);
        let id = crate::test_util::entity(0x93);
        seed_entities(&vault, &[actor, beneficiary])?;
        // `profile.note` is gate-normal under the default policy manifest (the
        // `profile.` prefix rule pins criticality/sensitivity to normal), so the
        // public `put_claim` seed is gate-allowed; the commitment-decodable
        // value under a foreign predicate is the trap the guard must reject.
        let body = crate::claim::ClaimBody::new(
            "profile.note",
            crate::claim::ClaimSubject::Entity(actor),
            encode_commitment_value(&record(actor, beneficiary, CommitmentStrength::Decision)?)?,
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        vault.put_claim(&id, &body, time(10, 20), 1)?;
        let raw = vault.get_raw(&id)?;
        let env = envelope(actor)?;
        for result in [
            vault.fulfill_commitment(&id, &env, 2),
            vault.release_commitment(&id, &env, 3),
            vault.supersede_commitment(&id, &env, 4),
        ] {
            assert!(matches!(
                result,
                Err(Error::InvalidClaimBody(
                    "claim predicate is not commitment.record"
                ))
            ));
            assert_eq!(vault.get_raw(&id)?, raw);
        }
        Ok(())
    }
}
