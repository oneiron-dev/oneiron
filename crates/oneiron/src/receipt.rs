//! Unified receipt-family query surface over existing receipt emitters.
//!
//! RS1 is intentionally a projection over existing event substrates. This
//! module does not mint a new receipt store and does not change emitter schema.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::access_grant::{AccessGrant, AccessGrantScope, decode_access_grant_body};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, Result};
use crate::federation::{FederationGrant, FederationGrantScope, decode_federation_grant_body};
use crate::store::GateDecisionRecord;
use crate::types::{
    ENTITY_ID_LEN, ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_COMPANION_REGISTER,
    ENTITY_TYPE_FEDERATION_GRANT, EntityId,
    companion::{
        CompanionLifecycleEvent, CompanionRecord, CompanionScope, CompanionSubject,
        decode_companion_record_body,
    },
};

const DEFAULT_RECEIPT_QUERY_LIMIT: usize = 100;
const MAX_RECEIPT_QUERY_SCAN: usize = 100_000;

const fn default_receipt_query_limit() -> usize {
    DEFAULT_RECEIPT_QUERY_LIMIT
}

/// Receipt family discriminator pinned by OF-367 RS1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ReceiptKind {
    /// Outbound effect receipt.
    Outbound,
    /// Gate decision/stamp receipt.
    Gate,
    /// Companion/persona identity lifecycle receipt.
    IdentityLifecycle,
    /// Scoped read/access receipt.
    ScopedRead,
    /// Share/federation receipt.
    Share,
}

impl ReceiptKind {
    /// Returns the stable query string for this receipt kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Outbound => "outbound",
            Self::Gate => "gate",
            Self::IdentityLifecycle => "identity_lifecycle",
            Self::ScopedRead => "scoped_read",
            Self::Share => "share",
        }
    }

    /// Parses a stable receipt kind string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "outbound" => Some(Self::Outbound),
            "gate" => Some(Self::Gate),
            "identity_lifecycle" => Some(Self::IdentityLifecycle),
            "scoped_read" => Some(Self::ScopedRead),
            "share" => Some(Self::Share),
            _ => None,
        }
    }
}

/// Query filters for the unified receipt family.
///
/// Empty `kinds` means all supported receipt kinds. `start_at` and `end_at`
/// are inclusive Unix-second bounds over the receipt event time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptQuery {
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub kinds: BTreeSet<ReceiptKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_at: Option<u64>,
    #[serde(default = "default_receipt_query_limit")]
    pub limit: usize,
}

impl Default for ReceiptQuery {
    fn default() -> Self {
        Self {
            kinds: BTreeSet::new(),
            actor: None,
            outcome: None,
            start_at: None,
            end_at: None,
            limit: DEFAULT_RECEIPT_QUERY_LIMIT,
        }
    }
}

impl ReceiptQuery {
    /// Builds an all-kind query with an explicit result limit.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            ..Self::default()
        }
    }

    /// Adds one kind filter.
    #[must_use]
    pub fn with_kind(mut self, kind: ReceiptKind) -> Self {
        self.kinds.insert(kind);
        self
    }

    /// Adds an actor filter.
    #[must_use]
    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = Some(actor.into());
        self
    }

    /// Adds an outcome filter.
    #[must_use]
    pub fn with_outcome(mut self, outcome: impl Into<String>) -> Self {
        self.outcome = Some(outcome.into());
        self
    }

    /// Adds inclusive Unix-second time bounds.
    #[must_use]
    pub const fn with_time_bounds(mut self, start_at: Option<u64>, end_at: Option<u64>) -> Self {
        self.start_at = start_at;
        self.end_at = end_at;
        self
    }

    fn includes_kind(&self, kind: ReceiptKind) -> bool {
        self.kinds.is_empty() || self.kinds.contains(&kind)
    }

    fn matches(&self, receipt: &ReceiptRecord) -> bool {
        if !self.includes_kind(receipt.receipt_kind) {
            return false;
        }
        if let Some(actor) = self.actor.as_deref()
            && receipt.actor.as_deref() != Some(actor)
            && receipt.on_behalf_of.as_deref() != Some(actor)
        {
            return false;
        }
        if let Some(outcome) = self.outcome.as_deref()
            && receipt.outcome != outcome
        {
            return false;
        }
        if let Some(start_at) = self.start_at
            && receipt.occurred_at < start_at
        {
            return false;
        }
        if let Some(end_at) = self.end_at
            && receipt.occurred_at > end_at
        {
            return false;
        }
        true
    }
}

/// One projected receipt-family row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptRecord {
    pub receipt_id: String,
    pub receipt_kind: ReceiptKind,
    pub occurred_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<String>,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_trace: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, String>,
}

impl Vault {
    /// Queries the unified receipt family across existing receipt emitters.
    pub fn receipts(&self, query: ReceiptQuery) -> Result<Vec<ReceiptRecord>> {
        receipt_family_query(self, &query)
    }

    /// Alias for callers that prefer verb-first query naming.
    pub fn query_receipts(&self, query: ReceiptQuery) -> Result<Vec<ReceiptRecord>> {
        self.receipts(query)
    }
}

fn receipt_family_query(vault: &Vault, query: &ReceiptQuery) -> Result<Vec<ReceiptRecord>> {
    if query.limit == 0 {
        return Ok(Vec::new());
    }

    let mut records = Vec::new();
    if query.includes_kind(ReceiptKind::Gate) {
        records.extend(gate_receipts(vault, query)?);
    }

    let rtxn = vault.store.env.read_txn()?;
    if query.includes_kind(ReceiptKind::IdentityLifecycle) {
        records.extend(companion_lifecycle_receipts(vault, &rtxn, query)?);
    }
    if query.includes_kind(ReceiptKind::ScopedRead) {
        records.extend(access_grant_receipts(vault, &rtxn, query)?);
    }
    if query.includes_kind(ReceiptKind::Share) {
        records.extend(federation_share_receipts(vault, &rtxn, query)?);
    }

    records.sort_by(|left, right| {
        right
            .occurred_at
            .cmp(&left.occurred_at)
            .then_with(|| left.receipt_kind.cmp(&right.receipt_kind))
            .then_with(|| left.receipt_id.cmp(&right.receipt_id))
    });
    records.truncate(query.limit);
    Ok(records)
}

fn gate_receipts(vault: &Vault, query: &ReceiptQuery) -> Result<Vec<ReceiptRecord>> {
    let mut receipts = Vec::new();
    for decision in vault.store.gate_decisions(MAX_RECEIPT_QUERY_SCAN)? {
        let receipt = gate_decision_receipt(&decision);
        if query.matches(&receipt) {
            receipts.push(receipt);
        }
    }
    Ok(receipts)
}

fn gate_decision_receipt(record: &GateDecisionRecord) -> ReceiptRecord {
    let mut fields = BTreeMap::new();
    fields.insert("actor_class".to_owned(), record.actor_class.clone());
    fields.insert("content_kind".to_owned(), record.content_kind.clone());
    fields.insert(
        "policy_manifest_version".to_owned(),
        record.policy_manifest_version.clone(),
    );
    fields.insert("diff_handle".to_owned(), hex_lower(&record.diff_handle));
    fields.insert(
        "read_frontier_hash".to_owned(),
        hex_lower(&record.read_frontier_hash),
    );

    ReceiptRecord {
        receipt_id: format!("gate:{}", record.decision_id.to_hex()),
        receipt_kind: ReceiptKind::Gate,
        occurred_at: record.created_at,
        actor: record
            .actor_ref
            .clone()
            .or_else(|| Some(record.actor_class.clone())),
        on_behalf_of: None,
        outcome: record.outcome.clone(),
        trigger_ref: record
            .claim_id
            .map(|id| format!("claim:{}", hex_lower(&id))),
        policy_trace: record.reason_codes.clone(),
        fields,
    }
}

fn companion_lifecycle_receipts(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let mut receipts = Vec::new();
    scan_entities_by_type(
        vault,
        txn,
        ENTITY_TYPE_COMPANION_REGISTER,
        "companion register type index",
        |id, header, body| {
            let record = decode_companion_record_body(body)?;
            for (index, event) in record.lifecycle_events.iter().enumerate() {
                let receipt =
                    companion_lifecycle_receipt(id, &record, *event, index, header.learned_at);
                if query.matches(&receipt) {
                    receipts.push(receipt);
                }
            }
            Ok(())
        },
    )?;
    Ok(receipts)
}

fn companion_lifecycle_receipt(
    id: EntityId,
    record: &CompanionRecord,
    event: CompanionLifecycleEvent,
    event_index: usize,
    learned_at: u64,
) -> ReceiptRecord {
    let mut fields = BTreeMap::new();
    fields.insert(
        "actor_class".to_owned(),
        record.provenance.actor_class.gate_actor_class().to_owned(),
    );
    fields.insert(
        "source".to_owned(),
        record.provenance.source.as_str().to_owned(),
    );
    fields.insert(
        "approval".to_owned(),
        record.provenance.approval.as_str().to_owned(),
    );
    fields.insert("record_kind".to_owned(), record.kind().as_str().to_owned());
    fields.insert(
        "record_lifecycle".to_owned(),
        record.lifecycle.as_str().to_owned(),
    );
    fields.insert("learned_at".to_owned(), learned_at.to_string());
    append_companion_scope_fields(&mut fields, &record.scope);
    append_companion_subject_fields(&mut fields, &record.subject);

    ReceiptRecord {
        receipt_id: format!(
            "identity_lifecycle:{}:{}:{}",
            id.to_hex(),
            event.kind.as_str(),
            event_index
        ),
        receipt_kind: ReceiptKind::IdentityLifecycle,
        occurred_at: event.at,
        actor: Some(record.provenance.actor_ref.to_hex()),
        on_behalf_of: None,
        outcome: event.kind.as_str().to_owned(),
        trigger_ref: Some(format!("entity:{}", id.to_hex())),
        policy_trace: Vec::new(),
        fields,
    }
}

fn access_grant_receipts(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let mut receipts = Vec::new();
    scan_entities_by_type(
        vault,
        txn,
        ENTITY_TYPE_ACCESS_GRANT,
        "access grant type index",
        |id, _header, body| {
            let grant = decode_access_grant_body(body)?;
            let created = access_grant_receipt(id, &grant, grant.created_at, "active", "created");
            if query.matches(&created) {
                receipts.push(created);
            }
            if let Some(revoked_at) = grant.revoked_at {
                let revoked = access_grant_receipt(id, &grant, revoked_at, "revoked", "revoked");
                if query.matches(&revoked) {
                    receipts.push(revoked);
                }
            }
            Ok(())
        },
    )?;
    Ok(receipts)
}

fn access_grant_receipt(
    id: EntityId,
    grant: &AccessGrant,
    occurred_at: u64,
    outcome: &str,
    event_name: &str,
) -> ReceiptRecord {
    let mut fields = BTreeMap::new();
    fields.insert("status".to_owned(), grant.status.as_str().to_owned());
    fields.insert(
        "capability".to_owned(),
        grant.capability.as_str().to_owned(),
    );
    append_access_grant_scope_fields(&mut fields, grant.scope);

    ReceiptRecord {
        receipt_id: format!("scoped_read:{}:{event_name}", id.to_hex()),
        receipt_kind: ReceiptKind::ScopedRead,
        occurred_at,
        actor: Some(grant.principal_ref.to_hex()),
        on_behalf_of: None,
        outcome: outcome.to_owned(),
        trigger_ref: Some(format!("access_grant:{}", id.to_hex())),
        policy_trace: Vec::new(),
        fields,
    }
}

fn federation_share_receipts(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let mut receipts = Vec::new();
    scan_entities_by_type(
        vault,
        txn,
        ENTITY_TYPE_FEDERATION_GRANT,
        "federation grant type index",
        |id, header, body| {
            let grant = decode_federation_grant_body(body)?;
            let receipt = federation_share_receipt(id, &grant, header.occurred_start);
            if query.matches(&receipt) {
                receipts.push(receipt);
            }
            Ok(())
        },
    )?;
    Ok(receipts)
}

fn federation_share_receipt(
    id: EntityId,
    grant: &FederationGrant,
    occurred_at: u64,
) -> ReceiptRecord {
    let mut fields = BTreeMap::new();
    fields.insert("role".to_owned(), grant.role.as_str().to_owned());
    fields.insert("preset".to_owned(), grant.preset.as_str().to_owned());
    append_federation_scope_fields(&mut fields, grant.scope);

    ReceiptRecord {
        receipt_id: format!("share:{}", id.to_hex()),
        receipt_kind: ReceiptKind::Share,
        occurred_at,
        actor: Some(grant.member_ref.to_hex()),
        on_behalf_of: None,
        outcome: "granted".to_owned(),
        trigger_ref: Some(format!("federation_grant:{}", id.to_hex())),
        policy_trace: Vec::new(),
        fields,
    }
}

fn scan_entities_by_type(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    entity_type: u8,
    context: &'static str,
    mut visit: impl FnMut(EntityId, EntityMetadataHeader, &[u8]) -> Result<()>,
) -> Result<()> {
    let mut scanned = 0_usize;
    for entry in vault.store.type_index.prefix_iter(txn, &[entity_type])? {
        let (key, _) = entry?;
        if key.first().copied() != Some(entity_type) {
            return Err(Error::CorruptedIndex(context));
        }
        let id = entity_id_from_type_index_key(key, context)?;
        let Some(raw) = vault.store.entities.get(txn, id.as_bytes())? else {
            return Err(Error::CorruptedIndex(context));
        };
        let header = EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex(context))?;
        if header.entity_type != entity_type {
            return Err(Error::CorruptedIndex(context));
        }
        visit(id, header, &raw[ENTITY_METADATA_HEADER_LEN..])?;
        scanned = scanned.saturating_add(1);
        if scanned >= MAX_RECEIPT_QUERY_SCAN {
            break;
        }
    }
    Ok(())
}

fn entity_id_from_type_index_key(key: &[u8], context: &'static str) -> Result<EntityId> {
    if key.len() != 1 + ENTITY_ID_LEN {
        return Err(Error::CorruptedIndex(context));
    }
    EntityId::from_bytes(
        key[1..]
            .try_into()
            .map_err(|_| Error::CorruptedIndex(context))?,
    )
    .map_err(|_| Error::CorruptedIndex(context))
}

fn append_companion_scope_fields(fields: &mut BTreeMap<String, String>, scope: &CompanionScope) {
    match scope {
        CompanionScope::Neutral => {
            fields.insert("scope".to_owned(), "neutral".to_owned());
        }
        CompanionScope::Personal { person_ref } => {
            fields.insert("scope".to_owned(), "personal".to_owned());
            fields.insert("person_ref".to_owned(), person_ref.to_hex());
        }
        CompanionScope::SharedVault { vault_id } => {
            fields.insert("scope".to_owned(), "shared_vault".to_owned());
            fields.insert("vault_id".to_owned(), vault_id.to_string());
        }
    }
}

fn append_companion_subject_fields(
    fields: &mut BTreeMap<String, String>,
    subject: &CompanionSubject,
) {
    match subject {
        CompanionSubject::Persona { persona_ref } => {
            fields.insert("subject".to_owned(), "persona".to_owned());
            fields.insert("persona_ref".to_owned(), persona_ref.to_hex());
        }
        CompanionSubject::Relationship {
            source_ref,
            target_ref,
        } => {
            fields.insert("subject".to_owned(), "relationship".to_owned());
            fields.insert("source_ref".to_owned(), source_ref.to_hex());
            fields.insert("target_ref".to_owned(), target_ref.to_hex());
        }
    }
}

fn append_access_grant_scope_fields(
    fields: &mut BTreeMap<String, String>,
    scope: AccessGrantScope,
) {
    match scope {
        AccessGrantScope::CompanionProfile {
            person_ref,
            persona_ref,
        } => {
            fields.insert("scope".to_owned(), "companion_profile".to_owned());
            fields.insert("person_ref".to_owned(), person_ref.to_hex());
            fields.insert("persona_ref".to_owned(), persona_ref.to_hex());
        }
    }
}

fn append_federation_scope_fields(
    fields: &mut BTreeMap<String, String>,
    scope: FederationGrantScope,
) {
    match scope {
        FederationGrantScope::Vault { vault_id } => {
            fields.insert("scope".to_owned(), "vault".to_owned());
            fields.insert("vault_id".to_owned(), vault_id.to_string());
        }
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access_grant::AccessGrant;
    use crate::batch::ENTITY_METADATA_HEADER_LEN;
    use crate::claim::{ClaimApprovalStatus, ClaimSource};
    use crate::federation::{
        FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
        encode_federation_grant_body,
    };
    use crate::store::{GateDecisionId, Store};
    use crate::types::{
        ENTITY_TYPE_REDACTION_AUDIT, EdgeActorClass, HnswConfig, TimeRange, VaultConfig,
        WriteActor, WriteEnvelope, WriteProvenance,
        companion::{
            CompanionExportClassification, CompanionProvenance, CompanionRecord, CompanionScope,
        },
    };

    fn test_config() -> VaultConfig {
        let mut config = VaultConfig::device();
        config.map_size = 16 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = Some("test-model-v1".to_owned());
        config.max_readers = 16;
        config.hnsw = HnswConfig::default();
        config
    }

    fn temp_vault() -> Result<(tempfile::TempDir, Vault)> {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), test_config())?;
        Ok((dir, vault))
    }

    fn entity(seed: u8) -> EntityId {
        let mut bytes = [seed; ENTITY_ID_LEN];
        bytes[0] = seed.max(1);
        EntityId::from_bytes(bytes).expect("test entity id")
    }

    fn append_gate_decision(
        vault: &Vault,
        created_at: u64,
        actor: &str,
        outcome: &str,
        reason: &str,
    ) -> Result<GateDecisionId> {
        let decision_id = GateDecisionId::now();
        vault.with_write_txn(|wtxn| {
            vault.store.append_gate_decision_in_txn(
                wtxn,
                &GateDecisionRecord {
                    version: 0,
                    decision_id,
                    created_at,
                    outcome: outcome.to_owned(),
                    reason_codes: vec![reason.to_owned()],
                    actor_class: "agent".to_owned(),
                    actor_ref: Some(actor.to_owned()),
                    content_kind: "external_effect".to_owned(),
                    policy_manifest_version: "test-policy".to_owned(),
                    claim_id: Some(*entity(0x41).as_bytes()),
                    diff_handle: vec![0xA5],
                    read_frontier_hash: [0xB6; 32],
                },
            )
        })?;
        Ok(decision_id)
    }

    fn provenance(actor: EntityId) -> CompanionProvenance {
        let envelope = WriteEnvelope::new(
            WriteActor::new(actor, EdgeActorClass::Agent),
            ClaimSource::UserStated,
            WriteProvenance::new(rmpv::Value::from("receipt fixture")).unwrap(),
            ClaimApprovalStatus::Approved,
        );
        CompanionProvenance::from_envelope(&envelope)
    }

    fn companion_record(actor: EntityId) -> CompanionRecord {
        CompanionRecord::persona(
            CompanionScope::neutral(),
            entity(0x51),
            rmpv::Value::from("persona"),
            provenance(actor),
            CompanionExportClassification::Portable,
        )
    }

    fn put_federation_grant(vault: &Vault, id: EntityId, learned_at: u64) -> Result<()> {
        let grant = FederationGrant::new(
            FederationGrantScope::vault(7),
            entity(0x61),
            FederationGrantRole::Viewer,
            FederationGrantPreset::ReadOnly,
        );
        let body = encode_federation_grant_body(&grant)?;
        vault
            .batch()
            .put(
                &id,
                ENTITY_TYPE_FEDERATION_GRANT,
                TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
                &body,
            )
            .commit()
    }

    fn put_redaction_floor_receipt(vault: &Vault, id: EntityId, learned_at: u64) -> Result<()> {
        let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + 4);
        payload.push(ENTITY_TYPE_REDACTION_AUDIT);
        payload.extend_from_slice(&learned_at.to_be_bytes());
        payload.extend_from_slice(&learned_at.to_be_bytes());
        payload.extend_from_slice(&learned_at.to_be_bytes());
        payload.extend_from_slice(b"seal");
        vault.with_write_txn(|wtxn| {
            vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
            let type_key = Store::encode_type_key(ENTITY_TYPE_REDACTION_AUDIT, &id);
            vault.store.type_index.put(wtxn, &type_key, &[])?;
            let temporal_key = Store::encode_temporal_key(learned_at, &id);
            vault
                .store
                .temporal_occurred_start
                .put(wtxn, &temporal_key, &[])?;
            vault.store.temporal_learned.put(wtxn, &temporal_key, &[])?;
            Ok(())
        })
    }

    #[test]
    fn receipt_query_deserializes_missing_limit_with_default() -> Result<()> {
        let query: ReceiptQuery = serde_json::from_str(r#"{"outcome":"held"}"#)
            .map_err(|_| Error::InvariantViolation("receipt query json fixture"))?;
        assert_eq!(query.limit, DEFAULT_RECEIPT_QUERY_LIMIT);
        assert_eq!(query.outcome.as_deref(), Some("held"));
        Ok(())
    }

    #[test]
    fn receipt_query_returns_mixed_kinds_and_filters() -> Result<()> {
        let (_tmp, vault) = temp_vault()?;
        append_gate_decision(
            &vault,
            10,
            "agent-alpha",
            "pending",
            "gate.pending.actor_ceiling",
        )?;

        let identity_actor = entity(0x50);
        vault.create_companion_record(&entity(0x52), &companion_record(identity_actor), 20)?;

        let access_grant =
            AccessGrant::companion_profile_read(entity(0x60), entity(0x62), entity(0x63), 30);
        vault.create_access_grant(&entity(0x64), &access_grant)?;
        put_federation_grant(&vault, entity(0x65), 40)?;

        let receipts = vault.receipts(ReceiptQuery::new(10))?;
        let kinds: BTreeSet<_> = receipts
            .iter()
            .map(|receipt| receipt.receipt_kind)
            .collect();
        assert!(kinds.contains(&ReceiptKind::Gate));
        assert!(kinds.contains(&ReceiptKind::IdentityLifecycle));
        assert!(kinds.contains(&ReceiptKind::ScopedRead));
        assert!(kinds.contains(&ReceiptKind::Share));

        let gate = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
        assert_eq!(gate.len(), 1);
        assert_eq!(gate[0].actor.as_deref(), Some("agent-alpha"));

        let by_actor = vault.receipts(ReceiptQuery::new(10).with_actor(identity_actor.to_hex()))?;
        assert_eq!(by_actor.len(), 1);
        assert_eq!(by_actor[0].receipt_kind, ReceiptKind::IdentityLifecycle);

        let by_outcome = vault.receipts(ReceiptQuery::new(10).with_outcome("active"))?;
        assert_eq!(by_outcome.len(), 1);
        assert_eq!(by_outcome[0].receipt_kind, ReceiptKind::ScopedRead);

        let recent = vault.receipts(ReceiptQuery::new(10).with_time_bounds(Some(35), None))?;
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].receipt_kind, ReceiptKind::Share);
        Ok(())
    }

    #[test]
    fn receipt_query_filters_negative_space_outcomes_identically() -> Result<()> {
        let (_tmp, vault) = temp_vault()?;
        append_gate_decision(&vault, 10, "agent-alpha", "delivered", "gate.allow")?;
        append_gate_decision(
            &vault,
            11,
            "agent-alpha",
            "held",
            "gate.pending.external_effect_authority",
        )?;
        append_gate_decision(
            &vault,
            12,
            "agent-beta",
            "let_go",
            "gate.pending.external_effect_authority",
        )?;

        let held = vault.receipts(ReceiptQuery::new(10).with_outcome("held"))?;
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].outcome, "held");

        let let_go = vault.receipts(ReceiptQuery::new(10).with_outcome("let_go"))?;
        assert_eq!(let_go.len(), 1);
        assert_eq!(let_go[0].actor.as_deref(), Some("agent-beta"));

        let delivered = vault.receipts(ReceiptQuery::new(10).with_outcome("delivered"))?;
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].outcome, "delivered");
        Ok(())
    }

    #[test]
    fn receipt_query_never_returns_floor_redaction_receipts() -> Result<()> {
        let (_tmp, vault) = temp_vault()?;
        let floor_id = entity(0x70);
        put_redaction_floor_receipt(&vault, floor_id, 50)?;
        append_gate_decision(
            &vault,
            10,
            "agent-alpha",
            "pending",
            "gate.pending.actor_ceiling",
        )?;

        let all = vault.receipts(ReceiptQuery::new(10))?;
        assert!(
            all.iter()
                .all(|receipt| !receipt.receipt_id.contains(&floor_id.to_hex()))
        );

        for kind in [
            ReceiptKind::Outbound,
            ReceiptKind::Gate,
            ReceiptKind::IdentityLifecycle,
            ReceiptKind::ScopedRead,
            ReceiptKind::Share,
        ] {
            let rows = vault.receipts(ReceiptQuery::new(10).with_kind(kind))?;
            assert!(
                rows.iter()
                    .all(|receipt| !receipt.receipt_id.contains(&floor_id.to_hex()))
            );
        }
        Ok(())
    }
}
