//! Authenticated ChannelIdentity autonomy, immutable bounds, and offer-only graduation.
//!
//! Authority lives in unified consent grants. These versioned vault-meta law rows
//! cannot be forged through generic claim writes. Envelope handles are content
//! addressed and immutable; posture is a pointer, never permission by itself.

use std::io::Cursor;

use rmpv::Value;

use crate::Vault;
use crate::access_grant::{AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::channel_identity::{ChannelIdentityBinding, ChannelIdentityState, decode_channel_identity_body};
use crate::channel_identity_selection::RelationshipContext;
use crate::consent::{ActionClass, ActionEnvelope, ActorBound, AudienceBound, AuthenticatedOwner,
    DisclosureClass, DisclosureEnvelope, GrantBound};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::outbound_grant::{StandingOutboundGrant, StandingOutboundGrantScope, StandingOutboundGrantStatus,
    standing_outbound_grant_in_txn};
use crate::receipt::{ReceiptKind, ReceiptQuery};
use crate::write_envelope::WriteActor;

pub const CHANNEL_IDENTITY_AUTONOMY_SCHEMA_VERSION: u64 = 1;
pub const DEFAULT_GRADUATION_UNCHANGED_STREAK: u32 = 12;
pub const PREDICATE_MAILBOX_READ_ENVELOPE: &str = "channel_identity.mailbox_read_envelope";
pub const PREDICATE_ACTION_ENVELOPE: &str = "channel_identity.action_envelope";
pub const PREDICATE_AUTONOMY_MODE: &str = "channel_identity.autonomy_mode";
pub const PREDICATE_GRADUATION_EVIDENCE: &str = "channel_identity.graduation_evidence";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChannelIdentityAutonomyRung {
    ScopedRead,
    DraftOnly,
    SendWithApproval,
    AutonomousWithinEnvelope,
}

impl ChannelIdentityAutonomyRung {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ScopedRead => "scoped_read",
            Self::DraftOnly => "draft_only",
            Self::SendWithApproval => "send_with_approval",
            Self::AutonomousWithinEnvelope => "autonomous_within_envelope",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "scoped_read" => Some(Self::ScopedRead),
            "draft_only" => Some(Self::DraftOnly),
            "send_with_approval" => Some(Self::SendWithApproval),
            "autonomous_within_envelope" => Some(Self::AutonomousWithinEnvelope),
            _ => None,
        }
    }

    fn verb(self) -> Option<&'static str> {
        match self {
            Self::ScopedRead => None,
            Self::DraftOnly | Self::SendWithApproval => Some("mail.draft"),
            Self::AutonomousWithinEnvelope => Some("mail.send"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxReadEnvelope {
    pub identity_ref: EntityId,
    pub label_allowlist: Vec<String>,
    pub thread_allowlist: Vec<String>,
    /// Inclusive lower bound on mailbox item time, not a volume-window clock.
    pub not_before: Option<u64>,
    /// Inclusive upper bound on mailbox item time.
    pub not_after: Option<u64>,
}


/// One already-resolved mailbox item to check against read-side authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxReadCandidate {
    pub identity_ref: EntityId,
    pub label: Option<String>,
    pub thread_ref: Option<String>,
    pub occurred_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelIdentityActionEnvelope {
    pub identity_ref: EntityId,
    pub relationship_context: RelationshipContext,
    /// None matches only an unclassified counterparty, not every class.
    pub counterparty_class: Option<String>,
    pub max_actions: u32,
    pub window_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelIdentityEffectCandidate {
    pub identity_ref: EntityId,
    pub relationship_context: RelationshipContext,
    pub verb_class: String,
    pub counterparty_class: Option<String>,
    /// Engine effect identity. Reuse reserves no second slot or delivery.
    pub effect_key: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelIdentityGrantWindowUsage {
    pub window_started_at: u64,
    pub used_actions: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelIdentityAutonomyMode {
    pub identity_ref: EntityId,
    pub relationship_context: RelationshipContext,
    pub rung: ChannelIdentityAutonomyRung,
    pub read_grant_ref: Option<EntityId>,
    pub action_grant_ref: Option<EntityId>,
}

/// Exact desired configuration. Apply refuses to replace a different posture;
/// intentional changes use the authenticated mode door after minting bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelIdentityAutonomyRequest {
    pub actor_ref: EntityId,
    pub relationship_context: RelationshipContext,
    pub rung: ChannelIdentityAutonomyRung,
    pub read_envelope: MailboxReadEnvelope,
    pub action_envelope: Option<ChannelIdentityActionEnvelope>,
}


impl ChannelIdentityAutonomyRequest {
    /// Starting posture for a newly delegated mailbox. Applying it still needs
    /// owner consent and creates separate read and draft grants, never send.
    #[must_use]
    pub fn draft_only(actor_ref: EntityId, read_envelope: MailboxReadEnvelope,
        action_envelope: ChannelIdentityActionEnvelope) -> Self {
        Self { actor_ref, relationship_context: action_envelope.relationship_context,
            rung: ChannelIdentityAutonomyRung::DraftOnly, read_envelope, action_envelope: Some(action_envelope) }
    }
}

/// Read-back proof includes the actual persisted grants, not just a mode label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelIdentityAutonomyState {
    pub mode: ChannelIdentityAutonomyMode,
    pub read_envelope: MailboxReadEnvelope,
    pub action_envelope: Option<ChannelIdentityActionEnvelope>,
    pub read_grant: AccessGrant,
    pub action_grant: Option<StandingOutboundGrant>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GraduationScopeKey {
    pub actor_ref: EntityId,
    pub identity_ref: EntityId,
    pub relationship_context: RelationshipContext,
    pub verb_class: String,
    pub counterparty_class: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DraftReviewOutcome {
    ApprovedUntouched,
    ApprovedAmended { edit_distance_millis: u32 },
    Rejected,
    Undone,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraduationEvidence {
    pub scope: GraduationScopeKey,
    pub outcome: DraftReviewOutcome,
    pub receipt_ref: String,
    pub occurred_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraduationOffer {
    pub scope: GraduationScopeKey,
    pub evidence_refs: Vec<String>,
    pub proposed_envelope: ChannelIdentityActionEnvelope,
    pub unchanged_streak: u32,
    pub offered_at: u64,
}

pub(crate) fn invalid_autonomy() -> Error {
    Error::InvalidConsentBound("channel identity autonomy is absent, mismatched, or unauthorized")
}

fn text(value: &Value) -> Result<&str> { value.as_str().ok_or_else(invalid_autonomy) }
fn number(value: &Value) -> Result<u64> { value.as_u64().ok_or_else(invalid_autonomy) }
fn id_value(id: EntityId) -> Value { Value::from(id.to_hex()) }
fn id(value: &Value) -> Result<EntityId> { EntityId::from_hex(text(value)?) }
fn optional_id(value: &Value) -> Result<Option<EntityId>> {
    if value.is_nil() { Ok(None) } else { id(value).map(Some) }
}
fn optional_number(value: &Value) -> Result<Option<u64>> {
    if value.is_nil() { Ok(None) } else { number(value).map(Some) }
}
fn optional_text(value: &Value) -> Result<Option<String>> {
    if value.is_nil() { Ok(None) } else { Ok(Some(text(value)?.to_owned())) }
}
fn array(value: &Value, len: usize) -> Result<&[Value]> {
    value.as_array().filter(|v| v.len() == len).map(Vec::as_slice).ok_or_else(invalid_autonomy)
}
fn context(value: &Value) -> Result<RelationshipContext> {
    RelationshipContext::parse(text(value)?).ok_or_else(invalid_autonomy)
}
fn token(value: &str) -> Result<()> {
    if value.is_empty() || value.trim() != value || value.len() > 512 {
        return Err(invalid_autonomy());
    }
    Ok(())
}
fn encode(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).map_err(|_| invalid_autonomy())?;
    Ok(bytes)
}
fn decode(bytes: &[u8]) -> Result<Value> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_autonomy())?;
    if cursor.position() != bytes.len() as u64 { return Err(invalid_autonomy()); }
    Ok(value)
}
fn key(kind: &str, suffix: &str) -> Vec<u8> {
    format!("channel_identity_autonomy:v1:{kind}:{suffix}").into_bytes()
}
fn address(kind: &str, value: &Value) -> Result<EntityId> {
    let bytes = encode(&Value::Array(vec![Value::from(kind), value.clone()]))?;
    let hash = blake3::hash(&bytes);
    EntityId::from_bytes(hash.as_bytes()[..16].try_into().map_err(|_| invalid_autonomy())?)
}
fn mode_key(identity: EntityId, context: RelationshipContext) -> Vec<u8> {
    key(PREDICATE_AUTONOMY_MODE, &format!("{}:{}", identity.to_hex(), context.as_str()))
}
fn read_value(e: &MailboxReadEnvelope) -> Result<Value> {
    if e.label_allowlist.is_empty() && e.thread_allowlist.is_empty()
        || e.not_before.zip(e.not_after).is_some_and(|(a, b)| a > b)
    { return Err(invalid_autonomy()); }
    for list in [&e.label_allowlist, &e.thread_allowlist] {
        if list.len() > 256 { return Err(invalid_autonomy()); }
        for item in list { token(item)?; }
        if list.iter().collect::<std::collections::BTreeSet<_>>().len() != list.len() {
            return Err(invalid_autonomy());
        }
    }
    Ok(Value::Array(vec![id_value(e.identity_ref),
        Value::Array(e.label_allowlist.iter().cloned().map(Value::from).collect()),
        Value::Array(e.thread_allowlist.iter().cloned().map(Value::from).collect()),
        e.not_before.map_or(Value::Nil, Value::from), e.not_after.map_or(Value::Nil, Value::from)]))
}
fn read_from(value: &Value) -> Result<MailboxReadEnvelope> {
    let v = array(value, 5)?;
    let strings = |v: &Value| -> Result<Vec<String>> {
        v.as_array().ok_or_else(invalid_autonomy)?.iter().map(|v| Ok(text(v)?.to_owned())).collect()
    };
    let e = MailboxReadEnvelope { identity_ref: id(&v[0])?, label_allowlist: strings(&v[1])?,
        thread_allowlist: strings(&v[2])?, not_before: optional_number(&v[3])?, not_after: optional_number(&v[4])? };
    read_value(&e)?;
    Ok(e)
}
fn action_value(e: &ChannelIdentityActionEnvelope) -> Result<Value> {
    if e.max_actions == 0 || e.window_secs == 0 { return Err(invalid_autonomy()); }
    if let Some(c) = &e.counterparty_class { token(c)?; }
    Ok(Value::Array(vec![id_value(e.identity_ref), Value::from(e.relationship_context.as_str()),
        e.counterparty_class.clone().map_or(Value::Nil, Value::from),
        Value::from(e.max_actions), Value::from(e.window_secs)]))
}
fn action_from(value: &Value) -> Result<ChannelIdentityActionEnvelope> {
    let v = array(value, 5)?;
    let e = ChannelIdentityActionEnvelope { identity_ref: id(&v[0])?, relationship_context: context(&v[1])?,
        counterparty_class: optional_text(&v[2])?, max_actions: u32::try_from(number(&v[3])?).map_err(|_| invalid_autonomy())?,
        window_secs: number(&v[4])? };
    action_value(&e)?;
    Ok(e)
}
fn mode_value(m: &ChannelIdentityAutonomyMode) -> Value {
    Value::Array(vec![id_value(m.identity_ref), Value::from(m.relationship_context.as_str()),
        Value::from(m.rung.as_str()), m.read_grant_ref.map_or(Value::Nil, id_value),
        m.action_grant_ref.map_or(Value::Nil, id_value)])
}
fn mode_from(value: &Value) -> Result<ChannelIdentityAutonomyMode> {
    let v = array(value, 5)?;
    Ok(ChannelIdentityAutonomyMode { identity_ref: id(&v[0])?, relationship_context: context(&v[1])?,
        rung: ChannelIdentityAutonomyRung::parse(text(&v[2])?).ok_or_else(invalid_autonomy)?,
        read_grant_ref: optional_id(&v[3])?, action_grant_ref: optional_id(&v[4])? })
}

impl Vault {
    fn autonomy_owner(&self, owner: &AuthenticatedOwner) -> Result<()> {
        self.authenticate_owner(owner.actor(), owner.principal_ref(), true, owner.decision_id()).map(|_| ())
    }

    fn autonomy_row(&self, txn: &heed::RoTxn<'_>, key: &[u8]) -> Result<(EntityId, u64, Value)> {
        let bytes = self.store.vault_meta.get(txn, key)?.ok_or_else(invalid_autonomy)?;
        let value = decode(&bytes)?;
        let v = array(&value, 4)?;
        if number(&v[0])? != CHANNEL_IDENTITY_AUTONOMY_SCHEMA_VERSION { return Err(invalid_autonomy()); }
        Ok((id(&v[1])?, number(&v[2])?, v[3].clone()))
    }

    fn write_autonomy_row(&self, txn: &mut heed::RwTxn<'_>, key: &[u8], actor: EntityId,
        at: u64, value: Value) -> Result<()> {
        let bytes = encode(&Value::Array(vec![Value::from(CHANNEL_IDENTITY_AUTONOMY_SCHEMA_VERSION),
            id_value(actor), Value::from(at), value]))?;
        self.store.vault_meta.put(txn, key, &bytes)?;
        Ok(())
    }

    fn put_autonomy_envelope(&self, txn: &mut heed::RwTxn<'_>, kind: &str,
        value: Value, owner: &AuthenticatedOwner, at: u64) -> Result<EntityId> {
        let reference = address(kind, &value)?;
        let key = key(kind, &reference.to_hex());
        if self.store.vault_meta.get(txn, &key)?.is_some() {
            let (actor, _, old) = self.autonomy_row(txn, &key)?;
            if actor != owner.actor() || old != value { return Err(invalid_autonomy()); }
        } else {
            self.write_autonomy_row(txn, &key, owner.actor(), at, value)?;
        }
        Ok(reference)
    }

    /// Owner-only immutable write. An exact retry returns the same handle.
    pub fn put_mailbox_read_envelope(&self, envelope: MailboxReadEnvelope,
        owner: &AuthenticatedOwner, learned_at: u64) -> Result<EntityId> {
        self.autonomy_owner(owner)?;
        let value = read_value(&envelope)?;
        let mut txn = self.store.env.write_txn()?;
        self.autonomy_identity_actor(&txn, envelope.identity_ref)?;
        let id = self.put_autonomy_envelope(&mut txn, PREDICATE_MAILBOX_READ_ENVELOPE, value, owner, learned_at)?;
        txn.commit()?;
        Ok(id)
    }

    /// Owner-only immutable action bound. This does not mint a grant.
    pub fn put_channel_identity_action_envelope(&self, envelope: ChannelIdentityActionEnvelope,
        owner: &AuthenticatedOwner, learned_at: u64) -> Result<EntityId> {
        self.autonomy_owner(owner)?;
        let value = action_value(&envelope)?;
        let mut txn = self.store.env.write_txn()?;
        self.autonomy_identity_actor(&txn, envelope.identity_ref)?;
        let id = self.put_autonomy_envelope(&mut txn, PREDICATE_ACTION_ENVELOPE, value, owner, learned_at)?;
        txn.commit()?;
        Ok(id)
    }

    pub fn get_mailbox_read_envelope(&self, reference: &EntityId) -> Result<MailboxReadEnvelope> {
        let txn = self.store.env.read_txn()?;
        read_from(&self.autonomy_row(&txn, &key(PREDICATE_MAILBOX_READ_ENVELOPE, &reference.to_hex()))?.2)
    }

    pub fn get_channel_identity_action_envelope(&self, reference: &EntityId) -> Result<ChannelIdentityActionEnvelope> {
        let txn = self.store.env.read_txn()?;
        self.autonomy_action_envelope(&txn, reference)
    }

    pub(crate) fn autonomy_action_envelope(&self, txn: &heed::RoTxn<'_>, reference: &EntityId) -> Result<ChannelIdentityActionEnvelope> {
        let value = self.autonomy_row(txn, &key(PREDICATE_ACTION_ENVELOPE, &reference.to_hex()))?.2;
        if address(PREDICATE_ACTION_ENVELOPE, &value)? != *reference { return Err(invalid_autonomy()); }
        action_from(&value)
    }

    pub(crate) fn autonomy_identity_actor(&self, txn: &heed::RoTxn<'_>, identity: EntityId) -> Result<EntityId> {
        let raw = self.store.entities.get(txn, identity.as_bytes())?.ok_or_else(invalid_autonomy)?;
        let header = EntityMetadataHeader::parse(&raw).ok_or_else(invalid_autonomy)?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY { return Err(invalid_autonomy()); }
        let record = decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        if record.state != ChannelIdentityState::Active { return Err(invalid_autonomy()); }
        if record.is_delegated() {
            crate::channel_identity::admit_channel_identity_transition_in_txn(&self.store, txn, &identity,
                crate::channel_identity::IdentityTransition::Step { prior: &record, next: &record })?;
        }
        match record.binding {
            ChannelIdentityBinding::Actor { actor_ref, .. } => Ok(actor_ref),
            ChannelIdentityBinding::Vault { .. } => Err(invalid_autonomy()),
        }
    }


    /// Read authorization is disjoint from action reservation. Populated
    /// allowlists are conjunctive; empty lists do not widen the other axis.
    pub fn authorize_channel_identity_scoped_read(&self, grant_ref: &EntityId,
        actor_ref: &EntityId, candidate: &MailboxReadCandidate) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&txn, grant_ref.as_bytes())? else { return Ok(false); };
        let header = EntityMetadataHeader::parse(&raw).ok_or_else(invalid_autonomy)?;
        if header.entity_type != crate::registry::ENTITY_TYPE_ACCESS_GRANT { return Ok(false); }
        let grant = crate::access_grant::decode_access_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        let AccessGrantScope::ChannelIdentity { identity_ref, envelope_ref } = grant.scope else { return Ok(false); };
        if identity_ref != candidate.identity_ref || grant.principal_ref != *actor_ref
            || grant.status != AccessGrantStatus::Active || grant.created_at > crate::unix_seconds_now()
            || self.autonomy_identity_actor(&txn, identity_ref)? != *actor_ref { return Ok(false); }
        let (_, at, value) = self.autonomy_row(&txn, &key(PREDICATE_MAILBOX_READ_ENVELOPE, &envelope_ref.to_hex()))?;
        let envelope = read_from(&value)?;
        if at > crate::unix_seconds_now() || envelope.identity_ref != identity_ref
            || address(PREDICATE_MAILBOX_READ_ENVELOPE, &value)? != envelope_ref { return Ok(false); }
        match self.require_autonomy_bound(&txn, &read_bound(*actor_ref, identity_ref, envelope_ref)?) {
            Ok(()) => {}
            Err(Error::InvalidConsentBound(_)) => return Ok(false),
            Err(error) => return Err(error),
        }
        Ok((envelope.label_allowlist.is_empty() || candidate.label.as_ref().is_some_and(|label| envelope.label_allowlist.contains(label)))
            && (envelope.thread_allowlist.is_empty() || candidate.thread_ref.as_ref().is_some_and(|thread| envelope.thread_allowlist.contains(thread)))
            && envelope.not_before.is_none_or(|at| candidate.occurred_at >= at)
            && envelope.not_after.is_none_or(|at| candidate.occurred_at <= at))
    }

    /// Authenticated atomic apply. Exact replay is read-only, including receipts.
    /// A mismatch or revoked authority is an error, never an implicit re-mint.
    pub fn apply_channel_identity_autonomy(&self, desired: &ChannelIdentityAutonomyRequest,
        owner: &AuthenticatedOwner) -> Result<ChannelIdentityAutonomyState> {
        self.autonomy_owner(owner)?;
        let now = crate::unix_seconds_now();
        let mut txn = self.store.env.write_txn()?;
        let identity = desired.read_envelope.identity_ref;
        if self.autonomy_identity_actor(&txn, identity)? != desired.actor_ref { return Err(invalid_autonomy()); }
        let mkey = mode_key(identity, desired.relationship_context);
        if self.store.vault_meta.get(&txn, &mkey)?.is_some() {
            return self.verify_autonomy_in_txn(&txn, desired, owner, now);
        }
        let read_ref = self.put_autonomy_envelope(&mut txn, PREDICATE_MAILBOX_READ_ENVELOPE,
            read_value(&desired.read_envelope)?, owner, now)?;
        let read_bound = read_bound(desired.actor_ref, identity, read_ref)?;
        let read_grant_ref = address("read_grant", &Value::from(read_bound.digest().to_hex()))?;
        let read_grant = AccessGrant { principal_ref: desired.actor_ref,
            scope: AccessGrantScope::ChannelIdentity { identity_ref: identity, envelope_ref: read_ref },
            capability: AccessGrantCapability::ChannelIdentityScopedRead, status: AccessGrantStatus::Active,
            created_at: now, revoked_at: None };
        if let Some(raw) = self.store.entities.get(&txn, read_grant_ref.as_bytes())? {
            let header = EntityMetadataHeader::parse(&raw).ok_or_else(invalid_autonomy)?;
            if header.entity_type != crate::registry::ENTITY_TYPE_ACCESS_GRANT { return Err(invalid_autonomy()); }
            let existing = crate::access_grant::decode_access_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if existing.scope != read_grant.scope || existing.principal_ref != desired.actor_ref
                || existing.status != AccessGrantStatus::Active { return Err(invalid_autonomy()); }
            self.require_autonomy_bound(&txn, &read_bound)?;
        } else {
            self.create_standing_grant_in_txn(&mut txn, owner, read_bound)?;
            self.apply_access_grant_body(&mut txn, &read_grant_ref, now,
                crate::access_grant::encode_access_grant_body(&read_grant)?)?;
        }
        let action_grant_ref = match (desired.rung.verb(), &desired.action_envelope) {
            (None, None) => None,
            (Some(verb), Some(envelope)) => {
                if envelope.identity_ref != identity || envelope.relationship_context != desired.relationship_context {
                    return Err(invalid_autonomy());
                }
                let envelope_ref = self.put_autonomy_envelope(&mut txn, PREDICATE_ACTION_ENVELOPE,
                    action_value(envelope)?, owner, now)?;
                let bound = action_bound(desired.actor_ref, envelope_ref, envelope, verb)?;
                let receipt = self.create_standing_grant_in_txn(&mut txn, owner, bound.clone())?;
                let grant_ref = address("action_grant", &Value::from(bound.digest().to_hex()))?;
                if self.store.entities.get(&txn, grant_ref.as_bytes())?.is_some() { return Err(invalid_autonomy()); }
                let grant = StandingOutboundGrant { principal_ref: desired.actor_ref.to_hex(),
                    origin_component_id: "channel_identity.autonomy".to_owned(), origin_action_id: "apply".to_owned(),
                    origin_receipt_ref: Some(receipt.decision_id().to_hex()),
                    scope: StandingOutboundGrantScope::ChannelIdentityEnvelope { identity_ref: identity, envelope_ref, verb_class: verb.to_owned() },
                    status: StandingOutboundGrantStatus::Active, created_at: now, revoked_at: None, last_used_at: None,
                    binding_diff_handle: bound.digest().as_bytes().to_vec(),
                    read_frontier_hash: crate::gate::resolve_policy_manifest(&self.store, &txn)?.read_frontier_hash()? };
                self.apply_standing_outbound_grant_body(&mut txn, &grant_ref, now,
                    crate::outbound_grant::encode_standing_outbound_grant_body(&grant)?)?;
                Some(grant_ref)
            }
            _ => return Err(invalid_autonomy()),
        };
        let mode = ChannelIdentityAutonomyMode { identity_ref: identity,
            relationship_context: desired.relationship_context, rung: desired.rung,
            read_grant_ref: Some(read_grant_ref), action_grant_ref };
        self.write_autonomy_row(&mut txn, &mkey, owner.actor(), now, mode_value(&mode))?;
        let state = self.verify_autonomy_in_txn(&txn, desired, owner, now)?;
        txn.commit()?;
        Ok(state)
    }


    /// Mints one exact action bound through unified owner consent. Offers do
    /// not call this door. Reusing a live exact grant is read-only; revocation
    /// cannot be undone by an idempotent retry.
    pub fn mint_channel_identity_action_grant(&self, envelope_ref: &EntityId,
        verb_class: &str, owner: &AuthenticatedOwner) -> Result<EntityId> {
        self.autonomy_owner(owner)?;
        if !matches!(verb_class, "mail.draft" | "mail.send") { return Err(invalid_autonomy()); }
        let now = crate::unix_seconds_now();
        let mut txn = self.store.env.write_txn()?;
        let (writer, at, _) = self.autonomy_row(&txn, &key(PREDICATE_ACTION_ENVELOPE, &envelope_ref.to_hex()))?;
        if writer != owner.actor() || at > now { return Err(invalid_autonomy()); }
        let envelope = self.autonomy_action_envelope(&txn, envelope_ref)?;
        let actor = self.autonomy_identity_actor(&txn, envelope.identity_ref)?;
        let bound = action_bound(actor, *envelope_ref, &envelope, verb_class)?;
        let reference = address("action_grant", &Value::from(bound.digest().to_hex()))?;
        if let Some(grant) = standing_outbound_grant_in_txn(&self.store, &txn, &reference)? {
            self.validate_autonomy_action(&txn, &grant, now)?;
            if grant.binding_diff_handle != bound.digest().as_bytes().to_vec() { return Err(invalid_autonomy()); }
            return Ok(reference);
        }
        let receipt = self.create_standing_grant_in_txn(&mut txn, owner, bound.clone())?;
        let grant = StandingOutboundGrant { principal_ref: actor.to_hex(),
            origin_component_id: "channel_identity.autonomy".to_owned(), origin_action_id: "owner_grant".to_owned(),
            origin_receipt_ref: Some(receipt.decision_id().to_hex()),
            scope: StandingOutboundGrantScope::ChannelIdentityEnvelope { identity_ref: envelope.identity_ref,
                envelope_ref: *envelope_ref, verb_class: verb_class.to_owned() },
            status: StandingOutboundGrantStatus::Active, created_at: now, revoked_at: None, last_used_at: None,
            binding_diff_handle: bound.digest().as_bytes().to_vec(),
            read_frontier_hash: crate::gate::resolve_policy_manifest(&self.store, &txn)?.read_frontier_hash()? };
        self.apply_standing_outbound_grant_body(&mut txn, &reference, now,
            crate::outbound_grant::encode_standing_outbound_grant_body(&grant)?)?;
        txn.commit()?;
        Ok(reference)
    }

    /// Authenticated, read-only exact verification against live authority.
    pub fn verify_channel_identity_autonomy(&self, desired: &ChannelIdentityAutonomyRequest,
        owner: &AuthenticatedOwner) -> Result<ChannelIdentityAutonomyState> {
        self.autonomy_owner(owner)?;
        let txn = self.store.env.read_txn()?;
        self.verify_autonomy_in_txn(&txn, desired, owner, crate::unix_seconds_now())
    }

    fn verify_autonomy_in_txn(&self, txn: &heed::RoTxn<'_>, desired: &ChannelIdentityAutonomyRequest,
        owner: &AuthenticatedOwner, now: u64) -> Result<ChannelIdentityAutonomyState> {
        let (writer, at, value) = self.autonomy_row(txn, &mode_key(desired.read_envelope.identity_ref, desired.relationship_context))?;
        if writer != owner.actor() || at > now { return Err(invalid_autonomy()); }
        let state = self.autonomy_state(txn, mode_from(&value)?, now)?;
        if state.mode.identity_ref != desired.read_envelope.identity_ref
            || state.mode.relationship_context != desired.relationship_context
            || state.mode.rung != desired.rung || state.read_grant.principal_ref != desired.actor_ref
            || state.read_envelope != desired.read_envelope || state.action_envelope != desired.action_envelope
        { return Err(invalid_autonomy()); }
        Ok(state)
    }

    /// Owner may select any rung supported by live exact grants, for any face.
    pub fn set_channel_identity_autonomy_mode(&self, mode: ChannelIdentityAutonomyMode,
        owner: &AuthenticatedOwner, learned_at: u64) -> Result<EntityId> {
        self.autonomy_owner(owner)?;
        let mut txn = self.store.env.write_txn()?;
        if learned_at > crate::unix_seconds_now() { return Err(invalid_autonomy()); }
        self.autonomy_state(&txn, mode.clone(), crate::unix_seconds_now())?;
        let key = mode_key(mode.identity_ref, mode.relationship_context);
        let value = mode_value(&mode);
        if self.store.vault_meta.get(&txn, &key)?.is_some() {
            let (writer, at, old) = self.autonomy_row(&txn, &key)?;
            if writer != owner.actor() || learned_at < at { return Err(invalid_autonomy()); }
            if old == value { return address(PREDICATE_AUTONOMY_MODE, &value); }
        }
        self.write_autonomy_row(&mut txn, &key, owner.actor(), learned_at, value.clone())?;
        txn.commit()?;
        address(PREDICATE_AUTONOMY_MODE, &value)
    }

    /// Missing, expired, revoked, stale-policy, or mismatched grants fail closed.
    pub fn resolve_channel_identity_autonomy_mode(&self, identity_ref: &EntityId,
        context: &RelationshipContext, at: u64) -> Result<ChannelIdentityAutonomyMode> {
        let txn = self.store.env.read_txn()?;
        self.autonomy_mode_in_txn(&txn, *identity_ref, *context, at.min(crate::unix_seconds_now()))
    }

    pub(crate) fn autonomy_mode_in_txn(&self, txn: &heed::RoTxn<'_>, identity: EntityId,
        context: RelationshipContext, at: u64) -> Result<ChannelIdentityAutonomyMode> {
        let (_, learned_at, value) = self.autonomy_row(txn, &mode_key(identity, context))?;
        let mode = mode_from(&value)?;
        if learned_at > at || mode.identity_ref != identity || mode.relationship_context != context { return Err(invalid_autonomy()); }
        Ok(self.autonomy_state(txn, mode, at)?.mode)
    }

    fn autonomy_state(&self, txn: &heed::RoTxn<'_>, mode: ChannelIdentityAutonomyMode,
        at: u64) -> Result<ChannelIdentityAutonomyState> {
        let actor = self.autonomy_identity_actor(txn, mode.identity_ref)?;
        let reference = mode.read_grant_ref.ok_or_else(invalid_autonomy)?;
        let raw = self.store.entities.get(txn, reference.as_bytes())?.ok_or_else(invalid_autonomy)?;
        let header = EntityMetadataHeader::parse(&raw).ok_or_else(invalid_autonomy)?;
        if header.entity_type != crate::registry::ENTITY_TYPE_ACCESS_GRANT { return Err(invalid_autonomy()); }
        let grant = crate::access_grant::decode_access_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        let AccessGrantScope::ChannelIdentity { identity_ref, envelope_ref } = grant.scope else { return Err(invalid_autonomy()); };
        if identity_ref != mode.identity_ref || grant.principal_ref != actor
            || grant.status != AccessGrantStatus::Active || grant.created_at > at { return Err(invalid_autonomy()); }
        let (_, learned_at, value) = self.autonomy_row(txn, &key(PREDICATE_MAILBOX_READ_ENVELOPE, &envelope_ref.to_hex()))?;
        let read_envelope = read_from(&value)?;
        if address(PREDICATE_MAILBOX_READ_ENVELOPE, &value)? != envelope_ref || learned_at > at
            || read_envelope.identity_ref != identity_ref { return Err(invalid_autonomy()); }
        self.require_autonomy_bound(txn, &read_bound(actor, identity_ref, envelope_ref)?)?;
        let (action_grant, action_envelope) = match (mode.rung.verb(), mode.action_grant_ref) {
            (None, None) => (None, None),
            (Some(verb), Some(reference)) => {
                let action = standing_outbound_grant_in_txn(&self.store, txn, &reference)?.ok_or_else(invalid_autonomy)?;
                let envelope = self.validate_autonomy_action(txn, &action, at)?;
                if envelope.identity_ref != identity_ref || envelope.relationship_context != mode.relationship_context
                    || !matches!(&action.scope, StandingOutboundGrantScope::ChannelIdentityEnvelope { verb_class, .. } if verb_class == verb)
                { return Err(invalid_autonomy()); }
                (Some(action), Some(envelope))
            }
            _ => return Err(invalid_autonomy()),
        };
        Ok(ChannelIdentityAutonomyState { mode, read_envelope, action_envelope, read_grant: grant, action_grant })
    }

    pub(crate) fn require_autonomy_bound(&self, txn: &heed::RoTxn<'_>, bound: &GrantBound) -> Result<()> {
        if !self.active_standing_consent_grants_in_txn(txn)?.iter().any(|g| g.bound() == bound) {
            return Err(invalid_autonomy());
        }
        Ok(())
    }

    pub(crate) fn validate_autonomy_action(&self, txn: &heed::RoTxn<'_>, grant: &StandingOutboundGrant,
        at: u64) -> Result<ChannelIdentityActionEnvelope> {
        let StandingOutboundGrantScope::ChannelIdentityEnvelope { identity_ref, envelope_ref, verb_class } = &grant.scope
            else { return Err(invalid_autonomy()); };
        let actor = self.autonomy_identity_actor(txn, *identity_ref)?;
        if self.autonomy_row(txn, &key(PREDICATE_ACTION_ENVELOPE, &envelope_ref.to_hex()))?.1 > at {
            return Err(invalid_autonomy());
        }
        let envelope = self.autonomy_action_envelope(txn, envelope_ref)?;
        let bound = action_bound(actor, *envelope_ref, &envelope, verb_class)?;
        if envelope.identity_ref != *identity_ref || grant.principal_ref != actor.to_hex() || grant.created_at > at
            || grant.binding_diff_handle != bound.digest().as_bytes().to_vec()
            || !grant.is_active_under_policy(&crate::gate::resolve_policy_manifest(&self.store, txn)?.read_frontier_hash()?)
        { return Err(invalid_autonomy()); }
        self.require_autonomy_bound(txn, &bound)?;
        Ok(envelope)
    }
}

fn read_bound(actor: EntityId, identity: EntityId, envelope: EntityId) -> Result<GrantBound> {
    GrantBound::disclosure(AudienceBound::singleton(actor.to_hex())?,
        DisclosureClass::new("channel_identity.scoped_read")?,
        DisclosureEnvelope::new([format!("identity:{}", identity.to_hex()), format!("envelope:{}", envelope.to_hex())])?)
}
fn action_bound(actor: EntityId, reference: EntityId, e: &ChannelIdentityActionEnvelope, verb: &str) -> Result<GrantBound> {
    GrantBound::action(ActorBound::new(actor.to_hex())?, ActionClass::new(verb)?,
        ActionEnvelope::new([format!("identity:{}", e.identity_ref.to_hex()), format!("envelope:{}", reference.to_hex()),
            format!("context:{}", e.relationship_context.as_str()), format!("window_secs:{}", e.window_secs)])?
            .with_target(e.identity_ref.to_hex())?.with_budget(u64::from(e.max_actions)).with_receipt_required(true))
}

fn scope_value(scope: &GraduationScopeKey) -> Result<Value> {
    if !matches!(scope.verb_class.as_str(), "mail.draft" | "mail.send") { return Err(invalid_autonomy()); }
    if let Some(c) = &scope.counterparty_class { token(c)?; }
    Ok(Value::Array(vec![id_value(scope.actor_ref), id_value(scope.identity_ref),
        Value::from(scope.relationship_context.as_str()), Value::from(scope.verb_class.clone()),
        scope.counterparty_class.clone().map_or(Value::Nil, Value::from)]))
}

impl Vault {
    /// Attributed evidence of a persisted outbound review, never caller proof.
    /// Duplicate receipts are rejected; corrections need their own review receipt.
    /// `WriteActor` supplies attribution only, not review authentication.
    pub fn record_graduation_evidence(&self, evidence: GraduationEvidence, actor: &WriteActor) -> Result<EntityId> {
        if actor.entity_ref() != evidence.scope.actor_ref || actor.actor_class() != crate::edge::EdgeActorClass::Agent {
            return Err(invalid_autonomy());
        }
        self.record_graduation_evidence_by(evidence, actor.entity_ref(), false)
    }

    /// Owner-attributed review/correction. A caller-asserted Human WriteActor
    /// is not owner authentication and cannot use this exception.
    pub fn record_graduation_evidence_as_owner(&self, evidence: GraduationEvidence,
        owner: &AuthenticatedOwner) -> Result<EntityId> {
        self.autonomy_owner(owner)?;
        self.record_graduation_evidence_by(evidence, owner.actor(), true)
    }

    fn record_graduation_evidence_by(&self, evidence: GraduationEvidence, writer: EntityId,
        owner_authenticated: bool) -> Result<EntityId> {
        let scope = scope_value(&evidence.scope)?;
        token(&evidence.receipt_ref)?;
        if evidence.occurred_at > crate::unix_seconds_now() { return Err(invalid_autonomy()); }
        let (task_ref, outcome, distance) = self.validate_graduation_review(&evidence)?;
        let mut txn = self.store.env.write_txn()?;
        if self.autonomy_identity_actor(&txn, evidence.scope.identity_ref)? != evidence.scope.actor_ref {
            return Err(invalid_autonomy());
        }
        let prefix = key(PREDICATE_GRADUATION_EVIDENCE, &address("scope", &scope)?.to_hex());
        let reference = address("evidence", &Value::Array(vec![scope, Value::from(evidence.receipt_ref.clone())]))?;
        let mut key = prefix;
        key.extend_from_slice(reference.as_bytes());
        let value = Value::Array(vec![Value::from(evidence.receipt_ref), Value::from(outcome), distance,
            id_value(evidence.scope.actor_ref), Value::from(owner_authenticated), id_value(task_ref)]);
        if self.store.vault_meta.get(&txn, &key)?.is_some() { return Err(invalid_autonomy()); }
        self.write_autonomy_row(&mut txn, &key, writer, evidence.occurred_at, value)?;
        txn.commit()?;
        Ok(reference)
    }

    // A transport outcome alone is not a draft review. Eligible outbound rows
    // carry an explicit review_outcome and the exact graduation scope fields.
    // Resolve before opening the write txn: the receipt door owns its read txns
    // and send audit receipts are append-only. No actor/time filter may hide an
    // ambiguous receipt id; all durable outbound rows must remain visible.
    fn validate_graduation_review(&self, evidence: &GraduationEvidence) -> Result<(EntityId, &'static str, Value)> {
        let scan = self.scan_receipts(
            ReceiptQuery::new(crate::receipt::MAX_RECEIPT_QUERY_SCAN).with_kind(ReceiptKind::Outbound)
        )?;
        // Continuations describe omitted data, not resumable snapshot pages.
        // Without a bounded resume door, neither a missing id nor one visible
        // match proves uniqueness. Reject source AND result truncation.
        if !scan.complete { return Err(invalid_autonomy()); }
        let mut matches = scan.records.iter().filter(|r| r.receipt_id == evidence.receipt_ref);
        let receipt = matches.next().ok_or_else(invalid_autonomy)?;
        if matches.next().is_some() { return Err(invalid_autonomy()); }
        let field = |key: &str| receipt.fields.get(key).map(String::as_str);
        let task_ref = field(crate::receipt::FIELD_TASK_REF)
            .and_then(|value| EntityId::from_hex(value).ok()).ok_or_else(invalid_autonomy)?;
        let (outcome, distance) = match &evidence.outcome {
            DraftReviewOutcome::ApprovedUntouched => ("approved_untouched", None),
            DraftReviewOutcome::ApprovedAmended { edit_distance_millis } => ("approved_amended", Some(*edit_distance_millis)),
            DraftReviewOutcome::Rejected => ("rejected", None),
            DraftReviewOutcome::Undone => ("undone", None),
        };
        if receipt.actor.as_deref() != Some(evidence.scope.actor_ref.to_hex().as_str())
            || receipt.occurred_at != evidence.occurred_at
            || field("channel_identity_ref") != Some(evidence.scope.identity_ref.to_hex().as_str())
            || field("relationship_context") != Some(evidence.scope.relationship_context.as_str())
            || field("verb_class") != Some(evidence.scope.verb_class.as_str())
            || field("counterparty_class") != evidence.scope.counterparty_class.as_deref()
            || field("review_outcome") != Some(outcome)
            || field("edit_distance_millis") != distance.map(|d| d.to_string()).as_deref()
        { return Err(invalid_autonomy()); }
        Ok((task_ref, outcome, distance.map_or(Value::Nil, Value::from)))
    }

    /// Pure evaluation: zero selects the pinned default of twelve. The proposal
    /// retains the existing draft volume bound; acceptance must use owner consent.
    /// Each task contributes only its latest `(occurred_at, receipt_ref)` review,
    /// independent of admission order. A later correction replaces its old outcome.
    pub fn evaluate_graduation_offer(&self, scope: &GraduationScopeKey, unchanged_streak: u32,
        now: u64) -> Result<Option<GraduationOffer>> {
        let threshold = if unchanged_streak == 0 { DEFAULT_GRADUATION_UNCHANGED_STREAK } else { unchanged_streak };
        let prefix = key(PREDICATE_GRADUATION_EVIDENCE, &address("scope", &scope_value(scope)?)?.to_hex());
        let txn = self.store.env.read_txn()?;
        let now = now.min(crate::unix_seconds_now());
        let mode = self.autonomy_mode_in_txn(&txn, scope.identity_ref, scope.relationship_context, now)?;
        if !matches!(mode.rung, ChannelIdentityAutonomyRung::DraftOnly | ChannelIdentityAutonomyRung::SendWithApproval)
            || scope.verb_class != "mail.send" || self.autonomy_identity_actor(&txn, scope.identity_ref)? != scope.actor_ref
        { return Ok(None); }
        let state = self.autonomy_state(&txn, mode, now)?;
        let proposed_envelope = state.action_envelope.ok_or_else(invalid_autonomy)?;
        if proposed_envelope.counterparty_class != scope.counterparty_class { return Ok(None); }
        let mut rows = Vec::new();
        for entry in self.store.vault_meta.prefix_iter(&txn, &prefix)? {
            let (key, _) = entry?;
            let (actor, at, value) = self.autonomy_row(&txn, &key)?;
            let v = array(&value, 6)?;
            let task_ref = id(&v[5])?;
            let owner_authenticated = v[4].as_bool().ok_or_else(invalid_autonomy)?;
            if id(&v[3])? != scope.actor_ref || actor != scope.actor_ref && !owner_authenticated {
                return Err(invalid_autonomy());
            }
            if at <= now { rows.push((at, text(&v[0])?.to_owned(), text(&v[1])?.to_owned(), task_ref)); }
        }
        rows.sort();
        let mut evidence_refs = Vec::new();
        let mut seen_tasks = std::collections::BTreeSet::new();
        for (_, reference, outcome, task_ref) in rows.into_iter().rev() {
            if !seen_tasks.insert(task_ref) { continue; }
            if outcome != "approved_untouched" { break; }
            evidence_refs.push(reference);
        }
        let streak = u32::try_from(evidence_refs.len()).map_err(|_| invalid_autonomy())?;
        if streak < threshold { return Ok(None); }
        evidence_refs.reverse();
        Ok(Some(GraduationOffer { scope: scope.clone(), evidence_refs, proposed_envelope,
            unchanged_streak: streak, offered_at: now }))
    }
}

#[cfg(test)]
mod tests;
