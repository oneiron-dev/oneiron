//! Scoped-read authorization, the atomic autonomy apply, action-grant mint, verify, mode set/resolve, live-state resolution and bound/action validation.

use rmpv::Value;

use crate::Vault;
use crate::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::channel_identity_selection::RelationshipContext;
use crate::consent::{AuthenticatedOwner, GrantBound};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::outbound_grant::{
    StandingOutboundGrant, StandingOutboundGrantScope, StandingOutboundGrantStatus,
    standing_outbound_grant_in_txn,
};

use super::codec::{
    action_bound, action_value, address, key, mode_from, mode_key, mode_value, read_bound,
    read_from, read_value,
};
use super::invalid_autonomy;
use super::types::{
    ChannelIdentityActionEnvelope, ChannelIdentityAutonomyMode, ChannelIdentityAutonomyRequest,
    ChannelIdentityAutonomyState, MailboxReadCandidate, PREDICATE_ACTION_ENVELOPE,
    PREDICATE_AUTONOMY_MODE, PREDICATE_MAILBOX_READ_ENVELOPE,
};

impl Vault {
    /// Read authorization is disjoint from action reservation. Populated
    /// allowlists are conjunctive; empty lists do not widen the other axis.
    pub fn authorize_channel_identity_scoped_read(
        &self,
        grant_ref: &EntityId,
        actor_ref: &EntityId,
        candidate: &MailboxReadCandidate,
    ) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&txn, grant_ref.as_bytes())? else {
            return Ok(false);
        };
        let header = EntityMetadataHeader::parse(&raw).ok_or_else(invalid_autonomy)?;
        if header.entity_type != crate::registry::ENTITY_TYPE_ACCESS_GRANT {
            return Ok(false);
        }
        let grant =
            crate::access_grant::decode_access_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        let AccessGrantScope::ChannelIdentity {
            identity_ref,
            envelope_ref,
        } = grant.scope
        else {
            return Ok(false);
        };
        if identity_ref != candidate.identity_ref
            || grant.principal_ref != *actor_ref
            || grant.status != AccessGrantStatus::Active
            || grant.created_at > crate::unix_seconds_now()
            || self.autonomy_identity_actor(&txn, identity_ref)? != *actor_ref
        {
            return Ok(false);
        }
        let (_, at, value) = self.autonomy_row(
            &txn,
            &key(PREDICATE_MAILBOX_READ_ENVELOPE, &envelope_ref.to_hex()),
        )?;
        let envelope = read_from(&value)?;
        if at > crate::unix_seconds_now()
            || envelope.identity_ref != identity_ref
            || address(PREDICATE_MAILBOX_READ_ENVELOPE, &value)? != envelope_ref
        {
            return Ok(false);
        }
        match self
            .require_autonomy_bound(&txn, &read_bound(*actor_ref, identity_ref, envelope_ref)?)
        {
            Ok(()) => {}
            Err(Error::InvalidConsentBound(_)) => return Ok(false),
            Err(error) => return Err(error),
        }
        Ok((envelope.label_allowlist.is_empty()
            || candidate
                .label
                .as_ref()
                .is_some_and(|label| envelope.label_allowlist.contains(label)))
            && (envelope.thread_allowlist.is_empty()
                || candidate
                    .thread_ref
                    .as_ref()
                    .is_some_and(|thread| envelope.thread_allowlist.contains(thread)))
            && envelope
                .not_before
                .is_none_or(|at| candidate.occurred_at >= at)
            && envelope
                .not_after
                .is_none_or(|at| candidate.occurred_at <= at))
    }

    /// Authenticated atomic apply. Exact replay is read-only, including receipts.
    /// A mismatch or revoked authority is an error, never an implicit re-mint.
    pub fn apply_channel_identity_autonomy(
        &self,
        desired: &ChannelIdentityAutonomyRequest,
        owner: &AuthenticatedOwner,
    ) -> Result<ChannelIdentityAutonomyState> {
        self.autonomy_owner(owner)?;
        let now = crate::unix_seconds_now();
        let mut txn = self.store.env.write_txn()?;
        let identity = desired.read_envelope.identity_ref;
        if self.autonomy_identity_actor(&txn, identity)? != desired.actor_ref {
            return Err(invalid_autonomy());
        }
        let mkey = mode_key(identity, desired.relationship_context);
        if self.store.vault_meta.get(&txn, &mkey)?.is_some() {
            return self.verify_autonomy_in_txn(&txn, desired, owner, now);
        }
        let read_ref = self.put_autonomy_envelope(
            &mut txn,
            PREDICATE_MAILBOX_READ_ENVELOPE,
            read_value(&desired.read_envelope)?,
            owner,
            now,
        )?;
        let read_bound = read_bound(desired.actor_ref, identity, read_ref)?;
        let read_grant_ref = address("read_grant", &Value::from(read_bound.digest().to_hex()))?;
        let read_grant = AccessGrant {
            principal_ref: desired.actor_ref,
            scope: AccessGrantScope::ChannelIdentity {
                identity_ref: identity,
                envelope_ref: read_ref,
            },
            capability: AccessGrantCapability::ChannelIdentityScopedRead,
            status: AccessGrantStatus::Active,
            created_at: now,
            revoked_at: None,
        };
        if let Some(raw) = self.store.entities.get(&txn, read_grant_ref.as_bytes())? {
            let header = EntityMetadataHeader::parse(&raw).ok_or_else(invalid_autonomy)?;
            if header.entity_type != crate::registry::ENTITY_TYPE_ACCESS_GRANT {
                return Err(invalid_autonomy());
            }
            let existing =
                crate::access_grant::decode_access_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if existing.scope != read_grant.scope
                || existing.principal_ref != desired.actor_ref
                || existing.status != AccessGrantStatus::Active
            {
                return Err(invalid_autonomy());
            }
            self.require_autonomy_bound(&txn, &read_bound)?;
        } else {
            self.create_standing_grant_in_txn(&mut txn, owner, read_bound)?;
            self.apply_access_grant_body(
                &mut txn,
                &read_grant_ref,
                now,
                crate::access_grant::encode_access_grant_body(&read_grant)?,
            )?;
        }
        let action_grant_ref = match (desired.rung.verb(), &desired.action_envelope) {
            (None, None) => None,
            (Some(verb), Some(envelope)) => {
                if envelope.identity_ref != identity
                    || envelope.relationship_context != desired.relationship_context
                {
                    return Err(invalid_autonomy());
                }
                let envelope_ref = self.put_autonomy_envelope(
                    &mut txn,
                    PREDICATE_ACTION_ENVELOPE,
                    action_value(envelope)?,
                    owner,
                    now,
                )?;
                let bound = action_bound(desired.actor_ref, envelope_ref, envelope, verb)?;
                let receipt = self.create_standing_grant_in_txn(&mut txn, owner, bound.clone())?;
                let grant_ref = address("action_grant", &Value::from(bound.digest().to_hex()))?;
                if self
                    .store
                    .entities
                    .get(&txn, grant_ref.as_bytes())?
                    .is_some()
                {
                    return Err(invalid_autonomy());
                }
                let grant = StandingOutboundGrant {
                    principal_ref: desired.actor_ref.to_hex(),
                    origin_component_id: "channel_identity.autonomy".to_owned(),
                    origin_action_id: "apply".to_owned(),
                    origin_receipt_ref: Some(receipt.decision_id().to_hex()),
                    scope: StandingOutboundGrantScope::ChannelIdentityEnvelope {
                        identity_ref: identity,
                        envelope_ref,
                        verb_class: verb.to_owned(),
                    },
                    status: StandingOutboundGrantStatus::Active,
                    created_at: now,
                    revoked_at: None,
                    last_used_at: None,
                    binding_diff_handle: bound.digest().as_bytes().to_vec(),
                    read_frontier_hash: crate::gate::resolve_policy_manifest(&self.store, &txn)?
                        .read_frontier_hash()?,
                };
                self.apply_standing_outbound_grant_body(
                    &mut txn,
                    &grant_ref,
                    now,
                    crate::outbound_grant::encode_standing_outbound_grant_body(&grant)?,
                )?;
                Some(grant_ref)
            }
            _ => return Err(invalid_autonomy()),
        };
        let mode = ChannelIdentityAutonomyMode {
            identity_ref: identity,
            relationship_context: desired.relationship_context,
            rung: desired.rung,
            read_grant_ref: Some(read_grant_ref),
            action_grant_ref,
        };
        self.write_autonomy_row(&mut txn, &mkey, owner.actor(), now, mode_value(&mode))?;
        let state = self.verify_autonomy_in_txn(&txn, desired, owner, now)?;
        txn.commit()?;
        Ok(state)
    }

    /// Mints one exact action bound through unified owner consent. Offers do
    /// not call this door. Reusing a live exact grant is read-only; revocation
    /// cannot be undone by an idempotent retry.
    pub fn mint_channel_identity_action_grant(
        &self,
        envelope_ref: &EntityId,
        verb_class: &str,
        owner: &AuthenticatedOwner,
    ) -> Result<EntityId> {
        self.autonomy_owner(owner)?;
        if !matches!(verb_class, "mail.draft" | "mail.send") {
            return Err(invalid_autonomy());
        }
        let now = crate::unix_seconds_now();
        let mut txn = self.store.env.write_txn()?;
        let (writer, at, _) = self.autonomy_row(
            &txn,
            &key(PREDICATE_ACTION_ENVELOPE, &envelope_ref.to_hex()),
        )?;
        if writer != owner.actor() || at > now {
            return Err(invalid_autonomy());
        }
        let envelope = self.autonomy_action_envelope(&txn, envelope_ref)?;
        let actor = self.autonomy_identity_actor(&txn, envelope.identity_ref)?;
        let bound = action_bound(actor, *envelope_ref, &envelope, verb_class)?;
        let reference = address("action_grant", &Value::from(bound.digest().to_hex()))?;
        if let Some(grant) = standing_outbound_grant_in_txn(&self.store, &txn, &reference)? {
            self.validate_autonomy_action(&txn, &grant, now)?;
            if grant.binding_diff_handle != bound.digest().as_bytes().to_vec() {
                return Err(invalid_autonomy());
            }
            return Ok(reference);
        }
        let receipt = self.create_standing_grant_in_txn(&mut txn, owner, bound.clone())?;
        let grant = StandingOutboundGrant {
            principal_ref: actor.to_hex(),
            origin_component_id: "channel_identity.autonomy".to_owned(),
            origin_action_id: "owner_grant".to_owned(),
            origin_receipt_ref: Some(receipt.decision_id().to_hex()),
            scope: StandingOutboundGrantScope::ChannelIdentityEnvelope {
                identity_ref: envelope.identity_ref,
                envelope_ref: *envelope_ref,
                verb_class: verb_class.to_owned(),
            },
            status: StandingOutboundGrantStatus::Active,
            created_at: now,
            revoked_at: None,
            last_used_at: None,
            binding_diff_handle: bound.digest().as_bytes().to_vec(),
            read_frontier_hash: crate::gate::resolve_policy_manifest(&self.store, &txn)?
                .read_frontier_hash()?,
        };
        self.apply_standing_outbound_grant_body(
            &mut txn,
            &reference,
            now,
            crate::outbound_grant::encode_standing_outbound_grant_body(&grant)?,
        )?;
        txn.commit()?;
        Ok(reference)
    }

    /// Authenticated, read-only exact verification against live authority.
    pub fn verify_channel_identity_autonomy(
        &self,
        desired: &ChannelIdentityAutonomyRequest,
        owner: &AuthenticatedOwner,
    ) -> Result<ChannelIdentityAutonomyState> {
        self.autonomy_owner(owner)?;
        let txn = self.store.env.read_txn()?;
        self.verify_autonomy_in_txn(&txn, desired, owner, crate::unix_seconds_now())
    }

    fn verify_autonomy_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        desired: &ChannelIdentityAutonomyRequest,
        owner: &AuthenticatedOwner,
        now: u64,
    ) -> Result<ChannelIdentityAutonomyState> {
        let (writer, at, value) = self.autonomy_row(
            txn,
            &mode_key(
                desired.read_envelope.identity_ref,
                desired.relationship_context,
            ),
        )?;
        if writer != owner.actor() || at > now {
            return Err(invalid_autonomy());
        }
        let state = self.autonomy_state(txn, mode_from(&value)?, now)?;
        if state.mode.identity_ref != desired.read_envelope.identity_ref
            || state.mode.relationship_context != desired.relationship_context
            || state.mode.rung != desired.rung
            || state.read_grant.principal_ref != desired.actor_ref
            || state.read_envelope != desired.read_envelope
            || state.action_envelope != desired.action_envelope
        {
            return Err(invalid_autonomy());
        }
        Ok(state)
    }

    /// Owner may select any rung supported by live exact grants, for any face.
    pub fn set_channel_identity_autonomy_mode(
        &self,
        mode: ChannelIdentityAutonomyMode,
        owner: &AuthenticatedOwner,
        learned_at: u64,
    ) -> Result<EntityId> {
        self.autonomy_owner(owner)?;
        let mut txn = self.store.env.write_txn()?;
        if learned_at > crate::unix_seconds_now() {
            return Err(invalid_autonomy());
        }
        self.autonomy_state(&txn, mode.clone(), crate::unix_seconds_now())?;
        let key = mode_key(mode.identity_ref, mode.relationship_context);
        let value = mode_value(&mode);
        if self.store.vault_meta.get(&txn, &key)?.is_some() {
            let (writer, at, old) = self.autonomy_row(&txn, &key)?;
            if writer != owner.actor() || learned_at < at {
                return Err(invalid_autonomy());
            }
            if old == value {
                return address(PREDICATE_AUTONOMY_MODE, &value);
            }
        }
        self.write_autonomy_row(&mut txn, &key, owner.actor(), learned_at, value.clone())?;
        txn.commit()?;
        address(PREDICATE_AUTONOMY_MODE, &value)
    }

    /// Missing, expired, revoked, stale-policy, or mismatched grants fail closed.
    pub fn resolve_channel_identity_autonomy_mode(
        &self,
        identity_ref: &EntityId,
        context: &RelationshipContext,
        at: u64,
    ) -> Result<ChannelIdentityAutonomyMode> {
        let txn = self.store.env.read_txn()?;
        self.autonomy_mode_in_txn(
            &txn,
            *identity_ref,
            *context,
            at.min(crate::unix_seconds_now()),
        )
    }

    pub(crate) fn autonomy_mode_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        identity: EntityId,
        context: RelationshipContext,
        at: u64,
    ) -> Result<ChannelIdentityAutonomyMode> {
        let (_, learned_at, value) = self.autonomy_row(txn, &mode_key(identity, context))?;
        let mode = mode_from(&value)?;
        if learned_at > at || mode.identity_ref != identity || mode.relationship_context != context
        {
            return Err(invalid_autonomy());
        }
        Ok(self.autonomy_state(txn, mode, at)?.mode)
    }

    pub(super) fn autonomy_state(
        &self,
        txn: &heed::RoTxn<'_>,
        mode: ChannelIdentityAutonomyMode,
        at: u64,
    ) -> Result<ChannelIdentityAutonomyState> {
        let actor = self.autonomy_identity_actor(txn, mode.identity_ref)?;
        let reference = mode.read_grant_ref.ok_or_else(invalid_autonomy)?;
        let raw = self
            .store
            .entities
            .get(txn, reference.as_bytes())?
            .ok_or_else(invalid_autonomy)?;
        let header = EntityMetadataHeader::parse(&raw).ok_or_else(invalid_autonomy)?;
        if header.entity_type != crate::registry::ENTITY_TYPE_ACCESS_GRANT {
            return Err(invalid_autonomy());
        }
        let grant =
            crate::access_grant::decode_access_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        let AccessGrantScope::ChannelIdentity {
            identity_ref,
            envelope_ref,
        } = grant.scope
        else {
            return Err(invalid_autonomy());
        };
        if identity_ref != mode.identity_ref
            || grant.principal_ref != actor
            || grant.status != AccessGrantStatus::Active
            || grant.created_at > at
        {
            return Err(invalid_autonomy());
        }
        let (_, learned_at, value) = self.autonomy_row(
            txn,
            &key(PREDICATE_MAILBOX_READ_ENVELOPE, &envelope_ref.to_hex()),
        )?;
        let read_envelope = read_from(&value)?;
        if address(PREDICATE_MAILBOX_READ_ENVELOPE, &value)? != envelope_ref
            || learned_at > at
            || read_envelope.identity_ref != identity_ref
        {
            return Err(invalid_autonomy());
        }
        self.require_autonomy_bound(txn, &read_bound(actor, identity_ref, envelope_ref)?)?;
        let (action_grant, action_envelope) = match (mode.rung.verb(), mode.action_grant_ref) {
            (None, None) => (None, None),
            (Some(verb), Some(reference)) => {
                let action = standing_outbound_grant_in_txn(&self.store, txn, &reference)?
                    .ok_or_else(invalid_autonomy)?;
                let envelope = self.validate_autonomy_action(txn, &action, at)?;
                if envelope.identity_ref != identity_ref
                    || envelope.relationship_context != mode.relationship_context
                    || !matches!(&action.scope, StandingOutboundGrantScope::ChannelIdentityEnvelope { verb_class, .. } if verb_class == verb)
                {
                    return Err(invalid_autonomy());
                }
                (Some(action), Some(envelope))
            }
            _ => return Err(invalid_autonomy()),
        };
        Ok(ChannelIdentityAutonomyState {
            mode,
            read_envelope,
            action_envelope,
            read_grant: grant,
            action_grant,
        })
    }

    pub(crate) fn require_autonomy_bound(
        &self,
        txn: &heed::RoTxn<'_>,
        bound: &GrantBound,
    ) -> Result<()> {
        if !self
            .active_standing_consent_grants_in_txn(txn)?
            .iter()
            .any(|g| g.bound() == bound)
        {
            return Err(invalid_autonomy());
        }
        Ok(())
    }

    pub(crate) fn validate_autonomy_action(
        &self,
        txn: &heed::RoTxn<'_>,
        grant: &StandingOutboundGrant,
        at: u64,
    ) -> Result<ChannelIdentityActionEnvelope> {
        let StandingOutboundGrantScope::ChannelIdentityEnvelope {
            identity_ref,
            envelope_ref,
            verb_class,
        } = &grant.scope
        else {
            return Err(invalid_autonomy());
        };
        let actor = self.autonomy_identity_actor(txn, *identity_ref)?;
        if self
            .autonomy_row(txn, &key(PREDICATE_ACTION_ENVELOPE, &envelope_ref.to_hex()))?
            .1
            > at
        {
            return Err(invalid_autonomy());
        }
        let envelope = self.autonomy_action_envelope(txn, envelope_ref)?;
        let bound = action_bound(actor, *envelope_ref, &envelope, verb_class)?;
        if envelope.identity_ref != *identity_ref
            || grant.principal_ref != actor.to_hex()
            || grant.created_at > at
            || grant.binding_diff_handle != bound.digest().as_bytes().to_vec()
            || !grant.is_active_under_policy(
                &crate::gate::resolve_policy_manifest(&self.store, txn)?.read_frontier_hash()?,
            )
        {
            return Err(invalid_autonomy());
        }
        self.require_autonomy_bound(txn, &bound)?;
        Ok(envelope)
    }
}
