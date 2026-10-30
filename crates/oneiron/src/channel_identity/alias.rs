//! Function-mailbox aliases (ARCH-0063 R6): an alias is routing data onto
//! one identity. Mail to `scheduling@` lands on the identity that holds the
//! alias, and that identity still sends from its own address.
//!
//! Each alias is one `channel_identity.alias` claim on its identity (OF-272:
//! channel facts are claims), its value the alias normalized the way the
//! identity's channel normalizes addresses. An address an assignment slot
//! holds is never an alias, and an alias exactly one live identity claims
//! routes to that identity; routing never ranks two claimants.

use rmpv::Value;

use super::address::{AssignmentKey, MailboxAddr};
use super::facts::channel_identity_facts_in_txn;
use super::record::ChannelIdentity;
use crate::Vault;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::ports::{EntityStoreRead, TombstoneStoreRead};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::Store;
use crate::temporal::TimeRange;

/// One alias's claim predicate: subject the identity, value the normalized
/// alias address.
pub const PREDICATE_CHANNEL_IDENTITY_ALIAS: &str = "channel_identity.alias";

/// One live alias claim and the key it routes.
struct AliasClaim {
    claim_id: EntityId,
    identity_ref: EntityId,
    /// The alias under its identity's channel.
    key: AssignmentKey,
}

/// Every live alias claim of an identity with live facts: Active, not stale,
/// auto or approved, and not erased. An identity whose facts are gone (an
/// erased row) holds no alias.
///
/// # Errors
///
/// Store failure or an alias claim that does not decode.
fn live_alias_claims_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> Result<Vec<AliasClaim>> {
    let mut aliases = Vec::new();
    for claim_id in
        crate::claim::claim_ids_for_predicate_in_txn(store, txn, PREDICATE_CHANNEL_IDENTITY_ALIAS)?
    {
        let Some(raw) = store.port_entity_record(txn, &claim_id)? else {
            continue;
        };
        if raw.entity_type != ENTITY_TYPE_CLAIM {
            continue;
        }
        let body = crate::claim::decode_claim_body(&raw.body, true)?;
        let (ClaimSubject::Entity(identity_ref), Some(alias)) = (body.subject, body.value.as_str())
        else {
            continue;
        };
        if body.predicate != PREDICATE_CHANNEL_IDENTITY_ALIAS
            || body.lifecycle != ClaimLifecycleStatus::Active
            || body.stale
            || !matches!(
                body.approval,
                ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
            )
            || store.port_deletion_state(txn, &claim_id)?.deleted
        {
            continue;
        }
        // An identity whose facts do not read is passed over with a warning,
        // so it never stops another address's routing.
        let facts = match channel_identity_facts_in_txn(store, txn, &identity_ref) {
            Ok(Some(facts)) => facts,
            Ok(None) => continue,
            Err(error) => {
                tracing::warn!(
                    identity = %identity_ref.to_hex(),
                    %error,
                    "channel identity facts do not read; its alias is skipped"
                );
                continue;
            }
        };
        aliases.push(AliasClaim {
            claim_id,
            identity_ref,
            key: AssignmentKey::of(&facts.channel, alias),
        });
    }
    Ok(aliases)
}

/// The one identity a live alias at `key` routes to: `None` when no live
/// identity claims it, or when two do.
fn alias_holder_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &AssignmentKey,
) -> Result<Option<EntityId>> {
    let mut holder = None;
    for alias in live_alias_claims_in_txn(store, txn)? {
        if &alias.key != key {
            continue;
        }
        match holder {
            None => holder = Some(alias.identity_ref),
            Some(held) if held == alias.identity_ref => {}
            Some(_) => return Ok(None),
        }
    }
    Ok(holder)
}

/// Whether an identity other than `id` claims a live alias at `key`, so the
/// address is not free for `id` to take as its own.
pub(super) fn alias_held_by_other_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &AssignmentKey,
    id: &EntityId,
) -> Result<bool> {
    Ok(live_alias_claims_in_txn(store, txn)?
        .iter()
        .any(|alias| &alias.key == key && alias.identity_ref != *id))
}

impl Vault {
    /// Adds `alias` to the identity at `identity_ref` (ARCH-0063 R6): inbound
    /// addressed to it routes to that identity. The alias is normalized as
    /// the identity's channel normalizes addresses. An alias the identity
    /// already holds returns its claim. The MTA or provider must deliver the
    /// alias's traffic; this records the routing only.
    ///
    /// # Errors
    ///
    /// [`Error::EntityNotFound`] for an identity with no facts;
    /// [`Error::InvalidConfig`] for a blank alias, an email alias outside the
    /// engine's address grammar, or the identity's own address;
    /// [`RecordError::ChannelIdentityAlreadyExists`] for an address an
    /// identity's assignment holds or another identity's alias.
    pub fn add_channel_identity_alias(
        &self,
        identity_ref: &EntityId,
        alias: &str,
        now: u64,
    ) -> Result<EntityId> {
        let mut wtxn = self.store.env.write_txn()?;
        let facts = channel_identity_facts_in_txn(&self.store, &wtxn, identity_ref)?
            .ok_or(Error::EntityNotFound)?;
        let key = AssignmentKey::of(&facts.channel, alias);
        if key.address_or_handle().is_empty() {
            return Err(Error::InvalidConfig(
                "channel identity alias must be non-empty".into(),
            ));
        }
        if key.channel() == "email" {
            MailboxAddr::parse_addr_spec(key.address_or_handle())?;
        }
        if key == AssignmentKey::of(&facts.channel, &facts.address_or_handle) {
            return Err(Error::InvalidConfig(
                "channel identity alias is the identity's own address".into(),
            ));
        }
        if super::assignment::holds_key(&self.store, &wtxn, &key)? {
            return Err(Error::Record(RecordError::ChannelIdentityAlreadyExists));
        }
        for held in live_alias_claims_in_txn(&self.store, &wtxn)? {
            if held.key != key {
                continue;
            }
            if held.identity_ref == *identity_ref {
                return Ok(held.claim_id);
            }
            return Err(Error::Record(RecordError::ChannelIdentityAlreadyExists));
        }
        let body = ClaimBody::new(
            PREDICATE_CHANNEL_IDENTITY_ALIAS,
            ClaimSubject::Entity(*identity_ref),
            Value::from(key.address_or_handle()),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )?;
        let claim_id = self.store.clock.entity_id()?;
        self.put_reserved_claim_in_txn(
            &mut wtxn,
            &claim_id,
            &body,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )?;
        wtxn.commit()?;
        self.store.notify_proactivity_changes();
        Ok(claim_id)
    }

    /// Removes `alias` from the identity at `identity_ref`: its claim is
    /// retracted, so inbound addressed to it no longer routes there. Returns
    /// whether the identity held it.
    ///
    /// # Errors
    ///
    /// [`Error::EntityNotFound`] for an identity with no facts; store and
    /// claim lifecycle failures.
    pub fn remove_channel_identity_alias(
        &self,
        identity_ref: &EntityId,
        alias: &str,
        now: u64,
    ) -> Result<bool> {
        let mut wtxn = self.store.env.write_txn()?;
        let facts = channel_identity_facts_in_txn(&self.store, &wtxn, identity_ref)?
            .ok_or(Error::EntityNotFound)?;
        let key = AssignmentKey::of(&facts.channel, alias);
        let held: Vec<EntityId> = live_alias_claims_in_txn(&self.store, &wtxn)?
            .into_iter()
            .filter(|claim| claim.identity_ref == *identity_ref && claim.key == key)
            .map(|claim| claim.claim_id)
            .collect();
        for claim_id in &held {
            self.retract_claim_in_txn(&mut wtxn, claim_id, now)?;
        }
        wtxn.commit()?;
        self.store.notify_proactivity_changes();
        Ok(!held.is_empty())
    }

    /// The identity's live aliases, normalized, in claim id order.
    ///
    /// # Errors
    ///
    /// Store failure or a claim that does not decode.
    pub fn channel_identity_aliases(&self, identity_ref: &EntityId) -> Result<Vec<String>> {
        let txn = self.store.env.read_txn()?;
        Ok(live_alias_claims_in_txn(&self.store, &txn)?
            .into_iter()
            .filter(|claim| claim.identity_ref == *identity_ref)
            .map(|claim| claim.key.address_or_handle().to_owned())
            .collect())
    }

    /// The identity a live alias at `(channel, address)` routes to, with its
    /// row: the inbound router's answer for an address no assignment holds.
    pub(crate) fn channel_identity_by_alias_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        channel: &str,
        address_or_handle: &str,
    ) -> Result<Option<(EntityId, ChannelIdentity)>> {
        let key = AssignmentKey::of(channel, address_or_handle);
        let Some(identity_ref) = alias_holder_in_txn(&self.store, rtxn, &key)? else {
            return Ok(None);
        };
        Ok(self
            .get_channel_identity_in_txn(rtxn, &identity_ref)?
            .map(|identity| (identity_ref, identity)))
    }
}
