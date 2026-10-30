//! A reader's weave digest also goes to the reader (FIX 1262): the vault's
//! companion agent sends it to the reader's own address on one of the
//! vault's channel identities, through the OF-327 schedule door, once the
//! period's inbox notice has committed. The inbox notice stays as it is; the
//! send carries that notice and is keyed `weave-digest:{reader}:{period}`,
//! so a second render of the period schedules nothing new. Nothing goes to
//! anyone but the reader.
//!
//! One owner row per reader ([`WeaveDigestChannelOverride`]) redirects the
//! send to another identity the reader has a live contact on, or turns it
//! off. With no row the send is on, on the reader's primary route: the first
//! companion agent, in id order, whose sending identity carries a live
//! contact of the reader's. A reader with no route gets the inbox notice
//! alone, and no error.

use serde::{Deserialize, Serialize};

use crate::agent_def::AgentWakeCadence;
use crate::channel_identity::ChannelIdentityState;
use crate::claim::WeaveDigestReader;
use crate::comm::{CommClaim, CommClaimValue, PREDICATE_COMM_REACHABLE_VIA};
use crate::consent::AuthenticatedOwner;
use crate::counterparty_contact::CounterpartyContactStatus;
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::human_task::HumanTaskError;
use crate::memory::OutboundDraftInput;
use crate::ports::EntityStoreRead;
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_CHANNEL_IDENTITY, ENTITY_TYPE_NOTIFICATION,
};
use crate::side_table::{self, Named, SideTable};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};

/// The verb a digest send takes on its channel.
const WEAVE_DIGEST_SEND_VERB: &str = "send";

/// The trigger a digest send records: the host's deadline timer renders the
/// period (OF-187 timer wake).
const WEAVE_DIGEST_SEND_TRIGGER: &str = "commitment_timer_wake";

/// One owner row per reader. Key: id16 (reader).
const OVERRIDES: SideTable<EntityId, WeaveDigestChannelOverride, Named> =
    SideTable::new(&side_table::WEAVE_DIGEST_CHANNEL_OVERRIDE);

/// Where the owner sends one reader's digest instead of the reader's primary
/// route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WeaveDigestChannelOverride {
    /// No send: the reader's inbox notice alone.
    Off,
    /// The send goes from this channel identity of the vault's, to the
    /// reader's live contact on it, from the companion agent it is bound to.
    /// While that identity carries no such route, nothing is sent.
    Identity {
        #[schemars(with = "String")]
        channel_identity_ref: EntityId,
    },
}

/// One reader's digest channel, as the owner reads and sets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveDigestChannelSetting {
    /// The reader, as 32 hex.
    #[schemars(with = "String")]
    pub reader_ref: EntityId,
    /// The owner's override; `None` is the default: the send on, to the
    /// reader's primary route. Setting `None` removes the row.
    pub route: Option<WeaveDigestChannelOverride>,
}

/// Who sends one digest, and to which address on which channel.
struct DigestRoute {
    sender: EntityId,
    channel: String,
    target: String,
}

impl Vault {
    /// Every reader's digest channel override, in reader order.
    ///
    /// # Errors
    /// A proof that is no longer the vault owner's, or a storage error.
    pub fn weave_digest_channel_overrides(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<Vec<WeaveDigestChannelSetting>> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        Ok(OVERRIDES
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(reader_ref, route)| WeaveDigestChannelSetting {
                reader_ref,
                route: Some(route),
            })
            .collect())
    }

    /// Stores one reader's override under the owner proof, or removes it
    /// when `route` is `None`. A redirect names one of the vault's channel
    /// identities; whether it routes to the reader is read at each send.
    ///
    /// # Errors
    /// A proof that is no longer the vault owner's, a redirect that names no
    /// channel identity, or a storage error.
    pub fn set_weave_digest_channel_override(
        &self,
        owner: &AuthenticatedOwner,
        setting: &WeaveDigestChannelSetting,
    ) -> Result<WeaveDigestChannelSetting> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            match &setting.route {
                Some(route) => {
                    if let WeaveDigestChannelOverride::Identity {
                        channel_identity_ref,
                    } = route
                        && self.get_entity_type_in_txn(txn, channel_identity_ref)?
                            != Some(ENTITY_TYPE_CHANNEL_IDENTITY)
                    {
                        return Err(Error::InvalidConfig(
                            "a weave digest redirect names one of the vault's channel identities"
                                .into(),
                        ));
                    }
                    OVERRIDES.put(&self.store, txn, &setting.reader_ref, route)?;
                }
                None => {
                    OVERRIDES.delete(&self.store, txn, &setting.reader_ref)?;
                }
            }
            Ok(*setting)
        })
    }

    /// Schedules `reader`'s digest of `period` to the reader's own channel,
    /// carrying the period's inbox notice `notice`. Called after the notice
    /// committed; a period whose notice is not live sends nothing. A send
    /// that cannot be scheduled is logged and never undoes the digest.
    pub(crate) fn send_weave_digest(
        &self,
        reader: WeaveDigestReader,
        period: u64,
        notice: EntityId,
    ) {
        let (tag, id) = match reader {
            WeaveDigestReader::Person(id) => ("p", id),
            WeaveDigestReader::Owner(id) => ("o", id),
            WeaveDigestReader::Agent(id) => ("a", id),
            // An Admin publishes no digest (OF-499 A3).
            WeaveDigestReader::Admin(_) => return,
        };
        let route = match self.weave_digest_route(id, notice) {
            Ok(Some(route)) => route,
            Ok(None) => return,
            Err(error) => {
                tracing::warn!(?error, "the weave digest route did not read");
                return;
            }
        };
        let key = format!("weave-digest:{tag}:{}:{period}", id.to_hex());
        let draft = OutboundDraftInput {
            verb: WEAVE_DIGEST_SEND_VERB.to_owned(),
            channel: route.channel,
            target: route.target,
            on_behalf_of: None,
            content_ref: Some(notice.to_hex()),
            idempotency_key: Some(key.clone()),
            dedupe_key: Some(key),
            trigger: WEAVE_DIGEST_SEND_TRIGGER.to_owned(),
            trigger_ref: notice.to_hex(),
            job_ref: None,
            occurred_at: None,
            mention: None,
        };
        if let Err(error) = self
            .memory(route.sender, EdgeActorClass::Agent)
            .schedule_outbound(&draft)
        {
            tracing::warn!(?error, "the weave digest send was not scheduled");
        }
    }

    /// The route `reader`'s digest takes: none when its notice is not live,
    /// the owner turned the send off, or no companion agent reaches the
    /// reader on the identity the row names, or on any.
    fn weave_digest_route(
        &self,
        reader: EntityId,
        notice: EntityId,
    ) -> Result<Option<DigestRoute>> {
        let txn = self.store.env.read_txn()?;
        if !matches!(
            live_entity_row_in_txn(&self.store, &txn, &notice)?,
            LiveEntityRow::Live { entity_type, .. } if entity_type == ENTITY_TYPE_NOTIFICATION
        ) {
            return Ok(None);
        }
        let companions = self.companion_agents_in(&txn)?;
        match OVERRIDES.get(&self.store, &txn, &reader)? {
            Some(WeaveDigestChannelOverride::Off) => Ok(None),
            Some(WeaveDigestChannelOverride::Identity {
                channel_identity_ref,
            }) => self.digest_route_on_identity_in(&txn, reader, channel_identity_ref, &companions),
            None => {
                for sender in companions {
                    match crate::human_task::resolve_native_human_route_for_actor_in(
                        self,
                        &txn,
                        reader,
                        sender,
                        &mut Vec::new(),
                    ) {
                        Ok(route) => {
                            return Ok(Some(DigestRoute {
                                sender,
                                channel: route.channel,
                                target: route.target,
                            }));
                        }
                        Err(HumanTaskError::NotNativelyReachable) => {}
                        Err(HumanTaskError::Engine(error)) => return Err(error),
                        // Not a person: no address of its own.
                        Err(_) => return Ok(None),
                    }
                }
                Ok(None)
            }
        }
    }

    /// The vault's companion agents: each live AGENT_DEF whose wake cadence
    /// is a companion's, in id order.
    fn companion_agents_in(&self, txn: &heed::RoTxn<'_>) -> Result<Vec<EntityId>> {
        let mut agents = Vec::new();
        for entry in self
            .store
            .port_entity_ids_by_type(txn, ENTITY_TYPE_AGENT_DEF, None)?
        {
            let id = entry?;
            if !live_entity_row_in_txn(&self.store, txn, &id)?.is_live() {
                continue;
            }
            if self
                .read_agent_definition_in_txn(txn, &id)
                .is_ok_and(|definition| {
                    matches!(
                        definition.wake_cadence,
                        Some(AgentWakeCadence::Companion { .. })
                    )
                })
            {
                agents.push(id);
            }
        }
        Ok(agents)
    }

    /// The route on `identity` alone: an active identity that may send, bound
    /// to one of `companions`, the one the outbound chokepoint selects for
    /// that companion on its channel, and a live contact of `reader`'s on it
    /// that no `comm.reachable_via: false` of the reader's takes away.
    fn digest_route_on_identity_in(
        &self,
        txn: &heed::RoTxn<'_>,
        reader: EntityId,
        identity: EntityId,
        companions: &[EntityId],
    ) -> Result<Option<DigestRoute>> {
        let Some(party_key) = crate::comm::person_party_key_in_txn(&self.store, txn, reader)?
        else {
            return Ok(None);
        };
        let Some(facts) =
            crate::channel_identity::channel_identity_facts_in_txn(&self.store, txn, &identity)?
        else {
            return Ok(None);
        };
        let Some(row) = self.get_channel_identity_in_txn(txn, &identity)? else {
            return Ok(None);
        };
        let Some(sender) = facts
            .binding
            .actor_ref()
            .filter(|actor| companions.contains(actor))
        else {
            return Ok(None);
        };
        let channel = facts.channel.as_str();
        if facts.state != ChannelIdentityState::Active
            || !row.may_send()
            || crate::outbound::outbound_verb_contract(channel, WEAVE_DIGEST_SEND_VERB).is_err()
            || crate::outbound::resolve_channel_identity_ref_for_connector(
                &self.store,
                txn,
                channel,
                Some(&sender),
            )? != Some(identity)
            || self.unreachable_on_channel_in(txn, reader, channel)?
        {
            return Ok(None);
        }
        let Some((_, contact)) =
            self.find_counterparty_contact_in_txn(txn, &identity, &party_key)?
        else {
            return Ok(None);
        };
        if contact.status != CounterpartyContactStatus::Active {
            return Ok(None);
        }
        Ok(Some(DigestRoute {
            sender,
            channel: facts.channel.clone(),
            target: contact.counterparty,
        }))
    }

    /// Whether an effective `comm.reachable_via: false` of `person`'s takes
    /// `channel` away, as it does from every native route.
    fn unreachable_on_channel_in(
        &self,
        txn: &heed::RoTxn<'_>,
        person: EntityId,
        channel: &str,
    ) -> Result<bool> {
        let now = self.store.clock.now_recorded_at();
        for claim_ref in self.claims_for_subject_in_txn(txn, &person)? {
            let Some(body) = self.get_claim_in_txn(txn, &claim_ref)? else {
                continue;
            };
            if body.predicate != PREDICATE_COMM_REACHABLE_VIA {
                continue;
            }
            let Ok(claim) = CommClaim::from_claim_body(&body) else {
                continue;
            };
            if claim.is_effective_at(now)
                && matches!(
                    &claim.value,
                    CommClaimValue::ReachableVia {
                        channel_class,
                        reachable: false,
                        ..
                    } if channel_class == channel
                )
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// An erased reader's override leaves with it (FIX 3520's sweep).
///
/// # Errors
/// A storage error.
pub(crate) fn erase_weave_digest_channel_override_actor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    OVERRIDES.delete(&vault.store, txn, actor)?;
    Ok(())
}
