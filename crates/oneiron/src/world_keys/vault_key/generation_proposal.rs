//! An agent's ask that the owners start a new data-key generation
//! (DATAKEY-GEN-WHO = C).
//!
//! An agent may start the ask behind a Grant; the owner confirms and presents
//! the secrets, and the act itself stays the owner's. The agent's live owner
//! Grant lists `vault.data_key.generation.propose` by name, or a verb class
//! admitting it names it, checked live at each use in the writer's snapshot.
//! One ask stands per owner and generation: asking again, by any agent, finds
//! the ask already put, and an owner who set it aside is not asked again
//! until a new generation. The owner's act settles the ask for the generation
//! it replaces. Nothing here changes any key.

use super::STATE;
use crate::Vault;
use crate::authority::{NoStanding, PACT_STANDING_LAPSED};
use crate::config::VaultDataKeyCustody;
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::inbox::{
    NotificationEvent, NotificationKind, NotificationSource, decode_notification_body,
};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// The inbox producer of an agent's data-key generation proposal; its event
/// is `<generation>:<owner id>`, the generation the ask would replace, so one
/// ask stands per owner and generation: asking again (any agent) finds the ask
/// already put, and an owner who set it aside is not asked again until a new
/// generation.
pub const NOTIFICATION_PRODUCER_DATA_KEY_GENERATION_PROPOSAL: &str =
    "vault.data_key_generation.proposal";

/// The verb a Grant lists to name an agent's data-key generation proposal:
/// the facade verb itself, since the ask is the verb's whole act. An explicit
/// verb listing, or a verb class admitting it, names it; a Grant over every
/// verb names none.
pub(crate) const DATA_KEY_GENERATION_PROPOSE_VERB: &str = "vault.data_key.generation.propose";

/// The longest reason an ask carries, in characters.
const REASON_MAX_CHARS: usize = 280;

/// An agent's ask that the owners start a new data-key generation
/// ([`Vault::propose_data_key_generation_as_agent`]). It changes no key.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataKeyGenerationProposal {
    /// The generation the ask would replace: the vault's now.
    pub generation: u32,
    /// True when this call put at least one new ask, false when every
    /// owner's ask for that generation stood already.
    pub asked: bool,
}

impl Vault {
    /// `memory`'s agent asks each owner to start a new data-key generation
    /// (DATAKEY-GEN-WHO = C): one inbox ask per owner for the vault's now
    /// generation, carrying the agent's reason. Asking again, by any agent,
    /// finds the ask already put. It changes no key; the act itself stays
    /// the owner's, and the owner's act settles the ask.
    ///
    /// # Errors
    ///
    /// FORBIDDEN for a caller that is no agent, for a vault with no data
    /// key, for a host-managed or supervisor-delivered key, and for an agent
    /// no live Grant from a live owner names with this verb; BAD_REQUEST for
    /// a reason past the limit or holding control characters; storage errors.
    pub fn propose_data_key_generation_as_agent(
        &self,
        memory: &Memory<'_>,
        reason: Option<&str>,
    ) -> MemoryResult<DataKeyGenerationProposal> {
        let agent = memory.actor();
        if memory.actor_class() != EdgeActorClass::Agent {
            return Err(refused("the caller is no agent"));
        }
        let reason = match reason.map(str::trim) {
            None | Some("") => None,
            Some(trimmed) if trimmed.chars().count() > REASON_MAX_CHARS => {
                return Err(MemoryError::bad_request("reason exceeds 280 characters"));
            }
            Some(trimmed) if trimmed.chars().any(char::is_control) => {
                return Err(MemoryError::bad_request(
                    "reason must not contain control characters",
                ));
            }
            Some(trimmed) => Some(trimmed),
        };
        if !matches!(self.data_key_custody(), VaultDataKeyCustody::OwnerHeldLocal) {
            return Err(refused(
                "a host-managed or supervisor-delivered data key gets a new generation from its supervisor",
            ));
        }
        let mut txn = self.store.env.write_txn().map_err(crate::Error::from)?;
        crate::memory::verify_actor_binding_in_txn(self, &txn, agent, EdgeActorClass::Agent)?;
        let standing = crate::authority::principal_standing_or_lapse_in_txn(
            self,
            &txn,
            agent,
            EdgeActorClass::Agent,
            DATA_KEY_GENERATION_PROPOSE_VERB,
        )
        .map_err(MemoryError::from)?;
        let grant = match standing {
            Ok(standing) => standing.grant,
            Err(NoStanding::PactStandingLapsed) => return Err(refused(PACT_STANDING_LAPSED)),
            Err(NoStanding::NotStanding) => None,
        };
        if grant.is_none() {
            return Err(refused(
                "no live Grant from a live owner names this agent and lists the verb",
            ));
        }
        let state = STATE
            .get(&self.store, &txn, &())?
            .ok_or_else(|| refused("the vault has no data key"))?;
        let generation = state.generation;
        let now = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
        let mut asked = false;
        for owner in crate::policy_model::owners_in_txn(self, &txn)? {
            let source = NotificationSource {
                producer: NOTIFICATION_PRODUCER_DATA_KEY_GENERATION_PROPOSAL.to_owned(),
                event: format!("{generation}:{}", owner.to_hex()),
                result: Some(generation.to_string()),
                detail: reason.map(str::to_owned),
                ..NotificationSource::default()
            };
            let id = crate::inbox::notification_id(&source)?;
            if matches!(
                live_entity_row_in_txn(&self.store, &txn, &id)?,
                LiveEntityRow::Absent
            ) {
                asked = true;
            }
            self.record_notification_in_txn(
                &mut txn,
                &NotificationEvent {
                    kind: NotificationKind::Ask,
                    source,
                    subject_refs: vec![agent],
                    recipient: Some(owner),
                    created_at: now,
                    origin_conversation: None,
                },
            )?;
        }
        txn.commit().map_err(crate::Error::from)?;
        if asked {
            self.store.notify_notification_updates();
        }
        Ok(DataKeyGenerationProposal { generation, asked })
    }

    /// Settles the agents' asks for `replaced`, the generation the owner's
    /// act just replaced: each live ask for it is seen and acked for the
    /// owner it was raised for. An absent, deleted or already acked row stays
    /// as it is.
    pub(crate) fn settle_data_key_generation_proposals_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        replaced: u32,
    ) -> Result<()> {
        for owner in crate::policy_model::owners_in_txn(self, txn)? {
            let source = NotificationSource {
                producer: NOTIFICATION_PRODUCER_DATA_KEY_GENERATION_PROPOSAL.to_owned(),
                event: format!("{replaced}:{}", owner.to_hex()),
                ..NotificationSource::default()
            };
            let id = crate::inbox::notification_id(&source)?;
            let LiveEntityRow::Live { entity_type, body } =
                live_entity_row_in_txn(&self.store, txn, &id)?
            else {
                continue;
            };
            if entity_type != crate::registry::ENTITY_TYPE_NOTIFICATION {
                continue;
            }
            let mut body = decode_notification_body(&body)?;
            let Some(recipient) = body.recipient.clone() else {
                continue;
            };
            if body.acked_by.get(&recipient) == Some(&true) {
                continue;
            }
            body.seen_by.insert(recipient.clone(), true);
            body.acked_by.insert(recipient, true);
            self.put_notification_in_txn(txn, &id, &body)?;
        }
        Ok(())
    }
}

fn refused(why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!("vault.data_key.generation.propose: {why}"),
        &[
            "Have the owner grant this agent the verb vault.data_key.generation.propose by name, \
             or ask the owner in conversation.",
        ],
    )
}
