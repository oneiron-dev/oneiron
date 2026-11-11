//! A genuine receiving-agent credential narrowed to one current phone call.

use super::*;
use crate::authority::VerifiedSlip;
use crate::claim::ScopedReadActorKey;

/// Call identity and owner consent carried by the read key, never a credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PhoneLineReadCeiling {
    identity_ref: EntityId,
    payload_key: [u8; 32],
    payload_ref: String,
    agent_ref: EntityId,
    bridge_actor: EntityId,
    owner_actor: EntityId,
    attempt_ref: String,
    frozen_scope: Scope,
}

impl PhoneLineReadCeiling {
    pub(crate) fn frozen_scope(&self) -> &Scope {
        &self.frozen_scope
    }

    /// Current consent can narrow the frozen call, but never widen it.
    /// The caller's original credential is checked separately by the read door.
    pub(crate) fn current_scope_in(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        caller: &str,
    ) -> Result<Option<Scope>> {
        if EntityId::from_hex(caller).ok() != Some(self.agent_ref) {
            return Ok(None);
        }
        let Some((line, record)) = answer_line_in_txn(
            vault,
            txn,
            self.identity_ref,
            &self.payload_key,
            &self.payload_ref,
        )?
        else {
            return Ok(None);
        };
        if line.agent_ref != self.agent_ref
            || line.bridge_actor != self.bridge_actor
            || line.owner_actor != self.owner_actor
            || record.attempt_ref != self.attempt_ref
        {
            return Ok(None);
        }
        Ok(Some(self.frozen_scope.meet(&line.share_scope)))
    }
}

impl Vault {
    /// Builds a call-bound read from the receiving agent's actual credential.
    /// It issues no credential, answers no audio, and grants the bridge no reads.
    pub fn phone_line_answer_read_key(
        &self,
        proof: &VerifiedSlip,
        identity_ref: EntityId,
        payload_ref: &str,
    ) -> Result<ScopedReadActorKey> {
        let key = self
            .credential_read_key(proof)?
            .ok_or_else(invalid)?
            .at(crate::claim::CallerLocality::OffDevice);
        let read = self.scoped_read(key.clone());
        read.persist_grant_clock()?;
        let txn = self.store.env.read_txn()?;
        let _policy = read.live_policy_manifest_in(&txn)?;
        if !read.proof_live_in(&txn)? {
            return Err(invalid());
        }
        let payload_key = payload_key(payload_ref)?;
        let (line, record) =
            answer_line_in_txn(self, &txn, identity_ref, &payload_key, payload_ref)?
                .ok_or_else(invalid)?;
        if EntityId::from_hex(key.actor_ref()).ok() != Some(line.agent_ref) {
            return Err(invalid());
        }
        let ceiling = PhoneLineReadCeiling {
            identity_ref,
            payload_key,
            payload_ref: payload_ref.to_owned(),
            agent_ref: line.agent_ref,
            bridge_actor: line.bridge_actor,
            owner_actor: line.owner_actor,
            attempt_ref: record.attempt_ref,
            frozen_scope: line.share_scope.meet(&record.share_scope),
        };
        Ok(key.within_phone_line(ceiling))
    }
}

fn answer_line_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    identity_ref: EntityId,
    key: &[u8; 32],
    payload_ref: &str,
) -> Result<Option<(PhoneLineState, PhoneLineArrivalRecord)>> {
    let Some(line) = LINES.get(&vault.store, txn, &identity_ref)? else {
        return Ok(None);
    };
    let (_, inbound, agent, bridge) = match line_in_txn(vault, txn, &identity_ref) {
        Ok(current) => current,
        Err(error) if matches!(&error, Error::InvalidConfig(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    if !line.enabled
        || line.identity_ref != identity_ref
        || line.agent_ref != agent
        || line.bridge_actor != bridge
        || !matches!(
            inbound,
            InboundDisposition::Deliver | InboundDisposition::DeliverRetiring
        )
        || !crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &line.owner_actor)?
    {
        return Ok(None);
    }
    let Some(StoredArrival::Live { record, .. }) = ARRIVALS.get(&vault.store, txn, key)? else {
        return Ok(None);
    };
    if record.identity_ref != identity_ref
        || record.payload_ref != payload_ref
        || record.agent_ref != agent
        || record.bridge_actor != bridge
    {
        return Ok(None);
    }
    Ok(Some((line, record)))
}
