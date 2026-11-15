//! A genuine receiving-agent credential narrowed to one current phone call.

use std::collections::BTreeSet;

use super::*;
use crate::authority::VerifiedSlip;
use crate::claim::ScopedReadActorKey;
use crate::voice_call::PhoneReach;

/// What one call may read under one ceiling: the line's reach frozen at
/// answer, met with the live reach on every read (VOICE-PHONE-AGENT-REACH
/// R2). Invariant: `confined` implies `caller_rule` (a confined call is
/// always also held to its current caller's thread).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CallReach {
    scope: Scope,
    caller_rule: bool,
    confined: Option<BTreeSet<EntityId>>,
}

impl CallReach {
    /// The reach a call freezes from the line's `voice.phone.reach` value:
    /// the default reads this caller's thread plus the picked documents, a
    /// custom reads its scope in the current caller's thread (or across
    /// callers when it includes them), and the whole vault reads everything
    /// the line agent's own credential reads.
    pub(crate) fn of(value: &PhoneReach) -> Self {
        match value {
            PhoneReach::Default { .. } => Self {
                scope: Scope::top(),
                caller_rule: true,
                confined: Some(value.documents().into_iter().collect()),
            },
            PhoneReach::Custom {
                scope,
                include_other_callers,
            } => Self {
                scope: scope.clone(),
                // REACH-CUSTOM-CALLER-RULE = A (Engine 16 Nov 04:16): Custom
                // keeps the current-caller rule unless it includes other
                // callers; then its Scope alone decides (the per-thread
                // grants still apply).
                caller_rule: !include_other_callers,
                confined: None,
            },
            PhoneReach::WholeVault => Self {
                scope: Scope::top(),
                caller_rule: false,
                confined: None,
            },
        }
    }

    /// The narrower of two reaches: the met scope, either caller rule, and
    /// the picked documents both sides name (a side that names none confines
    /// nothing away from the other).
    pub(crate) fn meet(&self, other: &Self) -> Self {
        Self {
            scope: self.scope.meet(&other.scope),
            caller_rule: self.caller_rule || other.caller_rule,
            confined: match (&self.confined, &other.confined) {
                (Some(own), Some(other)) => Some(own.intersection(other).copied().collect()),
                (Some(own), None) | (None, Some(own)) => Some(own.clone()),
                (None, None) => None,
            },
        }
    }

    /// The scope half of this reach.
    pub(crate) fn scope(&self) -> &Scope {
        &self.scope
    }

    /// Whether a marked phone-thread row reads only in the current caller's thread.
    pub(crate) fn caller_rule(&self) -> bool {
        self.caller_rule
    }

    /// The picked documents a confined call is held to, if any.
    pub(crate) fn confined(&self) -> Option<&BTreeSet<EntityId>> {
        self.confined.as_ref()
    }
}

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
    frozen: CallReach,
}

impl PhoneLineReadCeiling {
    pub(crate) fn frozen_scope(&self) -> &Scope {
        self.frozen.scope()
    }

    /// The line agent answering under this ceiling.
    pub(crate) fn agent_ref(&self) -> EntityId {
        self.agent_ref
    }

    /// The live reach of the frozen call: the frozen reach met with the
    /// line's current `voice.phone.reach`. A call never reads wider than its
    /// answer-time reach nor than the live value: a narrowing lands at the
    /// next read; a widening back within the answer-time reach (the owner's
    /// own, or an agent undoing its own narrowing) lands at once, and the rest
    /// waits for the next call (REACH-AGENT-UNDO-NARROWING = A).
    /// The caller's original credential is checked separately by the read door.
    pub(crate) fn current_reach_in(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        caller: &str,
    ) -> Result<Option<CallReach>> {
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
        let live = vault.phone_line_reach_in(txn, self.identity_ref, self.agent_ref)?;
        Ok(Some(self.frozen.meet(&CallReach::of(&live))))
    }

    /// The caller the call's arrival names, while that arrival still stands
    /// for this ceiling's attempt: the line provider's own text, untrusted.
    pub(crate) fn caller_in(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Option<String>> {
        let Some((_, record)) = answer_line_in_txn(
            vault,
            txn,
            self.identity_ref,
            &self.payload_key,
            &self.payload_ref,
        )?
        else {
            return Err(invalid());
        };
        if record.attempt_ref != self.attempt_ref {
            return Err(invalid());
        }
        Ok(record.arrival.caller)
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
            frozen: CallReach::of(&self.phone_line_reach_in(&txn, identity_ref, line.agent_ref)?),
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
