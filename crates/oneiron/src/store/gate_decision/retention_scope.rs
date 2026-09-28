//! Append-time retention scope: a decision keeps its verified ancestry after
//! its claim body or source is removed. No sweep caller can select a weaker scope.

use heed::{RoTxn, RwTxn};

use crate::EntityId;
use crate::error::{Error, Result};
use crate::gate::GateRetentionContext;
use crate::store::{ManifestDbs, Store};

use super::types::{GateDecisionId, GateDecisionRecord};

const DECISION_SCOPE_PREFIX: &[u8] = b"gate_decision:retention_context:v1:";
const CLAIM_SCOPE_PREFIX: &[u8] = b"gate_decision:claim_context:v1:";

fn key(prefix: &[u8], id: &[u8; 16]) -> Vec<u8> {
    let mut key = Vec::from(prefix);
    key.extend_from_slice(id);
    key
}

fn corrupt() -> Error {
    Error::CorruptedIndex("gate decision retention context")
}

fn encode(context: GateRetentionContext) -> Vec<u8> {
    if context == GateRetentionContext::default() {
        return vec![0];
    }
    let mut raw = vec![1];
    for id in [
        context.world,
        context.project,
        context.sub_project,
        context.thread,
    ] {
        raw.extend_from_slice(id.map_or([0; 16], |id| *id.as_bytes()).as_slice());
    }
    raw
}

fn decode(raw: &[u8]) -> Result<GateRetentionContext> {
    if raw == [0] {
        return Ok(GateRetentionContext::default());
    }
    if raw.len() != 65 || raw[0] != 1 {
        return Err(corrupt());
    }
    let mut axes = [None; 4];
    for (index, axis) in axes.iter_mut().enumerate() {
        let bytes: [u8; 16] = raw[1 + index * 16..17 + index * 16]
            .try_into()
            .map_err(|_| corrupt())?;
        if bytes != [0; 16] {
            *axis = Some(EntityId::from_bytes(bytes).map_err(|_| corrupt())?);
        }
    }
    let [world, project, sub_project, thread] = axes;
    if (sub_project.is_some() || thread.is_some()) && project.is_none() {
        return Err(corrupt());
    }
    let context = GateRetentionContext {
        world,
        project,
        sub_project,
        thread,
    };
    if context == GateRetentionContext::default() {
        return Err(corrupt());
    }
    Ok(context)
}

/// Every primary append writes its own context sidecar in the SAME txn. For
/// later decisions about a known claim, inherit the most recently verified
/// claim-write ancestry; claim-free decisions are explicitly vault scoped.
pub(super) fn append_context_in_txn(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    record: &GateDecisionRecord,
) -> Result<()> {
    let context = if let Some(claim) = record.claim_id {
        store
            .vault_meta()
            .get(&*txn, &key(CLAIM_SCOPE_PREFIX, &claim))?
            .map(|raw| decode(&raw))
            .transpose()?
            .unwrap_or_default()
    } else {
        GateRetentionContext::default()
    };
    store.vault_meta().put(
        txn,
        &key(DECISION_SCOPE_PREFIX, &record.decision_id.as_bytes()),
        &encode(context),
    )?;
    Ok(())
}

impl Store {
    /// The claim Gate has already validated this exact ClaimBody. Keep the
    /// scope beside its decision and cache it for later decisions on that ID.
    pub(crate) fn stamp_claim_gate_retention_context_in_txn(
        &self,
        txn: &mut RwTxn<'_>,
        decision_id: GateDecisionId,
        claim: &EntityId,
        context: GateRetentionContext,
    ) -> Result<()> {
        if self
            .gate_decision_in_txn(&*txn, decision_id)?
            .is_none_or(|record| record.claim_id != Some(*claim.as_bytes()))
        {
            return Err(corrupt());
        }
        let encoded = encode(context);
        if decode(&encoded)? != context {
            return Err(corrupt());
        }
        self.vault_meta
            .put(txn, &key(CLAIM_SCOPE_PREFIX, claim.as_bytes()), &encoded)?;
        self.vault_meta.put(
            txn,
            &key(DECISION_SCOPE_PREFIX, &decision_id.as_bytes()),
            &encoded,
        )?;
        Ok(())
    }

    pub(crate) fn gate_retention_context_in_txn(
        &self,
        txn: &RoTxn<'_>,
        record: &GateDecisionRecord,
    ) -> Result<GateRetentionContext> {
        match self.vault_meta.get(
            txn,
            &key(DECISION_SCOPE_PREFIX, &record.decision_id.as_bytes()),
        )? {
            Some(raw) => decode(&raw),
            // A missing append-time context on a claim-bound row cannot be
            // assumed vault-scoped once child retention policies exist.
            None if record.claim_id.is_some() => Err(corrupt()),
            None => Ok(GateRetentionContext::default()),
        }
    }

    pub(super) fn delete_gate_retention_context_in_txn(
        &self,
        txn: &mut RwTxn<'_>,
        decision_id: GateDecisionId,
    ) -> Result<()> {
        self.vault_meta
            .delete(txn, &key(DECISION_SCOPE_PREFIX, &decision_id.as_bytes()))?;
        Ok(())
    }
}
