//! Append-time retention scope: a decision keeps its verified ancestry after
//! its claim body or source is removed. No sweep caller can select a weaker scope.

use heed::{RoTxn, RwTxn};

use crate::EntityId;
use crate::error::{Error, Result};
use crate::gate::GateRetentionContext;
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::store::{ManifestDbs, Store};

use super::types::{GateDecisionId, GateDecisionRecord};

/// One decision's append-time context.
const DECISION_SCOPE: SideTable<GateDecisionId, GateRetentionContext, Raw> =
    SideTable::new(&side_table::GATE_DECISION_RETENTION_CONTEXT);
/// The latest verified context of a claim, inherited by its later decisions.
const CLAIM_SCOPE: SideTable<[u8; 16], GateRetentionContext, Raw> =
    SideTable::new(&side_table::GATE_DECISION_CLAIM_CONTEXT);

/// The module's own layout; a row that does not decode is the module's corruption error.
impl RawValue for GateRetentionContext {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode(*self))
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        decode(bytes).map_err(CodecError::Value)
    }
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
        CLAIM_SCOPE.get(store, &*txn, &claim)?.unwrap_or_default()
    } else {
        GateRetentionContext::default()
    };
    DECISION_SCOPE.put(store, txn, &record.decision_id, &context)?;
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
        if decode(&encode(context))? != context {
            return Err(corrupt());
        }
        CLAIM_SCOPE.put(self, txn, claim.as_bytes(), &context)?;
        DECISION_SCOPE.put(self, txn, &decision_id, &context)?;
        Ok(())
    }

    pub(crate) fn gate_retention_context_in_txn(
        &self,
        txn: &RoTxn<'_>,
        record: &GateDecisionRecord,
    ) -> Result<GateRetentionContext> {
        match DECISION_SCOPE.get(self, txn, &record.decision_id)? {
            Some(context) => Ok(context),
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
        DECISION_SCOPE.delete(self, txn, &decision_id)?;
        Ok(())
    }
}
