//! FIX 990: the owner's `always ask` setting on an admitted connector call.
//!
//! An admitted call's ledger row is the call: its frozen bytes, its grant
//! (the row's typed capability names it) and its attempt and call seq. Its
//! approve-once target is recomposed from exactly those, through the same
//! composer its first admission used (`approval::scoped_mcp_pinned_gate_input`):
//! no new render of a route, endpoint or header, no other actor and no
//! search for another grant. A replay meeting `always ask` names that
//! target, a held call's row keeps it as its current ask, and the owner's
//! press on it ([`Vault::approve_connector_call_once`]) releases exactly that
//! call. The press mints no grant and sends nothing; the call's next resume
//! still meets its scope, key, manifest, charters and the tool's setting.

use crate::Vault;
use crate::consent::{AuthenticatedOwner, ConsentReceipt, EffectDigest};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::gate::ExternalEffectGateInput;
use crate::outbound_intent_ledger::{
    IntentLedgerError, IntentLedgerRecord, IntentState, read_intent_for_attempt_in_txn,
};

use super::approval::{
    ConnectorCallApproval, HeldConnectorAsk, retain_held_ask, scoped_mcp_pinned_gate_input,
};
use super::connector_call::{ConnectorCallInvocation, PENDING_CALLS, connector_call_ref};
use super::tool_call::PreparedToolCall;

/// The hold reason an `always ask` replay carries, the Gate's own receipt
/// reason for the same setting.
pub(crate) const SLATE_ALWAYS_ASK_REASON: &str = "connector_key_slate_always_ask";

/// One admitted scoped call's exact approve-once target, from its frozen row.
pub(crate) struct FrozenScopedCandidate {
    /// The pinned Gate input its first admission evaluated.
    pub(crate) gate: ExternalEffectGateInput,
    /// The approve-once digest that input names.
    pub(crate) digest: EffectDigest,
    /// The actor whose press it is: the grant's principal, as the Gate binds it.
    pub(crate) actor: EntityId,
    /// The grant's principal, as the call's own row names it.
    pub(crate) principal_ref: String,
    /// The prepared request the row froze, read back from its exact bytes.
    pub(crate) prepared: PreparedToolCall,
}

/// The approve-once target `record` names, recomposed in `txn` from its
/// frozen bytes, its typed capability's grant and that grant's principal,
/// and its attempt and call seq. `None` for a row with no typed capability,
/// a grant that is gone, or bytes that do not agree with the row's own
/// server, tool and endpoint: such a row names no target to approve.
///
/// # Errors
/// Storage errors.
pub(crate) fn frozen_scoped_candidate_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: &IntentLedgerRecord,
) -> Result<Option<FrozenScopedCandidate>, IntentLedgerError> {
    let Some(capability) = record.capability_provenance() else {
        return Ok(None);
    };
    let grant_id = capability.grant_id();
    let Some(grant) =
        crate::outbound_grant::standing_outbound_grant_in_txn(&vault.store, txn, &grant_id)?
    else {
        return Ok(None);
    };
    let Ok(prepared) = PreparedToolCall::from_frozen(record.payload()) else {
        return Ok(None);
    };
    let call = prepared.call();
    if call.server != record.server
        || call.tool != record.tool
        || record.resolved_endpoint.as_deref() != Some(call.resolved_endpoint.as_str())
    {
        return Ok(None);
    }
    let gate = scoped_mcp_pinned_gate_input(
        &grant.principal_ref,
        grant_id,
        &prepared,
        record.attempt_id,
        record.call_seq,
    );
    let Some(digest) = crate::gate::external_effect_approval_digest(&gate) else {
        return Ok(None);
    };
    Ok(Some(FrozenScopedCandidate {
        gate,
        digest,
        actor: EntityId::from_hex(&grant.principal_ref).unwrap_or(grant_id),
        principal_ref: grant.principal_ref,
        prepared,
    }))
}

/// A held call's stored approve-once digest, 64 lower-hex, as bytes.
fn digest_from_hex(hex: &str) -> Option<EffectDigest> {
    if hex.len() != 64 {
        return None;
    }
    let mut bytes = [0_u8; 32];
    for (byte, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(EffectDigest::from_bytes(bytes))
}

impl Vault {
    /// FIX 990: the owner's approve-once press on the held connector call
    /// `call_ref`, for the exact ask he reviewed. `reviewed_digest` must be
    /// the call's current ask (its status and owner question name it); a
    /// call its ledger already admitted must still be Pending, and its
    /// frozen row must recompose that same target. The press is the consent
    /// door's own exact-digest marker: it grants nothing standing, sends
    /// nothing, and the call's next resume still meets every other check.
    ///
    /// # Errors
    /// [`IntentLedgerError::InvalidInput`] for a call that is not held, names
    /// no approvable ask, or whose ask moved since the owner reviewed it; the
    /// owner check's and the consent door's own errors (a spent digest
    /// included); storage errors.
    pub fn approve_connector_call_once(
        &self,
        owner: &AuthenticatedOwner,
        call_ref: &EntityId,
        reviewed_digest: &str,
    ) -> Result<ConsentReceipt, IntentLedgerError> {
        self.try_with_write_txn(|wtxn| {
            owner.revalidate_in_txn(self, wtxn)?;
            let row = PENDING_CALLS
                .get(&self.store, wtxn, call_ref)?
                .filter(|row| row.settled.is_none() && row.input.is_none())
                .ok_or(IntentLedgerError::InvalidInput(
                    "connector call is not held",
                ))?;
            let approval = row.approval.as_ref();
            let Some(current) = ConnectorCallApproval::current_digest(approval) else {
                return Err(IntentLedgerError::InvalidInput(
                    "held connector call names no approvable ask",
                ));
            };
            if current != reviewed_digest {
                return Err(IntentLedgerError::InvalidInput(
                    "held connector call's ask moved since it was reviewed",
                ));
            }
            let Some(digest) = digest_from_hex(current) else {
                return Err(IntentLedgerError::InvalidRecord(
                    "held connector call approval digest",
                ));
            };
            if let Some(record) =
                read_intent_for_attempt_in_txn(self, wtxn, row.attempt_id, row.call_seq)?
            {
                let recomposed = if record.state == IntentState::Pending {
                    frozen_scoped_candidate_in_txn(self, wtxn, &record)?
                } else {
                    None
                };
                if recomposed.is_none_or(|candidate| candidate.digest != digest) {
                    return Err(IntentLedgerError::InvalidInput(
                        "held connector call's ask moved since it was reviewed",
                    ));
                }
            }
            Ok(self.approve_once_in_txn(wtxn, owner, digest)?)
        })
    }

    /// FIX 990: a recovery sweep's `always ask` hold of the admitted call
    /// `record`, naming `approval_digest`. The held-call row its caller's
    /// invocation names (the principal, attempt and call seq), else the one
    /// row that holds that attempt and call seq for that principal, keeps the
    /// ask as its current one, and the owner is asked once, as a resume's
    /// hold asks. A call no row holds is only reported by the sweep: a row
    /// kept here could not name the credential the call presents. `true`
    /// when a row holds the call.
    ///
    /// # Errors
    /// Storage errors.
    pub(super) fn hold_swept_connector_call(
        &self,
        record: &IntentLedgerRecord,
        approval_digest: Option<String>,
    ) -> Result<bool, IntentLedgerError> {
        let candidate = {
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            frozen_scoped_candidate_in_txn(self, &txn, record)?
        };
        let Some(candidate) = candidate else {
            return Ok(false);
        };
        let named = connector_call_ref(
            &candidate.principal_ref,
            ConnectorCallInvocation {
                attempt_id: record.attempt_id,
                call_seq: record.call_seq,
            },
        )?;
        let ask = HeldConnectorAsk::of(approval_digest, &candidate.prepared);
        let held = self.try_with_write_txn(|txn| -> Result<_, IntentLedgerError> {
            let found = match PENDING_CALLS.get(&self.store, txn, &named)? {
                Some(row) => Some((named, row)),
                None => PENDING_CALLS
                    .scan(&self.store, txn)?
                    .into_iter()
                    .find(|(_, row)| {
                        row.attempt_id == record.attempt_id
                            && row.call_seq == record.call_seq
                            && row.principal_ref == candidate.principal_ref
                    }),
            };
            let Some((call_ref, mut row)) = found else {
                return Ok(None);
            };
            // A settled row, one a connector asked through, or one a code
            // consent wait owns asks nothing here.
            if row.settled.is_some() || row.input.is_some() || row.code_consent_wait.is_some() {
                return Ok(None);
            }
            retain_held_ask(&mut row, ask.as_ref());
            PENDING_CALLS.put(&self.store, txn, &call_ref, &row)?;
            Ok(Some(call_ref))
        })?;
        let Some(call_ref) = held else {
            return Ok(false);
        };
        let reasons = [SLATE_ALWAYS_ASK_REASON.to_owned()];
        if let Err(error) = self.queue_connector_call_owner_ask(&call_ref, &reasons) {
            tracing::warn!(
                call_ref = %call_ref.to_hex(),
                %error,
                "connector call owner ask not queued"
            );
        }
        Ok(true)
    }
}
