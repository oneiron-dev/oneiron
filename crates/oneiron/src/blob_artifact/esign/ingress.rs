//! Token-first admission at the public signing doors (FIX 3808, Engine
//! ruling 10-18): a recipient link's capability is checked against its
//! persisted binding before the host reads a byte of the request body, and
//! the body the host then spools is measured against its `[limits]` row.
use super::{
    capability::{EsignCapability, binding},
    ledger::restrictive_state_in,
    model::*,
    rate::keep_limit_crossings,
};
use crate::limit_ask::EngineLimit;
use crate::{EntityId, Result, Vault};

/// One signing link a public door admitted: the envelope and the recipient
/// its capability is bound to. It holds no capability and grants nothing on
/// its own; each act still rechecks its authority as it runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EsignIngress {
    document: EntityId,
    recipient: String,
}

impl Vault {
    /// Admits a signing link at a public door, before its request body is
    /// read: the capability's persisted binding names a live artifact, no
    /// one revoked it and its hard lifetime holds, its recipient is still on
    /// the envelope and inside its own deadline, and the envelope was sent.
    ///
    /// It only reads. It appends no Viewed, observes no ceremony call and
    /// decodes no input. Each door keeps its own turn and terminal answers
    /// after it, and every mutation rechecks its authority in its writer
    /// transaction. The state read is the whole chain, held events included,
    /// so admission refuses nothing a reject would still land on.
    pub fn admit_esign_ingress(&self, token: &EsignCapability) -> Result<EsignIngress> {
        let now = self.now_recorded_at();
        let txn = self.store.env.read_txn()?;
        let cap = binding(self, &txn, token)?;
        if cap.revoked_at.is_some() || now >= cap.hard_expires_at {
            return Err(invalid("invalid capability"));
        }
        let document = EntityId::from_hex(&cap.document)?;
        let state = restrictive_state_in(self, &txn, document)?;
        let on_envelope = state
            .document
            .recipients
            .iter()
            .any(|recipient| recipient.id == cap.recipient);
        let live = state
            .recipients
            .get(&cap.recipient)
            .is_some_and(|progress| now < progress.expires_at);
        if !on_envelope || !live || state.status == DocumentStatus::Draft {
            return Err(invalid("invalid capability"));
        }
        Ok(EsignIngress {
            document,
            recipient: cap.recipient,
        })
    }

    /// An admitted signing door's request body, `bytes` long as it spooled,
    /// measured against `[limits] esign_body_bytes`. Past it the crossing is
    /// kept as an e-sign check, which the host's OF-520 worker asks the
    /// envelope's sender about as it asks a signature upload's, and the body
    /// is served whole: the row never refuses it. Answers the row's bound
    /// when the body crossed it.
    pub fn measure_esign_body(&self, ingress: &EsignIngress, bytes: u64) -> Result<Option<u64>> {
        let row = EngineLimit::EsignBodyBytes;
        let bound = self.limit_watch().bound(row);
        if bytes <= bound {
            return Ok(None);
        }
        let now = self.now_recorded_at();
        let document = ingress.document.to_hex();
        self.with_write_txn_grouped(|txn| {
            keep_limit_crossings(
                self,
                txn,
                &document,
                &ingress.recipient,
                &[(row, bound, bytes)],
                now,
            )
        })?;
        Ok(Some(bound))
    }
}
