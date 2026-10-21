//! The typed authorization a content-free publisher issue signature carries
//! into admission (OF-420, FIX 739). The publisher delivery mints it
//! in-process for one frozen signature send; admission and every live retry
//! check it under the outbound writer. The effect must be the `signature`
//! verb on the frozen channel and logical send, and the delivery's custody
//! must still let those exact bytes leave to that destination, with the
//! owner's participation and the publisher dial both on. The gate's own
//! participation grant authorizes the send: this names no grant, carries no
//! owner press and never widens the bundle send's one-time approval.

use crate::Vault;
use crate::feedback::REPORT_SIGNATURE_VERB;
use crate::outbound_chokepoint::PreparedEffect;
use crate::outbound_intent_ledger::IntentLedgerError;

/// One frozen issue-signature send, as the publisher delivery froze it.
/// Minted only in-process by that delivery; never decoded from input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublisherSignatureAuthorization {
    pub(crate) issue_ref: String,
    pub(crate) publisher_ref: String,
    pub(crate) channel: String,
    pub(crate) endpoint: String,
    pub(crate) digest: String,
    pub(crate) send_ref: String,
}

impl PublisherSignatureAuthorization {
    pub(crate) fn new(
        issue_ref: String,
        publisher_ref: String,
        channel: String,
        endpoint: String,
        digest: String,
        send_ref: String,
    ) -> Self {
        Self {
            issue_ref,
            publisher_ref,
            channel,
            endpoint,
            digest,
            send_ref,
        }
    }
}

/// Admits one signature send under the outbound writer, or refuses it with
/// nothing recorded.
///
/// # Errors
///
/// [`IntentLedgerError::InvalidInput`] when the prepared effect is not this
/// signature's send, or when its custody no longer lets it leave; storage
/// errors.
pub(crate) fn validate_publisher_signature_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    authorization: &PublisherSignatureAuthorization,
    prepared: &PreparedEffect,
) -> Result<(), IntentLedgerError> {
    if prepared.tool != REPORT_SIGNATURE_VERB
        || prepared.server != authorization.channel
        || prepared.resolved_endpoint.is_some()
        || prepared.gate.scoped_mcp_call.is_some()
        || prepared.gate.send_ref.as_deref() != Some(authorization.send_ref.as_str())
    {
        return Err(IntentLedgerError::InvalidInput(
            "publisher signature preparation mismatch",
        ));
    }
    if !vault.report_signature_admissible_in_txn(txn, authorization)? {
        return Err(IntentLedgerError::InvalidInput(
            "publisher signature may no longer leave",
        ));
    }
    Ok(())
}
