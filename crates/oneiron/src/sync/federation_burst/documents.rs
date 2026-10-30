//! A federation peer's text doors (FIX 8861). On a federation lane a document
//! frame is a peer's text: its write is admitted in the transaction that
//! lands it, and each local text released to it is admitted on its own, then
//! again right before its send. Both read this peer's own grant and its
//! authenticated selector in the transaction that judges them; nothing the
//! peer claims in a frame is authority.

use heed::RoTxn;

use super::FederationPeer;
use crate::authority::PeerMachine;
use crate::error::Result;
use crate::sync::transport::{TAG_DOCUMENT, decode_document, document_sub_tags};
use crate::{EntityId, Vault};

impl FederationPeer {
    /// Whether this peer may write `entity`'s text here, read in the writer
    /// that lands it: its grant stands, `machine` may read the text, and the
    /// live selector admits writing the entity.
    pub(in crate::sync) fn admit_document_write_in_txn(
        &self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        entity: EntityId,
        machine: PeerMachine,
    ) -> Result<()> {
        self.revalidate_in_txn(vault, txn)?;
        crate::sync::documents::admit_document_destination_in_txn(vault, txn, entity, machine)?;
        crate::sync::selector::admit_document_write_in_txn(
            vault,
            txn,
            entity,
            self.scope,
            &self.selector,
        )
    }

    /// Whether this peer may read `entity`'s text, read in `txn`: its grant
    /// stands and the live selector admits reading the entity.
    pub(in crate::sync) fn admit_document_read_in_txn(
        &self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        entity: EntityId,
    ) -> Result<()> {
        self.revalidate_in_txn(vault, txn)?;
        crate::sync::selector::admit_document_read_in_txn(
            vault,
            txn,
            entity,
            self.scope,
            &self.selector,
        )
    }

    /// Whether an outgoing document `frame` carries text this peer may not
    /// read now, judged as it is released. Requests and ACKs carry no text;
    /// a frame that does not decode, or a read that fails, stays.
    pub(in crate::sync) fn document_frame_withheld(&self, vault: &Vault, frame: &[u8]) -> bool {
        if frame.first() != Some(&TAG_DOCUMENT) {
            return false;
        }
        let Ok(document) = decode_document(&frame[1..]) else {
            return true;
        };
        if matches!(
            document.kind,
            document_sub_tags::REQUEST | document_sub_tags::ACK
        ) {
            return false;
        }
        vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)
            .and_then(|txn| self.admit_document_read_in_txn(vault, &txn, document.entity))
            .is_err()
    }
}
