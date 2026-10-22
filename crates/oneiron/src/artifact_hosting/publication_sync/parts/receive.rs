//! The sync server's half of publication parts (FIX 9575): each part kept
//! in order under the owner's live credential, and a whole transfer hashed,
//! decoded, bound to its change and applied, then answered once.

use std::io::{self, Read};

use heed::{RoTxn, RwTxn};

use super::super::{ArtifactPublicationOutcome, PublicationWire, denied};
use super::{
    Envelope, PARTS, Side, SpoolRow, Transfer, drop_transfer_in_txn, part_key,
    publication_receipt_frame, spool_key, spooled,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;

/// Reads a spooled transfer's bytes back in offset order: one part held at a
/// time. A missing part ends it as an error.
struct SpoolReader<'a, 't> {
    store: &'a Store,
    txn: &'a RoTxn<'t>,
    side: Side,
    entity: EntityId,
    at: u64,
    total: u64,
    part: Vec<u8>,
    read: usize,
    /// The storage read that failed, which the reader's caller saw only as
    /// an I/O error.
    failed: Option<Error>,
}

impl Read for SpoolReader<'_, '_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.read == self.part.len() {
            if self.at >= self.total {
                return Ok(0);
            }
            match PARTS.get(
                self.store,
                self.txn,
                &part_key(self.side, &self.entity, self.at),
            ) {
                Ok(Some(SpoolRow::Part { bytes })) if !bytes.is_empty() => {
                    self.at = self.at.saturating_add(bytes.len() as u64);
                    self.part = bytes;
                    self.read = 0;
                }
                Ok(_) => return Err(io::Error::other("artifact publication spool gap")),
                Err(error) => {
                    self.failed = Some(error);
                    return Err(io::Error::other("artifact publication spool read"));
                }
            }
        }
        let taken = out.len().min(self.part.len() - self.read);
        out[..taken].copy_from_slice(&self.part[self.read..self.read + taken]);
        self.read += taken;
        Ok(taken)
    }
}

/// What keeping one part came to.
enum Kept {
    /// No progress: a later part of no transfer here, a gap, or a span that
    /// disagrees with the one kept.
    Nothing,
    /// The transfer was settled already, with this outcome.
    Settled(ArtifactPublicationOutcome),
    /// The transfer, holding the part.
    Held(Transfer),
}

impl Vault {
    /// Keeps one part of `entity`'s publication, and settles the transfer
    /// once its last part makes it whole.
    pub(in super::super) fn import_publication_part(
        &self,
        entity: EntityId,
        payload: &[u8],
        live: &dyn Fn(&RwTxn<'_>) -> bool,
    ) -> Result<Option<Vec<u8>>> {
        let Some(part) = Envelope::parse(payload) else {
            tracing::warn!("an artifact publication part did not read; nothing of it is kept");
            return Ok(None);
        };
        let last = part.end() == part.total;
        match self.keep_part(entity, &part, live)? {
            Kept::Settled(outcome) if last => {
                publication_receipt_frame(entity, part.digest, outcome).map(Some)
            }
            Kept::Held(transfer) if last && transfer.held == transfer.total => {
                self.settle_transfer(entity, &transfer, live)
            }
            _ => Ok(None),
        }
    }

    fn keep_part(
        &self,
        entity: EntityId,
        part: &Envelope<'_>,
        live: &dyn Fn(&RwTxn<'_>) -> bool,
    ) -> Result<Kept> {
        let mut wtxn = self.store.env.write_txn()?;
        if !live(&wtxn) {
            return Err(denied());
        }
        if let Some(SpoolRow::Settled {
            change_id,
            digest,
            outcome,
        }) = PARTS.get(&self.store, &wtxn, &spool_key(Side::Rx, &entity, "s"))?
            && change_id == part.change_id
            && digest == part.digest
        {
            return Ok(
                ArtifactPublicationOutcome::from_byte(outcome).map_or(Kept::Nothing, Kept::Settled)
            );
        }
        let mut transfer = match spooled(&self.store, &wtxn, Side::Rx, &entity)? {
            Some(transfer)
                if transfer.change_id == part.change_id
                    && transfer.digest == part.digest
                    && transfer.total == part.total =>
            {
                transfer
            }
            // A change's first part replaces whatever did not finish.
            _ if part.offset == 0 => {
                drop_transfer_in_txn(&self.store, &mut wtxn, Side::Rx, &entity)?;
                Transfer {
                    change_id: part.change_id,
                    digest: part.digest,
                    total: part.total,
                    held: 0,
                }
            }
            _ => return Ok(Kept::Nothing),
        };
        if part.offset < transfer.held {
            // An earlier span sent again is harmless while it agrees.
            let agrees = matches!(
                PARTS.get(&self.store, &wtxn, &part_key(Side::Rx, &entity, part.offset))?,
                Some(SpoolRow::Part { bytes }) if bytes == part.bytes
            );
            return Ok(if agrees {
                Kept::Held(transfer)
            } else {
                Kept::Nothing
            });
        }
        if part.offset > transfer.held {
            return Ok(Kept::Nothing);
        }
        PARTS.put(
            &self.store,
            &mut wtxn,
            &part_key(Side::Rx, &entity, part.offset),
            &SpoolRow::Part {
                bytes: part.bytes.to_vec(),
            },
        )?;
        transfer.held = part.end();
        PARTS.put(
            &self.store,
            &mut wtxn,
            &spool_key(Side::Rx, &entity, "m"),
            &SpoolRow::Transfer(transfer),
        )?;
        wtxn.commit()?;
        Ok(Kept::Held(transfer))
    }

    /// Settles a whole transfer: its bytes hashed against the digest every
    /// part named, then the publication decoded, bound to the transfer's
    /// change and applied. `Applied` and `Refused` settle it, `Staged`
    /// keeps it for the next round. Bytes that do not make the digest are
    /// dropped with no receipt, since none may claim it.
    fn settle_transfer(
        &self,
        entity: EntityId,
        transfer: &Transfer,
        live: &dyn Fn(&RwTxn<'_>) -> bool,
    ) -> Result<Option<Vec<u8>>> {
        use ArtifactPublicationOutcome::{Applied, Refused, Staged};
        let mut wtxn = self.store.env.write_txn()?;
        if !live(&wtxn) {
            return Err(denied());
        }
        if !self.received_whole_in_txn(&wtxn, entity, transfer)? {
            drop_transfer_in_txn(&self.store, &mut wtxn, Side::Rx, &entity)?;
            wtxn.commit()?;
            tracing::warn!(
                "an artifact publication's parts did not make the digest they name; it is sent again"
            );
            return Ok(None);
        }
        let outcome = match self.received_wire_in_txn(&wtxn, entity, transfer)? {
            Some(wire) if wire.change_id == transfer.change_id => {
                self.apply_publication_in_txn(&mut wtxn, entity, wire)?
            }
            _ => Refused,
        };
        match outcome {
            Staged => drop(wtxn),
            Applied => {
                settle_received_in_txn(&self.store, &mut wtxn, &entity, transfer, Applied)?;
                wtxn.commit()?;
            }
            Refused => {
                drop(wtxn);
                let mut wtxn = self.store.env.write_txn()?;
                if !live(&wtxn) {
                    return Err(denied());
                }
                settle_received_in_txn(&self.store, &mut wtxn, &entity, transfer, Refused)?;
                wtxn.commit()?;
            }
        }
        publication_receipt_frame(entity, transfer.digest, outcome).map(Some)
    }

    fn received_reader<'a, 't>(
        &'a self,
        txn: &'a RoTxn<'t>,
        entity: EntityId,
        transfer: &Transfer,
    ) -> SpoolReader<'a, 't> {
        SpoolReader {
            store: &self.store,
            txn,
            side: Side::Rx,
            entity,
            at: 0,
            total: transfer.total,
            part: Vec::new(),
            read: 0,
            failed: None,
        }
    }

    /// Whether the received bytes are the transfer's: its whole length, in
    /// order, hashing to its digest.
    fn received_whole_in_txn(
        &self,
        txn: &RoTxn<'_>,
        entity: EntityId,
        transfer: &Transfer,
    ) -> Result<bool> {
        let mut reader = self.received_reader(txn, entity, transfer);
        let mut hasher = blake3::Hasher::new();
        let copied = io::copy(&mut reader, &mut hasher);
        if let Some(error) = reader.failed.take() {
            return Err(error);
        }
        Ok(copied.is_ok_and(|length| length == transfer.total)
            && *hasher.finalize().as_bytes() == transfer.digest)
    }

    /// The publication the received bytes decode to, `None` when they do
    /// not.
    fn received_wire_in_txn(
        &self,
        txn: &RoTxn<'_>,
        entity: EntityId,
        transfer: &Transfer,
    ) -> Result<Option<PublicationWire>> {
        let mut reader = self.received_reader(txn, entity, transfer);
        let wire = rmp_serde::from_read::<_, PublicationWire>(&mut reader).ok();
        if let Some(error) = reader.failed.take() {
            return Err(error);
        }
        Ok(wire)
    }
}

/// Drops a settled transfer's parts and keeps its identity and outcome, so
/// the same transfer sent again is answered, never applied again.
fn settle_received_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    entity: &EntityId,
    transfer: &Transfer,
    outcome: ArtifactPublicationOutcome,
) -> Result<()> {
    drop_transfer_in_txn(store, wtxn, Side::Rx, entity)?;
    PARTS.put(
        store,
        wtxn,
        &spool_key(Side::Rx, entity, "s"),
        &SpoolRow::Settled {
            change_id: transfer.change_id,
            digest: transfer.digest,
            outcome: outcome.byte(),
        },
    )
}
