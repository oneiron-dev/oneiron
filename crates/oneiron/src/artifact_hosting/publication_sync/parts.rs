//! Core half of `artifact_hosting::publication_sync::parts`: its store-layer items live in `oneiron_store::artifact_hosting::publication_sync::parts` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::artifact_hosting::publication_sync::parts::*;

use super::{
    ArtifactPointerRowKey, ArtifactPublicationOutcome, PUBLICATION_OUTBOX, RECEIPT_LEN,
    publication_entity_id, readable_marker, write_publication,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::store::document_frame_tags::document_sub_tags;
use crate::store::framing::encode_document;
use heed::{RoTxn, RwTxn};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, Write};
use std::ops::Bound;

// The server's half: keeping parts, and settling a whole transfer.
mod receive;

const PARTS: SideTable<String, SpoolRow, Named> =
    SideTable::new(&side_table::ARTIFACT_PUBLICATION_PARTS);

fn spooled(
    store: &Store,
    txn: &RoTxn<'_>,
    side: Side,
    entity: &EntityId,
) -> Result<Option<Transfer>> {
    Ok(
        match PARTS.get(store, txn, &spool_key(side, entity, "m"))? {
            Some(SpoolRow::Transfer(transfer)) => Some(transfer),
            _ => None,
        },
    )
}

/// Removes a transfer and every part it holds; a settled row stays.
fn drop_transfer_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    side: Side,
    entity: &EntityId,
) -> Result<()> {
    PARTS.delete_from(store, wtxn, spool_key(side, entity, "p:").as_bytes())?;
    PARTS.delete(store, wtxn, &spool_key(side, entity, "m"))?;
    Ok(())
}

/// Removes what the device spooled for `entity`, whose publication a receipt
/// settled.
pub(super) fn drop_sent_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    drop_transfer_in_txn(store, wtxn, Side::Tx, entity)
}

/// The receipt frame of a complete publication: its digest and outcome.
fn publication_receipt_frame(
    entity: EntityId,
    digest: [u8; 32],
    outcome: ArtifactPublicationOutcome,
) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(RECEIPT_LEN);
    payload.extend_from_slice(&digest);
    payload.push(outcome.byte());
    encode_document(entity, document_sub_tags::ARTIFACT_RECEIPT, &payload)
        .map_err(|_| Error::InvariantViolation("artifact receipt exceeds wire limit"))
}

/// Where a connection stands in the publications it owes: which outbox key
/// it visited last, and each round under way. Local to one connection; the
/// outbox and the spool outlive it.
#[derive(Debug, Default)]
pub(crate) struct ArtifactPublicationCursor {
    after: Option<ArtifactPointerRowKey>,
    rounds: HashMap<EntityId, Round>,
}

impl ArtifactPublicationCursor {
    /// Moves on past `part` once it went out (`sent`), or forgets its round
    /// when it was dropped unsent. `true` when it ended its round.
    pub(crate) fn released(&mut self, part: &ArtifactPublicationPart, sent: bool) -> bool {
        if sent && part.end < part.total {
            self.rounds.insert(
                part.entity,
                Round {
                    digest: part.digest,
                    next: part.end,
                },
            );
            return false;
        }
        self.rounds.remove(&part.entity);
        sent
    }
}

/// One part ready to go, with what its release checks.
#[derive(Debug)]
pub(crate) struct ArtifactPublicationPart {
    key: ArtifactPointerRowKey,
    entity: EntityId,
    change_id: [u8; 16],
    /// The digest of the whole publication, which its receipt names.
    pub(crate) digest: [u8; 32],
    end: u64,
    total: u64,
    /// The document frame.
    pub(crate) frame: Vec<u8>,
}

/// What one pull found.
#[derive(Debug)]
pub(crate) enum ArtifactPublicationStep {
    /// A part to send.
    Ready(ArtifactPublicationPart),
    /// One publication did not prepare: it stays owed, and the next pull
    /// moves on to the next one.
    ItemError { entity: EntityId, error: Error },
    /// Nothing is due now.
    Idle,
}

impl Vault {
    /// Refuses a part at the socket's owner gate without reading or changing
    /// publication state. The receipt echoes only the supplied whole digest;
    /// an unreadable part has no receipt, as on the admitted import path.
    pub fn refused_artifact_publication_receipt(
        entity: EntityId,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        let Some(part) = Envelope::parse(payload) else {
            return Ok(None);
        };
        publication_receipt_frame(entity, part.digest, ArtifactPublicationOutcome::Refused)
            .map(Some)
    }

    /// The next part this device owes the sync server: the first outbox key
    /// after the cursor's, wrapping once, with a round under way, a change
    /// not spooled yet, or a spooled one `due` to go again. One step tries
    /// one key, and a key gives one part a visit.
    pub(crate) fn next_artifact_publication_step(
        &self,
        cursor: &mut ArtifactPublicationCursor,
        due: &dyn Fn(&[u8; 32]) -> bool,
    ) -> Result<ArtifactPublicationStep> {
        let Some((key, change_id, entity)) = self.next_owed_publication(cursor, due)? else {
            return Ok(ArtifactPublicationStep::Idle);
        };
        cursor.after = Some(key.clone());
        let round = cursor.rounds.get(&entity).copied();
        match self.publication_part(&key, change_id, entity, round) {
            Ok(part) => Ok(ArtifactPublicationStep::Ready(part)),
            Err(error) => {
                cursor.rounds.remove(&entity);
                Ok(ArtifactPublicationStep::ItemError { entity, error })
            }
        }
    }

    /// Whether `part`'s pointer still owes the change it carries: a part of
    /// a change since replaced, or of a publication a receipt settled, goes
    /// nowhere.
    pub(crate) fn artifact_publication_part_current(
        &self,
        part: &ArtifactPublicationPart,
    ) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        Ok(PUBLICATION_OUTBOX
            .get(&self.store, &txn, &part.key)?
            .is_some_and(|marker| marker.change_id == part.change_id))
    }

    fn next_owed_publication(
        &self,
        cursor: &ArtifactPublicationCursor,
        due: &dyn Fn(&[u8; 32]) -> bool,
    ) -> Result<Option<(ArtifactPointerRowKey, [u8; 16], EntityId)>> {
        let txn = self.store.env.read_txn()?;
        let ranges = match &cursor.after {
            Some(after) => vec![
                (Bound::Excluded(after), Bound::Unbounded),
                (Bound::Unbounded, Bound::Included(after)),
            ],
            None => vec![(Bound::Unbounded, Bound::Unbounded)],
        };
        for (start, end) in ranges {
            for row in PUBLICATION_OUTBOX.iter_range(&self.store, &txn, start, end)? {
                let Some((key, marker)) = readable_marker(row)? else {
                    continue;
                };
                let entity = publication_entity_id(key.channel, &key.artifact)?;
                let owes = cursor.rounds.contains_key(&entity)
                    || spooled(&self.store, &txn, Side::Tx, &entity)
                        .ok()
                        .flatten()
                        .is_none_or(|sent| sent.change_id != marker.change_id || due(&sent.digest));
                if owes {
                    return Ok(Some((key, marker.change_id, entity)));
                }
            }
        }
        Ok(None)
    }

    /// The part a visit to `key` gives: the next of a round under way while
    /// the spool still holds what it began with, else the first of a new
    /// round, spooled from the publication as it stands now.
    fn publication_part(
        &self,
        key: &ArtifactPointerRowKey,
        change_id: [u8; 16],
        entity: EntityId,
        round: Option<Round>,
    ) -> Result<ArtifactPublicationPart> {
        if let Some(round) = round {
            let txn = self.store.env.read_txn()?;
            if let Some(sent) = spooled(&self.store, &txn, Side::Tx, &entity)?
                && sent.change_id == change_id
                && sent.digest == round.digest
            {
                return sent_part_in_txn(&self.store, &txn, key, entity, &sent, round.next);
            }
        }
        let sent = self.spool_publication(key, change_id, entity)?;
        let txn = self.store.env.read_txn()?;
        sent_part_in_txn(&self.store, &txn, key, entity, &sent, 0)
    }

    /// The device's spool of `key`'s publication for change `change_id` as it
    /// stands now: kept when it already holds those bytes, else written
    /// again, part by part as the publication is serialized.
    fn spool_publication(
        &self,
        key: &ArtifactPointerRowKey,
        change_id: [u8; 16],
        entity: EntityId,
    ) -> Result<Transfer> {
        {
            let txn = self.store.env.read_txn()?;
            let digest = self.publication_digest_in_txn(&txn, key, change_id)?;
            if let Some(sent) = spooled(&self.store, &txn, Side::Tx, &entity)?
                && sent.change_id == change_id
                && sent.digest == digest
            {
                return Ok(sent);
            }
        }
        let mut wtxn = self.store.env.write_txn()?;
        drop_transfer_in_txn(&self.store, &mut wtxn, Side::Tx, &entity)?;
        let wire = self.publication_wire_in_txn(&wtxn, key, change_id)?;
        let mut writer = SpoolWriter {
            store: &self.store,
            wtxn: &mut wtxn,
            entity,
            part: Vec::new(),
            written: 0,
            hasher: blake3::Hasher::new(),
            failed: None,
        };
        let encoded = write_publication(&mut writer, &wire);
        let (digest, total) = writer.finish(encoded)?;
        let sent = Transfer {
            change_id,
            digest,
            total,
            held: total,
        };
        PARTS.put(
            &self.store,
            &mut wtxn,
            &spool_key(Side::Tx, &entity, "m"),
            &SpoolRow::Transfer(sent),
        )?;
        wtxn.commit()?;
        Ok(sent)
    }
}

/// The spooled part at `offset` of `sent`, framed.
fn sent_part_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    key: &ArtifactPointerRowKey,
    entity: EntityId,
    sent: &Transfer,
    offset: u64,
) -> Result<ArtifactPublicationPart> {
    let Some(SpoolRow::Part { bytes }) =
        PARTS.get(store, txn, &part_key(Side::Tx, &entity, offset))?
    else {
        return Err(Error::CorruptedIndex("artifact publication spool part"));
    };
    let part = Envelope {
        change_id: sent.change_id,
        digest: sent.digest,
        total: sent.total,
        offset,
        bytes: &bytes,
    };
    if bytes.is_empty() || part.end() > sent.total {
        return Err(Error::CorruptedIndex("artifact publication spool part"));
    }
    let frame = encode_document(
        entity,
        document_sub_tags::ARTIFACT_PUBLICATION,
        &part.encode()?,
    )
    .map_err(|_| Error::InvariantViolation("artifact publication part exceeds wire limit"))?;
    Ok(ArtifactPublicationPart {
        key: key.clone(),
        entity,
        change_id: sent.change_id,
        digest: sent.digest,
        end: part.end(),
        total: sent.total,
        frame,
    })
}

/// Writes a serialization into the device's spool one part at a time as it
/// is made, hashing it on the way: no more than one part is held.
struct SpoolWriter<'a, 't> {
    store: &'a Store,
    wtxn: &'a mut RwTxn<'t>,
    entity: EntityId,
    part: Vec<u8>,
    written: u64,
    hasher: blake3::Hasher,
    /// The spool write that failed, which the serializer saw only as an I/O
    /// error.
    failed: Option<Error>,
}

impl SpoolWriter<'_, '_> {
    fn put_part(&mut self) -> Result<()> {
        if self.part.is_empty() {
            return Ok(());
        }
        let bytes = std::mem::take(&mut self.part);
        self.hasher.update(&bytes);
        let key = part_key(Side::Tx, &self.entity, self.written);
        self.written = self.written.saturating_add(bytes.len() as u64);
        PARTS.put(self.store, self.wtxn, &key, &SpoolRow::Part { bytes })
    }

    /// The digest and length of what `encoded` serialized, its last part
    /// written; the spool's own failure before the serializer's.
    fn finish(mut self, encoded: Result<()>) -> Result<([u8; 32], u64)> {
        if let Some(error) = self.failed.take() {
            return Err(error);
        }
        encoded?;
        self.put_part()?;
        Ok((*self.hasher.finalize().as_bytes(), self.written))
    }
}

impl Write for SpoolWriter<'_, '_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let taken = bytes.len().min(PUBLICATION_PART_BYTES - self.part.len());
        self.part.extend_from_slice(&bytes[..taken]);
        if self.part.len() == PUBLICATION_PART_BYTES
            && let Err(error) = self.put_part()
        {
            self.failed = Some(error);
            return Err(io::Error::other("artifact publication spool write"));
        }
        Ok(taken)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
