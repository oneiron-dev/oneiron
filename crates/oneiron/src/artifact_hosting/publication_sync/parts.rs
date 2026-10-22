//! Bounded publication parts (FIX 9575).
//!
//! A publication goes to the sync server as one or more parts on the
//! `ARTIFACT_PUBLICATION` document kind, each at most
//! [`PUBLICATION_PART_BYTES`] of the serialized publication behind a fixed
//! header: its change id, the BLAKE3 of the whole serialization, its total
//! length, the part's offset and the part's length. No publication outgrows
//! a frame, and a small one, an unpublish included, is one part.
//!
//! The device writes each publication it owes into its spool when the
//! publication changes, checked again at the start of every round, and pulls
//! one part at a time, a turn for each owed publication in outbox order, so
//! one large publication, or one that does not prepare, holds back no other.
//! The server keeps each part, in order, under the owner's live credential,
//! and applies the publication only once every part is there and the whole
//! hashes to the digest every part names. Only that complete publication is
//! answered, with the 33-byte receipt of digest and outcome; no part is
//! acknowledged on its own. A change's first part replaces a transfer that
//! did not finish; a later part never starts or revives one, and a settled
//! transfer sent again is answered with its receipt, never applied again.
//!
//! The spool is runtime state under the `bulk:` prefix: a restore drops it,
//! and the canonical outbox sends the publication again from its first part.
//! It is kept per publication entity: `tx` rows on the device, `rx` rows on
//! the server.

use std::collections::HashMap;
use std::io::{self, Write};
use std::ops::Bound;

use heed::{RoTxn, RwTxn};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use super::{
    ArtifactPointerRowKey, ArtifactPublicationOutcome, PUBLICATION_OUTBOX, RECEIPT_LEN,
    publication_entity_id, readable_marker, write_publication,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::sync::transport::{document_sub_tags, encode_document};

/// The most bytes of a serialized publication one part carries. A part's
/// frame is this, its 68-byte header and the 18-byte document frame, well
/// under the server's default per-update gate. It bounds one part, never a
/// publication or the outbox.
const PUBLICATION_PART_BYTES: usize = 256 * 1024;

/// A part's header: change id (16), digest (32), total and offset (u64 be),
/// and the part's length (u32 be).
const PART_HEADER_LEN: usize = 68;

const PARTS: SideTable<String, SpoolRow, Named> =
    SideTable::new(&side_table::ARTIFACT_PUBLICATION_PARTS);

// The server's half: keeping parts, and settling a whole transfer.
mod receive;

/// One spool row.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum SpoolRow {
    /// A transfer's identity, and how many of its bytes the spool holds from
    /// offset 0 on: all of them on the device.
    Transfer(Transfer),
    /// One part's bytes, at the offset its key names.
    Part {
        #[serde(with = "spool_bytes")]
        bytes: Vec<u8>,
    },
    /// The last transfer the server settled, and its outcome's byte.
    Settled {
        change_id: [u8; 16],
        digest: [u8; 32],
        outcome: u8,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transfer {
    change_id: [u8; 16],
    digest: [u8; 32],
    total: u64,
    held: u64,
}

/// Which end of the lane a spool row is kept at.
#[derive(Clone, Copy)]
enum Side {
    /// The device that sends.
    Tx,
    /// The server that receives.
    Rx,
}

/// A spool key: the side, the publication entity's hex, then the row: `m`
/// the transfer, `p:<offset as 16 hex>` one part, `s` the last one settled.
fn spool_key(side: Side, entity: &EntityId, row: &str) -> String {
    let side = match side {
        Side::Tx => "tx",
        Side::Rx => "rx",
    };
    format!("{side}:{}:{row}", entity.to_hex())
}

fn part_key(side: Side, entity: &EntityId, offset: u64) -> String {
    spool_key(side, entity, &format!("p:{offset:016x}"))
}

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

/// A fresh change id: 16 bytes of OS entropy.
pub(super) fn new_publication_change_id() -> [u8; 16] {
    let mut change_id = [0_u8; 16];
    OsRng.fill_bytes(&mut change_id);
    change_id
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
        .into_result()
        .map_err(|_| Error::InvariantViolation("artifact receipt exceeds wire limit"))
}

/// One part as it rides the wire.
struct Envelope<'p> {
    change_id: [u8; 16],
    digest: [u8; 32],
    total: u64,
    offset: u64,
    bytes: &'p [u8],
}

impl<'p> Envelope<'p> {
    /// Reads a part: its exact length, a nonempty span, and an end no later
    /// than the total. Anything else is `None`.
    fn parse(payload: &'p [u8]) -> Option<Self> {
        let (header, bytes) = payload.split_at_checked(PART_HEADER_LEN)?;
        let word = |at: usize| -> Option<u64> {
            Some(u64::from_be_bytes(header.get(at..at + 8)?.try_into().ok()?))
        };
        let len = u32::from_be_bytes(header.get(64..68)?.try_into().ok()?);
        let part = Self {
            change_id: header.get(..16)?.try_into().ok()?,
            digest: header.get(16..48)?.try_into().ok()?,
            total: word(48)?,
            offset: word(56)?,
            bytes,
        };
        let fits = usize::try_from(len).ok()? == bytes.len()
            && !bytes.is_empty()
            && part.offset.checked_add(u64::from(len))? <= part.total;
        fits.then_some(part)
    }

    fn end(&self) -> u64 {
        self.offset.saturating_add(self.bytes.len() as u64)
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let len = u32::try_from(self.bytes.len())
            .map_err(|_| Error::InvariantViolation("artifact publication part length"))?;
        let mut payload = Vec::with_capacity(PART_HEADER_LEN + self.bytes.len());
        payload.extend_from_slice(&self.change_id);
        payload.extend_from_slice(&self.digest);
        payload.extend_from_slice(&self.total.to_be_bytes());
        payload.extend_from_slice(&self.offset.to_be_bytes());
        payload.extend_from_slice(&len.to_be_bytes());
        payload.extend_from_slice(self.bytes);
        Ok(payload)
    }
}

/// Where a connection stands in the publications it owes: which outbox key
/// it visited last, and each round under way. Local to one connection; the
/// outbox and the spool outlive it.
#[derive(Debug, Default)]
pub(crate) struct ArtifactPublicationCursor {
    after: Option<ArtifactPointerRowKey>,
    rounds: HashMap<EntityId, Round>,
}

/// A round under way: the digest it sends and the offset of its next part.
#[derive(Debug, Clone, Copy)]
struct Round {
    digest: [u8; 32],
    next: u64,
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
    .into_result()
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

/// A part's bytes as one msgpack bin, not an array of integers.
mod spool_bytes {
    use serde::{Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], out: S) -> Result<S::Ok, S::Error> {
        out.serialize_bytes(bytes)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(input: D) -> Result<Vec<u8>, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, bytes: &[u8]) -> Result<Vec<u8>, E> {
                Ok(bytes.to_vec())
            }
            fn visit_byte_buf<E: serde::de::Error>(self, bytes: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(bytes)
            }
        }
        input.deserialize_bytes(Visitor)
    }
}
