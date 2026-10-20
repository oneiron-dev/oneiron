//! Known custody values in a streamed ASSET body (FIX 5395, CALLS
//! KNOWN_VALUE_STREAM_FINDER). The stream door stages a long body before the
//! batch door sees it, and a body it binds as a file reaches the batch door
//! as a manifest, so the batch door's mark of a file's known values never
//! reads it. The stream is read here as it passes instead: each value the
//! known-value index holds is found, a value split across two frames
//! included, by carrying the last `longest - 1` bytes into the next frame
//! and taking at each place the longest value whole there. The bytes are
//! never changed: the body and its digest stay as streamed.
//!
//! In the put's own transaction each value found is marked as the batch door
//! marks a file's known value: its span in the stored bytes, the custody
//! record that holds it, reason `gate.secret_scan.known_value`, the file's
//! band; a value the owner ruled no secret in the record is left unmarked. A
//! marked file stays a file, and the batch door keeps the mark and restricts
//! the record by the file's digest (FIX 5507). Nothing is refused or skipped
//! for its size or its count of values: the carry holds up to the longest
//! value, and the marks grow with what is found.

use std::ops::Range;
use std::sync::Arc;

use heed::RwTxn;
use zeroize::Zeroizing;

use super::REASON_KNOWN_VALUE;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::secret_custody::{
    KeptValues, KeySpan, KnownValues, MASKED_FILE_BAND, MaskedFile, masked_file_in_txn,
    put_masked_file_in_txn,
};
use crate::store::Store;

/// How a streamed ASSET body meets a value custody holds (CALLS
/// KNOWN_VALUE_STREAM_FINDER).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KnownValueStreamFinder {
    /// Found as the stream passes, and marked in the put's transaction as
    /// the batch door marks a file's known value; the bytes stay as
    /// streamed.
    MarkLikeBatch,
}

const KNOWN_VALUE_STREAM_FINDER: KnownValueStreamFinder = KnownValueStreamFinder::MarkLikeBatch;

/// One known value in a stream: its span in the whole stream, and the
/// custody record that holds it.
struct StreamHit {
    span: Range<u64>,
    custody: EntityId,
}

/// A stream's mark-only finder: see the module notes.
pub(crate) struct KnownStreamFinder {
    known: Arc<KnownValues>,
    /// The bytes a value could still be arriving in.
    held: Zeroizing<Vec<u8>>,
    /// Where `held` starts in the stream.
    base: u64,
    hits: Vec<StreamHit>,
}

impl KnownStreamFinder {
    pub(crate) fn new(known: Arc<KnownValues>) -> Self {
        Self {
            known,
            held: Zeroizing::new(Vec::new()),
            base: 0,
            hits: Vec::new(),
        }
    }

    /// Reads `frame`: each value that starts far enough from the held
    /// bytes' end to be whole there is found, and the rest is held.
    pub(crate) fn feed(&mut self, frame: &[u8]) {
        self.held.extend_from_slice(frame);
        let hold = self.known.longest().saturating_sub(1);
        if self.held.len() > hold {
            self.find_until(self.held.len() - hold);
        }
    }

    /// What the stream held, read to its end once it ends.
    pub(crate) fn finish(mut self) -> StreamKnown {
        self.find_until(self.held.len());
        StreamKnown(self.hits)
    }

    /// Finds each value in the held bytes that starts before `limit`, the
    /// longest at each place, and drops the held bytes before the place the
    /// next search starts at.
    fn find_until(&mut self, limit: usize) {
        let mut from = 0;
        for hit in self.known.spans(&self.held) {
            if hit.span.start >= limit {
                break;
            }
            self.hits.push(StreamHit {
                span: self.base + hit.span.start as u64..self.base + hit.span.end as u64,
                custody: hit.custody,
            });
            from = hit.span.end;
        }
        let end = from.max(limit);
        self.held.drain(..end).for_each(drop);
        self.base += end as u64;
    }
}

/// What a finder found in one stream, for the put's transaction.
#[derive(Default)]
pub(crate) struct StreamKnown(Vec<StreamHit>);

impl StreamKnown {
    /// Marks the values found in the file `hash` names, which ASSET `record`
    /// puts, in `txn` (KNOWN_VALUE_STREAM_FINDER), unless the file is marked
    /// already: each but a value the owner ruled no secret in `record`, whose
    /// bytes `read` gives back by offset and length.
    ///
    /// # Errors
    ///
    /// `read`'s errors, and storage errors.
    pub(crate) fn mark_in_txn(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        record: &EntityId,
        hash: &[u8; 32],
        read: impl Fn(u64, usize) -> Result<Vec<u8>>,
    ) -> Result<()> {
        if self.0.is_empty() || masked_file_in_txn(store, txn, hash)?.is_some() {
            return Ok(());
        }
        let keys = match KNOWN_VALUE_STREAM_FINDER {
            KnownValueStreamFinder::MarkLikeBatch => self.batch_keys(store, txn, record, read)?,
        };
        if keys.is_empty() {
            return Ok(());
        }
        let file = MaskedFile {
            band: MASKED_FILE_BAND,
            keys,
            masked_at: crate::ports::recorded_at_in_txn(store, txn)?,
            members: Vec::new(),
        };
        put_masked_file_in_txn(store, txn, hash, &file)
    }

    /// Each value found, as the batch door keys a file's known value, but
    /// one the owner ruled no secret in `record`.
    fn batch_keys(
        &self,
        store: &Store,
        txn: &RwTxn<'_>,
        record: &EntityId,
        read: impl Fn(u64, usize) -> Result<Vec<u8>>,
    ) -> Result<Vec<KeySpan>> {
        let kept = KeptValues::for_records_in_txn(store, txn, [*record])?;
        let mut keys = Vec::with_capacity(self.0.len());
        for hit in &self.0 {
            if !kept.is_empty() {
                let len = usize::try_from(hit.span.end - hit.span.start)
                    .map_err(|_| Error::ArithmeticOverflow("streamed known value length"))?;
                let value = Zeroizing::new(read(hit.span.start, len)?);
                if kept.holds(record, &value) {
                    continue;
                }
            }
            keys.push(KeySpan {
                start: hit.span.start,
                end: hit.span.end,
                custody: hit.custody,
                reason: REASON_KNOWN_VALUE.to_owned(),
            });
        }
        Ok(keys)
    }
}
