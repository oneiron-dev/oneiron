//! The shared value-print matcher builder.

use std::collections::BTreeSet;

use oneiron_store::known_value_index::forms;

use super::{Bucket, Keys, Known, KnownSpan, KnownValues, RollingSets, TAG_WINDOW, ValueOrigin};
use crate::error::{Error, Result};
use crate::store::KnownEntry;

impl KnownValues {
    /// Whether `handle` is the handle of a custody record a value the index
    /// knows is held by: a compare that keeps it as written reads that
    /// record's value only (FIX REPLAY-COMPARE-KNOWN-OTHER-CALLERS).
    pub(crate) fn holds_handle(&self, handle: &str) -> bool {
        self.buckets
            .iter()
            .flat_map(|bucket| &bucket.known)
            .any(|known| matches!(known.origin, ValueOrigin::Custody(_)) && known.handle == handle)
    }

    /// Each value a custody record `holds` takes holds in `data`, past those
    /// `keep` exempts, as [`Self::spans_except`] reads them, with every
    /// other value out before the longest at a place is chosen (FIX
    /// RECEIPT-RECORDS-CALL-HELD-INPUT): a compare reads a held row and its
    /// offer for the values of the records the row names alone, so a longer
    /// value another record took since never hides the one a handle names.
    /// `holds` reads each value's record handle and the custody slot its
    /// entry is held at, so a read can stop at the slot each record had
    /// (FIX ERASED-IDENTITY-ROTATION-GENERATION). With `longest`, only
    /// those values at most that many bytes long are read. A base64 run is
    /// read as far as those values reach alone, so a record named nowhere
    /// never changes what is read (blind review round 2 of #9528).
    pub(crate) fn spans_held_by(
        &self,
        data: &[u8],
        keep: impl Fn(&[u8]) -> bool,
        holds: impl Fn(&str, u64) -> bool,
        longest: Option<usize>,
    ) -> Vec<KnownSpan<'_>> {
        let admits = |known: &Known| {
            matches!(known.origin, ValueOrigin::Custody(_))
                && holds(known.handle.as_str(), known.slot)
                && longest.is_none_or(|longest| known.len <= longest)
        };
        let reach = self
            .admitted(&admits)
            .map(|known| known.len)
            .max()
            .unwrap_or(0)
            .saturating_mul(forms::KNOWN_FORM_REACH_FACTOR);
        self.matched_spans_by(data, keep, &admits, reach)
            .into_iter()
            .filter_map(|hit| match hit.origin {
                ValueOrigin::Custody(custody) => Some(KnownSpan {
                    span: hit.span,
                    custody,
                    handle: hit.handle,
                }),
                ValueOrigin::Person => None,
            })
            .collect()
    }

    /// Whether `data` is, whole, one value the custody record `handle`
    /// holds, at any generation its history keeps, in any spelling
    /// [`Self::spans_except`] reads (FIX RECEIPT-RECORDS-CALL-HELD-INPUT):
    /// what a handle a held row keeps meets in the offer read against it.
    pub(crate) fn is_whole_held_by(&self, data: &[u8], handle: &str) -> bool {
        !data.is_empty()
            && self
                .spans_held_by(data, |_| false, |held, _| held == handle, None)
                .first()
                .is_some_and(|hit| hit.span == (0..data.len()))
    }

    /// Each length a value a custody record `holds` takes holds has, at any
    /// generation its history keeps, ascending, each once.
    pub(crate) fn held_lengths(&self, holds: impl Fn(&str) -> bool) -> Vec<usize> {
        let lengths: BTreeSet<usize> = self
            .admitted(&|known: &Known| {
                matches!(known.origin, ValueOrigin::Custody(_)) && holds(known.handle.as_str())
            })
            .map(|known| known.len)
            .collect();
        lengths.into_iter().collect()
    }

    /// The newest custody slot an entry of the custody record `handle`
    /// that this index read is held at, or `None` when it knows no value
    /// of that record: what an erase pins each record it names at (FIX
    /// ERASED-IDENTITY-ROTATION-GENERATION). A value the record takes later,
    /// at a new generation or its current one, is held past it.
    pub(crate) fn held_slot(&self, handle: &str) -> Option<u64> {
        self.admitted(&|known: &Known| {
            matches!(known.origin, ValueOrigin::Custody(_)) && known.handle == handle
        })
        .map(|known| known.newest_slot)
        .max()
    }

    /// Each value the index knows that `admits` takes.
    fn admitted<'s>(
        &'s self,
        admits: &'s dyn Fn(&Known) -> bool,
    ) -> impl Iterator<Item = &'s Known> + 's {
        self.buckets
            .iter()
            .flat_map(|bucket| &bucket.known)
            .filter(move |known| admits(known))
    }

    /// The matcher over `values`, each an entry, the custody slot it is
    /// held at, its origin and its handle, or `None` when it holds no
    /// value.
    pub(super) fn of_entries<'a>(
        master: &'a [u8; 32],
        values: impl IntoIterator<Item = (&'a KnownEntry, u64, ValueOrigin, String)>,
    ) -> Result<Option<Self>> {
        let mut buckets: Vec<Bucket> = Vec::new();
        let mut rolling = RollingSets::default();
        let mut lengths = Vec::new();
        let mut longest = 0;
        for (entry, slot, origin, handle) in values {
            let len = usize::try_from(entry.len)
                .map_err(|_| Error::ArithmeticOverflow("known value length"))?;
            if len == 0 {
                continue;
            }
            rolling.insert(len.min(TAG_WINDOW), entry.rolling);
            let at = match buckets.binary_search_by(|bucket| bucket.tag.cmp(&entry.tag)) {
                Ok(at) => at,
                Err(at) => {
                    buckets.insert(
                        at,
                        Bucket {
                            tag: entry.tag,
                            known: Vec::new(),
                        },
                    );
                    at
                }
            };
            let bucket = &mut buckets[at];
            // Each holder of the same bytes keeps its own entry (FIX 8966):
            // the first still wins a place, and a holder enumeration sees
            // every record a release of those bytes shows. One holder's
            // bytes match at their lowest slot and pin at their highest.
            if let Some(known) = bucket.known.iter_mut().find(|known| {
                known.len == len && known.fingerprint == entry.fingerprint && known.origin == origin
            }) {
                known.slot = known.slot.min(slot);
                known.newest_slot = known.newest_slot.max(slot);
                continue;
            }
            longest = longest.max(len);
            lengths.push(len);
            bucket.known.push(Known {
                len,
                fingerprint: entry.fingerprint,
                origin,
                handle,
                slot,
                newest_slot: slot,
            });
        }
        if buckets.is_empty() {
            return Ok(None);
        }
        for bucket in &mut buckets {
            bucket
                .known
                .sort_by_key(|known| std::cmp::Reverse(known.len));
        }
        lengths.sort_unstable();
        lengths.dedup();
        Ok(Some(Self {
            keys: Keys::derive(master),
            buckets,
            windows: rolling.windows().collect(),
            rolling,
            lengths,
            longest,
        }))
    }
}
