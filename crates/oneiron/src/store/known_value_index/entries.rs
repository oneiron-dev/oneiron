//! The shared value-print matcher builder.

use super::{Bucket, Keys, Known, KnownValues, RollingSets, TAG_WINDOW, ValueOrigin};
use crate::error::{Error, Result};
use crate::store::KnownEntry;

impl KnownValues {
    pub(super) fn of_entries<'a>(
        master: &'a [u8; 32],
        values: impl IntoIterator<Item = (&'a KnownEntry, ValueOrigin, String)>,
    ) -> Result<Option<Self>> {
        let mut buckets: Vec<Bucket> = Vec::new();
        let mut rolling = RollingSets::default();
        let mut lengths = Vec::new();
        let mut longest = 0;
        for (entry, origin, handle) in values {
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
            if bucket
                .known
                .iter()
                .any(|known| known.len == len && known.fingerprint == entry.fingerprint)
            {
                continue;
            }
            longest = longest.max(len);
            lengths.push(len);
            bucket.known.push(Known {
                len,
                fingerprint: entry.fingerprint,
                origin,
                handle,
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
