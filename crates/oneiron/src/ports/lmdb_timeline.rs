//! Time-ordered entity cursors with exclusive resume positions.
use super::{EntityTime, PortRows, TimeAxis, TimelineQuery};
use crate::{
    EntityId,
    error::{Error, Result},
    store::{ManifestDbs, Store},
};
use heed::RoTxn;
use std::ops::Bound;
pub(super) fn timeline<'a>(
    store: &impl ManifestDbs,
    txn: &'a RoTxn<'_>,
    q: TimelineQuery,
) -> Result<PortRows<'a, EntityTime>> {
    // Seek by timestamp prefixes, not padded entity IDs. Padding a lower
    // bound to 24 bytes skips short corrupt keys at the boundary second;
    // padding an upper bound can likewise hide oversized keys in that second.
    let lower = match q.start {
        Bound::Unbounded => Bound::Unbounded,
        Bound::Included(t) => Bound::Included(t.to_be_bytes().to_vec()),
        Bound::Excluded(t) => match t.checked_add(1) {
            Some(next) => Bound::Included(next.to_be_bytes().to_vec()),
            None => return Ok(Box::new(std::iter::empty())),
        },
    };
    let upper = match q.end {
        Bound::Unbounded => Bound::Unbounded,
        Bound::Included(t) => t.checked_add(1).map_or(Bound::Unbounded, |next| {
            Bound::Excluded(next.to_be_bytes().to_vec())
        }),
        Bound::Excluded(t) => Bound::Excluded(t.to_be_bytes().to_vec()),
    };
    let mut lower = lower;
    let mut upper = upper;
    if let Some(after) = q.after {
        let cursor = Store::encode_temporal_key(after.timestamp, &after.id).to_vec();
        if q.reverse {
            let tighter = match &upper {
                Bound::Unbounded => true,
                Bound::Included(k) | Bound::Excluded(k) => cursor <= *k,
            };
            if tighter {
                upper = Bound::Excluded(cursor);
            }
        } else {
            let tighter = match &lower {
                Bound::Unbounded => true,
                Bound::Included(k) | Bound::Excluded(k) => cursor >= *k,
            };
            if tighter {
                lower = Bound::Excluded(cursor);
            }
        }
    }
    let bounds = (bound_as_slice(&lower), bound_as_slice(&upper));
    if let (Bound::Included(l) | Bound::Excluded(l), Bound::Included(u) | Bound::Excluded(u)) =
        bounds
        && l >= u
    {
        return Ok(Box::new(std::iter::empty()));
    }
    let db = match q.axis {
        TimeAxis::Learned => store.temporal_learned(),
        TimeAxis::OccurredStart => store.temporal_occurred_start(),
        TimeAxis::OccurredEnd => store.temporal_occurred_end(),
    };
    let rows: PortRows<'a, _> = if q.reverse {
        Box::new(db.rev_range(txn, &bounds)?)
    } else {
        Box::new(db.range(txn, &bounds)?)
    };
    let context = match q.axis {
        TimeAxis::Learned => "temporal learned key",
        TimeAxis::OccurredStart => "temporal occurred start key",
        TimeAxis::OccurredEnd => "temporal occurred end key",
    };
    Ok(Box::new(rows.map(move |row| {
        let (key, _) = row?;
        if key.len() != 24 {
            return Err(Error::CorruptedIndex(context));
        }
        Ok(EntityTime {
            timestamp: u64::from_be_bytes(
                key[..8]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex(context))?,
            ),
            id: EntityId::from_bytes(
                key[8..]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex(context))?,
            )
            .map_err(|_| Error::CorruptedIndex(context))?,
        })
    })))
}

fn bound_as_slice(b: &Bound<Vec<u8>>) -> Bound<&[u8]> {
    match b {
        Bound::Unbounded => Bound::Unbounded,
        Bound::Included(k) => Bound::Included(k.as_slice()),
        Bound::Excluded(k) => Bound::Excluded(k.as_slice()),
    }
}
