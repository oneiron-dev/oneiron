//! Pre-admitted payload allocations for native retained-review decoding.

use std::fmt;

use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

use super::payload::reserve_memory;
use super::{FederationBurstReviewBundle, corrupt};

#[derive(Deserialize)]
struct ReviewPayloadSizes {
    updates: Vec<ReviewUpdateSize>,
}

#[derive(Deserialize)]
struct ReviewUpdateSize {
    admitted_update: PayloadSize,
}

struct PayloadSize(usize);

impl<'de> Deserialize<'de> for PayloadSize {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SizeVisitor;

        impl<'de> Visitor<'de> for SizeVisitor {
            type Value = PayloadSize;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an admitted update byte array")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut size = 0;
                while sequence.next_element::<u8>()?.is_some() {
                    size += 1;
                }
                Ok(PayloadSize(size))
            }
        }

        deserializer.deserialize_seq(SizeVisitor)
    }
}

pub(super) fn decode(bytes: &[u8]) -> crate::Result<FederationBurstReviewBundle> {
    // This projection allocates only per-update metadata, not payload bytes.
    let sizes: ReviewPayloadSizes = rmp_serde::from_slice(bytes).map_err(|_| corrupt())?;
    let reservations = sizes
        .updates
        .into_iter()
        .map(|update| reserve_memory(update.admitted_update.0 as u64))
        .collect::<crate::Result<Vec<_>>>()?;
    let mut bundle: FederationBurstReviewBundle =
        rmp_serde::from_slice(bytes).map_err(|_| corrupt())?;
    for (update, mut memory) in bundle.updates.iter_mut().zip(reservations) {
        let reserved = memory.bytes();
        memory.materialized(reserved, update.admitted_update.capacity() as u64);
        update.admitted_update.attach_memory(memory);
    }
    Ok(bundle)
}
