//! Owned keyed-memory output lifts for opaque stored JSON (FIX 12936).

use super::{Lift, OneironError, WireJson};

impl Lift<oneiron::memory::KeyValueItem> for crate::KeyValueItem {
    fn lift(item: oneiron::memory::KeyValueItem) -> Result<Self, OneironError> {
        let oneiron::memory::KeyValueItem {
            namespace,
            key,
            value,
            created_at,
            updated_at,
            revision,
        } = item;
        let value = WireJson::lift(value)?;
        Ok(Self {
            namespace,
            key,
            value,
            created_at,
            updated_at,
            revision,
        })
    }
}

impl Lift<oneiron::memory::KeyValuePutReceipt> for crate::KeyValuePutReceipt {
    fn lift(receipt: oneiron::memory::KeyValuePutReceipt) -> Result<Self, OneironError> {
        let oneiron::memory::KeyValuePutReceipt {
            item,
            replayed,
            receipt_ref,
        } = receipt;
        Ok(Self {
            item: crate::KeyValueItem::lift(item)?,
            replayed,
            receipt_ref,
        })
    }
}
