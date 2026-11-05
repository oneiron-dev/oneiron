//! Seals fresh MESSAGE parts only when their room is explicitly saved.

use rmpv::Value;
use zeroize::{Zeroize, Zeroizing};

use super::wipe::{PlanOps, PlanTree, wipe_value};
use crate::Vault;
use crate::batch::BatchOp;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_MESSAGE;
use crate::store::witness_message_body::{
    StoredMessagePart, validate_canonical_witness_message_body,
};

pub(crate) fn seal_promoted_message_ops_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    ops: Vec<BatchOp>,
) -> Result<Vec<BatchOp>> {
    let mut ops = PlanOps::from_owned(ops);
    for op in ops.iter_mut() {
        let BatchOp::Put {
            id,
            entity_type: ENTITY_TYPE_MESSAGE,
            data,
            ..
        } = op
        else {
            continue;
        };
        // Existing ids retain the original bytes for the ordinary replay's
        // equality check. A retry must never mint a different custody handle.
        if vault.store.port_entity_present(txn, id)? {
            continue;
        }
        validate_canonical_witness_message_body(data)?;
        let malformed =
            || Error::InvalidClaimBody("a promoted MESSAGE is not a canonical envelope");
        let mut tree =
            PlanTree(rmpv::decode::read_value(&mut data.as_slice()).map_err(|_| malformed())?);
        let Value::Map(fields) = &mut tree.0 else {
            return Err(malformed());
        };
        let Some((_, value)) = fields
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("parts"))
        else {
            continue;
        };
        let mut encoded = Zeroizing::new(Vec::new());
        rmpv::encode::write_value(&mut *encoded, value).map_err(|_| malformed())?;
        let mut parts: Vec<StoredMessagePart> =
            rmp_serde::from_slice(&encoded).map_err(|_| malformed())?;
        let before = custody_count(&parts);
        super::super::seal_message_parts_in_txn(vault, txn, *id, 0, &mut parts)?;
        if custody_count(&parts) == before {
            continue;
        }
        let sealed = Zeroizing::new(rmp_serde::to_vec_named(&parts).map_err(|_| malformed())?);
        let replacement =
            rmpv::decode::read_value(&mut sealed.as_slice()).map_err(|_| malformed())?;
        wipe_value(value);
        *value = replacement;
        let mut body = Vec::new();
        rmpv::encode::write_value(&mut body, &tree.0).map_err(|_| malformed())?;
        data.zeroize();
        *data = body;
    }
    Ok(ops.into_ops())
}

fn custody_count(parts: &[StoredMessagePart]) -> usize {
    parts
        .iter()
        .filter(|part| matches!(part, StoredMessagePart::Custody { .. }))
        .count()
}
