//! Marks restored capsule references only when their body custody retired.

use std::collections::{BTreeMap, BTreeSet};

use super::{CAPSULES, CapsuleRequest, FORKS, ForkValue};
use crate::Result;

type Rows = Vec<(Vec<u8>, Vec<u8>)>;

pub(crate) fn retire_replay_bodies_in_rows(
    databases: &mut BTreeMap<String, Rows>,
    digests: &BTreeSet<[u8; 32]>,
) -> Result<()> {
    if digests.is_empty() {
        return Ok(());
    }
    let Some(rows) = databases.get_mut("vault_meta") else {
        return Ok(());
    };
    for (key, value) in rows {
        if key.starts_with(CAPSULES.decl().prefix) {
            let Ok(mut capsule) = CAPSULES.decode_value(value) else {
                continue;
            };
            let mut changed = false;
            if let CapsuleRequest::Kept { body, erased, .. } = &mut capsule.request
                && !*erased
                && digests.contains(&body.hash)
            {
                *erased = true;
                changed = true;
            }
            if let Some(start) = &mut capsule.start
                && !start.erased
                && digests.contains(&start.body.hash)
            {
                start.erased = true;
                changed = true;
            }
            if changed {
                *value = CAPSULES.encode_value(&capsule)?;
            }
        } else if key.starts_with(FORKS.decl().prefix) {
            let Ok(mut row) = FORKS.decode_value(value) else {
                continue;
            };
            let ForkValue::Fork(receipt) = &mut row.value else {
                continue;
            };
            if !receipt.response_erased && digests.contains(&receipt.response.hash) {
                receipt.response_erased = true;
                *value = FORKS.encode_value(&row)?;
            }
        }
    }
    Ok(())
}
