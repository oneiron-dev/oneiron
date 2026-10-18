//! The uploads the home stages, as its disk sees them (FIX 3354). The home
//! holds a claim on its disk's free-space floor for each machine's stage
//! across its parts, through the commit or replace that writes its stored
//! copy, and reconciles those claims with the stage headers here: at startup,
//! and once a stage is committed, replaced or idles out.

use super::bundle::{STAGE_IDLE_SECS, STAGES, SealedBundleObject, decode_stage};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// One upload the home stages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealedBundleStaged {
    /// The machine that stages it.
    pub machine: EntityId,
    pub object: SealedBundleObject,
    /// The whole object's length.
    pub total: u64,
    /// The bytes staged so far.
    pub staged: u64,
}

/// Every upload the home stages now and that has not idled out. A header
/// that does not decode is left out: the next stage drops it.
///
/// # Errors
///
/// Storage errors.
pub fn sealed_bundle_stages(vault: &Vault) -> Result<Vec<SealedBundleStaged>> {
    let txn = vault.store.env.read_txn()?;
    let now = vault.instant_in_txn(&txn)?.secs();
    let mut out = Vec::new();
    for row in STAGES.iter_raw_from(&vault.store, &txn, &[])? {
        let (key, raw) = row?;
        let Some((machine, object)) = std::str::from_utf8(&key)
            .ok()
            .and_then(|key| key.split_once(':'))
            .and_then(|(machine, letter)| {
                let object = match letter {
                    "b" => SealedBundleObject::Bundle,
                    "k" => SealedBundleObject::Pads,
                    _ => return None,
                };
                Some((EntityId::from_hex(machine).ok()?, object))
            })
        else {
            continue;
        };
        let Ok((at, stage, staged)) = decode_stage(&raw, object) else {
            continue;
        };
        if at.saturating_add(STAGE_IDLE_SECS) >= now {
            out.push(SealedBundleStaged {
                machine,
                object,
                total: stage.total,
                staged,
            });
        }
    }
    Ok(out)
}
