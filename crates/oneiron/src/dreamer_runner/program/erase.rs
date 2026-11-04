//! The erase of a turn program's waking actor takes the signed instrument a
//! slip's turn sealed out of every admission it kept (FIX 10668). Each
//! admission stays, admitted, refused or settled alike: its dedupe identity,
//! wake refs, Gate receipt, attempt, outcome and times, and its slip's id,
//! parent, Grant and scope digest as witnesses. Only the instrument goes, so
//! the authority it sealed stands no more.

use crate::error::Result;
use crate::{EntityId, Vault};

use super::ADMISSION;

/// Rewrites each decodable admission whose waking actor is `actor` without
/// its slip's instrument, in the erase's own writer. The actor's admissions
/// are read by their actor index (FIX 5735). ADMISSION is keyed by a hash
/// that names no actor, so a row that does not decode is not this actor's
/// by proof and stays as it is.
pub(super) fn scrub_actor_admission_instruments_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if crate::deletion::names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut scrubbed = Vec::new();
    for key in super::index::actor_admissions_in_txn(vault, wtxn, actor)? {
        let Some(mut record) = ADMISSION.get_lenient(vault, wtxn, &key)? else {
            continue;
        };
        if record.wake.authority.scrub_instrument_of(actor) {
            scrubbed.push((key, record));
        }
    }
    for (key, record) in scrubbed {
        ADMISSION.put(vault, wtxn, &key, &record)?;
    }
    Ok(())
}
