//! An erased actor out of the share admissions (FIX 3520).

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::{ADMISSIONS, ShareAdmission};

/// What an actor's erase does with the admission of a share that actor
/// issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareAdmissionErase {
    /// The admission stays as history naming no issuer, and grants nothing.
    Inert,
    /// The admission goes, and the share's receipts with it.
    Delete,
}

/// An erased issuer's share grants nothing more, but its admission is the
/// share's receipt, so the erase keeps it as inert history: its Gate
/// decision, its digest and its times, with no issuer (FIX 3520).
pub const ACTOR_ERASE_SHARE_ADMISSION: ShareAdmissionErase = ShareAdmissionErase::Inert;

/// Whether `id`'s entity is no actor, so its erase has no one to take out of
/// the admissions.
fn names_no_actor(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    if let Some(raw) = vault.get_raw_in(txn, id)?
        && let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw)
    {
        return Ok(!matches!(
            header.entity_type,
            crate::registry::ENTITY_TYPE_PERSON
                | crate::registry::ENTITY_TYPE_MACHINE
                | crate::registry::ENTITY_TYPE_AGENT_DEF
        ));
    }
    Ok(false)
}

/// Erasing `actor` from the share admissions (FIX 3520): a share it issued
/// grants nothing more, and its admission keeps its Gate decision, its
/// digest and its times with no issuer, when [`ACTOR_ERASE_SHARE_ADMISSION`]
/// says so; grant resolution refuses it and the share receipts still read
/// it. A share it revoked stays revoked, at its time, naming no revoker.
/// One-way, in the erase's own transaction. An id whose entity is no actor
/// scans nothing.
///
/// # Errors
///
/// Storage errors, or an admission row that cannot be read.
pub(crate) fn erase_admission_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let store = &vault.store;
    let mut doomed = Vec::new();
    let mut erased = Vec::new();
    for (id, raw) in ADMISSIONS.scan(store, wtxn)? {
        let mut admission =
            ShareAdmission::decode(&raw).ok_or(Error::CorruptedIndex("share admission"))?;
        let issued = admission
            .issuer
            .is_some_and(|issuer| issuer.entity_ref() == *actor);
        let revoked = admission
            .revoker
            .is_some_and(|revoker| revoker.entity_ref() == *actor);
        if issued && ACTOR_ERASE_SHARE_ADMISSION == ShareAdmissionErase::Delete {
            doomed.push(id);
            continue;
        }
        if issued {
            admission.issuer = None;
        }
        if revoked {
            admission.revoker = None;
        }
        if issued || revoked {
            erased.push((id, admission.encode()));
        }
    }
    for id in &doomed {
        ADMISSIONS.delete(store, wtxn, id)?;
    }
    for (id, bytes) in &erased {
        ADMISSIONS.put(store, wtxn, id, bytes)?;
    }
    Ok(())
}
