//! Live admission of a PROJECT write: direct, batch and typed doors. Replay
//! never reaches this check; the read fold judges replicated rows instead.
use super::read::{ProjectReader, ProjectVerdict, bound_by_parents, stored};
use super::*;
use crate::authority::{CapabilitySlip, authority_fold_readonly_for_store_in_txn};
use crate::store::Store;

fn refused(reason: &'static str) -> Error {
    RecordError::InvalidProjectBody(reason).into()
}

pub(crate) fn validate_transition(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
    bytes: &[u8],
    posture: crate::HostingPrivacyPosture,
) -> Result<()> {
    let next: ProjectRecord = decode(bytes).map_err(|_| refused("invalid project body"))?;
    let prior = stored(store, txn, id, kind)?;
    if let Some(old) = &prior {
        // Membership, goal and ask edits keep the authority and its proof.
        if old.authority() == next.authority() && old.write_proof == next.write_proof {
            return Ok(());
        }
        if next.write_proof.is_none() {
            return Err(refused("project authority change needs a signed proof"));
        }
    }
    let reader = ProjectReader::new(store, txn, posture)?.ok_or_else(invalid)?;
    if let Some(proof) = &next.write_proof
        && prior
            .as_ref()
            .is_none_or(|old| old.write_proof.as_ref() != Some(proof))
    {
        verify_live(store, txn, id, &next, proof, posture)?;
        match &prior {
            // A visible row is the current authority; a hidden one (say, a
            // forged replay) may be repaired over the last authorized state.
            Some(old)
                if proof.anchor.as_deref() != Some(&old.anchor())
                    && reader.judge(id, old)? == ProjectVerdict::Visible =>
            {
                return Err(refused("project write must build on its current authority"));
            }
            None if proof.anchor.is_some() => {
                return Err(refused("a new project has no earlier authority"));
            }
            _ => {}
        }
        if prior.is_some() {
            refuse_stranded_children(store, txn, id, kind, &next.authority())?;
        }
    }
    match reader.judge(id, &next)? {
        ProjectVerdict::Visible => Ok(()),
        ProjectVerdict::Pending(reason) | ProjectVerdict::Quarantined(reason) => {
            Err(refused(reason))
        }
    }
}

/// A new signature is a live act: its slip must be live at this door's
/// clock as well as at its signed time, and it may not be dated ahead.
fn verify_live(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    next: &ProjectRecord,
    proof: &ProjectWriteProof,
    posture: crate::HostingPrivacyPosture,
) -> Result<()> {
    let slip = CapabilitySlip::from_token(&proof.slip_wire)
        .map_err(|_| refused("invalid project write slip"))?;
    let fold = authority_fold_readonly_for_store_in_txn(store, posture, txn)?;
    let mint = fold
        .slips
        .mints
        .get(&slip.claims.slip_id)
        .ok_or_else(|| refused("project write slip not minted"))?;
    let floor = crate::authority::AUTHORITY_FIRST_SEEN
        .get_lenient(
            store,
            txn,
            &crate::authority::authority_first_seen_clock_key(),
        )?
        .unwrap_or(0);
    let now =
        crate::authority::authority_observation_secs(store, floor, store.clock.now_recorded_at());
    if proof.signed_at > now {
        return Err(refused("project write proof is dated ahead"));
    }
    let challenge =
        next.authority()
            .write_challenge(id, proof.signed_at, proof.anchor.as_deref())?;
    slip.verify_with_host_key(
        &mint.signer,
        &fold,
        now,
        &challenge,
        &proof.holder_signature,
    )
    .map_err(|_| refused("invalid project write proof"))?;
    Ok(())
}

/// Narrowing a live parent may not leave a signed subproject wider than it.
fn refuse_stranded_children(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
    next: &ProjectAuthority,
) -> Result<()> {
    let parent = id.to_hex();
    for row in store.type_index.prefix_iter(txn, &[kind])? {
        let (key, _) = row?;
        let child = EntityId::from_bytes(
            key[1..]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("project type index"))?,
        )?;
        if let Some(body) = stored(store, txn, child, kind)?
            && bound_by_parents(&body)
            && body.parents.contains(&parent)
            && !body.authority().fits_under(next)
        {
            return Err(refused("narrowing would strand a wider subproject"));
        }
    }
    Ok(())
}
