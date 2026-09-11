//! SKILL body validators shared by the put and update arms.

use heed::RwTxn;

use super::EntityMetadataHeader;
use crate::entity_id::EntityId;
use crate::error::ArtifactError;
use crate::error::{Error, ErrorKind, Result};
use crate::registry::ENTITY_TYPE_SKILL;
use crate::store::Store;

/// Every gate a SKILL body OVERWRITE passes at this chokepoint.
///
/// Extracted from [`apply_put`] rather than inlined: this arm answers one
/// question ("may this body replace that one?") and three doors ask it.
///
/// A legacy-opaque prior body is the one exemption, as it has always been —
/// there is no decoded predecessor to judge an update against, so the upgrade
/// is admitted and the record's shape is validated on its own terms.
///
/// # Errors
///
/// [`ArtifactError::InvalidSkillBody`](crate::error::ArtifactError::InvalidSkillBody) from the substrate update gate, the hub-sync
/// door's variant of it, or ONE-1449's admission gate.
pub(super) fn validate_skill_body_overwrite(
    store: &Store,
    wtxn: &RwTxn<'_>,
    id: &EntityId,
    prior_body: &[u8],
    updated: &crate::skill::SkillRecord,
    hub_sync_imported: bool,
    replicated: bool,
) -> Result<()> {
    match crate::skill::decode_skill_record(prior_body) {
        Ok(prior) if hub_sync_imported => {
            crate::skill::validate_hub_sync_skill_update(&prior, updated)
        }
        Ok(prior) => {
            crate::skill::validate_skill_update(&prior, updated)?;
            // ONE-1449's admission gate, placed HERE for the reason ONE-1892's
            // scan consult is: this is the arm every SKILL body update
            // converges on, so `put_entity`, a raw `batch().put`, the typed
            // update door and sync replay are bound by one rule rather than
            // four. The substrate update gate above already judges a
            // replicated row against its predecessor; exempting THIS gate
            // alone (ONE-1449 K3 M-6) let a peer's row edit optimizer origin
            // provenance and flip an optimizer-born candidate to `active` with
            // no verdict anywhere — a fail-open the local doors are closed to.
            // Which half of the rule a road can be held to is the gate's own
            // question to answer, so the road travels with the call rather
            // than deciding here whether to make it.
            crate::skill_optimize::check_optimizer_admission_in_txn(
                store, wtxn, id, &prior, updated, replicated,
            )
        }
        Err(error)
            if error.kind() == ErrorKind::InvalidSkillBody
                && crate::skill::is_legacy_opaque_skill_body(prior_body) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// The ONE-1735 birth law for a LOCAL SKILL create.
///
/// Extracted from [`apply_put`] for the reason [`validate_skill_body_overwrite`]
/// is: this answers one question ("may this id be BORN with this body?"), and
/// the create arm now asks two — the origin marker, which every road carries,
/// and this, which only a local create is held to. Legacy-opaque upgrades take
/// the update arm instead (a prior record exists), so this sees genuine creates
/// only. New skills are born candidate, and fork lineage must name a real
/// type-7 SKILL parent (the `DerivedFrom` edge is door-authored and cannot
/// precede this create in the txn, so it is not required here).
///
/// # Errors
///
/// [`ArtifactError::InvalidSkillBody`](crate::error::ArtifactError::InvalidSkillBody) for a create that is not born candidate or whose
/// `forkedFrom` names itself, a missing row, or a row of another kind.
pub(super) fn validate_local_skill_create(
    store: &Store,
    wtxn: &RwTxn<'_>,
    id: &EntityId,
    created: &crate::skill::SkillRecord,
) -> Result<()> {
    if created.lifecycle_status != crate::skill::SkillLifecycle::Candidate {
        return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
            "new skills are born candidate; the admission gate activates them",
        )));
    }
    let Some(parent) = created.forked_from else {
        return Ok(());
    };
    if parent == *id {
        return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
            "forkedFrom cannot name the fork itself",
        )));
    }
    let parent_raw = store
        .entities
        .get(wtxn, parent.as_bytes())?
        .ok_or(Error::Artifact(ArtifactError::InvalidSkillBody(
            "forkedFrom parent must exist as a type-7 SKILL",
        )))?;
    let parent_header =
        EntityMetadataHeader::parse(&parent_raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if parent_header.entity_type != ENTITY_TYPE_SKILL {
        return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
            "forkedFrom parent must exist as a type-7 SKILL",
        )));
    }
    Ok(())
}
