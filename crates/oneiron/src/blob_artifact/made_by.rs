//! The made_by receipt every blob version carries (ARCH-0078 "The provenance
//! receipt", ARCH-0035 Rule A): what the version was made from, what made it,
//! and when. A writer that names no envelope gets its own: the writing actor
//! as the process, the parent version's ledger claim as the input, no trigger.

use heed::RoTxn;
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::batch::secret_scan;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess,
};
use crate::write_envelope::WriteActor;

use super::provenance::BlobVersionProvenance;

/// The writer's own envelope for a version that names none.
pub(super) fn default_version_made_by(
    actor: &WriteActor,
    provenance: &BlobVersionProvenance,
    parent_claim: Option<EntityId>,
    at: u64,
) -> MadeBy {
    MadeBy {
        inputs: parent_claim
            .into_iter()
            .map(|row| MadeByInput {
                row,
                role: MadeByInputRole::Input,
            })
            .collect(),
        process: MadeByProcess {
            actor: actor.entity_ref(),
            class: match provenance {
                BlobVersionProvenance::AgentRun { .. } => MadeByClass::Concluded,
                _ if actor.actor_class() == EdgeActorClass::Human => MadeByClass::Stated,
                _ => MadeByClass::Concluded,
            },
            identity: provenance.as_str().to_owned(),
            version: "1".into(),
            params_hash: format!("{:x}", Sha256::digest([])),
        },
        at,
        trigger: None,
    }
}

/// Checks a named envelope before it lands on a version: a valid process,
/// any number of inputs (Rule 5), no secret in its text, and a trigger that names a live
/// task, ask, run or skill in this vault (the row-birth rule).
pub(super) fn validate_version_made_by_in_txn(
    vault: &Vault,
    rtxn: &RoTxn<'_>,
    made_by: &MadeBy,
) -> Result<()> {
    if !made_by.process.is_valid() {
        return Err(invalid(
            "made_by needs a process identity, version and params hash of 1-256 bytes",
        ));
    }
    for text in [
        &made_by.process.identity,
        &made_by.process.version,
        &made_by.process.params_hash,
    ] {
        secret_scan::scan_metadata_field(text)?;
    }
    if let Some(trigger) = &made_by.trigger
        && !crate::provenance::birth::trigger_is_live_in_txn(&vault.store, rtxn, trigger)?
    {
        return Err(invalid(
            "made_by trigger must name a live task, ask, run or skill",
        ));
    }
    Ok(())
}

/// Whether an envelope may also stand as the artifact row's birth: a
/// concluded birth names what it was made from, and a triggered birth names
/// its prompt (the row-birth shape rule).
pub(super) fn births_row(made_by: &MadeBy) -> bool {
    (made_by.process.class == MadeByClass::Stated || !made_by.inputs.is_empty())
        && (made_by.trigger.is_none()
            || made_by
                .inputs
                .iter()
                .any(|input| input.role == MadeByInputRole::Prompt))
}

/// The envelope's stored spelling: the same JSON text commits carry.
pub(super) fn made_by_text(made_by: &MadeBy) -> Result<String> {
    serde_json::to_string(made_by).map_err(|_| invalid("made_by does not encode"))
}

pub(super) fn made_by_from_text(text: &str) -> Result<MadeBy> {
    serde_json::from_str(text).map_err(|_| invalid("made_by is not a valid envelope"))
}

fn invalid(message: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidBlobArtifactBody(message))
}
