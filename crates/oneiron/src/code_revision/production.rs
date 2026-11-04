//! The host-production witness a code revision carries, outside its immutable artifact
//! fold. The witness value is the ONE shared stamp
//! ([`OutputProductionStamp`]); this module owns only its code-revision
//! integration: the actor-erase scrubs the `CODE_REVISION_RECORD` and
//! `CODE_REVISION_PROPOSAL` declarations name, and the checkpoint actor-part
//! split/join the two checkpoint getters share. Record and proposal core
//! identity, folds and replay behavior are untouched: erasing a witness
//! rewrites only its row, and a held record keeps its witness while the hold
//! stands (public views project instead).

use heed::RwTxn;

use super::keys::RECORDS;
use super::proposals::PROPOSALS;
use crate::Vault;
use crate::blob_artifact::OutputProductionStamp;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::store::checkpoint_payload::rows::{self, ActorPart};

/// The checkpoint actor-part field that carries a split production witness.
pub(super) const PRODUCTION_PART: &str = "production";

/// Whether a standing hold names `revision_id`'s record. The check is
/// fail-safe: a storage error reads as held, so the pair is preserved, never
/// half-scrubbed.
fn record_hold_standing_in_txn(
    vault: &Vault,
    wtxn: &RwTxn<'_>,
    revision_id: &EntityId,
) -> Result<bool> {
    Ok(!crate::store::legal_hold::holds_on_in_txn(
        &vault.store,
        wtxn,
        &crate::deletion::LegalHoldTarget::Record(*revision_id),
    )?
    .is_empty())
}

/// Erases `actor` from every finalized revision's production witness, in the
/// purge's one transaction. A witness naming the actor (as producer or as
/// executor run) becomes `Erased` whole; every other field, fold and index
/// row stays byte-exact, so no descendant refolds. A held record keeps its
/// stored witness while the hold stands; public views project it instead.
pub(crate) fn erase_code_revision_record_production_actor_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if crate::deletion::names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut scrubbed = Vec::new();
    for (key, mut revision) in RECORDS.scan(&vault.store, wtxn)? {
        if revision.production.erase_actor(actor) {
            scrubbed.push((key, revision));
        }
    }
    scrubbed.retain(|(_, revision)| {
        !record_hold_standing_in_txn(vault, wtxn, &revision.revision_id).unwrap_or(true)
    });
    for (key, revision) in scrubbed {
        RECORDS.put(&vault.store, wtxn, &key, &revision)?;
    }
    Ok(())
}

/// Erases `actor` from every stranded proposal's production witness, in the
/// purge's one transaction. Same witness-only rewrite as the record scrub;
/// a held proposal keeps its stored witness while the hold stands.
pub(crate) fn erase_code_revision_proposal_production_actor_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if crate::deletion::names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut scrubbed = Vec::new();
    for (key, mut proposal) in PROPOSALS.scan(&vault.store, wtxn)? {
        if proposal.revision.production.erase_actor(actor) {
            scrubbed.push((key, proposal));
        }
    }
    scrubbed.retain(|(_, proposal)| {
        !record_hold_standing_in_txn(vault, wtxn, &proposal.revision.revision_id).unwrap_or(true)
    });
    for (key, proposal) in scrubbed {
        PROPOSALS.put(&vault.store, wtxn, &key, &proposal)?;
    }
    Ok(())
}

/// The actor part a checkpoint splits a Host witness into: the complete
/// stamp bytes under its producer. Unknown and Erased stay in the row.
pub(super) fn split_production_part(
    production: &OutputProductionStamp,
) -> Result<Option<(EntityId, Vec<u8>)>> {
    match production {
        OutputProductionStamp::Host(host) => {
            let bytes = super::codec::encode_value(
                &production.to_value(),
                "code revision production checkpoint encode failed",
            )?;
            Ok(Some((host.actor(), bytes)))
        }
        OutputProductionStamp::Unknown | OutputProductionStamp::Erased => Ok(None),
    }
}

/// Reads one split production witness back. Closed current format only.
fn read_production_value(bytes: &[u8]) -> Result<rmpv::Value> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| {
        Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "production checkpoint is not valid MessagePack",
        ))
    })?;
    if !cursor.is_empty() {
        return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "trailing bytes after production checkpoint map",
        )));
    }
    Ok(value)
}

/// Puts a split record's or proposal's production witness back. A missing
/// part restores the skeleton as it stands (Erased): only the witness is
/// ever withheld, never the revision or proposal. Any other field, a second
/// production part, or a part on a non-Erased skeleton refuses.
pub(super) fn rejoin_production_part(
    skeleton: OutputProductionStamp,
    parts: &[&ActorPart],
) -> Result<OutputProductionStamp> {
    let mut production = skeleton;
    let mut seen = false;
    for part in parts {
        match part.field.as_str() {
            PRODUCTION_PART if !seen && production == OutputProductionStamp::Erased => {
                let stamp =
                    OutputProductionStamp::from_value(&read_production_value(&part.bytes)?)?;
                if !matches!(&stamp, OutputProductionStamp::Host(host) if host.actor() == part.actor_entity)
                {
                    return Err(rows::bad_part());
                }
                production = stamp;
                seen = true;
            }
            _ => return Err(rows::bad_part()),
        }
    }
    Ok(production)
}
