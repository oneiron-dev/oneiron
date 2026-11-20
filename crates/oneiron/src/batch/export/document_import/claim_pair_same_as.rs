//! A restored `same_as` between two CLAIMs (fix list row
//! WHOLE-VAULT-RESTORE-CLAIM-AND-NOTE-SAME-AS; Engine ANSWER
//! CLAIM-NOTE-SAME-AS-RESTORE-PROOF = A, 20 Nov 10:11).
//!
//! The Dreamer applies such a link only under the owner's standing
//! nightly-link grant (`federation::put_consolidated_same_as_in_txn`), so a
//! restore brings one back only on that same proof, read on this vault. The
//! owner's restore installs its archived standing grants before any row or
//! link (`archive_retained_side_rows::land_standing_grants_first_in_txn`),
//! then reads once whether a live grant of a live owner of this vault lets
//! the Dreamer apply its nightly links here ([`index_nightly_link_grant`]).
//! The link then lands when both CLAIMs and an active status claim on it
//! come back ([`claim_pair_proof`]), and the grant's use is recorded with a
//! Gate receipt whose effect digest names the restore
//! ([`ClaimPairProof::record_use_in_txn`]). Every other door installs no
//! grant and records none, so it keeps the link out.

use oneiron_contracts::fingerprint::ContentHasher;

use super::super::archive_index::{ArchiveIndex, Tag, edge_key, id_at};
use crate::Vault;
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::ClaimReadStatus;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::write_envelope::WriteActor;
use crate::write_envelope::claim_body::{ClaimBody, ClaimSubject};

/// The domain of a restored consolidated link's grant-use effect digest.
const RESTORED_CONSOLIDATED_SAME_AS_DOMAIN: &[u8] = b"oneiron:restored-consolidated-same-as:v1";

/// Records in `index`, on the owner's restore, the ref of the live standing
/// grant that lets the Dreamer apply its nightly `same_as` links on this
/// vault, read in `txn` once the restore's archived grants are in
/// (`dreamer_consolidation::resources::require_nightly_link_write`), with
/// the restore's receipt ref `restore_receipt_ref`. Records nothing when no
/// such grant is live. The Dreamer's id is the same in every vault, so a
/// grant the source's owner minted names this vault's Dreamer.
pub(super) fn index_nightly_link_grant(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    index: &mut ArchiveIndex<'_>,
    restore_receipt_ref: &str,
) -> Result<()> {
    let dreamer = WriteActor::new(
        crate::store::base_agent::dreamer_actor_id()?,
        EdgeActorClass::System,
    );
    let Some(grant_ref) =
        crate::dreamer_consolidation::resources::require_nightly_link_write(vault, txn, dreamer)?
    else {
        return Ok(());
    };
    let mut value = grant_ref.into_bytes();
    value.push(0);
    value.extend_from_slice(restore_receipt_ref.as_bytes());
    index.put(Tag::NightlyLinkGrant, &[], &value)
}

/// What a restored `same_as` between two CLAIMs lands on: the owner's grant,
/// the restore that read it, and the link's status claim.
pub(super) struct ClaimPairProof {
    grant_ref: String,
    restore_receipt_ref: String,
    status_claim: EntityId,
}

/// The proof the archived link `source` -> `target` between two CLAIMs lands
/// on, read in `txn`, as the Dreamer's writer reads it: the grant
/// [`index_nightly_link_grant`] recorded; two distinct ends, each a live,
/// unarchived CLAIM this import put in; and an active
/// `core.coreference.status` claim on exactly this link that the archive
/// carries and this import puts in (it comes back proposed, as every
/// imported claim does). `None` when any part fails.
pub(super) fn claim_pair_proof(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    inserted: &ArchiveIndex<'_>,
    source: EntityId,
    target: EntityId,
) -> Result<Option<ClaimPairProof>> {
    let Some(grant) = inserted.get(Tag::NightlyLinkGrant, &[])? else {
        return Ok(None);
    };
    if source == target {
        return Ok(None);
    }
    for id in [source, target] {
        let claim = matches!(
            live_entity_row_in_txn(&vault.store, txn, &id)?,
            LiveEntityRow::Live {
                entity_type: crate::registry::ENTITY_TYPE_CLAIM,
                ..
            }
        );
        if !claim
            || !inserted.contains(Tag::Inserted, id.as_bytes())?
            || vault.archive_tombstone_in_txn(txn, &id)?.is_some()
        {
            return Ok(None);
        }
    }
    let Some(status_claim) = active_status_claim(inserted, &source, &target)? else {
        return Ok(None);
    };
    let split = grant
        .iter()
        .position(|&byte| byte == 0)
        .ok_or(Error::InvariantViolation("nightly link grant index value"))?;
    let text = |bytes: &[u8]| {
        String::from_utf8(bytes.to_vec())
            .map_err(|_| Error::InvariantViolation("nightly link grant index value"))
    };
    Ok(Some(ClaimPairProof {
        grant_ref: text(&grant[..split])?,
        restore_receipt_ref: text(&grant[split + 1..])?,
        status_claim,
    }))
}

/// The mode the live Owners read archived claim `claim`'s EdgeRef subject at
/// when this import puts it, read in `txn`: [`ClaimReadStatus::Recorded`] on
/// the owner's restore for a claim about a `same_as` link between two CLAIMs
/// that [`claim_pair_proof`] proves (its `core.coreference.status` claim, or
/// any other claim the source holds about it), since the link's two restored
/// CLAIMs come back proposed, as every imported claim does, and the
/// Surfaceable mode admits no proposed claim (FIX
/// OWNER-RESTORE-OF-GRANTED-CLAIM-PAIR-LINK-ABORTS, REVIEW-9744 P1: the put
/// refused the restored link as `EntityNotFound` and the whole restore
/// aborted); [`ClaimReadStatus::Surfaceable`] for every other claim and door.
/// The put still reads the exact live link and both its ends.
pub(super) fn claim_edge_subject_read_status(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    inserted: &ArchiveIndex<'_>,
    owner_restore: bool,
    claim: &ClaimBody,
) -> Result<ClaimReadStatus> {
    if owner_restore
        && let ClaimSubject::Edge {
            source,
            kind: EdgeKind::SameAs,
            target,
        } = claim.subject
        && claim_pair_proof(vault, txn, inserted, source, target)?.is_some()
    {
        return Ok(ClaimReadStatus::Recorded);
    }
    Ok(ClaimReadStatus::Surfaceable)
}

/// The first active `core.coreference.status` claim the archive carries on
/// the `same_as` link `source` -> `target` and this import puts in (one it
/// has put in, or one still pending that it has not kept out).
fn active_status_claim(
    archive: &ArchiveIndex<'_>,
    source: &EntityId,
    target: &EntityId,
) -> Result<Option<EntityId>> {
    let link = edge_key(source, EdgeKind::SameAs as u8, target);
    let mut after: Option<Vec<u8>> = None;
    while let Some((key, active)) = archive.next(Tag::CoreferenceStatus, &link, after.as_deref())? {
        let id = id_at(&key, link.len())?;
        if active == [1u8] && archive.contains(Tag::Inserted, id.as_bytes())? {
            return Ok(Some(id));
        }
        after = Some(key);
    }
    Ok(None)
}

impl ClaimPairProof {
    /// Records the grant's use for the link `source` -> `target` it landed,
    /// in the restore's `wtxn`: a Gate receipt naming the grant, whose
    /// effect digest binds both ends, the status claim and the restore's
    /// receipt ref.
    pub(super) fn record_use_in_txn(
        &self,
        vault: &Vault,
        wtxn: &mut heed::RwTxn<'_>,
        source: EntityId,
        target: EntityId,
    ) -> Result<()> {
        let mut digest = ContentHasher::new();
        digest
            .update(RESTORED_CONSOLIDATED_SAME_AS_DOMAIN)
            .update(source.as_bytes())
            .update(target.as_bytes())
            .update(self.status_claim.as_bytes())
            .update(self.restore_receipt_ref.as_bytes());
        vault.record_standing_grant_use_in_txn(
            wtxn,
            &self.grant_ref,
            crate::consent::EffectDigest::from_bytes(digest.finish().into_bytes()),
        )?;
        Ok(())
    }
}
