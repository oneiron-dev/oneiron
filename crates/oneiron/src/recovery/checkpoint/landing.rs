//! Landing one checkpoint image in its destination: the restore pipeline
//! behind every restore, wake and migrate (moved out of the checkpoint
//! module whole).

use std::collections::BTreeSet;
use std::path::Path;

use heed::types::Bytes;

#[cfg(test)]
use super::test_hooks::{RestoreStep, fail_at};
use super::{
    CheckpointImage, Custody, ForkedCustody, RESTORE_EPOCH, RecoveryWriteBudget, Rejected,
    RestoreEpoch, RestoreReason, RestoreReport, artifact, carried_bodies, codec_error, rebuild,
    response_rows, write_budget,
};
use crate::store::{DB_MANIFEST, MadeDestination};
use crate::{EntityId, Result, Vault, VaultConfig};

impl Vault {
    /// Restores `image` into `destination`. The made directory, the forked
    /// custody and the copy come back in that order, so a caller's bindings,
    /// dropped in reverse, close the copy before the others go. The copy's
    /// writes claim their room on `budget` (`write_budget`, FIX 5479). A
    /// refusal carries the reason its branch names beside the error today's
    /// paths take back with `?` (FIX 6474): the claim preflight's, a missing
    /// key's, a body landing's frame check and the final receipt scan's; any
    /// other is typed by its kind.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn restore_image(
        mut image: CheckpointImage,
        checkpoint_id: String,
        bodies: artifact::SealedBodies<'_>,
        destination: &Path,
        config: VaultConfig,
        reason: RestoreReason,
        restored_at: u64,
        custody: Custody<'_>,
        erased: &BTreeSet<EntityId>,
        budget: &dyn RecoveryWriteBudget,
    ) -> std::result::Result<(MadeDestination, ForkedCustody, Self, RestoreReport), Rejected> {
        validate_image_rows_before_destination(&image)?;
        // Authenticate every ORCB row against LIVE exterior custody before
        // creating a destination. A checkpoint never carries a key copy, and
        // a row whose key an erase destroyed since is dropped, not restored.
        let (fork, source, home) = match custody {
            Custody::Keep | Custody::Landed | Custody::NewHost => (false, None, None),
            Custody::Replace(home, _) => (false, None, Some(home)),
            Custody::Fork(source) => (true, source.map(|(live, _)| live), None),
        };
        let candidacy = match custody {
            Custody::Replace(_, candidacy) => candidacy,
            Custody::Keep | Custody::Landed | Custody::NewHost | Custody::Fork(_) => None,
        };
        let new_host = matches!(custody, Custody::NewHost);
        let mut gate_custody = if new_host {
            crate::store::preflight_absent_custody_rows(&image.databases["vault_meta"])?
        } else {
            crate::store::preflight_checkpoint_rows_rejected(
                &image.databases["vault_meta"],
                source,
            )?
        };
        // Every body instance the rows name, through the plan the claim keys
        // share, so one fork copies both: missing refuses by name, retired
        // takes its rows out (KS-2A).
        let retired = carried_bodies::require(&mut image, gate_custody.plan_mut())?;
        // The known-value history the rows commit to, through the same plan
        // (KS-3): every retained entry and the master, or the restore is
        // refused by name, so it never claims to mask what the vault masked
        // without them; an erased holder's references go. The no-head drop
        // of claim rows never reaches it.
        crate::store::require_known_history(
            image
                .databases
                .get_mut("vault_meta")
                .ok_or_else(codec_error)?,
            gate_custody.plan_mut(),
        )?;
        // Every world key pad a row names, through the same plan (KS-5, FIX
        // 5686 part 2): one its custody retired since takes its row out, a
        // live one forks with the rest, and a bare reference rests again
        // once the rows land.
        let pads = super::pad_custody::require(&mut image, gate_custody.plan_mut(), custody)?;
        // Every credential value a row commits to, by exact id through the
        // same plan (KS-6 part 2): a row rides sealed as it rests, and a
        // fork copies its value's key with the rest, no older generation
        // besides. A row carried in the clear lands withheld.
        let credentials =
            super::credential_custody::require(&mut image, gate_custody.plan_mut(), custody)?;
        let body_custody = gate_custody.plan_mut().source().cloned();
        // The responses that never decoded and land as they rested (FIX
        // 6227): a claim among them is never decoded, indexed or embedded.
        let (opaque_responses, opaque_claims) = carried_bodies::opaque_landing(&image, &retired)?;
        let checkpoint_sequence = image.checkpoint_sequence;
        if fork {
            crate::store::refuse_custody_beside(destination)?;
        }
        // The pin pass below reads every agent id pin the restore brings
        // back: one no pin decodes from is refused here, before a
        // destination exists (H215).
        crate::agent_def::refuse_unreadable_agent_id_pins(&image.databases["vault_meta"])?;
        // Existing content is never replaced or partially restored over. A
        // refusal from here on drops the copy, then the directory made for
        // it: only a committed restore keeps them (C8). The config is checked
        // first, as an owned open checks it before it touches the disk.
        Self::check_open_config(&config)?;
        // Each row is counted at the length it lands at (FIX 6025, 6232).
        let lengths = super::landing_lengths::LandingRowLengths::of(&image, &retired);
        let mut room = write_budget::RestoreRoom::new(budget, &image, &lengths, &config);
        room.admit()?;
        let mut made = MadeDestination::make(destination, home)?;
        // A sealed copy's open writes its page-seal mirror beside it, outside
        // the directory: a refusal removes that too.
        if config.page_seal.is_some() {
            made.owns_page_seal_mirror()?;
        }
        let mut forked = ForkedCustody(None);
        let vault = Self::open_under_lease(destination, config.clone(), made.lease()?)?;
        #[cfg(test)]
        fail_at(RestoreStep::FirstOpen)?;
        made.holds(&vault.store)?;
        // The bodies land, read back through their sealed chunks and each
        // checked against its digest, before any row naming them does: a
        // result body with its line index, an ASSET's file raw (FIX 3677),
        // a sealed vault's envelope checked frame by frame under its key row
        // (FIX 5348).
        carried_bodies::restore(
            &vault,
            &mut image,
            bodies,
            &mut room,
            (body_custody.as_ref(), &retired),
        )
        .map_err(Rejected::landing)?;
        // A queue row landed from its carried bytes goes unleased, as the
        // snapshot unleased every other (FIX 7115).
        response_rows::unlease_carried_attempts(&mut image, &retired).map_err(Rejected::landing)?;
        room.landing_rows(&image)?;
        vault.with_write_txn_grouped(|txn| {
            for entry in DB_MANIFEST {
                let db = vault
                    .store
                    .env
                    .open_database::<Bytes, Bytes>(txn, Some(entry.name))?
                    .ok_or(codec_error())?;
                db.clear(txn)?;
                for (key, value) in &image.databases[entry.name] {
                    db.put(txn, key, value)?;
                }
            }
            // The rows came back without a put: every entity kind is judged
            // against the image's own registry, now readable in this
            // transaction. A refusal discards the copy before it commits.
            vault
                .store
                .validate_checkpoint_entity_kinds_in_txn(&*txn, &image.databases["entities"])?;
            if fork {
                forked.0 = vault.store.fork_gate_custody_in_txn(txn, &gate_custody)?;
            }
            if let Some(home) = home {
                vault.store.mark_live_only_at_in_txn(txn, home)?;
            }
            vault
                .store
                .drop_erased_gate_decisions_in_txn(txn, &gate_custody.dropped())?;
            if new_host {
                crate::store::unbind_custody_in_txn(&vault.store, txn)?;
            }
            // A written-here mark carried from the live vault binds only a
            // carrier the restored rows hold, byte for byte.
            crate::identity_topology::drop_unheld_author_marks_in_txn(&vault.store, txn)?;
            // Open-time seed/backfill gates consult type indexes. Reconstruct this
            // mechanical projection before reopening; tokenizer/model work waits
            // until those compatibility gates have passed.
            for (key, raw) in &image.databases["entities"] {
                let id = crate::EntityId::from_bytes(
                    key.as_slice().try_into().map_err(|_| codec_error())?,
                )?;
                let h = crate::batch::EntityMetadataHeader::parse(raw).ok_or_else(codec_error)?;
                crate::batch::stage_entity_index_rows(
                    &vault.store,
                    txn,
                    &id,
                    h.entity_type,
                    crate::temporal::TimeRange {
                        start: h.occurred_start,
                        end: h.occurred_end,
                    },
                    h.learned_at,
                )?;
            }
            // Rows came back without a put: each definition pins its id as a
            // put of it would have (H215).
            crate::agent_def::pin_stored_rows_in_txn(&vault.store, txn)?;
            // An erased actor's name, carried back by the image's rows, goes
            // again, now the type index is back.
            crate::deletion::rerun_actor_scrubs_in_txn(&vault, txn, erased)?;
            // A step claim's response pins go with what the rows no longer
            // hold, now the type index is back: an erased shell's release,
            // an omitted claim's or version's pin goes alone (FIX 6225).
            crate::llm::prune_step_response_pins_in_txn(
                &vault.store,
                txn,
                &BTreeSet::new(),
                &BTreeSet::new(),
            )?;
            #[cfg(test)]
            fail_at(RestoreStep::ImageWrite)?;
            Ok(())
        })?;
        drop(vault);
        // Re-open through all ABI, model, analyzer and manifest gates before rebuilding.
        room.admit_derived(destination)?;
        let vault = Self::open_under_lease(destination, config, made.lease()?)?;
        #[cfg(test)]
        fail_at(RestoreStep::SecondOpen)?;
        made.holds(&vault.store)?;
        if let Some(home) = home {
            vault.store.unseal_replacement(home)?;
        }
        // The image carries only a binding to current exterior custody, never
        // the keys. Verify EVERY claim-bound receipt against those live keys,
        // or a side copy's forked ones, before reporting a successful restore,
        // wake, or migration.
        {
            let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
            vault
                .store
                .for_each_gate_decision_in_txn(&txn, |_| Ok(()))
                .map_err(Rejected::receipt)?;
            #[cfg(test)]
            fail_at(RestoreStep::ReceiptCheck)?;
        }
        // Each pad a row names by reference rests again with the pad its
        // custody holds, or is withheld by its world's setting; any other is
        // refused before the vault is kept (KS-5).
        let pad_notes = super::pad_custody::land(&vault, pads)?;
        // Each credential value reads back from the custody this vault now
        // holds; each it did not land readable is named (KS-6 part 2).
        let credential_notes = super::credential_custody::land(&vault, credentials);
        room.admit_derived(destination)?;
        let (rebuilt_entities, rebuilt_text_documents, pending_embeddings) =
            rebuild::rebuild(&vault, &opaque_claims)?;
        room.admit_derived(destination)?;
        rebuild::rebuild_auxiliary(&vault, image.created_at)?;
        room.admit_derived(destination)?;
        // No caller sees the vault before its home is elected again.
        rebuild::reelect_home(&vault, candidacy, restored_at);
        let epoch = RestoreEpoch {
            checkpoint_id,
            restored_at,
            reason,
        };
        vault.with_write_txn_grouped(|txn| {
            let sequence = match RESTORE_EPOCH.iter_rev_from(&vault.store, txn, &[])?.next() {
                None => 0,
                Some(row) => {
                    let (sequence, _) = row?;
                    sequence.checked_add(1).ok_or(codec_error())?
                }
            };
            RESTORE_EPOCH.put(&vault.store, txn, &sequence, &epoch)?;
            Ok(())
        })?;
        let report = RestoreReport {
            epoch,
            rebuilt_entities,
            rebuilt_text_documents,
            pending_embeddings,
            dropped_gate_decisions: gate_custody
                .lost()
                .iter()
                .map(|(id, _)| id.to_hex())
                .collect(),
            custody_note: None,
            training_note: vault.training_link_restore_notice(),
            home_table_notes: Vec::new(),
            pad_notes,
            checkpoint_sequence,
            opaque_responses,
            credential_notes,
        };
        Ok((made, forked, vault, report))
    }
}

/// Refuses a row with no header, which the index rebuild refuses anyway; a
/// body the local identity refusal turns away; or an AUTHORITY_LOG row whose
/// body the shared authority validator refuses, an empty one included: no
/// authority row is a bodiless shell.
fn validate_checkpoint_entity_row(blob: &[u8]) -> Result<()> {
    let header = crate::batch::EntityMetadataHeader::parse(blob).ok_or_else(codec_error)?;
    let body = &blob[crate::batch::ENTITY_METADATA_HEADER_LEN..];
    crate::batch::validate_local_identity_body(header.entity_type, body)?;
    if header.entity_type == crate::registry::ENTITY_TYPE_AUTHORITY_LOG
        && crate::authority::validate_authority_log_entry_body_bytes(body).is_err()
    {
        return Err(codec_error());
    }
    Ok(())
}

/// The image rows refused before any destination exists.
fn validate_image_rows_before_destination(
    image: &CheckpointImage,
) -> std::result::Result<(), Rejected> {
    // A job row of another kind in the owner-retained key range would
    // hide from that kind's scans: refused before any destination exists.
    if image.databases["job_records"]
        .iter()
        .any(|(key, value)| crate::attempt_queue::foreign_row_in_owner_retained_range(key, value))
    {
        return Err(codec_error().into());
    }
    // A signed authority row that fails its key-free checks (an owner
    // root or a world-key record among them), and a FACET carrying PERSON
    // identity, are refused here as at every other write door, before any
    // destination exists.
    for (_, blob) in &image.databases["entities"] {
        validate_checkpoint_entity_row(blob)?;
    }
    Ok(())
}
