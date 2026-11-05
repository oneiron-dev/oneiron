//! The approved untouched-byte promotion (FIX 6869, G4 PR1; owner ASK 3,
//! CALL F the lighter rule).
//!
//! A checked queue Baseline holds bytes no operation authored. The owner
//! admits them by accepting one exact import manifest over the exact
//! finalized Baseline it matches: same object store, commit, tree and
//! complete blob inventory, its successful baseline checks still on the
//! checker's rows, and the manifest review the owner's selected catalog
//! asks for (none at quorum 0). One writer co-commits the deterministic
//! `repo.import_approval` claim and the Baseline's existing promotion
//! receipt naming it. Checks and green confer no review authority; the
//! ordinary `promote_code_revision` guards are untouched.
use heed::RoTxn;

use super::CodeRevision;
use super::import_anchor::{
    baseline_import_approval_in_txn, import_manifest_in_txn, import_snapshot_custody_in_txn,
};
use super::import_types::{
    CodeImportAcceptance, CodeImportApproval, CodeImportManifest, IMPORT_APPROVAL_PREDICATE,
    approval_id, catalog_digest, manifest_digest,
};
use super::integrity::verify_or_build_code_revision_integrity_record_in_txn;
use super::promotion::{promotion_receipt_in_txn, put_promotion_receipt_in_txn};
use super::storage::get_code_revision_in_txn;
use super::tree_inventory::CodeTreeInventory;
use crate::consent::AuthenticatedOwner;
use crate::critic::{CRITIC_LENS_CATALOG_SCHEMA_VERSION, CritiqueVerdict, LensCatalog};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::merge_queue::QueueTestedTarget;
use crate::{EntityId, TimeRange, Vault};

/// Why an import's promotion waits (CALL H): the exact proof it lacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CodeImportHold {
    /// The named Baseline is not finalized, or its checks are gone.
    Baseline(String),
    /// The selected catalog's saved Accept review is missing.
    Review(String),
}

impl Vault {
    /// Promotes the checked Baseline `accept` names over the import
    /// manifest `manifest_ref`, as the live owner. Returns the approval id;
    /// an identical repeat returns the same one and writes nothing. A
    /// missing proof holds by name and writes nothing.
    ///
    /// # Errors
    /// An owner refusal, an acceptance of another digest, a Baseline that is
    /// not this manifest's, a withheld import, a promotion receipt that
    /// already names another approval, corruption or a store failure.
    pub(crate) fn promote_imported_code_revision(
        &self,
        owner: &AuthenticatedOwner,
        manifest_ref: EntityId,
        accept: &CodeImportAcceptance,
    ) -> Result<std::result::Result<EntityId, CodeImportHold>> {
        let served = {
            let txn = self.store.env.read_txn()?;
            import_manifest_in_txn(self, &txn, manifest_ref)?
                .ok_or(Error::EntityNotFound)?
                .anchor
                .served_repo
        };
        let common_dir = crate::origin::smart_http::push_queue_key(self, &served)?;
        let _guard = crate::git_wire::lock_repository(&common_dir)?;
        self.with_write_txn_grouped(|txn| {
            let approver = owner.revalidate_in_txn(self, txn)?;
            let manifest =
                import_manifest_in_txn(self, txn, manifest_ref)?.ok_or(Error::EntityNotFound)?;
            if accept.manifest_digest != manifest.digest {
                return Err(Error::InvalidClaimBody(
                    "owner acceptance names another import manifest digest",
                ));
            }
            if let Err(detail) = import_snapshot_custody_in_txn(self, txn, &manifest)? {
                return Err(Error::Refused(detail));
            }
            let Some(baseline) =
                get_code_revision_in_txn(&self.store, txn, &accept.baseline_revision)?
            else {
                return Ok(Err(CodeImportHold::Baseline(
                    "the named checked baseline is not finalized".to_owned(),
                )));
            };
            if let Err(hold) = require_import_baseline_in_txn(self, txn, &baseline, &manifest)? {
                return Ok(Err(hold));
            }
            let review = match require_import_manifest_review(
                self,
                txn,
                manifest_ref,
                &manifest.digest,
                accept,
            )? {
                Ok(review) => review,
                Err(detail) => return Ok(Err(CodeImportHold::Review(detail))),
            };
            let approval = approval_record(
                self,
                txn,
                &baseline,
                &manifest,
                manifest_ref,
                accept,
                review,
                approver,
            )?;
            let id = approval_id(&approval)?;
            let ids = vec![id.to_hex()];
            let stored = promotion_receipt_in_txn(&self.store, txn, &baseline.revision_id)?;
            if stored.as_ref().is_some_and(|stored| *stored != ids) {
                return Err(Error::ConcurrentWrite("revision promotion is immutable"));
            }
            match self.get_claim_in_txn(txn, &id)? {
                Some(body) if CodeImportApproval::from_claim(&body)? == approval => {}
                Some(_) => {
                    return Err(Error::ConcurrentWrite(
                        "an import approval id holds another record",
                    ));
                }
                None if self.get_raw_in(txn, &id)?.is_some() => {
                    return Err(Error::ConcurrentWrite(
                        "an import approval id holds another record",
                    ));
                }
                None => {
                    let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
                    let at = TimeRange {
                        start: now,
                        end: now,
                    };
                    self.put_reserved_claim_in_txn(txn, &id, &approval.claim_body()?, at, now)?;
                }
            }
            if stored.is_none() {
                put_promotion_receipt_in_txn(&self.store, txn, &baseline.revision_id, ids)?;
            }
            Ok(Ok(id))
        })
    }

    /// A Baseline's stored promotion receipt, judged again (G4 PR1): it
    /// names one typed import approval whose manifest, Baseline fold,
    /// complete inventory, checks, custody and selected review still hold.
    /// `Ok(Err(_))` names what no longer does.
    ///
    /// # Errors
    /// Corruption or a store failure.
    pub(crate) fn require_imported_baseline_promotion_in_txn(
        &self,
        txn: &RoTxn<'_>,
        baseline: &CodeRevision,
        stored: &[String],
    ) -> Result<std::result::Result<(), String>> {
        let Some((id, approval)) =
            baseline_import_approval_in_txn(self, txn, baseline.revision_id)?
        else {
            return Ok(Err(
                "the checked baseline holds untouched bytes no reviewed import admitted".to_owned(),
            ));
        };
        if stored != [id.to_hex()] {
            return Err(Error::CorruptedIndex(
                "a checked baseline's receipt is not its import approval",
            ));
        }
        // The recorded approver is judged again too: an approval stands
        // only while its approver is still a live owner here (FIX 7393).
        if !crate::policy_model::is_live_vault_owner_in_txn(self, txn, &approval.approver)? {
            return Ok(Err(
                "the import approval's approver is no longer an owner of this vault".to_owned(),
            ));
        }
        let Some(manifest) = import_manifest_in_txn(self, txn, approval.manifest)? else {
            return Ok(Err("the approved import manifest is gone".to_owned()));
        };
        if let Err(detail) = import_snapshot_custody_in_txn(self, txn, &manifest)? {
            return Ok(Err(detail));
        }
        if !baseline_names_import(baseline, &manifest) {
            return Ok(Err("the approved import names another baseline".to_owned()));
        }
        if let Err(detail) = self.require_tested_baseline_evidence_in_txn(txn, baseline)? {
            return Ok(Err(detail));
        }
        let catalog: LensCatalog = serde_json::from_str(&approval.catalog)
            .map_err(|_| Error::CorruptedIndex("an import approval's catalog does not read"))?;
        let accept = CodeImportAcceptance {
            manifest_digest: approval.manifest_digest.clone(),
            baseline_revision: baseline.revision_id,
            catalog,
            review_verdict: approval.review,
        };
        let review = match require_import_manifest_review(
            self,
            txn,
            approval.manifest,
            &manifest.digest,
            &accept,
        )? {
            Ok(review) => review,
            Err(detail) => return Ok(Err(detail)),
        };
        let expected = approval_record(
            self,
            txn,
            baseline,
            &manifest,
            approval.manifest,
            &accept,
            review,
            approval.approver,
        )?;
        if expected != approval {
            return Ok(Err(
                "the import approval no longer matches its baseline, evidence or review".to_owned(),
            ));
        }
        Ok(Ok(()))
    }
}

impl Vault {
    /// The checked Baseline the import manifest `manifest_ref` promotes now,
    /// with its approval, read with no acceptance (FIX 7393): the approval
    /// about the manifest that its Baseline's promotion receipt names, judged
    /// again. `Ok(Err(detail))` when one is recorded but no longer holds;
    /// `Ok(Ok(None))` when none is.
    ///
    /// # Errors
    /// Corruption or a store failure.
    pub(crate) fn imported_manifest_promotion(
        &self,
        manifest_ref: EntityId,
    ) -> Result<std::result::Result<Option<(EntityId, EntityId)>, String>> {
        let txn = self.store.env.read_txn()?;
        let mut approvals = Vec::new();
        self.find_claim_for_subject_in_txn(&txn, &manifest_ref, |id, body| {
            if body.predicate == IMPORT_APPROVAL_PREDICATE {
                approvals.push((*id, body.clone()));
            }
            None::<()>
        })?;
        let mut held = None;
        for (id, body) in approvals {
            let approval = CodeImportApproval::from_claim(&body)?;
            let Some(stored) =
                promotion_receipt_in_txn(&self.store, &txn, &approval.baseline_revision)?
            else {
                continue;
            };
            let Some(baseline) =
                get_code_revision_in_txn(&self.store, &txn, &approval.baseline_revision)?
            else {
                continue;
            };
            if stored != [id.to_hex()] {
                continue;
            }
            match self.require_imported_baseline_promotion_in_txn(&txn, &baseline, &stored)? {
                Ok(()) => return Ok(Ok(Some((baseline.revision_id, id)))),
                Err(detail) => held = Some(detail),
            }
        }
        Ok(held.map_or(Ok(None), Err))
    }
}

/// The exact Baseline a manifest admits, whose baseline checks are still on
/// the checker's rows. Another Baseline is an error; checks that are gone
/// hold.
fn require_import_baseline_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    baseline: &CodeRevision,
    manifest: &CodeImportManifest,
) -> Result<std::result::Result<(), CodeImportHold>> {
    if !baseline_names_import(baseline, manifest) {
        return Err(Error::InvalidClaimBody(
            "the named baseline is not the checked baseline of this import manifest",
        ));
    }
    Ok(vault
        .require_tested_baseline_evidence_in_txn(txn, baseline)?
        .map_err(CodeImportHold::Baseline))
}

/// Whether `baseline` is the checked Baseline `manifest` names: of its
/// object store at its commit and tree, with no documents, binding or
/// retired path, and holding exactly the manifest's complete blob
/// inventory, path, object, hash, size and mode.
fn baseline_names_import(baseline: &CodeRevision, manifest: &CodeImportManifest) -> bool {
    let anchor = &manifest.anchor;
    baseline.tested_queue.as_ref().is_some_and(|tested| {
        tested.target == QueueTestedTarget::Baseline
            && tested.store == anchor.object_store
            && tested.commit == anchor.source_commit
            && tested.tree == anchor.source_tree
            && CodeTreeInventory::digest(baseline)
                .is_ok_and(|digest| digest == tested.inventory_digest)
    }) && baseline.parent_revision_id.is_none()
        && baseline.file_frontiers.is_empty()
        && baseline.retired_paths.is_empty()
        && baseline.snapshot_anchor.is_none()
        && bytes_to_hex_lower(&CodeTreeInventory::blob_digest(&baseline.blob_frontiers))
            == manifest.inventory_digest
        && manifest_digest(anchor, &baseline.blob_frontiers) == manifest.digest
}

/// CALL F "import manifest review", the lighter rule (ih-rulings G4 PR1):
/// the owner's acceptance of the exact digest, plus, at the quorum the
/// owner's selected catalog sets, the saved `vault.critic.review` of this
/// manifest with an Accept triage covering every lens. An empty lens list
/// is quorum 0 on this import alone: the acceptance is the review and no
/// verdict is used. `Ok(Ok(review))` is the effective review the approval
/// keeps; `Ok(Err(_))` names the missing one. No fixed number of critics,
/// no independence or unanimity rule, and no auto-resolution is asked.
fn require_import_manifest_review(
    vault: &Vault,
    txn: &RoTxn<'_>,
    manifest_ref: EntityId,
    expected_digest: &str,
    accept: &CodeImportAcceptance,
) -> Result<std::result::Result<Option<EntityId>, String>> {
    if accept.manifest_digest != expected_digest {
        return Err(Error::InvalidClaimBody(
            "owner acceptance names another import manifest digest",
        ));
    }
    if accept.catalog.schema_version != CRITIC_LENS_CATALOG_SCHEMA_VERSION {
        return Err(Error::InvalidConfig(
            "unsupported import review catalog schema_version".into(),
        ));
    }
    // The owner selected zero reviews: the exact-digest acceptance is it.
    if accept.catalog.lenses.is_empty() {
        return Ok(Ok(None));
    }
    let catalog_json = serde_json::to_string(&accept.catalog)
        .map_err(|_| Error::InvalidClaimBody("import review catalog encode"))?;
    let catalog = LensCatalog::from_json_str(&catalog_json)?;
    let held = |detail: &str| Ok(Err(detail.to_owned()));
    let Some(verdict) = accept.review_verdict else {
        return held("the selected catalog asks for a saved manifest review");
    };
    let Some(review) =
        crate::critic::review::trusted_review_in_txn(vault, txn, &verdict, &manifest_ref)?
    else {
        return held("no saved review of this manifest names that verdict");
    };
    let target = manifest_ref.to_hex();
    if review.triage.verdict != CritiqueVerdict::Accept {
        return held("the saved manifest review did not accept it");
    }
    if catalog.lenses.iter().any(|lens| {
        !review.artifacts.iter().any(|artifact| {
            artifact.candidate_ref == target
                && artifact.lens_id == lens.id
                && artifact.domain == lens.domain
                && !artifact.out_of_scope
                && (!lens.hard_check || artifact.hard_check_passed == Some(true))
        })
    }) {
        return held("the saved manifest review does not cover the selected catalog");
    }
    Ok(Ok(Some(review.verdict_claim)))
}

/// The approval record one promotion writes: the manifest, the Baseline's
/// fold, inventory, plan and receipts, the selected catalog, the effective
/// review and the real approving owner.
#[allow(
    clippy::too_many_arguments,
    reason = "the approval binds each of these exactly"
)]
fn approval_record(
    vault: &Vault,
    txn: &RoTxn<'_>,
    baseline: &CodeRevision,
    manifest: &CodeImportManifest,
    manifest_ref: EntityId,
    accept: &CodeImportAcceptance,
    review: Option<EntityId>,
    approver: EntityId,
) -> Result<CodeImportApproval> {
    let tested = baseline
        .tested_queue
        .as_ref()
        .ok_or(Error::InvalidClaimBody("not a tested queue revision"))?;
    let fold = verify_or_build_code_revision_integrity_record_in_txn(
        &vault.store,
        txn,
        baseline,
        &mut std::collections::HashSet::new(),
    )?
    .revision_fold;
    let (catalog, catalog_digest) = catalog_digest(&accept.catalog)?;
    Ok(CodeImportApproval {
        schema_version: 1,
        manifest: manifest_ref,
        manifest_digest: manifest.digest.clone(),
        baseline_revision: baseline.revision_id,
        baseline_fold: bytes_to_hex_lower(&fold),
        inventory_digest: bytes_to_hex_lower(&tested.inventory_digest),
        plan_digest: tested.plan_digest.clone(),
        evidence: tested
            .fast
            .iter()
            .chain(std::iter::once(&tested.slow))
            .map(|link| link.inputs_digest.clone())
            .collect(),
        catalog,
        catalog_digest,
        review,
        approver,
    })
}
