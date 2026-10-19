//! The deck's export: its projection over the package it is bound to,
//! landed as the artifact's next blob version while the profile's export
//! gate is open, or waiting beside the artifact for Keep while it is closed.
//!
//! Either way the export was made over one version, the deck's base: its
//! last landed export, else the imported source. When the artifact's head is
//! another version by the time the export lands (one that landed outside the
//! deck since), the export forks from the base and becomes the head, the
//! version it replaced stays beside it as its own, the deck binds to the
//! export, and the result names both (FIX 2700). Nothing refuses because the
//! head moved, and no bytes merge.

use super::super::{
    EXPORTS, OfficeBodyExportRecord, OfficeBodyKind, SOURCES, invalid, version_key, writer,
};
use super::{PptxExport, doc, export_gate, live};
use crate::Vault;
use crate::blob_artifact::{
    BlobArtifactVersion, BlobVersionProvenance, VersionReconciliation,
    read_blob_artifact_head_in_txn,
};
use crate::edit_roundtrip::VaultAssets;
use crate::edit_settle::{DeckExportHold, NativeOutput, PendingProposalView};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::provenance::made_by::MadeBy;
use crate::temporal::TimeRange;
use crate::typed_body::{BodyActor, edit_typed_body_in_txn};
use crate::write_envelope::WriteActor;
use heed::RwTxn;
use oneiron_docedit::live::deck_export::PROJECTOR_VERSION;
use oneiron_docedit::live::{ExportOutcome, ExportProfile, HeldAssets, effect_receipt, project};
use oneiron_docedit::retained_opc::Package;

impl Vault {
    /// Project the deck at its head over its retained package (the imported
    /// source, or the version the last landed export made). Until the
    /// profile's export gate opens the result is a proposal artifact: nothing
    /// lands, and the caller proposes the bytes through the edit rails.
    pub fn export_pptx_body(&self, artifact: &EntityId) -> Result<PptxExport> {
        let source = self
            .office_body_head(artifact)?
            .ok_or(Error::EntityNotFound)?;
        let profile = ExportProfile::default();
        let (head, body, gate, assets) = {
            let txn = self.store.env.read_txn()?;
            let (head, body) = self.deck_head(&txn, artifact)?;
            let assets = HeldAssets::resolve(
                &VaultAssets {
                    vault: self,
                    txn: &txn,
                },
                &[&body.deck],
            );
            (
                head,
                body,
                export_gate(&self.store, &txn, &profile.name)?,
                assets,
            )
        };
        let (base_version, base_hash) = body
            .retained
            .map_or((source.source_version, source.source_hash), |retained| {
                (retained.version, retained.hash)
            });
        let package = Package::open(
            &self.deck_source(artifact, &source, body.retained)?,
            self.docedit_package_limits()?,
        )
        .map_err(|_| invalid("the PPTX package could not be read"))?;
        let outcome =
            project(&body.deck, &package, &artifact.to_hex(), &profile, &assets).map_err(live)?;
        Ok(PptxExport {
            frontier: head.frontier,
            authoritative: gate.is_open(),
            outcome,
            base_version,
            base_hash,
        })
    }

    /// Land an authoritative export: its bytes become the artifact's next blob
    /// version, recorded with the frontier it projects, and the deck rebinds to
    /// them (the same node identities, the exported native ids and
    /// fingerprints, the joined allocation history) in the lander's commit; the
    /// next export projects over them. When the head is not the version the
    /// deck projected over, the export forks from that version and the head
    /// stays beside it, named in the result (FIX 2700). A proposal export, an
    /// export whose profile's gate is closed now or whose projector is not the
    /// current one, or a deck head that moved since the export, refuses.
    pub fn land_pptx_export(
        &self,
        artifact: &EntityId,
        export: &PptxExport,
        actor: WriteActor,
        made_by: &MadeBy,
        provenance: &BlobVersionProvenance,
    ) -> Result<(BlobArtifactVersion, Option<VersionReconciliation>)> {
        if !export.authoritative {
            return Err(invalid(
                "the deck export gate is closed for its profile; the export is a proposal",
            ));
        }
        let at = self.now_recorded_at();
        self.with_write_txn_grouped(|wtxn| {
            let key = &export.outcome.key;
            if key.projector != PROJECTOR_VERSION
                || !export_gate(&self.store, wtxn, &key.profile)?.is_open()
            {
                return Err(invalid(
                    "the deck export gate is closed for its profile; the export is a proposal",
                ));
            }
            let (head, mut body) = self.deck_head(wtxn, artifact)?;
            if head.frontier != export.frontier {
                return Err(invalid("the deck moved since the export; export again"));
            }
            let replaced = read_blob_artifact_head_in_txn(&self.store, wtxn, artifact)?;
            let fork_parent = forked_from(export.base_version, replaced.as_ref());
            let version = self.append_blob_artifact_version_with_engine_and_parent_in_txn(
                wtxn,
                artifact,
                &export.outcome.bytes,
                provenance,
                None,
                actor,
                TimeRange { start: at, end: at },
                at,
                fork_parent,
                None,
            )?;
            body.deck.rebind(&export.outcome).map_err(live)?;
            let retained = doc::Retained {
                version: version.version,
                hash: *blake3::hash(&export.outcome.bytes).as_bytes(),
            };
            let writer = writer(OfficeBodyKind::Pptx, actor, made_by);
            edit_typed_body_in_txn(self, wtxn, artifact, None, writer, |doc| {
                doc::sync_to(doc, &body.deck)?;
                doc::push_landed(doc, &retained)
            })?;
            let record = export_record(
                (artifact, version.version, export.frontier.clone()),
                export.base_version,
                actor,
                at,
                (
                    export.outcome.changed_parts.len() as u64,
                    export.outcome.effects.iter().map(effect_receipt).collect(),
                ),
            );
            EXPORTS.put(
                &self.store,
                wtxn,
                &version_key(artifact, version.version),
                &record,
            )?;
            let reconciliation = VersionReconciliation::of(fork_parent, replaced.as_ref());
            Ok((version, reconciliation))
        })
    }

    /// Offer a proposal export (its profile's gate closed) to the artifact as
    /// a waiting proposal under `run_ref`, pinned to the version the deck
    /// projected over: the Keep door lands its bytes as the next blob version
    /// under a person's consent, forked from that version when the head is
    /// another, and binds the deck to it ([`Self::keep_deck_export_in_txn`]);
    /// Discard drops it.
    pub fn propose_pptx_export(
        &self,
        artifact: &EntityId,
        export: &PptxExport,
        run_ref: &str,
        actor: WriteActor,
        made_by: &MadeBy,
    ) -> Result<PendingProposalView> {
        if export.authoritative {
            return Err(invalid("an authoritative export lands; it is not proposed"));
        }
        let body = self
            .get_blob_artifact(artifact)?
            .ok_or(Error::EntityNotFound)?;
        let outcome = &export.outcome;
        let key = &outcome.key;
        let effects: Vec<String> = outcome.effects.iter().map(effect_receipt).collect();
        let output = NativeOutput {
            run_ref: run_ref.to_owned(),
            name: body.name,
            media_type: body.media_type,
            bytes: outcome.bytes.clone(),
            report: serde_json::json!({
                "deck_export": {
                    "profile": key.profile,
                    "projector": key.projector,
                    "document_version": outcome.document_version,
                    "changed_parts": outcome.changed_parts,
                    "effects": effects,
                }
            }),
            made_by: Some(made_by.clone()),
        };
        let hold = DeckExportHold {
            frontier: export.frontier.clone(),
            key: key.clone(),
            document_version: outcome.document_version,
            bindings: outcome.bindings.clone(),
            opaque_parts: outcome.opaque_parts.clone(),
            id_marks: outcome.id_marks.clone(),
            changes: outcome.changed_parts.len() as u64,
            effects,
        };
        self.propose_deck_export(
            artifact,
            &output,
            (actor, self.now_recorded_at()),
            (export.base_version, export.base_hash),
            hold,
        )
    }

    /// The deck side of a kept deck export (FIX 2700), in the Keep's
    /// transaction once its version `version` landed: the export record, and
    /// the deck bound to `version` when it is still bound to `base`, the
    /// version the export projected over. The binding is written at the
    /// export's frontier and merges into the head as a CRDT peer's would, so
    /// edits made since stay as they are and the next export projects them
    /// over the kept version. A deck bound to another version since, or one
    /// whose state at that frontier is not the exported one, keeps its
    /// binding, as a Keep left it before.
    pub(crate) fn keep_deck_export_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact: &EntityId,
        hold: &DeckExportHold,
        (base_version, base_hash): (Option<u64>, Option<[u8; 32]>),
        version: &BlobArtifactVersion,
        (actor, made_by, at): (WriteActor, Option<&MadeBy>, u64),
    ) -> Result<()> {
        let Some(source) = SOURCES.get(&self.store, wtxn, artifact)? else {
            return Ok(());
        };
        if source.kind != OfficeBodyKind::Pptx {
            return Ok(());
        }
        let (head, body) = self.deck_head(wtxn, artifact)?;
        let bound = body
            .retained
            .map_or((source.source_version, source.source_hash), |retained| {
                (retained.version, retained.hash)
            });
        // The deck as the export projected it, bound to the kept version.
        let still_bound = (Some(bound.0), Some(bound.1)) == (base_version, base_hash);
        if let Some(made_by) = made_by
            && still_bound
            && let Ok((_, at_export)) =
                self.loro_body(wtxn, artifact, OfficeBodyKind::Pptx, Some(&hold.frontier))
            && let Ok(mut exported) = doc::read(&at_export)
            && exported.deck.rebind(&outcome_of(hold)).is_ok()
        {
            let retained = doc::Retained {
                version: version.version,
                hash: version.content_hash,
            };
            let base = (head.frontier != hold.frontier).then_some(hold.frontier.as_slice());
            let writer = writer(OfficeBodyKind::Pptx, actor, made_by);
            edit_typed_body_in_txn(self, wtxn, artifact, base, writer, |doc| {
                doc::sync_to(doc, &exported.deck)?;
                doc::push_landed(doc, &retained)
            })?;
        }
        let record = export_record(
            (artifact, version.version, hold.frontier.clone()),
            base_version.unwrap_or(source.source_version),
            actor,
            at,
            (hold.changes, hold.effects.clone()),
        );
        EXPORTS.put(
            &self.store,
            wtxn,
            &version_key(artifact, version.version),
            &record,
        )
    }
}

/// The version an export forks from: its `base` when the artifact's head
/// is another version; none when the head is the base, or there is none.
fn forked_from(base: u64, head: Option<&BlobArtifactVersion>) -> Option<u64> {
    head.filter(|head| head.version != base).map(|_| base)
}

/// The rebinding a held export carries, as the projection gave it: its key
/// (whose state hash pins the deck state it binds), bindings, opaque part
/// hashes and allocation history.
fn outcome_of(hold: &DeckExportHold) -> ExportOutcome {
    ExportOutcome {
        bytes: Vec::new(),
        key: hold.key.clone(),
        document_version: hold.document_version,
        changed_parts: Vec::new(),
        noop: false,
        bindings: hold.bindings.clone(),
        opaque_parts: hold.opaque_parts.clone(),
        id_marks: hold.id_marks.clone(),
        effects: Vec::new(),
    }
}

/// The export record of version `version` of `artifact`, projected at
/// `frontier` over `source_version`: its lander, time, change count and
/// effect receipts.
fn export_record(
    (artifact, version, frontier): (&EntityId, u64, Vec<u8>),
    source_version: u64,
    actor: WriteActor,
    at: u64,
    (changes, effects): (u64, Vec<String>),
) -> OfficeBodyExportRecord {
    OfficeBodyExportRecord {
        artifact: *artifact,
        version,
        frontier,
        source_version,
        actor: BodyActor::Actor(actor.entity_ref()),
        author: actor.entity_ref().to_hex(),
        token: None,
        at,
        changes,
        recalc: None,
        effects,
    }
}
