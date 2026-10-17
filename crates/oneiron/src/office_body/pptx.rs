//! The PPTX body: the OF-510 live deck (`oneiron_docedit::live`) as a Loro
//! document on the typed-body door, schema `office.pptx.v1` (ARCH-0077,
//! "Multiplayer: the target body shape"; its layout is in [`doc`]).
//!
//! A deck/shape tree with model node ids kept apart from native ids and from
//! the Loro handles, one rich-text body per text shape, and a log in which
//! every operation names its actor, from which the attribution index rebuilds.
//! A person's operations apply to the deck as of the frontier the caller read
//! and merge into the head as a CRDT peer's would; the merged deck must still
//! keep the deck's tree rules, since a converged state is not necessarily a
//! valid deck. Machine work goes through a typed-body fork of the document,
//! each call a Loro commit under its maker's receipt; the merge preflight
//! reviews it as a `DeckFork` (the deck at the fork's base and the operations
//! its log holds past it), and someone other than its proposer lands it: the
//! fork's own changes are imported, so its receipts land with them. Until the
//! deck export gate opens for its profile, blob versions stay authoritative: an
//! export is a proposal artifact, not a version. The gate opens on the deck
//! oracle's receipt for the profile ([`Vault::record_pptx_oracle_receipt`]),
//! all eight steps passed on a clean opening against the current projector.
//! Once it opens, [`Vault::land_pptx_export`] lands the bytes as the next blob
//! version, records the frontier it projects, and rebinds the deck to them,
//! and later exports project over them.
//!
//! Every creation names its node identity before it is logged, so a fork's
//! operations replay onto the head as the same nodes.

mod doc;

pub(super) use doc::{birth, validate};

use super::{
    EXPORTS, FORKS, ForkState, OfficeBodyEdit, OfficeBodyExportRecord, OfficeBodyFork,
    OfficeBodyHead, OfficeBodyKind, bounded_ops, check_made_by, invalid, source, version_key,
    writer,
};
use crate::Vault;
use crate::blob_artifact::{BlobArtifactVersion, BlobVersionProvenance};
use crate::edit_roundtrip::VaultAssets;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, LiveDeckRefusal, Result};
use crate::provenance::made_by::MadeBy;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::typed_body::{
    TypedBodyHead, discard_typed_body_fork_in_txn, edit_typed_body_fork_in_txn,
    edit_typed_body_in_txn, merge_typed_body_fork_in_txn, open_typed_body_fork_in_txn,
    typed_body_fork_in_txn,
};
use crate::write_envelope::WriteActor;
use heed::{RoTxn, RwTxn};
use oneiron_docedit::live::deck_export::PROJECTOR_VERSION;
use oneiron_docedit::live::{
    ApproveScope, AttributionIndex, DeckFork, DeckOp, ExportOutcome, ExportProfile, Gate,
    HeldAssets, Landing, LandingReceipt, LiveDeck, LiveError, NodeId, OracleReceipt,
    PreflightReport, StampedOp, attach_evidence, land, preflight, project,
};
use oneiron_docedit::retained_opc::{Limits, Package};
use serde::{Deserialize, Serialize};

/// The deck oracle's latest receipt per export profile, by profile name.
const ORACLE: SideTable<String, OracleRecord, Named> =
    SideTable::new(&side_table::OFFICE_BODY_ORACLE);

/// The longest export profile name a receipt may carry.
const MAX_PROFILE_LEN: usize = 128;

/// One profile's oracle receipt as recorded: the eight-step check's outcome
/// and the projector it checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct OracleRecord {
    receipt: OracleReceipt,
    /// The projector the oracle checked (`PROJECTOR_VERSION` when it was
    /// recorded); a receipt for another projector opens nothing.
    projector: String,
    recorded_by: EntityId,
    recorded_at: u64,
}

/// A typed read of the deck body at one frontier.
#[derive(Debug, Clone)]
pub struct PptxBody {
    pub deck: LiveDeck,
    /// Every stamped operation the body holds, in log order.
    pub log: Vec<StampedOp>,
    /// Who made each visible thing; imported content has no maker.
    pub attribution: AttributionIndex,
    pub frontier: Vec<u8>,
}

/// A deck fork reviewed against the head it would land on.
#[derive(Debug, Clone)]
pub struct PptxReview {
    pub head: Vec<u8>,
    pub report: PreflightReport,
    /// Units the fork touches that the head changed since its base: their
    /// answers are withdrawn (ARCH-0075 section 4), untouched units carry.
    pub stale_units: Vec<NodeId>,
    /// Why the relationship and render components could not be attached
    /// (the head or the candidate does not project); the diff then keeps its
    /// conservative affected slides.
    pub evidence_refusal: Option<String>,
}

/// A projected deck. `authoritative` only when the export gate is open for the
/// profile; until then the bytes are a proposal artifact for the edit rails.
#[derive(Debug, Clone)]
pub struct PptxExport {
    pub frontier: Vec<u8>,
    pub authoritative: bool,
    pub outcome: ExportOutcome,
}

/// The imported deck a body is born with.
pub(super) fn import_deck(bytes: &[u8], limits: Limits) -> Result<LiveDeck> {
    let package =
        Package::open(bytes, limits).map_err(|_| invalid("the PPTX package could not be read"))?;
    LiveDeck::import(&package).map_err(live)
}

impl Vault {
    /// The deck body at its head, or at an earlier frontier `at` of its
    /// history, with who made each visible thing.
    pub fn read_pptx_body(&self, artifact: &EntityId, at: Option<&[u8]>) -> Result<PptxBody> {
        let txn = self.store.env.read_txn()?;
        let (head, doc) = self.loro_body(&txn, artifact, OfficeBodyKind::Pptx, at)?;
        let body = doc::read(&doc)?;
        Ok(PptxBody {
            attribution: AttributionIndex::build(&body.deck, &body.log),
            frontier: at.map_or(head.frontier, <[u8]>::to_vec),
            deck: body.deck,
            log: body.log,
        })
    }

    /// A person's operations on the live deck, each stamped with the actor.
    /// Read against an older `base` frontier they apply to the deck as it was
    /// there and merge into the head as a CRDT peer's would. A merged deck
    /// that breaks the tree rules refuses, as does replacing an opaque part
    /// another writer replaced since the base. Machine work goes through a
    /// fork.
    pub fn edit_pptx_body(
        &self,
        artifact: &EntityId,
        base: Option<&[u8]>,
        ops: &[DeckOp],
        actor: WriteActor,
        made_by: &MadeBy,
    ) -> Result<OfficeBodyEdit> {
        bounded_ops(ops.len())?;
        let ops = self.name_creations(ops)?;
        let stamped: Vec<StampedOp> = ops
            .iter()
            .map(|op| StampedOp {
                made_by: actor.entity_ref().to_hex(),
                at: made_by.at,
                op: op.clone(),
            })
            .collect();
        self.edit_live(
            artifact,
            OfficeBodyKind::Pptx,
            base,
            (actor, made_by),
            |base, head| doc::admit(base, head, &ops),
            |doc| {
                let mut body = doc::read(doc)?;
                for op in &stamped {
                    body.deck.apply(op).map_err(live)?;
                }
                doc::sync_to(doc, &body.deck)?;
                doc::append_log(doc, &stamped)?;
                Ok(ops
                    .iter()
                    .filter_map(DeckOp::created)
                    .map(|id| id.0.to_string())
                    .collect())
            },
        )
    }

    /// The opener's operations on its open deck fork, one Loro commit on the
    /// fork's document under `made_by`'s receipt. Each must apply to the
    /// fork's proposal state.
    pub fn edit_pptx_body_fork(
        &self,
        artifact: &EntityId,
        fork: &EntityId,
        ops: &[DeckOp],
        actor: WriteActor,
        made_by: &MadeBy,
    ) -> Result<OfficeBodyEdit> {
        bounded_ops(ops.len())?;
        check_made_by(actor, made_by)?;
        let ops = self.name_creations(ops)?;
        let stamped: Vec<StampedOp> = ops
            .iter()
            .map(|op| StampedOp {
                made_by: actor.entity_ref().to_hex(),
                at: made_by.at,
                op: op.clone(),
            })
            .collect();
        self.with_write_txn_grouped(|wtxn| {
            let key = (*artifact, *fork);
            let mut record = open_record(&self.store, wtxn, artifact, fork)?;
            if record.opener != actor.entity_ref() {
                return Err(invalid("only the opener writes to its open fork"));
            }
            let writer = writer(OfficeBodyKind::Pptx, actor, made_by);
            let (_, commit) =
                edit_typed_body_fork_in_txn(self, wtxn, artifact, fork, writer, |doc| {
                    let mut body = doc::read(doc)?;
                    for op in &stamped {
                        body.deck.apply(op).map_err(live)?;
                    }
                    doc::sync_to(doc, &body.deck)?;
                    doc::append_log(doc, &stamped)
                })?;
            record.commits += 1;
            FORKS.put(&self.store, wtxn, &key, &record)?;
            Ok(OfficeBodyEdit {
                frontier: commit.frontier,
                minted: ops
                    .iter()
                    .filter_map(DeckOp::created)
                    .map(|id| id.0.to_string())
                    .collect(),
                receipt: commit.receipt,
            })
        })
    }

    /// The deck fork's merge preflight against the live head: the three-way
    /// diff with its named conflicts, the replay onto the head, the stale
    /// units, and the relationship and render components of the head's export
    /// against the merged candidate's.
    pub fn pptx_body_fork_review(
        &self,
        artifact: &EntityId,
        fork: &EntityId,
    ) -> Result<PptxReview> {
        let source = self
            .office_body_head(artifact)?
            .ok_or(Error::EntityNotFound)?;
        // The live-born pictures' assets of the head and the candidate are read
        // in the same transaction as the head.
        let ((head, body), work, mut report, assets) = {
            let txn = self.store.env.read_txn()?;
            let (head, body) = self.deck_head(&txn, artifact)?;
            let record = open_record(&self.store, &txn, artifact, fork)?;
            let work = self.deck_fork(&txn, &record)?;
            let report = preflight(&body.deck, &work).map_err(live)?;
            let assets = HeldAssets::resolve(
                &VaultAssets {
                    vault: self,
                    txn: &txn,
                },
                &[&body.deck, &report.candidate],
            );
            ((head, body), work, report, assets)
        };
        let package = Package::open(
            &self.deck_source(artifact, &source, body.retained)?,
            self.docedit_package_limits()?,
        )
        .map_err(|_| invalid("the PPTX package could not be read"))?;
        let evidence_refusal = attach_evidence(
            &mut report,
            &body.deck,
            &package,
            &artifact.to_hex(),
            &ExportProfile::default(),
            &assets,
        )
        .err()
        .map(|error| error.to_string());
        Ok(PptxReview {
            report,
            stale_units: work.stale_units(&body.deck),
            head: head.frontier,
            evidence_refusal,
        })
    }

    /// Land a reviewed deck fork. The settler names the head it reviewed; a
    /// moved head, an unresolved conflict, the opener as settler or a scope
    /// that does not cover the fork refuses. Once the landing checks pass, the
    /// fork's own Loro changes are imported, so its operations join the
    /// body's log with their receipts; where the imported deck differs from
    /// the landing's (a switch, or a merge the head moved under), one commit
    /// of the settler's makes it the landing's.
    #[allow(clippy::too_many_arguments)]
    pub fn merge_pptx_body_fork(
        &self,
        artifact: &EntityId,
        fork: &EntityId,
        expected_head: &[u8],
        actor: WriteActor,
        made_by: &MadeBy,
        scope: ApproveScope,
        landing: Landing,
    ) -> Result<LandingReceipt> {
        let at = self.now_recorded_at();
        self.with_write_txn_grouped(|wtxn| {
            let key = (*artifact, *fork);
            let mut record = open_record(&self.store, wtxn, artifact, fork)?;
            // "The opener's lineage and its forks never settle their own proposal."
            if record.opener == actor.entity_ref() {
                return Err(invalid("a fork's opener cannot merge it"));
            }
            let (head, mut body) = self.deck_head(wtxn, artifact)?;
            if head.frontier != expected_head {
                return Err(invalid("the deck moved since the review; review it again"));
            }
            let work = self.deck_fork(wtxn, &record)?;
            let report = preflight(&body.deck, &work).map_err(live)?;
            let mut receipt = land(
                &mut body.deck,
                &work,
                &report,
                &actor.entity_ref().to_hex(),
                scope,
                landing,
                false,
            )
            .map_err(live)?;
            let merged =
                merge_typed_body_fork_in_txn(self, wtxn, artifact, fork, &head.frontier, actor)?;
            let (_, imported) = self.deck_head(wtxn, artifact)?;
            let landed = imported.deck.semantically_eq(&body.deck)
                && imported.deck.next_node == body.deck.next_node
                && imported.deck.id_marks == body.deck.id_marks;
            let frontier = if landed {
                receipt.landed_version = imported.deck.version;
                merged.frontier
            } else {
                let writer = writer(OfficeBodyKind::Pptx, actor, made_by);
                let (_, commit) =
                    edit_typed_body_in_txn(self, wtxn, artifact, None, writer, |doc| {
                        doc::sync_to(doc, &body.deck)
                    })?;
                receipt.landed_version = self.deck_head(wtxn, artifact)?.1.deck.version;
                commit.frontier
            };
            record.state = ForkState::Merged {
                by: actor.entity_ref(),
                at,
                head: frontier,
            };
            FORKS.put(&self.store, wtxn, &key, &record)?;
            Ok(receipt)
        })
    }

    /// Record the deck oracle's receipt for its profile, checked against the
    /// current projector. It replaces the profile's earlier receipt, so a
    /// later failed run closes the gate a pass opened.
    pub fn record_pptx_oracle_receipt(
        &self,
        receipt: &OracleReceipt,
        actor: WriteActor,
    ) -> Result<()> {
        if receipt.profile.is_empty() || receipt.profile.len() > MAX_PROFILE_LEN {
            return Err(invalid("an oracle receipt names its export profile"));
        }
        let record = OracleRecord {
            receipt: receipt.clone(),
            projector: PROJECTOR_VERSION.to_owned(),
            recorded_by: actor.entity_ref(),
            recorded_at: self.now_recorded_at(),
        };
        self.with_write_txn_grouped(|wtxn| ORACLE.put(&self.store, wtxn, &receipt.profile, &record))
    }

    /// The deck export gate for `profile`: its recorded oracle receipt, when
    /// that receipt checked the current projector.
    pub fn pptx_export_gate(&self, profile: &str) -> Result<Gate> {
        let txn = self.store.env.read_txn()?;
        export_gate(&self.store, &txn, profile)
    }

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
        })
    }

    /// Land an authoritative export: its bytes become the artifact's next blob
    /// version, recorded with the frontier it projects, and the deck rebinds to
    /// them (the same node identities, the exported native ids and
    /// fingerprints, the joined allocation history) in the lander's commit; the
    /// next export projects over them. A proposal export, an export whose
    /// profile's gate is closed now or whose projector is not the current one,
    /// or a head that moved since the export, refuses.
    pub fn land_pptx_export(
        &self,
        artifact: &EntityId,
        export: &PptxExport,
        actor: WriteActor,
        made_by: &MadeBy,
        provenance: &BlobVersionProvenance,
    ) -> Result<BlobArtifactVersion> {
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
            let version = self.append_blob_artifact_version_in_txn(
                wtxn,
                artifact,
                &export.outcome.bytes,
                provenance,
                actor,
                TimeRange { start: at, end: at },
                at,
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
            let record = OfficeBodyExportRecord {
                artifact: *artifact,
                version: version.version,
                frontier: export.frontier.clone(),
                source_version: source(&self.store, wtxn, artifact)?.source_version,
                actor: actor.entity_ref(),
                author: actor.entity_ref().to_hex(),
                at,
                changes: export.outcome.changed_parts.len() as u64,
                recalc: None,
            };
            EXPORTS.put(
                &self.store,
                wtxn,
                &version_key(artifact, version.version),
                &record,
            )?;
            Ok(version)
        })
    }

    /// The deck at the head of its body, with the head.
    fn deck_head(
        &self,
        txn: &RoTxn<'_>,
        artifact: &EntityId,
    ) -> Result<(TypedBodyHead, doc::Body)> {
        let (head, doc) = self.loro_body(txn, artifact, OfficeBodyKind::Pptx, None)?;
        Ok((head, doc::read(&doc)?))
    }

    /// The package the deck is bound to, checked against its recorded hash.
    fn deck_source(
        &self,
        artifact: &EntityId,
        head: &OfficeBodyHead,
        retained: Option<doc::Retained>,
    ) -> Result<Vec<u8>> {
        let Some(retained) = retained else {
            return self.body_source(artifact, head);
        };
        let bytes = self
            .read_blob_artifact_version(artifact, retained.version)?
            .ok_or(Error::EntityNotFound)?;
        if *blake3::hash(&bytes).as_bytes() != retained.hash {
            return Err(Error::CorruptedIndex("deck retained version"));
        }
        Ok(bytes)
    }

    /// `ops` with every creation naming a fresh identity, so the log, a fork's
    /// replay onto the head and a concurrent writer all make the same node.
    /// Fresh identities set the top bit, above the import's sequential ones.
    fn name_creations(&self, ops: &[DeckOp]) -> Result<Vec<DeckOp>> {
        ops.iter()
            .map(|op| {
                let mut op = op.clone();
                if matches!(
                    op,
                    DeckOp::AddSlide { id: None } | DeckOp::AddNode { id: None, .. }
                ) {
                    let entropy = self.new_entity_id()?;
                    op.name_creation(|| fresh_node(&entropy));
                }
                Ok(op)
            })
            .collect()
    }

    /// Open a deck fork at the live head for `actor`'s machine work in the run
    /// `run_root`, so that run's approve-all scope covers it: a typed-body
    /// fork of the document, with the office record that names the run.
    pub(super) fn open_deck_fork(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact: &EntityId,
        actor: WriteActor,
        run_root: Option<&EntityId>,
    ) -> Result<OfficeBodyFork> {
        let typed = open_typed_body_fork_in_txn(
            self,
            wtxn,
            artifact,
            OfficeBodyKind::Pptx.schema(),
            actor,
        )?;
        let fork = OfficeBodyFork {
            id: typed.fork,
            artifact: *artifact,
            opener: typed.opener,
            base: typed.base,
            commits: 0,
            opened_at: typed.opened_at,
            state: ForkState::Open,
            run_root: run_root.copied(),
        };
        FORKS.put(&self.store, wtxn, &(*artifact, fork.id), &fork)?;
        Ok(fork)
    }

    /// The open deck fork as the merge preflight reads it: the deck at the
    /// fork's base, and the operations the fork's log holds past the base's.
    fn deck_fork(&self, txn: &RoTxn<'_>, record: &OfficeBodyFork) -> Result<DeckFork> {
        let (typed, proposal) =
            typed_body_fork_in_txn(&self.store, txn, &record.artifact, &record.id)?
                .ok_or(Error::EntityNotFound)?;
        let proposal = doc::read(&proposal.ok_or_else(|| invalid("the fork is not open"))?)?;
        let (_, base) = self.loro_body(
            txn,
            &record.artifact,
            OfficeBodyKind::Pptx,
            Some(&typed.base),
        )?;
        let base = doc::read(&base)?;
        let ops = proposal
            .log
            .get(base.log.len()..)
            .ok_or(Error::CorruptedIndex("deck fork log"))?;
        let run_root = record.run_root.map(|root| root.to_hex());
        let mut work = base.deck.fork_at(
            &record.id.to_hex(),
            &record.opener.to_hex(),
            run_root.as_deref(),
        );
        for op in ops {
            work.record(op.clone());
        }
        Ok(work)
    }

    pub(super) fn discard_deck_fork(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact: &EntityId,
        fork: &EntityId,
        actor: WriteActor,
    ) -> Result<()> {
        let mut record = open_record(&self.store, wtxn, artifact, fork)?;
        discard_typed_body_fork_in_txn(self, wtxn, artifact, fork, actor)?;
        record.state = ForkState::Discarded {
            by: actor.entity_ref(),
            at: self.now_recorded_at(),
        };
        FORKS.put(&self.store, wtxn, &(*artifact, *fork), &record)?;
        Ok(())
    }
}

fn export_gate(store: &Store, txn: &RoTxn<'_>, profile: &str) -> Result<Gate> {
    let receipt = ORACLE
        .get(store, txn, &profile.to_owned())?
        .filter(|record| record.projector == PROJECTOR_VERSION)
        .map(|record| record.receipt);
    Ok(Gate {
        profile: profile.to_owned(),
        receipt,
    })
}

fn open_record(
    store: &Store,
    txn: &RoTxn<'_>,
    artifact: &EntityId,
    fork: &EntityId,
) -> Result<OfficeBodyFork> {
    let record = FORKS
        .get(store, txn, &(*artifact, *fork))?
        .ok_or(Error::EntityNotFound)?;
    if record.state != ForkState::Open {
        return Err(invalid("the fork is not open"));
    }
    Ok(record)
}

/// A node identity drawn from fresh entity entropy, top bit set.
fn fresh_node(entropy: &EntityId) -> NodeId {
    let hash = blake3::hash(entropy.as_bytes());
    let mut word = [0u8; 8];
    word.copy_from_slice(&hash.as_bytes()[..8]);
    NodeId(u64::from_le_bytes(word) | 1 << 63)
}

fn live(error: LiveError) -> Error {
    live_refused(error)
}

/// The docedit refusal as the engine error, kept whole: its class, its
/// message and the live nodes it names.
pub(crate) fn live_refused(error: LiveError) -> Error {
    let refusal = match &error {
        LiveError::Deck(_) => LiveDeckRefusal::Deck,
        LiveError::Package(_) => LiveDeckRefusal::Package,
        LiveError::Edit(_) | LiveError::Native(_) => LiveDeckRefusal::Edit,
        LiveError::Invalid(_) => LiveDeckRefusal::Invalid,
        LiveError::UnknownNode => LiveDeckRefusal::UnknownNode,
        LiveError::TreeShape(_) => LiveDeckRefusal::TreeShape,
        LiveError::SelfSettle => LiveDeckRefusal::SelfSettle,
        LiveError::HeadAdvanced => LiveDeckRefusal::HeadAdvanced,
        LiveError::UnboundNodes(_) => LiveDeckRefusal::UnboundNodes,
        LiveError::Encoding(_) => LiveDeckRefusal::Encoding,
    };
    let nodes = match &error {
        LiveError::UnboundNodes(nodes) => nodes.iter().map(|node| node.0).collect(),
        _ => Vec::new(),
    };
    Error::Artifact(ArtifactError::LiveDeckRefused {
        refusal,
        detail: error.to_string(),
        nodes,
    })
}
