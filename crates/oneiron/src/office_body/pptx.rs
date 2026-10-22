//! The PPTX body: the OF-510 live deck (`oneiron_docedit::live`) as a Loro
//! document on the typed-body door, schema `office.pptx.v1` (ARCH-0077,
//! "Multiplayer: the target body shape"; its layout is in [`doc`]).
//!
//! A deck/shape tree with model node ids kept apart from native ids and from
//! the Loro handles, one rich-text body per text shape, and a log in which
//! every operation names its commit peer, whose receipt names its actor, from
//! which the attribution index rebuilds ([`log`]).
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
//! all eight steps passed on a clean opening, from a run of the current
//! projector: the receipt names its run's projector, source revision and
//! case manifest, and is that run's evidence.
//! Once it opens, [`Vault::land_pptx_export`] lands the bytes as the next blob
//! version, records the frontier it projects, and rebinds the deck to them,
//! and later exports project over them.
//!
//! Every creation names its node identity before it is logged, and so does
//! every row or column a table edit inserts and every series a chart write
//! or chart edit adds, so a fork's operations replay onto the head as the
//! same nodes, rows, columns and series; a whole table written over a table
//! is logged as the table edits that make it, and a whole chart written
//! over a chart as the chart edits that make it. The per-call operation
//! count is the caller's: a lowered write stays one operation. A fork's
//! review, preview and landing read its actual merged candidate ([`merge`]).

mod doc;
mod export;
mod log;
mod merge;
mod peers;
mod preview;
mod verbs;

pub(crate) use doc::deck_log_ops;
pub(super) use doc::{birth, validate};
pub use peers::merge_deck_peers;
pub use preview::{DeckPreview, DeckPreviewRequest, DeckPreviewSlide};
pub use verbs::{
    DeckBodyView, DeckExportRequest, DeckExportView, DeckForkMergeRequest, DeckGateRequest,
    DeckGateView, DeckNodeView, DeckOracleRequest, DeckReviewView,
};

use super::{
    FORKS, ForkState, OfficeBodyEdit, OfficeBodyFork, OfficeBodyHead, OfficeBodyKind, bounded_ops,
    check_made_by, invalid, writer,
};
use crate::Vault;
use crate::edit_roundtrip::VaultAssets;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, LiveDeckRefusal, Result};
use crate::provenance::made_by::MadeBy;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::typed_body::reviewed_fork::{ReviewedLanding, merge_reviewed_fork_in_txn};
use crate::typed_body::{
    BodyActor, TypedBodyHead, discard_typed_body_fork_in_txn, edit_typed_body_fork_in_txn,
    edit_typed_body_in_txn, open_typed_body_fork_in_txn,
};
use crate::write_envelope::WriteActor;
use heed::{RoTxn, RwTxn};
use loro::LoroDoc;
use oneiron_docedit::live::deck_export::PROJECTOR_VERSION;
use oneiron_docedit::live::{
    ApproveScope, AttributionIndex, DeckFork, DeckOp, ExportOutcome, ExportProfile, Gate,
    HeldAssets, Landing, LandingReceipt, LiveDeck, LiveError, NodeId, OracleReceipt,
    PreflightReport, StampedOp, attach_evidence, check_picture, effect_receipt, land,
};
use oneiron_docedit::retained_opc::{Limits, Package};
use serde::{Deserialize, Serialize};

/// The deck oracle's latest receipt per export profile, by profile name.
pub(super) const ORACLE: SideTable<String, OracleRecord, Named> =
    SideTable::new(&side_table::OFFICE_BODY_ORACLE);

/// The longest export profile name a receipt may carry.
const MAX_PROFILE_LEN: usize = 128;

/// One profile's oracle receipt as recorded: the eight-step check's outcome
/// and the run it checked, as the receipt names it (FIX 3772); a receipt
/// from another projector's run opens nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct OracleRecord {
    receipt: OracleReceipt,
    /// No one once that actor was erased (FIX 4511).
    pub(super) recorded_by: BodyActor,
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
    /// The fork's frontier this review read; a landing applies the fork up
    /// to it, beside `head` (FIX 9992).
    pub fork_head: Vec<u8>,
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
    /// The version the deck projected over, and its BLAKE3: its last landed
    /// export, else the imported source. A version landing outside the deck
    /// since leaves the export forked from it (FIX 2700).
    pub base_version: u64,
    pub base_hash: [u8; 32],
}

/// The imported deck a body is born with.
pub(super) fn import_deck(bytes: &[u8], limits: Limits) -> Result<LiveDeck> {
    let package = Package::open(bytes, limits, &crate::office_body::document_resources()).map_err(
        |error| super::document_error(error.resource(), "the PPTX package could not be read"),
    )?;
    LiveDeck::import(&package).map_err(live)
}

/// [`Vault::read_pptx_body`] of `doc`, `artifact`'s deck body at `frontier`,
/// read in `txn`: a read that holds its document projects it in the
/// snapshot it reads its lifted keys in (FIX 2939).
pub(super) fn body_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    artifact: &EntityId,
    doc: &LoroDoc,
    frontier: Vec<u8>,
) -> Result<PptxBody> {
    let body = doc::read(doc)?;
    let log = log::stamped(store, txn, artifact, &body.log)?;
    Ok(PptxBody {
        attribution: AttributionIndex::build(&body.deck, &log),
        frontier,
        deck: body.deck,
        log,
    })
}

impl Vault {
    /// The deck body at its head, or at an earlier frontier `at` of its
    /// history, with who made each visible thing.
    pub fn read_pptx_body(&self, artifact: &EntityId, at: Option<&[u8]>) -> Result<PptxBody> {
        let txn = self.store.env.read_txn()?;
        let (head, doc) = self.loro_body(&txn, artifact, OfficeBodyKind::Pptx, at)?;
        let frontier = at.map_or(head.frontier, <[u8]>::to_vec);
        body_in_txn(&self.store, &txn, artifact, &doc, frontier)
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
        self.check_pictures(ops)?;
        let mut fresh = Fresh::new(self.new_entity_id()?);
        let ops = name_creations(ops, &mut fresh);
        let maker = actor.entity_ref().to_hex();
        // What the operations did PowerPoint's way, for the receipt.
        let mut effects = Vec::new();
        let mut edit = self.edit_live(
            artifact,
            OfficeBodyKind::Pptx,
            base,
            (actor, made_by),
            |base, head| doc::admit(base, head, &ops),
            |doc| {
                let mut body = doc::read(doc)?;
                let stamped = apply_ops(
                    &mut body.deck,
                    &ops,
                    (&maker, made_by.at),
                    &mut fresh,
                    &mut effects,
                )?;
                doc::sync_to(doc, &body.deck)?;
                doc::append_log(doc, &log::logged(doc, &stamped))?;
                Ok(ops
                    .iter()
                    .filter_map(DeckOp::created)
                    .map(|id| id.0.to_string())
                    .collect())
            },
        )?;
        edit.effects = effects;
        Ok(edit)
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
        self.check_pictures(ops)?;
        let mut fresh = Fresh::new(self.new_entity_id()?);
        let ops = name_creations(ops, &mut fresh);
        let maker = actor.entity_ref().to_hex();
        self.with_write_txn_grouped(|wtxn| {
            let key = (*artifact, *fork);
            let mut record = open_record(&self.store, wtxn, artifact, fork)?;
            if !record.opener.is(actor.entity_ref()) {
                return Err(invalid("only the opener writes to its open fork"));
            }
            let writer = writer(OfficeBodyKind::Pptx, actor, made_by);
            let mut effects = Vec::new();
            let (_, commit) =
                edit_typed_body_fork_in_txn(self, wtxn, artifact, fork, writer, |doc| {
                    let mut body = doc::read(doc)?;
                    let stamped = apply_ops(
                        &mut body.deck,
                        &ops,
                        (&maker, made_by.at),
                        &mut fresh,
                        &mut effects,
                    )?;
                    doc::sync_to(doc, &body.deck)?;
                    doc::append_log(doc, &log::logged(doc, &stamped))
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
                effects,
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
        let ((head, body), fork_head, work, mut report, assets) = {
            let txn = self.store.env.read_txn()?;
            let (head, body) = self.deck_head(&txn, artifact)?;
            let record = open_record(&self.store, &txn, artifact, fork)?;
            // One read of the fork's document: its frontier, work and candidate.
            let (base, proposal) = self.deck_fork_doc(&txn, &record)?;
            let fork_head = proposal.oplog_frontiers().encode();
            let (work, report) =
                self.deck_preflight_of(&txn, artifact, &body.deck, &record, (&base, &proposal))?;
            let assets = HeldAssets::resolve(
                &VaultAssets {
                    vault: self,
                    txn: &txn,
                },
                &[&body.deck, &report.candidate],
            );
            ((head, body), fork_head, work, report, assets)
        };
        let package = Package::open(
            &self.deck_source(artifact, &source, body.retained)?,
            self.docedit_package_limits()?,
            &crate::office_body::document_resources(),
        )
        .map_err(|error| {
            super::document_error(error.resource(), "the PPTX package could not be read")
        })?;
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
            fork_head,
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
        (expected_head, reviewed_fork): (&[u8], &[u8]),
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
            if record.opener.is(actor.entity_ref()) {
                return Err(invalid("a fork's opener cannot merge it"));
            }
            let (head, mut body) = self.deck_head(wtxn, artifact)?;
            if head.frontier != expected_head {
                return Err(invalid("the deck moved since the review; review it again"));
            }
            // The fork as reviewed, never as it stands now (FIX 9992).
            let (base, proposal) = self.reviewed_fork_doc(wtxn, &record, reviewed_fork)?;
            let (work, report) =
                self.deck_preflight_of(wtxn, artifact, &body.deck, &record, (&base, &proposal))?;
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
            let merged = merge_reviewed_fork_in_txn(
                self,
                wtxn,
                artifact,
                fork,
                &head.frontier,
                reviewed_fork,
                actor,
            )?;
            let (merged, rest) = match merged {
                ReviewedLanding::Whole(head) => (head, None),
                ReviewedLanding::Prefix {
                    head,
                    base,
                    commits,
                } => (head, Some((base, commits))),
            };
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
            match rest {
                // Work appended after the review stays open for the next one.
                Some((base, commits)) => {
                    record.base = base;
                    record.commits = commits;
                }
                None => {
                    record.state = ForkState::Merged {
                        by: BodyActor::Actor(actor.entity_ref()),
                        at,
                        head: frontier,
                    };
                }
            }
            FORKS.put(&self.store, wtxn, &key, &record)?;
            Ok(receipt)
        })
    }

    /// Record the deck oracle's receipt for its profile, as the evidence of
    /// the run it names: its projector, source revision and case manifest
    /// hash are checked for form and kept as given, never stamped with this
    /// server's projector, so a receipt from another projector's run opens
    /// nothing here. It replaces the profile's earlier receipt, so a later
    /// failed run, or a run of another projector, closes the gate a pass
    /// opened.
    pub fn record_pptx_oracle_receipt(
        &self,
        receipt: &OracleReceipt,
        actor: WriteActor,
    ) -> Result<()> {
        if receipt.profile.is_empty() || receipt.profile.len() > MAX_PROFILE_LEN {
            return Err(invalid("an oracle receipt names its export profile"));
        }
        names_its_run(receipt)?;
        let record = OracleRecord {
            receipt: receipt.clone(),
            recorded_by: BodyActor::Actor(actor.entity_ref()),
            recorded_at: self.now_recorded_at(),
        };
        self.with_write_txn_grouped(|wtxn| ORACLE.put(&self.store, wtxn, &receipt.profile, &record))
    }

    /// The deck export gate for `profile`: its recorded oracle receipt, with
    /// the run it names; it opens only for a run of the current projector.
    pub fn pptx_export_gate(&self, profile: &str) -> Result<Gate> {
        let txn = self.store.env.read_txn()?;
        export_gate(&self.store, &txn, profile)
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
        self.deck_source_listing(artifact, head, retained)
            .map(|(bytes, _)| bytes)
    }

    /// [`Self::deck_source`], beside the rows the package's version is (its
    /// version CLAIM and ASSET, FIX 5455): the retained export the deck is
    /// bound to, or the imported source.
    fn deck_source_listing(
        &self,
        artifact: &EntityId,
        head: &OfficeBodyHead,
        retained: Option<doc::Retained>,
    ) -> Result<(Vec<u8>, Vec<EntityId>)> {
        let (version, hash, corrupt) = match retained {
            Some(retained) => (retained.version, retained.hash, "deck retained version"),
            None => (
                head.source_version,
                head.source_hash,
                "office body source version",
            ),
        };
        let (bytes, rows) = self
            .read_blob_artifact_version_listing(artifact, version)?
            .ok_or(Error::EntityNotFound)?;
        if *blake3::hash(&bytes).as_bytes() != hash {
            return Err(Error::CorruptedIndex(corrupt));
        }
        Ok((bytes, rows))
    }

    /// Refuse a picture an operation writes whose asset does not resolve, or
    /// whose bytes do not match its reference, when the operation is made
    /// rather than at the export that writes it.
    fn check_pictures(&self, ops: &[DeckOp]) -> Result<()> {
        if ops.iter().all(|op| op.picture().is_none()) {
            return Ok(());
        }
        let txn = self.store.env.read_txn()?;
        let assets = VaultAssets {
            vault: self,
            txn: &txn,
        };
        for image in ops.iter().filter_map(DeckOp::picture) {
            check_picture(image, &assets).map_err(live)?;
        }
        Ok(())
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
        let (base, proposal) = self.deck_fork_doc(txn, record)?;
        self.deck_fork_of(txn, record, (&base, &proposal))
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
            by: BodyActor::Actor(actor.entity_ref()),
            at: self.now_recorded_at(),
        };
        FORKS.put(&self.store, wtxn, &(*artifact, *fork), &record)?;
        Ok(())
    }
}

fn export_gate(store: &Store, txn: &RoTxn<'_>, profile: &str) -> Result<Gate> {
    let receipt = ORACLE
        .get(store, txn, &profile.to_owned())?
        .map(|record| record.receipt);
    Ok(Gate {
        profile: profile.to_owned(),
        receipt,
    })
}

/// A receipt names the run it came from (FIX 3772), as the run's manifest
/// pins it: a deck projector version (`live-deck-projector/<n>`), the full
/// commit id (40 or 64 hex digits) its engine half was built from, and its
/// case manifest's SHA-256 (64 hex digits). Any projector of the family
/// records; only the current one opens the gate ([`Gate::is_open`]).
fn names_its_run(receipt: &OracleReceipt) -> Result<()> {
    let hex = |text: &str, lengths: &[usize]| {
        lengths.contains(&text.len()) && text.bytes().all(|byte| byte.is_ascii_hexdigit())
    };
    let family = PROJECTOR_VERSION
        .rsplit_once('/')
        .map_or(PROJECTOR_VERSION, |(family, _)| family);
    let projector = receipt
        .projector
        .strip_prefix(family)
        .and_then(|rest| rest.strip_prefix('/'))
        .is_some_and(|number| !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()));
    if !projector {
        return Err(invalid(
            "an oracle receipt names the deck projector its run exported through",
        ));
    }
    if !hex(&receipt.source_sha, &[40, 64]) {
        return Err(invalid(
            "an oracle receipt names the full commit its run was built from",
        ));
    }
    if !hex(&receipt.case_manifest_sha256, &[64]) {
        return Err(invalid(
            "an oracle receipt names the SHA-256 of its run's case manifest",
        ));
    }
    Ok(())
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

/// Node identities drawn from one call's fresh entity entropy, top bit set
/// (above the import's sequential ones): each the hash of the entropy and
/// its ordinal.
struct Fresh {
    entropy: EntityId,
    next: u64,
}

impl Fresh {
    fn new(entropy: EntityId) -> Self {
        Self { entropy, next: 0 }
    }

    fn node(&mut self) -> NodeId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.entropy.as_bytes());
        hasher.update(&self.next.to_le_bytes());
        self.next += 1;
        let mut word = [0u8; 8];
        word.copy_from_slice(&hasher.finalize().as_bytes()[..8]);
        NodeId(u64::from_le_bytes(word) | 1 << 63)
    }
}

/// `ops` with every creation, every row or column a table edit inserts, and
/// every series a chart write or chart edit adds, naming a fresh identity,
/// so the log, a fork's replay onto the head and a concurrent writer all
/// make the same node, row, column or series.
fn name_creations(ops: &[DeckOp], fresh: &mut Fresh) -> Vec<DeckOp> {
    ops.iter()
        .map(|op| {
            let mut op = op.clone();
            op.name_creation(|| fresh.node());
            op
        })
        .collect()
}

/// Apply `ops` to `deck` as `maker` at `at`, each first lowered against the
/// deck it applies to ([`LiveDeck::lower`]: a whole table written over a
/// table becomes the table edits that make it, and a whole chart written
/// over a chart the chart edits that make it, their new rows, columns and
/// series named from `fresh`); what they did PowerPoint's way joins
/// `effects`. The operations as logged.
fn apply_ops(
    deck: &mut LiveDeck,
    ops: &[DeckOp],
    (maker, at): (&str, u64),
    fresh: &mut Fresh,
    effects: &mut Vec<String>,
) -> Result<Vec<StampedOp>> {
    let mut stamped = Vec::with_capacity(ops.len());
    for op in ops {
        let op = StampedOp {
            made_by: maker.to_owned(),
            at,
            op: deck.lower(op, || fresh.node()),
        };
        let (_, done) = deck.apply_with_effects(&op).map_err(live)?;
        effects.extend(done.iter().map(effect_receipt));
        stamped.push(op);
    }
    Ok(stamped)
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
        LiveError::MemoryFloor { .. } => LiveDeckRefusal::MemoryFloor,
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
