//! The PPTX body: the OF-510 live deck (`oneiron_docedit::live`) kept in this
//! module's tables (ARCH-0077, "Multiplayer: the target body shape").
//!
//! A deck/shape tree with model node ids kept apart from native ids, one
//! rich-text body per text shape, and a log in which every operation names its
//! actor, from which the attribution index rebuilds. Unlike the DOCX and XLSX
//! bodies the deck is not a CRDT: operations apply in order on one head, so a
//! person's call names the head it read. Machine work goes through a
//! `DeckFork`, reviewed by the merge preflight and landed by someone other than
//! its proposer. Until the deck export gate opens for its profile, blob
//! versions stay authoritative: an export is a proposal artifact, not a version.
//! Once it opens, [`Vault::land_pptx_export`] lands the bytes as the next blob
//! version and rebinds the deck to them, and later exports project over them.
//!
//! Every creation names its node identity before it is logged, so a fork's
//! operations replay onto the head as the same nodes.

use super::{
    COMMITS, DOCS, FORKS, ForkState, OfficeBodyEdit, OfficeBodyFork, OfficeBodyHead,
    OfficeBodyKind, bounded_ops, check_made_by, invalid, source,
};
use crate::Vault;
use crate::blob_artifact::{BlobArtifactVersion, BlobVersionProvenance};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::provenance::made_by::MadeBy;
use crate::provenance::text_commit::TextCommitReceipt;
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;
use heed::{RoTxn, RwTxn};
use oneiron_docedit::live::{
    ApproveScope, AttributionIndex, DeckFork, DeckOp, ExportOutcome, ExportProfile, Gate, Landing,
    LandingReceipt, LiveDeck, LiveError, NodeId, PreflightReport, StampedOp, attach_evidence, land,
    preflight, project,
};
use oneiron_docedit::retained_opc::{Limits, Package};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// The stored body: the deck at its head, the operations that made it, the
/// frontier it was imported at and its commit count.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct DeckState {
    deck: LiveDeck,
    log: Vec<StampedOp>,
    import_frontier: Vec<u8>,
    commits: u64,
    /// The blob version a landed export bound the deck to; `None` while it
    /// is bound to the imported source.
    retained: Option<Retained>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct Retained {
    version: u64,
    hash: [u8; 32],
}

/// A typed read of the deck body at its head.
#[derive(Debug, Clone)]
pub struct PptxBody {
    pub deck: LiveDeck,
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

impl DeckState {
    pub(super) fn import(bytes: &[u8], limits: Limits) -> Result<Self> {
        let package = Package::open(bytes, limits)
            .map_err(|_| invalid("the PPTX package could not be read"))?;
        let mut state = Self {
            deck: LiveDeck::import(&package).map_err(live)?,
            log: Vec::new(),
            import_frontier: Vec::new(),
            commits: 0,
            retained: None,
        };
        state.import_frontier = state.frontier();
        Ok(state)
    }

    pub(super) fn load(store: &Store, txn: &RoTxn<'_>, artifact: &EntityId) -> Result<Self> {
        let bytes = DOCS
            .get(store, txn, artifact)?
            .ok_or(Error::CorruptedIndex("office body document missing"))?;
        serde_json::from_slice(&bytes).map_err(|_| Error::CorruptedIndex("office body deck"))
    }

    /// The import frontier, the head frontier and the commit count.
    pub(super) fn head(&self) -> (Vec<u8>, Vec<u8>, u64) {
        (self.import_frontier.clone(), self.frontier(), self.commits)
    }

    /// The head's identity: its version and state hash.
    fn frontier(&self) -> Vec<u8> {
        let mut out = self.deck.version.to_be_bytes().to_vec();
        out.extend_from_slice(&self.deck.state_hash());
        out
    }

    /// Apply one call's operations stamped with `actor`, in order; returns the
    /// node ids the call minted.
    fn apply(&mut self, actor: &str, at: u64, ops: &[DeckOp]) -> Result<Vec<String>> {
        let before: BTreeSet<NodeId> = self.deck.nodes.keys().copied().collect();
        for op in ops {
            let stamped = StampedOp {
                made_by: actor.to_owned(),
                at,
                op: op.clone(),
            };
            self.deck.apply(&stamped).map_err(live)?;
            self.log.push(stamped);
        }
        Ok(self
            .deck
            .nodes
            .keys()
            .filter(|id| !before.contains(id))
            .map(|id| id.0.to_string())
            .collect())
    }
}

impl Vault {
    /// The deck body at its head, with who made each visible thing.
    pub fn read_pptx_body(&self, artifact: &EntityId) -> Result<PptxBody> {
        let txn = self.store.env.read_txn()?;
        let state = load_deck(&self.store, &txn, artifact)?;
        Ok(PptxBody {
            attribution: AttributionIndex::build(&state.deck, &state.log),
            frontier: state.frontier(),
            deck: state.deck,
        })
    }

    /// A person's operations on the live deck, applied in order on the head the
    /// caller read and each stamped with the actor. Machine work goes through a
    /// fork.
    pub fn edit_pptx_body(
        &self,
        artifact: &EntityId,
        expected_head: &[u8],
        ops: &[DeckOp],
        actor: WriteActor,
        made_by: &MadeBy,
    ) -> Result<OfficeBodyEdit> {
        if actor.actor_class() != EdgeActorClass::Human {
            return Err(invalid("machine work edits a fork, not the live body"));
        }
        bounded_ops(ops.len())?;
        check_made_by(actor, made_by)?;
        let ops = self.name_creations(ops)?;
        self.with_write_txn_grouped(|wtxn| {
            let mut state = load_deck(&self.store, wtxn, artifact)?;
            if state.frontier() != expected_head {
                return Err(invalid("the deck moved since it was read; read it again"));
            }
            let start = state.log.len();
            let minted = state.apply(&actor.entity_ref().to_hex(), made_by.at, &ops)?;
            let receipt = log_receipt(*artifact, start, state.log.len(), made_by)?;
            let mut commits = state.commits;
            self.record_commit(wtxn, artifact, &mut commits, &receipt)?;
            state.commits = commits;
            store_deck(&self.store, wtxn, artifact, &state)?;
            Ok(OfficeBodyEdit {
                frontier: state.frontier(),
                minted,
                receipt,
            })
        })
    }

    /// The opener's operations on its open deck fork. Each must apply to the
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
        self.with_write_txn_grouped(|wtxn| {
            let key = (*artifact, *fork);
            let mut record = FORKS
                .get(&self.store, wtxn, &key)?
                .ok_or(Error::EntityNotFound)?;
            if record.state != ForkState::Open || record.opener != actor.entity_ref() {
                return Err(invalid("only the opener writes to its open fork"));
            }
            let mut work = load_fork(&self.store, wtxn, fork)?;
            let mut proposal = DeckState {
                deck: work.candidate().map_err(live)?,
                log: Vec::new(),
                import_frontier: Vec::new(),
                commits: 0,
                retained: None,
            };
            let start = work.ops.len();
            let minted = proposal.apply(&actor.entity_ref().to_hex(), made_by.at, &ops)?;
            let frontier = proposal.frontier();
            work.ops.extend(proposal.log);
            let receipt = log_receipt(*artifact, start, work.ops.len(), made_by)?;
            store_fork(&self.store, wtxn, fork, &work)?;
            self.record_commit(wtxn, fork, &mut record.commits, &receipt)?;
            FORKS.put(&self.store, wtxn, &key, &record)?;
            Ok(OfficeBodyEdit {
                frontier,
                minted,
                receipt,
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
        let head = self
            .office_body_head(artifact)?
            .ok_or(Error::EntityNotFound)?;
        let (state, work) = {
            let txn = self.store.env.read_txn()?;
            let state = load_deck(&self.store, &txn, artifact)?;
            open_record(&self.store, &txn, artifact, fork)?;
            (state, load_fork(&self.store, &txn, fork)?)
        };
        let mut report = preflight(&state.deck, &work).map_err(live)?;
        let package = Package::open(
            &self.deck_source(artifact, &head, &state)?,
            self.docedit_package_limits()?,
        )
        .map_err(|_| invalid("the PPTX package could not be read"))?;
        let evidence_refusal = attach_evidence(
            &mut report,
            &state.deck,
            &package,
            &artifact.to_hex(),
            &ExportProfile::default(),
        )
        .err()
        .map(|error| error.to_string());
        Ok(PptxReview {
            report,
            stale_units: work.stale_units(&state.deck),
            head: state.frontier(),
            evidence_refusal,
        })
    }

    /// Land a reviewed deck fork. The settler names the head it reviewed; a moved
    /// head, an unresolved conflict, the opener as settler or a scope that does
    /// not cover the fork refuses. The fork's operations join the body's log and
    /// its receipts the body's, so attribution survives the landing.
    pub fn merge_pptx_body_fork(
        &self,
        artifact: &EntityId,
        fork: &EntityId,
        expected_head: &[u8],
        actor: WriteActor,
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
            let mut state = load_deck(&self.store, wtxn, artifact)?;
            if state.frontier() != expected_head {
                return Err(invalid("the deck moved since the review; review it again"));
            }
            let work = load_fork(&self.store, wtxn, fork)?;
            let report = preflight(&state.deck, &work).map_err(live)?;
            let receipt = land(
                &mut state.deck,
                &work,
                &report,
                &actor.entity_ref().to_hex(),
                scope,
                landing,
                false,
            )
            .map_err(live)?;
            state.log.extend(work.ops.iter().cloned());
            let mut commits = state.commits;
            for (_, commit) in COMMITS.scan_from(&self.store, wtxn, fork.as_bytes())? {
                self.record_commit(wtxn, artifact, &mut commits, &commit)?;
            }
            state.commits = commits;
            store_deck(&self.store, wtxn, artifact, &state)?;
            record.state = ForkState::Merged {
                by: actor.entity_ref(),
                at,
                head: state.frontier(),
            };
            FORKS.put(&self.store, wtxn, &key, &record)?;
            DOCS.delete(&self.store, wtxn, fork)?;
            Ok(receipt)
        })
    }

    /// Project the deck at its head over its retained package (the imported
    /// source, or the version the last landed export made). Until the
    /// profile's export gate opens the result is a proposal artifact: nothing
    /// lands, and the caller proposes the bytes through the edit rails.
    pub fn export_pptx_body(&self, artifact: &EntityId) -> Result<PptxExport> {
        let head = self
            .office_body_head(artifact)?
            .ok_or(Error::EntityNotFound)?;
        let state = {
            let txn = self.store.env.read_txn()?;
            load_deck(&self.store, &txn, artifact)?
        };
        let profile = ExportProfile::default();
        let package = Package::open(
            &self.deck_source(artifact, &head, &state)?,
            self.docedit_package_limits()?,
        )
        .map_err(|_| invalid("the PPTX package could not be read"))?;
        let outcome = project(&state.deck, &package, &artifact.to_hex(), &profile).map_err(live)?;
        Ok(PptxExport {
            frontier: state.frontier(),
            authoritative: Gate::closed(&profile.name).is_open(),
            outcome,
        })
    }

    /// Land an authoritative export: its bytes become the artifact's next blob
    /// version, the deck rebinds to them (the same node identities, the
    /// exported native ids and fingerprints, the joined allocation history),
    /// and the next export projects over them. A proposal export, or a head
    /// that moved since the export, refuses.
    pub fn land_pptx_export(
        &self,
        artifact: &EntityId,
        export: &PptxExport,
        actor: WriteActor,
        provenance: &BlobVersionProvenance,
    ) -> Result<BlobArtifactVersion> {
        if !export.authoritative {
            return Err(invalid(
                "the deck export gate is closed for its profile; the export is a proposal",
            ));
        }
        let at = self.now_recorded_at();
        self.with_write_txn_grouped(|wtxn| {
            let mut state = load_deck(&self.store, wtxn, artifact)?;
            if state.frontier() != export.frontier {
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
            state.deck.rebind(&export.outcome).map_err(live)?;
            state.retained = Some(Retained {
                version: version.version,
                hash: *blake3::hash(&export.outcome.bytes).as_bytes(),
            });
            store_deck(&self.store, wtxn, artifact, &state)?;
            Ok(version)
        })
    }

    /// The package the deck is bound to, checked against its recorded hash.
    fn deck_source(
        &self,
        artifact: &EntityId,
        head: &OfficeBodyHead,
        state: &DeckState,
    ) -> Result<Vec<u8>> {
        let Some(retained) = state.retained else {
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

    /// Store an imported deck as the artifact's body; the import is an empty
    /// span of the operation log, since imported content has unknown authorship.
    pub(super) fn birth_deck(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact: &EntityId,
        mut state: DeckState,
        made_by: &MadeBy,
    ) -> Result<()> {
        let receipt = log_receipt(*artifact, 0, 0, made_by)?;
        self.record_commit(wtxn, artifact, &mut state.commits, &receipt)?;
        store_deck(&self.store, wtxn, artifact, &state)
    }

    /// Open a deck fork at the live head for `actor`'s machine work.
    pub(super) fn open_deck_fork(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact: &EntityId,
        actor: WriteActor,
    ) -> Result<OfficeBodyFork> {
        let state = load_deck(&self.store, wtxn, artifact)?;
        let fork = OfficeBodyFork {
            id: self.new_entity_id()?,
            artifact: *artifact,
            opener: actor.entity_ref(),
            base: state.frontier(),
            commits: 0,
            opened_at: self.now_recorded_at(),
            state: ForkState::Open,
        };
        let work = state
            .deck
            .fork_at(&fork.id.to_hex(), &fork.opener.to_hex(), None);
        store_fork(&self.store, wtxn, &fork.id, &work)?;
        FORKS.put(&self.store, wtxn, &(*artifact, fork.id), &fork)?;
        Ok(fork)
    }

    pub(super) fn discard_deck_fork(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact: &EntityId,
        fork: &EntityId,
        actor: WriteActor,
    ) -> Result<()> {
        let mut record = open_record(&self.store, wtxn, artifact, fork)?;
        record.state = ForkState::Discarded {
            by: actor.entity_ref(),
            at: self.now_recorded_at(),
        };
        FORKS.put(&self.store, wtxn, &(*artifact, *fork), &record)?;
        DOCS.delete(&self.store, wtxn, fork)?;
        Ok(())
    }
}

/// The artifact's deck body; another format refuses.
fn load_deck(store: &Store, txn: &RoTxn<'_>, artifact: &EntityId) -> Result<DeckState> {
    if source(store, txn, artifact)?.kind != OfficeBodyKind::Pptx {
        return Err(invalid("the artifact's live body is another format"));
    }
    DeckState::load(store, txn, artifact)
}

fn store_deck(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    artifact: &EntityId,
    state: &DeckState,
) -> Result<()> {
    let bytes = serde_json::to_vec(state).map_err(|_| invalid("deck body encoding"))?;
    DOCS.put(store, wtxn, artifact, &bytes)
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

fn load_fork(store: &Store, txn: &RoTxn<'_>, fork: &EntityId) -> Result<DeckFork> {
    let bytes = DOCS
        .get(store, txn, fork)?
        .ok_or(Error::CorruptedIndex("office body fork missing"))?;
    serde_json::from_slice(&bytes).map_err(|_| Error::CorruptedIndex("office body deck fork"))
}

fn store_fork(store: &Store, wtxn: &mut RwTxn<'_>, fork: &EntityId, work: &DeckFork) -> Result<()> {
    let bytes = serde_json::to_vec(work).map_err(|_| invalid("deck fork encoding"))?;
    DOCS.put(store, wtxn, fork, &bytes)
}

/// A deck call's receipt: its span of the operation log (peer 0, which no Loro
/// peer takes).
fn log_receipt(
    document: EntityId,
    start: usize,
    end: usize,
    made_by: &MadeBy,
) -> Result<TextCommitReceipt> {
    let span = |at: usize| i32::try_from(at).map_err(|_| invalid("the deck log is too long"));
    Ok(TextCommitReceipt {
        document,
        peer: 0,
        start: span(start)?,
        end: span(end)?,
        made_by: made_by.clone(),
    })
}

/// A node identity drawn from fresh entity entropy, top bit set.
fn fresh_node(entropy: &EntityId) -> NodeId {
    let hash = blake3::hash(entropy.as_bytes());
    let mut word = [0u8; 8];
    word.copy_from_slice(&hash.as_bytes()[..8]);
    NodeId(u64::from_le_bytes(word) | 1 << 63)
}

fn live(error: LiveError) -> Error {
    invalid(&format!("live deck: {error}"))
}
