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

use super::{
    COMMITS, DOCS, FORKS, ForkState, HEADS, OfficeBodyEdit, OfficeBodyFork, OfficeBodyHead,
    OfficeBodyKind, bounded_ops, check_made_by, invalid,
};
use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::provenance::made_by::MadeBy;
use crate::provenance::text_commit::TextCommitReceipt;
use crate::write_envelope::WriteActor;
use heed::{RoTxn, RwTxn};
use oneiron_docedit::live::{
    ApproveScope, AttributionIndex, DeckFork, DeckOp, ExportOutcome, ExportProfile, Gate,
    Landing, LandingReceipt, LiveDeck, LiveError, NodeId, PreflightReport, StampedOp, land,
    preflight, project,
};
use oneiron_docedit::retained_opc::{Limits, Package};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub(super) const SCHEMA: u32 = 1;

/// The stored body: the deck at its head and the operations that made it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct DeckState {
    deck: LiveDeck,
    log: Vec<StampedOp>,
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
        Ok(Self {
            deck: LiveDeck::import(&package).map_err(live)?,
            log: Vec::new(),
        })
    }

    /// The head's identity: its version and state hash.
    pub(super) fn frontier(&self) -> Vec<u8> {
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

    pub(super) fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| invalid("deck body encoding"))
    }
}

impl Vault {
    /// The deck body at its head, with who made each visible thing.
    pub fn read_pptx_body(&self, artifact: &EntityId) -> Result<PptxBody> {
        let txn = self.store.env.read_txn()?;
        let head = deck_head(self, &txn, artifact)?;
        let state = self.load_deck(&txn, artifact, &head)?;
        Ok(PptxBody {
            attribution: AttributionIndex::build(&state.deck, &state.log),
            frontier: head.frontier,
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
        self.with_write_txn_grouped(|wtxn| {
            let mut head = deck_head(self, wtxn, artifact)?;
            if head.frontier != expected_head {
                return Err(invalid("the deck moved since it was read; read it again"));
            }
            let mut state = self.load_deck(wtxn, artifact, &head)?;
            let start = state.log.len();
            let minted = state.apply(&actor.entity_ref().to_hex(), made_by.at, ops)?;
            let receipt = log_receipt(*artifact, start, state.log.len(), made_by)?;
            head.frontier = self.store_deck(wtxn, artifact, &state)?;
            self.record_commit(wtxn, artifact, &mut head.commits, &receipt)?;
            HEADS.put(&self.store, wtxn, artifact, &head)?;
            Ok(OfficeBodyEdit {
                frontier: head.frontier.clone(),
                minted,
                receipt,
            })
        })
    }

    /// The opener's operations on its open deck fork. Each must apply to the
    /// fork's proposal state.
    pub fn edit_pptx_body_fork(
        &self,
        fork: &EntityId,
        ops: &[DeckOp],
        actor: WriteActor,
        made_by: &MadeBy,
    ) -> Result<OfficeBodyEdit> {
        bounded_ops(ops.len())?;
        check_made_by(actor, made_by)?;
        self.with_write_txn_grouped(|wtxn| {
            let mut record = FORKS
                .get(&self.store, wtxn, fork)?
                .ok_or(Error::EntityNotFound)?;
            if record.state != ForkState::Open || record.opener != actor.entity_ref() {
                return Err(invalid("only the opener writes to its open fork"));
            }
            deck_head(self, wtxn, &record.artifact)?;
            let mut work = load_fork(self, wtxn, fork)?;
            let mut proposal = DeckState {
                deck: work.candidate().map_err(live)?,
                log: Vec::new(),
            };
            let start = work.ops.len();
            let minted = proposal.apply(&actor.entity_ref().to_hex(), made_by.at, ops)?;
            let frontier = proposal.frontier();
            work.ops.extend(proposal.log);
            let receipt = log_receipt(record.artifact, start, work.ops.len(), made_by)?;
            store_fork(self, wtxn, fork, &work)?;
            self.record_commit(wtxn, fork, &mut record.commits, &receipt)?;
            FORKS.put(&self.store, wtxn, fork, &record)?;
            Ok(OfficeBodyEdit {
                frontier,
                minted,
                receipt,
            })
        })
    }

    /// The deck fork's merge preflight against the live head: the three-way
    /// diff with its named conflicts, the replay onto the head, and the stale
    /// units.
    pub fn pptx_body_fork_review(&self, fork: &EntityId) -> Result<PptxReview> {
        let txn = self.store.env.read_txn()?;
        let record = FORKS
            .get(&self.store, &txn, fork)?
            .ok_or(Error::EntityNotFound)?;
        let head = deck_head(self, &txn, &record.artifact)?;
        let state = self.load_deck(&txn, &record.artifact, &head)?;
        let work = load_fork(self, &txn, fork)?;
        Ok(PptxReview {
            report: preflight(&state.deck, &work).map_err(live)?,
            stale_units: work.stale_units(&state.deck),
            head: head.frontier,
        })
    }

    /// Land a reviewed deck fork. The settler names the head it reviewed; a moved
    /// head, an unresolved conflict, the opener as settler or a scope that does
    /// not cover the fork refuses. The fork's operations join the body's log and
    /// its receipts the body's, so attribution survives the landing.
    pub fn merge_pptx_body_fork(
        &self,
        fork: &EntityId,
        expected_head: &[u8],
        actor: WriteActor,
        scope: ApproveScope,
        landing: Landing,
    ) -> Result<LandingReceipt> {
        let at = self.now_recorded_at();
        self.with_write_txn_grouped(|wtxn| {
            let mut record = FORKS
                .get(&self.store, wtxn, fork)?
                .ok_or(Error::EntityNotFound)?;
            if record.state != ForkState::Open {
                return Err(invalid("the fork is not open"));
            }
            // "The opener's lineage and its forks never settle their own proposal."
            if record.opener == actor.entity_ref() {
                return Err(invalid("a fork's opener cannot merge it"));
            }
            let mut head = deck_head(self, wtxn, &record.artifact)?;
            if head.frontier != expected_head {
                return Err(invalid("the deck moved since the review; review it again"));
            }
            let mut state = self.load_deck(wtxn, &record.artifact, &head)?;
            let work = load_fork(self, wtxn, fork)?;
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
            head.frontier = self.store_deck(wtxn, &record.artifact, &state)?;
            for (_, commit) in COMMITS.scan_from(&self.store, wtxn, fork.as_bytes())? {
                self.record_commit(wtxn, &record.artifact, &mut head.commits, &commit)?;
            }
            HEADS.put(&self.store, wtxn, &record.artifact, &head)?;
            record.state = ForkState::Merged {
                by: actor.entity_ref(),
                at,
                head: head.frontier.clone(),
            };
            FORKS.put(&self.store, wtxn, fork, &record)?;
            DOCS.delete(&self.store, wtxn, fork)?;
            Ok(receipt)
        })
    }

    /// Project the deck at its head over the imported package. Until the
    /// profile's export gate opens the result is a proposal artifact: nothing
    /// lands, and the caller proposes the bytes through the edit rails.
    pub fn export_pptx_body(&self, artifact: &EntityId) -> Result<PptxExport> {
        let (head, state) = {
            let txn = self.store.env.read_txn()?;
            let head = deck_head(self, &txn, artifact)?;
            let state = self.load_deck(&txn, artifact, &head)?;
            (head, state)
        };
        let profile = ExportProfile::default();
        let package = Package::open(&self.body_source(artifact, &head)?, self.docedit_package_limits()?)
            .map_err(|_| invalid("the PPTX package could not be read"))?;
        let outcome = project(&state.deck, &package, &artifact.to_hex(), &profile).map_err(live)?;
        Ok(PptxExport {
            frontier: head.frontier,
            authoritative: Gate::closed(&profile.name).is_open(),
            outcome,
        })
    }

    /// Open a deck fork at the live head; [`Vault::open_office_body_fork`]
    /// routes a PPTX body here.
    pub(super) fn open_deck_fork(
        &self,
        wtxn: &mut RwTxn<'_>,
        head: &OfficeBodyHead,
        fork: &OfficeBodyFork,
    ) -> Result<()> {
        let state = self.load_deck(wtxn, &head.artifact, head)?;
        let work = state
            .deck
            .fork_at(&fork.id.to_hex(), &fork.opener.to_hex(), None);
        store_fork(self, wtxn, &fork.id, &work)
    }

    fn store_deck(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact: &EntityId,
        state: &DeckState,
    ) -> Result<Vec<u8>> {
        DOCS.put(&self.store, wtxn, artifact, &state.encode()?)?;
        Ok(state.frontier())
    }

    fn load_deck(
        &self,
        txn: &RoTxn<'_>,
        artifact: &EntityId,
        head: &OfficeBodyHead,
    ) -> Result<DeckState> {
        let bytes = DOCS
            .get(&self.store, txn, artifact)?
            .ok_or(Error::CorruptedIndex("office body document missing"))?;
        let state: DeckState = serde_json::from_slice(&bytes)
            .map_err(|_| Error::CorruptedIndex("office body deck"))?;
        if state.frontier() != head.frontier {
            return Err(Error::CorruptedIndex("office body frontier"));
        }
        Ok(state)
    }
}

fn deck_head(vault: &Vault, txn: &RoTxn<'_>, artifact: &EntityId) -> Result<OfficeBodyHead> {
    let head = HEADS
        .get(&vault.store, txn, artifact)?
        .ok_or(Error::EntityNotFound)?;
    if head.kind != OfficeBodyKind::Pptx {
        return Err(invalid("the artifact's live body is another format"));
    }
    Ok(head)
}

fn load_fork(vault: &Vault, txn: &RoTxn<'_>, fork: &EntityId) -> Result<DeckFork> {
    let bytes = DOCS
        .get(&vault.store, txn, fork)?
        .ok_or(Error::CorruptedIndex("office body fork missing"))?;
    serde_json::from_slice(&bytes).map_err(|_| Error::CorruptedIndex("office body deck fork"))
}

fn store_fork(vault: &Vault, wtxn: &mut RwTxn<'_>, fork: &EntityId, work: &DeckFork) -> Result<()> {
    let bytes = serde_json::to_vec(work).map_err(|_| invalid("deck fork encoding"))?;
    DOCS.put(&vault.store, wtxn, fork, &bytes)
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

fn live(error: LiveError) -> Error {
    invalid(&format!("live deck: {error}"))
}
