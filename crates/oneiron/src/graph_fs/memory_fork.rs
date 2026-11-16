//! The graph-FS memory fork (L3-39): a mount that reads the vault's memory
//! as it stood at a frontier the engine handed out.
//!
//! Each row reads at the revision the memory timeline names for it there,
//! through the existing pinned-read admission: a reader sees a row at the
//! fork only when its live read admits the row now and admits the row's
//! bytes at the frontier. A row born after the frontier reads as no file, and
//! so does one erased, deleted or withdrawn since, as at every selected
//! version. Every listing walks the index the live head walks and keeps a
//! row only as it stood at the fork, with one change: an entity's claims
//! walk every claim, because the live `ClaimOf` edges name each claim's
//! subject now. The learned-time listings (the days, `ls -t`) file and order
//! rows by their live learned time, so a row a re-put restamped after the
//! frontier lists under no day there and sorts at its live time
//! (PLAN-L3-39 Design 7). Edges keep no history: a link stands at the fork
//! when it stands now, was recorded before the frontier's instant, and its
//! far end reads there.
//!
//! A row the reader's live read admits, whose revision at the frontier this
//! machine no longer holds, is left out of every listing, and a direct read
//! of its path answers [`Error::HistoryNotHeld`] (ruling L3-39-UNRETAINED =
//! B).

use heed::RoTxn;

use super::model::{GraphFsMount, GraphFsResolver};
use crate::claim::ScopedRead;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{PointRead, ReadRow, ReadTarget};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::vault::entity_revision::{
    MemoryFrontier, ReadMode, RevisionRef, entity_owns_revision_in_txn, memory_frontier_in_txn,
    revision_at_frontier_in_txn,
};
use crate::write_envelope::claim_body::decode_claim_body;
use crate::{ClaimBody, ClaimSubject};

/// The plan reason of every coreutils answer at a memory fork.
pub(super) const MEMORY_FORK_WALK_REASON: &str = "memory fork, rows read at the frontier";

/// A row as it stood at a memory fork, as the reader is admitted to it.
pub(super) struct ForkRow {
    pub(super) entity_type: u8,
    pub(super) learned_at: u64,
    pub(super) body: Vec<u8>,
}

impl ForkRow {
    /// The claim this row was at the fork; `None` when it was no claim.
    pub(super) fn claim(&self) -> Option<ClaimBody> {
        (self.entity_type == ENTITY_TYPE_CLAIM)
            .then(|| decode_claim_body(&self.body, true).ok())
            .flatten()
    }
}

/// The claim a served file row carries; `None` when it carries no claim.
pub(super) fn served_claim(row: &ReadRow) -> Option<ClaimBody> {
    row.body
        .as_deref()
        .filter(|_| row.entity_type == ENTITY_TYPE_CLAIM)
        .and_then(|body| decode_claim_body(body, true).ok())
}

/// Whether `claim` is about `subject`: its entity, or either end of its edge.
pub(super) fn claim_names_subject(claim: &ClaimBody, subject: &EntityId) -> bool {
    match &claim.subject {
        ClaimSubject::Entity(id) => id == subject,
        ClaimSubject::Edge { source, target, .. } => source == subject || target == subject,
    }
}

impl ScopedRead<'_> {
    /// The memory frontier `hash` names, checked against this store: one
    /// whose sequence is past the committed head, or whose instant is past
    /// the recording clock, was never handed out here and is not found, the
    /// answer a wrong repository hash gets. Nothing is minted or kept: the
    /// frontier selects content, and each read's admission decides what the
    /// fork shows.
    pub(super) fn handed_out_memory_frontier(&self, hash: &str) -> Result<MemoryFrontier> {
        let frontier = MemoryFrontier::from_hex(hash)?;
        let vault = self.vault();
        let now = vault.now_recorded_at();
        let txn = vault.store.env.read_txn()?;
        let head = memory_frontier_in_txn(&vault.store, &txn, now)?;
        if frontier.sequence > head.sequence || frontier.recorded_at > now {
            return Err(Error::EntityNotFound);
        }
        Ok(frontier)
    }
}

impl GraphFsResolver<'_, '_> {
    /// The frontier this mount reads at, if it is a memory fork.
    pub(super) fn memory_fork(&self) -> Option<MemoryFrontier> {
        match self.options.mount {
            GraphFsMount::MemoryFork(frontier) => Some(frontier),
            GraphFsMount::LiveHead | GraphFsMount::ForkHash(_) => None,
        }
    }

    /// Whether this mount reads the live head, where the live indexes may
    /// answer a coreutil directly.
    pub(super) fn reads_live_head(&self) -> bool {
        self.snapshot.is_none() && self.memory_fork().is_none()
    }

    /// The memory frontier a mount reports to its caller: the one the
    /// committed head stands at now on a live mount, a fork's own, and none
    /// for a repository mount.
    ///
    /// # Errors
    /// Storage errors.
    pub fn memory_frontier(&self) -> Result<Option<MemoryFrontier>> {
        if self.snapshot.is_some() {
            return Ok(None);
        }
        if let Some(frontier) = self.memory_fork() {
            return Ok(Some(frontier));
        }
        let vault = self.scoped_read.vault();
        let recorded_at = vault.now_recorded_at();
        let txn = vault.store.env.read_txn()?;
        memory_frontier_in_txn(&vault.store, &txn, recorded_at).map(Some)
    }

    /// The revision `id` held at `frontier`, when this store still holds its
    /// bytes. `None` when its first move came later, or the timeline holds
    /// none of it (an erased row), or that revision's bytes are gone.
    fn held_revision_at_in_txn(
        &self,
        txn: &RoTxn<'_>,
        frontier: MemoryFrontier,
        id: &EntityId,
    ) -> Result<Option<RevisionRef>> {
        let store = &self.scoped_read.vault().store;
        let Some(revision) = revision_at_frontier_in_txn(store, txn, id, frontier)? else {
            return Ok(None);
        };
        Ok(entity_owns_revision_in_txn(store, txn, id, revision)?.then_some(revision))
    }

    /// Each of `reads` at `frontier`: an id at the revision it held there,
    /// and `None` for one with no held revision there. A short reference
    /// names a live row, so it reads nothing at a fork.
    pub(super) fn fork_reads_in_txn<'r>(
        &self,
        txn: &RoTxn<'_>,
        frontier: MemoryFrontier,
        reads: &[PointRead<'r>],
    ) -> Result<Vec<Option<PointRead<'r>>>> {
        reads
            .iter()
            .map(|read| {
                let ReadTarget::Id(id) = read.target else {
                    return Ok(None);
                };
                Ok(self
                    .held_revision_at_in_txn(txn, frontier, &id)?
                    .map(|revision| PointRead::id(id).at(ReadMode::Pinned(revision))))
            })
            .collect()
    }

    /// Whether a listing keeps `id` at this mount, judged in the listing's
    /// own `txn`: always on a live mount; at a memory fork, when the reader
    /// is admitted to its row as it stood there and `member` holds for that
    /// row.
    pub(super) fn listed_at_fork_in(
        &self,
        txn: &RoTxn<'_>,
        id: &EntityId,
        member: impl FnOnce(&ForkRow) -> Result<bool>,
    ) -> Result<bool> {
        let Some(frontier) = self.memory_fork() else {
            return Ok(true);
        };
        let Some(revision) = self.held_revision_at_in_txn(txn, frontier, id)? else {
            return Ok(false);
        };
        let Some((entity_type, learned_at, body)) = self
            .scoped_read
            .get_entities_parts_with_mode_in_txn(txn, &[*id], ReadMode::Pinned(revision))?
            .into_iter()
            .next()
            .flatten()
        else {
            return Ok(false);
        };
        member(&ForkRow {
            entity_type,
            learned_at,
            body,
        })
    }

    /// Whether a link recorded at `created_at` stands at this mount: always
    /// on a live mount; at a memory fork, when it was recorded before the
    /// frontier's instant. A link recorded in the frontier's own second
    /// reads as not yet there, so no later link can enter a fork.
    pub(super) fn link_at_fork(&self, created_at: u64) -> bool {
        self.memory_fork()
            .is_none_or(|frontier| created_at < frontier.recorded_at)
    }

    /// The refusal a direct read of `id`'s path at a memory fork answers when
    /// it found no file because this machine no longer holds the bytes the
    /// timeline names for `id` there, and the reader's live read admits the
    /// row: it then reveals nothing the reader could not read already.
    /// `Ok(())` in every other case, and on any other mount.
    pub(super) fn refuse_history_not_held(&self, id: &EntityId) -> Result<()> {
        let Some(frontier) = self.memory_fork() else {
            return Ok(());
        };
        let not_held = {
            let store = &self.scoped_read.vault().store;
            let txn = store.env.read_txn()?;
            match revision_at_frontier_in_txn(store, &txn, id, frontier)? {
                Some(revision) => !entity_owns_revision_in_txn(store, &txn, id, revision)?,
                None => false,
            }
        };
        if not_held && self.scoped_read.is_entity_readable(id)? {
            return Err(Error::HistoryNotHeld);
        }
        Ok(())
    }
}
