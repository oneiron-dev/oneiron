//! The board's typed re-parent (ARCH-0079 stacking: "each parent leader sits
//! on its board with a slice of authority no wider than its own"). One
//! grouped write moves a project under new parents: it builds on the head the
//! caller saw, seats each parent's leader on the board, fits under every
//! parent's effective view, and signs the head each parent serves as a
//! witness, so a reader judges the re-parent against the history it saw.
use super::fold::{ProjectDisposition, authority_fits};
use super::*;
use crate::authority::CapabilitySlip;

fn refused(reason: &'static str) -> Error {
    RecordError::InvalidProjectBody(reason).into()
}

fn unresolved(project: EntityId, reason: &'static str) -> Error {
    RecordError::ProjectAuthorityUnresolved { project, reason }.into()
}

impl Vault {
    /// The state a re-parent of `id` under `parents` signs, built on the head
    /// `expected` the project serves now: the head's authority with the
    /// stored content, the new parents, the head each parent serves now as
    /// its witness, and each parent's leader added to the board. The signer
    /// signs it as a v3 state over the frontier's witness anchor.
    /// [`Self::reparent_project`] builds it again in its own transaction, so a
    /// parent that moved since refuses the proof.
    pub fn reparent_candidate(
        &self,
        id: EntityId,
        expected: ProjectRevisionHash,
        parents: &[EntityId],
    ) -> Result<ProjectRecord> {
        let txn = self.store.env.read_txn()?;
        self.reparent_candidate_in_txn(&txn, id, expected, parents)
    }

    fn reparent_candidate_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        expected: ProjectRevisionHash,
        parents: &[EntityId],
    ) -> Result<ProjectRecord> {
        if parents.is_empty()
            || parents.contains(&id)
            || parents.iter().collect::<BTreeSet<_>>().len() != parents.len()
        {
            return Err(refused(
                "a re-parent names distinct parents other than the project",
            ));
        }
        let reader =
            ProjectReader::new(&self.store, txn, self.privacy_posture())?.ok_or_else(invalid)?;
        let frontier = reader.frontier(id)?.ok_or(Error::EntityNotFound)?;
        if !matches!(
            frontier.disposition,
            ProjectDisposition::Settled | ProjectDisposition::Unsigned
        ) || frontier.effective.is_none()
        {
            return Err(unresolved(id, "a re-parent needs a settled project"));
        }
        let Some(witness) = frontier.witness.filter(|witness| witness.head == expected) else {
            return Err(unresolved(id, "a re-parent builds on the current head"));
        };
        let mut next = reader.stored_row(id)?.ok_or(Error::EntityNotFound)?;
        let head = witness.authority()?.clone();
        next.claims_scope_ref = head.claims_scope_ref;
        next.slice = head.slice;
        next.depth_limit = head.depth_limit;
        next.depth_remaining = head.depth_remaining;
        next.leader = head.leader;
        next.board = head.board;
        if let Some(roster) = head.roster {
            next.roster = roster.into_iter().collect();
        }
        next.parents = parents.iter().map(EntityId::to_hex).collect();
        next.parent_heads = Vec::with_capacity(parents.len());
        for parent in parents {
            let Some(ProjectFrontier {
                witness: Some(seen),
                effective: Some(_),
                ..
            }) = reader.frontier(*parent)?
            else {
                return Err(refused("a re-parent's parent serves no authority"));
            };
            let leader = EntityId::from_hex(&seen.authority()?.leader)?;
            if !next.board.contains(&leader.to_hex()) {
                next.board.push(leader.to_hex());
            }
            next.parent_heads.push(ProjectParentWitness {
                project: *parent,
                head: seen.head,
                leader,
            });
        }
        next.write_proof = None;
        Ok(next)
    }

    /// The board re-parents `id` under `parents` in one grouped write. The
    /// project must still serve the head `expected`; `proof` is a board
    /// holder's, or the host's, signature over the state
    /// [`Self::reparent_candidate`] returns; every parent serves authority,
    /// and a board holder's state fits under each parent's effective view.
    /// The common write door then verifies the proof live, folds the state
    /// with every project its parents tie it to, walks the stored ancestry
    /// for a cycle, and refuses unless the state installs. Returns the
    /// frontier the project serves after the write.
    pub fn reparent_project(
        &self,
        id: EntityId,
        expected: ProjectRevisionHash,
        parents: Vec<EntityId>,
        proof: ProjectWriteProof,
        now: u64,
    ) -> Result<ProjectFrontier> {
        let kind = self.project_type_byte()?;
        let holder = CapabilitySlip::from_token(&proof.slip_wire)?
            .claims
            .holder_ref;
        self.with_write_txn_grouped(|txn| {
            let mut next = self.reparent_candidate_in_txn(txn, id, expected, &parents)?;
            next.write_proof = Some(proof);
            {
                let reader = ProjectReader::new(&self.store, txn, self.privacy_posture())?
                    .ok_or_else(invalid)?;
                let current = reader
                    .effective(id)?
                    .ok_or_else(|| unresolved(id, "a re-parent needs a settled project"))?;
                let host = holder == "host";
                if !host && !current.board.contains(&holder) {
                    return Err(refused("a re-parent is a board act"));
                }
                if !host {
                    let authority = next.authority();
                    for parent in &parents {
                        let view = reader
                            .effective(*parent)?
                            .ok_or_else(|| refused("a re-parent's parent serves no authority"))?;
                        if !authority_fits(&authority, &view) {
                            return Err(refused("project slice exceeds parent"));
                        }
                    }
                }
            }
            self.batch_in()
                .put(
                    &id,
                    kind,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                    &encode(&next)?,
                )
                .apply(txn)?;
            ProjectReader::new(&self.store, txn, self.privacy_posture())?
                .ok_or_else(invalid)?
                .frontier(id)?
                .ok_or_else(invalid)
        })
    }
}
