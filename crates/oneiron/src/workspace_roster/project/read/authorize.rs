//! Who authorized a stored project row's authority fields: its proof and
//! the anchor lineage it builds on.
use super::*;
use crate::scan_check::{EngineScan, ScanCount};

impl ProjectReader<'_, '_> {
    /// Who authorized these authority fields, following the anchor lineage
    /// however long it is (rule 5, FIX 9436). Each state's proof is
    /// verified from the newest down, in the order the lineage nests, then
    /// each prior state admits the change over it, from the oldest up: the
    /// verdict the nested walk gave. The lineage's depth is counted against
    /// [`EngineScan::ProjectAnchorDepth`] for the project; a crossing raises
    /// a check and the row is judged in full.
    pub(super) fn authorize(
        &self,
        id: EntityId,
        authority: &ProjectAuthority,
        proof: Option<&ProjectWriteProof>,
    ) -> Result<ProjectVerdict> {
        let mut depth = 0;
        let verdict = self.authorize_lineage(id, authority, proof, &mut depth);
        if depth > 0 {
            match ScanCount::start(
                self.store,
                self.txn,
                EngineScan::ProjectAnchorDepth,
                id.as_bytes(),
            ) {
                Ok(mut count) => {
                    count.rows(depth);
                    count.defer(self.store);
                }
                Err(error) => {
                    tracing::warn!(kind = ?error.kind(), "project anchor depth was not counted");
                }
            }
        }
        verdict
    }

    /// [`Self::authorize`]'s walk; `depth` ends as the anchors it followed.
    fn authorize_lineage(
        &self,
        id: EntityId,
        authority: &ProjectAuthority,
        proof: Option<&ProjectWriteProof>,
        depth: &mut usize,
    ) -> Result<ProjectVerdict> {
        // Each signed state that builds on an earlier one, newest first: its
        // fields, its verified holder and the state it builds on.
        let mut changes: Vec<(&ProjectAuthority, Holder, &ProjectAuthority)> = Vec::new();
        let (mut authority, mut proof) = (authority, proof);
        let base = loop {
            let Some(signed) = proof else {
                // Only a v3 proof signs a roster; an unsigned state vouches for none.
                if authority.roster.is_some() {
                    break ProjectVerdict::Quarantined(
                        "an unsigned project state carries a roster",
                    );
                }
                break self.unsigned(id, authority)?;
            };
            let holder = match self.verify(id, authority, signed)? {
                Ok(holder) => holder,
                Err(verdict) => return Ok(verdict),
            };
            // The host signs for the owner, who sits on every board through the root.
            let host = holder.actor == "host";
            let Some(anchor) = signed.anchor.as_deref() else {
                if authority.parents.is_empty() {
                    break if host && Some(id) == self.root {
                        ProjectVerdict::Visible
                    } else {
                        ProjectVerdict::Quarantined("a parentless project is not this vault's root")
                    };
                }
                let parent = EntityId::from_hex(&authority.parents[0])
                    .map_err(|_| RecordError::InvalidProjectBody("invalid parent id"))?;
                break match super::super::validity::parent_view(self, parent)? {
                    Err(verdict) => verdict,
                    Ok(view)
                        if view.leader == holder.actor
                            && holder.attenuated
                            && holder.audience.contains(&ScopeId(parent)) =>
                    {
                        ProjectVerdict::Visible
                    }
                    Ok(_) => ProjectVerdict::Quarantined("project spawn needs parent leader slip"),
                };
            };
            // An unsigned earlier state is an owner-door row, whose fields no
            // signature binds. Only the host, acting for the owner, builds on it.
            if anchor.proof.is_none() && Some(id) != self.root && !host {
                return Ok(ProjectVerdict::Quarantined(
                    "only the owner may sign over an unsigned project",
                ));
            }
            changes.push((authority, holder, &anchor.authority));
            *depth += 1;
            (authority, proof) = (&anchor.authority, anchor.proof.as_ref());
        };
        if base != ProjectVerdict::Visible {
            return Ok(base);
        }
        for (authority, holder, prior) in changes.into_iter().rev() {
            let host = holder.actor == "host";
            let verdict = if !holder.audience.contains(&ScopeId(id)) {
                ProjectVerdict::Quarantined("project write outside slip audience")
            } else if prior.board_action(authority) {
                if prior.board.contains(&holder.actor) || host {
                    ProjectVerdict::Visible
                } else {
                    ProjectVerdict::Quarantined("project widening needs board holder proof")
                }
            } else if prior.leader == holder.actor || prior.board.contains(&holder.actor) || host {
                ProjectVerdict::Visible
            } else {
                ProjectVerdict::Quarantined("only the leader or board may change project authority")
            };
            if verdict != ProjectVerdict::Visible {
                return Ok(verdict);
            }
        }
        Ok(ProjectVerdict::Visible)
    }

    /// Owner-door rows (card mint, thread conversion, owner creation) carry
    /// no slip: their creation authority is the owner birth their door
    /// requires (ONE-2118). An unsigned row that replay laid over a signed
    /// one stays quarantined.
    fn unsigned(&self, id: EntityId, authority: &ProjectAuthority) -> Result<ProjectVerdict> {
        if Some(id) == self.root {
            return Ok(ProjectVerdict::Visible);
        }
        if authority.parents.is_empty() {
            return Ok(ProjectVerdict::Quarantined(
                "a parentless project is not this vault's root",
            ));
        }
        Ok(if STRIPPED_PROOF.contains(self.store, self.txn, &id)? {
            ProjectVerdict::Quarantined("signed project replaced by an unsigned row")
        } else {
            ProjectVerdict::Visible
        })
    }
}
