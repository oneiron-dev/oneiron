//! Who authorized a stored project row's authority fields: its proof and
//! the anchor lineage it builds on.
use super::*;

impl ProjectReader<'_, '_> {
    /// Who authorized these authority fields, following the anchor lineage.
    pub(super) fn authorize(
        &self,
        id: EntityId,
        authority: &ProjectAuthority,
        proof: Option<&ProjectWriteProof>,
        depth: usize,
    ) -> Result<ProjectVerdict> {
        if depth > MAX_PROJECT_ANCHORS {
            return Ok(ProjectVerdict::Quarantined(
                "project authority chain too long",
            ));
        }
        let Some(proof) = proof else {
            // Only a v3 proof signs a roster; an unsigned state vouches for none.
            if authority.roster.is_some() {
                return Ok(ProjectVerdict::Quarantined(
                    "an unsigned project state carries a roster",
                ));
            }
            return self.unsigned(id, authority);
        };
        let holder = match self.verify(id, authority, proof)? {
            Ok(holder) => holder,
            Err(verdict) => return Ok(verdict),
        };
        // The host signs for the owner, who sits on every board through the root.
        let host = holder.actor == "host";
        let Some(anchor) = proof.anchor.as_deref() else {
            if authority.parents.is_empty() {
                return Ok(if host && Some(id) == self.root {
                    ProjectVerdict::Visible
                } else {
                    ProjectVerdict::Quarantined("a parentless project is not this vault's root")
                });
            }
            let parent = EntityId::from_hex(&authority.parents[0])
                .map_err(|_| RecordError::InvalidProjectBody("invalid parent id"))?;
            return Ok(match super::super::validity::parent_view(self, parent)? {
                Err(verdict) => verdict,
                Ok(view)
                    if view.leader == holder.actor
                        && holder.attenuated
                        && holder.audience.contains(&ScopeId(parent)) =>
                {
                    ProjectVerdict::Visible
                }
                Ok(_) => ProjectVerdict::Quarantined("project spawn needs parent leader slip"),
            });
        };
        // An unsigned earlier state is an owner-door row, whose fields no
        // signature binds. Only the host, acting for the owner, builds on it.
        if anchor.proof.is_none() && Some(id) != self.root && !host {
            return Ok(ProjectVerdict::Quarantined(
                "only the owner may sign over an unsigned project",
            ));
        }
        let prior = self.authorize(id, &anchor.authority, anchor.proof.as_ref(), depth + 1)?;
        if prior != ProjectVerdict::Visible {
            return Ok(prior);
        }
        if !holder.audience.contains(&ScopeId(id)) {
            return Ok(ProjectVerdict::Quarantined(
                "project write outside slip audience",
            ));
        }
        let prior = &anchor.authority;
        Ok(if prior.board_action(authority) {
            if prior.board.contains(&holder.actor) || host {
                ProjectVerdict::Visible
            } else {
                ProjectVerdict::Quarantined("project widening needs board holder proof")
            }
        } else if prior.leader == holder.actor || prior.board.contains(&holder.actor) || host {
            ProjectVerdict::Visible
        } else {
            ProjectVerdict::Quarantined("only the leader or board may change project authority")
        })
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
