//! The read surface of signed project history and its two settling doors:
//! the board's resolution of a board fork (decision 6) and the owner's seal
//! (ruling F2 condition 2, decision 10). Both write a signed envelope beside
//! the PROJECT row it settles, in one transaction.
use super::fold::{ProjectDisposition, ProjectFrontier, ProjectRank, reason};
use super::owner_signer::{OwnerProjectSigner, owner_signed_at};
use super::read::{ProjectReader, ProjectVerdict, stored};
use super::resolution::{ProjectResolution, ProjectSeal};
use super::revision::{
    ProjectRevision, ProjectRevisionHash, REVISIONS, RevisionOrigin, held_in_txn,
    project_revision_type, revision_entity_id,
};
use super::*;
use crate::consent::AuthenticatedOwner;

fn unresolved(project: EntityId, reason: &'static str) -> Error {
    RecordError::ProjectAuthorityUnresolved { project, reason }.into()
}

impl Vault {
    /// The folded view of one project's signed history: its disposition,
    /// the authentic witness and the effective view every member consumer reads.
    pub fn project_frontier(&self, id: EntityId) -> Result<Option<ProjectFrontier>> {
        let txn = self.store.env.read_txn()?;
        match ProjectReader::new(&self.store, &txn, self.privacy_posture())? {
            Some(reader) => reader.committed().frontier(id),
            None => Ok(None),
        }
    }

    /// Every revision this vault holds for a project, with the fold's
    /// verdict on it: quarantine is per revision (decision 7). A revision
    /// whose origin failed is listed too, though no fold reads it.
    pub fn project_revisions(
        &self,
        id: EntityId,
    ) -> Result<Vec<(ProjectRevisionHash, ProjectVerdict)>> {
        let txn = self.store.env.read_txn()?;
        let Some(reader) = ProjectReader::new(&self.store, &txn, self.privacy_posture())? else {
            return Ok(Vec::new());
        };
        let held = reader.held_of(id)?;
        let mut listed = std::collections::BTreeMap::new();
        match reader
            .decide(id)?
            .as_ref()
            .and_then(|decided| decided.fold.as_ref())
        {
            Some(fold) => listed.extend(
                fold.verdicts
                    .iter()
                    .map(|(hash, verdict)| (*hash, *verdict)),
            ),
            None => {
                let cx = reader.door_cx(id, &held)?;
                for hash in held.rows.keys() {
                    listed.insert(*hash, cx.verdict(*hash)?);
                }
            }
        }
        for ((_, hash), (_, origin)) in REVISIONS.scan_from(&self.store, &txn, id.as_bytes())? {
            if origin == RevisionOrigin::Forged {
                listed.insert(hash, ProjectVerdict::Quarantined(reason::FORGED));
            }
        }
        Ok(listed.into_iter().collect())
    }

    /// A board holder of the fork anchor writes `next` (a fresh v3 sibling
    /// over the anchor, or a contender) with the envelope in one transaction.
    /// The fork is the frontier's own, or one a parent cycle leaves open: the
    /// fork and the cycle are one decision (ruling (a)). `prior` must equal
    /// the fork's causal resolution tips (ruling (b)). Refused unless the
    /// fold with both has `next` as its head, in every world of a cycle.
    pub fn resolve_project_fork(
        &self,
        id: EntityId,
        next: ProjectRecord,
        resolution: ProjectResolution,
    ) -> Result<()> {
        let kind = self.project_type_byte()?;
        let revision_kind = project_revision_type(&self.store).ok_or_else(invalid)?;
        let envelope = ProjectRevision::Resolution {
            project: id,
            resolution: resolution.clone(),
        };
        let envelope_hash = envelope.hash()?;
        let now = self.store.clock.now_recorded_at();
        self.with_write_txn_grouped(|txn| {
            {
                let reader = ProjectReader::new(&self.store, txn, self.privacy_posture())?
                    .ok_or_else(invalid)?;
                let Some(frontier) = reader.frontier(id)? else {
                    return Err(Error::EntityNotFound);
                };
                let tips = match frontier.disposition {
                    ProjectDisposition::Fork {
                        anchor,
                        rank: ProjectRank::Board,
                        resolution_tips,
                        ..
                    } => {
                        if anchor != resolution.anchor {
                            return Err(unresolved(id, "the resolution names another anchor"));
                        }
                        resolution_tips
                    }
                    ProjectDisposition::ParentCycle { forks, .. } => {
                        let Some(fork) = forks.into_iter().find(|fork| {
                            fork.anchor == resolution.anchor && fork.rank == ProjectRank::Board
                        }) else {
                            return Err(unresolved(id, "no board fork to resolve"));
                        };
                        fork.resolution_tips
                    }
                    _ => return Err(unresolved(id, "no board fork to resolve")),
                };
                if tips.into_iter().collect::<Vec<_>>() != resolution.prior {
                    return Err(unresolved(
                        id,
                        "the resolution must build on the current resolution tips",
                    ));
                }
            }
            self.batch_in()
                .put_engine_history(
                    &revision_entity_id(envelope_hash)?,
                    revision_kind,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                    &envelope.canonical_bytes()?,
                )
                .apply(txn)?;
            // The live door folds the envelope and `next` together and
            // refuses unless `next` becomes the head.
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
                .apply(txn)
        })
    }

    /// The owner's seal (ruling F2 condition 2, decision 10). The door builds
    /// `next` with `authority` over the held revision `over`, stores it as the
    /// PROJECT row (content kept), and seals it with `supersedes` = every
    /// owner seal no seal retires yet, whether or not its target stands: an
    /// undefined seal is retired, never made to look valid (ruling (c)). The
    /// owner-project signer signs both the state and the seal (decision 3). A
    /// snapshot already held is never published again, and seals move
    /// strictly forward in time.
    pub fn seal_project(
        &self,
        owner: &AuthenticatedOwner,
        signer: &OwnerProjectSigner<'_>,
        id: EntityId,
        authority: ProjectAuthority,
        over: ProjectRevisionHash,
    ) -> Result<ProjectRevisionHash> {
        let kind = self.project_type_byte()?;
        let revision_kind = project_revision_type(&self.store).ok_or_else(invalid)?;
        if authority.roster.is_none() {
            return Err(unresolved(id, "a seal is a host-signed v3 state"));
        }
        self.with_write_txn(|txn| {
            owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let signed_at = owner_signed_at(self, txn)?;
            let (record, anchor, supersedes) = {
                let reader = ProjectReader::new(&self.store, txn, self.privacy_posture())?
                    .ok_or_else(invalid)?;
                let Some(record) = stored(&self.store, txn, id, kind)? else {
                    return Err(Error::EntityNotFound);
                };
                let held = held_in_txn(&self.store, txn, id, kind)?;
                let cx = reader.door_cx(id, &held)?;
                if cx.verdict(over)? != ProjectVerdict::Visible {
                    return Err(unresolved(id, "a seal builds on a valid held revision"));
                }
                let anchor = revision::anchor_of(&held, over)
                    .ok_or_else(|| unresolved(id, "a seal builds on a held state"))?;
                let supersedes = cx.seal_status()?.tips.clone();
                for tip in &supersedes {
                    if let Some(ProjectRevision::Seal { seal, .. }) = cx.row(tip)
                        && seal.signed_at >= signed_at
                    {
                        return Err(unresolved(id, "seal time repeats; retry"));
                    }
                }
                (record, anchor, supersedes)
            };
            let mut next = record;
            next.parents = authority.parents.clone();
            next.parent_heads = authority.parent_heads.clone();
            next.claims_scope_ref = authority.claims_scope_ref.clone();
            next.slice = authority.slice.clone();
            next.depth_limit = authority.depth_limit;
            next.depth_remaining = authority.depth_remaining;
            next.leader = authority.leader.clone();
            next.board = authority.board.clone();
            next.roster = authority.roster.iter().flatten().cloned().collect();
            self.sign_owner_project_in_txn(
                txn,
                owner,
                signer,
                id,
                &mut next,
                Some(anchor),
                signed_at,
            )?;
            let chain = revision::revisions_of_row(id, &next)?;
            let Some(next_hash) = chain.last().map(|(hash, _)| *hash) else {
                return Err(invalid());
            };
            if revision::REVISIONS.contains(&self.store, txn, &(id, next_hash))? {
                return Err(unresolved(id, "seal snapshot repeats; retry"));
            }
            let mut seal = ProjectSeal {
                next: next_hash,
                supersedes: supersedes.into_iter().collect(),
                slip_wire: signer.wire().to_owned(),
                holder_signature: Vec::new(),
                signed_at,
            };
            seal.holder_signature = signer.sign(&seal.challenge(id)?)?;
            let envelope = ProjectRevision::Seal { project: id, seal };
            let envelope_hash = envelope.hash()?;
            let at = TimeRange {
                start: signed_at,
                end: signed_at,
            };
            // The sealed row passed the owner's door above; it lands as
            // history does, and its chain is captured with it.
            self.batch_in()
                .put_engine_history(&id, kind, at, signed_at, &encode(&next)?)
                .put_engine_history(
                    &revision_entity_id(envelope_hash)?,
                    revision_kind,
                    at,
                    signed_at,
                    &envelope.canonical_bytes()?,
                )
                .apply(txn)?;
            // The owner's act commits only a seal the fold installs: a
            // signature or slip it refuses fails here, not on a later read.
            // The new state can install without its seal, so both must.
            let reader = ProjectReader::new(&self.store, txn, self.privacy_posture())?
                .ok_or_else(invalid)?;
            let held = held_in_txn(&self.store, txn, id, kind)?;
            let sealed = reader.door_cx(id, &held)?.seal_status()?.tips
                == std::collections::BTreeSet::from([envelope_hash]);
            let installed = sealed
                && reader.frontier(id)?.is_some_and(|frontier| {
                    frontier.disposition == ProjectDisposition::Settled
                        && frontier
                            .witness
                            .is_some_and(|witness| witness.head == next_hash)
                });
            if !installed {
                return Err(unresolved(id, "the seal does not install"));
            }
            Ok(envelope_hash)
        })
    }
}
