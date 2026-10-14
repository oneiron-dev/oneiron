//! The one read door for PROJECT rows. Replay stores a row after structural
//! checks only; this reader judges authority when it is read (ARCH-0040
//! ONE-AUTHLOG-F2), by folding every signed revision the project ever held
//! into one frontier (decision 7). The stored row supplies content; the
//! frontier supplies authority. A project whose frontier serves no authority
//! stays in storage, hidden from ordinary reads and listed for the owner.
use super::fold::{ProjectEffective, ProjectFrontier, budget_count, fold_project, reason};
use super::history_policy::{frozen_frontier, policy_in};
use super::validity::FoldCx;
use super::*;
use crate::HostingPrivacyPosture;
use crate::authority::{AuthorityFold, CapabilitySlip};
use crate::federation::{ScopeAxis, ScopeId};
use crate::store::Store;
use std::cell::RefCell;
use std::collections::BTreeMap;

/// How the fold judges one stored project row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectVerdict {
    Visible,
    /// Waits for an earlier fact: a parent, a slip mint or an owner birth.
    Pending(&'static str),
    /// Its authorization failed. Only the owner sees it, with this reason.
    Quarantined(&'static str),
}

/// A stored project row the fold hides, as the owner sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectQuarantine {
    pub id: EntityId,
    pub record: ProjectRecord,
    pub verdict: ProjectVerdict,
}

/// The stored row, before any authority judgement. Only write doors and this
/// fold read it; every other reader goes through [`ProjectReader`].
pub(super) fn stored(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
) -> Result<Option<ProjectRecord>> {
    record(store, txn, id, kind)
}

/// Whether a row must fit under its parents: a leader's or board holder's
/// signed row does. An owner row, unsigned from an owner door or signed by the
/// host for the owner, is capped by the vault alone.
pub(super) fn bound_by_parents(record: &ProjectRecord) -> bool {
    record.write_proof.as_ref().is_some_and(|proof| {
        CapabilitySlip::from_token(&proof.slip_wire)
            .is_ok_and(|slip| slip.claims.holder_ref != "host")
    })
}

/// The signer a verified proof names and the audience its slip reaches.
pub(super) struct Holder {
    pub(super) actor: String,
    pub(super) audience: ScopeAxis<ScopeId>,
    pub(super) attenuated: bool,
}

/// One snapshot-bound fold over every project row. The authority fold is
/// built once per reader, and each project's frontier is computed once.
pub(crate) struct ProjectReader<'a, 't> {
    store: &'a Store,
    txn: &'a heed::RoTxn<'t>,
    posture: HostingPrivacyPosture,
    kind: u8,
    root: Option<EntityId>,
    fold: RefCell<Option<std::rc::Rc<AuthorityFold>>>,
    frontiers: RefCell<BTreeMap<EntityId, Option<ProjectFrontier>>>,
    open: RefCell<BTreeSet<EntityId>>,
    /// How often a fold met an open project (a parent cycle). A frontier whose
    /// fold met one depends on where the read began, so it is not kept.
    cycle_hits: std::cell::Cell<u64>,
    /// Whether this snapshot is committed, so its fork evidence may publish:
    /// only a door that opened a read transaction says so.
    publish: bool,
}

impl<'a, 't> ProjectReader<'a, 't> {
    /// `None` when the vault has no project kind yet.
    pub(crate) fn new(
        store: &'a Store,
        txn: &'a heed::RoTxn<'t>,
        posture: HostingPrivacyPosture,
    ) -> Result<Option<Self>> {
        let Some(kind) = project_type(store) else {
            return Ok(None);
        };
        Ok(Some(Self {
            store,
            txn,
            posture,
            kind,
            root: ROOT.get(store, txn, &())?,
            fold: RefCell::new(None),
            frontiers: RefCell::new(BTreeMap::new()),
            open: RefCell::new(BTreeSet::new()),
            cycle_hits: std::cell::Cell::new(0),
            publish: false,
        }))
    }

    /// A reader over a committed read snapshot: its folds publish fork
    /// evidence. A reader inside a write transaction, which may still abort,
    /// never does.
    pub(crate) fn committed(mut self) -> Self {
        self.publish = true;
        self
    }

    pub(super) fn store(&self) -> &'a Store {
        self.store
    }
    pub(super) fn txn(&self) -> &'a heed::RoTxn<'t> {
        self.txn
    }
    pub(super) fn root(&self) -> Option<EntityId> {
        self.root
    }
    pub(super) fn kind(&self) -> u8 {
        self.kind
    }

    /// The folded view of one project's signed history; `None` when no
    /// PROJECT row is stored (revisions may still be held).
    pub(crate) fn frontier(&self, id: EntityId) -> Result<Option<ProjectFrontier>> {
        if let Some(known) = self.frontiers.borrow().get(&id) {
            return Ok(known.clone());
        }
        let Some(record) = stored(self.store, self.txn, id, self.kind)? else {
            self.frontiers.borrow_mut().insert(id, None);
            return Ok(None);
        };
        if !self.open.borrow_mut().insert(id) {
            self.cycle_hits.set(self.cycle_hits.get() + 1);
            return Ok(Some(ProjectFrontier {
                id,
                disposition: super::fold::ProjectDisposition::unauthorized(reason::CYCLE),
                witness: None,
                effective: None,
            }));
        }
        let hits = self.cycle_hits.get();
        let frontier = self.compute(id, &record);
        self.open.borrow_mut().remove(&id);
        let frontier = Some(frontier?);
        if self.cycle_hits.get() == hits {
            self.frontiers.borrow_mut().insert(id, frontier.clone());
        }
        Ok(frontier)
    }

    fn compute(&self, id: EntityId, record: &ProjectRecord) -> Result<ProjectFrontier> {
        let held = super::revision::held_in_txn(self.store, self.txn, id, self.kind)?;
        let cx = FoldCx::new(self, id, &held);
        let count = budget_count(&cx)?;
        let policy = policy_in(self.store, self.txn)?;
        if count > policy.max_revisions {
            return frozen_frontier(self, &cx, count, policy.max_revisions);
        }
        let fold = fold_project(&cx, record)?;
        if self.publish {
            for fork in fold.forks {
                self.store.project_forks.record(fork);
            }
        }
        Ok(fold.frontier)
    }

    /// The effective authority every permission consumer reads.
    pub(crate) fn effective(&self, id: EntityId) -> Result<Option<ProjectEffective>> {
        Ok(self.frontier(id)?.and_then(|frontier| frontier.effective))
    }

    /// The stored row's content when the frontier serves authority. Its
    /// authority fields are the row's own claim (point B): permission
    /// consumers read [`Self::effective`].
    pub(crate) fn visible(&self, id: EntityId) -> Result<Option<ProjectRecord>> {
        Ok(match self.read(id)? {
            Some((record, ProjectVerdict::Visible)) => Some(record),
            _ => None,
        })
    }

    /// The content and effective authority of a project.
    pub(crate) fn visible_with_effective(
        &self,
        id: EntityId,
    ) -> Result<Option<(ProjectRecord, ProjectEffective)>> {
        let Some(effective) = self.effective(id)? else {
            return Ok(None);
        };
        Ok(stored(self.store, self.txn, id, self.kind)?.map(|record| (record, effective)))
    }

    /// A body read through another view (an off-record session composes its
    /// overlay over base): its content, with the authority the base history
    /// folds to. A project only the overlay holds is judged as main judges it.
    pub(crate) fn visible_body(
        &self,
        id: EntityId,
        body: &[u8],
    ) -> Result<Option<(ProjectRecord, ProjectEffective)>> {
        let record: ProjectRecord = decode(body)?;
        if stored(self.store, self.txn, id, self.kind)?.is_some() {
            return Ok(self.effective(id)?.map(|effective| (record, effective)));
        }
        if self.judge_stored(id, &record)? != ProjectVerdict::Visible {
            return Ok(None);
        }
        let effective = ProjectEffective::of(
            &record.authority(),
            record.members().into_iter().collect(),
            bound_by_parents(&record),
        );
        Ok(Some((record, effective)))
    }

    /// The stored row with its verdict.
    pub(crate) fn read(&self, id: EntityId) -> Result<Option<(ProjectRecord, ProjectVerdict)>> {
        let Some(frontier) = self.frontier(id)? else {
            return Ok(None);
        };
        Ok(stored(self.store, self.txn, id, self.kind)?.map(|record| (record, frontier.verdict())))
    }

    /// Every stored project with its verdict, in id order.
    pub(crate) fn all(&self) -> Result<Vec<(EntityId, ProjectRecord, ProjectVerdict)>> {
        let mut ids = Vec::new();
        for row in self.store.type_index.prefix_iter(self.txn, &[self.kind])? {
            let (key, _) = row?;
            ids.push(EntityId::from_bytes(
                key[1..]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("project type index"))?,
            )?);
        }
        let mut rows = Vec::new();
        for id in ids {
            if let Some((record, verdict)) = self.read(id)? {
                rows.push((id, record, verdict));
            }
        }
        Ok(rows)
    }

    /// Main's stored-row reader: the verdict of one row on its own anchor
    /// chain. The fold applies it only when no signed history is held (G).
    pub(super) fn judge_stored(
        &self,
        id: EntityId,
        record: &ProjectRecord,
    ) -> Result<ProjectVerdict> {
        let authority = record.authority();
        if authority.parents.is_empty() && Some(id) != self.root {
            return Ok(ProjectVerdict::Quarantined(
                "a parentless project is not this vault's root",
            ));
        }
        let verdict = self.authorize(id, &authority, record.write_proof.as_ref(), 0)?;
        if verdict != ProjectVerdict::Visible || Some(id) == self.root {
            return Ok(verdict);
        }
        let effective = ProjectEffective::of(&authority, BTreeSet::new(), bound_by_parents(record));
        Ok(match super::fold::parent_bounds(self, id, &effective)? {
            Ok(()) => verdict,
            Err(verdict) => verdict,
        })
    }

    pub(super) fn authority(&self) -> Result<std::rc::Rc<AuthorityFold>> {
        self.fold()
    }

    fn fold(&self) -> Result<std::rc::Rc<AuthorityFold>> {
        if let Some(fold) = self.fold.borrow().as_ref() {
            return Ok(fold.clone());
        }
        let fold = std::rc::Rc::new(crate::authority::authority_fold_readonly_for_store_in_txn(
            self.store,
            self.posture,
            self.txn,
        )?);
        *self.fold.borrow_mut() = Some(fold.clone());
        Ok(fold)
    }

    /// Who authorized these authority fields, following the anchor lineage.
    fn authorize(
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
            return Ok(match super::validity::parent_view(self, parent)? {
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

    /// Verifies the slip chain and holder signature as of the signed time.
    pub(super) fn verify(
        &self,
        id: EntityId,
        authority: &ProjectAuthority,
        proof: &ProjectWriteProof,
    ) -> Result<std::result::Result<Holder, ProjectVerdict>> {
        // A v2 proof over a roster, or a v3 proof without one, signs nothing.
        let Ok(challenge) =
            authority.write_challenge(id, proof.version, proof.signed_at, proof.anchor.as_deref())
        else {
            return Ok(Err(ProjectVerdict::Quarantined(
                "invalid project write proof",
            )));
        };
        self.verify_envelope(
            id,
            &proof.slip_wire,
            &challenge,
            &proof.holder_signature,
            proof.signed_at,
            &authority.slice,
        )
    }

    /// Verifies a slip's standing at `signed_at`, its holder's signature
    /// over `challenge`, and a project.write scope over `slice`.
    pub(super) fn verify_envelope(
        &self,
        id: EntityId,
        slip_wire: &str,
        challenge: &[u8],
        holder_signature: &[u8],
        signed_at: u64,
        slice: &Scope,
    ) -> Result<std::result::Result<Holder, ProjectVerdict>> {
        let Ok(slip) = CapabilitySlip::from_token(slip_wire) else {
            return Ok(Err(ProjectVerdict::Quarantined(
                "invalid project write slip",
            )));
        };
        let fold = self.fold()?;
        let Some(mint) = fold.slips.mints.get(&slip.claims.slip_id) else {
            return Ok(Err(ProjectVerdict::Pending(
                "authorizing slip not yet received",
            )));
        };
        // Revocations order before concurrent events (federation:F-MERGE):
        // a revoke seen in any order refuses the same rows on every replica.
        if fold.slips.is_revoked(&slip.claims.slip_id) {
            return Ok(Err(ProjectVerdict::Quarantined("authorizing slip revoked")));
        }
        let Ok(verified) =
            slip.verify_history(&mint.signer, &fold, signed_at, challenge, holder_signature)
        else {
            return Ok(Err(ProjectVerdict::Quarantined(
                "invalid project write proof",
            )));
        };
        let scope = verified.scope();
        let world = ScopeId(slice.world.unwrap_or(id));
        if !scope.verbs.contains(&"project.write".to_owned())
            || !scope.bands.contains(&self.kind)
            || !(scope.worlds.contains(&world) || matches!(scope.worlds, ScopeAxis::All))
            || slice
                .facet
                .is_some_and(|facet| !scope.facets.contains(&ScopeId(facet)))
        {
            return Ok(Err(ProjectVerdict::Quarantined(
                "project write outside slip scope",
            )));
        }
        Ok(Ok(Holder {
            actor: verified.claims().holder_ref.clone(),
            audience: scope.audience.clone(),
            attenuated: !slip.caveats.is_empty(),
        }))
    }
}
