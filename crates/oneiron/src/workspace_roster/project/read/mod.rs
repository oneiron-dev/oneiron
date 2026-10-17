//! The one read door for PROJECT rows. Replay stores a row after structural
//! checks only; this reader judges authority when it is read (ARCH-0040
//! ONE-AUTHLOG-F2), by folding every signed revision the project ever held
//! into one frontier (decision 7). The stored row supplies content; the
//! frontier supplies authority. A project whose frontier serves no authority
//! stays in storage, hidden from ordinary reads and listed for the owner.
use super::fold::{ProjectEffective, ProjectFold, ProjectFrontier, fold_project, reason};
use super::history_policy::{frozen_frontier, policy_in};
use super::revision::{HeldRevisions, ProjectRevision, ProjectRevisionHash, RevisionOrigin};
use super::validity::FoldCx;
use super::*;
use crate::HostingPrivacyPosture;
use crate::authority::{AuthorityFold, CapabilitySlip};
use crate::federation::{ScopeAxis, ScopeId};
use crate::store::Store;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

mod component;

#[cfg(test)]
thread_local! {
    /// How many signed revisions this thread verified: once per reader, however
    /// many worlds fold them.
    pub(super) static REVISIONS_VERIFIED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

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

/// Main's stored-row verdict on an unsigned row, before its parents are read
/// (a component reads them for all its members at once).
pub(super) fn stored_verdict(
    reader: &ProjectReader<'_, '_>,
    id: EntityId,
    authority: &ProjectAuthority,
) -> Result<ProjectVerdict> {
    if authority.parents.is_empty() && Some(id) != reader.root() {
        return Ok(ProjectVerdict::Quarantined(
            "a parentless project is not this vault's root",
        ));
    }
    reader.authorize(id, authority, None, 0)
}

/// The signer a verified proof names and the audience its slip reaches.
#[derive(Clone)]
pub(super) struct Holder {
    pub(super) actor: String,
    pub(super) audience: ScopeAxis<ScopeId>,
    pub(super) attenuated: bool,
}

/// One project's held history and what it says on its own, before any
/// parent project is read.
pub(super) struct Facts {
    pub(super) record: ProjectRecord,
    pub(super) held: HeldRevisions,
    pub(super) count: u64,
    pub(super) over_budget: bool,
    /// Whether an authenticated signed state is held (else main's stored
    /// row rule applies).
    pub(super) signed: bool,
    /// Each held state's verdict on its own lineage, and its signer: empty
    /// past the budget, whose frozen view folds nothing.
    pub(super) intrinsic: BTreeMap<ProjectRevisionHash, ProjectVerdict>,
    pub(super) signers: BTreeMap<ProjectRevisionHash, String>,
    /// Every parent project whose view can decide this one's.
    pub(super) edges: BTreeSet<EntityId>,
    /// The owner's unretired seals, whatever their targets (ruling (c)).
    pub(super) seals: BTreeSet<ProjectRevisionHash>,
    /// The states the one seal tip keeps (its next's lineage, the next and
    /// every descendant); `None` without a seal or when seals conflict.
    pub(super) sealed: Option<BTreeSet<ProjectRevisionHash>>,
}

/// What every door reads of one project, decided once per reader with every
/// project its parents tie it to (`joint.rs`).
pub(crate) struct Decided {
    pub(crate) frontier: ProjectFrontier,
    /// The within-budget fold the frontier came from; `None` past the budget.
    pub(crate) fold: Option<ProjectFold>,
    /// A component's verdict on each held state, which every door's fold
    /// starts from; `None` when the project folds alone.
    pub(super) labels: Option<BTreeMap<ProjectRevisionHash, ProjectVerdict>>,
    /// Where each board conduit hangs once its prior has fallen.
    pub(super) rehomed: BTreeMap<ProjectRevisionHash, Vec<ProjectRevisionHash>>,
}

/// A decision that read an open project: no authority, and none of the
/// verdicts it listed valid. Within budget its fold is what a refresh
/// persists; past the budget the saved record stays.
fn read_open(id: EntityId, own: &Decided) -> Rc<Decided> {
    let frontier = ProjectFrontier {
        id,
        disposition: super::fold::ProjectDisposition::unauthorized(reason::CYCLE),
        witness: None,
        effective: None,
    };
    let fold = own.fold.as_ref().map(|fold| ProjectFold {
        frontier: frontier.clone(),
        verdicts: (fold.verdicts.iter())
            .map(|(hash, verdict)| match verdict {
                ProjectVerdict::Visible => (*hash, ProjectVerdict::Quarantined(reason::CYCLE)),
                verdict => (*hash, *verdict),
            })
            .collect(),
        dependencies: Default::default(),
        forks: Vec::new(),
        evidence: fold.evidence.clone(),
    });
    Rc::new(Decided {
        frontier,
        fold,
        labels: None,
        rehomed: BTreeMap::new(),
    })
}

/// A live write's trial: its row and chain, held beside the snapshot's.
struct Overlay {
    id: EntityId,
    record: ProjectRecord,
    chain: Vec<(ProjectRevisionHash, ProjectRevision)>,
}

/// One snapshot-bound fold over every project row. The authority fold is
/// built once per reader, and each project's frontier is decided once.
pub(crate) struct ProjectReader<'a, 't> {
    store: &'a Store,
    txn: &'a heed::RoTxn<'t>,
    posture: HostingPrivacyPosture,
    kind: u8,
    root: Option<EntityId>,
    fold: RefCell<Option<Rc<AuthorityFold>>>,
    overlay: Option<Overlay>,
    facts: RefCell<BTreeMap<EntityId, Option<Rc<Facts>>>>,
    components: RefCell<BTreeMap<EntityId, Rc<Vec<EntityId>>>>,
    /// The members of every component closed, in closing order.
    closed: RefCell<Vec<EntityId>>,
    decided: RefCell<BTreeMap<EntityId, Option<Rc<Decided>>>>,
    /// Each signed state's and envelope's slip and signature check, by
    /// project and hash.
    verified: RefCell<
        BTreeMap<(EntityId, ProjectRevisionHash), std::result::Result<Holder, ProjectVerdict>>,
    >,
    open: RefCell<BTreeSet<EntityId>>,
    /// How often a decision met an open project. Components make this
    /// unreachable; a decision that met one is kept from the memo.
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
            overlay: None,
            facts: RefCell::new(BTreeMap::new()),
            components: RefCell::new(BTreeMap::new()),
            closed: RefCell::new(Vec::new()),
            decided: RefCell::new(BTreeMap::new()),
            verified: RefCell::new(BTreeMap::new()),
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

    /// A reader over the same snapshot that also holds a live write's row
    /// and chain for `id`: the trial its door folds.
    pub(super) fn with_write(
        &self,
        id: EntityId,
        record: ProjectRecord,
        chain: Vec<(ProjectRevisionHash, ProjectRevision)>,
    ) -> Result<Self> {
        let mut trial = Self::new(self.store, self.txn, self.posture)?.ok_or_else(invalid)?;
        trial.overlay = Some(Overlay { id, record, chain });
        Ok(trial)
    }

    /// The stored row, or the trial's.
    pub(super) fn stored_row(&self, id: EntityId) -> Result<Option<ProjectRecord>> {
        match &self.overlay {
            Some(overlay) if overlay.id == id => Ok(Some(overlay.record.clone())),
            _ => stored(self.store, self.txn, id, self.kind),
        }
    }

    /// Every held revision of `id`, with the trial's chain.
    pub(super) fn held_of(&self, id: EntityId) -> Result<HeldRevisions> {
        let mut held = super::revision::held_in_txn(self.store, self.txn, id, self.kind)?;
        if let Some(overlay) = self.overlay.as_ref().filter(|overlay| overlay.id == id) {
            for (hash, revision) in &overlay.chain {
                held.insert(*hash, revision.clone(), RevisionOrigin::AwaitingParent);
            }
        }
        Ok(held)
    }

    /// The folded view of one project's signed history; `None` when no
    /// PROJECT row is stored (revisions may still be held).
    pub(crate) fn frontier(&self, id: EntityId) -> Result<Option<ProjectFrontier>> {
        Ok(self.decide(id)?.map(|decided| decided.frontier.clone()))
    }

    /// One project's decision, with every project of its component.
    pub(crate) fn decide(&self, id: EntityId) -> Result<Option<Rc<Decided>>> {
        if let Some(known) = self.decided.borrow().get(&id) {
            return Ok(known.clone());
        }
        if self.facts(id)?.is_none() {
            self.decided.borrow_mut().insert(id, None);
            return Ok(None);
        }
        let members = self.component(id)?;
        if members
            .iter()
            .any(|member| self.open.borrow().contains(member))
        {
            self.cycle_hits.set(self.cycle_hits.get() + 1);
            return Ok(Some(Rc::new(Decided {
                frontier: ProjectFrontier {
                    id,
                    disposition: super::fold::ProjectDisposition::unauthorized(reason::CYCLE),
                    witness: None,
                    effective: None,
                },
                fold: None,
                labels: None,
                rehomed: BTreeMap::new(),
            })));
        }
        self.open.borrow_mut().extend(members.iter().copied());
        let hits = self.cycle_hits.get();
        let decided = match members[..] {
            [only] => self
                .decide_alone(only)
                .map(|decided| BTreeMap::from([(only, decided)])),
            _ => super::joint::solve(self, &members),
        };
        for member in members.iter() {
            self.open.borrow_mut().remove(member);
        }
        let decided = decided?;
        if self.cycle_hits.get() != hits {
            // It read a project this read still had open, which answered
            // without its component: no authority, and nothing of it is
            // memoized, published or persisted (Astra #1434c F2). A later
            // read decides again.
            return Ok(decided.get(&id).map(|own| read_open(id, own)));
        }
        let own = decided.get(&id).cloned();
        for (member, decision) in decided {
            if let Some(fold) = &decision.fold {
                self.publish_forks(&fold.forks);
            }
            self.decided.borrow_mut().insert(member, Some(decision));
        }
        Ok(own)
    }

    fn decide_alone(&self, id: EntityId) -> Result<Rc<Decided>> {
        let facts = self.facts(id)?.ok_or_else(invalid)?;
        let cx = FoldCx::new(self, id, &facts.held);
        if facts.over_budget {
            let policy = policy_in(self.store, self.txn)?;
            let frontier = frozen_frontier(self, &cx, facts.count, policy.max_revisions, true)?;
            return Ok(Rc::new(Decided {
                frontier,
                fold: None,
                labels: None,
                rehomed: BTreeMap::new(),
            }));
        }
        let fold = fold_project(&cx, &facts.record)?;
        Ok(Rc::new(Decided {
            frontier: fold.frontier.clone(),
            fold: Some(fold),
            labels: None,
            rehomed: BTreeMap::new(),
        }))
    }

    /// A fold of `id` for a door: it starts from the component's verdicts,
    /// so a door never decides a parent admission on its own.
    pub(super) fn door_cx<'r>(
        &'r self,
        id: EntityId,
        held: &'r HeldRevisions,
    ) -> Result<FoldCx<'r, 'a, 't>> {
        let decided = self.decide(id)?;
        let seed = decided.and_then(|decided| {
            (decided.labels.clone()).map(|labels| (labels, decided.rehomed.clone()))
        });
        Ok(match (seed, self.facts(id)?) {
            (Some((labels, rehomed)), Some(facts)) => {
                FoldCx::seeded(self, id, held, labels, facts.signers.clone(), rehomed)
            }
            _ => FoldCx::new(self, id, held),
        })
    }

    /// Records fork evidence when this snapshot is committed.
    pub(super) fn publish_forks(&self, forks: &[super::fork_evidence::ProjectForkEvidence]) {
        if self.publish {
            for fork in forks {
                self.store.project_forks.record(fork.clone());
            }
        }
    }

    /// How often a decision met an open project.
    #[cfg(all(test, feature = "sync"))]
    pub(super) fn cycle_hits(&self) -> u64 {
        self.cycle_hits.get()
    }

    /// Every project this reader has read, stored or missing: what its
    /// decisions rest on.
    pub(super) fn read_projects(&self) -> BTreeSet<EntityId> {
        self.facts.borrow().keys().copied().collect()
    }

    /// Every project of each component this reader closed, parents first: a
    /// component closes only after every component it reads.
    pub(super) fn parents_first(&self) -> Vec<EntityId> {
        self.closed.borrow().clone()
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
        Ok(self.stored_row(id)?.map(|record| (record, effective)))
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
        if self.stored_row(id)?.is_some() {
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
        Ok(self
            .stored_row(id)?
            .map(|record| (record, frontier.verdict())))
    }

    /// Every stored project with its verdict, in id order.
    pub(crate) fn all(&self) -> Result<Vec<(EntityId, ProjectRecord, ProjectVerdict)>> {
        let mut ids = Vec::new();
        for id in crate::ports::EntityStoreRead::port_entity_ids_by_type(
            self.store, self.txn, self.kind, None,
        )? {
            ids.push(id?);
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

    pub(super) fn authority(&self) -> Result<Rc<AuthorityFold>> {
        self.fold()
    }

    fn fold(&self) -> Result<Rc<AuthorityFold>> {
        if let Some(fold) = self.fold.borrow().as_ref() {
            return Ok(fold.clone());
        }
        let fold = Rc::new(crate::authority::authority_fold_readonly_for_store_in_txn(
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

    /// [`Self::verify`] of one held signed state, once per reader.
    pub(super) fn verify_revision(
        &self,
        id: EntityId,
        hash: ProjectRevisionHash,
        authority: &ProjectAuthority,
        proof: &ProjectWriteProof,
    ) -> Result<std::result::Result<Holder, ProjectVerdict>> {
        if let Some(known) = self.verified.borrow().get(&(id, hash)) {
            return Ok(known.clone());
        }
        #[cfg(test)]
        REVISIONS_VERIFIED.with(|count| count.set(count.get() + 1));
        let verified = self.verify(id, authority, proof)?;
        self.verified
            .borrow_mut()
            .insert((id, hash), verified.clone());
        Ok(verified)
    }

    /// `check` of one held resolution or seal envelope, once per reader: a
    /// component's read and its members' folds share it.
    pub(super) fn verify_held_envelope(
        &self,
        id: EntityId,
        hash: ProjectRevisionHash,
        check: impl FnOnce() -> Result<std::result::Result<Holder, ProjectVerdict>>,
    ) -> Result<std::result::Result<Holder, ProjectVerdict>> {
        let known = self.verified.borrow().get(&(id, hash)).cloned();
        if let Some(known) = known {
            return Ok(known);
        }
        let verified = check()?;
        self.verified
            .borrow_mut()
            .insert((id, hash), verified.clone());
        Ok(verified)
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

/// The facets a project's home room limits what is read through it: the
/// slice facet of the authority its history folds to (owner ruling
/// FACET-READ), never a stored row the fold does not serve. A MESSAGE or
/// TURN said there sits in it. `None` is a room no project owns, or one whose
/// project serves no authority or names no facet.
pub(crate) fn room_facets_in(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
) -> Result<Option<ScopeAxis<ScopeId>>> {
    let Some(project) = ROOM_PROJECT.get(&vault.store, txn, &room)? else {
        return Ok(None);
    };
    let Some(reader) = ProjectReader::new(&vault.store, txn, vault.privacy_posture())? else {
        return Ok(None);
    };
    Ok(reader
        .effective(project)?
        .and_then(|effective| effective.slice)
        .and_then(|slice| slice.facet)
        .map(|facet| ScopeAxis::Some([ScopeId(facet)].into())))
}
