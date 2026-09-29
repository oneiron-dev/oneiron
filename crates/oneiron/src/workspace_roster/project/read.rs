//! The one read door for PROJECT rows. Replay stores a row after structural
//! checks only; this fold judges its authority when it is read (ARCH-0040
//! ONE-AUTHLOG-F2). A row whose authorization fails stays in storage, hidden
//! from ordinary reads and listed for the owner with its reason.
use super::*;
use crate::HostingPrivacyPosture;
use crate::authority::{AuthorityFold, CapabilitySlip};
use crate::federation::{ScopeAxis, ScopeId};
use crate::gate::project_depth::ProjectDepthDisposition;
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
struct Holder {
    actor: String,
    audience: ScopeAxis<ScopeId>,
    attenuated: bool,
}

/// One snapshot-bound fold over every project row. The authority fold is
/// built once per reader, and each row's verdict is computed once.
pub(crate) struct ProjectReader<'a, 't> {
    store: &'a Store,
    txn: &'a heed::RoTxn<'t>,
    posture: HostingPrivacyPosture,
    kind: u8,
    root: Option<EntityId>,
    fold: RefCell<Option<std::rc::Rc<AuthorityFold>>>,
    verdicts: RefCell<BTreeMap<EntityId, Option<(ProjectRecord, ProjectVerdict)>>>,
    open: RefCell<BTreeSet<EntityId>>,
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
            verdicts: RefCell::new(BTreeMap::new()),
            open: RefCell::new(BTreeSet::new()),
        }))
    }

    /// The project as ordinary readers see it: absent unless the fold accepts it.
    pub(crate) fn visible(&self, id: EntityId) -> Result<Option<ProjectRecord>> {
        Ok(match self.read(id)? {
            Some((record, ProjectVerdict::Visible)) => Some(record),
            _ => None,
        })
    }

    /// The stored row with its verdict.
    pub(crate) fn read(&self, id: EntityId) -> Result<Option<(ProjectRecord, ProjectVerdict)>> {
        if let Some(known) = self.verdicts.borrow().get(&id) {
            return Ok(known.clone());
        }
        let Some(record) = stored(self.store, self.txn, id, self.kind)? else {
            self.verdicts.borrow_mut().insert(id, None);
            return Ok(None);
        };
        if !self.open.borrow_mut().insert(id) {
            return Ok(Some((
                record,
                ProjectVerdict::Quarantined("project ancestry cycle"),
            )));
        }
        let verdict = self.judge(id, &record);
        self.open.borrow_mut().remove(&id);
        let known = Some((record, verdict?));
        self.verdicts.borrow_mut().insert(id, known.clone());
        Ok(known)
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

    /// The same verdict for a stored row or a body a write door is about to store.
    pub(crate) fn judge(&self, id: EntityId, record: &ProjectRecord) -> Result<ProjectVerdict> {
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
        for parent in &authority.parents {
            let parent = EntityId::from_hex(parent)
                .map_err(|_| RecordError::InvalidProjectBody("invalid parent id"))?;
            let parent = match self.read(parent)? {
                None => return Ok(ProjectVerdict::Pending("parent project not yet received")),
                Some((_, ProjectVerdict::Pending(_))) => {
                    return Ok(ProjectVerdict::Pending("parent project pending"));
                }
                Some((_, ProjectVerdict::Quarantined(_))) => {
                    return Ok(ProjectVerdict::Quarantined("parent project is quarantined"));
                }
                Some((parent, ProjectVerdict::Visible)) => parent,
            };
            if bound_by_parents(record) && !authority.fits_under(&parent.authority()) {
                return Ok(ProjectVerdict::Quarantined("project slice exceeds parent"));
            }
        }
        Ok(verdict)
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
            return Ok(match self.read(parent)? {
                None => ProjectVerdict::Pending("parent project not yet received"),
                Some((_, ProjectVerdict::Pending(_))) => {
                    ProjectVerdict::Pending("parent project pending")
                }
                Some((_, ProjectVerdict::Quarantined(_))) => {
                    ProjectVerdict::Quarantined("parent project is quarantined")
                }
                Some((parent_row, ProjectVerdict::Visible)) => {
                    if parent_row.leader == holder.actor
                        && holder.attenuated
                        && holder.audience.contains(&ScopeId(parent))
                    {
                        ProjectVerdict::Visible
                    } else {
                        ProjectVerdict::Quarantined("project spawn needs parent leader slip")
                    }
                }
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
    /// no slip. Their creation authority is the owner birth of ONE-2118.
    fn unsigned(&self, id: EntityId, authority: &ProjectAuthority) -> Result<ProjectVerdict> {
        if Some(id) == self.root {
            return Ok(ProjectVerdict::Visible);
        }
        if authority.parents.is_empty() {
            return Ok(ProjectVerdict::Quarantined(
                "a parentless project is not this vault's root",
            ));
        }
        Ok(
            match crate::gate::project_depth::birth_authorization(
                self.store,
                self.txn,
                self.posture,
                id,
            )? {
                ProjectDepthDisposition::Authorized => ProjectVerdict::Visible,
                ProjectDepthDisposition::Pending => {
                    ProjectVerdict::Pending("owner birth not yet received")
                }
                ProjectDepthDisposition::Quarantined => ProjectVerdict::Quarantined(
                    "unsigned project without an authorized owner birth",
                ),
            },
        )
    }

    /// Verifies the slip chain and holder signature as of the signed time.
    fn verify(
        &self,
        id: EntityId,
        authority: &ProjectAuthority,
        proof: &ProjectWriteProof,
    ) -> Result<std::result::Result<Holder, ProjectVerdict>> {
        let Ok(slip) = CapabilitySlip::from_token(&proof.slip_wire) else {
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
        let challenge = authority.write_challenge(id, proof.signed_at, proof.anchor.as_deref())?;
        let Ok(verified) = slip.verify_history(
            &mint.signer,
            &fold,
            proof.signed_at,
            &challenge,
            &proof.holder_signature,
        ) else {
            return Ok(Err(ProjectVerdict::Quarantined(
                "invalid project write proof",
            )));
        };
        let scope = verified.scope();
        let world = ScopeId(authority.slice.world.unwrap_or(id));
        if !scope.verbs.contains(&"project.write".to_owned())
            || !scope.bands.contains(&self.kind)
            || !(scope.worlds.contains(&world) || matches!(scope.worlds, ScopeAxis::All))
            || authority
                .slice
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
