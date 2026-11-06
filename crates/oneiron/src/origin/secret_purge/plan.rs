//! The purge request (FIX 7608 slice 10): plans one served repository's
//! purge and freezes the plan, moving nothing (module docs of
//! `origin::secret_purge`).

use std::collections::{BTreeSet, HashSet};

use super::{
    OUTSTANDING, REPO_SECRET_PURGE_PREDICATE, RepoSecretPurgeKeepRoot, RepoSecretPurgePlan,
    RepoSecretPurgeRefMove, RepoSecretPurgeRequest, plan_id, plan_value, purge_claim,
    put_purge_claim,
};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{GitObjectKind, GitOid, GitWire, GitWireRepo};
use crate::origin::publication::OriginKeepRefKind;
use crate::origin::secret_marks::{RepoMarkFacts, RepoSecretMarkLookup};
use crate::origin::smart_http::origin_repo_dir;

impl Vault {
    /// Plans the purge `request` names for `owner` and freezes it as one
    /// `repo.secret_purge` claim. The masked copy of every object the
    /// store's published refs and keep-ref owners reach is written into the
    /// store beside its original; no ref, keep-ref or reflog moves. The same
    /// purge of the same refs by the same owner answers its frozen plan.
    ///
    /// # Errors
    /// The owner's proof is not live, the repository publishes no ref, a
    /// selected mark is not readable, no published history holds a marked
    /// blob, or a store or Git failure.
    pub(crate) fn plan_repo_secret_purge(
        &self,
        owner: &AuthenticatedOwner,
        request: &RepoSecretPurgeRequest,
    ) -> Result<RepoSecretPurgePlan> {
        let actor = owner.revalidate(self)?;
        let wire = GitWire::new(self)?;
        let (store, repo) = open_purge_store(self, &wire, &request.repo)?;
        let facts = purge_facts(self, request.marks.as_deref())?.ok_or_else(|| {
            Error::Refused("a selected mark is not a readable repo secret mark".to_owned())
        })?;
        let published = self.published_origin_refs(&wire, store, &repo)?;
        let mut owners: Vec<(OriginKeepRefKind, String, GitOid)> = Vec::new();
        for kind in OriginKeepRefKind::ALL {
            for (oid, key) in self.origin_keep_owners_of_kind(store, kind)? {
                owners.push((kind, key, oid));
            }
        }
        // Every published object, then every kept one the store holds: a
        // keep-ref owner whose history reaches a marked blob is named too.
        let mut tips: Vec<GitOid> = Vec::new();
        let mut seen: HashSet<GitOid> = HashSet::new();
        for (_, oid) in &published {
            if seen.insert(oid.clone()) {
                tips.push(oid.clone());
            }
        }
        for (_, _, oid) in &owners {
            if !seen.contains(oid) && wire.object_exists(&repo, oid)? {
                seen.insert(oid.clone());
                tips.push(oid.clone());
            }
        }
        // The masked copy masks what custody knows now too (FIX 8966 part
        // 3), as every masked copy does.
        let copy = self.with_known_values(|known| {
            crate::origin::secret_projection::graph_objects::copy_repo_projection_objects(
                self, &wire, &repo, &repo, &tips, &facts, store, None, known,
            )
        })?;
        let mut marks: BTreeSet<EntityId> = BTreeSet::new();
        let mut purged: BTreeSet<String> = BTreeSet::new();
        let mut rewritten: u64 = 0;
        let mut signatures: u64 = 0;
        for object in &copy.objects {
            if object.original == object.copy {
                continue;
            }
            if object.kind == GitObjectKind::Blob {
                marks.extend(object.marks.iter().copied());
                purged.insert(object.original.as_str().to_owned());
            } else {
                rewritten += 1;
            }
            if object.signature_not_preserved {
                signatures += 1;
            }
        }
        let mut moves: Vec<RepoSecretPurgeRefMove> = published
            .iter()
            .filter_map(|(name, old)| {
                let new = copy.copy_of(old);
                (new != *old).then(|| RepoSecretPurgeRefMove {
                    ref_name: name.as_str().to_owned(),
                    old_oid: old.as_str().to_owned(),
                    new_oid: new.as_str().to_owned(),
                })
            })
            .collect();
        if moves.is_empty() {
            return Err(Error::Refused(
                "no published history of this repository holds a marked blob".to_owned(),
            ));
        }
        moves.sort_by(|left, right| left.ref_name.cmp(&right.ref_name));
        let mut keep_roots: Vec<RepoSecretPurgeKeepRoot> = owners
            .into_iter()
            .filter(|(_, _, oid)| copy.copy_of(oid) != *oid)
            .map(|(kind, owner_key, oid)| RepoSecretPurgeKeepRoot {
                kind: kind.as_str().to_owned(),
                owner: owner_key,
                oid: oid.as_str().to_owned(),
                releases: kind == OriginKeepRefKind::Change,
            })
            .collect();
        keep_roots.sort_by(|left, right| {
            (&left.kind, &left.owner, &left.oid).cmp(&(&right.kind, &right.owner, &right.oid))
        });
        let marks: Vec<EntityId> = marks.into_iter().collect();
        let id = plan_id(actor, store, &marks, &moves)?;
        if let Some(frozen) = self.repo_secret_purge_plan(id)? {
            return Ok(frozen);
        }
        let plan = RepoSecretPurgePlan {
            plan: id,
            owner: actor,
            repo: request.repo.clone(),
            store,
            marks,
            moves,
            purged_blobs: purged.into_iter().collect(),
            rewritten_objects: rewritten,
            signatures_dropped: signatures,
            keep_roots,
            outstanding: OUTSTANDING.to_vec(),
            planned_at: self.now_recorded_at(),
        };
        let body = purge_claim(REPO_SECRET_PURGE_PREDICATE, actor, store, plan_value(&plan))?;
        put_purge_claim(self, owner, actor, id, &body, plan.planned_at)?;
        Ok(self.repo_secret_purge_plan(id)?.unwrap_or(plan))
    }
}

/// The served store `repo` names, opened through a commit it published,
/// with its id.
///
/// # Errors
/// An invalid name, a repository that publishes no ref, or a Git failure.
pub(super) fn open_purge_store(
    vault: &Vault,
    wire: &GitWire<'_>,
    repo: &str,
) -> Result<(EntityId, GitWireRepo)> {
    let dir = origin_repo_dir(vault, repo)?;
    vault
        .published_origin_repo(wire, &dir)?
        .ok_or_else(|| Error::Refused("the served repository publishes no ref to purge".to_owned()))
}

/// The readable marks a purge masks: every one, or exactly the ones
/// `marks` selects. `None` when a selected mark is not readable.
///
/// # Errors
/// A store failure, or a mark that does not decode.
pub(super) fn purge_facts(
    vault: &Vault,
    marks: Option<&[EntityId]>,
) -> Result<Option<RepoMarkFacts>> {
    let facts = {
        let txn = vault.store.env.read_txn()?;
        RepoMarkFacts::read_in_txn(vault, &txn, RepoSecretMarkLookup::ReadableClaims)?
    };
    match marks {
        None => Ok(Some(facts)),
        Some(marks) => facts.retained(&marks.iter().copied().collect()),
    }
}
