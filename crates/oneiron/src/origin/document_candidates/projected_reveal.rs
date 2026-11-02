//! A live real-byte reveal grant on a held projected file (FIX 7608
//! pre-flip, FIX 10271; CALL H, ASK E, CALL GRANT-CONFLICT-REPLACEMENT).
//!
//! A push received into a masked copy's private ingress keeps the
//! recipient its host proved and the CODE anchor its admission named. A
//! held file of its proposal is the ORIGINAL file that recipient's grant
//! names: the same repo, store, path and blob, judged by the same target
//! and evaluator a per-file read is. A live standing grant covering it now
//! clears the file's cause, and for a diff with no unique mapping it lets
//! the exact submitted replacement (or deletion) become the canonical
//! target, its cause kept for every later live recheck. Nothing is asked,
//! spent or delivered here. A push with no proven recipient or no anchor,
//! a file with no ORIGINAL, and a blob no readable mark names in this store
//! are not covered: they keep today's ways out (the owner's settlement of
//! the exact replacement, or an exact or rebased push).

use heed::RoTxn;

use crate::error::Result;
use crate::git_wire::GitOid;
use crate::origin::secret_marks::{RepoBlobAddress, RepoMarkFacts, RepoSecretMarkLookup};
use crate::origin::secret_projection::claims::{RepoProjectionClaim, RepoProjectionRecord};
use crate::origin::secret_projection::recipient::RepoProjectionRevealBinding;
use crate::secret_custody::{RepoFileKeys, RepoFileOriginal, RepoFileRevealTarget};
use crate::{EntityId, Vault};

/// What one held proposal's files are checked against: the recipient its
/// push proved, the canonical store and the readable marks now.
pub(crate) struct ProjectedRevealCheck {
    binding: RepoProjectionRevealBinding,
    store_identity: String,
    store_id: EntityId,
    facts: RepoMarkFacts,
}

impl Vault {
    /// The reveal check of the push `operation` received into the copy
    /// `graph`, in `txn`; `None` when its ingress keeps no proven
    /// recipient, or its copy no longer stands.
    ///
    /// # Errors
    /// A store failure, or a record or mark that does not decode.
    pub(crate) fn projected_reveal_check_in_txn(
        &self,
        txn: &RoTxn<'_>,
        graph: &EntityId,
        operation: &EntityId,
    ) -> Result<Option<ProjectedRevealCheck>> {
        let Some(ingress) = RepoProjectionClaim::load_ingress_in_txn(self, txn, graph, operation)?
        else {
            return Ok(None);
        };
        let Some(binding) = ingress.reveal else {
            return Ok(None);
        };
        let Some(stored) = RepoProjectionClaim::load_graph_in_txn(self, txn, graph)? else {
            return Ok(None);
        };
        let RepoProjectionRecord::Graph {
            store_identity,
            store_id,
            ..
        } = stored.record
        else {
            return Ok(None);
        };
        let facts = RepoMarkFacts::read_in_txn(self, txn, RepoSecretMarkLookup::ReadableClaims)?;
        Ok(Some(ProjectedRevealCheck {
            binding,
            store_identity,
            store_id,
            facts,
        }))
    }
}

impl ProjectedRevealCheck {
    /// Whether a live standing grant covers the held file at `path`,
    /// whose ORIGINAL blob is `original`, for this push's recipient now.
    ///
    /// # Errors
    /// A store failure, or a selector the consent bound refuses.
    pub(crate) fn covers_in_txn(
        &self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        path: &str,
        original: Option<&GitOid>,
    ) -> Result<bool> {
        let Some(original) = original else {
            return Ok(false);
        };
        let marks = self.facts.for_blob(&RepoBlobAddress {
            store: self.store_id,
            blob: original.clone(),
        });
        if marks.is_empty() {
            return Ok(false);
        }
        let asker = self.binding.asker();
        let file = RepoFileOriginal {
            repo: self.binding.repo,
            store: self.store_identity.clone(),
            snapshot: None,
            path: path.to_owned(),
            blob: original.clone(),
            source: None,
            marks: marks.ids()?,
        };
        let target = RepoFileRevealTarget::new(&file, &asker);
        let keys = RepoFileKeys {
            custody: marks.custody(),
            opaque: marks.opaque(),
        };
        vault.repo_file_reveal_granted_in_txn(txn, &asker, &target, &keys)
    }
}

/// CALL GRANT-CONFLICT-REPLACEMENT, one hook: the paths of the held
/// conflict files `files` (each its path and ORIGINAL blob, lower hex) a
/// live grant covers for the push `operation` into `graph` now. Their
/// exact submitted replacement becomes the canonical target; their cause
/// stays. A base or source ambiguity never reaches here.
///
/// # Errors
/// A store failure, or a record, mark or pin that does not decode.
pub(crate) fn granted_projected_conflicts<'f, I>(
    vault: &Vault,
    provenance: EntityId,
    graph: &EntityId,
    files: I,
) -> Result<std::collections::BTreeSet<String>>
where
    I: IntoIterator<Item = (&'f str, Option<&'f String>)>,
{
    let mut granted = std::collections::BTreeSet::new();
    let txn = vault.store.env.read_txn()?;
    let Some(operation) = super::projected_join::receive_operation_in_txn(vault, &txn, provenance)?
    else {
        return Ok(granted);
    };
    let Some(check) = vault.projected_reveal_check_in_txn(&txn, graph, &operation)? else {
        return Ok(granted);
    };
    for (path, original) in files {
        let original = original
            .map(|oid| GitOid::parse_hex(oid.clone()))
            .transpose()?;
        if check.covers_in_txn(vault, &txn, path, original.as_ref())? {
            granted.insert(path.to_owned());
        }
    }
    Ok(granted)
}
