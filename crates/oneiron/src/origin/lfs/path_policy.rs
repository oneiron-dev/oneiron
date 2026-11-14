//! The owner's repository LFS path policy (NO-DOOR REPO-LFS-PATH-POLICY;
//! Engine CODECUSTODY-LFS Q1 = A): one served origin's ordered rules, each an
//! exact path or a directory prefix with its class, and the revision of the
//! owner's last set, which the next set must name. The first rule that
//! matches a path decides its class; a path no rule matches is
//! repository-large. A rule never reads a byte count.

use serde::{Deserialize, Serialize};

use super::{LfsAssetClass, LfsPathPolicy};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::git_path_bytes;
use crate::side_table::{self, Named, SideTable};
use crate::store::code_snapshot::validation::validate_manifest_path;

/// One served origin's path policy. Key: the origin's LFS repo id.
const PATH_POLICY: SideTable<EntityId, OriginLfsPathPolicy, Named> =
    SideTable::new(&side_table::ORIGIN_LFS_PATH_POLICY);

#[doc(hidden)]
pub use oneiron_verb_wire::origin::lfs::path_policy::OriginLfsPathMatch;

/// One ordered rule: the paths it matches and their class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OriginLfsPathRule {
    #[serde(rename = "match")]
    pub path_match: OriginLfsPathMatch,
    pub class: LfsAssetClass,
}

/// One served origin's LFS path policy: its ordered rules and the revision
/// of the owner's last set. Revision 0 with no rules is an origin whose
/// owner never set one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OriginLfsPathPolicy {
    pub revision: u64,
    pub rules: Vec<OriginLfsPathRule>,
}

impl OriginLfsPathRule {
    /// The rule's path text.
    fn text(&self) -> &str {
        match &self.path_match {
            OriginLfsPathMatch::Exact(text) | OriginLfsPathMatch::Prefix(text) => text,
        }
    }

    /// Refuses a path that is not a normalized repository-relative path in
    /// the canonical text of its bytes.
    fn validate(&self) -> Result<()> {
        validate_manifest_path(self.text())?;
        git_path_bytes(self.text())?;
        Ok(())
    }

    fn matches(&self, path: &[u8]) -> Result<bool> {
        let rule = git_path_bytes(self.text())?;
        Ok(match self.path_match {
            OriginLfsPathMatch::Exact(_) => path == rule.as_ref(),
            OriginLfsPathMatch::Prefix(_) => path
                .strip_prefix(rule.as_ref())
                .is_some_and(|rest| rest.first() == Some(&b'/')),
        })
    }
}

/// Refuses a rule list with a path that is not a normalized
/// repository-relative path in the canonical text of its bytes.
///
/// # Errors
/// The first such path's refusal.
pub(crate) fn validate_origin_lfs_path_rules(rules: &[OriginLfsPathRule]) -> Result<()> {
    rules.iter().try_for_each(OriginLfsPathRule::validate)
}

impl LfsPathPolicy for OriginLfsPathPolicy {
    fn classify(&self, _repo_id: EntityId, path: &[u8]) -> Result<LfsAssetClass> {
        for rule in &self.rules {
            if rule.matches(path)? {
                return Ok(rule.class);
            }
        }
        Ok(LfsAssetClass::RepositoryLarge)
    }
}

impl Vault {
    /// The LFS path policy of the served origin `repo_name` and its repo id:
    /// what the owner last set, or revision 0 with no rules.
    ///
    /// # Errors
    /// A name that is no served origin, or a store failure.
    pub fn served_origin_lfs_path_policy(
        &self,
        repo_name: &str,
    ) -> Result<(EntityId, OriginLfsPathPolicy)> {
        let repo_id = self.served_mirror_repo_id(repo_name)?;
        let txn = self.store.env.read_txn()?;
        Ok((repo_id, self.origin_lfs_path_policy_in_txn(&txn, repo_id)?))
    }

    /// The served origin `repo_id`'s policy, read now: what a push's
    /// pointers are classified by when it is accepted and when it lands. No
    /// decision reads the class yet (Engine CODECUSTODY-LFS-CLASS = B), so a
    /// later set changes nothing an accepted push does; the first consumer of
    /// the class freezes the revision on the push (FIX
    /// LFS-CLASS-FIRST-CONSUMER).
    ///
    /// # Errors
    /// A stored row that does not decode, or a store failure.
    pub(crate) fn origin_lfs_path_policy(&self, repo_id: EntityId) -> Result<OriginLfsPathPolicy> {
        let txn = self.store.env.read_txn()?;
        self.origin_lfs_path_policy_in_txn(&txn, repo_id)
    }

    /// The served origin `repo_id`'s policy in `txn`; revision 0 with no
    /// rules when the owner never set one. A stored row that does not decode
    /// is an error, never the default.
    pub(crate) fn origin_lfs_path_policy_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        repo_id: EntityId,
    ) -> Result<OriginLfsPathPolicy> {
        Ok(PATH_POLICY
            .get(&self.store, txn, &repo_id)?
            .unwrap_or_default())
    }

    /// Replaces the served origin `repo_id`'s rules in `txn` when its stored
    /// revision is `expected_revision`, and advances the revision by one; an
    /// empty rule list sets the default back and still advances it. The
    /// stored revision otherwise, and nothing is written.
    ///
    /// # Errors
    /// A rule whose path is not a normalized repository-relative path, a
    /// revision overflow, or a store failure.
    pub(crate) fn set_origin_lfs_path_policy_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        repo_id: EntityId,
        expected_revision: u64,
        rules: Vec<OriginLfsPathRule>,
    ) -> Result<std::result::Result<OriginLfsPathPolicy, u64>> {
        validate_origin_lfs_path_rules(&rules)?;
        let current = self.origin_lfs_path_policy_in_txn(txn, repo_id)?;
        if current.revision != expected_revision {
            return Ok(Err(current.revision));
        }
        let policy = OriginLfsPathPolicy {
            revision: current
                .revision
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("origin lfs path policy revision"))?,
            rules,
        };
        PATH_POLICY.put(&self.store, txn, &repo_id, &policy)?;
        Ok(Ok(policy))
    }
}
