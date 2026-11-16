//! The owner's repository LFS path policy (NO-DOOR REPO-LFS-PATH-POLICY;
//! Engine CODECUSTODY-LFS Q1 = A): one served origin's ordered rules, each an
//! exact path or a directory prefix with its class. The rules are the
//! catalogue key `origin.lfs_path_rules` at the origin's repo scope (DESIGN
//! 15-setting-primitive stage 4), set through `vault.settings.set` with the
//! revision the setter read. The first rule that matches a path decides its
//! class; a path no rule matches is repository-large. A rule never reads a
//! byte count.

use serde::{Deserialize, Serialize};

use super::{LfsAssetClass, LfsPathPolicy};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::git_wire::git_path_bytes;
use crate::origin::setting_keys::LFS_PATH_RULES;
use crate::setting::{SettingScope, SettingValue};
use crate::store::code_snapshot::validation::validate_manifest_path;

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

/// One served origin's LFS path rules in order: the value of the catalogue
/// key `origin.lfs_path_rules`. None by default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub struct OriginLfsPathRules(pub Vec<OriginLfsPathRule>);

impl SettingValue for OriginLfsPathRules {
    fn check(self) -> Result<Self> {
        validate_origin_lfs_path_rules(&self.0)?;
        Ok(self)
    }
}

/// One served origin's LFS path policy as a push reads it: its ordered rules
/// and the revision of the key's row that decided them. Revision 0 with no
/// rules is an origin whose owner never set one.
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
fn validate_origin_lfs_path_rules(rules: &[OriginLfsPathRule]) -> Result<()> {
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
        let resolved =
            LFS_PATH_RULES.read_in_txn(self, txn, &[SettingScope::Repo(repo_id)], None)?;
        Ok(OriginLfsPathPolicy {
            revision: resolved.revision,
            rules: resolved.value.0,
        })
    }
}
