//! Moved from `crates/oneiron/src/origin/lfs/path_policy.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::code_snapshot::validation::validate_manifest_path;
use oneiron_store::git_wire::path_text::git_path_bytes;
use oneiron_store::origin::lfs::policy::LfsAssetClass;
use oneiron_store::origin::lfs::policy::LfsPathPolicy;
use serde::Deserialize;
use serde::Serialize;

/// The paths one rule names, in the canonical text of Git path bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OriginLfsPathMatch {
    /// This one repository-relative path.
    Exact(String),
    /// Every path under this directory, at a `/` boundary: `vendor` matches
    /// `vendor/lib.bin`, not `vendor` itself or `vendor-other/lib.bin`. No
    /// trailing `/`.
    Prefix(String),
}

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
