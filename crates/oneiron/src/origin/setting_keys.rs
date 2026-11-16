//! The catalogue keys `origin` declares (DESIGN 15-setting-primitive, stage 4): a served
//! repository's LFS path rules and its outbound mirror, each at the repository's scope.

use super::lfs::OriginLfsPathRules;
use super::mirror::{OriginMirrorSetup, mirror_setup_changed_in_txn};
use crate::setting::{Kind, Restore, ScopeKind};

fn no_lfs_path_rules() -> OriginLfsPathRules {
    OriginLfsPathRules::default()
}

fn no_mirror() -> Option<OriginMirrorSetup> {
    None
}

crate::setting::setting_keys! {
    /// A served repository's ordered LFS path rules: each an exact path or a directory prefix
    /// with its class. The first rule that matches a path decides its class; a path no rule
    /// matches is repository-large. Part of what the repository's records mean, so a restore
    /// brings the image's rules back. None until the owner sets some.
    pub(crate) LFS_PATH_RULES: OriginLfsPathRules = "origin.lfs_path_rules" {
        kind: Kind::new(no_lfs_path_rules),
        scopes: &[ScopeKind::Repo],
        restore: Restore::Content,
    };
    /// A served repository's outbound mirror: its https URL, the custody name of its push
    /// token (bound to origin:mirror-push and checked when set), the basic-auth user, the
    /// seconds between pushes, the sync strategy and who can read it. Set per repository only.
    /// None until the owner sets one; a clear stops the pushes and the mirror keeps what it has.
    pub(crate) MIRROR: Option<OriginMirrorSetup> = "origin.mirror" {
        kind: Kind::new(no_mirror).strictest(no_mirror),
        scopes: &[ScopeKind::Repo],
        on_change: Some(mirror_setup_changed_in_txn),
    };
}
