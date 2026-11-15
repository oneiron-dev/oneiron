//! The setting keys `skill_hub` declares (Setting stage 1): the crate's build script lists each
//! row in the setting catalogue.

use super::SkillFitSetting;
use crate::setting::Kind;

const fn on() -> bool {
    true
}

const fn off() -> bool {
    false
}

crate::setting::setting_keys! {
    /// Whether a dependency advisory hit turns a ready marketplace fit into one owner ask before
    /// the install lands. On unless the owner turns it off.
    pub(crate) ADVISORY_ASK: bool = "skills.advisory_ask" {
        kind: Kind::new(on),
    };
    /// Whether a code-bearing marketplace folder auto-installs. Off unless the owner turns it on;
    /// a host should turn it on only after its sandbox install tests pass, which this switch does
    /// not run. A code-bearing import while it is off stays a Candidate.
    pub(crate) CODE_AUTO_INSTALL: bool = "skills.code_auto_install" {
        kind: Kind::new(off),
    };
    /// Which fit an ordinary skill install runs: the rule fit (a code-free package that requests
    /// no permission the caller lacks installs with undo; anything else asks), or the owner-asked
    /// fit (every install asks).
    pub(crate) SKILL_FIT: SkillFitSetting = "skills.fit" {
        kind: Kind::new(SkillFitSetting::default),
    };
}
