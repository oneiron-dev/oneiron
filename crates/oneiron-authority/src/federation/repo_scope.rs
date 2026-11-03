//! Repo access bounds on an owner's agent Grant, and the pure admission of a
//! repo target under them (FIX 6867, the L02 admission seams the Engine
//! approved for L11 G1).
//!
//! The six-axis [`Scope`] has no repo, ref or path axis, and this module adds
//! none: [`RepoAccessBounds`] supplements one Grant. It names one CODE anchor
//! (the CODE_ARTIFACT whose stored repo_ref is the repo), the real PROJECT the
//! anchor belongs to, the full Git ref names the Grant may touch, and two
//! separate path-glob sets, one to read and one to edit. A Grant whose edit
//! set is empty edits nothing, and read never implies edit. The Grant's own
//! Scope still decides the verb and the audience: an intent needs its verb
//! ([`REPO_READ_VERB`] or [`REPO_EDIT_VERB`]) and the bounds' PROJECT in the
//! audience axis. World, facet and audience never carry a path.
//!
//! The grammar (CALLS "FIX 6867 repo bounds grammar"):
//! - a ref is a full Git ref name under `refs/` (`refs/heads/main`), matched
//!   exactly; `HEAD`, `main` or any short name is never resolved implicitly;
//! - a ref entry may instead be a prefix rule (CALLS "FIX 6895 ref prefix
//!   rule"): `refs` or a full ref name, then [`REF_PREFIX_RULE_SUFFIX`]
//!   (`refs/heads/run/*`). It admits every full ref name under that prefix,
//!   at any depth, so the owner need not list each run branch up front. Git
//!   never names a ref with `*`, so no exact entry reads as a rule;
//! - a path is a normalized repo-relative path: no leading or trailing `/`,
//!   no empty, `.` or `..` component, no `\` and no control character. A
//!   path that is not normalized is outside every scope, never normalized
//!   on the caller's behalf;
//! - a glob is a normalized path whose components may hold `*` (any run of
//!   characters inside one component) and `?` (one character inside one
//!   component), or be exactly `**` (zero or more whole components). Every
//!   other character is literal. A glob matches the whole path. `**` alone is
//!   the whole repo, and only when written.
//!
//! [`Scope::admit_repo_target`] judges in a fixed order: membership (verb and
//! PROJECT audience), then repo, then ref, then paths. Its caller has already
//! admitted the repo handle, so [`RepoAccessRefusal::WrongRepo`] is a mismatch
//! between two admitted handles, never an existence oracle.

use std::collections::BTreeSet;
use std::fmt;

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::scope::{Scope, ScopeId};
use crate::EntityId;

/// The verb a Grant's Scope lists for a repo read (CALLS "FIX 6867 repo
/// bounds grammar").
pub const REPO_READ_VERB: &str = "read";
/// The verb a Grant's Scope lists for a repo edit (CALLS "FIX 6867 repo
/// bounds grammar"). An edit is a write to the agent's own working set; its
/// publication still goes through the proposal and queue gates.
pub const REPO_EDIT_VERB: &str = "write";
/// The one ref prefix rule (CALLS "FIX 6895 ref prefix rule"): a bounds ref
/// entry that ends in this suffix, after `refs` or a full ref name, admits
/// every full ref name under that prefix, at any depth. Every other entry is
/// matched exactly.
pub const REF_PREFIX_RULE_SUFFIX: &str = "/*";

/// The repo bounds an owner's agent Grant carries: one repo, its PROJECT,
/// the refs, and the separate read and edit globs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoAccessBounds {
    /// The CODE anchor (32 hex): a live CODE_ARTIFACT whose stored repo_ref
    /// is the repo. Its current repo is resolved from the store, never from
    /// a path or a snapshot hash the caller names.
    #[schemars(with = "String")]
    pub repo: EntityId,
    /// The real PROJECT (32 hex) the anchor belongs to. The Grant's audience
    /// must name it.
    #[schemars(with = "String")]
    pub project: EntityId,
    /// Full Git ref names (`refs/heads/main`), matched exactly, or prefix
    /// rules (`refs/heads/run/*`) that admit every full ref name under the
    /// prefix; at least one.
    pub refs: BTreeSet<String>,
    /// Repo-relative globs the agent may read. Empty: it reads no file.
    #[serde(default)]
    pub readable: BTreeSet<String>,
    /// Repo-relative globs the agent may edit. Empty: it edits nothing.
    /// Reading a path never lets the agent edit it.
    #[serde(default)]
    pub editable: BTreeSet<String>,
}

/// The bounds name no ref.
const NO_REFS: &str = "repo bounds name at least one full Git ref name";
/// A ref is not a full Git ref name, nor a prefix rule.
const NOT_A_FULL_REF: &str = "repo bounds refs are full Git ref names under refs/ (refs/heads/main) or prefix rules ending in /* (refs/heads/run/*), never HEAD or a short name";
/// A glob is outside the grammar.
const NOT_A_GLOB: &str = "repo bounds globs are normalized repo-relative paths whose components may hold * and ?, or be exactly **";

impl RepoAccessBounds {
    /// Checks the grammar: at least one ref, every ref a full Git ref name
    /// or a prefix rule, every glob in the grammar. The store checks (a live
    /// anchor in a live PROJECT) are the engine writer's.
    ///
    /// # Errors
    /// The reason text of the first rule the bounds break.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.refs.is_empty() {
            return Err(NO_REFS);
        }
        if !self.refs.iter().all(|entry| is_ref_entry(entry)) {
            return Err(NOT_A_FULL_REF);
        }
        if !self
            .readable
            .iter()
            .chain(&self.editable)
            .all(|glob| is_path_glob(glob))
        {
            return Err(NOT_A_GLOB);
        }
        Ok(())
    }

    /// The globs `intent` is judged against: the read set or the edit set,
    /// never their union.
    #[must_use]
    pub const fn globs(&self, intent: RepoAccessIntent) -> &BTreeSet<String> {
        match intent {
            RepoAccessIntent::Read => &self.readable,
            RepoAccessIntent::Edit => &self.editable,
        }
    }

    /// Whether `git_ref` is a full Git ref name that one ref entry admits:
    /// the same name, or a prefix rule it falls under.
    #[must_use]
    pub fn admits_ref(&self, git_ref: &str) -> bool {
        is_full_ref_name(git_ref)
            && (self.refs.contains(git_ref)
                || self
                    .refs
                    .iter()
                    .any(|entry| prefix_rule_admits(entry, git_ref)))
    }

    /// Whether `path` is a normalized repo-relative path that one glob of
    /// `intent`'s set matches whole.
    #[must_use]
    pub fn admits_path(&self, intent: RepoAccessIntent, path: &str) -> bool {
        is_normal_path(path)
            && self
                .globs(intent)
                .iter()
                .any(|glob| glob_matches(glob, path))
    }
}

/// What one repo act names: the repo handle, the full ref it reads or moves,
/// and every path it reads or changes. A rename names both its old and new
/// path, a delete the path it removes. No path names the ref itself (an open
/// or a listing); the intent's glob set must still be nonempty.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RepoTarget {
    /// The CODE anchor the act names.
    pub repo: EntityId,
    /// The full Git ref name the act reads or moves.
    pub git_ref: String,
    /// Every repo-relative path the act reads or changes.
    pub paths: BTreeSet<String>,
}

/// Whether an act reads or edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RepoAccessIntent {
    /// Reads files under the readable globs.
    Read,
    /// Edits files under the editable globs.
    Edit,
}

impl RepoAccessIntent {
    /// The verb a Grant's Scope must list for this intent.
    #[must_use]
    pub const fn verb(self) -> &'static str {
        match self {
            Self::Read => REPO_READ_VERB,
            Self::Edit => REPO_EDIT_VERB,
        }
    }
}

/// Why a repo act was refused. The order is the order of the checks, so the
/// greatest refusal across an actor's Grants is the one that got furthest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RepoAccessRefusal {
    /// No live Grant of the actor's names this repo for this intent: the
    /// first check, made before any other id is resolved or revealed.
    NoMembership,
    /// A live Grant of the actor's names this repo, but the shared vault's
    /// membership gate holds it for a cause that can clear (its root is
    /// conflicted): a typed hold, not a refusal of the Grant, that the
    /// caller retries once the cause is resolved (FIX 6896).
    MembershipHeld,
    /// The act names another repo than the admitted handle.
    WrongRepo,
    /// The ref is not a full ref name the Grant's bounds list, nor one under
    /// a prefix rule they list.
    WrongRef,
    /// A path is not normalized, or no glob of the intent's set matches it,
    /// or the set is empty.
    PathOutsideScope,
    /// The actor's lease, checkout or declaration fence is no longer the
    /// current one (the run fence a later door checks).
    StaleLease,
}

impl RepoAccessRefusal {
    /// Every typed reason, in check order.
    pub const ALL: [Self; 6] = [
        Self::NoMembership,
        Self::MembershipHeld,
        Self::WrongRepo,
        Self::WrongRef,
        Self::PathOutsideScope,
        Self::StaleLease,
    ];

    /// The stable public code a door answers with: the one hook for the six
    /// typed reasons.
    #[must_use]
    pub const fn public_code(self) -> &'static str {
        match self {
            Self::NoMembership => "repo_no_membership",
            Self::MembershipHeld => "repo_membership_held",
            Self::WrongRepo => "repo_wrong_repo",
            Self::WrongRef => "repo_wrong_ref",
            Self::PathOutsideScope => "repo_path_outside_scope",
            Self::StaleLease => "repo_stale_lease",
        }
    }

    /// The plain message a door shows beside the code.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::NoMembership => "no live Grant of this actor admits it to this repo",
            Self::MembershipHeld => {
                "this actor's Grant is held while the shared vault's root is conflicted; retry once it is resolved"
            }
            Self::WrongRepo => "the act names another repo than the one this actor was admitted to",
            Self::WrongRef => {
                "the ref is not a full Git ref name this actor's Grant lists or covers"
            }
            Self::PathOutsideScope => "a path is outside this actor's read or edit globs",
            Self::StaleLease => "this actor's lease is no longer the current one",
        }
    }
}

impl fmt::Display for RepoAccessRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl Scope {
    /// Whether this Grant Scope makes its holder a member of the bounds'
    /// repo: it lists [`REPO_READ_VERB`] and its audience holds the bounds'
    /// PROJECT.
    #[must_use]
    pub fn admits_repo_member(&self, bounds: &RepoAccessBounds) -> bool {
        self.admits_repo_intent(bounds, RepoAccessIntent::Read)
    }

    /// The pure conjunction of this Grant Scope and its repo `bounds` over
    /// `target` for `intent`: the verb and the PROJECT audience, then the
    /// repo, the ref and every path, in that order.
    ///
    /// # Errors
    /// The first [`RepoAccessRefusal`] the target meets; never
    /// [`RepoAccessRefusal::StaleLease`], which is a run fence's, nor
    /// [`RepoAccessRefusal::MembershipHeld`], the shared vault gate's.
    pub fn admit_repo_target(
        &self,
        bounds: &RepoAccessBounds,
        target: &RepoTarget,
        intent: RepoAccessIntent,
    ) -> Result<(), RepoAccessRefusal> {
        if !self.admits_repo_intent(bounds, intent) {
            return Err(RepoAccessRefusal::NoMembership);
        }
        if target.repo != bounds.repo {
            return Err(RepoAccessRefusal::WrongRepo);
        }
        if !bounds.admits_ref(&target.git_ref) {
            return Err(RepoAccessRefusal::WrongRef);
        }
        if bounds.globs(intent).is_empty()
            || !target
                .paths
                .iter()
                .all(|path| bounds.admits_path(intent, path))
        {
            return Err(RepoAccessRefusal::PathOutsideScope);
        }
        Ok(())
    }

    fn admits_repo_intent(&self, bounds: &RepoAccessBounds, intent: RepoAccessIntent) -> bool {
        self.verbs.contains(&intent.verb().to_owned())
            && self.audience.contains(&ScopeId(bounds.project))
    }
}

/// Whether `name` is a full Git ref name: under `refs/`, by git's
/// check-ref-format rules.
fn is_full_ref_name(name: &str) -> bool {
    name.strip_prefix("refs/")
        .is_some_and(|rest| !rest.is_empty())
        && !name.ends_with('.')
        && !name.contains("..")
        && !name.contains("@{")
        && !name.chars().any(|ch| {
            ch.is_ascii_control() || matches!(ch, ' ' | '~' | '^' | ':' | '?' | '*' | '[' | '\\')
        })
        && name.split('/').all(|component| {
            !component.is_empty() && !component.starts_with('.') && !component.ends_with(".lock")
        })
}

/// Whether `entry` is a bounds ref entry: a full Git ref name, or a prefix
/// rule whose prefix is `refs` or a full Git ref name.
fn is_ref_entry(entry: &str) -> bool {
    match entry.strip_suffix(REF_PREFIX_RULE_SUFFIX) {
        Some(prefix) => prefix == "refs" || is_full_ref_name(prefix),
        None => is_full_ref_name(entry),
    }
}

/// Whether `entry` is a prefix rule that `git_ref` falls under: the prefix,
/// a `/`, then at least one more character.
fn prefix_rule_admits(entry: &str, git_ref: &str) -> bool {
    entry
        .strip_suffix(REF_PREFIX_RULE_SUFFIX)
        .and_then(|prefix| git_ref.strip_prefix(prefix))
        .and_then(|rest| rest.strip_prefix('/'))
        .is_some_and(|rest| !rest.is_empty())
}

/// Whether `path` is a normalized repo-relative path.
fn is_normal_path(path: &str) -> bool {
    !path.chars().any(|ch| ch == '\\' || ch.is_control())
        && path
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

/// Whether `glob` is in the grammar: a normalized path whose `**` stands only
/// as a whole component.
fn is_path_glob(glob: &str) -> bool {
    is_normal_path(glob)
        && glob
            .split('/')
            .all(|component| component == "**" || !component.contains("**"))
}

/// Whether `glob` matches the whole of `path`, component by component; `**`
/// spans zero or more whole components.
fn glob_matches(glob: &str, path: &str) -> bool {
    let names: Vec<&str> = path.split('/').collect();
    // reach[n]: the glob so far matches the first n components exactly.
    let mut reach = vec![false; names.len() + 1];
    reach[0] = true;
    for part in glob.split('/') {
        let mut next = vec![false; names.len() + 1];
        if part == "**" {
            let mut seen = false;
            for (slot, reached) in next.iter_mut().zip(&reach) {
                seen |= *reached;
                *slot = seen;
            }
        } else {
            for (index, name) in names.iter().enumerate() {
                if reach[index] && component_matches(part, name) {
                    next[index + 1] = true;
                }
            }
        }
        reach = next;
    }
    reach.last() == Some(&true)
}

/// Whether one glob component matches one path component whole: `*` is any
/// run of characters, `?` one character, every other character itself.
fn component_matches(part: &str, name: &str) -> bool {
    let part: Vec<char> = part.chars().collect();
    let name: Vec<char> = name.chars().collect();
    let (mut at, mut on) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while on < name.len() {
        if at < part.len() && (part[at] == '?' || part[at] == name[on]) {
            at += 1;
            on += 1;
        } else if at < part.len() && part[at] == '*' {
            star = Some((at, on));
            at += 1;
        } else if let Some((star_at, star_on)) = star {
            at = star_at + 1;
            on = star_on + 1;
            star = Some((star_at, star_on + 1));
        } else {
            return false;
        }
    }
    part[at..].iter().all(|ch| *ch == '*')
}

/// The canonical MessagePack key order of [`repo_bounds_value`].
const REPO_BOUNDS_KEYS: [&str; 5] = ["repo", "project", "refs", "readable", "editable"];

/// The one MessagePack form of [`RepoAccessBounds`], on the FEDERATION_GRANT
/// body and in the owner's signed mint act alike: a five-key map in
/// [`REPO_BOUNDS_KEYS`] order, ids as lower hex, each set as an ascending
/// string array.
#[must_use]
pub fn repo_bounds_value(bounds: &RepoAccessBounds) -> Value {
    let strings = |set: &BTreeSet<String>| {
        Value::Array(set.iter().map(|item| Value::from(item.as_str())).collect())
    };
    Value::Map(vec![
        (
            Value::from(REPO_BOUNDS_KEYS[0]),
            Value::from(bounds.repo.to_hex()),
        ),
        (
            Value::from(REPO_BOUNDS_KEYS[1]),
            Value::from(bounds.project.to_hex()),
        ),
        (Value::from(REPO_BOUNDS_KEYS[2]), strings(&bounds.refs)),
        (Value::from(REPO_BOUNDS_KEYS[3]), strings(&bounds.readable)),
        (Value::from(REPO_BOUNDS_KEYS[4]), strings(&bounds.editable)),
    ])
}

/// Decodes [`repo_bounds_value`]'s form, fail-closed: exactly its five keys in
/// order, canonical lower-hex ids, strictly ascending sets, and bounds that
/// pass [`RepoAccessBounds::validate`]. `None` for anything else; each codec
/// maps that to its own body refusal.
#[must_use]
pub fn decode_repo_bounds_value(value: &Value) -> Option<RepoAccessBounds> {
    let Value::Map(entries) = value else {
        return None;
    };
    if entries.len() != REPO_BOUNDS_KEYS.len()
        || entries
            .iter()
            .zip(REPO_BOUNDS_KEYS)
            .any(|((key, _), expected)| key.as_str() != Some(expected))
    {
        return None;
    }
    let id = |value: &Value| {
        let hex = value.as_str()?;
        EntityId::from_hex(hex).ok().filter(|id| id.to_hex() == hex)
    };
    let strings = |value: &Value| {
        let Value::Array(items) = value else {
            return None;
        };
        let mut set = BTreeSet::new();
        let mut last: Option<&str> = None;
        for item in items {
            let item = item.as_str()?;
            if last.is_some_and(|prior| prior >= item) {
                return None;
            }
            last = Some(item);
            set.insert(item.to_owned());
        }
        Some(set)
    };
    let bounds = RepoAccessBounds {
        repo: id(&entries[0].1)?,
        project: id(&entries[1].1)?,
        refs: strings(&entries[2].1)?,
        readable: strings(&entries[3].1)?,
        editable: strings(&entries[4].1)?,
    };
    bounds.validate().ok()?;
    Some(bounds)
}
