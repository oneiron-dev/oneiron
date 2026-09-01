//! Checkout HEAD resolution for ONE-1579 run provenance.
//!
//! The git SHA identifies the checkout THIS BINARY came from — the build
//! checkout first, then the running executable's own directory — and never
//! the caller's working directory. Callers pass absolute plan and output
//! paths, so a bench invoked from inside an unrelated repository used to
//! record that repository's HEAD as the benchmark's provenance. The lookup
//! also resolves through a linked worktree's `commondir`, so a normal
//! worktree run reports its actual commit instead of `not_ready`.

use std::path::{Path, PathBuf};

/// Environment variable that pins the git sha for a PACKAGED binary that no
/// longer sits in the checkout it was built from (container, CI artifact).
/// It is an explicit override, never a fallback for a missing lookup.
const GIT_SHA_ENV: &str = "ONEIRON_BENCH_GIT_SHA";
/// The crate source directory this binary was BUILT from, captured at compile
/// time. This is what makes the sha the BENCHMARK's provenance rather than a
/// property of wherever the process was started.
const BUILD_MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

// ─── git sha ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GitShaResolution {
    pub(crate) sha: Option<String>,
    pub(crate) source: String,
}

/// Resolves THIS BENCHMARK binary's checkout HEAD by reading Git's on-disk
/// refs. The caller's current directory is deliberately never consulted: an
/// absolute `perf run --plan ... --out ...` may be launched from any checkout.
pub(crate) fn git_sha() -> GitShaResolution {
    if let Ok(pinned) = std::env::var(GIT_SHA_ENV)
        && !pinned.trim().is_empty()
    {
        let sha = valid_sha(pinned.trim());
        return GitShaResolution {
            sha,
            source: if valid_sha(pinned.trim()).is_some() {
                format!("explicit packaged-binary override {GIT_SHA_ENV}")
            } else {
                format!("{GIT_SHA_ENV} was set but did not contain a full hexadecimal git sha")
            },
        };
    }

    git_sha_from_provenance(
        Path::new(BUILD_MANIFEST_DIR),
        std::env::current_exe().ok().as_deref(),
    )
}

/// Build checkout first, executable location second. Both identify where the
/// benchmark came from; neither depends on the process working directory.
pub(crate) fn git_sha_from_provenance(
    build_manifest_dir: &Path,
    executable: Option<&Path>,
) -> GitShaResolution {
    let mut attempted = Vec::new();
    for (kind, start) in std::iter::once(("build_manifest_dir", build_manifest_dir)).chain(
        executable
            .and_then(Path::parent)
            .map(|parent| ("current_executable", parent)),
    ) {
        attempted.push(format!("{kind}:{}", start.display()));
        let Some(git_dir) = discover_git_dir(start) else {
            continue;
        };
        if let Some(sha) = resolve_git_sha(&git_dir) {
            return GitShaResolution {
                sha: Some(sha),
                source: format!("{kind}:{} via {}", start.display(), git_dir.display()),
            };
        }
    }
    GitShaResolution {
        sha: None,
        source: format!(
            "no benchmark checkout HEAD resolved from {}; set {GIT_SHA_ENV} only for an explicit              packaged-binary override",
            attempted.join(", ")
        ),
    }
}

/// Resolves HEAD inside one git directory, which may be a linked worktree's.
///
/// A linked worktree keeps its own `HEAD`, but its branch's LOOSE ref lives in
/// the common directory named by its `commondir` file — not under
/// `worktrees/<name>/refs`. Looking only in the worktree git dir and then in
/// `packed-refs` misses the ordinary case where the branch ref is loose, which
/// is why every worktree run used to report `not_ready`.
pub(crate) fn resolve_git_sha(git_dir: &Path) -> Option<String> {
    let head = std::fs::read_to_string(git_dir.join("HEAD")).ok()?;
    let head = head.trim();
    let Some(reference) = head.strip_prefix("ref: ") else {
        return valid_sha(head);
    };
    let reference = reference.trim();
    if reference.is_empty() {
        return None;
    }
    let common = common_git_dir(git_dir);
    for root in std::iter::once(git_dir).chain(common.as_deref()) {
        if let Some(direct) = std::fs::read_to_string(root.join(reference))
            .ok()
            .and_then(|raw| valid_sha(raw.trim()))
        {
            return Some(direct);
        }
    }
    packed_ref(git_dir, common.as_deref(), reference)
}

/// The common git directory a linked worktree points at, resolved from its
/// `commondir` file. `None` for an ordinary (non-linked) git directory.
fn common_git_dir(git_dir: &Path) -> Option<PathBuf> {
    let raw = std::fs::read_to_string(git_dir.join("commondir")).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let candidate = PathBuf::from(trimmed);
    let resolved = if candidate.is_absolute() {
        candidate
    } else {
        git_dir.join(candidate)
    };
    Some(std::fs::canonicalize(&resolved).unwrap_or(resolved))
}

/// `packed-refs` lives in the common dir. The declared `commondir` is probed
/// first; the positional `worktrees/<name>` layout is kept as a fallback for
/// a git dir that carries no `commondir` file.
fn packed_ref(git_dir: &Path, common: Option<&Path>, reference: &str) -> Option<String> {
    let mut candidates = vec![git_dir.join("packed-refs")];
    if let Some(common) = common {
        candidates.push(common.join("packed-refs"));
    }
    if let Some(parent) = git_dir.parent()
        && let Some(positional) = parent.parent()
    {
        candidates.push(positional.join("packed-refs"));
    }
    for candidate in candidates {
        let Ok(contents) = std::fs::read_to_string(candidate) else {
            continue;
        };
        for line in contents.lines() {
            let Some((sha, name)) = line.split_once(' ') else {
                continue;
            };
            if name.trim() == reference
                && let Some(sha) = valid_sha(sha)
            {
                return Some(sha);
            }
        }
    }
    None
}

/// Walks up from `start` looking for `.git`. Handles the linked-worktree case
/// where `.git` is a FILE containing `gitdir: <path>`.
fn discover_git_dir(start: &Path) -> Option<PathBuf> {
    for ancestor in start.ancestors() {
        let candidate = ancestor.join(".git");
        let Ok(metadata) = std::fs::metadata(&candidate) else {
            continue;
        };
        if metadata.is_dir() {
            return Some(candidate);
        }
        let pointer = std::fs::read_to_string(candidate).ok()?;
        let gitdir = pointer.trim().strip_prefix("gitdir:")?.trim();
        let gitdir = PathBuf::from(gitdir);
        return Some(if gitdir.is_absolute() {
            gitdir
        } else {
            ancestor.join(gitdir)
        });
    }
    None
}

fn valid_sha(candidate: &str) -> Option<String> {
    let candidate = candidate.trim();
    if candidate.len() >= 40 && candidate.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(candidate.to_owned());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const SHA: &str = "b9b8dfda109ebec67a4005614b71f993d4cc6aba";
    const OTHER_SHA: &str = "533ccf46f25e393b4ea128560d498aeac3488cf2";

    /// Builds `<root>/repo/.git` plus a linked worktree git dir at
    /// `<root>/repo/.git/worktrees/wt` whose `commondir` is `../..`.
    fn linked_worktree(root: &Path) -> (PathBuf, PathBuf) {
        let common = root.join("repo/.git");
        let worktree = common.join("worktrees/wt");
        std::fs::create_dir_all(common.join("refs/heads/w6")).expect("common refs");
        std::fs::create_dir_all(&worktree).expect("worktree git dir");
        std::fs::write(worktree.join("HEAD"), "ref: refs/heads/w6/one-1579\n")
            .expect("worktree HEAD");
        std::fs::write(worktree.join("commondir"), "../..\n").expect("commondir");
        (common, worktree)
    }

    /// The ordinary linked-worktree shape: HEAD is a symbolic ref and the
    /// branch's LOOSE ref lives in the common directory. Resolving only inside
    /// the worktree git dir (or only in packed-refs) reports not_ready for a
    /// perfectly resolvable commit, so the commondir hop is load-bearing.
    #[test]
    fn a_linked_worktree_resolves_its_loose_ref_through_commondir() {
        let root = tempfile::tempdir().expect("tempdir");
        let (common, worktree) = linked_worktree(root.path());
        std::fs::write(common.join("refs/heads/w6/one-1579"), format!("{SHA}\n"))
            .expect("loose ref");

        // The loose ref is NOT under the worktree git dir, and there is no
        // packed-refs at all: only the commondir hop can find it.
        assert!(!worktree.join("refs/heads/w6/one-1579").exists());
        assert!(!common.join("packed-refs").exists());
        assert_eq!(resolve_git_sha(&worktree).as_deref(), Some(SHA));
    }

    /// A worktree-local loose ref still wins, and packed-refs in the common
    /// directory remains the fallback when no loose ref exists anywhere.
    #[test]
    fn loose_refs_win_and_packed_refs_remain_the_fallback() {
        let root = tempfile::tempdir().expect("tempdir");
        let (common, worktree) = linked_worktree(root.path());
        std::fs::write(
            common.join("packed-refs"),
            format!("# pack-refs with: peeled\n{OTHER_SHA} refs/heads/w6/one-1579\n"),
        )
        .expect("packed refs");

        assert_eq!(
            resolve_git_sha(&worktree).as_deref(),
            Some(OTHER_SHA),
            "with no loose ref anywhere the common packed-refs answers"
        );

        std::fs::write(common.join("refs/heads/w6/one-1579"), format!("{SHA}\n"))
            .expect("loose ref");
        assert_eq!(
            resolve_git_sha(&worktree).as_deref(),
            Some(SHA),
            "a loose ref is authoritative over a stale packed entry"
        );
    }

    /// A detached HEAD is a sha outright, and a genuinely unresolvable ref
    /// stays fail-closed rather than guessing.
    #[test]
    fn an_unresolvable_head_stays_fail_closed() {
        let root = tempfile::tempdir().expect("tempdir");
        let (_, worktree) = linked_worktree(root.path());
        assert!(
            resolve_git_sha(&worktree).is_none(),
            "no loose ref and no packed-refs must resolve to nothing, never a guess"
        );

        std::fs::write(worktree.join("HEAD"), format!("{SHA}\n")).expect("detached HEAD");
        assert_eq!(resolve_git_sha(&worktree).as_deref(), Some(SHA));

        std::fs::write(worktree.join("HEAD"), "ref: refs/heads/missing\n").expect("HEAD");
        assert!(resolve_git_sha(&worktree).is_none());

        std::fs::write(worktree.join("HEAD"), "not-a-sha\n").expect("HEAD");
        assert!(resolve_git_sha(&worktree).is_none());
    }

    /// Benchmark provenance comes from the build checkout before the running
    /// executable's checkout, and never from the caller cwd. An unrelated
    /// executable path cannot replace the source SHA captured by the build
    /// manifest directory.
    #[test]
    fn git_sha_prefers_build_and_executable_provenance_not_caller_state() {
        let root = tempfile::tempdir().expect("tempdir");
        let build_repo = root.path().join("build-repo");
        let executable_repo = root.path().join("executable-repo");
        for (repo, sha) in [(&build_repo, SHA), (&executable_repo, OTHER_SHA)] {
            std::fs::create_dir_all(repo.join(".git")).expect("git dir");
            std::fs::write(
                repo.join(".git/HEAD"),
                format!(
                    "{sha}
"
                ),
            )
            .expect("detached HEAD");
        }
        let manifest_dir = build_repo.join("crates/oneiron-bench");
        let executable = executable_repo.join("target/release/oneiron-bench");
        std::fs::create_dir_all(&manifest_dir).expect("manifest dir");
        std::fs::create_dir_all(executable.parent().expect("executable parent"))
            .expect("executable dir");

        let resolved = git_sha_from_provenance(&manifest_dir, Some(&executable));
        assert_eq!(resolved.sha.as_deref(), Some(SHA));
        assert!(resolved.source.starts_with("build_manifest_dir:"));

        let missing_build = root.path().join("packaged/no/source");
        let fallback = git_sha_from_provenance(&missing_build, Some(&executable));
        assert_eq!(fallback.sha.as_deref(), Some(OTHER_SHA));
        assert!(fallback.source.starts_with("current_executable:"));
    }

    /// The bench runs from a linked worktree in this repository. Whatever the
    /// checkout shape, a discoverable git dir with a resolvable HEAD must
    /// produce a sha rather than the `not_ready` cell the old lookup emitted.
    #[test]
    fn the_running_checkout_resolves_its_own_sha() {
        let Some(git_dir) = std::env::current_dir()
            .ok()
            .as_deref()
            .and_then(discover_git_dir)
        else {
            return;
        };
        let head = std::fs::read_to_string(git_dir.join("HEAD")).unwrap_or_default();
        let reference = head
            .trim()
            .strip_prefix("ref: ")
            .map(str::trim)
            .map(PathBuf::from);
        let resolvable = reference.is_none_or(|reference| {
            git_dir.join(&reference).exists()
                || common_git_dir(&git_dir).is_some_and(|common| common.join(&reference).exists())
        });
        if !resolvable {
            return;
        }
        assert!(
            resolve_git_sha(&git_dir).is_some(),
            "a checkout whose HEAD ref exists on disk must resolve, not report not_ready"
        );
    }
}
