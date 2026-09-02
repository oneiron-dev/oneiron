//! Build-revision and checkout-HEAD resolution for ONE-1579 provenance.
//!
//! These are deliberately two different facts:
//!
//! * the BUILD REVISION is the BLAKE3 digest of the running executable image,
//!   paired with a git SHA and a DIRTY FLAG captured by the build environment.
//!   All three are immutable for that artifact and cannot change with the
//!   caller's cwd or a later branch advance;
//! * the SOURCE CHECKOUT HEAD is a descriptive runtime observation from the
//!   compile-time manifest path (then the executable location). It is useful
//!   context, but it is never promoted into the build-revision slot because a
//!   checkout can move after the binary was compiled.
//!
//! The dirty flag is the half that a SHA alone cannot carry. A binary compiled
//! from a tree with uncommitted changes contains code that no commit describes,
//! so attributing its numbers to the SHA its checkout happened to be on is
//! wrong in exactly the way a later branch advance is wrong. Because only the
//! build environment can know it, it is read through `option_env!` — embedded
//! into the artifact at compile time — and an artifact that embedded nothing is
//! fail-closed `not_ready`, never an assumed "clean".
//!
//! Linked worktrees are supported through `commondir`, and the caller's current
//! directory is never consulted.

use std::io::Read;
use std::path::{Path, PathBuf};

/// Explicit runtime override for the build git SHA of a packaged binary. The
/// report names this source, so it cannot be confused with an automatic read.
const GIT_SHA_ENV: &str = "ONEIRON_BENCH_GIT_SHA";
/// Preferred compile-time build SHA. A release/CI build can set this without a
/// build script; `option_env!` embeds the value into the artifact.
const BUILD_GIT_SHA_ENV: &str = "ONEIRON_BENCH_BUILD_GIT_SHA";
const COMPILE_TIME_BUILD_GIT_SHA: Option<&str> = option_env!("ONEIRON_BENCH_BUILD_GIT_SHA");
const COMPILE_TIME_GITHUB_SHA: Option<&str> = option_env!("GITHUB_SHA");
const COMPILE_TIME_GITLAB_SHA: Option<&str> = option_env!("CI_COMMIT_SHA");
/// Compile-time declaration of whether the tree the artifact was BUILT from
/// carried uncommitted changes. Only the build environment can know this, so it
/// is embedded rather than re-derived from a checkout at report time.
const BUILD_DIRTY_ENV: &str = "ONEIRON_BENCH_BUILD_GIT_DIRTY";
const COMPILE_TIME_BUILD_DIRTY: Option<&str> = option_env!("ONEIRON_BENCH_BUILD_GIT_DIRTY");
/// The crate source directory this binary was built from, captured at compile
/// time. It is used only for the descriptive checkout-head observation.
const BUILD_MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GitShaResolution {
    pub(crate) sha: Option<String>,
    pub(crate) source: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExecutableDigestResolution {
    pub(crate) digest: Option<String>,
    pub(crate) source: String,
    pub(crate) executable: Option<String>,
}

/// BLAKE3 over the executable image this process is actually running.
///
/// Linux uses `/proc/self/exe`, which remains attached to the running inode even
/// if the pathname in `target/` is replaced after process start. Other targets
/// fall back to `current_exe`. This digest is the always-local build identifier;
/// it needs no git checkout and cannot accidentally identify the caller's repo.
pub(crate) fn running_executable_blake3() -> ExecutableDigestResolution {
    let displayed = std::env::current_exe()
        .ok()
        .map(|path| path.display().to_string());
    #[cfg(target_os = "linux")]
    let hash_path = PathBuf::from("/proc/self/exe");
    #[cfg(not(target_os = "linux"))]
    let hash_path = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => {
            return ExecutableDigestResolution {
                digest: None,
                source: format!("the running executable path is not resolvable: {error}"),
                executable: None,
            };
        }
    };

    match hash_file_blake3(&hash_path) {
        Ok(digest) => ExecutableDigestResolution {
            digest: Some(digest),
            source: format!(
                "BLAKE3 of running executable image `{}`",
                hash_path.display()
            ),
            executable: displayed.or_else(|| Some(hash_path.display().to_string())),
        },
        Err(error) => ExecutableDigestResolution {
            digest: None,
            source: format!(
                "could not hash running executable image `{}`: {error}",
                hash_path.display()
            ),
            executable: displayed,
        },
    }
}

/// BLAKE3 over the exact bytes of one file. Shared with the ONE-1963
/// ready-child digest so the parent artifact and its child are hashed the same
/// way, and a comparison between them is a comparison of like with like.
pub(crate) fn hash_file_blake3(path: &Path) -> Result<String, std::io::Error> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

/// Git SHA captured for the build, never inferred from a mutable checkout at
/// report time. The packaged-binary runtime override is explicit; otherwise
/// only compile-time environment values are eligible.
pub(crate) fn build_git_sha() -> GitShaResolution {
    if let Ok(pinned) = std::env::var(GIT_SHA_ENV)
        && !pinned.trim().is_empty()
    {
        let sha = valid_sha(pinned.trim());
        return GitShaResolution {
            sha,
            source: if valid_sha(pinned.trim()).is_some() {
                format!("explicit packaged-binary override {GIT_SHA_ENV}")
            } else {
                format!("{GIT_SHA_ENV} was set but did not contain a 40-hex git SHA")
            },
        };
    }

    for (name, candidate) in [
        (BUILD_GIT_SHA_ENV, COMPILE_TIME_BUILD_GIT_SHA),
        ("GITHUB_SHA", COMPILE_TIME_GITHUB_SHA),
        ("CI_COMMIT_SHA", COMPILE_TIME_GITLAB_SHA),
    ] {
        if let Some(candidate) = candidate {
            return GitShaResolution {
                sha: valid_sha(candidate),
                source: if valid_sha(candidate).is_some() {
                    format!("compile-time environment {name}")
                } else {
                    format!("compile-time environment {name} did not contain a 40-hex git SHA")
                },
            };
        }
    }

    GitShaResolution {
        sha: None,
        source: format!(
            "no git SHA was embedded at build time; set {BUILD_GIT_SHA_ENV} while compiling (or use {GIT_SHA_ENV} only as an explicit packaged-binary override)"
        ),
    }
}

/// Whether the source tree the running artifact was COMPILED from carried
/// uncommitted changes, as declared by the build environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BuildDirtyResolution {
    pub(crate) dirty: Option<bool>,
    pub(crate) source: String,
}

/// Reads the compile-time dirty declaration. Fail-closed: an artifact that
/// embedded nothing, or embedded something unreadable, reports `None` with the
/// reason rather than assuming a clean tree.
pub(crate) fn build_tree_dirty() -> BuildDirtyResolution {
    let Some(raw) = COMPILE_TIME_BUILD_DIRTY else {
        return BuildDirtyResolution {
            dirty: None,
            source: format!(
                "no build-tree cleanliness was embedded at compile time; set {BUILD_DIRTY_ENV} \
                 while compiling so the artifact carries whether its sources were committed"
            ),
        };
    };
    match parse_dirty(raw) {
        Some(dirty) => BuildDirtyResolution {
            dirty: Some(dirty),
            source: format!("compile-time environment {BUILD_DIRTY_ENV}"),
        },
        None => BuildDirtyResolution {
            dirty: None,
            source: format!(
                "compile-time environment {BUILD_DIRTY_ENV} was set but did not read as a \
                 boolean, so the build tree's cleanliness is unknown rather than assumed"
            ),
        },
    }
}

/// The accepted spellings, matched case-insensitively. Anything else is
/// unknown; the flag is never coerced by treating "unrecognised" as clean.
fn parse_dirty(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "dirty" | "modified" => Some(true),
        "0" | "false" | "no" | "clean" => Some(false),
        _ => None,
    }
}

/// Descriptive source-checkout HEAD at report capture. This is intentionally
/// separate from [`build_git_sha`]: the branch may have advanced since compile.
pub(crate) fn source_checkout_git_sha() -> GitShaResolution {
    git_sha_from_provenance(
        Path::new(BUILD_MANIFEST_DIR),
        std::env::current_exe().ok().as_deref(),
    )
}

/// Build checkout first, executable location second. Both identify the source
/// checkout associated with the benchmark and neither depends on process cwd.
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
            "no associated source-checkout HEAD resolved from {}",
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
    if candidate.len() == 40 && candidate.chars().all(|c| c.is_ascii_hexdigit()) {
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

    /// The executable digest identifies file CONTENT, not a path label. Equal
    /// bytes under different names produce equal build revisions; one changed
    /// byte produces a different revision.
    #[test]
    fn executable_revision_is_a_content_digest() {
        let root = tempfile::tempdir().expect("tempdir");
        let left = root.path().join("left");
        let copy = root.path().join("copy");
        let changed = root.path().join("changed");
        std::fs::write(&left, b"oneiron-bench image v1").expect("left");
        std::fs::write(&copy, b"oneiron-bench image v1").expect("copy");
        std::fs::write(&changed, b"oneiron-bench image v2").expect("changed");
        assert_eq!(
            hash_file_blake3(&left).expect("left hashes"),
            hash_file_blake3(&copy).expect("copy hashes")
        );
        assert_ne!(
            hash_file_blake3(&left).expect("left hashes"),
            hash_file_blake3(&changed).expect("changed hashes")
        );
    }

    /// A SHA alone cannot describe a binary compiled from uncommitted
    /// sources, so the dirty flag rides beside it and is captured at COMPILE
    /// time. An artifact that embedded nothing must stay `not_ready` rather
    /// than assume a clean tree, and it must never be re-derived by looking at
    /// whatever checkout happens to sit under the manifest path at report time.
    #[test]
    fn build_tree_dirtiness_is_a_compile_time_fact_and_fails_closed() {
        for raw in ["1", "true", "TRUE", " yes ", "dirty", "Modified"] {
            assert_eq!(parse_dirty(raw), Some(true), "{raw} means dirty");
        }
        for raw in ["0", "false", "No", "clean", "CLEAN "] {
            assert_eq!(parse_dirty(raw), Some(false), "{raw} means clean");
        }
        for raw in ["", "  ", "maybe", "2", "unknown", "-1"] {
            assert_eq!(
                parse_dirty(raw),
                None,
                "`{raw}` is unreadable and must not be coerced to clean"
            );
        }

        let resolved = build_tree_dirty();
        assert_eq!(
            resolved.dirty,
            COMPILE_TIME_BUILD_DIRTY.and_then(parse_dirty)
        );
        assert!(
            resolved.source.contains(BUILD_DIRTY_ENV),
            "{}",
            resolved.source
        );
        if COMPILE_TIME_BUILD_DIRTY.is_none() {
            assert!(
                resolved.dirty.is_none(),
                "an artifact that embedded nothing knows nothing about its build tree"
            );
        }

        // The flag is a compile-time constant. The resolver reads no runtime
        // variable and no checkout, so it is stable for the artifact's life,
        // unlike the report-time source-checkout observation beside it.
        assert_eq!(build_tree_dirty(), resolved);
        assert!(
            !resolved.source.contains(BUILD_MANIFEST_DIR),
            "build attribution must not be derived from the manifest path: {}",
            resolved.source
        );
    }

    /// The running binary must expose an artifact revision without relying on
    /// any Git checkout or caller working directory.
    #[test]
    fn the_running_executable_has_a_build_revision_digest() {
        let revision = running_executable_blake3();
        let digest = revision.digest.expect("the test executable can be hashed");
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(revision.source.contains("BLAKE3"));
    }

    /// Source-checkout provenance comes from the build checkout before the
    /// running executable's checkout, and never from the caller cwd. This is a
    /// descriptive source HEAD and is deliberately distinct from build ID.
    #[test]
    fn source_sha_prefers_build_and_executable_provenance_not_caller_state() {
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
