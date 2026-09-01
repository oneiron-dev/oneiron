//! ONE-1579 run provenance: where, on what, and from which inputs a report
//! was made.
//!
//! Everything here describes the ENVIRONMENT a run happened in. None of it is
//! an engine benchmark row, and none of it is allowed to invent a value: an
//! unavailable fact is an explicit `not_ready` cell carrying the reason it
//! could not be read, never a zero, an empty string or a guess.
//!
//! Three things here are load-bearing beyond description:
//!
//! * the GIT SHA identifies the checkout THIS BINARY came from — the build
//!   checkout first, then the running executable's own directory — and never
//!   the caller's working directory. Callers pass absolute plan and output
//!   paths, so a bench invoked from inside an unrelated repository used to
//!   record that repository's HEAD as the benchmark's provenance. The lookup
//!   also resolves through a linked worktree's `commondir`, so a normal
//!   worktree run reports its actual commit instead of `not_ready`;
//! * the CACHE-EVENT HASH covers the exact bytes the cache axis read, so the
//!   stream that produced the reported hit rates is identifiable and cannot be
//!   swapped without changing provenance;
//! * the NODE IDENTITY names the host and says whether it is the designated
//!   first Tokyo node, which the publication predicate requires.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use super::cells::{Cell, EvidenceKind};

/// Environment variable that pins the git sha for a PACKAGED binary that no
/// longer sits in the checkout it was built from (container, CI artifact).
/// It is an explicit override, never a fallback for a missing lookup.
const GIT_SHA_ENV: &str = "ONEIRON_BENCH_GIT_SHA";
/// The crate source directory this binary was BUILT from, captured at compile
/// time. This is what makes the sha the BENCHMARK's provenance rather than a
/// property of wherever the process was started.
const BUILD_MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");
/// Environment variable declaring which node this run happened on.
pub(crate) const NODE_ENV: &str = "ONEIRON_BENCH_NODE";
/// Environment variable declaring that node's location.
pub(crate) const NODE_LOCATION_ENV: &str = "ONEIRON_BENCH_NODE_LOCATION";
/// The node a publishable full run must be produced on.
pub(crate) const DESIGNATED_FIRST_TOKYO_NODE: &str = "tokyo-1";
/// The location that node must declare.
pub(crate) const DESIGNATED_NODE_LOCATION: &str = "tokyo";

const NODE_RULE: &str = "a publishable full run must declare the designated first Tokyo node and \
     its location, and must resolve a hostname and machine id, so the report carries an \
     auditable identity for WHERE it ran rather than only numeric floors";

/// CPU facts. Every slot is optional-by-construction.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct CpuFacts {
    pub(crate) arch: &'static str,
    pub(crate) model: Cell<String>,
    pub(crate) logical_cores: Cell<usize>,
}

/// Host memory facts.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct MemoryFacts {
    pub(crate) total_bytes: Cell<u64>,
}

/// Operating-system facts.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct OsFacts {
    pub(crate) family: &'static str,
    pub(crate) name: &'static str,
    pub(crate) kernel_release: Cell<String>,
    pub(crate) distribution: Cell<String>,
}

/// The mount the measured vault actually lived on.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct MountFacts {
    pub(crate) measured_path: String,
    pub(crate) mount_point: String,
    pub(crate) filesystem_type: String,
    pub(crate) device: String,
    pub(crate) options: String,
}

/// Authoritative identity of the host a run happened on.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct NodeIdentity {
    pub(crate) hostname: Cell<String>,
    pub(crate) machine_id: Cell<String>,
    pub(crate) declared_node: Cell<String>,
    pub(crate) declared_location: Cell<String>,
    pub(crate) declared_node_source: &'static str,
    pub(crate) declared_location_source: &'static str,
    pub(crate) designated_first_tokyo_node: &'static str,
    pub(crate) designated_location: &'static str,
    pub(crate) is_designated_first_tokyo_node: bool,
    pub(crate) rule: &'static str,
}

impl NodeIdentity {
    pub(crate) fn collect() -> Self {
        let hostname = read_trimmed("/proc/sys/kernel/hostname");
        let machine_id = read_trimmed("/etc/machine-id");
        let declared_node = declared(NODE_ENV);
        let declared_location = declared(NODE_LOCATION_ENV);
        let is_designated = declared_node.as_deref() == Some(DESIGNATED_FIRST_TOKYO_NODE)
            && declared_location.as_deref() == Some(DESIGNATED_NODE_LOCATION)
            && hostname.is_some()
            && machine_id.is_some();
        Self {
            hostname: Cell::from_option(
                hostname,
                "no hostname is readable on this platform, so the run has no auditable host",
            ),
            machine_id: Cell::from_option(
                machine_id,
                "no machine id is readable on this platform, so the run has no stable host id",
            ),
            declared_node: Cell::from_option(
                declared_node,
                format!("no node was declared for this run via {NODE_ENV}"),
            ),
            declared_location: Cell::from_option(
                declared_location,
                format!("no node location was declared for this run via {NODE_LOCATION_ENV}"),
            ),
            declared_node_source: NODE_ENV,
            declared_location_source: NODE_LOCATION_ENV,
            designated_first_tokyo_node: DESIGNATED_FIRST_TOKYO_NODE,
            designated_location: DESIGNATED_NODE_LOCATION,
            is_designated_first_tokyo_node: is_designated,
            rule: NODE_RULE,
        }
    }

    /// One line explaining the designation verdict, for the publication check.
    pub(crate) fn publication_detail(&self) -> String {
        if self.is_designated_first_tokyo_node {
            return format!(
                "declared node `{DESIGNATED_FIRST_TOKYO_NODE}` in \
                 `{DESIGNATED_NODE_LOCATION}` with a resolved hostname and machine id"
            );
        }
        format!(
            "a publishable full run must declare node `{DESIGNATED_FIRST_TOKYO_NODE}` \
             ({NODE_ENV}) in `{DESIGNATED_NODE_LOCATION}` ({NODE_LOCATION_ENV}) and resolve a \
             hostname and machine id; this run declared node {} and location {}, with hostname {} \
             and machine id {}",
            describe(&self.declared_node),
            describe(&self.declared_location),
            describe(&self.hostname),
            describe(&self.machine_id),
        )
    }
}

fn describe(cell: &Cell<String>) -> String {
    cell.value()
        .map_or_else(|| "<none>".to_owned(), |value| format!("`{value}`"))
}

fn declared(variable: &str) -> Option<String> {
    let raw = std::env::var(variable).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_owned())
}

/// Everything a reader needs to know about where and how a report was made.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct Provenance {
    pub(crate) git_sha: Cell<String>,
    /// WHICH checkout the sha above was read from, or why none was found. A
    /// reader can tell a build-checkout sha from a packaged-binary override
    /// without having to trust the number alone.
    pub(crate) git_sha_source: String,
    pub(crate) target_triple: String,
    pub(crate) node: NodeIdentity,
    pub(crate) cpu: CpuFacts,
    pub(crate) memory: MemoryFacts,
    pub(crate) os: OsFacts,
    pub(crate) filesystem: Cell<MountFacts>,
    pub(crate) plan_hash: String,
    pub(crate) corpus_hash: String,
    /// blake3 over the EXACT cache-event bytes the cache axis read. A pathname
    /// alone would let an edited stream produce a materially different
    /// experiment under an identical provenance block.
    pub(crate) cache_events_hash: Cell<String>,
    pub(crate) cache_events_bytes: usize,
    pub(crate) seed: u64,
    pub(crate) sample_counts: BTreeMap<String, usize>,
    pub(crate) evidence_kind: EvidenceKind,
    pub(crate) captured_at_unix_ms: u64,
    pub(crate) plan_source: String,
    pub(crate) cache_source: String,
    pub(crate) bench_binary: Cell<String>,
}

/// Inputs the caller already knows; the host facts are collected here.
pub(crate) struct ProvenanceInputs {
    pub(crate) plan_hash: String,
    pub(crate) corpus_hash: String,
    pub(crate) cache_events: String,
    pub(crate) seed: u64,
    pub(crate) sample_counts: BTreeMap<String, usize>,
    pub(crate) evidence_kind: EvidenceKind,
    pub(crate) plan_source: String,
    pub(crate) cache_source: String,
    pub(crate) measured_path: PathBuf,
    pub(crate) node: NodeIdentity,
}

impl Provenance {
    pub(crate) fn collect(inputs: ProvenanceInputs) -> Self {
        let cache_bytes = inputs.cache_events.as_bytes();
        let git = git_sha();
        Self {
            git_sha: Cell::from_option(git.sha, git.source.clone()),
            git_sha_source: git.source,
            target_triple: target_triple(),
            node: inputs.node,
            cpu: cpu_facts(),
            memory: memory_facts(),
            os: os_facts(),
            filesystem: Cell::from_option(
                mount_facts(&inputs.measured_path),
                "the mount table is not readable on this platform",
            ),
            plan_hash: inputs.plan_hash,
            corpus_hash: inputs.corpus_hash,
            cache_events_hash: Cell::from_option(
                (!cache_bytes.is_empty()).then(|| blake3::hash(cache_bytes).to_hex().to_string()),
                "this run admitted no cache-event bytes, so there is no cache input to identify",
            ),
            cache_events_bytes: cache_bytes.len(),
            seed: inputs.seed,
            sample_counts: inputs.sample_counts,
            evidence_kind: inputs.evidence_kind,
            captured_at_unix_ms: unix_millis(),
            plan_source: inputs.plan_source,
            cache_source: inputs.cache_source,
            bench_binary: Cell::from_option(
                std::env::current_exe()
                    .ok()
                    .map(|path| path.display().to_string()),
                "the running executable path is not resolvable",
            ),
        }
    }
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Target triple assembled from the compile-time target cfgs. This is the
/// triple the binary was BUILT for, not a runtime guess about the host.
pub(crate) fn target_triple() -> String {
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;
    let vendor = if cfg!(target_vendor = "apple") {
        "apple"
    } else if cfg!(target_vendor = "pc") {
        "pc"
    } else {
        "unknown"
    };
    let environment = if cfg!(target_env = "gnu") {
        Some("gnu")
    } else if cfg!(target_env = "musl") {
        Some("musl")
    } else if cfg!(target_env = "msvc") {
        Some("msvc")
    } else {
        None
    };
    match environment {
        Some(environment) => format!("{arch}-{vendor}-{os}-{environment}"),
        None => format!("{arch}-{vendor}-{os}"),
    }
}

fn cpu_facts() -> CpuFacts {
    CpuFacts {
        arch: std::env::consts::ARCH,
        model: Cell::from_option(
            cpu_model(),
            "no CPU model string is readable on this platform",
        ),
        logical_cores: Cell::from_option(
            std::thread::available_parallelism().ok().map(Into::into),
            "the available parallelism is not reportable on this platform",
        ),
    }
}

fn cpu_model() -> Option<String> {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    for line in cpuinfo.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        if key == "model name" || key == "Model" || key == "cpu model" {
            return Some(value.trim().to_owned());
        }
    }
    None
}

fn memory_facts() -> MemoryFacts {
    MemoryFacts {
        total_bytes: Cell::from_option(
            meminfo_total_bytes(),
            "no total-memory counter is readable on this platform",
        ),
    }
}

fn meminfo_total_bytes() -> Option<u64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let line = meminfo.lines().find(|line| line.starts_with("MemTotal:"))?;
    let kib: u64 = line
        .trim_start_matches("MemTotal:")
        .trim()
        .trim_end_matches("kB")
        .trim()
        .parse()
        .ok()?;
    Some(kib * 1024)
}

fn os_facts() -> OsFacts {
    OsFacts {
        family: std::env::consts::FAMILY,
        name: std::env::consts::OS,
        kernel_release: Cell::from_option(
            read_trimmed("/proc/sys/kernel/osrelease"),
            "no kernel release string is readable on this platform",
        ),
        distribution: Cell::from_option(
            os_release_pretty_name(),
            "no distribution release file is readable on this platform",
        ),
    }
}

/// Reads a file and trims it, treating an empty result as absent.
pub(crate) fn read_trimmed(path: &str) -> Option<String> {
    let raw = std::fs::read_to_string(path).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_owned())
}

fn os_release_pretty_name() -> Option<String> {
    let contents = std::fs::read_to_string("/etc/os-release").ok()?;
    for line in contents.lines() {
        let Some(value) = line.strip_prefix("PRETTY_NAME=") else {
            continue;
        };
        return Some(value.trim_matches('"').to_owned());
    }
    None
}

// ─── mount table ─────────────────────────────────────────────────────────

/// The mount entry whose mount point is the longest prefix of `path`.
pub(crate) fn mount_facts(path: &Path) -> Option<MountFacts> {
    let mounts = std::fs::read_to_string("/proc/self/mounts").ok()?;
    let target = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mut best: Option<MountFacts> = None;
    let mut best_len = 0_usize;
    for line in mounts.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let mount_point = PathBuf::from(unescape_mount_field(fields[1]));
        if !target.starts_with(&mount_point) {
            continue;
        }
        let len = mount_point.as_os_str().len();
        if best.is_some() && len <= best_len {
            continue;
        }
        best_len = len;
        best = Some(MountFacts {
            measured_path: target.display().to_string(),
            mount_point: mount_point.display().to_string(),
            filesystem_type: fields[2].to_owned(),
            device: unescape_mount_field(fields[0]),
            options: fields[3].to_owned(),
        });
    }
    best
}

/// `/proc/self/mounts` octal-escapes space, tab, newline and backslash.
fn unescape_mount_field(field: &str) -> String {
    field
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

// ─── git sha ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
struct GitShaResolution {
    sha: Option<String>,
    source: String,
}

/// Resolves THIS BENCHMARK binary's checkout HEAD by reading Git's on-disk
/// refs. The caller's current directory is deliberately never consulted: an
/// absolute `perf run --plan ... --out ...` may be launched from any checkout.
fn git_sha() -> GitShaResolution {
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
fn git_sha_from_provenance(
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

    #[test]
    fn target_triple_names_the_build_target() {
        let triple = target_triple();
        assert!(triple.starts_with(std::env::consts::ARCH), "{triple}");
        assert!(triple.contains(std::env::consts::OS), "{triple}");
        assert!(triple.split('-').count() >= 3, "{triple}");
    }

    #[test]
    fn mount_lookup_prefers_the_longest_matching_mount_point() {
        // Only meaningful where a mount table exists; elsewhere the cell is
        // explicitly not-ready, which is itself the contract.
        let dir = tempfile::tempdir().expect("tempdir");
        match mount_facts(dir.path()) {
            Some(facts) => {
                assert!(!facts.mount_point.is_empty());
                assert!(!facts.filesystem_type.is_empty());
                assert!(facts.measured_path.starts_with(facts.mount_point.as_str()));
            }
            None => assert!(
                std::fs::metadata("/proc/self/mounts").is_err(),
                "a readable mount table must resolve a mount for a temp dir"
            ),
        }
    }

    #[test]
    fn mount_fields_are_unescaped() {
        assert_eq!(unescape_mount_field("/mnt/my\\040disk"), "/mnt/my disk");
        assert_eq!(unescape_mount_field("/dev/nvme0n1p2"), "/dev/nvme0n1p2");
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

    /// Node identity is captured for every run, and a host that did not
    /// declare the designated node is NOT the designated node.
    #[test]
    fn node_identity_is_captured_and_designation_is_declared_not_assumed() {
        let identity = NodeIdentity::collect();
        assert_eq!(identity.designated_first_tokyo_node, "tokyo-1");
        assert_eq!(identity.designated_location, "tokyo");
        assert_eq!(identity.declared_node_source, NODE_ENV);
        assert_eq!(identity.declared_location_source, NODE_LOCATION_ENV);
        if identity.declared_node.value().map(String::as_str) != Some(DESIGNATED_FIRST_TOKYO_NODE) {
            assert!(
                !identity.is_designated_first_tokyo_node,
                "a host that did not declare the designated node cannot be it"
            );
            let detail = identity.publication_detail();
            assert!(detail.contains(NODE_ENV), "{detail}");
            assert!(detail.contains(DESIGNATED_FIRST_TOKYO_NODE), "{detail}");
        }
        let rendered = serde_json::to_string(&identity).expect("identity renders");
        assert!(
            rendered.contains("is_designated_first_tokyo_node"),
            "{rendered}"
        );
    }

    /// The cache stream that produced the reported hit rates must be
    /// identifiable by CONTENT: two different streams under the same pathname
    /// must not share a provenance block.
    #[test]
    fn cache_event_bytes_are_hashed_into_provenance() {
        let dir = tempfile::tempdir().expect("tempdir");
        let build = |events: &str| {
            Provenance::collect(ProvenanceInputs {
                plan_hash: "plan".to_owned(),
                corpus_hash: "corpus".to_owned(),
                cache_events: events.to_owned(),
                seed: 1579,
                sample_counts: BTreeMap::new(),
                evidence_kind: EvidenceKind::SyntheticSmoke,
                plan_source: "same/path/plan.json".to_owned(),
                cache_source: "same/path/cache.jsonl".to_owned(),
                measured_path: dir.path().to_path_buf(),
                node: NodeIdentity::collect(),
            })
        };
        let left = build(r#"{"rung":"embedding","outcome":"hit","source":"real_traffic"}"#);
        let right = build(r#"{"rung":"embedding","outcome":"miss","source":"real_traffic"}"#);

        assert_eq!(left.plan_hash, right.plan_hash);
        assert_eq!(left.cache_source, right.cache_source);
        assert!(left.cache_events_hash.is_measured());
        assert_ne!(
            left.cache_events_hash, right.cache_events_hash,
            "editing the cache stream must change provenance even under one pathname"
        );
        assert_eq!(
            left.cache_events_bytes,
            r#"{"rung":"embedding","outcome":"hit","source":"real_traffic"}"#.len(),
            "the byte count must describe the stream that was actually hashed"
        );

        let empty = build("");
        assert!(
            !empty.cache_events_hash.is_measured(),
            "no admitted bytes means no cache input to identify, not a hash of nothing"
        );
    }
}
