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
//! * the BUILD REVISION is BLAKE3 over the running executable image and is
//!   independent of any checkout or caller cwd. A build-time Git SHA can ride
//!   beside it when CI embedded one; the associated source-checkout HEAD is a
//!   separate descriptive observation so a branch advance after compilation
//!   can never rewrite artifact identity;
//! * the CACHE-EVENT HASH covers the exact bytes the cache axis read, so the
//!   stream that produced the reported hit rates is identifiable and cannot be
//!   swapped without changing provenance;
//! * the NODE IDENTITY names the host and says whether it is the designated
//!   first Tokyo node, which the publication predicate requires. Designation
//!   is bound to the host identity this process OBSERVES — its kernel hostname
//!   and machine id — matched against an allowlist embedded at compile time. A
//!   free-form runtime claim is recorded as the operator's declaration and is
//!   necessary, but it is never sufficient: any host can export
//!   `ONEIRON_BENCH_NODE=tokyo-1`, and none can rewrite the artifact's
//!   allowlist or the identity the kernel reports.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use super::build_profile::BuildProfile;
use super::cells::{Cell, EvidenceKind};
use super::corpus::{CorpusMarkerEvidence, CorpusQueryEvidence};
use super::git_sha::{
    build_git_sha, build_tree_dirty, running_executable_blake3, source_checkout_git_sha,
};

/// Environment variable declaring which node this run happened on.
pub(crate) const NODE_ENV: &str = "ONEIRON_BENCH_NODE";
/// Environment variable declaring that node's location.
pub(crate) const NODE_LOCATION_ENV: &str = "ONEIRON_BENCH_NODE_LOCATION";
/// The node a publishable full run must be produced on.
pub(crate) const DESIGNATED_FIRST_TOKYO_NODE: &str = "tokyo-1";
/// The location that node must declare.
pub(crate) const DESIGNATED_NODE_LOCATION: &str = "tokyo";
/// Compile-time allowlist of the OBSERVED host identities that are the
/// designated first Tokyo node.
///
/// Entries are `hostname/machine-id` pairs separated by commas, semicolons or
/// newlines; blank entries and `#` comments are ignored. Both halves are
/// required, because either alone is guessable or shared. The allowlist is
/// embedded with `option_env!` so it is part of the artifact rather than
/// something the measured host can assert about itself, and an artifact that
/// embedded no allowlist designates nothing at all.
pub(crate) const TOKYO_NODE_ALLOWLIST_ENV: &str = "ONEIRON_BENCH_TOKYO_NODE_ALLOWLIST";
const COMPILE_TIME_TOKYO_ALLOWLIST: Option<&str> =
    option_env!("ONEIRON_BENCH_TOKYO_NODE_ALLOWLIST");

const NODE_RULE: &str = "a publishable full run must run on an OBSERVED host identity (kernel \
     hostname plus machine id) that appears on the allowlist compiled into this artifact, and \
     must additionally declare the designated first Tokyo node and its location; the declaration \
     is an operator claim any host can make, so it is necessary but never sufficient, and a \
     non-allowlisted host cannot publish however it labels itself";

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
    /// Where the artifact's allowlist of observed identities came from.
    pub(crate) observed_identity_allowlist_source: &'static str,
    /// How many identities that allowlist carries. Zero designates nothing.
    pub(crate) observed_identity_allowlist_entries: usize,
    /// The OBSERVED hostname and machine id appear together on the allowlist
    /// compiled into this artifact. This is the binding fact; the declared
    /// node/location beside it is only the operator's claim.
    pub(crate) observed_identity_allowlisted: bool,
    pub(crate) is_designated_first_tokyo_node: bool,
    pub(crate) rule: &'static str,
}

impl NodeIdentity {
    pub(crate) fn collect() -> Self {
        Self::resolve(
            read_trimmed("/proc/sys/kernel/hostname"),
            read_trimmed("/etc/machine-id"),
            COMPILE_TIME_TOKYO_ALLOWLIST,
        )
    }

    /// The designation decision over one observed identity and one allowlist,
    /// so every branch is reachable from a test without recompiling.
    fn resolve(
        hostname: Option<String>,
        machine_id: Option<String>,
        allowlist: Option<&str>,
    ) -> Self {
        let declared_node = declared(NODE_ENV);
        let declared_location = declared(NODE_LOCATION_ENV);
        let entries = allowlist_entries(allowlist);
        // The BINDING fact: the identity this process observed is one the
        // artifact was built to accept. A host that merely claims the node name
        // cannot reach this, and a host on the allowlist that forgot to declare
        // its node still does not publish — both halves are required.
        let observed = hostname.as_deref().zip(machine_id.as_deref());
        let allowlisted = observed.is_some_and(|(host, machine)| {
            entries
                .iter()
                .any(|(listed, id)| listed == host && id == machine)
        });
        let is_designated = allowlisted
            && declared_node.as_deref() == Some(DESIGNATED_FIRST_TOKYO_NODE)
            && declared_location.as_deref() == Some(DESIGNATED_NODE_LOCATION);
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
            observed_identity_allowlist_source: TOKYO_NODE_ALLOWLIST_ENV,
            observed_identity_allowlist_entries: entries.len(),
            observed_identity_allowlisted: allowlisted,
            is_designated_first_tokyo_node: is_designated,
            rule: NODE_RULE,
        }
    }

    /// One line explaining the designation verdict, for the publication check.
    pub(crate) fn publication_detail(&self) -> String {
        if self.is_designated_first_tokyo_node {
            return format!(
                "observed host {}/{} is on this artifact's {} entry allowlist and declared node \
                 `{DESIGNATED_FIRST_TOKYO_NODE}` in `{DESIGNATED_NODE_LOCATION}`",
                describe(&self.hostname),
                describe(&self.machine_id),
                self.observed_identity_allowlist_entries,
            );
        }
        format!(
            "a publishable full run must run on an observed hostname/machine-id pair listed in \
             the artifact's {TOKYO_NODE_ALLOWLIST_ENV} allowlist AND declare node \
             `{DESIGNATED_FIRST_TOKYO_NODE}` ({NODE_ENV}) in `{DESIGNATED_NODE_LOCATION}` \
             ({NODE_LOCATION_ENV}); this run observed hostname {} and machine id {} \
             (allowlisted={} against {} embedded entry/entries) and declared node {} and \
             location {}",
            describe(&self.hostname),
            describe(&self.machine_id),
            self.observed_identity_allowlisted,
            self.observed_identity_allowlist_entries,
            describe(&self.declared_node),
            describe(&self.declared_location),
        )
    }
}

/// Parses the compile-time allowlist into `(hostname, machine_id)` pairs.
///
/// An entry missing either half is DROPPED rather than half-matched: a
/// hostname alone is trivially spoofable and a machine id alone says nothing
/// about which host the operator meant.
fn allowlist_entries(allowlist: Option<&str>) -> Vec<(String, String)> {
    let Some(raw) = allowlist else {
        return Vec::new();
    };
    raw.split(['\n', ',', ';'])
        .map(str::trim)
        .filter(|entry| !entry.is_empty() && !entry.starts_with('#'))
        .filter_map(|entry| {
            let (host, machine) = entry.split_once('/')?;
            let (host, machine) = (host.trim(), machine.trim());
            (!host.is_empty() && !machine.is_empty()).then(|| (host.to_owned(), machine.to_owned()))
        })
        .collect()
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
    /// Immutable identity of the artifact that executed this run. This is
    /// BLAKE3 over the running executable image, so it remains valid outside a
    /// checkout and cannot drift when a branch advances after compilation.
    pub(crate) build_revision_blake3: Cell<String>,
    pub(crate) build_revision_source: String,
    /// Git revision captured by the build environment. Optional because local
    /// Cargo builds may not embed one; it is never inferred from mutable cwd.
    pub(crate) build_git_sha: Cell<String>,
    pub(crate) build_git_sha_source: String,
    /// Whether the tree the artifact was COMPILED from carried uncommitted
    /// changes, declared by the build environment. A SHA alone cannot say
    /// this, and a dirty build's numbers belong to no commit; `not_ready`
    /// means the artifact embedded nothing, never "assumed clean".
    pub(crate) build_tree_dirty: Cell<bool>,
    pub(crate) build_tree_dirty_source: String,
    /// The compile-time optimisation profile of the running executable.
    pub(crate) build_profile: BuildProfile,
    /// Descriptive HEAD of the source checkout associated with the binary at
    /// report time. Kept separate so it cannot masquerade as build revision.
    pub(crate) source_checkout_git_sha: Cell<String>,
    pub(crate) source_checkout_git_sha_source: String,
    pub(crate) target_triple: String,
    pub(crate) node: NodeIdentity,
    pub(crate) cpu: CpuFacts,
    pub(crate) memory: MemoryFacts,
    pub(crate) os: OsFacts,
    pub(crate) filesystem: Cell<MountFacts>,
    pub(crate) plan_hash: String,
    pub(crate) corpus_hash: String,
    pub(crate) corpus_marker_evidence: CorpusMarkerEvidence,
    /// Counted evidence that the run's queries probed as many DISTINCT
    /// documents as it reports queries.
    pub(crate) corpus_query_evidence: CorpusQueryEvidence,
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
    pub(crate) corpus_marker_evidence: CorpusMarkerEvidence,
    pub(crate) corpus_query_evidence: CorpusQueryEvidence,
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
        let build_revision = running_executable_blake3();
        let build_git = build_git_sha();
        let build_dirty = build_tree_dirty();
        let source_git = source_checkout_git_sha();
        Self {
            build_revision_blake3: Cell::from_option(
                build_revision.digest,
                build_revision.source.clone(),
            ),
            build_revision_source: build_revision.source,
            build_git_sha: Cell::from_option(build_git.sha, build_git.source.clone()),
            build_git_sha_source: build_git.source,
            build_tree_dirty: Cell::from_option(build_dirty.dirty, build_dirty.source.clone()),
            build_tree_dirty_source: build_dirty.source,
            build_profile: BuildProfile::collect(),
            source_checkout_git_sha: Cell::from_option(source_git.sha, source_git.source.clone()),
            source_checkout_git_sha_source: source_git.source,
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
            corpus_marker_evidence: inputs.corpus_marker_evidence,
            corpus_query_evidence: inputs.corpus_query_evidence,
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
                build_revision.executable,
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

#[cfg(test)]
mod tests;
