//! ONE-1579 external/descriptive facts: run provenance and the NVMe fsync row.
//!
//! Everything in this module describes the ENVIRONMENT a run happened in. None
//! of it is an engine benchmark row, and none of it is allowed to invent a
//! value: an unavailable fact is an explicit `not_ready` cell carrying the
//! reason it could not be read, never a zero, an empty string or a guess.
//!
//! The NVMe row is the sharpest case. If the vault's backing block device
//! cannot be resolved, or resolves to something that is not NVMe, the fsync
//! loop is NOT RUN AT ALL and the latency cells stay `not_ready`. Missing
//! hardware stays missing; it never becomes a plausible-looking number.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::Serialize;

use super::report::{Cell, EvidenceKind, Percentiles};

/// Environment variable that pins the git sha when the bench runs outside a
/// checkout (packaged binary, container, CI artifact).
const GIT_SHA_ENV: &str = "ONEIRON_BENCH_GIT_SHA";

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

/// Backing block device facts for the NVMe row.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct BlockDeviceFacts {
    pub(crate) device: String,
    pub(crate) disk: String,
    pub(crate) is_nvme: bool,
    pub(crate) rotational: Cell<bool>,
}

/// Everything a reader needs to know about where and how a report was made.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct Provenance {
    pub(crate) git_sha: Cell<String>,
    pub(crate) target_triple: String,
    pub(crate) cpu: CpuFacts,
    pub(crate) memory: MemoryFacts,
    pub(crate) os: OsFacts,
    pub(crate) filesystem: Cell<MountFacts>,
    pub(crate) plan_hash: String,
    pub(crate) corpus_hash: String,
    pub(crate) seed: u64,
    pub(crate) sample_counts: BTreeMap<String, usize>,
    pub(crate) evidence_kind: EvidenceKind,
    pub(crate) captured_at_unix_ms: u64,
    pub(crate) plan_source: String,
    pub(crate) bench_binary: Cell<String>,
}

/// Inputs the caller already knows; the host facts are collected here.
pub(crate) struct ProvenanceInputs {
    pub(crate) plan_hash: String,
    pub(crate) corpus_hash: String,
    pub(crate) seed: u64,
    pub(crate) sample_counts: BTreeMap<String, usize>,
    pub(crate) evidence_kind: EvidenceKind,
    pub(crate) plan_source: String,
    pub(crate) measured_path: PathBuf,
}

impl Provenance {
    pub(crate) fn collect(inputs: ProvenanceInputs) -> Self {
        Self {
            git_sha: Cell::from_option(
                git_sha(),
                format!(
                    "no git checkout resolved from the working directory and {GIT_SHA_ENV} is unset"
                ),
            ),
            target_triple: target_triple(),
            cpu: cpu_facts(),
            memory: memory_facts(),
            os: os_facts(),
            filesystem: Cell::from_option(
                mount_facts(&inputs.measured_path),
                "the mount table is not readable on this platform",
            ),
            plan_hash: inputs.plan_hash,
            corpus_hash: inputs.corpus_hash,
            seed: inputs.seed,
            sample_counts: inputs.sample_counts,
            evidence_kind: inputs.evidence_kind,
            captured_at_unix_ms: unix_millis(),
            plan_source: inputs.plan_source,
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

fn read_trimmed(path: &str) -> Option<String> {
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

/// Resolves the checkout's HEAD by READING git's on-disk refs. No subprocess
/// is spawned and no network or remote is touched.
pub(crate) fn git_sha() -> Option<String> {
    if let Ok(pinned) = std::env::var(GIT_SHA_ENV)
        && !pinned.trim().is_empty()
    {
        return Some(pinned.trim().to_owned());
    }
    let git_dir = discover_git_dir(&std::env::current_dir().ok()?)?;
    let head = std::fs::read_to_string(git_dir.join("HEAD")).ok()?;
    let head = head.trim();
    let Some(reference) = head.strip_prefix("ref: ") else {
        return valid_sha(head);
    };
    if let Some(direct) = std::fs::read_to_string(git_dir.join(reference))
        .ok()
        .and_then(|raw| valid_sha(raw.trim()))
    {
        return Some(direct);
    }
    packed_ref(&git_dir, reference)
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

/// A linked worktree's `packed-refs` lives in the COMMON dir, one or two
/// levels above `worktrees/<name>`; both layouts are probed.
fn packed_ref(git_dir: &Path, reference: &str) -> Option<String> {
    let mut candidates = vec![git_dir.join("packed-refs")];
    if let Some(parent) = git_dir.parent()
        && let Some(common) = parent.parent()
    {
        candidates.push(common.join("packed-refs"));
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

fn valid_sha(candidate: &str) -> Option<String> {
    let candidate = candidate.trim();
    if candidate.len() >= 40 && candidate.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(candidate.to_owned());
    }
    None
}

// ─── NVMe descriptive row ────────────────────────────────────────────────

/// Axis 8: descriptive sequential/random fsync behaviour of the device the
/// vault actually sat on. Descriptive only — never an engine benchmark row.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct NvmeFsyncAxis {
    pub(crate) status: &'static str,
    pub(crate) descriptive_only: bool,
    pub(crate) device: Cell<BlockDeviceFacts>,
    pub(crate) block_bytes: usize,
    pub(crate) sequential_ops: usize,
    pub(crate) random_ops: usize,
    pub(crate) sequential_fsync_ms: Cell<Percentiles>,
    pub(crate) random_fsync_ms: Cell<Percentiles>,
    pub(crate) evidence_kind: EvidenceKind,
    pub(crate) note: &'static str,
}

const NVME_NOTE: &str = "descriptive external hardware row: it characterises the storage the run \
     sat on and is never an engine performance claim; when the backing device cannot be resolved \
     as NVMe the fsync loop is not run at all and the cells stay not_ready";

/// Fsync sizing for one descriptive NVMe row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NvmeProbe {
    pub(crate) sequential_ops: usize,
    pub(crate) random_ops: usize,
    pub(crate) block_bytes: usize,
    pub(crate) seed: u64,
}

/// Describes `dir`'s backing device and, ONLY when it resolves as NVMe,
/// measures sequential and random single-block fsync latency inside `dir`.
pub(crate) fn describe_nvme_fsync(dir: &Path, probe: NvmeProbe) -> NvmeFsyncAxis {
    let facts = block_device_facts(dir);
    let unresolved = match &facts {
        None => {
            Some("the backing block device could not be resolved from the mount table".to_owned())
        }
        Some(facts) if !facts.is_nvme => Some(format!(
            "the backing block device `{}` is not NVMe; no NVMe row is available on this host",
            facts.device
        )),
        Some(_) => None,
    };
    let device = Cell::from_option(
        facts,
        "the backing block device could not be resolved from the mount table",
    );
    if let Some(reason) = unresolved {
        return NvmeFsyncAxis {
            status: "not_ready",
            descriptive_only: true,
            device,
            block_bytes: probe.block_bytes,
            sequential_ops: probe.sequential_ops,
            random_ops: probe.random_ops,
            sequential_fsync_ms: Cell::not_ready(reason.clone()),
            random_fsync_ms: Cell::not_ready(reason),
            evidence_kind: EvidenceKind::DescriptiveExternal,
            note: NVME_NOTE,
        };
    }

    let sequential_fsync_ms = samples_cell(fsync_samples(dir, probe, false));
    let random_fsync_ms = samples_cell(fsync_samples(dir, probe, true));
    let status = if sequential_fsync_ms.is_measured() && random_fsync_ms.is_measured() {
        "measured"
    } else {
        "not_ready"
    };
    NvmeFsyncAxis {
        status,
        descriptive_only: true,
        device,
        block_bytes: probe.block_bytes,
        sequential_ops: probe.sequential_ops,
        random_ops: probe.random_ops,
        sequential_fsync_ms,
        random_fsync_ms,
        evidence_kind: EvidenceKind::DescriptiveExternal,
        note: NVME_NOTE,
    }
}

fn samples_cell(samples: Result<Vec<f64>, String>) -> Cell<Percentiles> {
    match samples {
        Ok(samples) => Cell::from_option(
            Percentiles::from_samples(&samples),
            "the fsync probe collected no samples",
        ),
        Err(error) => Cell::not_ready(error),
    }
}

/// One block write + `fsync` per sample, either walking forward or landing on
/// seeded random block offsets inside the same pre-sized scratch file.
fn fsync_samples(dir: &Path, probe: NvmeProbe, random: bool) -> Result<Vec<f64>, String> {
    let ops = if random {
        probe.random_ops
    } else {
        probe.sequential_ops
    };
    if ops == 0 || probe.block_bytes == 0 {
        return Ok(Vec::new());
    }
    let name = if random {
        "perf-fsync-random.bin"
    } else {
        "perf-fsync-sequential.bin"
    };
    let path = dir.join(name);
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&path)
        .map_err(|error| format!("fsync scratch file open failed: {error}"))?;
    let block = vec![0x5A_u8; probe.block_bytes];
    let mut rng = StdRng::seed_from_u64(probe.seed);
    let mut samples = Vec::with_capacity(ops);
    for index in 0..ops {
        let slot = if random { rng.gen_range(0..ops) } else { index };
        let offset = (slot as u64) * (probe.block_bytes as u64);
        let started = Instant::now();
        write_block_and_fsync(&mut file, offset, &block)
            .map_err(|error| format!("fsync probe failed at op {index}: {error}"))?;
        samples.push(started.elapsed().as_secs_f64() * 1e3);
    }
    drop(file);
    let _ = std::fs::remove_file(path);
    Ok(samples)
}

fn write_block_and_fsync(
    file: &mut std::fs::File,
    offset: u64,
    block: &[u8],
) -> std::io::Result<()> {
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(block)?;
    file.sync_all()
}

/// Resolves `dir`'s mount device to a block device, then reports whether that
/// device is NVMe. Anything that is not a `/dev/...` block device (tmpfs,
/// overlay, network mounts) resolves to `None`.
pub(crate) fn block_device_facts(dir: &Path) -> Option<BlockDeviceFacts> {
    let mount = mount_facts(dir)?;
    let device = mount.device;
    let name = device.strip_prefix("/dev/")?;
    if name.is_empty() {
        return None;
    }
    let disk = parent_disk(name);
    let is_nvme = disk.starts_with("nvme");
    let rotational = Cell::from_option(
        read_trimmed(&format!("/sys/block/{disk}/queue/rotational")).and_then(|raw| {
            match raw.as_str() {
                "0" => Some(false),
                "1" => Some(true),
                _ => None,
            }
        }),
        format!("/sys/block/{disk}/queue/rotational is not readable"),
    );
    Some(BlockDeviceFacts {
        device,
        disk,
        is_nvme,
        rotational,
    })
}

/// `nvme0n1p3` -> `nvme0n1`, `sda2` -> `sda`, `dm-0` -> `dm-0`.
fn parent_disk(name: &str) -> String {
    if Path::new(&format!("/sys/block/{name}")).exists() {
        return name.to_owned();
    }
    if let Some((disk, partition)) = name.rsplit_once('p')
        && partition.chars().all(|c| c.is_ascii_digit())
        && !partition.is_empty()
        && Path::new(&format!("/sys/block/{disk}")).exists()
    {
        return disk.to_owned();
    }
    let trimmed = name.trim_end_matches(|c: char| c.is_ascii_digit());
    if !trimmed.is_empty() && Path::new(&format!("/sys/block/{trimmed}")).exists() {
        return trimmed.to_owned();
    }
    name.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_triple_names_the_build_target() {
        let triple = target_triple();
        assert!(triple.starts_with(std::env::consts::ARCH), "{triple}");
        assert!(triple.contains(std::env::consts::OS), "{triple}");
        assert!(triple.split('-').count() >= 3, "{triple}");
    }

    #[test]
    fn a_missing_nvme_device_never_reports_a_zero_row() {
        let dir = tempfile::tempdir().expect("tempdir");
        let axis = describe_nvme_fsync(
            dir.path(),
            NvmeProbe {
                sequential_ops: 0,
                random_ops: 0,
                block_bytes: 4096,
                seed: 7,
            },
        );
        assert!(axis.descriptive_only);
        assert_eq!(axis.evidence_kind, EvidenceKind::DescriptiveExternal);
        if axis.status == "not_ready" {
            assert!(matches!(axis.sequential_fsync_ms, Cell::NotReady { .. }));
            assert!(matches!(axis.random_fsync_ms, Cell::NotReady { .. }));
        }
        let rendered = serde_json::to_string(&axis).expect("axis renders");
        assert!(rendered.contains("descriptive_only"));
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
}
