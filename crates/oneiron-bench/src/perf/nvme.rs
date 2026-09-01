//! ONE-1579 axis 8: the descriptive NVMe sequential/random fsync row.
//!
//! This row describes the STORAGE a run sat on. It is never an engine
//! benchmark row, and it never invents a value: if the vault's backing block
//! device cannot be resolved, or resolves to something that is not NVMe, the
//! fsync loop is NOT RUN AT ALL and the latency cells stay `not_ready`.
//!
//! Two things the row is careful about:
//!
//! * the scratch file is FULLY ALLOCATED and persisted before the timed window
//!   opens. A truncated-to-zero file would make every sequential sample an
//!   append and every random sample a sparse-file extension, so the row would
//!   report allocation and size-update cost rather than overwrite fsync
//!   latency;
//! * the report carries COMPLETED operation counts beside the requested ones.
//!   A run that skipped the loop, or stopped part way, says how many
//!   operations actually happened instead of restating what was asked for.

use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use std::time::Instant;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::Serialize;

use super::cells::{Cell, EvidenceKind, Percentiles};
use super::provenance::{mount_facts, read_trimmed};

/// Byte the setup pass fills the scratch file with.
const SCRATCH_FILL_BYTE: u8 = 0x5A;
/// Byte the timed pass overwrites with, so a sample is a genuine rewrite of
/// bytes that already exist rather than a first touch.
const SCRATCH_OVERWRITE_BYTE: u8 = 0xA5;
/// Refusal bar for the scratch file. A plan that would size the descriptive
/// probe past this is refused rather than allowed to fill the vault's mount.
const MAX_SCRATCH_BYTES: u64 = 1024 * 1024 * 1024;

const NVME_NOTE: &str = "descriptive external hardware row: it characterises the storage the run \
     sat on and is never an engine performance claim; when the backing device cannot be resolved \
     as NVMe the fsync loop is not run at all and the cells stay not_ready";
const PRESIZE_RULE: &str = "the scratch file is set to ops*block_bytes and every block is written \
     and fsynced BEFORE the timed window opens, so a timed sample measures an overwrite fsync on \
     already-allocated blocks rather than file growth, block allocation or a size update";
const COMPLETED_RULE: &str = "*_ops are what the plan requested; *_ops_completed are how many \
     operations actually ran and were timed, which is 0 whenever the probe was skipped";

/// Backing block device facts for the NVMe row.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct BlockDeviceFacts {
    pub(crate) device: String,
    pub(crate) disk: String,
    pub(crate) is_nvme: bool,
    pub(crate) rotational: Cell<bool>,
}

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
    pub(crate) sequential_ops_completed: usize,
    pub(crate) random_ops_completed: usize,
    pub(crate) scratch_bytes: Cell<u64>,
    pub(crate) sequential_fsync_ms: Cell<Percentiles>,
    pub(crate) random_fsync_ms: Cell<Percentiles>,
    pub(crate) presize_rule: &'static str,
    pub(crate) completed_ops_rule: &'static str,
    pub(crate) evidence_kind: EvidenceKind,
    pub(crate) note: &'static str,
}

impl NvmeFsyncAxis {
    /// Operations that actually ran. Provenance reports THIS, never the
    /// requested count.
    pub(crate) const fn completed_ops(&self) -> usize {
        self.sequential_ops_completed + self.random_ops_completed
    }

    /// Whether the NVMe sanity result is good enough for a publishable full
    /// report: the device resolved as NVMe and both fsync rows were measured.
    pub(crate) fn sanity_ok(&self) -> bool {
        self.status == "measured"
            && self
                .device
                .value()
                .is_some_and(|facts| facts.is_nvme)
            && self.sequential_fsync_ms.is_measured()
            && self.random_fsync_ms.is_measured()
    }

    /// One line explaining the sanity verdict, for the publication check.
    pub(crate) fn publication_detail(&self) -> String {
        let device = self
            .device
            .value()
            .map_or_else(|| "<unresolved>".to_owned(), |facts| facts.device.clone());
        format!(
            "backing device {device}, status `{}`, {} of {} sequential and {} of {} random fsync \
             operations completed; a publishable full run needs a resolved NVMe device with both \
             fsync rows measured",
            self.status,
            self.sequential_ops_completed,
            self.sequential_ops,
            self.random_ops_completed,
            self.random_ops,
        )
    }
}

/// Fsync sizing for one descriptive NVMe row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NvmeProbe {
    pub(crate) sequential_ops: usize,
    pub(crate) random_ops: usize,
    pub(crate) block_bytes: usize,
    pub(crate) seed: u64,
}

/// One completed fsync pass.
#[derive(Debug)]
struct FsyncPass {
    samples: Vec<f64>,
    scratch_bytes: u64,
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
        return skipped(probe, device, reason);
    }

    let sequential = fsync_samples(dir, probe, false);
    let random = fsync_samples(dir, probe, true);
    let sequential_fsync_ms = samples_cell(&sequential);
    let random_fsync_ms = samples_cell(&random);
    let status = if sequential_fsync_ms.is_measured() && random_fsync_ms.is_measured() {
        "measured"
    } else {
        "not_ready"
    };
    let scratch_bytes = sequential
        .as_ref()
        .ok()
        .map(|pass| pass.scratch_bytes)
        .max(random.as_ref().ok().map(|pass| pass.scratch_bytes));
    NvmeFsyncAxis {
        status,
        descriptive_only: true,
        device,
        block_bytes: probe.block_bytes,
        sequential_ops: probe.sequential_ops,
        random_ops: probe.random_ops,
        sequential_ops_completed: completed(&sequential),
        random_ops_completed: completed(&random),
        scratch_bytes: Cell::from_option(
            scratch_bytes,
            "no fsync pass sized a scratch file in this run",
        ),
        sequential_fsync_ms,
        random_fsync_ms,
        presize_rule: PRESIZE_RULE,
        completed_ops_rule: COMPLETED_RULE,
        evidence_kind: EvidenceKind::DescriptiveExternal,
        note: NVME_NOTE,
    }
}

/// The row for a host where the probe was deliberately not run. Requested
/// counts are reported as requested; COMPLETED counts are zero.
fn skipped(probe: NvmeProbe, device: Cell<BlockDeviceFacts>, reason: String) -> NvmeFsyncAxis {
    NvmeFsyncAxis {
        status: "not_ready",
        descriptive_only: true,
        device,
        block_bytes: probe.block_bytes,
        sequential_ops: probe.sequential_ops,
        random_ops: probe.random_ops,
        sequential_ops_completed: 0,
        random_ops_completed: 0,
        scratch_bytes: Cell::not_ready(reason.clone()),
        sequential_fsync_ms: Cell::not_ready(reason.clone()),
        random_fsync_ms: Cell::not_ready(reason),
        presize_rule: PRESIZE_RULE,
        completed_ops_rule: COMPLETED_RULE,
        evidence_kind: EvidenceKind::DescriptiveExternal,
        note: NVME_NOTE,
    }
}

fn completed(pass: &Result<FsyncPass, String>) -> usize {
    pass.as_ref().map_or(0, |pass| pass.samples.len())
}

fn samples_cell(pass: &Result<FsyncPass, String>) -> Cell<Percentiles> {
    match pass {
        Ok(pass) => Cell::from_option(
            Percentiles::from_samples(&pass.samples),
            "the fsync probe collected no samples",
        ),
        Err(error) => Cell::not_ready(error.clone()),
    }
}

/// One block write + `fsync` per sample, either walking forward or landing on
/// seeded random block offsets inside the same PRE-SIZED scratch file.
fn fsync_samples(dir: &Path, probe: NvmeProbe, random: bool) -> Result<FsyncPass, String> {
    let ops = if random {
        probe.random_ops
    } else {
        probe.sequential_ops
    };
    if ops == 0 || probe.block_bytes == 0 {
        return Ok(FsyncPass {
            samples: Vec::new(),
            scratch_bytes: 0,
        });
    }
    let scratch_bytes = scratch_size(ops, probe.block_bytes)?;
    let name = if random {
        "perf-fsync-random.bin"
    } else {
        "perf-fsync-sequential.bin"
    };
    let path = dir.join(name);
    let mut file = prepare_scratch(&path, ops, probe.block_bytes)?;

    let block = vec![SCRATCH_OVERWRITE_BYTE; probe.block_bytes];
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
    Ok(FsyncPass {
        samples,
        scratch_bytes,
    })
}

/// `ops * block_bytes`, refused on overflow or past the scratch bar.
fn scratch_size(ops: usize, block_bytes: usize) -> Result<u64, String> {
    let total = (ops as u64)
        .checked_mul(block_bytes as u64)
        .ok_or_else(|| format!("fsync scratch size {ops} * {block_bytes} overflows"))?;
    if total > MAX_SCRATCH_BYTES {
        return Err(format!(
            "fsync scratch size {total} B ({ops} ops * {block_bytes} B) exceeds the \
             {MAX_SCRATCH_BYTES} B bar for a descriptive probe"
        ));
    }
    Ok(total)
}

/// Creates the scratch file at exactly `ops * block_bytes`, WRITES every block
/// it will later overwrite, and persists that setup. Returns the open handle
/// positioned for the timed window.
///
/// The allocation and the size update happen here, outside any timed sample.
fn prepare_scratch(path: &Path, ops: usize, block_bytes: usize) -> Result<File, String> {
    let total = scratch_size(ops, block_bytes)?;
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("fsync scratch file open failed: {error}"))?;
    file.set_len(total)
        .map_err(|error| format!("fsync scratch file could not be sized: {error}"))?;
    let block = vec![SCRATCH_FILL_BYTE; block_bytes];
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("fsync scratch file seek failed: {error}"))?;
    for _ in 0..ops {
        file.write_all(&block)
            .map_err(|error| format!("fsync scratch file could not be initialised: {error}"))?;
    }
    file.sync_all()
        .map_err(|error| format!("fsync scratch file setup could not be persisted: {error}"))?;
    Ok(file)
}

fn write_block_and_fsync(file: &mut File, offset: u64, block: &[u8]) -> std::io::Result<()> {
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

/// Scratch pathname for one pass, used by the presizing regression.
#[cfg(test)]
fn scratch_path(dir: &Path, random: bool) -> std::path::PathBuf {
    dir.join(if random {
        "perf-fsync-random.bin"
    } else {
        "perf-fsync-sequential.bin"
    })
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

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
            assert!(!axis.sanity_ok());
        }
        let rendered = serde_json::to_string(&axis).expect("axis renders");
        assert!(rendered.contains("descriptive_only"));
    }

    /// A skipped probe must report ZERO completed operations while still
    /// reporting what the plan requested. Reporting the requested count as
    /// though it had run is exactly the provenance overstatement this guards.
    #[test]
    fn a_skipped_probe_completes_no_operations() {
        let dir = tempfile::tempdir().expect("tempdir");
        let probe = NvmeProbe {
            sequential_ops: 16,
            random_ops: 16,
            block_bytes: 4096,
            seed: 7,
        };
        let axis = skipped(
            probe,
            Cell::not_ready("no device"),
            "the backing block device is not NVMe".to_owned(),
        );
        assert_eq!(axis.sequential_ops, 16, "the request is still reported");
        assert_eq!(axis.random_ops, 16);
        assert_eq!(
            axis.completed_ops(),
            0,
            "no operation ran, so provenance must see zero rather than 32"
        );
        assert!(!axis.sanity_ok());
        assert!(axis.publication_detail().contains("0 of 16"));

        // The same must hold through the real entry point on a host whose
        // scratch directory has no resolvable NVMe device.
        let axis = describe_nvme_fsync(dir.path(), probe);
        if axis.status == "not_ready" {
            assert_eq!(axis.completed_ops(), 0);
            assert_eq!(axis.sequential_ops + axis.random_ops, 32);
        }
    }

    /// The timed window must open on a file that is already the full size and
    /// already has every block written. A truncated-to-zero file would make
    /// sequential samples appends and random samples sparse extensions.
    #[test]
    fn the_scratch_file_is_allocated_and_persisted_before_the_timed_window() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = scratch_path(dir.path(), true);
        let ops = 8_usize;
        let block_bytes = 4096_usize;

        let file = prepare_scratch(&path, ops, block_bytes).expect("scratch prepares");
        drop(file);

        let metadata = std::fs::metadata(&path).expect("scratch exists");
        assert_eq!(
            metadata.len(),
            (ops * block_bytes) as u64,
            "the scratch file must already be ops*block_bytes before any sample is timed"
        );

        // The LAST block — the one a sparse random write would have to extend
        // into — must already hold the setup pattern, not sparse zeroes.
        let mut file = File::open(&path).expect("scratch reopens");
        file.seek(SeekFrom::Start(((ops - 1) * block_bytes) as u64))
            .expect("seek to the final block");
        let mut tail = vec![0_u8; block_bytes];
        file.read_exact(&mut tail).expect("final block reads back");
        assert!(
            tail.iter().all(|byte| *byte == SCRATCH_FILL_BYTE),
            "the final block must be written by setup, so a timed sample overwrites it"
        );
    }

    /// Both passes run over a pre-sized file and report exactly as many
    /// completed operations as they timed.
    #[test]
    fn both_fsync_passes_complete_every_requested_operation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let probe = NvmeProbe {
            sequential_ops: 4,
            random_ops: 6,
            block_bytes: 512,
            seed: 1579,
        };
        for (random, expected) in [(false, 4_usize), (true, 6)] {
            let pass = fsync_samples(dir.path(), probe, random).expect("pass runs");
            assert_eq!(pass.samples.len(), expected);
            assert_eq!(pass.scratch_bytes, (expected * 512) as u64);
            assert!(pass.samples.iter().all(|sample| *sample >= 0.0));
            assert!(
                !scratch_path(dir.path(), random).exists(),
                "the scratch file is removed after the pass"
            );
        }
    }

    /// A plan that would size the scratch file past the bar, or overflow it,
    /// is refused rather than allowed to fill the vault's mount.
    #[test]
    fn an_oversized_or_overflowing_scratch_size_is_refused() {
        assert_eq!(scratch_size(8, 4096).expect("in range"), 32_768);
        let overflow = scratch_size(usize::MAX, 4096).expect_err("overflow is refused");
        assert!(overflow.contains("overflow"), "{overflow}");
        let oversized = scratch_size(1_048_577, 1024).expect_err("past the bar");
        assert!(oversized.contains("exceeds"), "{oversized}");

        let dir = tempfile::tempdir().expect("tempdir");
        let error = fsync_samples(
            dir.path(),
            NvmeProbe {
                sequential_ops: 1_048_577,
                random_ops: 0,
                block_bytes: 1024,
                seed: 1,
            },
            false,
        )
        .expect_err("an oversized pass is refused before it opens a file");
        assert!(error.contains("exceeds"), "{error}");
    }
}
