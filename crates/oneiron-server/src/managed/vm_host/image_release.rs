//! Native VM release evidence. Measurements describe host path bytes before
//! the VMM opens them, never immutable boot inputs or a qualified snapshot.

use super::VaultVm;
use oneiron_container::image_release::{
    Blake3Digest, IMAGE_RELEASE_BINDINGS_ENV, IMAGE_SIGNATURE_POLICY, ImageReleaseObservation,
    LaunchBackend, NoVerifierConfigured, ObservedArtifacts, SelectedImage, observe_bound_release,
};
use oneiron_vault_contract::{UnixTs, now_ts};
use serde::Serialize;
use std::{
    fs::OpenOptions,
    io::{self, Read},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

/// Evidence from the most recent native VM boot or snapshot-load attempt.
/// It does not establish that the attempt succeeded or is still running.
#[derive(Clone, Debug, Serialize)]
pub struct VmImageReleaseObservation {
    /// When this record was made, after any path measurements completed.
    pub recorded_at: UnixTs,
    pub measurement: VmImageMeasurement,
    /// Present only when the binding was absent or both path digests were
    /// measured. Measurement failure is not a claim that no manifest exists.
    pub release: Option<ImageReleaseObservation>,
    /// No native RAM snapshot has a qualified release key yet (FIX 9140).
    pub snapshot_qualified: bool,
}

/// What the host actually measured for this attempt.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum VmImageMeasurement {
    /// No binding map was configured, so neither artifact was read.
    BindingAbsent,
    /// Bytes read from the configured paths before VMM spawn. Firecracker
    /// later opens the original paths; these are not pinned boot identities.
    PreBootPaths {
        kernel: Result<Blake3Digest, String>,
        rootfs: Result<Blake3Digest, String>,
    },
    /// The blocking observation task did not return its measurements.
    Unavailable { reason: String },
    /// A snapshot load measures neither current image paths nor saved RAM.
    SnapshotResumeUnmeasured,
}

impl VaultVm {
    /// The last boot/load attempt's evidence, not current health or an image
    /// admission decision. A snapshot load replaces any earlier cold record.
    pub fn image_release_observation(&self) -> Option<&VmImageReleaseObservation> {
        self.image_release.as_ref()
    }

    pub(super) async fn observe_image_release(&mut self) {
        let kernel = self.config.kernel.clone();
        let rootfs = self.config.rootfs.clone();
        let observation = tokio::task::spawn_blocking(move || observe(&kernel, &rootfs))
            .await
            .unwrap_or_else(|error| VmImageReleaseObservation {
                recorded_at: now_ts(),
                measurement: VmImageMeasurement::Unavailable {
                    reason: error.to_string(),
                },
                release: None,
                snapshot_qualified: false,
            });
        self.record_image_release(observation);
    }

    pub(super) fn observe_snapshot_image_release(&mut self) {
        self.record_image_release(VmImageReleaseObservation {
            recorded_at: now_ts(),
            measurement: VmImageMeasurement::SnapshotResumeUnmeasured,
            release: None,
            snapshot_qualified: false,
        });
    }

    fn record_image_release(&mut self, observation: VmImageReleaseObservation) {
        let measurement_state = match &observation.measurement {
            VmImageMeasurement::BindingAbsent => "binding_absent",
            VmImageMeasurement::PreBootPaths { .. } => "pre_boot_paths",
            VmImageMeasurement::Unavailable { .. } => "unavailable",
            VmImageMeasurement::SnapshotResumeUnmeasured => "snapshot_resume_unmeasured",
        };
        let facts: Vec<&str> = observation
            .release
            .as_ref()
            .map_or_else(Vec::new, |release| {
                release.facts.iter().map(|fact| fact.as_str()).collect()
            });
        tracing::info!(
            reason = "vm_image_release_observed",
            vault = %self.vault,
            measurement_state,
            ?facts,
            snapshot_qualified = observation.snapshot_qualified,
            "native VM image evidence for a boot or snapshot-load attempt"
        );
        self.image_release = Some(observation);
    }
}

fn observe(kernel: &Path, rootfs: &Path) -> VmImageReleaseObservation {
    let (measurement, release) =
        if std::env::var_os(IMAGE_RELEASE_BINDINGS_ENV).is_none_or(|path| path.is_empty()) {
            (
                VmImageMeasurement::BindingAbsent,
                Some(ImageReleaseObservation::manifest_absent(
                    IMAGE_SIGNATURE_POLICY,
                )),
            )
        } else {
            let kernel = digest_file(kernel).map_err(|error| error.to_string());
            let rootfs = digest_file(rootfs).map_err(|error| error.to_string());
            let release = match (&kernel, &rootfs) {
                (Ok(kernel), Ok(rootfs)) => {
                    let observed = ObservedArtifacts {
                        kernel_blake3: Some(Blake3Digest::from_bytes(*kernel)),
                        rootfs_ext4_blake3: Some(Blake3Digest::from_bytes(*rootfs)),
                        ..ObservedArtifacts::default()
                    };
                    Some(observe_bound_release(
                        SelectedImage::Boot {
                            kernel: *kernel,
                            rootfs: *rootfs,
                        },
                        &observed,
                        &NoVerifierConfigured,
                        LaunchBackend::MicroVm,
                    ))
                }
                _ => None,
            };
            (
                VmImageMeasurement::PreBootPaths {
                    kernel: kernel.map(Blake3Digest::from_bytes),
                    rootfs: rootfs.map(Blake3Digest::from_bytes),
                },
                release,
            )
        };
    VmImageReleaseObservation {
        recorded_at: now_ts(),
        measurement,
        release,
        snapshot_qualified: false,
    }
}

fn digest_file(path: &Path) -> io::Result<[u8; 32]> {
    // O_NONBLOCK prevents a FIFO substitution from stalling the open. The
    // opened descriptor, not a preceding path lookup, must be regular.
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    // The initial file length is read geometry, not an artifact size cap.
    // A growing file cannot turn this observation into an endless read.
    let mut bytes = (&mut file).take(before.len());
    let mut hasher = blake3::Hasher::new();
    hasher.update_reader(&mut bytes)?;
    if bytes.limit() != 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "artifact shortened during measurement",
        ));
    }
    let after = file.metadata()?;
    if before.len() != after.len() || before.modified()? != after.modified()? {
        return Err(io::Error::other("artifact changed during measurement"));
    }
    Ok(*hasher.finalize().as_bytes())
}
