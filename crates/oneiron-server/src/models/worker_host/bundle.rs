//! The worker code this binary carries (DESIGN-V2 R2): the house EXL3 server
//! with every module it imports, the llama.cpp launch-identity script, the
//! EXL3 environment lock, and the media workers (FIX 8318): VoxCPM2 speech,
//! local ASR and the module they share. A managed install writes them under
//! the runtime root in a directory named by their digest; nothing is
//! fetched.
//!
//! They are the files in `deploy/house-model/`, `deploy/voxcpm2/`,
//! `deploy/asr/` and `deploy/media-worker/`, read when this crate is built
//! from the source tree.
use sha2::{Digest as _, Sha256};

/// Every file a worker runs from, by the name it is written under.
pub(super) const WORKER_FILES: &[(&str, &[u8])] = &[
    (
        "asr_worker.py",
        include_bytes!("../../../../../deploy/asr/worker.py"),
    ),
    (
        "body_codec.py",
        include_bytes!("../../../../../deploy/house-model/body_codec.py"),
    ),
    (
        "cache_usage.py",
        include_bytes!("../../../../../deploy/house-model/cache_usage.py"),
    ),
    (
        "exl3_ipc.py",
        include_bytes!("../../../../../deploy/house-model/exl3_ipc.py"),
    ),
    (
        "exl3_server.py",
        include_bytes!("../../../../../deploy/house-model/exl3_server.py"),
    ),
    (
        "exl3_session/__init__.py",
        include_bytes!("../../../../../deploy/house-model/exl3_session/__init__.py"),
    ),
    (
        "exl3_session/anchor.py",
        include_bytes!("../../../../../deploy/house-model/exl3_session/anchor.py"),
    ),
    (
        "exl3_session/generator.py",
        include_bytes!("../../../../../deploy/house-model/exl3_session/generator.py"),
    ),
    (
        "exl3_session/jobs.py",
        include_bytes!("../../../../../deploy/house-model/exl3_session/jobs.py"),
    ),
    (
        "exl3_session/layer.py",
        include_bytes!("../../../../../deploy/house-model/exl3_session/layer.py"),
    ),
    (
        "exl3_session/ops.py",
        include_bytes!("../../../../../deploy/house-model/exl3_session/ops.py"),
    ),
    (
        "exl3_session/pages.py",
        include_bytes!("../../../../../deploy/house-model/exl3_session/pages.py"),
    ),
    (
        "exl3_session/registry.py",
        include_bytes!("../../../../../deploy/house-model/exl3_session/registry.py"),
    ),
    (
        "exl3_session/snapshot.py",
        include_bytes!("../../../../../deploy/house-model/exl3_session/snapshot.py"),
    ),
    (
        "exl3_session/state.py",
        include_bytes!("../../../../../deploy/house-model/exl3_session/state.py"),
    ),
    (
        "exl3_stats.py",
        include_bytes!("../../../../../deploy/house-model/exl3_stats.py"),
    ),
    (
        "exl3_tools.py",
        include_bytes!("../../../../../deploy/house-model/exl3_tools.py"),
    ),
    (
        "llama_identity.py",
        include_bytes!("../../../../../deploy/house-model/llama_identity.py"),
    ),
    (
        "voxcpm2_worker.py",
        include_bytes!("../../../../../deploy/voxcpm2/worker.py"),
    ),
    (
        "weights_manifest.py",
        include_bytes!("../../../../../deploy/house-model/weights_manifest.py"),
    ),
    (
        "worker_support.py",
        include_bytes!("../../../../../deploy/media-worker/worker_support.py"),
    ),
];

/// The EXL3 server's script, within the bundle.
pub(super) const EXL3_SERVER: &str = "exl3_server.py";

/// The llama.cpp launch-identity script, within the bundle.
pub(super) const LLAMA_IDENTITY: &str = "llama_identity.py";

/// The VoxCPM2 speech worker's script, within the bundle.
pub(super) const VOXCPM2_WORKER: &str = "voxcpm2_worker.py";

/// The local ASR worker's script, within the bundle.
pub(super) const ASR_WORKER: &str = "asr_worker.py";

/// The EXL3 worker's hash-locked Python environment.
pub(super) const EXL3_LOCK: &[u8] =
    include_bytes!("../../../../../deploy/house-model/requirements-exl3.lock");

/// The bundle's digest: SHA-256 over each file's name, length and bytes, in
/// name order.
pub(super) fn bundle_sha256() -> String {
    let mut digest = Sha256::new();
    for (name, bytes) in WORKER_FILES {
        digest.update(name.as_bytes());
        digest.update([0_u8]);
        digest.update(bytes.len().to_string().as_bytes());
        digest.update([0_u8]);
        digest.update(bytes);
    }
    format!("{:x}", digest.finalize())
}

/// SHA-256 of `bytes`, lowercase hex.
pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
