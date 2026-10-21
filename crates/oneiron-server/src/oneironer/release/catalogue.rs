//! The shipped release catalogue (FIX 6755). One release ships: the
//! format-2 bundle `b8cf6fb2f5d71020`, pinned file by file with the sizes
//! and SHA-256 digests the publisher read back from Hugging Face after
//! upload, smallest first. Its two archives name the platform row each
//! installs, so a fetch places only the ones it selects, and once the
//! manifest's own pin verifies, [`platform_rows`] holds each archive's pin
//! to its manifest row. The format-1 release `fde950a412728a86` is no
//! longer shipped, since this build reads format 2 only; git keeps its row.

use std::borrow::Cow;

use super::{ONEIRONER_LICENCE, OneironerFetchError, OneironerRelease, ReleaseFile};
use crate::embedder::model_manager::PinnedArtifact;
use crate::oneironer::bundle::{COREML_ROW, MLX_ROW, Manifest, Platform};

/// A file every bundle of the release holds.
const fn common(file: &'static str, sha256: &'static str, bytes: u64) -> ReleaseFile {
    ReleaseFile {
        artifact: pinned(file, sha256, bytes),
        platform: None,
    }
}

/// The archive the platform row `row` installs.
const fn archive(
    row: &'static str,
    file: &'static str,
    sha256: &'static str,
    bytes: u64,
) -> ReleaseFile {
    ReleaseFile {
        artifact: pinned(file, sha256, bytes),
        platform: Some(row),
    }
}

const fn pinned(file: &'static str, sha256: &'static str, bytes: u64) -> PinnedArtifact {
    PinnedArtifact {
        file: Cow::Borrowed(file),
        sha256,
        bytes,
    }
}

/// Stack `b8cf6fb2f5d71020`: checkpoint `eeeaf8bea4e8d166`, 53 labels, the
/// Candle files with the Core ML model and the MLX worker beside them.
const B8CF6FB2F5D71020_FILES: [ReleaseFile; 8] = [
    common(
        "config.json",
        "2ea2cb7d559c6315558e91dab54893c169a0af12c762bd5fff303e7a996e5768",
        1_349,
    ),
    common(
        "oneironer.json",
        "b8cf6fb2f5d71020569ebd04b68a6f555283639027a7b971d67e8b20abe66a90",
        5_106,
    ),
    common(
        "char_config.json",
        "c7a097ff34650e547c9cb43fc2229ca0fa612e81d71ac57359bf43d42306945c",
        139_172,
    ),
    common(
        "parity.json",
        "5003f4392af2319c378c441beb7d6bba4c4c432f059a70128f6a4bc32dcb8df1",
        280_410,
    ),
    common(
        "tokenizer.json",
        "f59925fcb90c92b894cb93e51bb9b4a6105c5c249fe54ce1c704420ac39b81af",
        17_082_756,
    ),
    archive(
        COREML_ROW,
        "coreml-ane-port-v1.mlmodelc.tar",
        "a0807d1649893b8340cb5995e55683355704fa6f4d393b91d0c21ecf3cf563b9",
        237_588_480,
    ),
    archive(
        MLX_ROW,
        "oneironer-mlx-worker-0.2.0-macos-arm64.tar",
        "04ead8bc9fc96fc1662041a09c22fc89dc789e1aabee125bb6f114cf151a6d88",
        350_044_160,
    ),
    common(
        "trunk.safetensors",
        "eeeaf8bea4e8d166f0fa252124b13d6d8c2d8d8081253d20a02ad47873e93008",
        1_226_637_420,
    ),
];

const B8CF6FB2F5D71020: OneironerRelease = OneironerRelease {
    stack_sha16: "b8cf6fb2f5d71020",
    checkpoint_sha16: "eeeaf8bea4e8d166",
    label_count: 53,
    licence: ONEIRONER_LICENCE,
    files: &B8CF6FB2F5D71020_FILES,
};

/// Every shipped release, the default first.
pub(super) const ONEIRONER_RELEASES: &[OneironerRelease] = &[B8CF6FB2F5D71020];

/// Each archive of `release`, by its row name, with the manifest row it
/// installs, once its pin is that row's own archive: the same file, SHA-256
/// and size. A pinned archive with no row, or a row with no pinned archive,
/// is a catalogue its manifest disowns.
pub(super) fn platform_rows<'m>(
    release: &OneironerRelease,
    manifest: &'m Manifest,
) -> Result<Vec<(&'static str, &'static ReleaseFile, &'m Platform)>, OneironerFetchError> {
    let disowned = |reason: String| OneironerFetchError::Manifest { reason };
    let mut rows = Vec::new();
    for file in release.files {
        let Some(name) = file.platform else {
            continue;
        };
        let pin = &file.artifact;
        let Some(row) = manifest.platform(name) else {
            return Err(disowned(format!("it has no platform row {name}")));
        };
        let shipped = row.artifact();
        if shipped.file != *pin.file || shipped.sha256 != pin.sha256 || shipped.bytes != pin.bytes {
            return Err(disowned(format!(
                "platform row {name} is not the pinned {}",
                pin.file
            )));
        }
        rows.push((name, file, row));
    }
    for row in &manifest.platforms {
        if !rows.iter().any(|(name, ..)| *name == row.name()) {
            return Err(disowned(format!("platform row {} has no pin", row.name())));
        }
    }
    Ok(rows)
}
