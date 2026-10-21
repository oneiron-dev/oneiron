//! The shipped releases.

use std::borrow::Cow;

use super::{ONEIRONER_LICENCE, OneironerRelease};
use crate::embedder::model_manager::PinnedArtifact;

/// Stack `fde950a412728a86`: checkpoint `eeeaf8bea4e8d166`, 53 labels.
const FDE950A412728A86_FILES: [PinnedArtifact; 5] = [
    PinnedArtifact {
        file: Cow::Borrowed("oneironer.json"),
        sha256: "fde950a412728a86a755a92c65cd25e9159896727e41a32c4dd680150544f6c0",
        bytes: 1_821,
    },
    PinnedArtifact {
        file: Cow::Borrowed("config.json"),
        sha256: "2ea2cb7d559c6315558e91dab54893c169a0af12c762bd5fff303e7a996e5768",
        bytes: 1_349,
    },
    PinnedArtifact {
        file: Cow::Borrowed("char_config.json"),
        sha256: "c7a097ff34650e547c9cb43fc2229ca0fa612e81d71ac57359bf43d42306945c",
        bytes: 139_172,
    },
    PinnedArtifact {
        file: Cow::Borrowed("tokenizer.json"),
        sha256: "f59925fcb90c92b894cb93e51bb9b4a6105c5c249fe54ce1c704420ac39b81af",
        bytes: 17_082_756,
    },
    PinnedArtifact {
        file: Cow::Borrowed("trunk.safetensors"),
        sha256: "eeeaf8bea4e8d166f0fa252124b13d6d8c2d8d8081253d20a02ad47873e93008",
        bytes: 1_226_637_420,
    },
];

const FDE950A412728A86: OneironerRelease = OneironerRelease {
    stack_sha16: "fde950a412728a86",
    checkpoint_sha16: "eeeaf8bea4e8d166",
    label_count: 53,
    licence: ONEIRONER_LICENCE,
    files: &FDE950A412728A86_FILES,
};

/// Every shipped release, the default first.
pub(super) const ONEIRONER_RELEASES: &[OneironerRelease] = &[FDE950A412728A86];
