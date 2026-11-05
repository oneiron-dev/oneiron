//! Local references to occurrences in the host's actual publisher inputs.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::{PublisherCandidate, PublisherCandidateKind};
use crate::dreamer_runner::shadow_values::EngineArtifactPin;

/// The input a publisher candidate actually supplies. A digest compares
/// instruction content; neither variant proves publisher identity or authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PublisherCandidateInput {
    Instruction { digest: [u8; 32] },
    Engine { pin: EngineArtifactPin },
}

/// One occurrence among equal ids and inputs in a full host candidate slice.
/// This is a local input association, not a global publisher identity. Reordering
/// other inputs does not change it; a changed instruction or engine gets a new
/// input. Identical occurrences are numbered in their collection order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublisherCandidateRef {
    pub input: PublisherCandidateInput,
    pub occurrence: usize,
}

pub(super) fn publisher_candidates_with_refs(
    pinned: &[PublisherCandidate],
) -> Vec<(&PublisherCandidate, PublisherCandidateRef)> {
    let mut occurrences: HashMap<(String, PublisherCandidateInput), usize> = HashMap::new();
    pinned
        .iter()
        .map(|candidate| {
            let input = match &candidate.kind {
                PublisherCandidateKind::Instruction { instruction } => {
                    PublisherCandidateInput::Instruction {
                        digest: *blake3::hash(instruction.as_bytes()).as_bytes(),
                    }
                }
                kind @ (PublisherCandidateKind::EngineBuild { .. }
                | PublisherCandidateKind::EnginePatch { .. }) => PublisherCandidateInput::Engine {
                    pin: kind.engine_pin().expect("engine candidates carry a pin"),
                },
            };
            let occurrence = occurrences
                .entry((candidate.id.clone(), input))
                .or_default();
            let publisher_ref = PublisherCandidateRef {
                input,
                occurrence: *occurrence,
            };
            *occurrence += 1;
            (candidate, publisher_ref)
        })
        .collect()
}
