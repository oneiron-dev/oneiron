//! Local references to occurrences in the host's actual publisher inputs.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::{CandidateRun, CodeFixSettled, PublisherCandidate, PublisherCandidateKind};
use crate::dreamer_runner::shadow_values::EngineArtifactPin;
use crate::failure_signals::CodeFixVerdict;

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

/// Pairs every candidate in the host's full input slice with its local reference.
/// Use the complete slice before filtering; equal ids and inputs take their
/// occurrence numbers from collection order. This is association data only,
/// not proof of external publisher identity or authority.
#[must_use]
pub fn publisher_candidates_with_refs(
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

impl CodeFixSettled {
    /// Joins a candidate-fix record's public id to every retained local publisher
    /// run and its input in the host's full candidate slice. This uses the queued id
    /// kept with the run, not the candidate label alone. Coach drafts, withheld
    /// runs and inputs no longer in the supplied slice do not match.
    ///
    /// Pass the complete slice, not only missing candidates: identical inputs
    /// take their occurrence numbers from that slice. All matches are returned;
    /// this is not a uniqueness, publisher identity or delivery-eligibility proof.
    /// Queue acknowledgement does not remove the local work this view reads,
    /// but the owner's erasure or cleanup can. Nothing is queued or exported.
    #[must_use]
    pub fn publisher_candidates_for_result<'work, 'inputs>(
        &'work self,
        result_id: &str,
        pinned: &'inputs [PublisherCandidate],
    ) -> Vec<(&'work CandidateRun, &'inputs PublisherCandidate)> {
        let pinned = publisher_candidates_with_refs(pinned);
        let mut matches = Vec::new();
        for run in &self.candidates {
            if !matches!(&run.export, CodeFixVerdict::Queued { id } if id == result_id) {
                continue;
            }
            for (candidate, publisher_ref) in &pinned {
                if run.matches_publisher(&candidate.id, Some(publisher_ref)) {
                    matches.push((run, *candidate));
                }
            }
        }
        matches
    }
}
