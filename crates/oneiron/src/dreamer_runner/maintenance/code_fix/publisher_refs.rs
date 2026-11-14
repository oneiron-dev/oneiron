//! Local references to occurrences in the host's actual publisher inputs.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::{CandidateRun, CodeFixSettled, PublisherCandidate, PublisherCandidateKind};
use crate::dreamer_runner::shadow_values::EngineArtifactPin;
use crate::failure_signals::CodeFixVerdict;

#[doc(hidden)]
pub use oneiron_records::dreamer_runner::maintenance::code_fix::publisher_refs::{
    PublisherCandidateInput, PublisherCandidateRef, publisher_candidates_with_refs,
};

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
