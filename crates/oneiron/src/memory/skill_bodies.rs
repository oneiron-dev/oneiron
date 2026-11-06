//! The skill bodies a code-run call's answer carries, witnessed as the
//! answer's native producer returned it (FIX 3608, `crate::skill`).

use super::{Memory, MemoryResult};
use crate::skill::{CarriesSkillBodies, WitnessedAnswer, answer_digest};

impl Memory<'_> {
    /// `answer`, as its producer returned it, with what an answer it made
    /// carries witnessed for the code-run call this surface serves, when the
    /// call's origin asks for it: each skill body, and the BLAKE3 of the
    /// answer as the row encodes it as JSON. Nothing is witnessed for a
    /// refusal, for an answer that carries no body, nor for any other
    /// caller.
    pub(crate) fn witness_skill_bodies<T: CarriesSkillBodies + serde::Serialize>(
        &self,
        answer: MemoryResult<T>,
    ) -> MemoryResult<T> {
        let capture = self
            .host_origin
            .as_ref()
            .and_then(super::HostWriteOrigin::skill_bodies);
        if let (Some(capture), Ok(made)) = (capture, &answer) {
            let bodies = made.skill_bodies();
            // The answer's JSON as the row encodes it, then as its bytes.
            if !bodies.is_empty()
                && let Ok(json) =
                    serde_json::to_value(made).and_then(|json| serde_json::to_vec(&json))
            {
                capture.witness(WitnessedAnswer {
                    answer: answer_digest(&json),
                    bodies,
                });
            }
        }
        answer
    }
}
