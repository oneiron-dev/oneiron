//! The skill bodies a code-run call's answer carries, witnessed as the
//! answer's native producer returned it (FIX 3608, `crate::skill`).

use super::{Memory, MemoryResult};
use crate::skill::CarriesSkillBodies;

impl Memory<'_> {
    /// `answer`, as its producer returned it, with each skill body an
    /// answer it made carries witnessed for the code-run call this surface
    /// serves, when the call's origin asks for them; nothing is witnessed
    /// for a refusal, nor for any other caller.
    pub(crate) fn witness_skill_bodies<T: CarriesSkillBodies>(
        &self,
        answer: MemoryResult<T>,
    ) -> MemoryResult<T> {
        let capture = self
            .host_origin
            .as_ref()
            .and_then(super::HostWriteOrigin::skill_bodies);
        if let (Some(capture), Ok(answer)) = (capture, &answer) {
            for body in answer.skill_bodies() {
                capture.witness(body);
            }
        }
        answer
    }
}
