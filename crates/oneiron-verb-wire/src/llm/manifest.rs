//! Moved from `crates/oneiron/src/llm/manifest.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Result;
pub use oneiron_contracts::claim::ConfidenceBand;
pub use oneiron_contracts::claim::VerdictBasis;
use oneiron_model::llm::ModelId;
use oneiron_model::llm::ModelLocality;
pub use oneiron_model::model_binding::CalibratedVerdict;
pub use oneiron_model::model_binding::MODEL_ROLES;
pub use oneiron_model::model_binding::ModelBinding;
pub use oneiron_model::model_binding::ModelDisposition;
pub use oneiron_model::model_binding::ModelRole;
pub use oneiron_model::model_binding::ModelSlot;
pub use oneiron_model::model_binding::VerdictBinding;
pub use oneiron_model::model_binding::VerdictMode;
use oneiron_model::model_binding::invalid;
pub use oneiron_model::teacher_probe_policy::TEACHER_PROBE_ID;
pub use oneiron_model::teacher_probe_policy::TeacherProbePolicy;

pub fn model_for_route(
    binding: &ModelBinding,
    route: ModelLocality,
    widest: ModelLocality,
) -> Result<&ModelId> {
    if route == widest {
        Ok(&binding.model)
    } else {
        binding
            .route_models
            .get(&route)
            .ok_or_else(|| invalid("resident route has no model binding"))
    }
}

pub fn route_rank(route: ModelLocality) -> u8 {
    match route {
        ModelLocality::OnDevice => 0,
        ModelLocality::OwnServer => 1,
        ModelLocality::ThirdParty => 2,
    }
}
pub mod doors;
pub mod teacher_probe;
