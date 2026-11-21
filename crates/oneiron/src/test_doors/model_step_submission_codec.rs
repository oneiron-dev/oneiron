//! Doors for `tests/model_step_submission_codec.rs`
//! (STEP-CORRECTION-HEALTH-PARK): a model step's submission row as it was
//! kept before the correction point, in the named codec its table writes,
//! read as the row is today. Compiled only under `--cfg oneiron_test_support`
//! (`test_doors`); hidden, never API.

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::llm::model_step::{ModelStepResult, ModelStepSubmit};
use crate::side_table::{Named, SideCodec};
use crate::store::model_step_submission::Submission;

/// The submission row's fields before the correction point.
#[derive(Serialize, Deserialize)]
struct RowBeforeCorrectionPoint {
    actor: EntityId,
    input: ModelStepSubmit,
    step_hash: [u8; 32],
    result: Option<ModelStepResult>,
    sends: u8,
}

/// A row kept before the correction point with `input`, `result` and
/// `sends`, as it reads today: those three, once it decodes with no point.
/// `None` when it does not decode, or reads a point.
pub fn read_row_before_correction_point(
    input: ModelStepSubmit,
    result: Option<ModelStepResult>,
    sends: u8,
) -> Option<(ModelStepSubmit, Option<ModelStepResult>, u8)> {
    let kept = RowBeforeCorrectionPoint {
        actor: EntityId::now(),
        input,
        step_hash: [7; 32],
        result,
        sends,
    };
    let bytes = <Named as SideCodec<RowBeforeCorrectionPoint>>::encode(&kept).ok()?;
    let row = <Named as SideCodec<Submission>>::decode(&bytes).ok()?;
    row.correction
        .is_none()
        .then_some((row.input, row.result, row.sends))
}
