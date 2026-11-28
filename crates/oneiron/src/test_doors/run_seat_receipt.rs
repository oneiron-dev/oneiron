//! A run's host seat receipt for market seat tests (FIX
//! MARKET-SEAT-MODEL-STAMP): pin the receipt a seat birth would have written,
//! with no model manifest or decision behind it.

use crate::error::Result;
use crate::llm::seat::SeatChoiceReceipt;
use crate::{EntityId, Vault};
use oneiron_model::llm::{ModelId, ReasoningEffort};

/// Pins `run_id`'s seat on `model` (an engine id, `<provider>/<model>@<revision>`).
///
/// # Errors
///
/// A model id that does not parse; a store failure.
pub fn pin_run_seat(vault: &Vault, run_id: EntityId, model: &str) -> Result<()> {
    let model =
        ModelId::new(model).map_err(|_| crate::error::Error::InvalidConfig("model id".into()))?;
    vault.pin_run_seat_receipt(
        run_id,
        SeatChoiceReceipt {
            model,
            effort: ReasoningEffort::Medium,
            why: "fixture seat".to_owned(),
            reused: false,
            model_decisions: Vec::new(),
            effort_decision: None,
        },
    )
}
