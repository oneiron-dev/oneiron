//! The decision questions' learned knobs (ARCH-0003 #learning-settings; Setting stage 3): catalogue
//! keys a fit learns under the owner's seeds and pins. The crate's build script places each row in the
//! setting catalogue.

use crate::federation::EngineControlClass;
use crate::setting::{Kind, LEARNED_SCOPES, SetBy, lower_is_tighter};

crate::setting::setting_keys! {
    /// The vault's question call budget (ARCH-0076): each decision call's clock,
    /// in milliseconds, when neither the question nor the ask names one. It
    /// ships at a graph ask's default, within the asks' own bounds.
    pub QUESTION_CALL_BUDGET_MS: f64 = "question.call_budget_ms" {
        kind: Kind::new(|| crate::receipt::GRAPH_ASK_UNIT_DEADLINE_MS as f64).tighter(lower_is_tighter::<f64>).learned(1.0, oneiron_base::request_limits::MAX_RECALL_DEADLINE_MS as f64),
        scopes: &LEARNED_SCOPES,
        set_by: SetBy::Class(EngineControlClass::WorkBudget),
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };
}
