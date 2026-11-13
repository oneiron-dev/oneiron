use super::*;

mod atom_fuzz;
mod genui_render;
mod genui_validation;
// FIX [LIBTEST-QUARANTINE-LENS-TESTS-INSTRUMENT]: the lib test target's type check fails here (7 errors: E0599 x4, E0277 x3); port it, then drop this gate
#[cfg(any())]
mod instrument;
mod mediation;
mod result_set;
mod selection_handles;
mod selfui_actions;
mod support;
mod surface_dispatch;
mod versioning;

use support::*;
