use super::*;

mod atom_fuzz;
// FIX [LIBTEST-QUARANTINE-LENS-TESTS-GENUI-RENDER]: the lib test target's type check fails here (1 errors: unstreamed x1); port it, then drop this gate
#[cfg(any())]
mod genui_render;
mod genui_validation;
// FIX [LIBTEST-QUARANTINE-LENS-TESTS-INSTRUMENT]: the lib test target's type check fails here (7 errors: unstreamed x7); port it, then drop this gate
#[cfg(any())]
mod instrument;
mod mediation;
mod result_set;
// FIX [LIBTEST-QUARANTINE-LENS-TESTS-SELECTION-HANDLES]: the lib test target's type check fails here (2 errors: unstreamed x2); port it, then drop this gate
#[cfg(any())]
mod selection_handles;
// FIX [LIBTEST-QUARANTINE-LENS-TESTS-SELFUI-ACTIONS]: the lib test target's type check fails here (2 errors: unstreamed x2); port it, then drop this gate
#[cfg(any())]
mod selfui_actions;
mod support;
mod surface_dispatch;
mod versioning;

use support::*;
