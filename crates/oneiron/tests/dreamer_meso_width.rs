//! FIX 21927 P2: the lead's DREAMER-WIDTH ruling (13 Nov 2026) lets
//! clean Generated Dreamer priors run wide, while any tool-output or imported
//! member holds the whole Meso partition serial.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test dreamer_meso_width`

#![cfg(oneiron_test_support)]

use oneiron::test_doors::meso_extraction_width::{PriorScenario, meso_extraction_width};

#[test]
fn meso_extraction_runs_wide_over_generated_priors() {
    let result = meso_extraction_width(PriorScenario::Generated)
        .expect("real Meso pass over an admitted Generated/generated prior");
    assert_eq!(
        result.peak_extraction_calls_in_flight, 4,
        "four one-TURN slices must run wide: extraction_calls={}; {:?}",
        result.extraction_calls, result.diagnostics,
    );
}

#[test]
fn meso_extraction_stays_serial_over_a_tool_output_descended_prior() {
    let result = meso_extraction_width(PriorScenario::ToolOutputDescended)
        .expect("real Meso pass over admitted clean and tool-output-descended Dreamer priors");
    assert_eq!(
        result.peak_extraction_calls_in_flight, 1,
        "one ToolOutput/tool_output head holds the mixed bucket serial: extraction_calls={}; {:?}",
        result.extraction_calls, result.diagnostics,
    );
}

#[test]
fn meso_extraction_stays_serial_over_an_imported_prior() {
    let result = meso_extraction_width(PriorScenario::Imported)
        .expect("real Meso pass over admitted clean and Imported/imported Dreamer priors");
    assert_eq!(
        result.peak_extraction_calls_in_flight, 1,
        "one Imported/imported head holds the mixed bucket serial: extraction_calls={}; {:?}",
        result.extraction_calls, result.diagnostics,
    );
}
