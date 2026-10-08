//! Measure the shipped retained XLSX adapter without a precision fallback.
//! The recalculation reads this host's clock and local offset and a fresh
//! random seed, as the edit round trip does without a session clock.
//!
//! Exit status: 0 recalculated natively; 3 the adapter refuses the workbook
//! (`UnsupportedWorkbook`) and 4 the engine fails, both of which the edit
//! round trip hands to the host's precision fallback; 2 the round trip
//! refuses the package or workbook outright. No output is written unless the
//! status is 0; stdout carries one JSON report either way.
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use oneiron_docedit::retained_opc::{Limits, XmlLimits};
use oneiron_xlsx_formula::engine::FormualizerEngine;
use oneiron_xlsx_formula::{FormulaError, RecalcClock};

/// This measurement host's own ceilings. They equal the shipped document
/// resource policy row; a vault host passes its resolved limits instead.
const LIMITS: Limits = Limits {
    archive_bytes: 512 * 1024 * 1024,
    entries: 10_000,
    part_bytes: 64 * 1024 * 1024,
    expanded_bytes: 512 * 1024 * 1024,
    xml: XmlLimits {
        max_depth: 256,
        max_nodes: 1_000_000,
    },
};

fn main() -> Result<ExitCode, Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: recalc_native INPUT.xlsx OUTPUT.xlsx".into());
    }
    let input = PathBuf::from(&args[0]);
    let output = PathBuf::from(&args[1]);
    // Never overwrite a source, existing result, symlink or other caller's file.
    // The corpus harness supplies a fresh per-input output path.
    if output.symlink_metadata().is_ok() {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, "output already exists").into());
    }
    let report = match FormualizerEngine::new().recalculate_xlsx(
        &fs::read(input)?,
        LIMITS,
        &RecalcClock::system(),
    ) {
        Ok(report) => report,
        Err(error) => {
            let status = match error {
                FormulaError::UnsupportedWorkbook(_) => 3,
                FormulaError::Engine(_) => 4,
                _ => 2,
            };
            serde_json::to_writer(
                io::stdout().lock(),
                &serde_json::json!({
                    "code": error.code(),
                    "reason": error.to_string(),
                    "precision_fallback": status != 2,
                }),
            )?;
            return Ok(ExitCode::from(status));
        }
    };
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    file.write_all(&report.bytes)?;
    file.sync_all()?;
    serde_json::to_writer(
        io::stdout().lock(),
        &serde_json::json!({
            "engine": report.engine,
            "formulas": report.formula_count,
            "output_bytes": report.bytes.len(),
            "precision_fallback": false,
        }),
    )?;
    Ok(ExitCode::SUCCESS)
}
