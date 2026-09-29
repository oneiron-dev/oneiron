//! Measure the shipped retained XLSX adapter without a precision fallback.
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;

use oneiron_docedit::retained_opc::{Limits, XmlLimits};
use oneiron_xlsx_formula::engine::FormualizerEngine;

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

fn main() -> Result<(), Box<dyn Error>> {
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
    let report = FormualizerEngine::new().recalculate_xlsx(&fs::read(input)?, LIMITS)?;
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
    Ok(())
}
