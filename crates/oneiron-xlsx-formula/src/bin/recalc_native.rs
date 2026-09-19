//! Measure the shipped retained XLSX adapter without a precision fallback.
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;

use oneiron_xlsx_formula::engine::FormualizerEngine;

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
    let report = FormualizerEngine::new().recalculate_xlsx(&fs::read(input)?)?;
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
