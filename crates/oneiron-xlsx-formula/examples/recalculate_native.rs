//! Emit retained native XLSX bytes for one-time application-oracle checks.
use std::io::Write;
use std::path::PathBuf;

use oneiron_xlsx_formula::engine::FormualizerEngine;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: recalculate_native INPUT.xlsx NEW_OUTPUT.xlsx".into());
    }
    let input = PathBuf::from(&args[0]);
    let output = PathBuf::from(&args[1]);
    let report = FormualizerEngine::new().recalculate_xlsx(&std::fs::read(input)?)?;
    let stamp = serde_json::json!({"engine":report.engine, "formula_count":report.formula_count});
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output)?;
    file.write_all(&report.bytes)?;
    file.sync_all()?;
    let mut metadata = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.with_extension("engine.json"))?;
    metadata.write_all(&serde_json::to_vec_pretty(&stamp)?)?;
    Ok(())
}
