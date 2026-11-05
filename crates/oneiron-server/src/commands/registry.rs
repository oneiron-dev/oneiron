//! `oneiron registry`: print the engine-owned kind/family/zone registry as JSON.
//!
//! No vault required.

use std::io::Write as _;

/// Prints `oneiron::registry::export::registry_snapshot()` as pretty JSON.
pub fn registry() -> anyhow::Result<()> {
    let snapshot = oneiron::registry::export::registry_snapshot();
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, &snapshot)?;
    writeln!(stdout)?;
    Ok(())
}
