//! The maintenance report's held facet-stamp receipts (restriction wave 17,
//! `maintain.report.facet_receipts_shown`): plant retired receipts, run a
//! maintenance pass, and read what the report names.

/// Plants `count` retired facet-stamp receipts (each expired, under no
/// grant), runs a maintenance pass with no optional work, and answers how
/// many receipts its report names and the total it counts.
///
/// # Errors
///
/// Storage errors, and the maintenance pass's own.
#[cfg(feature = "sync")]
pub fn report_facet_receipts_after_planting(
    vault: &crate::Vault,
    count: u32,
) -> crate::Result<(usize, u64)> {
    crate::federation::facet_read::plant_retired_facet_receipts(vault, count)?;
    let report = vault.maintain().run()?;
    Ok((
        report.held_facet_stamp_receipts.len(),
        report.held_facet_stamp_receipts_total,
    ))
}
