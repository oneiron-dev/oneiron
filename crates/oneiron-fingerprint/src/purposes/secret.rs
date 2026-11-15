//! Purposes of secret scanning (`crates/oneiron/src/batch/secret_scan`).

purposes! {
    /// The place a lifted carrier row's custody records name as where their keys were found
    /// (`batch::secret_scan::mask::carrier`). Parts: `placeable`, or the table and key.
    LIFT_CARRIER = "oneiron:secret-lift:carrier:v1";
}

legacy_purposes! {}
