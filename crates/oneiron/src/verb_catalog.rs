//! Verb catalog vocabulary used by core admission and action surfaces.

/// The custody rows whose input carries a secret's value or its sealed
/// input. The action registry offers none of them: an action keeps its
/// whole input in its replay record.
pub const CUSTODY_VALUE_ROWS: [&str; 3] = [
    "vault.secrets.register",
    "vault.secrets.rotate",
    "vault.secrets.custody.submit",
];
