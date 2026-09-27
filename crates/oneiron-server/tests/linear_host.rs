//! Standalone host tests also run while unrelated server-lib test fixtures catch up
//! to the six-axis disclosure scope API.
#[allow(
    dead_code,
    reason = "standalone host tests reuse production source while library tests await unrelated disclosure fixture repair"
)]
#[path = "../src/linear_host.rs"]
mod linear_host;
