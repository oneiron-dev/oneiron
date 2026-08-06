//! Shared fixtures for the split Context Board oracle files.
//!
//! Policy (ONE-1797 split, frozen): a helper belongs here only when at least
//! two extracted `cb_oracle_*` integration-test files import the exact same
//! fixture. No arm, no assertion, no ticket-specific observation struct, and
//! no production behavior belongs here — those stay in the owning area file.
//!
//! This module is frozen after the split: additive-only. Changing an existing
//! fixture signature requires a PACKET_AMEND.
//!
//! The ONE-1797 extraction produced no cross-file fixture: every `arm_*` seam
//! carries its own module-local `use` block and constructs its own state, so
//! this module is intentionally empty of code.
