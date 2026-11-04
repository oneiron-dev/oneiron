//! The output decay policy: after how many turns a context output's view
//! drops from full to its overview, and from there to its stub.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputDecayPolicy {
    pub overview_after_turns: u64,
    pub stub_after_turns: u64,
}
