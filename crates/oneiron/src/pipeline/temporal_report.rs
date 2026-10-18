//! Caller-visible accounting for the temporal request, not its scope overfetch.

/// The sigma that scored the request and the rounds until that sigma settled.
/// These are produced by the engine's adaptive loop. Additional collection
/// rounds for a scoped channel's overfetch are not request widening evidence.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct TemporalSearchReport {
    pub sigma_secs: u64,
    /// One initial round, at most three rounds total; one when adaptive is off.
    pub rounds: usize,
}
