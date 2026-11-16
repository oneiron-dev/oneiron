//! Moved from `crates/oneiron/src/dreamer_runner/program/rebind.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Names what to rebind: an admitted try by `attempt`, or a wake its turn
/// owes and no admission has judged yet by `turn_ref` and `registration`
/// (FIX 11833). Exactly one of the two.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TurnProgramRebindRequest {
    /// 32-hex id of the try, as a program read names it (`job:` prefix
    /// allowed).
    #[serde(default)]
    pub attempt: Option<String>,
    /// 32-hex id of the TURN whose landing owes the wake.
    #[serde(default)]
    pub turn_ref: Option<String>,
    /// 32-hex registration of the armed program the turn woke.
    #[serde(default)]
    pub registration: Option<String>,
}

/// A rebound turn program try or owed wake: the try, its admission and both
/// slips.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TurnProgramRebindReceipt {
    /// 32-hex id of the try: the one rebound, or the root try an owed
    /// wake's admission queued on the new slip. None when that admission
    /// refused the wake.
    pub attempt: Option<String>,
    /// 64-hex id of the admission the try runs under, or the owed wake's.
    pub admission: String,
    /// 64-hex id of the slip the program stood on before: its predecessor.
    pub predecessor_slip: String,
    /// 64-hex id of the slip it stands on now: the one this request was
    /// admitted on.
    pub successor_slip: String,
    /// A live owner of this vault woke the program: owner work.
    pub owner_work: bool,
}
