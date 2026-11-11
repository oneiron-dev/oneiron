//! A step its deadline stopped before its program ended (FIX 7703). The
//! program stays pending on its run's replay record, and the run's next
//! entry runs the same stored program again before any new model turn. The
//! calls the program already made stay in the record's bridge log, the one
//! effect history; a pending step names where they start and end, which of
//! them the program made itself, and what the program ran under.

use super::super::correction::ExecutorWireRepairs;
use super::{CODE_RUN_REPLAY_HASH_LEN, CodeRunDeterminism};
use crate::ModelId;

/// One pending step of a code run (FIX 7703): the step's program stopped at
/// its deadline, after every host call it admitted had settled and its
/// answer was kept. It is not a completed step: it has no checkpoint, and
/// the run's completed step count does not include it. Its program's calls
/// are the record's bridge rows from `bridge_start` to `bridge_frontier`;
/// a resumed program meets each of them in order before any call runs live.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PendingCodeStep {
    /// The step's seq: the checkpoint it commits once its program ends.
    pub step_seq: u64,
    /// The step's first bridge position.
    pub bridge_start: u64,
    /// The bridge positions the step's own program called, in order. The
    /// rows between two of them are the calls a callable it called made.
    pub guest_calls: Vec<u64>,
    /// The bridge log's length when the step parked: the journal frontier.
    /// Past it, the program's calls run live.
    pub bridge_frontier: u64,
    /// The record's output count when the step parked: the output frontier.
    pub output_frontier: u64,
    /// The BLAKE3 of the program as stored at the step's script path.
    pub script_blake3: [u8; CODE_RUN_REPLAY_HASH_LEN],
    /// The identity of the JavaScript a TypeScript program ran as (FIX
    /// 8276); `None` for a JavaScript program.
    pub prepared_identity: Option<[u8; CODE_RUN_REPLAY_HASH_LEN]>,
    /// The digest of the guest boundary the program ran against: its WIT
    /// world and the imports it links.
    pub guest_abi: [u8; CODE_RUN_REPLAY_HASH_LEN],
    /// The canonical hash of the model request the program answers.
    pub request_hash: [u8; CODE_RUN_REPLAY_HASH_LEN],
    /// The model whose response gave the program.
    pub model: ModelId,
    /// The model id that response's served receipt named: the ladder rung
    /// that answered. The correction record the step commits names it, else
    /// `model` (CODE-CORRECTION-MODEL-ID-IS-SEAT-DIGEST). `None` when no
    /// receipt named one, and for a step parked before this field was kept.
    pub answered_by: Option<ModelId>,
    /// The repairs the ONE-1929 normalization made to that response. The
    /// response's correction record and heal tally commit from them, with
    /// the checkpoint the step commits once its program ends (FIX 4411).
    pub repairs: ExecutorWireRepairs,
    /// The frozen clock and RNG seed the program ran under.
    pub determinism: CodeRunDeterminism,
    /// Whether the model reply's trailing speech is kept beside the program,
    /// at the step's pending speech path.
    pub trailing_speech: bool,
    /// How many times the step parked at its deadline before this park,
    /// from zero: its replay generation. Every park writes a new one, so a
    /// park with no new call still changes the record's generation.
    pub park_generation: u64,
}
