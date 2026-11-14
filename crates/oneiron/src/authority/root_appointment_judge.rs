//! The fold's judgement of a root appointment (row
//! OWNER-ANCHOR-ROOT-RECOVERY, PLAN v3 sections 4, 4a and 5; Engine RULINGs
//! 14 Nov 21:01, 21:47 and 22:32).
//!
//! An appointment's verdict is a function of its own signed ancestry and the
//! root it names, so it is the same on every install:
//! - V1: the row's shape (the codec's check), and a successor key no row of
//!   its ancestry names ([`AppointmentVerdict::SuccessorNotFresh`]);
//! - V2: an owner root of that id, signed by the appointing anchor, that the
//!   anchor fold of the ancestry took, and a sequence above the anchor's own
//!   rows there;
//! - V3: the ancestry's canonical fold ([`proof_fold`]) holds no live
//!   `ROLE_OWNER` key;
//! - V4: the anchor is not burned in the ancestry.
//!
//! An anchor is burned by one void appointment (V2, V3 or V4 failed on a
//! complete ancestry), or by two valid ones beside each other, neither in the
//! other's ancestry. Its appointments are judged in topological order, and
//! after its first burn every later one is void with no proof fold, which
//! bounds the proof folds an anchor costs.
//!
//! Only the anchor of this install's pinned root is judged; every other
//! appointment costs no proof fold. No install counts an appointment yet:
//! the fold refuses every one, with its descendants, and reports its verdict
//! ([`AuthorityFoldIssue::AppointmentRefused`]).

/// Why a root appointment is void. A void appointment burns its anchor.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum AppointmentVoidReason {
    /// Its ancestry holds no owner root of its id that its anchor signed and
    /// the anchor fold took, or folds into another vault (V2).
    NoOwnerRoot,
    /// Its sequence is not above its anchor's own rows in its ancestry (V2).
    SequenceNotAdvanced,
    /// Its ancestry, folded canonically, still holds a live root key (V3).
    RootedAncestry,
    /// Its anchor is burned in its ancestry, or at an earlier appointment of
    /// this install's log (V4).
    AnchorBurned,
}

/// A root appointment's verdict on this install.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum AppointmentVerdict {
    /// Not judged: this install pins no root of the appointing anchor.
    Unjudged,
    /// Its ancestry is incomplete here, or its proof fold passed the fold's
    /// memory floor. It is judged again when that changes.
    Pending,
    /// A row of its ancestry names the successor key (V1). It burns nothing.
    SuccessorNotFresh,
    /// V2, V3 or V4 failed. It burns its anchor.
    Void(AppointmentVoidReason),
    /// V1 to V4 hold.
    Valid,
}
