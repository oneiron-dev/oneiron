//! Authority-log vocabulary the write path and the error share: the entry hash, and why a fold
//! needs history. The authority log itself stays in `oneiron::authority`.

/// BLAKE3 authority entry hash length.
pub const AUTHORITY_HASH_LEN: usize = 32;

/// Content hash of a canonical authority entry.
pub type AuthorityEntryHash = [u8; AUTHORITY_HASH_LEN];

/// Why an authority fold, or a door that reads one, needs history this vault
/// does not hold ([`crate::error::RecordError::AuthorityHistoryRequired`]).
/// [`Self::UnheldRows`] names the rows the fold reads itself: a fetch of them
/// closes it. The fold reasons after it are cases the fold past an adopted
/// checkpoint image does not settle: they name every covered row not held,
/// since only the whole history folds there, so a fetch closes them while
/// some vault still holds those rows and nothing does once retention has
/// deleted them everywhere. The last two are doors' refusals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthorityHistoryReason {
    /// Rows the fold reads that this vault does not hold: a parent a held or
    /// tail row names that no adopted image covers, or a hash a caller
    /// requires that is neither held nor a state the image keeps.
    UnheldRows,
    /// The image was built under another hosting posture, pin or set of
    /// admitted peers than this install's: a covered row that reads them is
    /// not judged alike here, or a tail row folds past the image only under
    /// the image's own.
    ImageContextMoved,
    /// The image's fold has an issue, a missing parent, an unsettled handoff
    /// or a covered row it did not accept, and a tail row folds past only a
    /// clean image, or is a parent a covered row names as missing.
    UncleanImage,
    /// A covered row is outside the causal past of a tail row that folds past
    /// the image only with every covered row in its past.
    CoveredRowConcurrent,
    /// A tail row names a covered row off the image's frontier, and the
    /// image keeps no state there that the fork may fold on.
    LateForkWithoutState,
    /// A tail row's op is one the fold past an image does not settle: a kind
    /// it never folds past (an owner record, an anchor's mark, an owner
    /// answer), a second re-root in one tail, a retired device-key op in a
    /// tail with a re-root, or a row of a kind that folds past only as
    /// rejected that the tail folds to a state.
    OpNotFoldedPast,
    /// A row with no state here (a rejected tail row, or a frontier row the
    /// image holds rejected) that the whole fold reads past: a withdrawal
    /// standing on it, a world refold crossing it, or any such row in a tail
    /// with a serial row, whose branch may carry a withdrawal past it.
    RejectedRowCrossed,
    /// A tail row is signed by a key the image retired.
    RetiredSigner,
    /// This install's sequence floor refuses a tail row.
    BelowSequenceFloor,
    /// A residence result past an image that dropped its residence bodies.
    ResidenceBodiesDropped,
    /// A tail re-root's fence could refuse a tail row outside its line, or a
    /// parent of the re-root has no state here.
    HandoffFence,
    /// A key only the tail admits signed a covered slip row, which only the
    /// whole history counts again.
    IssuersRecounted,
    /// The fold of the covered rows and the tail would pass this install's
    /// fold memory floor.
    FoldOverMemoryFloor,
    /// A key record's request walk met a row the image shows nothing of.
    CausalWalkIncomplete,
    /// The tail moves what the fold past the image settles only for a serial
    /// row of its own kind: a federation pact on a row that does not fold
    /// serially, a machine with no serial machine profile in the tail, a
    /// world, or an actor's write frontier the image cannot name.
    UnsettledMove,
    /// A stale-roster window this install cannot time past the image: a
    /// covered approval with no first-seen receipt here, a tail approval on a
    /// revoked key, or a projection resting on how this install counts
    /// machines while a machine's roster chain is stale or has no settled
    /// root.
    StaleRosterWindow,
    /// A door's walk reaches a row this vault does not store and the image
    /// carries no body of.
    UncarriedAncestor,
    /// A full export on a vault that adopted an image and does not hold
    /// every row it covers.
    CoveredPrefixUnheld,
}
