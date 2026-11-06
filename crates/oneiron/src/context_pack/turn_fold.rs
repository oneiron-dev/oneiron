//! How retrieval MESSAGE hits fold into their TURN.

/// What a run does with a MESSAGE hit
/// (`PipelineBuilder::fold_messages_into_turns`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TurnFold {
    /// Every hit stands as itself.
    Off,
    /// A MESSAGE hit becomes its TURN when the run admits the turn; any other
    /// message stays as itself.
    Fold,
    /// As [`Self::Fold`], and a MESSAGE that found no admitted turn leaves the
    /// run: the caller admits messages only as the way to their turns.
    TurnsOnly,
}

impl TurnFold {
    /// The mode's name in replay inputs and the fork hash.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Fold => "fold",
            Self::TurnsOnly => "turns_only",
        }
    }
}
