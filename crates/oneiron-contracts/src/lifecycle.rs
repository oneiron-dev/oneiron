//! One declared state machine for a stored lifecycle status (census UC-15).
//!
//! A status that rows hold declares once the states a writer may move a row
//! to from each state. A state with none is terminal. Its writers move a
//! row's status only through [`Lifecycle::transition_to`], so a move no edge
//! allows is refused before anything is written.
//!
//! The declaration never changes how a row spells its status: each status
//! keeps its own codec (serde, wire bytes or words), and [`LifecycleWords`]
//! only names the words a status spelt as text already stores.

use core::fmt;

/// A stored lifecycle status with its edges declared once.
pub trait Lifecycle: Sized {
    /// The state without its payload: the status itself when no state
    /// carries one.
    type Kind: Copy + Eq + fmt::Debug + 'static;

    /// This state's kind.
    fn kind(&self) -> Self::Kind;

    /// The kinds a writer may move a row to from `kind`, empty for a
    /// terminal one. A kind never lists itself: staying in it is no move.
    fn next_kinds(kind: Self::Kind) -> &'static [Self::Kind];

    /// Whether no writer moves a row on from this state.
    #[must_use]
    fn is_terminal(&self) -> bool {
        Self::next_kinds(self.kind()).is_empty()
    }

    /// Whether moving from this state to `next` is a declared edge. Staying
    /// in the same kind is not one.
    #[must_use]
    fn may_transition_to(&self, next: &Self) -> bool {
        Self::next_kinds(self.kind()).contains(&next.kind())
    }

    /// Sets `next` when it keeps this state's kind (its payload, or another
    /// field of the row, changes; the state does not) or when the move is a
    /// declared edge.
    ///
    /// # Errors
    ///
    /// [`IllegalTransition`] for any other move, with nothing set.
    fn transition_to(&mut self, next: Self) -> Result<(), IllegalTransition<Self::Kind>> {
        let (from, to) = (self.kind(), next.kind());
        if from != to && !Self::next_kinds(from).contains(&to) {
            return Err(IllegalTransition { from, to });
        }
        *self = next;
        Ok(())
    }
}

/// The word a status spelt as text stores for each of its kinds.
pub trait LifecycleWords: Lifecycle {
    /// Every kind with its stored word, each kind and each word once. A
    /// status's tests pin every word, because a stored row never changes
    /// meaning.
    const WORDS: &'static [(Self::Kind, &'static str)];

    /// This state's stored word. A kind missing from [`Self::WORDS`] has the
    /// empty word, which no status decodes.
    #[must_use]
    fn word(&self) -> &'static str {
        let kind = self.kind();
        Self::WORDS
            .iter()
            .find(|(known, _)| *known == kind)
            .map_or("", |&(_, word)| word)
    }

    /// The kind a stored word names; `None` for a word no kind stores.
    #[must_use]
    fn kind_from_word(word: &str) -> Option<Self::Kind> {
        Self::WORDS
            .iter()
            .find(|(_, known)| *known == word)
            .map(|&(kind, _)| kind)
    }
}

/// A move between two kinds that the status does not declare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("no declared edge leads from {from:?} to {to:?}")]
pub struct IllegalTransition<K: fmt::Debug> {
    pub from: K,
    pub to: K,
}

impl<K: fmt::Debug> From<IllegalTransition<K>> for crate::Error {
    fn from(_: IllegalTransition<K>) -> Self {
        Self::InvariantViolation(
            "a stored status moved along an edge its lifecycle does not declare",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{IllegalTransition, Lifecycle, LifecycleWords};

    /// A door's state, with the reason a closed one carries.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Door {
        Shut,
        Open,
        Closed(String),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum DoorKind {
        Shut,
        Open,
        Closed,
    }

    impl Lifecycle for Door {
        type Kind = DoorKind;

        fn kind(&self) -> DoorKind {
            match self {
                Self::Shut => DoorKind::Shut,
                Self::Open => DoorKind::Open,
                Self::Closed(_) => DoorKind::Closed,
            }
        }

        fn next_kinds(kind: DoorKind) -> &'static [DoorKind] {
            match kind {
                DoorKind::Shut => &[DoorKind::Open, DoorKind::Closed],
                DoorKind::Open => &[DoorKind::Shut, DoorKind::Closed],
                DoorKind::Closed => &[],
            }
        }
    }

    impl LifecycleWords for Door {
        const WORDS: &'static [(DoorKind, &'static str)] = &[
            (DoorKind::Shut, "shut"),
            (DoorKind::Open, "open"),
            (DoorKind::Closed, "closed"),
        ];
    }

    #[test]
    fn a_declared_edge_moves_and_any_other_move_is_refused_unset() {
        let mut door = Door::Shut;
        assert!(door.may_transition_to(&Door::Open));
        assert_eq!(door.transition_to(Door::Open), Ok(()));
        assert_eq!(door, Door::Open);

        let mut closed = Door::Closed("late".into());
        assert!(!closed.may_transition_to(&Door::Open));
        assert_eq!(
            closed.transition_to(Door::Open),
            Err(IllegalTransition {
                from: DoorKind::Closed,
                to: DoorKind::Open,
            })
        );
        assert_eq!(closed, Door::Closed("late".into()));
    }

    #[test]
    fn staying_in_a_kind_is_no_move_and_sets_its_payload() {
        let mut closed = Door::Closed("late".into());
        assert!(!closed.may_transition_to(&Door::Closed("early".into())));
        assert_eq!(closed.transition_to(Door::Closed("early".into())), Ok(()));
        assert_eq!(closed, Door::Closed("early".into()));
    }

    #[test]
    fn a_kind_with_no_next_kind_is_terminal() {
        assert!(Door::Closed(String::new()).is_terminal());
        assert!(!Door::Shut.is_terminal());
        assert!(!Door::Open.is_terminal());
    }

    #[test]
    fn each_word_names_its_kind_both_ways() {
        for (door, word) in [
            (Door::Shut, "shut"),
            (Door::Open, "open"),
            (Door::Closed("late".into()), "closed"),
        ] {
            assert_eq!(door.word(), word);
            assert_eq!(Door::kind_from_word(word), Some(door.kind()));
        }
        assert_eq!(Door::kind_from_word("ajar"), None);
    }
}
