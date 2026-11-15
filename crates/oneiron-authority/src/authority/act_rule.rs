//! The authority rule: what an act may do to the row it moves.
//!
//! An act counts for what its proved actor may do, in the direction it
//! moves; whatever is left of it is a question for someone who may. Every
//! door and every fold site that judges an act reads one scale twice: once
//! for the act's proved actor, once for the log entry that carries it. The
//! act may do the lesser of the two ([`Permitted::limited_by`]), and it
//! counts when that admits its direction ([`Permitted::admit`]).
//!
//! This file holds the judgement only. Its inputs stay with their own
//! modules: the row kind's comparator gives the [`Direction`]; the proof of
//! the actor, the live Grant and the entry's standing on this install give
//! each [`Permitted`]. (Authority one rule, the lead, 15 Nov.)

/// Which way an act moves its row, by the row kind's own comparator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Nothing that was refused before is allowed after.
    Narrows,
    /// The row kind guards nothing: no access, authority, money or identity
    /// moves with it.
    Neutral,
    /// Anything else: a removed restriction by any verb, a made or lowered
    /// proof, and every change the comparator cannot call a narrowing.
    Widens,
}

/// What may be done to a row, least first. Read twice for every act: for its
/// proved actor, and for the log entry that carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Permitted {
    /// No effect. An actor of whom only the carrier is proved, or with no
    /// right over the row; an entry that is not admitted.
    Nothing,
    /// A narrowing and nothing else. The row's own subject, its parent or
    /// grantor; an entry in doubt on this install.
    NarrowingOnly,
    /// A narrowing or a neutral change. A holder of a kind the row keeps its
    /// widening from.
    NoWidening,
    /// Any move. A holder of a kind the row lets its widening be handed to;
    /// an entry counted in full.
    AnyMove,
}

impl Permitted {
    /// What an act may do: the lesser of its actor's reading and its entry's.
    #[must_use]
    pub fn limited_by(self, _other: Self) -> Self {
        Self::Nothing
    }

    /// Whether this admits a move in `direction`.
    #[must_use]
    pub const fn admits(self, _direction: Direction) -> bool {
        false
    }

    /// Asks the rule for one move: the witness when this admits `direction`,
    /// None when the act counts for nothing here.
    #[must_use]
    pub const fn admit(self, _direction: Direction) -> Option<Admitted> {
        None
    }
}

/// Proof that the rule was asked for one move. Only [`Permitted::admit`]
/// builds it, so a function that makes a row take effect and takes
/// `&Admitted` cannot be called without stating what the act's actor may do
/// and which way the row moves. It proves that the question was asked, not
/// that its inputs were true.
#[derive(Debug)]
pub struct Admitted {
    direction: Direction,
}

impl Admitted {
    /// The direction the rule admitted.
    #[must_use]
    pub const fn direction(&self) -> Direction {
        self.direction
    }
}

/// The rule's version: raised by any change to this file, to what proves an
/// actor, or to how far a row kind hands its widening. The sync wire's
/// version fence compares it once that fence is built
/// (FIX `[AUTHORITY-WIRE-VERSION-FENCE]`).
pub const AUTHORITY_RULE_VERSION: u32 = 1;
