//! Registers: the engine's closed lists of names (Fable pass 25, the Register pattern).
//!
//! A Register is a closed list of names declared once in the source. Anything stored or sent under
//! one of its names is written by the Register's one door, which stamps it, and the build refuses
//! a name declared twice. A list of words (a Gate outcome, a receipt kind) is a plain enum with
//! `#[derive(Register)]` and one `#[register("lower.dotted")]` line: the derive writes `NAME`,
//! `ROWS`, `name` and an inherent `as_str`, and takes each row's name from the serde attributes
//! of the same enum, so the name serde writes and the name the table writes are one.
//!
//! An enum whose names differ from serde's, or that has no serde derive, states its own spelling:
//! `#[register("x.y", rename_all = "snake_case")]` for every row, `#[register(name = "..")]` on one
//! variant. The derive refuses a variant that carries data, two rows with one name, an empty name
//! or one with white space, and an enum with no `#[register("...")]` line.
//!
//! What is not a Register: anything a person or an agent adds while the engine runs (a Grant, a
//! schedule, the value of a Setting), free text, names built from parts at run time, numbers, and
//! enums whose variants carry data.

/// A closed list of names, declared once in the source.
pub trait Register: Copy + Eq + 'static {
    /// The Register's own name: lower case, dotted (`gate.outcome`). No two Registers share one.
    const NAME: &'static str;
    /// Every row, in declaration order.
    const ROWS: &'static [Self];

    /// The row's name: the one token that is stored and sent.
    fn name(self) -> &'static str;

    /// The row with this name. `None` for a name the Register does not declare.
    fn named(name: &str) -> Option<Self> {
        Self::ROWS.iter().copied().find(|row| row.name() == name)
    }
}

/// `#[derive(Register)]`: the derive carries the trait's name, as serde's derives do.
pub use oneiron_derive::Register;
