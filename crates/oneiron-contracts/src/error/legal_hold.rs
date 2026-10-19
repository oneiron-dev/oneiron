//! A legal order's typed refusal (OF-470; WILL-PLAN L01 rows 01 and 03).
//!
//! Where Oneiron hosts the bytes, a binding legal order may keep them, or
//! keep them for its own purpose only. Its refusal names that bound, the
//! law (DEC-0005: "a hosted refusal names its bound"), and says what
//! self-hosting changes. Every field is an opaque ref, a time or a code, as
//! the hold log's are (C3).
//!
//! Reached from the root as `Error::LegalHold(..)`.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The remedy both error projections give a legal order's refusal.
pub const LEGAL_HOLD_SUGGESTION: &str = "A legal order binding where Oneiron hosts these bytes keeps them until it lifts; the refusal names its bound. The same act works on bytes you host that no hold covers.";

/// The lead of a `retained_for_law` refusal.
const RETAINED_FOR_LAW_TEXT: &str =
    "legal hold: a legal order binding Oneiron's hosting keeps this record, so it is not deleted";

/// The lead of a `use_restricted` refusal.
const USE_RESTRICTED_TEXT: &str = "legal hold: a legal order binding Oneiron's hosting keeps this record for its own purpose only, so it is not used";

/// What a legal order does to the record its refusal names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegalHoldState {
    /// The order keeps the bytes: no delete or erase destroys them.
    RetainedForLaw,
    /// The order keeps the bytes for its own purpose only: no named read or
    /// write uses them while it stands.
    UseRestricted,
}

impl LegalHoldState {
    /// The stable wire code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RetainedForLaw => "retained_for_law",
            Self::UseRestricted => "use_restricted",
        }
    }
}

/// What kind of bound a hosted refusal names. A legal order's is the law.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegalHoldBoundKind {
    Law,
}

/// The law a legal order binds Oneiron's hosting under, as the host recorded
/// it. A term the host did not record is `None`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldBound {
    pub kind: LegalHoldBoundKind,
    /// The order's own opaque reference.
    pub order_ref: Option<String>,
    /// The law the order is made under, as an opaque ref.
    pub legal_basis_ref: Option<String>,
    /// Where that law binds, as an opaque code.
    pub jurisdiction: Option<String>,
    /// Who issued the order, as an opaque ref.
    pub issuing_authority_ref: Option<String>,
    /// When the order's stored period ends, in unix seconds.
    pub ends_at: Option<u64>,
}

/// A legal order's refusal, as far as the owner may be told it: never while
/// the order's silence runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldNotice {
    pub state: LegalHoldState,
    pub bound: LegalHoldBound,
    /// The same act works on bytes the owner hosts that no hold covers.
    pub works_self_hosted: bool,
    /// What self-hosting changes, and what it does not.
    pub self_hosted_note: String,
}

impl fmt::Display for LegalHoldNotice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.state {
            LegalHoldState::RetainedForLaw => RETAINED_FOR_LAW_TEXT,
            LegalHoldState::UseRestricted => USE_RESTRICTED_TEXT,
        })?;
        let bound = &self.bound;
        let terms = [
            ("order", &bound.order_ref),
            ("law", &bound.legal_basis_ref),
            ("jurisdiction", &bound.jurisdiction),
            ("authority", &bound.issuing_authority_ref),
        ];
        for (name, value) in terms {
            if let Some(value) = value {
                write!(f, "; {name} {value}")?;
            }
        }
        if let Some(ends_at) = bound.ends_at {
            write!(f, "; until {ends_at}")?;
        }
        if self.works_self_hosted {
            write!(f, ". {}", self.self_hosted_note)?;
        }
        Ok(())
    }
}
