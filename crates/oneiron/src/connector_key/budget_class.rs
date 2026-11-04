//! Persisted accounting class of an outbound effect.

/// Semantic accounting class. It is persisted so recovery never re-derives
/// whether this intent consumed the sends dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BudgetClass {
    Send,
    Operation,
}

impl BudgetClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Send => "send",
            Self::Operation => "operation",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "send" => Some(Self::Send),
            "operation" => Some(Self::Operation),
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_send(self) -> bool {
        matches!(self, Self::Send)
    }
}
