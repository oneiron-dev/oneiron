//! Stable reasons recorded by reference-refusal receipts.

use serde::{Deserialize, Serialize};

use oneiron_contracts::memory::{MEMORY_CODE_INVENTED_REFERENCE, MEMORY_CODE_NOT_FOUND};

/// Why a write or an answer was refused (OF-063, Engine 10-18): the one
/// reason the refusal's reference-refusal receipt records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RefusalReason {
    /// A record it named does not resolve for its writer: invented,
    /// missing, or one the writer may not read.
    #[serde(rename = "INVENTED_REFERENCE")]
    InventedReference,
    /// The gate, the door's authority or the write's own checks refused it.
    #[serde(rename = "GATE_REFUSED")]
    GateRefused,
}

impl RefusalReason {
    /// The stable form, as the receipt records it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InventedReference => MEMORY_CODE_INVENTED_REFERENCE,
            Self::GateRefused => "GATE_REFUSED",
        }
    }

    /// Parses the stable form.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        [Self::InventedReference, Self::GateRefused]
            .into_iter()
            .find(|reason| reason.as_str() == value)
    }

    /// The reason a refused claim element's error gives (the one policy
    /// hook for it): a record it named that does not resolve is an invented
    /// reference, and every other refusal the gate's or its door's.
    pub(crate) fn of_code(code: &str) -> Self {
        if code == MEMORY_CODE_INVENTED_REFERENCE || code == MEMORY_CODE_NOT_FOUND {
            Self::InventedReference
        } else {
            Self::GateRefused
        }
    }
}
