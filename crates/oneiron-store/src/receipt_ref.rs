//! A receipt reference: a receipt's kind and its id, in the one text form
//! `{kind}:{lowercase hex}` (fable pass 22 DESIGN section 3.3; PLAN-UC-04 2.4a).
//!
//! The text is what main already writes at each mint site (`format!("gate:{}", id.to_hex())`
//! and its siblings), so no stored row or wire value changes: a row may keep a reference
//! as a `String`, and this type is used where the string is made and where it is read.
//! A reference is a name, not a proof: a door that takes one looks the receipt up.

use std::fmt;
use std::str::FromStr;

use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::register::Register;

use crate::gate_decision::types::GateDecisionId;
use crate::receipt_row::ReceiptKind;

/// A receipt kind and the id of one receipt of that kind.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ReceiptRef {
    kind: ReceiptKind,
    id: ReceiptId,
}

/// A reference's id: 16 bytes for a UUID or an `EntityId`, 32 for a digest.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum ReceiptId {
    Short([u8; 16]),
    Long([u8; 32]),
}

/// The width of the id a reference of a kind carries.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum IdWidth {
    Short,
    Long,
}

impl ReceiptId {
    fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Short(bytes) => bytes,
            Self::Long(bytes) => bytes,
        }
    }
}

/// The id width a reference of `kind` carries; `None` for a kind no reference names.
///
/// Five kinds name a receipt as `{kind}:{hex}` today. The others write their receipt ids
/// in other shapes (several `:` segments, a sequence number), so a reference never names
/// them. A new kind takes its arm here.
const fn id_width(kind: ReceiptKind) -> Option<IdWidth> {
    match kind {
        ReceiptKind::Gate
        | ReceiptKind::ServedForm
        | ReceiptKind::ReferenceRefusal
        | ReceiptKind::TaskLifecycle => Some(IdWidth::Short),
        ReceiptKind::Hook => Some(IdWidth::Long),
        ReceiptKind::Outbound
        | ReceiptKind::IdentityLifecycle
        | ReceiptKind::ScopedRead
        | ReceiptKind::Share
        | ReceiptKind::ArtifactSettle
        | ReceiptKind::ProposalOutcome
        | ReceiptKind::CommitmentLifecycle
        | ReceiptKind::Extraction
        | ReceiptKind::RunHoldOverride
        | ReceiptKind::CheckIn
        | ReceiptKind::Inquiry => None,
    }
}

impl ReceiptRef {
    /// A gate decision's receipt.
    #[must_use]
    pub fn gate(id: GateDecisionId) -> Self {
        Self {
            kind: ReceiptKind::Gate,
            id: ReceiptId::Short(id.as_bytes()),
        }
    }

    /// The served-form record stored at `id`.
    #[must_use]
    pub fn served_form(id: EntityId) -> Self {
        Self {
            kind: ReceiptKind::ServedForm,
            id: ReceiptId::Short(*id.as_bytes()),
        }
    }

    /// The reference-refusal record stored at `id`.
    #[must_use]
    pub fn reference_refusal(id: EntityId) -> Self {
        Self {
            kind: ReceiptKind::ReferenceRefusal,
            id: ReceiptId::Short(*id.as_bytes()),
        }
    }

    /// A task-highway call's lifecycle receipt, at its derived id.
    #[must_use]
    pub fn task_lifecycle(id: EntityId) -> Self {
        Self {
            kind: ReceiptKind::TaskLifecycle,
            id: ReceiptId::Short(*id.as_bytes()),
        }
    }

    /// A fact-hook run's receipt, named by the run's 32-byte key.
    #[must_use]
    pub fn hook(run_key: [u8; 32]) -> Self {
        Self {
            kind: ReceiptKind::Hook,
            id: ReceiptId::Long(run_key),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> ReceiptKind {
        self.kind
    }

    /// The gate decision a `gate` reference names; `None` for any other kind.
    #[must_use]
    pub fn gate_id(&self) -> Option<GateDecisionId> {
        match (self.kind, self.id) {
            (ReceiptKind::Gate, ReceiptId::Short(bytes)) => Some(GateDecisionId::from_bytes(bytes)),
            _ => None,
        }
    }

    /// The id's bytes: 16, or 32 for a hook run.
    #[must_use]
    pub fn id_bytes(&self) -> &[u8] {
        self.id.as_bytes()
    }
}

impl fmt::Display for ReceiptRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}",
            self.kind.as_str(),
            oneiron_hex::encode(self.id.as_bytes())
        )
    }
}

/// Why a text is not a receipt reference.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum ReceiptRefError {
    /// No `:` separates a kind from an id.
    NoKind,
    /// The text before the first `:` is not a receipt kind.
    UnknownKind,
    /// A receipt kind that no reference names.
    NotAReferenceKind,
    /// The id is not lowercase hex of the kind's width.
    BadId,
}

impl fmt::Display for ReceiptRefError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NoKind => "a receipt reference is `{kind}:{hex}`; no `:` found",
            Self::UnknownKind => "a receipt reference names an unknown receipt kind",
            Self::NotAReferenceKind => "no receipt reference names this receipt kind",
            Self::BadId => "a receipt reference id is not lowercase hex of its kind's width",
        })
    }
}

impl std::error::Error for ReceiptRefError {}

impl FromStr for ReceiptRef {
    type Err = ReceiptRefError;

    /// A known kind, a `:`, then lowercase hex of that kind's width; anything else is refused.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (kind, hex) = text.split_once(':').ok_or(ReceiptRefError::NoKind)?;
        let kind = ReceiptKind::named(kind).ok_or(ReceiptRefError::UnknownKind)?;
        let id = match id_width(kind).ok_or(ReceiptRefError::NotAReferenceKind)? {
            IdWidth::Short => {
                ReceiptId::Short(oneiron_hex::decode(hex).ok_or(ReceiptRefError::BadId)?)
            }
            IdWidth::Long => {
                ReceiptId::Long(oneiron_hex::decode(hex).ok_or(ReceiptRefError::BadId)?)
            }
        };
        Ok(Self { kind, id })
    }
}
