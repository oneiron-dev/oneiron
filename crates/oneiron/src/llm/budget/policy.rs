//! Resolved manifest policy table for one budget meter.

use crate::entity_id::EntityId;
use crate::llm::CallPurpose;

/// Resolved `budget_policy` manifest table: ordered per-purpose/per-actor
/// floors and caps for ONE budget meter.
///
/// Each row selects exactly one call set — one call purpose or one actor ref —
/// and carries a floor, a cap, or both, in the meter's own units:
///
/// * a floor is a non-borrowable reservation. Matching calls may draw that
///   row's slice; non-matching calls may not, so the slice every call can
///   reach is `total - sum(all floors)`;
/// * a cap is conjunctive admission policy. A call matching several cap rows
///   must fit every one of them, and a cap denial is final.
///
/// Both directions are deliberate policy rather than capacity tuning: floors
/// strand budget on quiet days, and caps refuse matching work while the pool
/// still has room. An empty table is the plain single-pool meter.
///
/// Rows are data the host manifest authors; the engine installs none of its
/// own and gives no purpose an implicit reservation. Two shapes a manifest may
/// author (the numbers are illustrative, never engine defaults):
///
/// ```text
/// # Consolidation is guaranteed a reserved slice.
/// { purpose: "consolidation", floor: 200_000 }
///
/// # One autonomous agent is guaranteed a slice but cannot consume the vault.
/// { actor: "<canonical-actor-ref>", floor: 50_000, cap: 150_000 }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BudgetPolicyTable {
    rows: Vec<BudgetPolicyRow>,
}

impl BudgetPolicyTable {
    #[must_use]
    pub(crate) fn from_rows(rows: Vec<BudgetPolicyRow>) -> Self {
        Self { rows }
    }

    #[must_use]
    pub(crate) fn rows(&self) -> &[BudgetPolicyRow] {
        &self.rows
    }

    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Appends one decoded manifest's rows, preserving resolved order: row
    /// indices are manifest-scan order, then row order inside each manifest.
    pub(crate) fn extend_rows(&mut self, other: Self) {
        self.rows.extend(other.rows);
    }
}

/// One `budget_policy` row: a selector plus a floor, a cap, or both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BudgetPolicyRow {
    selector: BudgetPolicySelector,
    floor_units: Option<u64>,
    cap_units: Option<u64>,
}

impl BudgetPolicyRow {
    #[must_use]
    pub(crate) fn new(
        selector: BudgetPolicySelector,
        floor_units: Option<u64>,
        cap_units: Option<u64>,
    ) -> Self {
        Self {
            selector,
            floor_units,
            cap_units,
        }
    }

    #[must_use]
    pub(crate) fn selector(&self) -> &BudgetPolicySelector {
        &self.selector
    }

    #[must_use]
    pub(crate) fn floor_units(&self) -> Option<u64> {
        self.floor_units
    }

    #[must_use]
    pub(crate) fn cap_units(&self) -> Option<u64> {
        self.cap_units
    }
}

/// The one call set a policy row selects.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum BudgetPolicySelector {
    Purpose(CallPurpose),
    Actor(EntityId),
}

impl BudgetPolicySelector {
    /// Literal, purpose-independent on the actor axis: an actor row binds every
    /// call from the guard's construction-bound actor, including the
    /// purpose-less generic admissions, and a purpose row never matches one.
    pub(super) fn matches(&self, purpose: Option<&CallPurpose>, actor: Option<EntityId>) -> bool {
        match self {
            Self::Purpose(row_purpose) => purpose == Some(row_purpose),
            Self::Actor(row_actor) => actor == Some(*row_actor),
        }
    }

    /// Pinned snake-case manifest name of a purpose selector. `Other` rows
    /// carry their own name; the manifest parser maps every built-in name to
    /// its variant, so an `Other` name never collides with a built-in one.
    pub(crate) fn purpose_manifest_name(purpose: &CallPurpose) -> &str {
        match purpose {
            CallPurpose::Extraction => "extraction",
            CallPurpose::Consolidation => "consolidation",
            CallPurpose::AnswerGen => "answer_gen",
            CallPurpose::AutoCheck => "auto_check",
            CallPurpose::ToolRouting => "tool_routing",
            CallPurpose::Voice => "voice",
            CallPurpose::Eval => "eval",
            CallPurpose::Other { name } => name,
        }
    }
}
