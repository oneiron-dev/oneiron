//! The run declaration: the teachers a run pinned at its start, the aliases
//! frozen with them, the paid connectors it may call and its budget line.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::super::{ModelId, PinnedModelConfig};

/// A budget line's unit. Every line names one, and the run admission never
/// adds units of different kinds without a rate the host supplied.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LeaseUnit(String);

impl LeaseUnit {
    /// The unit every model call reports: input plus output tokens.
    #[must_use]
    pub fn tokens() -> Self {
        Self("tokens".to_owned())
    }

    /// A unit a pack row or a host line names: lowercase ASCII letters,
    /// digits, `_` and `-`.
    pub fn new(name: impl Into<String>) -> Result<Self, DeclarationError> {
        let name = name.into();
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
        {
            return Err(DeclarationError::UnitName);
        }
        Ok(Self(name))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The run's budget line: its limit and each call's reservation, in one unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetLine {
    pub limit_units: u64,
    /// What one model call reserves before it is sent: the admission cap, and
    /// the bounded charge of a call that reports no usage.
    pub reserve_units: u64,
    pub unit: LeaseUnit,
}

/// The teachers a run declares: exact revisioned ids, the alias mappings
/// frozen at the start, and what the teacher outputs train and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredTeachers {
    pins: PinnedModelConfig,
    aliases: BTreeMap<String, ModelId>,
    target: String,
    purpose: String,
}

impl DeclaredTeachers {
    /// The pinned set, with the aliases as the host maps them now; the run
    /// keeps this map whatever the host remaps later. A declaration without
    /// its target or its purpose is refused.
    pub fn new(
        models: impl IntoIterator<Item = ModelId>,
        aliases: impl IntoIterator<Item = (String, ModelId)>,
        target: impl Into<String>,
        purpose: impl Into<String>,
    ) -> Result<Self, DeclarationError> {
        let target = target.into();
        let purpose = purpose.into();
        if target.trim().is_empty() {
            return Err(DeclarationError::MissingTarget);
        }
        if purpose.trim().is_empty() {
            return Err(DeclarationError::MissingPurpose);
        }
        Ok(Self {
            pins: PinnedModelConfig {
                allowed: models.into_iter().collect(),
                background_tier_enabled: true,
            },
            aliases: aliases.into_iter().collect(),
            target,
            purpose,
        })
    }

    /// The pinned teacher ids.
    pub fn models(&self) -> impl Iterator<Item = &ModelId> {
        self.pins.allowed.iter()
    }

    /// The model the teacher outputs train.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// What that model is for.
    #[must_use]
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    pub(super) fn pins(&self) -> &PinnedModelConfig {
        &self.pins
    }

    pub(super) fn alias(&self, selector: &str) -> Option<&ModelId> {
        self.aliases.get(selector)
    }
}

/// What a run states about itself. Only the owner or the host changes it, and
/// each change is a recorded revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunDeclaration {
    declared: bool,
    teachers: Option<DeclaredTeachers>,
    budget: BudgetLine,
    connectors: BTreeSet<String>,
    custody_overrides: BTreeSet<String>,
}

impl RunDeclaration {
    /// A run that declares nothing: any bound model, any paid connector, keys
    /// at whatever rung the host holds them. Every call still takes a one-use
    /// permit on this line.
    #[must_use]
    pub fn undeclared(budget: BudgetLine) -> Self {
        Self {
            declared: false,
            teachers: None,
            budget,
            connectors: BTreeSet::new(),
            custody_overrides: BTreeSet::new(),
        }
    }

    /// A run that declares its budget: its paid keys stay at T0, it calls only
    /// the paid connectors it names, and, once it declares teachers, only them.
    #[must_use]
    pub fn declared(budget: BudgetLine) -> Self {
        Self {
            declared: true,
            ..Self::undeclared(budget)
        }
    }

    #[must_use]
    pub fn with_teachers(mut self, teachers: DeclaredTeachers) -> Self {
        self.declared = true;
        self.teachers = Some(teachers);
        self
    }

    /// Names one paid connector the run may call.
    #[must_use]
    pub fn with_connector(mut self, connector: impl Into<String>) -> Self {
        self.connectors.insert(connector.into());
        self
    }

    /// The owner lets one offer serve this run from a key held at T1. The
    /// run's receipts then say the teacher and budget guarantee is off for it.
    #[must_use]
    pub fn with_custody_override(mut self, offer: impl Into<String>) -> Self {
        self.custody_overrides.insert(offer.into());
        self
    }

    #[must_use]
    pub fn is_declared(&self) -> bool {
        self.declared
    }

    #[must_use]
    pub fn teachers(&self) -> Option<&DeclaredTeachers> {
        self.teachers.as_ref()
    }

    #[must_use]
    pub fn budget(&self) -> &BudgetLine {
        &self.budget
    }

    pub(super) fn admits_connector(&self, connector: &str) -> bool {
        !self.declared || self.connectors.contains(connector)
    }

    pub(super) fn overrides_custody(&self, offer: &str) -> bool {
        self.custody_overrides.contains(offer)
    }
}

/// Who asks for a new revision of a run's declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclarationEditor {
    Owner,
    Host,
    /// The run itself, which never edits its own declaration.
    Run,
}

/// Why a declaration could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum DeclarationError {
    #[error("a teacher declaration needs the target its outputs train")]
    MissingTarget,
    #[error("a teacher declaration needs its purpose")]
    MissingPurpose,
    #[error("a lease unit is lowercase ASCII letters, digits, '_' and '-'")]
    UnitName,
}
