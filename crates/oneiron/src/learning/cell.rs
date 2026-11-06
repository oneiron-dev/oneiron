//! One cell of measured state (ARCH-0003 #learning-qualifiers): the subject,
//! the predicate and the applicable executor, task type, axis, consent scope
//! and setting key, in one scope: a project's runs, or the vault's (FIX
//! 6038: scoped keys, `(scope, node@version)`). The judge is never part of
//! the key, so a judge swap never forks a cell.
//!
//! This `TypeRef` keeps a string node id and the stamp's u64 tree version
//! (FIX 4432); `task_verb::brief::TypeRef` uses an `EntityId`.

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::error::{Error, Result};

pub use crate::receipt::task_type_ref::{ROOT_TYPE_NODE, TypeRef};

/// Longest qualifier text a cell keeps, in bytes.
const MAX_QUALIFIER_BYTES: usize = 256;

pub use crate::claim::learning_predicate::LearningPredicate;

/// One cell's key.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct LearningCell {
    pub predicate: LearningPredicate,
    pub subject: EntityId,
    /// Executor identity at revision (`model@revision`, or an actor's own id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_ref: Option<TypeRef>,
    /// The scored axis, such as `quality` or `honesty`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub axis: Option<String>,
    /// The consent scope of attributed edit outcomes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent_scope: Option<String>,
    /// `learning.setting` only: the catalog key of the fitted knob.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting_key: Option<String>,
    /// The project whose runs the cell counts; `None` is the vault's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<EntityId>,
}

impl LearningCell {
    /// A cell with only its predicate and subject; add qualifiers with the
    /// builder methods.
    #[must_use]
    pub const fn new(predicate: LearningPredicate, subject: EntityId) -> Self {
        Self {
            predicate,
            subject,
            executor: None,
            type_ref: None,
            axis: None,
            consent_scope: None,
            setting_key: None,
            project: None,
        }
    }

    #[must_use]
    pub fn executor(mut self, executor: impl Into<String>) -> Self {
        self.executor = Some(executor.into());
        self
    }

    #[must_use]
    pub fn type_ref(mut self, type_ref: TypeRef) -> Self {
        self.type_ref = Some(type_ref);
        self
    }

    #[must_use]
    pub fn axis(mut self, axis: impl Into<String>) -> Self {
        self.axis = Some(axis.into());
        self
    }

    #[must_use]
    pub fn consent_scope(mut self, scope: impl Into<String>) -> Self {
        self.consent_scope = Some(scope.into());
        self
    }

    #[must_use]
    pub fn setting_key(mut self, key: impl Into<String>) -> Self {
        self.setting_key = Some(key.into());
        self
    }

    /// The cell in `project`'s scope; `None` keeps it the vault's.
    #[must_use]
    pub fn project(mut self, project: Option<EntityId>) -> Self {
        self.project = project;
        self
    }

    /// The applicable-qualifier law: each member names what it requires.
    ///
    /// | member | required |
    /// |---|---|
    /// | reliability | executor, typeRef, axis |
    /// | edit_cost | executor, consent_scope |
    /// | retest_noise | executor, axis |
    /// | setting | setting_key (a catalog row), typeRef |
    ///
    /// A setting key on any other member is refused: only `learning.setting`
    /// keys it.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidClaimBody`] naming the missing or malformed qualifier.
    pub fn validate(&self) -> Result<()> {
        for text in [
            self.executor.as_deref(),
            self.axis.as_deref(),
            self.consent_scope.as_deref(),
            self.setting_key.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if text.is_empty() || text.len() > MAX_QUALIFIER_BYTES || text.contains('\0') {
                return Err(Error::InvalidClaimBody(
                    "a learning qualifier is 1..=256 bytes without NUL",
                ));
            }
        }
        if let Some(type_ref) = &self.type_ref {
            type_ref.validate()?;
        }
        let need = |present: bool, what: &'static str| {
            if present {
                Ok(())
            } else {
                Err(Error::InvalidClaimBody(what))
            }
        };
        match self.predicate {
            LearningPredicate::Reliability => {
                need(
                    self.executor.is_some(),
                    "learning.reliability keys an executor",
                )?;
                need(
                    self.type_ref.is_some(),
                    "learning.reliability keys a typeRef",
                )?;
                need(self.axis.is_some(), "learning.reliability keys an axis")?;
            }
            LearningPredicate::EditCost => {
                need(
                    self.executor.is_some(),
                    "learning.edit_cost keys an executor",
                )?;
                need(
                    self.consent_scope.is_some(),
                    "learning.edit_cost keys a consent scope",
                )?;
            }
            LearningPredicate::RetestNoise => {
                need(
                    self.executor.is_some(),
                    "learning.retest_noise keys an executor",
                )?;
                need(self.axis.is_some(), "learning.retest_noise keys an axis")?;
            }
            LearningPredicate::Setting => {
                need(self.type_ref.is_some(), "learning.setting keys a typeRef")?;
                let key = self.setting_key.as_deref().ok_or(Error::InvalidClaimBody(
                    "learning.setting keys a setting_key",
                ))?;
                need(
                    crate::learning_setting::setting_spec(key).is_some(),
                    "learning.setting keys a setting-catalog row",
                )?;
            }
        }
        if self.predicate != LearningPredicate::Setting && self.setting_key.is_some() {
            return Err(Error::InvalidClaimBody(
                "only learning.setting keys a setting_key",
            ));
        }
        Ok(())
    }

    /// The cell's stable 32-byte identity: a domain-separated hash over every
    /// key field, length-framed, so two cells collide only if they are equal.
    /// A project scope is framed after the rest; the vault scope adds
    /// nothing, so a vault cell keeps the identity it has always had.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("oneiron learning cell v1");
        let mut field = |bytes: Option<&[u8]>| match bytes {
            None => {
                hasher.update(&[0]);
            }
            Some(bytes) => {
                hasher.update(&[1]);
                hasher.update(&(bytes.len() as u64).to_be_bytes());
                hasher.update(bytes);
            }
        };
        field(Some(self.predicate.as_str().as_bytes()));
        field(Some(&self.subject.as_bytes()[..]));
        field(self.executor.as_deref().map(str::as_bytes));
        let type_ref = self.type_ref.as_ref().map(TypeRef::wire_form);
        field(type_ref.as_deref().map(str::as_bytes));
        field(self.axis.as_deref().map(str::as_bytes));
        field(self.consent_scope.as_deref().map(str::as_bytes));
        field(self.setting_key.as_deref().map(str::as_bytes));
        if let Some(project) = &self.project {
            field(Some(&project.as_bytes()[..]));
        }
        *hasher.finalize().as_bytes()
    }

    /// The conflict key: this cell's question, never its changing estimate.
    /// A project scope follows as one more field; a vault cell has none.
    #[must_use]
    pub fn conflict_key(&self) -> String {
        let opt = |v: Option<&str>| v.unwrap_or("-").to_owned();
        let scope = self
            .project
            .map_or_else(String::new, |project| format!("|{}", project.to_hex()));
        format!(
            "{}|{}|{}|{}|{}|{}|{}{scope}",
            self.subject.to_hex(),
            self.predicate.as_str(),
            opt(self.executor.as_deref()),
            self.type_ref
                .as_ref()
                .map_or_else(|| "-".to_owned(), TypeRef::wire_form),
            opt(self.axis.as_deref()),
            opt(self.consent_scope.as_deref()),
            opt(self.setting_key.as_deref()),
        )
    }

    /// The same cell with its task type replaced.
    #[must_use]
    pub fn with_type(&self, type_ref: Option<TypeRef>) -> Self {
        let mut cell = self.clone();
        cell.type_ref = type_ref;
        cell
    }

    /// The same cell with its executor replaced.
    #[must_use]
    pub fn with_executor(&self, executor: Option<String>) -> Self {
        let mut cell = self.clone();
        cell.executor = executor;
        cell
    }

    /// The same cell with its scope replaced.
    #[must_use]
    pub fn with_project(&self, project: Option<EntityId>) -> Self {
        let mut cell = self.clone();
        cell.project = project;
        cell
    }

    /// Whether `other` is this cell under another task type or executor:
    /// every other qualifier matches, the scope included.
    #[must_use]
    pub fn same_question_modulo(
        &self,
        other: &Self,
        ignore_type: bool,
        ignore_executor: bool,
    ) -> bool {
        self.predicate == other.predicate
            && self.subject == other.subject
            && self.axis == other.axis
            && self.consent_scope == other.consent_scope
            && self.setting_key == other.setting_key
            && self.project == other.project
            && (ignore_type || self.type_ref == other.type_ref)
            && (ignore_executor || self.executor == other.executor)
    }
}
