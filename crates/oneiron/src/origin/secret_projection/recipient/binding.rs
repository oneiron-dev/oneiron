//! A proven recipient as a masked copy's records keep it (FIX 7608
//! pre-flip, FIX 9328 and 10271): the repo its files are read from and the
//! agent, provider, project and run its host proved. Value-free: ids and
//! the provider's name only, never a credential, a why or a receipt.
//!
//! A granted Git copy is made for exactly one binding, and a push received
//! into a private ingress keeps the binding its host proved, so a held
//! proposal's live clearance rebuilds the very file target the owner's
//! grant names. The binding admits nothing: every use still checks the
//! live grant. An unknown part stays `None`, which is never a wildcard: a
//! grant bound to a project or a run covers no read that names none.

use rmpv::Value;

use super::RepoRevealRecipient;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::secret_custody::RevealAsker;

/// The recipient a granted copy or a received push was proved for.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RepoProjectionRevealBinding {
    /// The repo its files' reveal targets name.
    pub(crate) repo: EntityId,
    pub(crate) agent: EntityId,
    pub(crate) provider: Option<String>,
    pub(crate) project: Option<EntityId>,
    pub(crate) run: Option<String>,
}

impl RepoProjectionRevealBinding {
    /// The binding of `recipient`, as its host proved it, reading `repo`.
    pub(crate) fn of(repo: EntityId, recipient: &RepoRevealRecipient) -> Self {
        Self {
            repo,
            agent: recipient.agent,
            provider: recipient.provider.clone(),
            project: recipient.project,
            run: recipient.run.clone(),
        }
    }

    /// The reveal asker its files' reads and grants are judged as.
    pub(crate) fn asker(&self) -> RevealAsker {
        RevealAsker::new(self.agent, self.project, self.run.clone())
            .with_provider(self.provider.as_deref())
    }

    /// Its record value: every part, each `nil` when unknown.
    pub(crate) fn value(&self) -> Value {
        let text = |text: &Option<String>| text.as_deref().map_or(Value::Nil, Value::from);
        Value::Map(vec![
            (Value::from("repo"), Value::from(self.repo.to_hex())),
            (Value::from("agent"), Value::from(self.agent.to_hex())),
            (Value::from("provider"), text(&self.provider)),
            (
                Value::from("project"),
                self.project
                    .map_or(Value::Nil, |project| Value::from(project.to_hex())),
            ),
            (Value::from("run"), text(&self.run)),
        ])
    }

    /// The binding `value` holds, every key required.
    ///
    /// # Errors
    /// A value that is not a binding.
    pub(crate) fn decode(value: &Value) -> Result<Self> {
        let map = value.as_map().ok_or_else(corrupt)?;
        let field = |key: &str| {
            map.iter()
                .find(|(name, _)| name.as_str() == Some(key))
                .map(|(_, value)| value)
                .ok_or_else(corrupt)
        };
        let id = |value: &Value| {
            value
                .as_str()
                .and_then(|hex| EntityId::from_hex(hex).ok())
                .ok_or_else(corrupt)
        };
        let text = |value: &Value| match value {
            Value::Nil => Ok(None),
            value => value
                .as_str()
                .map(|text| Some(text.to_owned()))
                .ok_or_else(corrupt),
        };
        Ok(Self {
            repo: id(field("repo")?)?,
            agent: id(field("agent")?)?,
            provider: text(field("provider")?)?,
            project: match field("project")? {
                Value::Nil => None,
                value => Some(id(value)?),
            },
            run: text(field("run")?)?,
        })
    }
}

fn corrupt() -> Error {
    Error::CorruptedIndex("a masked copy's recipient binding does not decode")
}
