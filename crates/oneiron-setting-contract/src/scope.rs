//! Where a stored row applies, and the chain of scopes a read walks.

use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// The kinds of place a row may sit at. One enum covers every scope the engine's settings use:
/// the nested narrowing of DEC-0005 `#precedence` (World, Project, SubProject, Thread), the
/// learned settings' scopes (Goal, TaskType), and the per-subject rows (Agent, Person, Repo).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ScopeKind {
    Vault,
    World,
    Project,
    SubProject,
    Thread,
    Goal,
    TaskType,
    Agent,
    Person,
    Repo,
}

impl ScopeKind {
    /// Every kind, narrowest first: the order a read's chain takes them in. A subject's own row
    /// is narrower than any place; inside a place, the nested narrowing; the task type after the
    /// places, as the learned settings read it; the vault last.
    pub const NARROWEST_FIRST: [Self; 10] = [
        Self::Agent,
        Self::Person,
        Self::Repo,
        Self::Thread,
        Self::SubProject,
        Self::Goal,
        Self::Project,
        Self::World,
        Self::TaskType,
        Self::Vault,
    ];

    /// The byte a stored key carries for this kind.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Vault => 0,
            Self::World => 1,
            Self::Project => 2,
            Self::SubProject => 3,
            Self::Thread => 4,
            Self::Goal => 5,
            Self::TaskType => 6,
            Self::Agent => 7,
            Self::Person => 8,
            Self::Repo => 9,
        }
    }

    /// The kind a stored key's byte names.
    #[must_use]
    pub fn from_tag(tag: u8) -> Option<Self> {
        Self::NARROWEST_FIRST
            .into_iter()
            .find(|kind| kind.tag() == tag)
    }

    /// The kind's place in [`Self::NARROWEST_FIRST`].
    #[must_use]
    pub fn rank(self) -> usize {
        Self::NARROWEST_FIRST
            .iter()
            .position(|kind| *kind == self)
            .unwrap_or(Self::NARROWEST_FIRST.len())
    }

    /// The kind's wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Vault => "vault",
            Self::World => "world",
            Self::Project => "project",
            Self::SubProject => "sub_project",
            Self::Thread => "thread",
            Self::Goal => "goal",
            Self::TaskType => "task_type",
            Self::Agent => "agent",
            Self::Person => "person",
            Self::Repo => "repo",
        }
    }
}

/// One place a row applies. The vault has no id; a task type is named by its type node; every
/// other kind by its entity.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum SettingScope {
    Vault,
    World(EntityId),
    Project(EntityId),
    SubProject(EntityId),
    Thread(EntityId),
    Goal(EntityId),
    TaskType(String),
    Agent(EntityId),
    Person(EntityId),
    Repo(EntityId),
}

impl SettingScope {
    /// Its kind.
    #[must_use]
    pub const fn kind(&self) -> ScopeKind {
        match self {
            Self::Vault => ScopeKind::Vault,
            Self::World(_) => ScopeKind::World,
            Self::Project(_) => ScopeKind::Project,
            Self::SubProject(_) => ScopeKind::SubProject,
            Self::Thread(_) => ScopeKind::Thread,
            Self::Goal(_) => ScopeKind::Goal,
            Self::TaskType(_) => ScopeKind::TaskType,
            Self::Agent(_) => ScopeKind::Agent,
            Self::Person(_) => ScopeKind::Person,
            Self::Repo(_) => ScopeKind::Repo,
        }
    }

    /// The entity it names, if any: what an erase of that entity takes out.
    #[must_use]
    pub const fn entity(&self) -> Option<EntityId> {
        match self {
            Self::Vault | Self::TaskType(_) => None,
            Self::World(id)
            | Self::Project(id)
            | Self::SubProject(id)
            | Self::Thread(id)
            | Self::Goal(id)
            | Self::Agent(id)
            | Self::Person(id)
            | Self::Repo(id) => Some(*id),
        }
    }

    /// The stored key's scope part: the kind's byte, then the entity's 16 bytes, the type node's
    /// UTF-8, or nothing for the vault.
    #[must_use]
    pub fn key_bytes(&self) -> Vec<u8> {
        let mut out = vec![self.kind().tag()];
        match self {
            Self::Vault => {}
            Self::TaskType(node) => out.extend_from_slice(node.as_bytes()),
            other => {
                if let Some(id) = other.entity() {
                    out.extend_from_slice(id.as_bytes());
                }
            }
        }
        out
    }

    /// The scope a stored key's scope part names; `None` for bytes no scope encodes to.
    #[must_use]
    pub fn from_key_bytes(bytes: &[u8]) -> Option<Self> {
        let (&tag, rest) = bytes.split_first()?;
        let kind = ScopeKind::from_tag(tag)?;
        let entity = || {
            <[u8; 16]>::try_from(rest)
                .ok()
                .and_then(|raw| EntityId::from_bytes(raw).ok())
        };
        Some(match kind {
            ScopeKind::Vault => rest.is_empty().then_some(Self::Vault)?,
            ScopeKind::TaskType => {
                let node = std::str::from_utf8(rest).ok()?;
                (!node.is_empty()).then(|| Self::TaskType(node.to_owned()))?
            }
            ScopeKind::World => Self::World(entity()?),
            ScopeKind::Project => Self::Project(entity()?),
            ScopeKind::SubProject => Self::SubProject(entity()?),
            ScopeKind::Thread => Self::Thread(entity()?),
            ScopeKind::Goal => Self::Goal(entity()?),
            ScopeKind::Agent => Self::Agent(entity()?),
            ScopeKind::Person => Self::Person(entity()?),
            ScopeKind::Repo => Self::Repo(entity()?),
        })
    }

    /// The chain a read walks, narrowest first: each scope the reader knows whose kind the key
    /// admits, in [`ScopeKind::NARROWEST_FIRST`] order, then the vault. One scope per kind: the
    /// first the reader names.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` when the reader names a vault scope among what it knows: the chain ends
    /// at the vault by itself.
    pub fn chain(known: &[Self], admitted: &[ScopeKind]) -> Result<Vec<Self>> {
        if known.iter().any(|scope| *scope == Self::Vault) {
            return Err(Error::InvalidConfig(
                "a setting read names the places it knows; the vault is always last".into(),
            ));
        }
        let mut chain: Vec<Self> = Vec::new();
        for kind in ScopeKind::NARROWEST_FIRST {
            if kind == ScopeKind::Vault || !admitted.contains(&kind) {
                continue;
            }
            if let Some(scope) = known.iter().find(|scope| scope.kind() == kind) {
                chain.push(scope.clone());
            }
        }
        chain.push(Self::Vault);
        Ok(chain)
    }
}

#[cfg(test)]
mod tests {
    use super::{ScopeKind, SettingScope};
    use oneiron_contracts::entity_id::EntityId;

    fn id(byte: u8) -> EntityId {
        EntityId::from_bytes_unchecked([byte; 16])
    }

    #[test]
    fn every_kind_has_one_tag_and_one_rank() {
        for kind in ScopeKind::NARROWEST_FIRST {
            assert_eq!(ScopeKind::from_tag(kind.tag()), Some(kind));
            assert_eq!(ScopeKind::NARROWEST_FIRST[kind.rank()], kind);
        }
        assert_eq!(ScopeKind::from_tag(10), None);
    }

    #[test]
    fn a_scope_round_trips_through_its_key_bytes() {
        for scope in [
            SettingScope::Vault,
            SettingScope::World(id(1)),
            SettingScope::Thread(id(2)),
            SettingScope::TaskType("type:invoice".to_owned()),
            SettingScope::Agent(id(3)),
        ] {
            assert_eq!(
                SettingScope::from_key_bytes(&scope.key_bytes()),
                Some(scope)
            );
        }
        assert_eq!(SettingScope::from_key_bytes(&[0, 1]), None);
        assert_eq!(SettingScope::from_key_bytes(&[1, 1, 2]), None);
        assert_eq!(SettingScope::from_key_bytes(&[6]), None);
    }

    #[test]
    fn the_chain_keeps_admitted_kinds_narrowest_first_and_ends_at_the_vault() {
        let known = [
            SettingScope::World(id(1)),
            SettingScope::Agent(id(3)),
            SettingScope::Thread(id(2)),
        ];
        let chain = SettingScope::chain(
            &known,
            &[ScopeKind::Vault, ScopeKind::World, ScopeKind::Thread],
        )
        .expect("a chain");
        assert_eq!(
            chain,
            vec![
                SettingScope::Thread(id(2)),
                SettingScope::World(id(1)),
                SettingScope::Vault
            ]
        );
        assert!(SettingScope::chain(&[SettingScope::Vault], &[ScopeKind::Vault]).is_err());
    }
}
