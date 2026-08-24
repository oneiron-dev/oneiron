use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// Exact agent-visible TASKS verb family in protocol sort order.
pub const TASKS_VERBS: [&str; 5] = [
    "tasks.ack",
    "tasks.cancel",
    "tasks.check",
    "tasks.create",
    "tasks.expand",
];

/// The five typed verbs available over the TASKS section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TasksVerb {
    Ack,
    Cancel,
    Check,
    Create,
    Expand,
}

impl TasksVerb {
    /// All typed TASKS verbs in protocol sort order.
    pub const ALL: [Self; 5] = [
        Self::Ack,
        Self::Cancel,
        Self::Check,
        Self::Create,
        Self::Expand,
    ];

    /// Stable protocol identifier for this typed verb.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ack => "tasks.ack",
            Self::Cancel => "tasks.cancel",
            Self::Check => "tasks.check",
            Self::Create => "tasks.create",
            Self::Expand => "tasks.expand",
        }
    }
}

/// Shape discriminator on the typed TASK body. Absent on a schema-v1 row,
/// where it means [`TaskKind::Standard`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskKind {
    Standard,
    Consult,
}

impl TaskKind {
    /// Stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Consult => "consult",
        }
    }

    pub(super) fn from_token(token: &str) -> Result<Self> {
        match token {
            "standard" => Ok(Self::Standard),
            "consult" => Ok(Self::Consult),
            _ => Err(Error::InvalidTaskBody("tasks.body.kind")),
        }
    }
}

/// The single TASK assignee wire mint. ONE-1700 routes over this field and
/// ONE-1708 activates the `Human` arm; neither replaces the wire.
///
/// Identity is the ACTOR — the connection — never a vendor, harness, or machine
/// string. Two subscriptions of the same product under different config dirs
/// are two actors; the harness is a display label resolved at projection time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskAssignee {
    Dreamer,
    AgentDef { agent_def_ref: EntityId },
    Peer { actor_ref: EntityId },
    Human { actor_ref: EntityId },
}

impl TaskAssignee {
    /// Stable wire token for the variant.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dreamer => "dreamer",
            Self::AgentDef { .. } => "agent_def",
            Self::Peer { .. } => "peer",
            Self::Human { .. } => "human",
        }
    }

    /// The addressed entity, or `None` for the local dreamer.
    #[must_use]
    pub const fn entity_ref(self) -> Option<EntityId> {
        match self {
            Self::Dreamer => None,
            Self::AgentDef { agent_def_ref } => Some(agent_def_ref),
            Self::Peer { actor_ref } | Self::Human { actor_ref } => Some(actor_ref),
        }
    }

    /// Binds the assignee to a resolved entity of the right kind. A dangling
    /// or mistyped assignee is refused here, before any write transaction.
    pub fn validate(&self, vault: &Vault) -> Result<()> {
        let Some(entity_ref) = self.entity_ref() else {
            return Ok(());
        };
        let stored = vault.get_entity_type(&entity_ref)?;
        let admitted = match self {
            // An agent definition is a typed row, so its kind is checkable.
            Self::AgentDef { .. } => stored == Some(crate::registry::ENTITY_TYPE_AGENT_DEF),
            // A peer/human actor is whatever kind the identity plane stores it
            // as (PERSON today); existence is the assertable invariant.
            Self::Dreamer | Self::Peer { .. } | Self::Human { .. } => stored.is_some(),
        };
        if admitted {
            Ok(())
        } else {
            Err(Error::EntityNotFound)
        }
    }
}

/// Absolute expiry instant. A relative duration would mean a different wall
/// time on every replica, so the caller's clock is resolved once, here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskTtl {
    pub deadline_at: u64,
}

impl TaskTtl {
    /// An already-absolute deadline.
    #[must_use]
    pub const fn at(deadline_at: u64) -> Self {
        Self { deadline_at }
    }

    /// Resolves `now + duration` to the stored absolute deadline.
    #[must_use]
    pub const fn after(now: u64, duration_seconds: u64) -> Self {
        Self {
            deadline_at: now.saturating_add(duration_seconds),
        }
    }
}
