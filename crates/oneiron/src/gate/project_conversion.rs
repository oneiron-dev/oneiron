//! Typed project-conversion policy, parsed from a trusted policy manifest.

use rmpv::Value;

use crate::entity_id::EntityId;

/// How conversion chooses a leader when the caller did not name one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum LeaderFallback {
    #[default]
    TaskHolderThenRoomHost,
    SourceLeaderOnly,
}

impl LeaderFallback {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::TaskHolderThenRoomHost => "task_holder_then_room_host",
            Self::SourceLeaderOnly => "source_leader_only",
        }
    }
}

/// How conversion derives membership from its source project.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum RosterSelection {
    #[default]
    InheritSource,
    LeaderOnly,
}

impl RosterSelection {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::InheritSource => "inherit_source",
            Self::LeaderOnly => "leader_only",
        }
    }
}

/// Which stored TASK field may supply a default holder.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum TaskHolderFallback {
    #[default]
    AssigneeThenOwner,
    AssigneeOnly,
}
impl TaskHolderFallback {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::AssigneeThenOwner => "assignee_then_owner",
            Self::AssigneeOnly => "assignee_only",
        }
    }
}

/// A bound on conversion, not a grant of extra authority. The chosen leader
/// must be in the source roster unless the policy allows an actual task holder
/// outside it. The latter exception is bound to the holder read in this txn.
/// A thread's task count only ever asks: `max_tasks` is a question threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProjectConversionPolicy {
    pub(crate) leader_fallback: LeaderFallback,
    pub(crate) task_holder_fallback: TaskHolderFallback,
    pub(crate) roster_selection: RosterSelection,
    /// The thread task count past which binding and conversion raise the
    /// owner's "is everything okay" question (rule 5, OF-522). Never a
    /// refusal: both count past it and go on.
    pub(crate) max_tasks: usize,
    pub(crate) allow_holder_override: bool,
}

impl Default for ProjectConversionPolicy {
    fn default() -> Self {
        Self {
            leader_fallback: LeaderFallback::TaskHolderThenRoomHost,
            task_holder_fallback: TaskHolderFallback::AssigneeThenOwner,
            roster_selection: RosterSelection::InheritSource,
            max_tasks: 4096,
            allow_holder_override: true,
        }
    }
}

impl ProjectConversionPolicy {
    /// Every trusted manifest narrows the policy; no later row can widen it.
    /// The lowest task threshold stands, so its question is raised earliest.
    pub(crate) fn restrict(self, other: Self) -> Self {
        Self {
            leader_fallback: if self.leader_fallback == LeaderFallback::SourceLeaderOnly
                || other.leader_fallback == LeaderFallback::SourceLeaderOnly
            {
                LeaderFallback::SourceLeaderOnly
            } else {
                LeaderFallback::TaskHolderThenRoomHost
            },
            task_holder_fallback: if self.task_holder_fallback == TaskHolderFallback::AssigneeOnly
                || other.task_holder_fallback == TaskHolderFallback::AssigneeOnly
            {
                TaskHolderFallback::AssigneeOnly
            } else {
                TaskHolderFallback::AssigneeThenOwner
            },
            roster_selection: if self.roster_selection == RosterSelection::LeaderOnly
                || other.roster_selection == RosterSelection::LeaderOnly
            {
                RosterSelection::LeaderOnly
            } else {
                RosterSelection::InheritSource
            },
            max_tasks: self.max_tasks.min(other.max_tasks),
            allow_holder_override: self.allow_holder_override && other.allow_holder_override,
        }
    }

    /// Neither an arbitrary existing entity nor a caller-claimed holder may
    /// bypass the source roster. Supply the holder read from stored tasks.
    pub(crate) fn allows_leader_override(
        self,
        requested: EntityId,
        source_roster: &[String],
        task_holder: Option<EntityId>,
    ) -> bool {
        source_roster.iter().any(|id| id == &requested.to_hex())
            || (self.allow_holder_override && task_holder == Some(requested))
    }
}

/// The shipped conversion row, as the default manifest carries it.
pub(super) fn shipped_row() -> Value {
    Value::Map(vec![
        (
            Value::from("precedence"),
            Value::from("nested_narrowing_holder_override_capped_vault"),
        ),
        (
            Value::from("leader_fallback"),
            Value::from("task_holder_then_room_host"),
        ),
        (
            Value::from("roster_selection"),
            Value::from("inherit_source"),
        ),
        (
            Value::from("task_holder_fallback"),
            Value::from("assignee_then_owner"),
        ),
        (Value::from("max_tasks"), Value::from(4096_u64)),
        (Value::from("allow_holder_override"), Value::Boolean(true)),
    ])
}

/// A complete map. Unknown, duplicate, missing, or ill-typed fields reject
/// the entire manifest, rather than silently authorizing the default.
pub(super) fn parse_project_conversion(value: &Value) -> Option<ProjectConversionPolicy> {
    let Value::Map(entries) = value else {
        return None;
    };
    if entries.len() != 6 {
        return None;
    }
    let mut leader_fallback = None;
    let mut roster_selection = None;
    let mut task_holder_fallback = None;
    let mut max_tasks = None;
    let mut allow_holder_override = None;
    let mut precedence = None;
    for (key, value) in entries {
        match key.as_str()? {
            "leader_fallback" => {
                leader_fallback = Some(match value.as_str()? {
                    "task_holder_then_room_host" if leader_fallback.is_none() => {
                        LeaderFallback::TaskHolderThenRoomHost
                    }
                    "source_leader_only" if leader_fallback.is_none() => {
                        LeaderFallback::SourceLeaderOnly
                    }
                    _ => return None,
                });
            }
            "task_holder_fallback" => {
                task_holder_fallback = Some(match value.as_str()? {
                    "assignee_then_owner" if task_holder_fallback.is_none() => {
                        TaskHolderFallback::AssigneeThenOwner
                    }
                    "assignee_only" if task_holder_fallback.is_none() => {
                        TaskHolderFallback::AssigneeOnly
                    }
                    _ => return None,
                });
            }
            "roster_selection" => {
                roster_selection = Some(match value.as_str()? {
                    "inherit_source" if roster_selection.is_none() => {
                        RosterSelection::InheritSource
                    }
                    "leader_only" if roster_selection.is_none() => RosterSelection::LeaderOnly,
                    _ => return None,
                });
            }
            "max_tasks" => {
                if max_tasks.is_some() {
                    return None;
                }
                // A row may lower the shipped question threshold, never
                // raise it.
                let threshold = value.as_u64()?;
                if threshold > 4096 {
                    return None;
                }
                max_tasks = Some(usize::try_from(threshold).ok()?);
            }
            "precedence" => {
                if precedence.is_some()
                    || value.as_str()? != "nested_narrowing_holder_override_capped_vault"
                {
                    return None;
                }
                precedence = Some(());
            }
            "allow_holder_override" => {
                if allow_holder_override.is_some() {
                    return None;
                }
                let Value::Boolean(allowed) = value else {
                    return None;
                };
                allow_holder_override = Some(*allowed);
            }
            _ => return None,
        }
    }
    precedence?;
    Some(ProjectConversionPolicy {
        leader_fallback: leader_fallback?,
        roster_selection: roster_selection?,
        task_holder_fallback: task_holder_fallback?,
        max_tasks: max_tasks?,
        allow_holder_override: allow_holder_override?,
    })
}
