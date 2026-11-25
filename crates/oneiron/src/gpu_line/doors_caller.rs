//! The GPU line doors' one call into the lane economy's door kit
//! (`verb_grant_caller`, `crate::memory::verb_grant_caller`), and the role
//! check of section 5.1 on top of it: the kit says the caller may use the
//! verb over the lane; the line's role lists say on which line.
use super::fold::{GpuLine, LineRole};
use crate::EntityId;
use crate::consent::AuthenticatedOwner;
use crate::memory::verb_grant_caller::VerbGrantCaller;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};

/// Who a GPU line door admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LineCaller {
    /// The vault owner under their own proof, as this actor.
    Owner(EntityId),
    /// An agent under the one live Grant that admits it to the verb.
    Agent { grant: EntityId },
}

impl LineCaller {
    /// The owner's actor, when the owner's own proof admitted the call.
    pub(crate) fn owner(self) -> Option<EntityId> {
        match self {
            Self::Owner(actor) => Some(actor),
            Self::Agent { .. } => None,
        }
    }

    /// Admits the call on `line` when the owner made it or its Grant holds
    /// one of `roles` there (section 5.1).
    ///
    /// # Errors
    ///
    /// `forbidden` (`not_this_line`) for a Grant that holds none of them.
    pub(crate) fn require_role(
        self,
        line: &GpuLine,
        roles: &[LineRole],
        verb: &str,
    ) -> MemoryResult<()> {
        match self {
            Self::Owner(_) => Ok(()),
            Self::Agent { grant } if roles.iter().any(|role| line.holds_role(&grant, *role)) => {
                Ok(())
            }
            Self::Agent { .. } => Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                format!(
                    "{verb}: not_this_line: the Grant holds no {} role on this line",
                    roles_named(roles)
                ),
                &["Ask the owner to name the Grant in the line's role list."],
            )),
        }
    }
}

fn roles_named(roles: &[LineRole]) -> String {
    roles
        .iter()
        .map(|role| match role {
            LineRole::Lead => "lead",
            LineRole::Reviewer => "reviewer",
            LineRole::Planner => "planner",
        })
        .collect::<Vec<_>>()
        .join(" or ")
}

/// Admits `memory`'s caller to `verb` in `txn` over the lane `project`: the
/// owner under their own proof, or an agent whose Grant admits it and
/// reaches the lane (its scope names no project, the lane or an ancestor of
/// it).
///
/// # Errors
///
/// `forbidden` for a caller the kit does not admit; a store read failure.
pub(crate) fn admit_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    owner: Option<&AuthenticatedOwner>,
    verb: &str,
    project: EntityId,
) -> MemoryResult<LineCaller> {
    let caller = memory.verb_grant_caller_admits_over_in_txn(txn, owner, verb, project)?;
    Ok(match caller {
        VerbGrantCaller::Owner => LineCaller::Owner(memory.actor()),
        VerbGrantCaller::Agent { grant, .. } => LineCaller::Agent { grant },
    })
}

/// The refusal of an agent at an act that is the owner's alone.
pub(super) fn refused_owner_act(verb: &str, act: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!("{verb}: {act} is the vault owner's own act"),
        &["Call it as the vault owner."],
    )
}
