//! Verified own-task and child event minting for routed board events.

use super::frames::StreamConnectionId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOwnTaskEvent {
    pub(super) task_ref: String,
    pub(super) actor_ref: String,
    pub(super) event_ref: String,
}

impl VerifiedOwnTaskEvent {
    pub(crate) fn task_ref(&self) -> &str {
        &self.task_ref
    }
    pub(crate) fn actor_ref(&self) -> &str {
        &self.actor_ref
    }
    pub(crate) fn consultee_ref(&self) -> &str {
        &self.actor_ref
    }
    pub(crate) fn event_ref(&self) -> &str {
        &self.event_ref
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WakeMintError {
    ConnectionMissing(StreamConnectionId),
    TaskMissing(String),
    NotOwnTask { task_ref: String, actor_ref: String },
}

#[allow(dead_code)]
pub(crate) trait OwnTaskProvenanceSource {
    fn routing_actor_for_own_task(
        &self,
        c: &StreamConnectionId,
        t: &str,
    ) -> Result<String, WakeMintError>;
}

#[allow(dead_code)]
pub(crate) fn mint_own_task_event(
    src: &dyn OwnTaskProvenanceSource,
    c: &StreamConnectionId,
    t: &str,
    e: &str,
) -> Result<VerifiedOwnTaskEvent, WakeMintError> {
    let actor = src.routing_actor_for_own_task(c, t)?;
    Ok(VerifiedOwnTaskEvent {
        task_ref: t.into(),
        actor_ref: actor,
        event_ref: e.into(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildEvent {
    pub(super) child_ref: String,
    pub(super) parent_actor_ref: String,
    pub(super) event_ref: String,
}

#[allow(dead_code)]
impl ChildEvent {
    pub(crate) fn child_ref(&self) -> &str {
        &self.child_ref
    }
    pub(crate) fn parent_actor_ref(&self) -> &str {
        &self.parent_actor_ref
    }
    pub(crate) fn event_ref(&self) -> &str {
        &self.event_ref
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ChildMintError {
    ChildMissing(String),
    ParentMissing(String),
    ProvenanceMismatch { child_ref: String },
}

#[allow(dead_code)]
pub(crate) trait ChildProvenanceSource {
    fn parent_actor_ref(&self, c: &str) -> Result<String, ChildMintError>;
}

#[allow(dead_code)]
pub(crate) fn mint_child_event(
    src: &dyn ChildProvenanceSource,
    c: &str,
    e: &str,
) -> Result<ChildEvent, ChildMintError> {
    let p = src.parent_actor_ref(c)?;
    Ok(ChildEvent {
        child_ref: c.into(),
        parent_actor_ref: p,
        event_ref: e.into(),
    })
}
