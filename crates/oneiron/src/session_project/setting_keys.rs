//! The `workspace.project` row (its value, rule and reader: the parent module). It sits in a
//! file named `setting_keys.rs`, the only name build.rs reads catalogue rows from.

use super::{WorkspaceProject, erase_bound_project, is_workspace_id, refuse_unless_live_project};
use crate::setting::{ItemDomain, Kind};

crate::setting::setting_keys! {
    /// The PROJECT an attached agent session's folder reads by default (RECALL-SESSION-PROJECT;
    /// Engine ANSWER RECALL-SESSION-PROJECT-INTENT, 26 Nov). One item per folder, named by its
    /// workspace id: the SHA-256 of the folder's canonical checkout path in lower-case hex, never
    /// the path. The value names the project and the folder's label, for display. Unset: no
    /// project is bound, so a session there that names no project reads none. A set must name a
    /// live PROJECT. Binding is the owner's act (`oneiron project bind <project-ref>` in the
    /// folder); an agent's change waits on the owner's answer. An unreadable row reads as
    /// unbound.
    pub(crate) WORKSPACE_PROJECT: WorkspaceProject = "workspace.project" {
        kind: Kind::new(WorkspaceProject::unbound)
            .strictest(WorkspaceProject::unbound)
            .erase_mentions(erase_bound_project),
        item: Some(ItemDomain { name: "workspace ids", admits: is_workspace_id }),
        on_change: Some(refuse_unless_live_project),
    };
}
