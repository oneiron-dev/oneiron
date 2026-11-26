//! The `workspace.project` row (its value, rule and reader: the parent module). It sits in a
//! file named `setting_keys.rs`, the only name build.rs reads catalogue rows from.

use super::{WorkspaceProject, check_workspace_binding, erase_bound_project, is_digest_text};
use crate::setting::{ItemDomain, Kind, SettingSync};

crate::setting::setting_keys! {
    /// The PROJECT an attached agent session's folder reads by default (RECALL-SESSION-PROJECT;
    /// Engine ANSWER RECALL-SESSION-PROJECT-INTENT, 26 Nov). One item per folder, named by its
    /// workspace id: the folder's digest keyed by this vault's id, `blake3:` and 64 lower-case
    /// hex, never the path. The value names the project and the folder's label, for display. Unset: no project
    /// is bound, so a session there that names no project reads none. A set must name a live
    /// PROJECT. Binding is the owner's act (`vault.projects.workspace.bind`, which
    /// `oneiron project bind <project-ref>` sends from the folder); an agent's change waits on
    /// the owner's answer to that change, and the owner's standing approval does not cover the
    /// key. The owner's bind of the binding a row already holds is checked again, so a bind of a
    /// PROJECT gone since never reports success. An unreadable row reads as unbound. A choice
    /// about this install: it never leaves the machine, and a restore drops it. Each row names
    /// its folder and is a value, never a pin.
    pub(crate) WORKSPACE_PROJECT: WorkspaceProject = "workspace.project" {
        kind: Kind::new(WorkspaceProject::unbound)
            .strictest(WorkspaceProject::unbound)
            .erase_mentions(erase_bound_project),
        item: Some(ItemDomain { name: "workspace ids", admits: is_digest_text }),
        sync: SettingSync::Install,
        on_change: Some(check_workspace_binding),
        records_equal_owner_write: true,
        standing_approval: false,
    };
}
