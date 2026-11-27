//! Name the folder a host session log names as the MCP bridge names an
//! attached session's folder. The queue reads logs only under their source's
//! configured root; direct imports read the owner's selected path. Both
//! read on this machine, so the log's `cwd` names a folder on this machine.
//! A folder that cannot be identified quietly lands at the default project;
//! resolving its identity never widens which logs the import reads.

use std::collections::HashMap;
use std::path::Path;

use oneiron::ingest::history::HistoryConversation;

use crate::workspace_identity::WorkspaceIdentity;

#[derive(Default)]
pub(super) struct SessionFolders {
    by_cwd: HashMap<String, Vec<String>>,
}

impl SessionFolders {
    pub(super) fn digests_of(&mut self, conversation: &HistoryConversation) -> Vec<String> {
        let Some(cwd) = &conversation.cwd else {
            return Vec::new();
        };
        self.by_cwd
            .entry(cwd.clone())
            .or_insert_with(|| {
                WorkspaceIdentity::of_session_folder(Path::new(cwd))
                    .map(|identity| identity.digests)
                    .unwrap_or_default()
            })
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oneiron::ingest::history::HistoryThreadKind;

    fn conversation(cwd: Option<&Path>) -> HistoryConversation {
        HistoryConversation {
            native_id: "session".into(),
            kind: HistoryThreadKind::Main,
            parent: None,
            title: None,
            started_at_ms: None,
            own_started_at_ms: None,
            cwd: cwd.map(|path| path.to_string_lossy().into_owned()),
            messages: Vec::new(),
            skipped: Default::default(),
            sharing: None,
        }
    }

    #[test]
    fn a_log_without_a_cwd_has_no_folder_digests() {
        let mut folders = SessionFolders::default();
        assert!(
            folders.digests_of(&conversation(None)).is_empty(),
            "a log without a cwd should have no folder digests"
        );
    }

    #[test]
    fn a_log_whose_folder_is_missing_has_no_folder_digests() {
        let dir = tempfile::tempdir().expect("create the session folder test directory");
        let missing = dir.path().join("missing");
        let mut folders = SessionFolders::default();
        assert!(
            folders.digests_of(&conversation(Some(&missing))).is_empty(),
            "a missing cwd should have no folder digests"
        );
    }

    #[test]
    fn an_existing_folders_digests_match_the_session_identity_and_are_cached() {
        let dir = tempfile::tempdir().expect("create the session folder test directory");
        let folder = dir.path().join("work");
        std::fs::create_dir(&folder).expect("create the logged folder");
        let expected = WorkspaceIdentity::of_session_folder(&folder)
            .expect("the logged folder should have a session identity")
            .digests;
        let log = conversation(Some(&folder));
        let mut folders = SessionFolders::default();
        let digests = folders.digests_of(&log);
        assert_eq!(
            digests, expected,
            "an existing cwd should have the same digests as an attached session"
        );

        std::fs::remove_dir(&folder).expect("remove the logged folder after resolving it");
        assert_eq!(
            folders.digests_of(&log),
            digests,
            "a second lookup of the same cwd should use the cached digests"
        );
    }
}
