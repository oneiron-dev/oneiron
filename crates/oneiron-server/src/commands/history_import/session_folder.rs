//! Name the folder a host session log names as the MCP bridge names an
//! attached session's folder. The queue reads logs only under their source's
//! configured root; direct imports read the owner's selected path. Both
//! read on this machine, so the log's `cwd` names a folder on this machine.
//! A folder that cannot be identified quietly lands at the default project;
//! resolving its identity never widens which logs the import reads. Only an
//! absolute `cwd` names a folder: a relative one would resolve against the
//! importer's own working directory, which is not the session's.

use std::collections::HashMap;
use std::path::Path;

use oneiron::ingest::history::{HistoryConversation, HistoryFile, HistorySource};

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
        // FIX SESSION-PROJECT-NOTE-MESSAGE-PLACEMENT PR D review round 2: the cache saves only
        // the git reads; a logged path names a folder only while it is still a directory.
        if !Path::new(cwd).is_dir() {
            return Vec::new();
        }
        self.by_cwd
            .entry(cwd.clone())
            .or_insert_with(|| logged_folder_digests(Path::new(cwd)))
            .clone()
    }
}

/// The folder digests of a log's `cwd`, as an attached session's folder is named.
fn logged_folder_digests(cwd: &Path) -> Vec<String> {
    // FIX SESSION-PROJECT-NOTE-MESSAGE-PLACEMENT PR D review: a relative cwd names no folder.
    if !cwd.is_absolute() {
        return Vec::new();
    }
    WorkspaceIdentity::of_session_folder(cwd)
        .map(|identity| identity.digests)
        .unwrap_or_default()
}

/// The folder digests of the session the log `text` (the file `file`, read as `source`'s
/// import reads it) records, as the local import names the folder it lands that log in
/// ([`SessionFolders::digests_of`]): the session's own conversation's `cwd` (for Claude Code
/// the one the log's stem names, else the first the log decodes to, as the vault names the
/// session's own), on this machine, where the session ran. None when the log does not
/// decode, records no absolute `cwd`, or names a folder that is not here; the vault then
/// lands it at the default project, as before (FIX SESSION-PROJECT-HOOK-TRANSCRIPT-PLACEMENT).
pub(in crate::commands) fn log_folder_digests(
    source: HistorySource,
    file: &HistoryFile,
    text: &str,
) -> Vec<String> {
    let Ok(conversations) = source.decode(text, file) else {
        return Vec::new();
    };
    let own = if source == HistorySource::ClaudeCode {
        conversations
            .iter()
            .find(|conv| conv.native_id == file.stem)
    } else {
        conversations.first()
    };
    own.and_then(|conv| conv.cwd.as_deref())
        .map(|cwd| logged_folder_digests(Path::new(cwd)))
        .unwrap_or_default()
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
    fn a_log_whose_cwd_is_relative_has_no_folder_digests() {
        // "." names this test's own working directory: a directory, neither home nor root.
        assert!(
            WorkspaceIdentity::of_session_folder(Path::new(".")).is_some(),
            "the importer's own working directory should have a session identity"
        );
        let mut folders = SessionFolders::default();
        assert!(
            folders
                .digests_of(&conversation(Some(Path::new("."))))
                .is_empty(),
            "a relative cwd should have no folder digests"
        );
    }

    #[test]
    fn a_log_whose_cwd_is_a_regular_file_has_no_folder_digests() {
        let dir = tempfile::tempdir().expect("create the session folder test directory");
        let file = dir.path().join("work");
        std::fs::write(&file, b"not a folder").expect("write a regular file at the logged path");
        let mut folders = SessionFolders::default();
        assert!(
            folders.digests_of(&conversation(Some(&file))).is_empty(),
            "a cwd that names a regular file should have no folder digests"
        );
    }

    #[test]
    fn an_existing_folders_digests_match_the_session_identity_while_it_is_a_folder() {
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
        assert_eq!(
            folders.digests_of(&log),
            digests,
            "a second lookup of the same folder should name it again"
        );

        // FIX SESSION-PROJECT-NOTE-MESSAGE-PLACEMENT PR D review round 2: a cached cwd is
        // checked again before its digests are reused.
        std::fs::remove_dir(&folder).expect("remove the logged folder after resolving it");
        assert!(
            folders.digests_of(&log).is_empty(),
            "a cwd whose folder was removed after a lookup should have no folder digests"
        );
        std::fs::write(&folder, b"not a folder")
            .expect("put a regular file where the logged folder was");
        assert!(
            folders.digests_of(&log).is_empty(),
            "a cwd that became a regular file after a lookup should have no folder digests"
        );
    }
}
