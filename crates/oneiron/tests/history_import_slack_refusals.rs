//! L2-18 PR 2, blind review (Muse Wonder, 16 Nov): a Slack export is
//! untrusted input, so an export that does not read one way only is refused
//! whole, never resolved by the decoder's order.
//! - F1: a conversation id listed twice (in two lists, or twice in one).
//! - F2: a folder two conversations would claim (two names alike, or a name
//!   that is another conversation's id).
//! - F4: members of more than one workspace (`team_id`).
//! - F5: two files at one path (a zip's `Export/groups.json` and
//!   `Export/./groups.json` read as one path).
//! - F6: an id that is not a Slack id (ASCII letters and digits), so no id
//!   holds the `:` the keys a conversation lands under are joined by; a
//!   workspace keyed by its name never keys as a Slack id does; a message
//!   whose speaker or Slack time is not Slack's does not read.
//!
//! At the head before the fix, every such export decodes.
//!
//! `cargo test --locked -p oneiron --all-features --test history_import_slack_refusals`

use oneiron::ingest::IngestError;
use oneiron::ingest::history::slack::{self, SlackExport, SlackExportFile, SlackWorkspace};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const USERS: &str = r#"[
  {"id": "U0", "team_id": "T1", "name": "owen", "profile": {}},
  {"id": "U1", "team_id": "T1", "name": "yuki", "profile": {}},
  {"id": "U2", "team_id": "T1", "name": "sam", "profile": {}}
]"#;

const DAY: &str =
    r#"[{"type": "message", "user": "U0", "text": "budget is set", "ts": "1761955600.000100"}]"#;

/// An export named `Example` of the files `files` (by path under the
/// export's folder).
fn export(files: &[(&str, &str)]) -> SlackExport {
    SlackExport {
        workspace: "Example".to_owned(),
        files: files
            .iter()
            .map(|(path, text)| SlackExportFile {
                path: (*path).to_owned(),
                text: (*text).to_owned(),
            })
            .collect(),
    }
}

fn decode(files: &[(&str, &str)]) -> Result<SlackWorkspace, IngestError> {
    slack::decode(&export(files))
}

/// The duplicate `decode` refused, as `(kind, id)`.
fn duplicate(files: &[(&str, &str)]) -> Result<(&'static str, String), Box<dyn std::error::Error>> {
    match decode(files) {
        Err(IngestError::DuplicateId { kind, id, .. }) => Ok((kind, id)),
        Err(other) => Err(format!("refused for another reason: {other}").into()),
        Ok(_) => Err("the export decodes".into()),
    }
}

/// The field `decode` refused.
fn refused_field(files: &[(&str, &str)]) -> Result<String, Box<dyn std::error::Error>> {
    match decode(files) {
        Err(IngestError::InvalidDocumentField { path, .. }) => Ok(path),
        Err(other) => Err(format!("refused for another reason: {other}").into()),
        Ok(_) => Err("the export decodes".into()),
    }
}

#[test]
fn a_conversation_id_listed_twice_is_refused() -> TestResult {
    // The public entry names yuki; the private one with the same id does not.
    let public = (
        "channels.json",
        r#"[{"id": "C1", "name": "board", "created": 1761955100, "members": ["U0", "U1"]}]"#,
    );
    let private = (
        "groups.json",
        r#"[{"id": "C1", "name": "board", "created": 1761955100, "members": ["U0"]}]"#,
    );
    let day = ("board/2026-11-01.json", DAY);
    assert_eq!(
        duplicate(&[("users.json", USERS), public, private, day])?,
        ("conversation", "C1".to_owned()),
        "an id in two lists"
    );
    let twice = (
        "groups.json",
        r#"[{"id": "G1", "name": "board", "members": ["U0"]},
            {"id": "G1", "name": "plans", "members": ["U0", "U1"]}]"#,
    );
    assert_eq!(
        duplicate(&[("users.json", USERS), twice])?,
        ("conversation", "G1".to_owned()),
        "an id twice in one list"
    );
    Ok(())
}

#[test]
fn a_folder_two_conversations_would_claim_is_refused() -> TestResult {
    let groups = (
        "groups.json",
        r#"[{"id": "G1", "name": "board", "members": ["U0", "U2"]},
            {"id": "G2", "name": "board", "members": ["U0", "U1"]}]"#,
    );
    let day = ("board/2026-11-01.json", DAY);
    assert_eq!(
        duplicate(&[("users.json", USERS), groups, day])?,
        ("conversation folder", "board".to_owned()),
        "two conversations of one name"
    );
    // A channel named as a DM's id: the DM's days are found by its id.
    let channels = (
        "channels.json",
        r#"[{"id": "C1", "name": "D1", "members": ["U0", "U1"]}]"#,
    );
    let dms = ("dms.json", r#"[{"id": "D1", "members": ["U0", "U2"]}]"#);
    let dm_day = ("D1/2026-11-01.json", DAY);
    assert_eq!(
        duplicate(&[("users.json", USERS), channels, dms, dm_day])?,
        ("conversation folder", "D1".to_owned()),
        "a name that is another conversation's id"
    );
    Ok(())
}

#[test]
fn a_conversation_named_by_its_own_id_still_decodes() -> TestResult {
    let groups = (
        "groups.json",
        r#"[{"id": "G1", "name": "G1", "members": ["U0", "U2"]}]"#,
    );
    let workspace = decode(&[("users.json", USERS), groups, ("G1/2026-11-01.json", DAY)])?;
    assert_eq!(workspace.conversations.len(), 1);
    assert_eq!(workspace.conversations[0].messages.len(), 1);
    Ok(())
}

#[test]
fn members_of_two_workspaces_are_refused() -> TestResult {
    let users = r#"[
      {"id": "U0", "team_id": "T1", "name": "owen", "profile": {}},
      {"id": "UX", "team_id": "T9", "name": "outsider", "profile": {}},
      {"id": "U1", "team_id": "T1", "name": "yuki", "profile": {}}
    ]"#;
    let channels = (
        "channels.json",
        r#"[{"id": "C1", "name": "general", "members": ["U0", "U1"]}]"#,
    );
    let field = refused_field(&[("users.json", users), channels])?;
    assert!(
        field.starts_with("users.json[1].team_id"),
        "the second workspace's member is named: {field}"
    );
    Ok(())
}

#[test]
fn a_member_naming_no_workspace_beside_one_that_does_still_decodes() -> TestResult {
    let users = r#"[
      {"id": "USLACKBOT", "name": "slackbot", "profile": {}},
      {"id": "U0", "team_id": "T1", "name": "owen", "profile": {}}
    ]"#;
    let workspace = decode(&[("users.json", users)])?;
    assert_eq!(workspace.key, "T1");
    Ok(())
}

#[test]
fn two_files_at_one_path_are_refused() -> TestResult {
    let owner_only = (
        "groups.json",
        r#"[{"id": "G1", "name": "board", "members": ["U0"]}]"#,
    );
    let widened = (
        "groups.json",
        r#"[{"id": "G1", "name": "board", "members": ["U0", "U1"]}]"#,
    );
    assert_eq!(
        duplicate(&[("users.json", USERS), owner_only, widened])?,
        ("file", "groups.json".to_owned())
    );
    let day = ("board/2026-11-01.json", DAY);
    assert_eq!(
        duplicate(&[("users.json", USERS), owner_only, day, day])?,
        ("file", "board/2026-11-01.json".to_owned()),
        "a day file twice"
    );
    Ok(())
}

#[test]
fn an_id_that_is_not_a_slack_id_is_refused() -> TestResult {
    let team = r#"[{"id": "U0", "team_id": "T1:C1", "name": "owen", "profile": {}}]"#;
    assert_eq!(
        refused_field(&[("users.json", team)])?,
        "users.json[0].team_id",
        "a workspace id holding the separator"
    );
    let member = r#"[{"id": "U0:x", "team_id": "T1", "name": "owen", "profile": {}}]"#;
    assert_eq!(
        refused_field(&[("users.json", member)])?,
        "users.json[0].id",
        "a member id holding the separator"
    );
    let conversation = (
        "groups.json",
        r#"[{"id": "C1:board", "name": "board", "members": ["U0"]}]"#,
    );
    assert_eq!(
        refused_field(&[("users.json", USERS), conversation])?,
        "groups.json[0].id",
        "a conversation id holding the separator"
    );
    let listed = (
        "groups.json",
        r#"[{"id": "G1", "name": "board", "members": ["U0", "U1:x"]}]"#,
    );
    assert_eq!(
        refused_field(&[("users.json", USERS), listed])?,
        "groups.json[0].members",
        "a listed member id holding the separator"
    );
    let long = format!(
        r#"[{{"id": "U{}", "team_id": "T1", "name": "owen", "profile": {{}}}}]"#,
        "0".repeat(128)
    );
    assert_eq!(
        refused_field(&[("users.json", long.as_str())])?,
        "users.json[0].id",
        "an id longer than a Slack id may be"
    );
    let folder = ("C1:board/2026-11-01.json", DAY);
    let field = refused_field(&[("users.json", USERS), folder])?;
    assert!(
        field.starts_with("C1:board/"),
        "a folder no list names, holding the separator: {field}"
    );
    Ok(())
}

#[test]
fn a_workspace_keyed_by_its_name_never_keys_as_a_workspace_id() -> TestResult {
    let named = r#"[{"id": "U0", "name": "owen", "profile": {}}]"#;
    let by_name = slack::decode(&SlackExport {
        workspace: "T1".to_owned(),
        files: export(&[("users.json", named), ("general/2026-11-01.json", DAY)]).files,
    })?;
    let by_id = decode(&[("users.json", USERS), ("general/2026-11-01.json", DAY)])?;
    assert_eq!(by_id.key, "T1");
    assert_ne!(
        by_name.key, by_id.key,
        "a workspace named T1 keys apart from the workspace whose id is T1"
    );
    assert_ne!(
        by_name.conversations[0].native_id,
        by_id.conversations[0].native_id
    );
    Ok(())
}

#[test]
fn a_message_whose_speaker_or_time_is_not_slacks_does_not_read() -> TestResult {
    let day = (
        "general/2026-11-01.json",
        r#"[
          {"type": "message", "user": "U1:x", "text": "a speaker with the separator", "ts": "1761955300.000100"},
          {"type": "message", "user": "U1", "text": "a time with the separator", "ts": "1761955400.000100:x"},
          {"type": "message", "user": "U1", "text": "a thread with the separator", "ts": "1761955500.000100", "thread_ts": "1761955300.000100:x"},
          {"type": "message", "user": "U1", "text": "a time of seven digits", "ts": "1761955550.0001001"},
          {"type": "message", "user": "U1", "text": "kept", "ts": "1761955600.000100"}
        ]"#,
    );
    let workspace = decode(&[("users.json", USERS), day])?;
    let general = &workspace.conversations[0];
    let texts: Vec<&str> = general
        .messages
        .iter()
        .map(|message| message.text.as_str())
        .collect();
    assert_eq!(texts, ["kept"]);
    assert_eq!(general.skipped.unreadable, 4);
    Ok(())
}
