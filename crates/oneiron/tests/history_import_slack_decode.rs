//! L2-18 PR 2 (ARCH-0027 #import-audience): a Slack workspace export decodes
//! into one conversation per channel, private channel, group DM or DM, each
//! with the members Slack shares it with. A public channel names every member
//! of the workspace, so it reads to every vault person matched to that
//! workspace (owner ruling IMPORT-PUBLIC = D, 15 Nov 00:43). Every message
//! names its speaker as `slack:<member id>` until the owner's member map says
//! which member is the owner, whose words then land as the owner's; every
//! member the map gives no person stays a contact (Engine ruling
//! L2-18-CONTACT = A). On main the reader does not exist.
//!
//! `cargo test --locked -p oneiron --all-features --test history_import_slack_decode`

use oneiron::EntityId;
use oneiron::ingest::history::slack::{
    self, SlackExport, SlackExportFile, SlackMemberCounts, SlackMemberMapping, SlackWorkspace,
};
use oneiron::ingest::history::{HistoryConversation, HistoryFile, HistoryRole, HistorySource};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A workspace of three members: owen (U0), yuki (U1) and sam (U2). The
/// public channel `general` lists owen and yuki, the private channel `board`
/// owen and sam, and the DM D1 owen and yuki.
fn export() -> SlackExport {
    let file = |path: &str, text: &str| SlackExportFile {
        path: path.to_owned(),
        text: text.to_owned(),
    };
    SlackExport {
        workspace: "Example".to_owned(),
        files: vec![
            file(
                "users.json",
                r#"[
                  {"id": "U0", "team_id": "T1", "name": "owen",
                   "profile": {"display_name": "owen", "email": "owen@example.com"}},
                  {"id": "U1", "team_id": "T1", "name": "yuki",
                   "profile": {"display_name": "", "real_name": "Yuki", "email": "yuki@example.com"}},
                  {"id": "U2", "team_id": "T1", "name": "sam", "profile": {}}
                ]"#,
            ),
            file(
                "channels.json",
                r#"[{"id": "C1", "name": "general", "created": 1761955000, "members": ["U0", "U1"]}]"#,
            ),
            file(
                "groups.json",
                r#"[{"id": "G1", "name": "board", "created": 1761955100, "members": ["U0", "U2"]}]"#,
            ),
            file(
                "dms.json",
                r#"[{"id": "D1", "created": 1761955200, "members": ["U0", "U1"]}]"#,
            ),
            // The later day first: the reader orders by Slack time.
            file(
                "general/2026-11-02.json",
                r#"[
                  {"type": "message", "user": "U1", "text": "the venue is booked", "ts": "1762041600.000200"},
                  {"type": "message", "subtype": "channel_join", "user": "U2", "text": "<@U2> has joined", "ts": "1762041700.000100"}
                ]"#,
            ),
            file(
                "general/2026-11-01.json",
                r#"[
                  {"type": "message", "user": "U0", "text": "who books the venue?", "ts": "1761955300.000100"},
                  {"type": "message", "user": "U1", "text": "I can", "ts": "1761955400.000100", "thread_ts": "1761955300.000100"}
                ]"#,
            ),
            file(
                "board/2026-11-01.json",
                r#"[
                  {"type": "message", "user": "U2", "text": "budget is set", "ts": "1761955500.000100"},
                  {"type": "message", "user": "U0", "text": "thanks", "ts": "1761955600.000100"}
                ]"#,
            ),
            file(
                "D1/2026-11-01.json",
                r#"[{"type": "message", "user": "U1", "text": "lunch friday?", "ts": "1761955700.000100"}]"#,
            ),
            file("integration_logs.json", "[]"),
        ],
    }
}

fn find<'w>(workspace: &'w SlackWorkspace, native_id: &str) -> &'w HistoryConversation {
    workspace
        .conversations
        .iter()
        .find(|conversation| conversation.native_id == native_id)
        .unwrap_or_else(|| panic!("conversation {native_id} decoded"))
}

fn member_ids(conversation: &HistoryConversation) -> Vec<&str> {
    conversation
        .sharing
        .as_ref()
        .expect("a Slack conversation carries its sharing")
        .members
        .iter()
        .map(|member| member.provider_id.as_str())
        .collect()
}

fn texts(conversation: &HistoryConversation) -> Vec<(&str, Option<&str>)> {
    conversation
        .messages
        .iter()
        .map(|message| (message.text.as_str(), message.said_by.as_deref()))
        .collect()
}

#[test]
fn a_slack_export_decodes_one_conversation_per_channel_with_its_members() -> TestResult {
    let workspace = slack::decode(&export())?;
    assert_eq!(workspace.key, "T1");
    assert_eq!(workspace.name, "Example");
    let members: Vec<(&str, &str, Option<&str>)> = workspace
        .members
        .iter()
        .map(|member| {
            (
                member.id.as_str(),
                member.name.as_str(),
                member.email.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        members,
        vec![
            ("U0", "owen", Some("owen@example.com")),
            ("U1", "Yuki", Some("yuki@example.com")),
            ("U2", "sam", None),
        ]
    );
    assert_eq!(workspace.passed, vec!["integration_logs.json".to_owned()]);
    let ids: Vec<&str> = workspace
        .conversations
        .iter()
        .map(|conversation| conversation.native_id.as_str())
        .collect();
    assert_eq!(ids, vec!["T1:C1", "T1:G1", "T1:D1"]);

    let general = find(&workspace, "T1:C1");
    assert_eq!(general.title.as_deref(), Some("general"));
    let sharing = general.sharing.as_ref().expect("general is shared");
    assert_eq!(sharing.container, "T1:C1");
    // A public channel reads to the whole workspace, not only its listed
    // members (IMPORT-PUBLIC = D).
    assert_eq!(member_ids(general), vec!["U0", "U1", "U2"]);
    assert_eq!(
        texts(general),
        vec![
            ("who books the venue?", Some("slack:U0")),
            ("I can", Some("slack:U1")),
            ("the venue is booked", Some("slack:U1")),
        ]
    );
    assert_eq!(general.messages[0].native_id, "T1:C1:1761955300.000100");
    assert_eq!(general.messages[0].at_ms, Some(1_761_955_300_000));
    assert_eq!(
        general.messages[1].parent_id.as_deref(),
        Some("T1:C1:1761955300.000100"),
        "a thread reply names the message that began its thread"
    );
    assert!(
        general
            .messages
            .iter()
            .all(|message| message.role == HistoryRole::User)
    );
    assert_eq!(general.skipped.system, 1, "the join is not kept");
    assert_eq!(general.started_at_ms, Some(1_761_955_000_000));

    let board = find(&workspace, "T1:G1");
    assert_eq!(member_ids(board), vec!["U0", "U2"]);
    assert_eq!(
        texts(board),
        vec![
            ("budget is set", Some("slack:U2")),
            ("thanks", Some("slack:U0"))
        ]
    );

    let dm = find(&workspace, "T1:D1");
    assert_eq!(member_ids(dm), vec!["U0", "U1"]);
    assert_eq!(dm.title.as_deref(), Some("owen, Yuki"));
    assert_eq!(texts(dm), vec![("lunch friday?", Some("slack:U1"))]);
    Ok(())
}

#[test]
fn the_member_map_lands_the_owners_words_as_the_owners_and_keeps_contacts() -> TestResult {
    let yuki = EntityId::now();
    let map = slack::parse_member_map(&format!(
        r#"{{"U0": "owner", "U1": "{}", "U2": null}}"#,
        yuki.to_hex()
    ))?;
    assert_eq!(map.get("U0"), Some(&SlackMemberMapping::Owner));
    assert_eq!(map.get("U1"), Some(&SlackMemberMapping::Person(yuki)));
    assert_eq!(map.get("U2"), Some(&SlackMemberMapping::Contact));

    let mut workspace = slack::decode(&export())?;
    let counts = workspace.map_members(&map)?;
    assert_eq!(
        counts,
        SlackMemberCounts {
            members: 2,
            matched: 1,
            contacts: 1,
        },
        "the owner's own member is not counted"
    );
    let general = find(&workspace, "T1:C1");
    let members: Vec<(&str, Option<EntityId>, bool)> = general
        .sharing
        .as_ref()
        .expect("general is shared")
        .members
        .iter()
        .map(|member| (member.provider_id.as_str(), member.person, member.importer))
        .collect();
    assert_eq!(
        members,
        vec![
            ("U0", None, true),
            ("U1", Some(yuki), false),
            ("U2", None, false)
        ]
    );
    assert_eq!(
        texts(general),
        vec![
            ("who books the venue?", None),
            ("I can", Some("slack:U1")),
            ("the venue is booked", Some("slack:U1")),
        ],
        "the owner's own words carry no other speaker"
    );

    let roster = workspace.mapped_members(&map);
    let names: Vec<(&str, Option<&str>, Option<EntityId>)> = roster
        .iter()
        .map(|member| {
            (
                member.provider_id.as_str(),
                member.name.as_deref(),
                member.person,
            )
        })
        .collect();
    assert_eq!(
        names,
        vec![
            ("U0", Some("owen"), None),
            ("U1", Some("Yuki"), Some(yuki)),
            ("U2", Some("sam"), None),
        ],
        "a contact keeps its name"
    );
    Ok(())
}

#[test]
fn a_member_map_naming_no_member_or_two_owners_is_refused() -> TestResult {
    let mut workspace = slack::decode(&export())?;
    let stranger = slack::parse_member_map(r#"{"U9": null}"#)?;
    assert!(
        workspace.map_members(&stranger).is_err(),
        "a member id the workspace does not list is refused, not ignored"
    );
    let two_owners = slack::parse_member_map(r#"{"U0": "owner", "U1": "owner"}"#)?;
    assert!(workspace.map_members(&two_owners).is_err());
    assert!(slack::parse_member_map("[]").is_err());
    assert!(slack::parse_member_map(r#"{"U1": 7}"#).is_err());
    assert!(slack::parse_member_map(r#"{"U1": "not hex"}"#).is_err());
    Ok(())
}

#[test]
fn slack_is_a_history_source_whose_export_decodes_only_whole() {
    assert_eq!(HistorySource::parse("slack"), Some(HistorySource::Slack));
    assert_eq!(HistorySource::Slack.source_id(), "slack");
    let file = HistoryFile {
        stem: "users".to_owned(),
        parent: None,
    };
    assert!(
        HistorySource::Slack.decode("[]", &file).is_err(),
        "one file of a Slack export is refused"
    );
    assert!(
        slack::decode(&SlackExport {
            workspace: "Example".to_owned(),
            files: Vec::new(),
        })
        .is_err(),
        "an export with no users.json is refused"
    );
}
