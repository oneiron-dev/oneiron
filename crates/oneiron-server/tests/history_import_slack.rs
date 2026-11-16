//! L2-18 PR 2: `oneiron import slack <zip | folder> --members <map.json>`,
//! through the shipped binary (ARCH-0027 #import-audience; the owner's
//! IMPORT-IDENTITY and IMPORT-PUBLIC rulings of 15 Nov 00:43; Engine rulings
//! L2-18-READERS = A and L2-18-CONTACT = A). Each conversation reads to the
//! members Slack shares it with whom the map gives a vault person, and to the
//! owner; a public channel's members are the whole workspace. Every other
//! member is a contact: its name is kept and it reads nothing. A workspace
//! with no member mapped reads to the owner alone, and the run says so. Every
//! TURN the import births is born under the workspace's own facet (Engine
//! ruling L2-18-WORKSPACE-FACET-CARRIER = A). On main `slack` is no `import`
//! subcommand.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --features oneiron/test-support --test history_import_slack`
#![cfg(oneiron_test_support)]

use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use oneiron::ingest::history::HistorySource;
use oneiron::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON};
use oneiron::test_doors::history_import_rows::imported_message_rows;
use oneiron::test_doors::source_audience_binding::reads;
use oneiron::{EdgeKind, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::Value;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The export: owen (U0, the owner's own member), yuki (U1) and sam (U2).
/// `general` is public and lists owen and yuki; `board` is private to owen
/// and sam. Five messages, one of them a join that is not kept.
const EXPORT: [(&str, &str); 5] = [
    (
        "users.json",
        r#"[
          {"id": "U0", "team_id": "T1", "name": "owen", "profile": {"display_name": "owen"}},
          {"id": "U1", "team_id": "T1", "name": "yuki", "profile": {"display_name": "yuki"}},
          {"id": "U2", "team_id": "T1", "name": "sam", "profile": {"display_name": "sam"}}
        ]"#,
    ),
    (
        "channels.json",
        r#"[{"id": "C1", "name": "general", "created": 1761955000, "members": ["U0", "U1"]}]"#,
    ),
    (
        "groups.json",
        r#"[{"id": "G1", "name": "board", "created": 1761955100, "members": ["U0", "U2"]}]"#,
    ),
    (
        "general/2026-11-01.json",
        r#"[
          {"type": "message", "user": "U0", "text": "who books the venue?", "ts": "1761955300.000100"},
          {"type": "message", "user": "U1", "text": "I can", "ts": "1761955400.000100"},
          {"type": "message", "subtype": "channel_join", "user": "U2", "text": "<@U2> has joined", "ts": "1761955450.000100"},
          {"type": "message", "user": "U2", "text": "count me in", "ts": "1761955500.000100"}
        ]"#,
    ),
    (
        "board/2026-11-01.json",
        r#"[{"type": "message", "user": "U2", "text": "budget is set", "ts": "1761955600.000100"}]"#,
    ),
];

/// The messages of `EXPORT` that land.
const LANDED: u64 = 4;

/// A fresh vault and the config file `init` wrote for it, with three
/// PERSONs put before any import: yuki, sam and an outsider who was never in
/// the workspace.
struct Home {
    dir: tempfile::TempDir,
    vault: PathBuf,
    config: PathBuf,
    owner: EntityId,
    yuki: EntityId,
    sam: EntityId,
    outsider: EntityId,
}

impl Home {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let vault = dir.path().join("vault");
        let config = dir.path().join("oneiron.toml");
        let init = Command::new(env!("CARGO_BIN_EXE_oneiron"))
            .arg("init")
            .arg(&vault)
            .arg("--config")
            .arg(&config)
            .args(["--embedder", "none"])
            .output()?;
        assert!(init.status.success(), "init: {}", stderr(&init));
        let (owner, yuki, sam, outsider) = {
            let opened = Vault::open_owned(&vault, VaultConfig::server())?;
            let owner = opened.ensure_embedded_owner_actor()?;
            let person = |body: &[u8]| -> Result<EntityId, Box<dyn std::error::Error>> {
                let id = EntityId::now();
                opened.put_entity(
                    &id,
                    ENTITY_TYPE_PERSON,
                    TimeRange { start: 1, end: 1 },
                    1,
                    body,
                )?;
                Ok(id)
            };
            (
                owner,
                person(b"yuki")?,
                person(b"sam")?,
                person(b"outsider")?,
            )
        };
        Ok(Self {
            dir,
            vault,
            config,
            owner,
            yuki,
            sam,
            outsider,
        })
    }

    /// Writes the member map `map` and returns its path.
    fn members(&self, map: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let path = self.dir.path().join("members.json");
        std::fs::write(&path, map)?;
        Ok(path)
    }

    /// Runs `oneiron import slack <export> --members <map>`.
    fn import(&self, export: &Path, members: &Path) -> Result<Output, std::io::Error> {
        Command::new(env!("CARGO_BIN_EXE_oneiron"))
            .args(["import", "slack"])
            .arg(export)
            .arg("--members")
            .arg(members)
            .args(["--workspace", "Example"])
            .arg("--config")
            .arg(&self.config)
            .env_remove("ONEIRON_VAULT_PATH")
            .output()
    }

    /// The export as a zip, with `extra` entries after it.
    fn zip(&self, extra: &[(&str, &str)]) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, text) in EXPORT.iter().chain(extra) {
            zip.start_file(*name, zip::write::FileOptions::default())?;
            zip.write_all(text.as_bytes())?;
        }
        let path = self.dir.path().join("Example Slack export Nov 1 2026.zip");
        std::fs::write(&path, zip.finish()?.into_inner())?;
        Ok(path)
    }

    /// The export as an unzipped folder.
    fn folder(&self) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let root = self.dir.path().join("export");
        for (name, text) in EXPORT {
            let path = root.join(name);
            std::fs::create_dir_all(path.parent().expect("a file under the folder"))?;
            std::fs::write(path, text)?;
        }
        Ok(root)
    }

    fn open(&self) -> Result<Vault, Box<dyn std::error::Error>> {
        Ok(Vault::open_owned(&self.vault, VaultConfig::server())?)
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Asserts the import succeeded and returns its report.
fn landed(output: &Output) -> Result<Value, Box<dyn std::error::Error>> {
    assert!(output.status.success(), "import: {}", stderr(output));
    Ok(serde_json::from_slice(&output.stdout)?)
}

/// The report of the conversation `native_id`.
fn conversation<'r>(report: &'r Value, native_id: &str) -> &'r Value {
    report["conversations"]
        .as_array()
        .and_then(|conversations| {
            conversations
                .iter()
                .find(|conversation| conversation["conversation"] == native_id)
        })
        .unwrap_or_else(|| panic!("{native_id} is in the report: {report}"))
}

/// The CONVERSATION, TURN and MESSAGE rows of the message `native_id`.
fn rows(vault: &Vault, native_id: &str) -> Result<Vec<EntityId>, Box<dyn std::error::Error>> {
    let rows = imported_message_rows(vault, HistorySource::Slack, native_id)?
        .ok_or_else(|| format!("message {native_id} did not land"))?;
    Ok(vec![rows.conversation, rows.turn, rows.message])
}

#[test]
fn oneiron_import_slack_lands_each_channel_bound_to_its_mapped_members() -> TestResult {
    let home = Home::new()?;
    let members = home.members(&format!(
        r#"{{"U0": "owner", "U1": "{}", "U2": null}}"#,
        home.yuki.to_hex()
    ))?;
    let export = home.zip(&[])?;
    let output = home.import(&export, &members)?;
    let report = landed(&output)?;
    assert_eq!(report["source"], "slack");
    assert_eq!(report["totals"]["new"], LANDED);
    assert_eq!(report["totals"]["refused"], 0);
    assert_eq!(report["workspace"]["name"], "Example");
    assert_eq!(report["workspace"]["members"], 2);
    assert_eq!(report["workspace"]["matched"], 1);
    assert_eq!(report["workspace"]["contacts"], 1);
    assert_eq!(report["workspace"]["owner_only"], false);
    // general is public: its members are the workspace, so yuki (mapped)
    // and the owner read it, and sam is a contact.
    let general = conversation(&report, "T1:C1");
    assert_eq!(general["sharing"]["readers"], 2);
    assert_eq!(general["sharing"]["unmapped"], 1);
    let board = conversation(&report, "T1:G1");
    assert_eq!(board["sharing"]["readers"], 1);
    assert_eq!(board["sharing"]["unmapped"], 1);
    assert!(
        stderr(&output).contains("Example: 1 of 2 matched, 1 kept as contacts"),
        "stderr: {}",
        stderr(&output)
    );

    let vault = home.open()?;
    for row in rows(&vault, "T1:C1:1761955400.000100")? {
        assert!(
            reads(&vault, row, &[home.yuki])?,
            "yuki reads general's {row:?}"
        );
        assert!(
            reads(&vault, row, &[home.owner])?,
            "the owner reads general's {row:?}"
        );
        assert!(
            !reads(&vault, row, &[home.sam])?,
            "sam's PERSON is not mapped, so it reads nothing of {row:?}"
        );
        assert!(
            !reads(&vault, row, &[home.outsider])?,
            "a person never in the workspace reads nothing of {row:?}"
        );
    }
    for row in rows(&vault, "T1:G1:1761955600.000100")? {
        assert!(
            reads(&vault, row, &[home.owner])?,
            "the owner reads board's {row:?}"
        );
        assert!(
            !reads(&vault, row, &[home.yuki])?,
            "yuki is not in the private channel, so reads nothing of {row:?}"
        );
    }
    let table: Vec<(String, Option<String>, Option<EntityId>, bool)> = vault
        .history_import_members(HistorySource::Slack, "T1")?
        .into_iter()
        .map(|member| {
            (
                member.provider_id,
                member.name,
                member.person,
                member.importer,
            )
        })
        .collect();
    assert_eq!(
        table,
        vec![
            ("U0".to_owned(), Some("owen".to_owned()), None, true),
            (
                "U1".to_owned(),
                Some("yuki".to_owned()),
                Some(home.yuki),
                false
            ),
            ("U2".to_owned(), Some("sam".to_owned()), None, false),
        ],
        "every member is kept by name; sam is a contact"
    );
    drop(vault);

    let again = landed(&home.import(&export, &members)?)?;
    assert_eq!(again["totals"]["new"], 0, "a re-import adds nothing");
    Ok(())
}

#[test]
fn a_slack_export_entry_that_escapes_is_listed_and_the_rest_lands() -> TestResult {
    let home = Home::new()?;
    let members = home.members(r#"{"U0": "owner"}"#)?;
    let export = home.zip(&[(
        "../general/2026-11-02.json",
        r#"[{"type": "message", "user": "U1", "text": "from outside", "ts": "1762041600.000100"}]"#,
    )])?;
    let report = landed(&home.import(&export, &members)?)?;
    assert_eq!(report["totals"]["new"], LANDED, "the rest lands");
    let skipped: Vec<(&str, &str)> = report["warnings"]
        .as_array()
        .expect("warnings")
        .iter()
        .filter(|warning| warning["warning"] == "archive_entry_skipped")
        .filter_map(|warning| Some((warning["name"].as_str()?, warning["reason"].as_str()?)))
        .collect();
    assert_eq!(
        skipped,
        vec![("../general/2026-11-02.json", "escaping_path")]
    );
    Ok(())
}

#[test]
fn a_workspace_with_no_member_mapped_reads_to_the_owner_alone() -> TestResult {
    let home = Home::new()?;
    // The dead-workspace import: no member is anyone in the vault.
    let members = home.members("{}")?;
    let output = home.import(&home.folder()?, &members)?;
    let report = landed(&output)?;
    assert_eq!(report["totals"]["new"], LANDED);
    assert_eq!(report["workspace"]["owner_only"], true);
    assert_eq!(report["workspace"]["matched"], 0);
    assert_eq!(report["workspace"]["contacts"], 3);
    assert!(
        stderr(&output).contains("Example: 0 of 3 matched, kept as contacts, owner-only"),
        "stderr: {}",
        stderr(&output)
    );
    let vault = home.open()?;
    for native_id in ["T1:C1:1761955300.000100", "T1:G1:1761955600.000100"] {
        for row in rows(&vault, native_id)? {
            assert!(
                reads(&vault, row, &[home.owner])?,
                "the owner reads {row:?}"
            );
            for other in [home.yuki, home.sam, home.outsider] {
                assert!(
                    !reads(&vault, row, &[other])?,
                    "no vault person but the owner reads {row:?}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn the_imports_turns_are_born_under_the_workspaces_facet() -> TestResult {
    let home = Home::new()?;
    let members = home.members(r#"{"U0": "owner"}"#)?;
    let export = home.zip(&[])?;
    let report = landed(&home.import(&export, &members)?)?;
    let named = report["workspace"]["facet"]
        .as_str()
        .ok_or("the report names the workspace's facet")?;
    let facet = EntityId::from_hex(named).map_err(|_| "the facet is an id in hex")?;
    let vault = home.open()?;
    for native_id in ["C1:1761955300.000100", "G1:1761955600.000100"] {
        let rows = imported_message_rows(&vault, HistorySource::Slack, native_id)?
            .ok_or_else(|| format!("message {native_id} did not land"))?;
        assert_eq!(
            vault.targets(&rows.turn, EdgeKind::FacetOf, Some(ENTITY_TYPE_FACET))?,
            vec![facet],
            "the TURN of {native_id} is born under the workspace's facet"
        );
        for row in [rows.conversation, rows.message] {
            assert!(
                vault.targets(&row, EdgeKind::FacetOf, None)?.is_empty(),
                "{native_id}: a CONVERSATION or MESSAGE keeps its substrate facet"
            );
        }
    }
    assert!(
        vault.facets_of(&home.owner)?.contains(&facet),
        "the owner wears the workspace's facet"
    );
    drop(vault);
    let again = landed(&home.import(&export, &members)?)?;
    assert_eq!(
        again["workspace"]["facet"], report["workspace"]["facet"],
        "a later import finds the workspace's facet by name"
    );
    Ok(())
}
