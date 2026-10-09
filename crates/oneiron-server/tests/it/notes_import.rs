//! `oneiron import notes <folder>` through the shipped binary: a folder of
//! linked markdown notes is one batch the owner approves or declines whole
//! (wave 9b, owner 2026-10-10). Its notes land with their titles and kinds,
//! their links as `mentions` edges, an unresolved link is counted, a declined
//! batch admits nothing, and a re-import of an unchanged folder adds nothing.
//! The folder is written here: small invented notes in an Obsidian-like
//! layout (frontmatter, a subfolder, a hidden folder, code fences).
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use oneiron::edge::EdgeKind;
use oneiron::registry::ENTITY_TYPE_NOTE;
use oneiron::{EntityId, Vault, VaultConfig};
use serde_json::Value;

/// A fresh vault, the config file `init` wrote for it, and a notes folder.
struct Home {
    dir: tempfile::TempDir,
    vault: PathBuf,
    config: PathBuf,
    notes: PathBuf,
}

impl Home {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("test fixture");
        let vault = dir.path().join("vault");
        let config = dir.path().join("oneiron.toml");
        let init = Command::new(env!("CARGO_BIN_EXE_oneiron"))
            .args(["init", vault.to_str().expect("test fixture")])
            .args([
                "--config",
                config.to_str().expect("test fixture"),
                "--embedder",
                "none",
            ])
            .output()
            .expect("test fixture");
        assert!(
            init.status.success(),
            "init: {}",
            String::from_utf8_lossy(&init.stderr)
        );
        let notes = dir.path().join("notes");
        Self {
            dir,
            vault,
            config,
            notes,
        }
    }

    fn write(&self, path: &str, text: &str) {
        let file = self.notes.join(path);
        std::fs::create_dir_all(file.parent().expect("test fixture")).expect("test fixture");
        std::fs::write(file, text).expect("test fixture");
    }

    fn oneiron(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_oneiron"))
            .args(args)
            .arg("--config")
            .arg(&self.config)
            .env_remove("ONEIRON_VAULT_PATH")
            .output()
            .expect("test fixture")
    }

    fn ok(&self, args: &[&str]) -> Value {
        let output = self.oneiron(args);
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("a JSON report on stdout")
    }

    /// `import notes` into a new batch file; its report.
    fn import(&self, batch: &str) -> Value {
        let out = self.dir.path().join(batch);
        self.ok(&[
            "import",
            "notes",
            self.notes.to_str().expect("test fixture"),
            "--out",
            out.to_str().expect("test fixture"),
        ])
    }

    fn decide(&self, verb: &str, report: &Value) -> Output {
        let batch = &report["batch"];
        self.oneiron(&[
            "import",
            verb,
            batch["file"].as_str().expect("a batch file"),
            "--digest",
            batch["digest"].as_str().expect("a digest"),
        ])
    }

    fn open(&self) -> Vault {
        Vault::open_owned(&self.vault, VaultConfig::server()).expect("open vault")
    }

    fn id(&self, path: &str) -> EntityId {
        let folder = std::fs::canonicalize(&self.notes).expect("test fixture");
        Vault::imported_note_id(&folder.to_string_lossy(), path).expect("test fixture")
    }
}

/// Six notes (one holds a credential), a blank file and a hidden folder. Ten
/// links: eight resolve (one to the credential's note), one names no note,
/// one embeds a picture; two more sit in code.
fn write_folder(home: &Home) {
    home.write(
        "MEMORY.md",
        "# Index\n\n- [[alpha]]\n- [[beta]]\n- [[notes/gamma]]\n- [[secret]]\n",
    );
    home.write(
        "alpha.md",
        "---\nname: alpha\ndescription: the first note\nmetadata:\n  type: feedback\n---\n\
         Alpha points at [[beta]] and [[gamma|the gamma note]] and [[missing-note]].\n\n\
         ```\n[[beta-in-code]]\n```\n\nInline `[[not-a-link]]` is code.\n",
    );
    home.write(
        "beta.md",
        "---\nname: beta\ntype: research\n---\nBeta answers [[alpha#Why]].\n\n![[photo.png]]\n",
    );
    home.write("notes/gamma.md", "Gamma links back to [[Alpha]].\n");
    home.write("other/alpha.md", "---\nname: alpha\n---\nA second alpha.\n");
    home.write(
        "secret.md",
        "here it is: token=ghp_0123456789abcdefghijklmnopqrstuvwxyz\n",
    );
    home.write("empty.md", "  \n");
    home.write(".obsidian/workspace.md", "[[alpha]]\n");
}

fn note_count(vault: &Vault) -> u64 {
    vault
        .count_entities_by_type(ENTITY_TYPE_NOTE)
        .expect("test fixture")
}

#[test]
fn a_notes_folder_lands_as_one_approved_batch_and_a_reimport_adds_nothing() {
    let home = Home::new();
    write_folder(&home);

    // The preview reads the folder and lands nothing.
    let first = home.import("first.json");
    assert_eq!(first["notes"]["found"], 6);
    assert_eq!(first["notes"]["new"], 5);
    assert_eq!(
        first["notes"]["refused"], 1,
        "the secret scan would refuse it"
    );
    assert_eq!(first["notes"]["blank"], 1);
    assert_eq!(first["kinds"]["observation"], 4);
    assert_eq!(first["kinds"]["research"], 1);
    assert_eq!(first["types"]["feedback"], 1);
    assert_eq!(first["titles"]["frontmatter"], 2);
    assert_eq!(first["titles"]["file_name"], 2);
    assert_eq!(
        first["titles"]["path"], 1,
        "a taken title falls back to the path"
    );
    let links = &first["links"];
    assert_eq!(links["found"], 10, "links in code are not links");
    assert_eq!(links["resolved"], 8);
    assert_eq!(links["unresolved"], 1);
    assert_eq!(links["attachments"], 1);
    assert_eq!(links["to_left_out"], 1);
    assert_eq!(links["new"], 7);
    assert_eq!(first["batch"]["notes"], 5);
    assert_eq!(first["batch"]["links"], 7);
    assert_eq!(note_count(&home.open()), 0);

    // Declined: nothing is admitted, and the decision is final.
    let declined = home.decide("decline", &first);
    assert!(declined.status.success(), "decline");
    assert_eq!(note_count(&home.open()), 0);
    assert!(!home.decide("approve", &first).status.success());
    assert_eq!(note_count(&home.open()), 0);

    // A new batch of the same folder, approved: every note and link lands.
    let second = home.import("second.json");
    assert_eq!(second["notes"]["new"], 5);
    let approved = home.decide("approve", &second);
    assert!(
        approved.status.success(),
        "approve: {}",
        String::from_utf8_lossy(&approved.stderr)
    );
    let approved: Value = serde_json::from_slice(&approved.stdout).expect("a JSON receipt");
    assert_eq!(approved["notes"], 5);
    assert_eq!(approved["links"], 7);
    assert!(!home.decide("approve", &second).status.success());

    let vault = home.open();
    assert_eq!(note_count(&vault), 5);
    let alpha = home.id("alpha.md");
    let beta = home.id("beta.md");
    let gamma = home.id("notes/gamma.md");
    let index = home.id("MEMORY.md");
    let title = |id: EntityId| vault.note_document(id).expect("a note").title;
    let kind = |id: EntityId| {
        vault
            .read_note(&id)
            .expect("test fixture")
            .expect("a note")
            .kind
            .as_str()
            .into_owned()
    };
    assert_eq!(title(alpha).as_deref(), Some("alpha"));
    assert_eq!(title(gamma).as_deref(), Some("gamma"));
    assert_eq!(
        title(home.id("other/alpha.md")).as_deref(),
        Some("other/alpha")
    );
    assert_eq!(kind(alpha), "observation");
    assert_eq!(kind(beta), "research");
    let alpha_body = vault.note_document(alpha).expect("a note").markdown;
    assert!(
        alpha_body.starts_with("---\nname: alpha\ndescription: the first note\n"),
        "a note keeps its file as written"
    );
    let mentions = |id: EntityId| {
        let mut targets = vault
            .targets(&id, EdgeKind::Mentions, Some(ENTITY_TYPE_NOTE))
            .expect("test fixture");
        targets.sort();
        targets
    };
    let mut alpha_links = vec![beta, gamma];
    alpha_links.sort();
    assert_eq!(mentions(alpha), alpha_links);
    assert_eq!(mentions(beta), vec![alpha]);
    assert_eq!(mentions(gamma), vec![alpha]);
    assert_eq!(mentions(index).len(), 3);
    drop(vault);

    // The same folder again: nothing is new, no batch is written.
    let again = home.import("again.json");
    assert_eq!(again["notes"]["new"], 0);
    assert_eq!(again["notes"]["unchanged"], 5);
    assert_eq!(again["links"]["new"], 0);
    assert!(again["batch"].is_null());
    assert!(!home.dir.path().join("again.json").exists());
    assert_eq!(note_count(&home.open()), 5);

    // A new note lands with its links; a changed one waits as it is.
    home.write("delta.md", "Delta follows [[alpha]].\n");
    home.write(
        "alpha.md",
        "---\nname: alpha\n---\nAlpha now points at [[delta]] too.\n",
    );
    let later = home.import("later.json");
    assert_eq!(later["notes"]["new"], 1);
    assert_eq!(later["notes"]["changed"], 1);
    assert_eq!(later["notes"]["unchanged"], 4);
    assert_eq!(later["batch"]["links"], 1, "only delta's link lands");
    assert!(home.decide("approve", &later).status.success());
    let vault = home.open();
    assert_eq!(note_count(&vault), 6);
    assert_eq!(
        vault
            .targets(&home.id("delta.md"), EdgeKind::Mentions, None)
            .expect("test fixture"),
        vec![alpha]
    );
    assert!(
        vault
            .note_document(alpha)
            .expect("a note")
            .markdown
            .contains("the first note"),
        "a changed file does not overwrite its note"
    );
}

#[test]
fn a_batch_edited_after_its_preview_is_refused() {
    let home = Home::new();
    write_folder(&home);
    let report = home.import("batch.json");
    let file = Path::new(report["batch"]["file"].as_str().expect("a batch file"));
    let text = std::fs::read_to_string(file).expect("test fixture");
    std::fs::write(file, text.replace("A second alpha.", "A changed alpha."))
        .expect("test fixture");
    assert!(!home.decide("approve", &report).status.success());
    assert_eq!(note_count(&home.open()), 0);
}
