//! A Google Drive source (MAIL-GOOGLE = A, ARCH-0027 #mail-drive; L2-17):
//! the Drive files the owner picked land as an attached folder source with
//! a remote origin. Metadata lands first and the text after it;
//! `changes.list` supersedes a changed file's text and retracts a removed
//! file's note; a token Drive no longer knows starts the feed again; a
//! Google Doc exports as Markdown; every call is charged within the
//! provider's per-user quota first; and one source's steps run one at a
//! time. The wire here is a fake Drive that records each call.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::mpsc;
use std::time::Duration;

use oneiron::consent::AuthenticatedOwner;
use oneiron::note::{
    DRIVE_WIRE_RATE_LIMITED, DriveChange, DriveChangesPage, DriveFileMeta, DriveOrigin, DriveQuota,
    DriveStepBudget, DriveWire, FolderFileState, FolderSource, NameOnlyReason,
};
use oneiron::registry::ENTITY_TYPE_NOTE;
use oneiron::store::GateDecisionId;
use oneiron::{Result, Vault, VaultConfig};

const DOC: &str = "application/vnd.google-apps.document";
const SHEET: &str = "application/vnd.google-apps.spreadsheet";
const FORM: &str = "application/vnd.google-apps.form";

/// A fake Drive: its files, the changes it reports next, the change token
/// it no longer knows, and every call.
#[derive(Default)]
struct FakeDrive {
    files: RefCell<HashMap<String, (DriveFileMeta, Vec<u8>)>>,
    changes: RefCell<Vec<DriveChange>>,
    forgotten: RefCell<Option<String>>,
    calls: RefCell<Vec<String>>,
    quota: Option<DriveQuota>,
    /// Holds each start read until the test lets it go.
    gate: Option<StartGate>,
}

/// A start read held until the test lets it go: it says it began, waits,
/// then answers (Drive's rate limit, or the start token).
struct StartGate {
    began: mpsc::Sender<()>,
    go: mpsc::Receiver<()>,
    rate_limited: bool,
}

impl FakeDrive {
    fn put(&self, id: &str, name: &str, mime_type: &str, modified_at: u64, text: &str) {
        let stored = !mime_type.starts_with("application/vnd.google-apps.");
        let meta = DriveFileMeta {
            id: id.to_owned(),
            name: name.to_owned(),
            mime_type: mime_type.to_owned(),
            modified_at,
            size: stored.then_some(text.len() as u64),
            trashed: false,
        };
        self.files
            .borrow_mut()
            .insert(id.to_owned(), (meta, text.as_bytes().to_vec()));
    }

    /// Changes `id` to `text` at `modified_at`, and reports it next.
    fn change(&self, id: &str, modified_at: u64, text: &str) {
        let (meta, _) = self.files.borrow()[id].clone();
        self.put(id, &meta.name, &meta.mime_type, modified_at, text);
        let file = self.files.borrow()[id].0.clone();
        self.changes.borrow_mut().push(DriveChange {
            file_id: id.to_owned(),
            removed: false,
            file: Some(file),
        });
    }

    /// Removes `id`, and reports it next.
    fn remove(&self, id: &str) {
        self.files.borrow_mut().remove(id);
        self.changes.borrow_mut().push(DriveChange {
            file_id: id.to_owned(),
            removed: true,
            file: None,
        });
    }

    fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }

    fn record(&self, call: String) {
        self.calls.borrow_mut().push(call);
    }
}

impl DriveWire for FakeDrive {
    fn start_page_token(&self, _origin: &DriveOrigin) -> Result<String> {
        let starts = self.calls().iter().filter(|call| *call == "start").count();
        self.record("start".to_owned());
        if let Some(gate) = &self.gate {
            let _began = gate.began.send(());
            let _go = gate.go.recv_timeout(Duration::from_secs(30));
            if gate.rate_limited {
                return Err(oneiron::Error::InvalidConfig(
                    DRIVE_WIRE_RATE_LIMITED.to_owned(),
                ));
            }
        }
        Ok(format!("t{starts}"))
    }

    fn changes(&self, _origin: &DriveOrigin, token: &str) -> Result<Option<DriveChangesPage>> {
        self.record(format!("changes {token}"));
        if self.forgotten.borrow().as_deref() == Some(token) {
            return Ok(None);
        }
        let changes = std::mem::take(&mut *self.changes.borrow_mut());
        Ok(Some(DriveChangesPage {
            changes,
            next_page: None,
            new_start: Some(format!("{token}+")),
        }))
    }

    fn file(&self, _origin: &DriveOrigin, id: &str) -> Result<Option<DriveFileMeta>> {
        self.record(format!("file {id}"));
        Ok(self.files.borrow().get(id).map(|(meta, _)| meta.clone()))
    }

    fn download(&self, _origin: &DriveOrigin, id: &str) -> Result<Option<Vec<u8>>> {
        self.record(format!("download {id}"));
        Ok(self.files.borrow().get(id).map(|(_, bytes)| bytes.clone()))
    }

    fn export(&self, _origin: &DriveOrigin, id: &str, mime_type: &str) -> Result<Option<Vec<u8>>> {
        self.record(format!("export {id} {mime_type}"));
        Ok(self.files.borrow().get(id).map(|(_, bytes)| bytes.clone()))
    }

    fn quota(&self) -> Option<DriveQuota> {
        self.quota
    }
}

fn owned_vault(temp: &tempfile::TempDir) -> (Vault, AuthenticatedOwner) {
    let path = temp.path().join("vault");
    drop(Vault::open_owned(&path, VaultConfig::device()).expect("initialize vault"));
    let vault = Vault::open_owned(&path, VaultConfig::device()).expect("reopen vault");
    let actor = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault
        .authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    (vault, owner)
}

fn attach(vault: &Vault, owner: &AuthenticatedOwner, files: &[&str]) -> FolderSource {
    vault
        .attach_drive_source(
            owner,
            DriveOrigin {
                custody_ref: "google-drive-owen".to_owned(),
                account: "owen@example.com".to_owned(),
                files: files.iter().map(|id| (*id).to_owned()).collect(),
            },
            None,
        )
        .expect("attach the Drive source")
}

fn note_text(vault: &Vault, source: &FolderSource, id: &str) -> Option<String> {
    let note = Vault::imported_note_id(&source.namespace(), id).expect("NOTE id");
    vault
        .read_note(&note)
        .expect("read NOTE")
        .map(|note| note.markdown)
}

fn ledger_state(vault: &Vault, source: &FolderSource, id: &str) -> Option<FolderFileState> {
    vault
        .folder_source_files(&source.folder)
        .expect("ledger")
        .into_iter()
        .find(|file| file.path == id)
        .map(|file| file.state)
}

fn texts(count: usize) -> DriveStepBudget {
    DriveStepBudget {
        change_pages: 10,
        texts: count,
    }
}

#[test]
fn drive_metadata_lands_before_content() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let (vault, owner) = owned_vault(&temp);
    let drive = FakeDrive::default();
    drive.put(
        "docA1",
        "Roadmap",
        DOC,
        1_700_000_200,
        "# Roadmap\n\nShip the tide log.\n",
    );
    drive.put(
        "mdB2",
        "Plan.md",
        "text/markdown",
        1_700_000_100,
        "# Plan\n\nRead the logs.\n",
    );
    let source = attach(&vault, &owner, &["docA1", "mdB2"]);

    let first = vault
        .drive_sync_step(&owner, &source.folder, &drive, texts(0))
        .expect("first step");
    assert_eq!(
        drive.calls(),
        ["start", "file docA1", "file mdB2"],
        "the first step takes the feed's start, then each picked file's metadata, and reads no text"
    );
    assert_eq!(
        (first.metadata, first.texts, first.owed),
        (2, 0, 2),
        "{first:?}"
    );
    for id in ["docA1", "mdB2"] {
        assert_eq!(
            ledger_state(&vault, &source, id),
            Some(FolderFileState::NameOnly {
                why: NameOnlyReason::Unread
            }),
            "{id} is held by its name until its text is read"
        );
        assert_eq!(note_text(&vault, &source, id), None, "{id} has no note yet");
    }

    let second = vault
        .drive_sync_step(&owner, &source.folder, &drive, DriveStepBudget::default())
        .expect("second step");
    assert_eq!(
        drive.calls()[3..],
        ["changes t0", "export docA1 text/markdown", "download mdB2"],
        "the next step drains the feed, then reads the owed text newest first"
    );
    assert_eq!((second.texts, second.owed), (2, 0), "{second:?}");
    assert_eq!(second.rescan.landed, 2, "{second:?}");
    assert_eq!(
        note_text(&vault, &source, "docA1").as_deref(),
        Some("# Roadmap\n\nShip the tide log.\n")
    );
    assert_eq!(
        note_text(&vault, &source, "mdB2").as_deref(),
        Some("# Plan\n\nRead the logs.\n")
    );
    assert_eq!(
        ledger_state(&vault, &source, "mdB2"),
        Some(FolderFileState::Landed)
    );
}

#[test]
fn drive_changes_list_supersedes_and_retracts() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let (vault, owner) = owned_vault(&temp);
    let drive = FakeDrive::default();
    drive.put(
        "mdB2",
        "Plan.md",
        "text/markdown",
        1_700_000_100,
        "# Plan\n\nRead the logs.\n",
    );
    drive.put(
        "zzOther",
        "Other.md",
        "text/markdown",
        1_700_000_100,
        "# Other\n",
    );
    let source = attach(&vault, &owner, &["mdB2"]);
    let landed = vault
        .drive_sync_step(&owner, &source.folder, &drive, DriveStepBudget::default())
        .expect("first step");
    assert_eq!(landed.rescan.landed, 1, "{landed:?}");

    drive.change("mdB2", 1_700_000_300, "# Plan\n\nRead the logs twice.\n");
    drive.change("zzOther", 1_700_000_300, "# Other, changed\n");
    let changed = vault
        .drive_sync_step(&owner, &source.folder, &drive, DriveStepBudget::default())
        .expect("changed step");
    assert_eq!(changed.rescan.superseded, 1, "{changed:?}");
    assert_eq!(
        note_text(&vault, &source, "mdB2").as_deref(),
        Some("# Plan\n\nRead the logs twice.\n"),
        "the new revision's text supersedes the note's"
    );
    assert!(
        drive.calls().iter().all(|call| !call.contains("zzOther")),
        "a file the owner did not pick is never read: {:?}",
        drive.calls()
    );

    drive.remove("mdB2");
    let removed = vault
        .drive_sync_step(&owner, &source.folder, &drive, DriveStepBudget::default())
        .expect("removed step");
    assert_eq!(removed.rescan.retracted, 1, "{removed:?}");
    assert_eq!(
        ledger_state(&vault, &source, "mdB2"),
        Some(FolderFileState::Retracted)
    );
    let note = Vault::imported_note_id(&source.namespace(), "mdB2").expect("NOTE id");
    assert_eq!(
        vault.get_entity_type(&note).expect("NOTE type"),
        Some(ENTITY_TYPE_NOTE),
        "a removed file's note is archived, never erased"
    );
}

#[test]
fn an_unknown_change_token_starts_the_feed_again() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let (vault, owner) = owned_vault(&temp);
    let drive = FakeDrive::default();
    drive.put(
        "mdB2",
        "Plan.md",
        "text/markdown",
        1_700_000_100,
        "# Plan\n\nRead the logs.\n",
    );
    let source = attach(&vault, &owner, &["mdB2"]);
    let landed = vault
        .drive_sync_step(&owner, &source.folder, &drive, DriveStepBudget::default())
        .expect("first step");
    assert_eq!(landed.rescan.landed, 1, "{landed:?}");
    assert_eq!(drive.calls(), ["start", "file mdB2", "download mdB2"]);

    // Drive forgets the source's token, and the change it would have
    // reported is lost with it.
    *drive.forgotten.borrow_mut() = Some("t0".to_owned());
    drive.put(
        "mdB2",
        "Plan.md",
        "text/markdown",
        1_700_000_300,
        "# Plan\n\nRead the logs twice.\n",
    );
    let again = vault
        .drive_sync_step(&owner, &source.folder, &drive, DriveStepBudget::default())
        .expect("a step on a forgotten token");
    assert_eq!(
        drive.calls()[3..],
        ["changes t0", "start", "file mdB2", "download mdB2"],
        "a token Drive no longer knows starts the feed again in the same step"
    );
    assert_eq!(again.rescan.superseded, 1, "{again:?}");
    assert_eq!(
        note_text(&vault, &source, "mdB2").as_deref(),
        Some("# Plan\n\nRead the logs twice.\n"),
        "the change the lost token held is read from the file's metadata"
    );

    vault
        .drive_sync_step(&owner, &source.folder, &drive, DriveStepBudget::default())
        .expect("a step after the new start");
    assert_eq!(
        drive.calls()[7..],
        ["changes t1"],
        "the source keeps the new start token"
    );
}

#[test]
fn a_google_doc_exports_as_markdown() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let (vault, owner) = owned_vault(&temp);
    let drive = FakeDrive::default();
    drive.put(
        "docA1",
        "Roadmap",
        DOC,
        1_700_000_300,
        "# Roadmap\n\n- tide log\n",
    );
    drive.put(
        "sheetC3",
        "Budget",
        SHEET,
        1_700_000_200,
        "item,cost\nrope,12\n",
    );
    drive.put("formD4", "Survey", FORM, 1_700_000_100, "");
    let source = attach(&vault, &owner, &["docA1", "sheetC3", "formD4"]);

    let step = vault
        .drive_sync_step(&owner, &source.folder, &drive, DriveStepBudget::default())
        .expect("step");
    let reads: Vec<String> = drive
        .calls()
        .into_iter()
        .filter(|call| call.starts_with("export") || call.starts_with("download"))
        .collect();
    assert_eq!(
        reads,
        ["export docA1 text/markdown", "export sheetC3 text/csv"],
        "a Doc exports as Markdown, a Sheet as CSV, and a form makes no call"
    );
    assert_eq!(step.rescan.landed, 2, "{step:?}");
    assert_eq!(
        note_text(&vault, &source, "docA1").as_deref(),
        Some("# Roadmap\n\n- tide log\n")
    );
    assert_eq!(
        note_text(&vault, &source, "sheetC3").as_deref(),
        Some("item,cost\nrope,12\n")
    );
    assert_eq!(
        ledger_state(&vault, &source, "formD4"),
        Some(FolderFileState::NameOnly {
            why: NameOnlyReason::Unsupported
        })
    );
}

#[test]
fn a_step_out_of_quota_rests_with_no_provider_call() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let (vault, owner) = owned_vault(&temp);
    let drive = FakeDrive {
        // The start and one metadata read fit; a download does not.
        quota: Some(DriveQuota {
            units_per_minute: 20,
            list: 100,
            get: 5,
            content: 200,
        }),
        ..FakeDrive::default()
    };
    drive.put(
        "mdB2",
        "Plan.md",
        "text/markdown",
        1_700_000_100,
        "# Plan\n",
    );
    let source = attach(&vault, &owner, &["mdB2"]);

    let first = vault
        .drive_sync_step(&owner, &source.folder, &drive, DriveStepBudget::default())
        .expect("first step");
    assert_eq!(drive.calls(), ["start", "file mdB2"]);
    assert!(first.quota_paused_until.is_some(), "{first:?}");
    assert_eq!((first.texts, first.owed), (0, 1), "{first:?}");
    assert_eq!(
        ledger_state(&vault, &source, "mdB2"),
        Some(FolderFileState::NameOnly {
            why: NameOnlyReason::Unread
        })
    );

    let resting = vault
        .drive_sync_step(&owner, &source.folder, &drive, DriveStepBudget::default())
        .expect("resting step");
    assert_eq!(
        drive.calls(),
        ["start", "file mdB2"],
        "a resting source makes no provider call"
    );
    assert!(resting.quota_paused_until.is_some(), "{resting:?}");
}

/// The owner's rescan steps the Drive source while the host's step of it is
/// under way, and Drive answers the host's step that its rate is spent. The
/// second step waits for the first, makes no call while the source rests,
/// and leaves the rest standing; without the wait it starts from the state
/// before the rest and, ending last, writes its own over it.
#[test]
fn a_concurrent_step_keeps_the_rest_a_rate_limit_answer_set() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let (vault, owner) = owned_vault(&temp);
    let source = attach(&vault, &owner, &["mdB2"]);
    let (first_began, first_begins) = mpsc::channel();
    let (first_go, first_goes) = mpsc::channel();
    let (second_began, second_begins) = mpsc::channel();
    let (second_go, second_goes) = mpsc::channel();
    let (vault, folder) = (&vault, source.folder.as_str());
    let (first_owner, second_owner) = (owner.clone(), owner.clone());
    std::thread::scope(|scope| {
        let first = scope.spawn(move || {
            let drive = FakeDrive {
                gate: Some(StartGate {
                    began: first_began,
                    go: first_goes,
                    rate_limited: true,
                }),
                ..FakeDrive::default()
            };
            vault
                .drive_sync_step(&first_owner, folder, &drive, DriveStepBudget::default())
                .map_err(|error| error.to_string())
        });
        first_begins
            .recv_timeout(Duration::from_secs(60))
            .expect("the first step reads its start");
        let second = scope.spawn(move || {
            let drive = FakeDrive {
                gate: Some(StartGate {
                    began: second_began,
                    go: second_goes,
                    rate_limited: false,
                }),
                ..FakeDrive::default()
            };
            drive.put(
                "mdB2",
                "Plan.md",
                "text/markdown",
                1_700_000_100,
                "# Plan\n",
            );
            let report = vault
                .drive_sync_step(&second_owner, folder, &drive, DriveStepBudget::default())
                .map_err(|error| error.to_string());
            (report, drive.calls())
        });
        // Without the wait, the second step reads its start while the first
        // is under way; with it, it waits for the first to end.
        let _second_began = second_begins.recv_timeout(Duration::from_secs(3));
        first_go.send(()).expect("let the first step go");
        let first = first
            .join()
            .expect("the first step ends")
            .expect("the first step pauses");
        let _second_go = second_go.send(());
        let (second, second_calls) = second.join().expect("the second step ends");
        let second = second.expect("the second step pauses");

        let until = first
            .quota_paused_until
            .expect("the rate-limited step rests the source");
        assert_eq!(
            second_calls,
            Vec::<String>::new(),
            "the second step makes no call while the source rests: {second:?}"
        );
        let after = FakeDrive::default();
        let resting = vault
            .drive_sync_step(&owner, folder, &after, DriveStepBudget::default())
            .expect("a step after both");
        assert_eq!(
            after.calls(),
            Vec::<String>::new(),
            "the rest the first step set stands after the second ends"
        );
        assert_eq!(resting.quota_paused_until, Some(until), "{resting:?}");
    });
}
