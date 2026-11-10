//! A folder attached to a stopped vault lands its Markdown files
//! (FIX-LIST [E2E-FOLDER-ATTACH-ABSENT-FACET], PORTABILITY-07). The folder's
//! importer is a MACHINE; its first write asked for its actor-stamp token,
//! a CLAIM born in the MACHINE's own substrate facet, which no row holds, so
//! every file was refused with "invalid active facet ... resolved type None,
//! expected FACET (13)". The CLI opens the vault owned, binds its embedded
//! owner, attaches, and hands the engine the files it read, as here.

use std::collections::HashMap;

use oneiron::note::{FolderRescan, ImportedNote};
use oneiron::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_NOTE};
use oneiron::store::GateDecisionId;
use oneiron::{Vault, VaultConfig};

#[test]
fn stopped_folder_attach_lands_two_markdown_notes() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let vault_path = temp.path().join("vault");
    let folder_path = temp.path().join("notes");
    std::fs::create_dir(&folder_path).expect("notes directory");
    std::fs::write(folder_path.join("first.md"), "# First\n\nFirst file.\n")
        .expect("first Markdown file");
    std::fs::write(folder_path.join("second.md"), "# Second\n\nSecond file.\n")
        .expect("second Markdown file");
    let folder = std::fs::canonicalize(&folder_path)
        .expect("canonical folder")
        .to_str()
        .expect("UTF-8 folder")
        .to_owned();

    // Initialize, stop, and reopen through the CLI's owned-vault door.
    drop(Vault::open_owned(&vault_path, VaultConfig::device()).expect("initialize vault"));
    let vault = Vault::open_owned(&vault_path, VaultConfig::device()).expect("reopen vault");
    assert!(
        vault
            .writer_lease()
            .expect("writer lease")
            .held_by_current_process()
    );
    let actor = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault
        .authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    assert!(vault.is_live_vault_owner(&owner).expect("live owner"));
    assert_eq!(
        vault
            .get_entity_type(&vault.default_facet().expect("default facet"))
            .expect("default facet type"),
        Some(ENTITY_TYPE_FACET),
        "the initialized owner's default facet already exists"
    );

    let source = vault
        .attach_folder_source(&owner, &folder, Vec::new(), "observation")
        .expect("attach folder");
    let notes = [("first.md", "First"), ("second.md", "Second")]
        .into_iter()
        .map(|(path, title)| ImportedNote {
            path: path.to_owned(),
            kind: source.kind.clone(),
            title: Some(title.to_owned()),
            written_at: 1,
            markdown: std::fs::read_to_string(folder_path.join(path)).expect("read Markdown"),
            original: None,
        })
        .collect();
    let report = vault
        .rescan_folder_source(
            &owner,
            FolderRescan {
                folder: source.folder.clone(),
                new: notes,
                links: Vec::new(),
                present: Vec::new(),
                name_only: Vec::new(),
                missing: Vec::new(),
                raw_hashes: HashMap::new(),
                facts: HashMap::new(),
                whole: true,
            },
        )
        .expect("rescan returns its per-file report");

    assert_eq!(report.landed, 2, "both files must land: {report:?}");
    assert_eq!(report.failed, 0, "no file may be refused: {report:?}");
    for path in ["first.md", "second.md"] {
        let id = Vault::imported_note_id(&source.namespace(), path).expect("imported NOTE id");
        assert_eq!(
            vault.get_entity_type(&id).expect("NOTE type"),
            Some(ENTITY_TYPE_NOTE)
        );
        let note = vault
            .read_note(&id)
            .expect("read NOTE")
            .expect("NOTE exists");
        assert_eq!(
            note.markdown,
            std::fs::read_to_string(folder_path.join(path)).expect("original Markdown")
        );
    }
}
