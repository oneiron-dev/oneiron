//! SESSION-PROJECT-NOTE-MESSAGE-PLACEMENT PR D, the host-import side: an import through
//! `Vault::import_history_in_session_folder` for a host session log whose folder names digests
//! places each TURN it mints with its MESSAGEs in the folder's bound project, as an attached
//! session's minted turn does (Engine ruling Q9 = a); a message the import appends to a TURN
//! that landed before keeps that TURN's project. Placement is read through the
//! `stamped_project` test door, MESSAGE ids through `imported_message_rows`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test
//! session_project_history_import`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::authority::HostSlipIssuer;
use oneiron::claim::default_project_id;
use oneiron::consent::AuthenticatedOwner;
use oneiron::ingest::history::{
    HistoryConversation, HistoryMessage, HistoryRole, HistorySkips, HistorySource,
    HistoryThreadKind,
};
use oneiron::registry::ENTITY_TYPE_FACET;
use oneiron::session_project::WorkspaceBindRequest;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::history_import_rows::imported_message_rows;
use oneiron::test_doors::room_facet_set::create_owner_project;
use oneiron::test_doors::witness_project::stamped_project;
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The digest of the folder bound to `alpha`.
const MAIN_DIGEST: &str = "blake3:a0b1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f5061728394a5b6c7d8e9f";
/// A folder nobody bound.
const UNBOUND_DIGEST: &str =
    "blake3:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// When the tests' imports land, in seconds.
const IMPORTED_AT: u64 = 1_800_000_000;

/// A rooted vault whose owner made `alpha` under the root and bound the folder `MAIN_DIGEST`
/// to it. Copied from `session_project_note_message_writes.rs`, trimmed: no `beta`, no writer
/// handle, no credential helper. The vault closes before its directory goes.
struct Fixture {
    vault: Vault,
    proof: AuthenticatedOwner,
    alpha: EntityId,
    _dir: tempfile::TempDir,
}

fn open() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault.ensure_embedded_owner_actor()?;
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner)?;
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let root = vault.root_project()?;
    vault.sign_owner_project(&proof, &vault.owner_project_signer(&issuer)?, root)?;
    let facet = EntityId::now();
    vault.put_entity(
        &facet,
        ENTITY_TYPE_FACET,
        TimeRange { start: 1, end: 1 },
        1,
        &rmp_serde::to_vec_named(&json!({ "name": "session write facet" }))?,
    )?;
    let alpha = project_under(&vault, &issuer, &proof, owner, root, facet)?;
    let binding = vault.bind_workspace_as_owner(
        &proof,
        Some(oneiron::authority::ActSurface::ThisInstall),
        WorkspaceBindRequest {
            folder_digest: MAIN_DIGEST.to_owned(),
            project: alpha,
            label: Some("alpha".to_owned()),
        },
    )?;
    assert_eq!(
        binding.project,
        Some(alpha),
        "FIXTURE: the owner binds the folder"
    );
    Ok(Fixture {
        vault,
        proof,
        alpha,
        _dir: dir,
    })
}

/// An owner-born project under `parent`, sliced to `facet`.
fn project_under(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    proof: &AuthenticatedOwner,
    owner: EntityId,
    parent: EntityId,
    facet: EntityId,
) -> TestResult<EntityId> {
    let id = EntityId::now();
    let mut record = ProjectRecord::new(id, Some(parent), vault.root_project()?, owner)?;
    record.slice.facet = Some(facet);
    record.depth_remaining = 1;
    create_owner_project(
        vault,
        issuer,
        proof,
        &vault.owner_project_signer(issuer)?,
        owner,
        id,
        &record,
    )?;
    Ok(id)
}

/// One kept message, as `continue_work_spill.rs` builds it: a `HistoryMessage` literal with no
/// parent, no `said_by`, no tools and no alias. `runs` groups by `role` and `said_by`, so two
/// messages share a TURN only when both match.
fn message(native_id: &str, role: HistoryRole, text: &str, at_ms: u64) -> HistoryMessage {
    HistoryMessage {
        native_id: native_id.to_owned(),
        parent_id: None,
        role,
        text: text.to_owned(),
        at_ms: Some(at_ms),
        said_by: None,
        tools: Vec::new(),
        alias: None,
    }
}

/// One source conversation, as `continue_work_spill.rs` builds it: a `HistoryConversation`
/// literal of kind `Main`, unshared, with no `cwd`.
fn conversation(native_id: &str, messages: Vec<HistoryMessage>) -> HistoryConversation {
    HistoryConversation {
        native_id: native_id.to_owned(),
        kind: HistoryThreadKind::Main,
        parent: None,
        title: Some("a host session log".to_owned()),
        started_at_ms: Some(1_799_990_000_000),
        own_started_at_ms: Some(1_799_990_000_000),
        cwd: None,
        messages,
        skipped: HistorySkips::default(),
        sharing: None,
    }
}

#[test]
fn an_import_in_a_bound_folder_lands_its_turns_and_messages_in_the_folders_project() -> TestResult {
    let fixture = open()?;
    let conv = conversation(
        "history-import-bound",
        vec![
            message(
                "bound-m1",
                HistoryRole::User,
                "repot the basil in the alpha folder",
                1_800_000_000_000,
            ),
            message(
                "bound-m2",
                HistoryRole::Assistant,
                "the basil is repotted",
                1_800_000_060_000,
            ),
        ],
    );
    let report = fixture
        .vault
        .import_history_in_session_folder(
            &fixture.proof,
            HistorySource::ClaudeCode,
            &conv,
            IMPORTED_AT,
            &[MAIN_DIGEST.to_owned()],
        )
        .map_err(|error| format!("vault.import_history_in_session_folder: {error:?}"))?;
    assert_eq!(
        report.new, 2,
        "a bound-folder import lands both messages new: {report:?}"
    );
    assert_eq!(
        report.refused, 0,
        "a bound-folder import refuses nothing: {report:?}"
    );
    assert_eq!(
        report.turns.len(),
        2,
        "a two-speaker conversation mints two TURNs: {report:?}"
    );
    for turn in &report.turns {
        assert_eq!(
            stamped_project(&fixture.vault, *turn)?,
            Some(fixture.alpha),
            "a TURN the bound-folder import mints lands in the folder's project"
        );
    }
    for native_id in ["bound-m1", "bound-m2"] {
        let rows = imported_message_rows(&fixture.vault, HistorySource::ClaudeCode, native_id)?
            .unwrap_or_else(|| panic!("the bound-folder import landed {native_id}"));
        assert!(
            report.turns.contains(&rows.turn),
            "the ledger row of {native_id} names a TURN the report holds: {report:?}"
        );
        assert_eq!(
            stamped_project(&fixture.vault, rows.message)?,
            Some(fixture.alpha),
            "a MESSAGE the bound-folder import lands sits in the folder's project"
        );
    }
    Ok(())
}

#[test]
fn an_import_with_no_folder_or_an_unbound_folder_lands_at_the_default_project() -> TestResult {
    let fixture = open()?;
    let no_folder = conversation(
        "history-import-nofolder",
        vec![
            message(
                "nofolder-m1",
                HistoryRole::User,
                "a prompt with no folder",
                1_800_000_000_000,
            ),
            message(
                "nofolder-m2",
                HistoryRole::Assistant,
                "a reply with no folder",
                1_800_000_060_000,
            ),
        ],
    );
    let report = fixture
        .vault
        .import_history_in_session_folder(
            &fixture.proof,
            HistorySource::ClaudeCode,
            &no_folder,
            IMPORTED_AT,
            &[],
        )
        .map_err(|error| {
            format!("vault.import_history_in_session_folder with no folder: {error:?}")
        })?;
    assert_eq!(
        report.new, 2,
        "an import with no folder lands both messages new: {report:?}"
    );
    assert_eq!(
        report.refused, 0,
        "an import with no folder refuses nothing: {report:?}"
    );
    assert_eq!(
        report.turns.len(),
        2,
        "an import with no folder mints two TURNs: {report:?}"
    );
    for turn in &report.turns {
        assert_eq!(
            stamped_project(&fixture.vault, *turn)?,
            Some(default_project_id()),
            "a TURN imported with no folder lands at the default project"
        );
    }
    let unbound_conv = conversation(
        "history-import-unbound",
        vec![
            message(
                "unbound-m1",
                HistoryRole::User,
                "a prompt in an unbound folder",
                1_800_000_000_000,
            ),
            message(
                "unbound-m2",
                HistoryRole::Assistant,
                "a reply in an unbound folder",
                1_800_000_060_000,
            ),
        ],
    );
    let unbound_report = fixture
        .vault
        .import_history_in_session_folder(
            &fixture.proof,
            HistorySource::ClaudeCode,
            &unbound_conv,
            IMPORTED_AT,
            &[UNBOUND_DIGEST.to_owned()],
        )
        .map_err(|error| {
            format!("vault.import_history_in_session_folder in an unbound folder: {error:?}")
        })?;
    assert_eq!(
        unbound_report.new, 2,
        "an import in an unbound folder lands both messages new: {unbound_report:?}"
    );
    assert_eq!(
        unbound_report.refused, 0,
        "an import in an unbound folder refuses nothing: {unbound_report:?}"
    );
    assert_eq!(
        unbound_report.turns.len(),
        2,
        "an import in an unbound folder mints two TURNs: {unbound_report:?}"
    );
    for turn in &unbound_report.turns {
        assert_eq!(
            stamped_project(&fixture.vault, *turn)?,
            Some(default_project_id()),
            "a TURN imported in an unbound folder lands at the default project"
        );
    }
    Ok(())
}

#[test]
fn a_later_import_that_appends_to_a_default_born_turn_keeps_it_at_the_default() -> TestResult {
    let fixture = open()?;
    let first_messages = vec![
        message(
            "append-default-m1",
            HistoryRole::User,
            "the default-born turn opens",
            1_800_000_000_000,
        ),
        message(
            "append-default-m2",
            HistoryRole::Assistant,
            "the default-born turn answers",
            1_800_000_060_000,
        ),
    ];
    let first_conv = conversation("history-import-append-default", first_messages.clone());
    let first = fixture
        .vault
        .import_history(
            &fixture.proof,
            HistorySource::ClaudeCode,
            &first_conv,
            IMPORTED_AT,
        )
        .map_err(|error| format!("vault.import_history first: {error:?}"))?;
    assert_eq!(
        first.new, 2,
        "the first import lands both messages new: {first:?}"
    );
    assert_eq!(
        first.refused, 0,
        "the first import refuses nothing: {first:?}"
    );
    assert_eq!(
        first.turns.len(),
        2,
        "the first import mints two TURNs: {first:?}"
    );
    for turn in &first.turns {
        assert_eq!(
            stamped_project(&fixture.vault, *turn)?,
            Some(default_project_id()),
            "a TURN born with no folder sits at the default project"
        );
    }
    let mut grown_messages = first_messages;
    grown_messages.push(message(
        "append-default-m3",
        HistoryRole::Assistant,
        "the session appends to the default turn",
        1_800_000_120_000,
    ));
    let grown = conversation("history-import-append-default", grown_messages);
    let second = fixture
        .vault
        .import_history_in_session_folder(
            &fixture.proof,
            HistorySource::ClaudeCode,
            &grown,
            IMPORTED_AT,
            &[MAIN_DIGEST.to_owned()],
        )
        .map_err(|error| format!("vault.import_history_in_session_folder grown: {error:?}"))?;
    assert_eq!(
        second.new, 1,
        "the grown import lands one message new: {second:?}"
    );
    assert_eq!(
        second.refused, 0,
        "the grown import refuses nothing: {second:?}"
    );
    assert_eq!(
        second.turns.len(),
        1,
        "the grown import lands in one TURN: {second:?}"
    );
    assert!(
        first.turns.contains(&second.turns[0]),
        "the grown import joins a TURN the first import minted: {first:?} {second:?}"
    );
    let turn = second.turns[0];
    assert_eq!(
        stamped_project(&fixture.vault, turn)?,
        Some(default_project_id()),
        "a TURN born at the default keeps the default when a bound-folder import appends"
    );
    let rows = imported_message_rows(
        &fixture.vault,
        HistorySource::ClaudeCode,
        "append-default-m3",
    )?
    .unwrap_or_else(|| panic!("the grown import landed append-default-m3"));
    assert_eq!(
        rows.turn, turn,
        "the appended MESSAGE's ledger row names the TURN it joined"
    );
    assert_eq!(
        stamped_project(&fixture.vault, rows.message)?,
        Some(default_project_id()),
        "a MESSAGE appended to a default-born TURN stays at the default project"
    );
    Ok(())
}

#[test]
fn a_turn_first_imported_in_a_bound_folder_keeps_its_project_when_a_folderless_import_appends()
-> TestResult {
    let fixture = open()?;
    let first_messages = vec![
        message(
            "append-alpha-m1",
            HistoryRole::User,
            "the alpha-born turn opens",
            1_800_000_000_000,
        ),
        message(
            "append-alpha-m2",
            HistoryRole::Assistant,
            "the alpha-born turn answers",
            1_800_000_060_000,
        ),
    ];
    let first_conv = conversation("history-import-append-alpha", first_messages.clone());
    let first = fixture
        .vault
        .import_history_in_session_folder(
            &fixture.proof,
            HistorySource::ClaudeCode,
            &first_conv,
            IMPORTED_AT,
            &[MAIN_DIGEST.to_owned()],
        )
        .map_err(|error| format!("vault.import_history_in_session_folder first: {error:?}"))?;
    assert_eq!(
        first.new, 2,
        "the first import lands both messages new: {first:?}"
    );
    assert_eq!(
        first.refused, 0,
        "the first import refuses nothing: {first:?}"
    );
    assert_eq!(
        first.turns.len(),
        2,
        "the first import mints two TURNs: {first:?}"
    );
    for turn in &first.turns {
        assert_eq!(
            stamped_project(&fixture.vault, *turn)?,
            Some(fixture.alpha),
            "a TURN born in a bound folder sits in the folder's project"
        );
    }
    let mut grown_messages = first_messages;
    grown_messages.push(message(
        "append-alpha-m3",
        HistoryRole::Assistant,
        "a folderless import appends to the alpha turn",
        1_800_000_120_000,
    ));
    let grown = conversation("history-import-append-alpha", grown_messages);
    let second = fixture
        .vault
        .import_history(
            &fixture.proof,
            HistorySource::ClaudeCode,
            &grown,
            IMPORTED_AT,
        )
        .map_err(|error| format!("vault.import_history grown: {error:?}"))?;
    assert_eq!(
        second.new, 1,
        "the grown import lands one message new: {second:?}"
    );
    assert_eq!(
        second.refused, 0,
        "the grown import refuses nothing: {second:?}"
    );
    assert_eq!(
        second.turns.len(),
        1,
        "the grown import lands in one TURN: {second:?}"
    );
    assert!(
        first.turns.contains(&second.turns[0]),
        "the grown import joins a TURN the first import minted: {first:?} {second:?}"
    );
    let turn = second.turns[0];
    assert_eq!(
        stamped_project(&fixture.vault, turn)?,
        Some(fixture.alpha),
        "a TURN born in a bound folder keeps its project when a folderless import appends"
    );
    let rows = imported_message_rows(&fixture.vault, HistorySource::ClaudeCode, "append-alpha-m3")?
        .unwrap_or_else(|| panic!("the grown import landed append-alpha-m3"));
    assert_eq!(
        rows.turn, turn,
        "the appended MESSAGE's ledger row names the TURN it joined"
    );
    assert_eq!(
        stamped_project(&fixture.vault, rows.message)?,
        Some(fixture.alpha),
        "a MESSAGE a folderless import appends to an alpha-born TURN lands in alpha"
    );
    Ok(())
}
