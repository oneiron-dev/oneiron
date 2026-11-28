//! SESSION-PROJECT-NOTE-MESSAGE-PLACEMENT PR C: a recall that names `project_refs`
//! reads NOTE, MESSAGE and TURN rows only in the selected projects; an empty selection
//! leaves them as before. No edge of a recalled row brings another project's NOTE into the
//! rendered pack (review round 1). A diary query or sealed-pad read admits entries by the handle's
//! session projects, even on a self-read. No folder keeps the previous read; an unknown
//! folder admits no entries.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test session_project_refs_diary`
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::HostSlipIssuer;
use oneiron::claim::default_project_id;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{
    DiaryReadOutcome, Memory, MemoryResult, RecallEffort, RecallRequest, RecallScope,
    WitnessReceipt, WitnessTurn,
};
use oneiron::registry::ENTITY_TYPE_FACET;
use oneiron::session_project::WorkspaceBindRequest;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::recall_unembedded;
use oneiron::test_doors::room_facet_set::create_owner_project;
use oneiron::test_doors::witness_project::stamped_project;
use oneiron::verbs::{DiaryEntryRequest, self_memory_diary_write};
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EdgeKind, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The digest of the folder bound to `alpha`.
const MAIN_DIGEST: &str = "blake3:a0b1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f5061728394a5b6c7d8e9f";
/// The digest of the folder bound to `beta`.
const BETA_DIGEST: &str = "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
/// A folder nobody bound.
const UNBOUND_DIGEST: &str =
    "blake3:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// The same invented word in each recall fixture row and in no other row.
const RECALL_TOKEN: &str = "quillharprefsrecall";

/// A rooted vault whose owner made `alpha` and `beta` under the root, bound `MAIN_DIGEST` to
/// `alpha` and `BETA_DIGEST` to `beta`. The vault closes before its directory goes.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    proof: AuthenticatedOwner,
    alpha: EntityId,
    beta: EntityId,
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
    let beta = project_under(&vault, &issuer, &proof, owner, root, facet)?;
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
        "FIXTURE: the owner binds the alpha folder"
    );
    let binding = vault.bind_workspace_as_owner(
        &proof,
        Some(oneiron::authority::ActSurface::ThisInstall),
        WorkspaceBindRequest {
            folder_digest: BETA_DIGEST.to_owned(),
            project: beta,
            label: Some("beta".to_owned()),
        },
    )?;
    assert_eq!(
        binding.project,
        Some(beta),
        "FIXTURE: the owner binds the beta folder"
    );
    Ok(Fixture {
        vault,
        owner,
        proof,
        alpha,
        beta,
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

impl Fixture {
    /// The owner's handle, bound for its writes to the folder `folder_digest` when given.
    fn writer(&self, folder_digest: Option<&str>) -> Memory<'_> {
        let memory = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .with_owner_authorship(&self.proof);
        match folder_digest {
            Some(digest) => memory.placing_in_session_workspace(&[digest.to_owned()]),
            None => memory,
        }
    }

    /// The owner's reading handle, with no folder: bound reads add
    /// `.in_session_workspace`, never the placing writer.
    fn reader(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }
}

/// One visible user MESSAGE of `content` in a fresh turn of `conversation`, as `vault.witness`
/// takes it without a project.
fn plain_turn(conversation: &str, content: &str) -> WitnessTurn {
    let value = json!({
        "conversation_ref": conversation,
        "messages": [{
            "author": "user",
            "message_type": "dialogue",
            "content": content,
            "is_visible": true,
            "order": 0,
        }],
        "occurred_at": 900,
    });
    serde_json::from_value(value).expect("the witness turn shape decodes")
}

/// The MESSAGE the witness wrote, as its stamped row.
fn first_message(receipt: &WitnessReceipt) -> EntityId {
    let message = receipt
        .messages
        .first()
        .expect("the witness writes one MESSAGE row");
    EntityId::from_hex(&message.id).expect("the message record ref parses")
}

struct Rows {
    note_alpha: EntityId,
    note_beta: EntityId,
    note_root: EntityId,
    turn_alpha: EntityId,
    turn_beta: EntityId,
    msg_alpha: EntityId,
    msg_beta: EntityId,
}

fn assert_project(fixture: &Fixture, name: &str, id: EntityId, project: EntityId) {
    assert_eq!(
        stamped_project(&fixture.vault, id).expect("FIXTURE: read the row's project stamp"),
        Some(project),
        "FIXTURE: {name} is placed in its expected project"
    );
}

fn recall_rows(fixture: &Fixture) -> Rows {
    let write_note = |folder, project| {
        let receipt = fixture
            .writer(folder)
            .create_note(
                "research",
                &format!("The {project} note shares {RECALL_TOKEN}."),
            )
            .unwrap_or_else(|error| panic!("FIXTURE: write {project} NOTE: {error:?}"));
        EntityId::from_hex(&receipt.id_hex).expect("FIXTURE: parse the NOTE receipt's id")
    };
    let note_alpha = write_note(Some(MAIN_DIGEST), "alpha");
    let note_beta = write_note(Some(BETA_DIGEST), "beta");
    let note_root = write_note(None, "root");
    let conversation = EntityId::now().to_hex();
    let receipt_alpha = fixture
        .writer(Some(MAIN_DIGEST))
        .witness(&plain_turn(
            &conversation,
            &format!("The alpha session describes {RECALL_TOKEN}."),
        ))
        .expect("FIXTURE: witness the alpha TURN and MESSAGE");
    let receipt_beta = fixture
        .writer(Some(BETA_DIGEST))
        .witness(&plain_turn(
            &conversation,
            &format!("The beta session asks about {RECALL_TOKEN}."),
        ))
        .expect("FIXTURE: witness the beta TURN and MESSAGE");
    let turn_alpha = receipt_alpha.turn_id;
    let turn_beta = receipt_beta.turn_id;
    for (name, receipt) in [("alpha", &receipt_alpha), ("beta", &receipt_beta)] {
        assert!(
            receipt
                .messages
                .first()
                .is_some_and(|message| EntityId::from_hex(&message.id).is_ok()),
            "FIXTURE: the {name} witness receipt includes a MESSAGE id"
        );
    }
    let msg_alpha = first_message(&receipt_alpha);
    let msg_beta = first_message(&receipt_beta);
    for (name, id, project) in [
        ("alpha NOTE", note_alpha, fixture.alpha),
        ("beta NOTE", note_beta, fixture.beta),
        ("root NOTE", note_root, default_project_id()),
        ("alpha TURN", turn_alpha, fixture.alpha),
        ("beta TURN", turn_beta, fixture.beta),
        ("alpha MESSAGE", msg_alpha, fixture.alpha),
        ("beta MESSAGE", msg_beta, fixture.beta),
    ] {
        assert_project(fixture, name, id, project);
    }
    fixture
        .vault
        .set_indexed_idle_delay_ms(0)
        .expect("FIXTURE: configure idle text publication");
    let published = fixture
        .vault
        .refresh_staged_indexed_at_idle(u64::MAX)
        .expect("FIXTURE: publish staged text without an embedder");
    assert!(
        published.failed.is_empty(),
        "FIXTURE: every staged text publishes: {published:?}"
    );
    Rows {
        note_alpha,
        note_beta,
        note_root,
        turn_alpha,
        turn_beta,
        msg_alpha,
        msg_beta,
    }
}

fn recall_ids(fixture: &Fixture, project_refs: Vec<String>) -> MemoryResult<BTreeSet<EntityId>> {
    let pack = recall_unembedded(
        &fixture.reader(),
        RecallRequest {
            query: RECALL_TOKEN.to_owned(),
            limit: Some(25),
            scope: Some(RecallScope {
                project_refs,
                kinds: Some(["NOTE", "TURN", "MESSAGE"].map(str::to_owned).to_vec()),
                ..RecallScope::default()
            }),
            ..RecallRequest::default()
        },
    )?;
    Ok(pack
        .items
        .iter()
        .filter_map(|item| item.record.as_ref())
        .map(|record| EntityId::from_hex(&record.id).expect("a recalled record id parses"))
        .collect())
}

#[test]
fn a_recall_naming_a_project_returns_only_that_projects_notes_turns_and_messages() {
    let fixture = open().expect("FIXTURE: open the vault and bind both projects");
    let rows = recall_rows(&fixture);
    let control =
        recall_ids(&fixture, vec![]).expect("FIXTURE: recall without a project selection");
    assert!(
        control.contains(&rows.note_alpha),
        "FIXTURE: alpha NOTE is recallable"
    );
    assert!(
        control.contains(&rows.note_beta),
        "FIXTURE: beta NOTE is recallable"
    );
    assert!(
        control.contains(&rows.turn_alpha) || control.contains(&rows.msg_alpha),
        "FIXTURE: alpha TURN or MESSAGE is recallable"
    );
    assert!(
        control.contains(&rows.turn_beta) || control.contains(&rows.msg_beta),
        "FIXTURE: beta TURN or MESSAGE is recallable"
    );

    let beta = recall_ids(&fixture, vec![fixture.beta.to_hex()]).expect("recall naming beta");
    let expected = [rows.note_beta, rows.turn_beta, rows.msg_beta]
        .into_iter()
        .filter(|id| control.contains(id))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        beta, expected,
        "recall retains only the beta rows from the control"
    );
    for id in [
        rows.note_alpha,
        rows.note_root,
        rows.turn_alpha,
        rows.msg_alpha,
    ] {
        assert!(
            !beta.contains(&id),
            "recall naming beta excludes alpha and root rows: {id:?}"
        );
    }
}

#[test]
fn an_empty_project_selection_reads_every_projects_notes_turns_and_messages() {
    let fixture = open().expect("FIXTURE: open the vault and bind both projects");
    let rows = recall_rows(&fixture);
    let recalled = recall_ids(&fixture, vec![]).expect("recall with an empty project selection");
    for id in [rows.note_alpha, rows.note_beta, rows.note_root] {
        assert!(
            recalled.contains(&id),
            "an empty selection reads every project's NOTE: {id:?}"
        );
    }
    assert!(
        recalled.contains(&rows.turn_alpha) || recalled.contains(&rows.msg_alpha),
        "an empty selection reads alpha's TURN or MESSAGE"
    );
    assert!(
        recalled.contains(&rows.turn_beta) || recalled.contains(&rows.msg_beta),
        "an empty selection reads beta's TURN or MESSAGE"
    );
}

fn granted_ids(outcome: DiaryReadOutcome) -> BTreeSet<EntityId> {
    match outcome {
        DiaryReadOutcome::Granted { entries, .. } => {
            entries.into_iter().map(|entry| entry.id).collect()
        }
        other => panic!("FIXTURE: the owner reads their own entries without review: {other:?}"),
    }
}

#[test]
fn a_bound_session_reads_only_its_projects_diary_entries() {
    let fixture = open().expect("FIXTURE: open the vault and bind both projects");
    let write_entry = |folder, name, project| {
        let entry = self_memory_diary_write(
            &fixture.writer(folder),
            DiaryEntryRequest {
                content: format!("A diary entry written in {name}."),
                kind: None,
            },
        )
        .unwrap_or_else(|error| panic!("FIXTURE: write the {name} diary entry: {error:?}"));
        let id = EntityId::from_hex(&entry.entry_id).expect("FIXTURE: parse the diary entry id");
        assert_project(&fixture, name, id, project);
        id
    };
    let alpha = write_entry(Some(MAIN_DIGEST), "alpha", fixture.alpha);
    let beta = write_entry(Some(BETA_DIGEST), "beta", fixture.beta);
    let root = write_entry(None, "root", default_project_id());
    let read = |memory: Memory<'_>| {
        granted_ids(
            memory
                .read_agent_diary(Some(&fixture.proof), fixture.owner, "self review")
                .expect("FIXTURE: read the owner's diary"),
        )
    };
    let reader = fixture.reader();
    assert_eq!(
        read(fixture.reader()),
        BTreeSet::from([alpha, beta, root]),
        "FIXTURE: the owner's no-folder diary query reads all three entries"
    );
    assert_eq!(
        read(reader.in_session_workspace(&[MAIN_DIGEST.to_owned()])),
        BTreeSet::from([alpha]),
        "the MAIN session reads only alpha's diary entry"
    );
    assert_eq!(
        read(reader.in_session_workspace(&[BETA_DIGEST.to_owned()])),
        BTreeSet::from([beta]),
        "the BETA session reads only beta's diary entry"
    );
    assert!(
        read(reader.in_session_workspace(&[UNBOUND_DIGEST.to_owned()])).is_empty(),
        "an unbound session reads no diary entries"
    );
}

#[test]
fn a_bound_session_reads_only_its_projects_sealed_pads() {
    let fixture = open().expect("FIXTURE: open the vault and bind both projects");
    let write_pad = |folder, label, project| {
        let memory = fixture.writer(Some(folder));
        let receipt = memory
            .scratchpad_append(label, &format!("One line for {label}."), None, false)
            .expect("FIXTURE: append a line to a new scratchpad");
        assert!(receipt.opened, "FIXTURE: the first line opens {label}");
        assert_eq!(
            memory
                .scratchpad_seal(label)
                .expect("FIXTURE: seal the scratchpad"),
            Some(receipt.pad),
            "FIXTURE: seal the pad opened at {label}"
        );
        assert_project(&fixture, label, receipt.pad, project);
        receipt.pad
    };
    let alpha = write_pad(MAIN_DIGEST, "alpha-pad", fixture.alpha);
    let beta = write_pad(BETA_DIGEST, "beta-pad", fixture.beta);
    let read = |memory: Memory<'_>| {
        granted_ids(
            memory
                .read_agent_sealed_pads(Some(&fixture.proof), fixture.owner, "self review")
                .expect("FIXTURE: read the owner's sealed pads"),
        )
    };
    let reader = fixture.reader();
    assert_eq!(
        read(fixture.reader()),
        BTreeSet::from([alpha, beta]),
        "FIXTURE: the owner's no-folder read returns both sealed pads"
    );
    assert_eq!(
        read(reader.in_session_workspace(&[MAIN_DIGEST.to_owned()])),
        BTreeSet::from([alpha]),
        "the MAIN session reads only alpha's sealed pad"
    );
    assert!(
        read(reader.in_session_workspace(&[UNBOUND_DIGEST.to_owned()])).is_empty(),
        "an unbound session reads no sealed pads"
    );
}

/// An invented word only in the alpha NOTE of the neighbor fixture.
const NEIGHBOR_QUERY: &str = "corvidlanternneighbour";
/// An invented word only in the beta NOTE that the alpha NOTE's edge reaches.
const NEIGHBOR_MARK: &str = "zephyrlatticebeyond";

/// The alpha NOTE holding the query word, and the beta NOTE its `Mentions` edge reaches,
/// which holds the mark and not the query word; both published. The test reads the beta
/// NOTE by its text: the alpha NOTE's own edge list may name the beta id.
fn neighbor_rows(fixture: &Fixture) -> (EntityId, EntityId) {
    let write_note = |folder: &str, text: String| {
        let receipt = fixture
            .writer(Some(folder))
            .create_note("research", &text)
            .unwrap_or_else(|error| panic!("FIXTURE: write NOTE {text:?}: {error:?}"));
        EntityId::from_hex(&receipt.id_hex).expect("FIXTURE: parse the NOTE receipt's id")
    };
    let alpha = write_note(
        MAIN_DIGEST,
        format!("The alpha note names {NEIGHBOR_QUERY}."),
    );
    let beta = write_note(BETA_DIGEST, format!("The beta note keeps {NEIGHBOR_MARK}."));
    assert_project(fixture, "alpha NOTE", alpha, fixture.alpha);
    assert_project(fixture, "beta NOTE", beta, fixture.beta);
    fixture
        .vault
        .put_edge(&alpha, EdgeKind::Mentions, &beta, 0.9)
        .expect("FIXTURE: link the alpha NOTE to the beta NOTE");
    fixture
        .vault
        .set_indexed_idle_delay_ms(0)
        .expect("FIXTURE: configure idle text publication");
    let published = fixture
        .vault
        .refresh_staged_indexed_at_idle(u64::MAX)
        .expect("FIXTURE: publish staged text without an embedder");
    assert!(
        published.failed.is_empty(),
        "FIXTURE: every staged text publishes: {published:?}"
    );
    (alpha, beta)
}

/// A medium recall of the neighbor query word, rendered as JSON: the ranked ids and the
/// rendered text, which carries the edge neighbors.
fn rendered_recall(
    fixture: &Fixture,
    project_refs: Vec<String>,
) -> MemoryResult<(BTreeSet<EntityId>, String)> {
    let pack = recall_unembedded(
        &fixture.reader(),
        RecallRequest {
            query: NEIGHBOR_QUERY.to_owned(),
            effort: Some(RecallEffort::Medium),
            limit: Some(25),
            format: Some("json".to_owned()),
            scope: Some(RecallScope {
                project_refs,
                kinds: Some(vec!["NOTE".to_owned()]),
                ..RecallScope::default()
            }),
            ..RecallRequest::default()
        },
    )?;
    let ids = pack
        .items
        .iter()
        .filter_map(|item| item.record.as_ref())
        .map(|record| EntityId::from_hex(&record.id).expect("a recalled record id parses"))
        .collect();
    Ok((ids, pack.rendered.unwrap_or_default()))
}

#[test]
fn a_recall_naming_a_project_renders_no_other_projects_note_through_an_edge() {
    let fixture = open().expect("FIXTURE: open the vault and bind both projects");
    let (alpha, beta) = neighbor_rows(&fixture);
    let (ids, rendered) =
        rendered_recall(&fixture, vec![]).expect("FIXTURE: recall without a project selection");
    assert!(ids.contains(&alpha), "FIXTURE: the alpha NOTE is recalled");
    assert!(
        !ids.contains(&beta),
        "FIXTURE: the beta NOTE is no ranked row; only the edge reaches it"
    );
    assert!(
        rendered.contains(NEIGHBOR_MARK),
        "FIXTURE: with no selection the edge brings the beta NOTE's text into the rendered \
         pack: {rendered}"
    );

    let (ids, rendered) =
        rendered_recall(&fixture, vec![fixture.alpha.to_hex()]).expect("recall naming alpha");
    assert!(
        ids.contains(&alpha),
        "recall naming alpha keeps the alpha NOTE"
    );
    assert!(
        !rendered.contains(NEIGHBOR_MARK),
        "recall naming alpha renders no beta NOTE reached through an edge: {rendered}"
    );
}
