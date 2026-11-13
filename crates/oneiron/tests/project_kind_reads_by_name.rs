//! A project reads back as kind `PROJECT` (FIX PROJECT-KIND-READS-TYPE-103).
//! PROJECT is a compiled-in product kind a vault registers at run time, so
//! its type byte is not in the static registry. Every read that named a
//! stored row's kind from the static registry alone answered `TYPE_<byte>`:
//! `vault.get`, the record `vault.refs.resolve` names, and a
//! `vault.neighbors` hit and its record. Canon: ARCH-0016:18 "A project is a
//! `PROJECT` entity". The verbs are called by name through the embedded
//! door, as the owner, and their output is read as JSON.
//!
//! Public paths only: `Vault` opens, its seeded root project, and a child
//! project put through `put_project`, as `project_extra_rooms.rs` does.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test project_kind_reads_by_name`

use oneiron::memory::Memory;
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// A vault this process owns, its embedded owner, its seeded root project
/// and one child project of the root, led by the owner. The vault closes
/// before its directory goes.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    root: EntityId,
    child: EntityId,
    _dir: tempfile::TempDir,
}

fn open() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let root = vault.root_project()?;
    let child = EntityId::now();
    let record = ProjectRecord::new(child, Some(root), root, owner)?;
    vault.put_project(child, &record, 1)?;
    Ok(Fixture {
        vault,
        owner,
        root,
        child,
        _dir: dir,
    })
}

fn owner_memory(fixture: &Fixture) -> Memory<'_> {
    fixture.vault.memory(fixture.owner, EdgeActorClass::Human)
}

fn invoke(memory: &Memory<'_>, verb: &str, input: Value) -> Value {
    oneiron::task_verb::sdk::invoke(memory, verb, input)
        .unwrap_or_else(|error| panic!("{verb} fails: {error:?}"))
}

#[test]
fn a_project_reads_back_as_project_at_vault_get_and_vault_refs_resolve() -> TestResult {
    let fixture = open()?;
    let memory = owner_memory(&fixture);
    for project in [fixture.root, fixture.child] {
        let read = invoke(
            &memory,
            "vault.get",
            json!({ "entity_ref": project.to_hex() }),
        );
        assert_eq!(
            read.pointer("/value/kind"),
            Some(&json!("PROJECT")),
            "vault.get names a project's kind PROJECT: {read}"
        );
        let reference = read
            .pointer("/value/short_ref")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("vault.get issued no short ref: {read}"))
            .to_owned();
        let resolved = invoke(
            &memory,
            "vault.refs.resolve",
            json!({ "reference": reference }),
        );
        assert_eq!(
            resolved.pointer("/value/record/kind"),
            Some(&json!("PROJECT")),
            "vault.refs.resolve names the project's record kind PROJECT: {resolved}"
        );
    }
    Ok(())
}

#[test]
fn a_child_projects_parent_reads_back_as_project_at_vault_neighbors() -> TestResult {
    let fixture = open()?;
    let memory = owner_memory(&fixture);
    let near = invoke(
        &memory,
        "vault.neighbors",
        json!({
            "entity_ref": fixture.child.to_hex(),
            "opts": { "edge_kind": "belongs_to", "limit": 8 },
        }),
    );
    let root = fixture.root.to_hex();
    let hits = near
        .pointer("/value")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("vault.neighbors answered no hit list: {near}"));
    let parent = hits
        .iter()
        .find(|hit| {
            hit.get("short_id")
                .and_then(Value::as_str)
                .is_some_and(|short| short.eq_ignore_ascii_case(&root))
                || hit
                    .pointer("/record/id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| id.eq_ignore_ascii_case(&root))
        })
        .unwrap_or_else(|| panic!("the child's belongs_to edge to the root is not a hit: {near}"));
    assert_eq!(
        parent.get("kind"),
        Some(&json!("PROJECT")),
        "vault.neighbors names the parent's kind PROJECT: {parent}"
    );
    assert_eq!(
        parent.pointer("/record/kind"),
        Some(&json!("PROJECT")),
        "vault.neighbors names the parent's record kind PROJECT: {parent}"
    );
    Ok(())
}
