//! L6-03-WRITER-FOUND-KEY-LIST (Engine RULING 14 Nov 11:39, PLAN = A): a
//! person who wrote a value that mask on write lifted lists the found keys
//! they wrote, which they may answer (L6-03-WRITER-MARK = B), on value-free
//! cards. Only their own keys are read, before the page's filter, order,
//! cursor and limit. The guard: a card names its record and its place only
//! while the person can still read that record; a record moved out of their
//! read scope lists the key with neither.
//!
//! `cargo test --locked -p oneiron --all-features --test found_key_writer_list`.

use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;

use oneiron::authority::ActSurface;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::StructuralPutInput;
use oneiron::registry::{
    ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST,
};
use oneiron::secret_custody::{
    FoundKeyAction, FoundKeyCard, WrittenFoundKeyCard, WrittenFoundKeyCursor,
};
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// GitHub tokens the door's text rules place by their span, one per EVENT:
/// a value custody already holds comes back under its old handle and is
/// lifted into no new key (OF-560 C).
const TOKENS: [&str; 3] = [
    "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
    "ghp_1123456789abcdefghijklmnopqrstuvwxyz",
    "ghp_2123456789abcdefghijklmnopqrstuvwxyz",
];

/// The shipped default policy pack, whose manifest the read grants join.
const SHIPPED_POLICY_PACK: &str = "oneiron-default-policy";

/// The answers a writer may give a key no one has answered yet.
const WRITER_ANSWERS: [FoundKeyAction; 2] =
    [FoundKeyAction::NotASecret, FoundKeyAction::KeptAsText];

/// A vault with the owner's scan switch at its default (on), a device
/// keystore, its embedded owner and the owner's proof.
fn open_vault() -> Result<(tempfile::TempDir, Vault, AuthenticatedOwner), Box<dyn std::error::Error>>
{
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault.ensure_embedded_owner_actor()?;
    let owner = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    Ok((dir, vault, owner))
}

/// A live PERSON who does not own the vault, and their own proof, which
/// holds at the person tier only.
fn person(vault: &Vault) -> Result<(EntityId, AuthenticatedOwner), Box<dyn std::error::Error>> {
    let id = EntityId::now();
    vault.put_entity(
        &id,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"human",
    )?;
    let proof = vault.authenticate_owner(id, &id.to_hex(), true, GateDecisionId::now())?;
    Ok((id, proof))
}

/// An EVENT `writer` writes in their own name, whose notes hold `token`.
fn write_event(vault: &Vault, writer: EntityId, token: &str) -> EntityId {
    let receipt = vault
        .memory(writer, EdgeActorClass::Human)
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "EVENT".to_owned(),
            body: json!({
                "name": "release",
                "notes": format!("deploy with token={token}"),
            }),
            text_fields: None,
            edges: None,
            occurred_at: 1,
            learned_at: None,
        })
        .unwrap_or_else(|error| panic!("FIXTURE: the person writes an EVENT: {error:?}"));
    EntityId::from_hex(&receipt.id_hex).expect("FIXTURE: the EVENT's id")
}

/// The key the mask lifted out of `record`, as the owner's list reads it.
fn owner_card(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    record: &EntityId,
) -> Result<FoundKeyCard, Box<dyn std::error::Error>> {
    Ok(vault
        .found_keys(owner, false, 50)?
        .into_iter()
        .find(|notice| notice.record == *record)
        .and_then(|notice| notice.keys.into_iter().next())
        .ok_or("FIXTURE: the mask lifted the token into a found key")?)
}

/// Every key `proof`'s person wrote, one page of up to 50.
fn written_keys(
    vault: &Vault,
    proof: &AuthenticatedOwner,
    open_only: bool,
) -> Result<Vec<WrittenFoundKeyCard>, Box<dyn std::error::Error>> {
    let page = vault.found_keys_written_by_page(proof, open_only, None, 50)?;
    assert!(page.done, "FIXTURE: one page holds every key here");
    Ok(page.keys)
}

fn handles(cards: &[WrittenFoundKeyCard]) -> Vec<String> {
    cards.iter().map(|card| card.handle.clone()).collect()
}

/// Gives `reader` one `core:read` row in the shipped policy manifest, in
/// place of any it held there: unrestricted, or with `selectors` narrowing
/// which rows it reads. A scoped-read key reads nothing until a trusted
/// manifest grants it (the `project_extra_rooms.rs` shape).
fn set_reads(vault: &Vault, reader: EntityId, selectors: Option<serde_json::Value>) -> TestResult {
    let mut shipped = None;
    for id in vault.entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)? {
        let Some(bytes) = vault.get(&id)? else {
            continue;
        };
        let manifest: serde_json::Value = rmp_serde::from_slice(&bytes)?;
        if manifest["pack_id"] == SHIPPED_POLICY_PACK {
            shipped = Some((id, manifest));
            break;
        }
    }
    let (id, mut manifest) =
        shipped.ok_or("FIXTURE: the vault holds no shipped policy manifest")?;
    let mut read = Scope::top();
    read.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let grants = manifest["scoped_grants"]
        .as_array_mut()
        .ok_or("FIXTURE: the shipped policy manifest has no scoped grants")?;
    grants.retain(|grant| grant["actor_ref"] != reader.to_hex());
    let mut grant = json!({
        "actor_ref": reader.to_hex(),
        "effector": "core:read",
        "scope": serde_json::to_value(&read)?,
        "receipt_required": false,
    });
    if let Some(selectors) = selectors {
        grant["selectors"] = selectors;
    }
    grants.push(grant);
    oneiron::test_support::put_policy_manifest_bytes(
        vault,
        id,
        &rmp_serde::to_vec_named(&manifest)?,
    )?;
    Ok(())
}

/// Whether `person` reads `record` through their own read lane.
fn reads(
    vault: &Vault,
    person: EntityId,
    record: &EntityId,
) -> Result<bool, Box<dyn std::error::Error>> {
    Ok(vault
        .memory(person, EdgeActorClass::Human)
        .get_entity(&record.to_hex())?
        .value
        .is_some())
}

#[test]
fn a_person_lists_only_the_keys_they_wrote() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let (writer, writer_proof) = person(&vault)?;
    let (other, other_proof) = person(&vault)?;
    let (_, stranger_proof) = person(&vault)?;
    let mine = write_event(&vault, writer, TOKENS[0]);
    let theirs = write_event(&vault, other, TOKENS[1]);
    let mine_card = owner_card(&vault, &owner, &mine)?;
    let theirs_card = owner_card(&vault, &owner, &theirs)?;

    let listed = written_keys(&vault, &writer_proof, false)?;
    assert_eq!(
        handles(&listed),
        vec![mine_card.handle.clone()],
        "the writer lists their own key and no other writer's"
    );
    let card = &listed[0];
    assert_eq!(card.kind, mine_card.kind, "the card names the scan kind");
    assert_eq!(card.settled, None);
    assert_eq!(
        card.actions, WRITER_ANSWERS,
        "an open key offers the writer's two answers, none of the owner's"
    );
    assert_eq!(
        handles(&written_keys(&vault, &other_proof, false)?),
        vec![theirs_card.handle],
        "the other writer lists only theirs"
    );
    assert!(
        written_keys(&vault, &stranger_proof, false)?.is_empty(),
        "a person who wrote no key lists none"
    );
    Ok(())
}

#[test]
fn the_writer_filter_runs_before_the_page_limit() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let (writer, writer_proof) = person(&vault)?;
    let (other, other_proof) = person(&vault)?;
    let older = write_event(&vault, writer, TOKENS[0]);
    let newer = [
        write_event(&vault, other, TOKENS[1]),
        write_event(&vault, other, TOKENS[2]),
    ];
    let older_handle = owner_card(&vault, &owner, &older)?.handle;

    let page = vault.found_keys_written_by_page(&writer_proof, false, None, 1)?;
    assert_eq!(
        handles(&page.keys),
        vec![older_handle],
        "the writer's older key fills their page, past another writer's newer ones"
    );
    assert!(page.done && page.next_cursor.is_none());

    // The other writer's two keys, a page of one at a time: each once.
    let first = vault.found_keys_written_by_page(&other_proof, false, None, 1)?;
    assert_eq!(first.keys.len(), 1);
    assert!(!first.done, "a second key is left");
    let cursor = first
        .next_cursor
        .clone()
        .ok_or("a page with a key left names its cursor")?;
    assert_eq!(
        WrittenFoundKeyCursor::parse(&cursor.to_text()),
        Some(cursor.clone()),
        "the cursor reads back from its text"
    );
    assert!(
        !cursor.to_text().contains(&newer[0].to_hex())
            && !cursor.to_text().contains(&newer[1].to_hex()),
        "the cursor names no record"
    );
    let second = vault.found_keys_written_by_page(&other_proof, false, Some(&cursor), 1)?;
    assert_eq!(second.keys.len(), 1);
    assert!(second.done && second.next_cursor.is_none());
    let paged: HashSet<String> = handles(&first.keys)
        .into_iter()
        .chain(handles(&second.keys))
        .collect();
    let expected: HashSet<String> = newer
        .iter()
        .map(|record| owner_card(&vault, &owner, record).map(|card| card.handle))
        .collect::<Result<_, _>>()?;
    assert_eq!(
        paged, expected,
        "the two pages list each of their keys once"
    );
    Ok(())
}

#[test]
fn open_only_keeps_the_keys_no_one_answered() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let (writer, writer_proof) = person(&vault)?;
    let answered = write_event(&vault, writer, TOKENS[0]);
    let open = write_event(&vault, writer, TOKENS[1]);
    let answered_handle = owner_card(&vault, &owner, &answered)?.handle;
    let open_handle = owner_card(&vault, &owner, &open)?.handle;
    let ruled = vault
        .rule_found_key_not_a_secret(&writer_proof, ActSurface::ThisInstall, &answered_handle)
        .unwrap_or_else(|error| panic!("FIXTURE: the writer rules their own key: {error:?}"));

    assert_eq!(
        handles(&written_keys(&vault, &writer_proof, true)?),
        vec![open_handle.clone()],
        "open_only lists the key no one answered"
    );
    let all = written_keys(&vault, &writer_proof, false)?;
    let answered_card = all
        .iter()
        .find(|card| card.handle == answered_handle)
        .ok_or("the full list keeps the answered key")?;
    let settled = answered_card
        .settled
        .ok_or("the answered key names its answer")?;
    assert_eq!(settled.action, FoundKeyAction::NotASecret);
    assert_eq!(settled.at, ruled.at, "and when it was given");
    assert!(
        answered_card.actions.is_empty(),
        "an answered key offers no answer"
    );
    let open_card = all
        .iter()
        .find(|card| card.handle == open_handle)
        .ok_or("the full list keeps the open key")?;
    assert_eq!(open_card.actions, WRITER_ANSWERS);
    Ok(())
}

#[test]
fn a_record_moved_out_of_the_writers_read_scope_lists_the_key_with_no_place() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let (writer, writer_proof) = person(&vault)?;
    let record = write_event(&vault, writer, TOKENS[0]);
    let owner_view = owner_card(&vault, &owner, &record)?;

    set_reads(&vault, writer, None)?;
    assert!(
        reads(&vault, writer, &record)?,
        "FIXTURE: an unrestricted read grant reads the writer's EVENT"
    );
    let listed = written_keys(&vault, &writer_proof, false)?;
    assert_eq!(handles(&listed), vec![owner_view.handle.clone()]);
    assert_eq!(
        listed[0].record,
        Some(record),
        "a record the writer reads is named"
    );
    assert_eq!(
        listed[0].place.as_deref(),
        Some(owner_view.place.as_str()),
        "with where the key sat in it"
    );

    // The owner narrows the writer's reads to room rows: the EVENT leaves
    // their read scope.
    set_reads(
        &vault,
        writer,
        Some(json!({"entity_types": [ENTITY_TYPE_CONVERSATION]})),
    )?;
    assert!(
        !reads(&vault, writer, &record)?,
        "FIXTURE: a CONVERSATION-only grant reads no EVENT"
    );
    let listed = written_keys(&vault, &writer_proof, false)?;
    assert_eq!(
        handles(&listed),
        vec![owner_view.handle],
        "the key is still the writer's to answer"
    );
    assert_eq!(listed[0].record, None, "the record is no longer named");
    assert_eq!(listed[0].place, None, "nor where in it the key sat");
    assert_eq!(listed[0].actions, WRITER_ANSWERS);
    Ok(())
}
