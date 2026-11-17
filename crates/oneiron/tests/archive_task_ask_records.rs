//! FIX OWNER-RESTORE-REFUSES-TASK-ASK-RECORDS (row of 17 Nov 09:46; Engine ruling
//! TASK-FACT-ARCHIVE-CROSSING = A, 17 Nov 00:02: "archives keep the facts"). An ask writes
//! its records as role-6 TASK rows through the engine's fact put (task_verb/ask_record.rs:
//! its group, each answer, its settlement), and a whole-vault archive carries them. The
//! owner's restore lands each at its archived id and body through that put, whose guard
//! checks it as it checks a replayed record. Every other import refuses the record at the
//! raw put, as built.
//!
//! - `an_owners_archive_with_a_settled_ask_restores_its_records`: red on the base (#9365's
//!   head 1290fa483922: the import fails whole, "reserved task role is written only by its
//!   engine door"), green on the head.
//! - `an_import_with_no_owner_refuses_the_ask_records`: guard, passes on the base and on the
//!   head.
//!
//! Public paths only; no test door.
//! Run: `cargo test --locked -p oneiron --all-features --test archive_task_ask_records`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::io::Cursor;

use oneiron::consent::AuthenticatedOwner;
use oneiron::registry::ENTITY_TYPE_TASK;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::{
    ConsultPayloadRef, TaskAskDefault, TaskAskHandle, TaskAskQuestion, TaskAskSettlementReason,
    TaskAskSpec, TaskAskStatus, TaskAskTarget, TaskAskWord, TaskAssignee,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig,
};
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use rmpv::Value;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A source vault whose owner asked himself about one claim and answered:
/// the ask settled on his first word.
struct Source {
    _directory: tempfile::TempDir,
    vault: Vault,
    handle: TaskAskHandle,
}

fn source_with_a_settled_ask() -> Result<Source, Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    // `open_owned` holds the writer lease the owner's policy door asks for.
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let claim = EntityId::now();
    let at = vault.now_recorded_at();
    vault.put_claim(
        &claim,
        &ClaimBody::new(
            "profile.note",
            ClaimSubject::Entity(owner),
            Value::from("files the quarterly report on Fridays"),
            0.9,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )?,
        TimeRange { start: at, end: at },
        at,
    )?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let receipt = memory.tasks_ask(&TaskAskSpec::shorthand(
        Some(TaskAskTarget::Responder(TaskAssignee::Human {
            actor_ref: owner,
        })),
        TaskAskQuestion::new(ConsultPayloadRef::Claim(claim)),
        None,
        TaskAskDefault::AskMe,
    ))?;
    memory.tasks_answer(&receipt.handle, &TaskAskWord::new(owner))?;
    let TaskAskStatus::Settled(result) = memory.tasks_ask_status(receipt.handle)? else {
        panic!("the owner's first word settles his ask on the source");
    };
    assert_eq!(result.settlement.reason, TaskAskSettlementReason::FirstWord);
    Ok(Source {
        _directory: directory,
        handle: receipt.handle,
        vault,
    })
}

/// A fresh destination, opened at least one wall-clock second after its
/// source, as `archive_task_authority_facts.rs` opens one.
fn open_later_vault() -> Result<(tempfile::TempDir, Vault), Box<dyn std::error::Error>> {
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let directory = tempfile::tempdir()?;
    let vault = Vault::open(directory.path(), VaultConfig::default())?;
    Ok((directory, vault))
}

/// The owner of `vault`, as his session proves him.
fn owner_proof(vault: &Vault) -> Result<AuthenticatedOwner, Box<dyn std::error::Error>> {
    let owner = vault.ensure_embedded_owner_actor()?;
    Ok(vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?)
}

/// The body's `subkind`, if it is a map that names one.
fn subkind(body: &[u8]) -> Option<String> {
    let value = rmpv::decode::read_value(&mut &body[..]).ok()?;
    value
        .as_map()?
        .iter()
        .find(|(key, _)| key.as_str() == Some("subkind"))
        .and_then(|(_, value)| value.as_str())
        .map(str::to_owned)
}

/// Every ask record `vault` holds (a TASK row whose subkind is an ask's), by
/// id: its subkind and its body.
fn ask_records(vault: &Vault) -> oneiron::Result<BTreeMap<EntityId, (String, Vec<u8>)>> {
    let mut records = BTreeMap::new();
    for id in vault.entities_by_type(ENTITY_TYPE_TASK)? {
        let Some(raw) = vault.get_raw(&id)? else {
            continue;
        };
        let body = raw[ENTITY_METADATA_HEADER_LEN..].to_vec();
        if let Some(kind) = subkind(&body).filter(|kind| kind.starts_with("tasks.ask_")) {
            records.insert(id, (kind, body));
        }
    }
    Ok(records)
}

#[test]
fn an_owners_archive_with_a_settled_ask_restores_its_records() -> TestResult {
    let source = source_with_a_settled_ask()?;
    let records = ask_records(&source.vault)?;
    for kind in ["tasks.ask_group", "tasks.ask_answer"] {
        assert!(
            records.values().any(|(held, _)| held == kind),
            "the source's ask wrote its {kind} record: {records:?}"
        );
    }
    let archive = source.vault.export_whole_vault(true)?.bytes().to_vec();

    let (_dest_directory, dest) = open_later_vault()?;
    let proof = owner_proof(&dest)?;
    if let Err(error) = dest.import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &proof)
    {
        panic!("the owner's whole archive with an ask must restore: {error:?}");
    }
    assert_eq!(
        ask_records(&dest)?,
        records,
        "every ask record comes back at its archived id, its body byte for byte"
    );
    let owner = dest.ensure_embedded_owner_actor()?;
    let TaskAskStatus::Settled(result) = dest
        .memory(owner, EdgeActorClass::Human)
        .tasks_ask_status(source.handle)?
    else {
        panic!("the restored ask reads settled");
    };
    assert_eq!(
        result.settlement.reason,
        TaskAskSettlementReason::FirstWord,
        "the restored ask keeps the settlement its owner's word made"
    );
    assert_eq!(result.evidence.len(), 1, "the owner's one word counts");
    Ok(())
}

#[test]
fn an_import_with_no_owner_refuses_the_ask_records() -> TestResult {
    let source = source_with_a_settled_ask()?;
    let records = ask_records(&source.vault)?;
    let archive = source.vault.export_whole_vault(true)?.bytes().to_vec();

    let (_dest_directory, dest) = open_later_vault()?;
    let refused = dest
        .import_whole_vault_archive(&archive)
        .expect_err("only the owner's restore lands an ask record");
    assert!(
        refused.to_string().contains("reserved task role"),
        "the import is refused at a role-6 record: {refused}"
    );
    assert!(
        ask_records(&dest)?
            .keys()
            .all(|id| !records.contains_key(id)),
        "no ask record of the refused import lands"
    );
    Ok(())
}
