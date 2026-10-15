//! The code's own list of engine scans: none refuses for how many rows it
//! reads (rule 5). Each serves one row past a lowered threshold row, twice,
//! and raises its check once.

use super::*;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::outbound_intent_ledger::IntentId;
use crate::receipt::{ReceiptKind, ReceiptRecord};
use crate::registry::ENTITY_TYPE_TASK_LIST;
use crate::store::Store;
use heed::RwTxn;

/// The row each scan is lowered to; every fixture reads one row past it.
const ROW: u64 = 2;
const PAST: usize = 3;
const LEARNED_AT: u64 = 1_700_000_000;

fn id(seed: u8, index: usize) -> EntityId {
    let mut bytes = [0x7e; 16];
    bytes[1] = seed;
    bytes[8..].copy_from_slice(&u64::try_from(index).expect("fits").to_be_bytes());
    EntityId::from_bytes(bytes).expect("seeded id")
}

/// A plain edge value: weight, then timestamp.
fn edge_value() -> [u8; 12] {
    let mut value = [0u8; 12];
    value[0..4].copy_from_slice(&0.9_f32.to_le_bytes());
    value[4..12].copy_from_slice(&1_u64.to_le_bytes());
    value
}

/// `len` records, each superseding the one before it; none materialized.
fn supersession_chain(vault: &Vault, wtxn: &mut RwTxn<'_>, seed: u8, len: usize) -> Result<()> {
    for index in 1..len {
        let (newer, older) = (id(seed, index), id(seed, index - 1));
        let out = Store::encode_edge_key(&newer, EdgeKind::Supersedes, &older);
        let into = Store::encode_edge_key(&older, EdgeKind::Supersedes, &newer);
        vault.store.edges_out.put(wtxn, &out, &edge_value())?;
        vault.store.edges_in.put(wtxn, &into, &edge_value())?;
    }
    Ok(())
}

/// One pending gate decision, its id minted now.
fn gate_decision(index: usize) -> crate::store::GateDecisionRecord {
    crate::store::GateDecisionRecord {
        version: 0,
        decision_id: crate::store::GateDecisionId::now(),
        created_at: u64::try_from(index).expect("fits") + 1,
        outcome: "pending".to_owned(),
        reason_codes: vec!["gate.pending.actor_ceiling".to_owned()],
        receipt_reasons: Vec::new(),
        system_notices: Vec::new(),
        actor_class: "agent".to_owned(),
        actor_ref: Some("agent-table".to_owned()),
        content_kind: "claim".to_owned(),
        policy_manifest_version: "test-policy".to_owned(),
        claim_id: Some(*id(0x57, index).as_bytes()),
        grant_ref: None,
        diff_handle: vec![0xA5],
        read_frontier_hash: [0xB6; 32],
        redacted_at: None,
    }
}

/// A PERSON with a `Mentions` edge to each of `PAST` other people, and a
/// PERSON-band read grant for `agent:reader`. Returns the first.
fn scoped_people(vault: &Vault) -> EntityId {
    use crate::federation::ScopeAxis;
    let at = crate::temporal::TimeRange { start: 1, end: 1 };
    let people: Vec<EntityId> = (0..=PAST).map(|_| EntityId::now()).collect();
    for person in &people {
        vault
            .put_entity(person, crate::registry::ENTITY_TYPE_PERSON, at, 1, b"node")
            .expect("person");
    }
    let mut batch = vault.batch();
    for peer in &people[1..] {
        batch = batch.edge(&people[0], EdgeKind::Mentions, peer, 1.0);
    }
    batch.commit().expect("edges");
    let mut scope = crate::federation::scope_codec::read_preset();
    scope.bands = ScopeAxis::Some([crate::registry::ENTITY_TYPE_PERSON].into());
    let grant = rmpv::Value::Map(vec![
        ("actor_ref".into(), "agent:reader".into()),
        ("effector".into(), "core:read".into()),
        (
            "scope".into(),
            crate::federation::scope_codec::encode_scope_value(&scope).expect("scope"),
        ),
        ("receipt_required".into(), false.into()),
    ]);
    let manifest =
        crate::gate::default_policy_manifest_with_scoped_grants(vec![grant]).expect("manifest");
    crate::test_util::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id().expect("manifest id"),
        &manifest,
    )
    .expect("put manifest");
    people[0]
}

/// One outbound suppression record, the shape the dedupe door keeps.
fn suppression(vault: &Vault, wtxn: &mut RwTxn<'_>, index: usize) -> Result<()> {
    let mut intent: IntentId = [0x5a; 32];
    intent[24..].copy_from_slice(&u64::try_from(index).expect("index fits").to_be_bytes());
    let receipt = ReceiptRecord {
        receipt_id: crate::receipt::suppression_receipt_id(&intent),
        receipt_kind: ReceiptKind::Outbound,
        occurred_at: LEARNED_AT,
        actor: None,
        on_behalf_of: None,
        outcome: "suppressed".to_owned(),
        job_ref: None,
        trigger_ref: None,
        policy_trace: Vec::new(),
        fields: [
            ("suppression".to_owned(), "dedupe".to_owned()),
            ("dedupe_key".to_owned(), format!("key-{index}")),
        ]
        .into(),
    };
    crate::receipt::put_suppression_in_txn(vault, wtxn, &intent, &receipt, LEARNED_AT)
}

/// A scan's read: the items it serves once it has read every row.
type Read<'a> = Box<dyn Fn() -> Result<usize> + 'a>;

/// Seeds `PAST` rows for `scan` and hands back what its read serves and the
/// read, or `None` for a scan whose fixture lives with its own tests: the
/// origin's table (`origin::smart_http::scan_cap_tests::
/// no_origin_scan_refuses_for_its_row_count`) and the mesh bind
/// (`authority::tests::machine_identity::a_mesh_bind_reads_past_the_old_machine_cap`).
fn seed(vault: &Vault, scan: EngineScan) -> Option<(usize, Read<'_>)> {
    let src = id(0x51, 0);
    match scan {
        EngineScan::ReceivePackIntents
        | EngineScan::PublicationRows
        | EngineScan::VisibleRefRows
        | EngineScan::KeepOwnerRows => {
            assert!(EngineScan::ORIGIN.contains(&scan));
            None
        }
        EngineScan::MachineRows => None,
        EngineScan::AccessGrantRows => {
            // Index rows whose grants are gone: read, skipped, never served.
            vault
                .with_write_txn(|wtxn| {
                    for index in 0..PAST {
                        let key = Store::encode_type_key(
                            crate::registry::ENTITY_TYPE_ACCESS_GRANT,
                            &id(0x58, index),
                        );
                        vault.store.type_index.put(wtxn, &key, &[])?;
                    }
                    Ok(())
                })
                .expect("seed");
            Some((
                0,
                Box::new(move || {
                    Ok(vault
                        .authorized_companion_profile_personas(&id(0x59, 0), &id(0x59, 1))?
                        .len())
                }),
            ))
        }
        EngineScan::TypeIndexRows => {
            vault
                .with_write_txn(|wtxn| {
                    for index in 0..PAST {
                        let key = Store::encode_type_key(ENTITY_TYPE_TASK_LIST, &id(0x52, index));
                        vault.store.type_index.put(wtxn, &key, &[])?;
                    }
                    Ok(())
                })
                .expect("seed");
            Some((
                PAST,
                Box::new(move || Ok(vault.entities_by_type(ENTITY_TYPE_TASK_LIST)?.len())),
            ))
        }
        EngineScan::LearnedRangeRows => {
            vault
                .with_write_txn(|wtxn| {
                    for index in 0..PAST {
                        let key =
                            [&LEARNED_AT.to_be_bytes()[..], id(0x53, index).as_bytes()].concat();
                        vault.store.temporal_learned.put(wtxn, &key, &[])?;
                    }
                    Ok(())
                })
                .expect("seed");
            Some((
                PAST,
                Box::new(move || {
                    Ok(vault
                        .entities_in_learned_range(LEARNED_AT, LEARNED_AT + 1)?
                        .len())
                }),
            ))
        }
        EngineScan::EdgePeerRows => {
            vault
                .with_write_txn(|wtxn| {
                    for index in 0..PAST {
                        let key =
                            Store::encode_edge_key(&src, EdgeKind::BelongsTo, &id(0x54, index));
                        vault.store.edges_out.put(wtxn, &key, &edge_value())?;
                    }
                    Ok(())
                })
                .expect("seed");
            Some((
                PAST,
                Box::new(move || Ok(vault.targets(&src, EdgeKind::BelongsTo, None)?.len())),
            ))
        }
        EngineScan::TimelineRecords => {
            vault
                .with_write_txn(|wtxn| supersession_chain(vault, wtxn, 0x55, PAST))
                .expect("seed");
            let anchor = id(0x55, 0);
            Some((
                PAST,
                Box::new(move || Ok(vault.memory_timeline(&anchor)?.records.len())),
            ))
        }
        EngineScan::GateDecisionRows => {
            vault
                .with_write_txn(|wtxn| {
                    for index in 0..PAST {
                        vault
                            .store
                            .append_gate_decision_in_txn(wtxn, &gate_decision(index))?;
                    }
                    Ok(())
                })
                .expect("seed");
            Some((
                PAST,
                Box::new(move || {
                    let query =
                        crate::receipt::ReceiptQuery::new(PAST).with_kind(ReceiptKind::Gate);
                    Ok(vault.receipts(query)?.len())
                }),
            ))
        }
        EngineScan::ScopedEdgeRows => {
            let center = scoped_people(vault);
            Some((
                PAST,
                Box::new(move || {
                    let reader =
                        crate::claim::ScopedReadActorKey::new("agent:reader").expect("key");
                    let edges = vault
                        .scoped_read(reader)
                        .edges_out_of_kind(&center, EdgeKind::Mentions)?;
                    Ok(edges.value.map_or(0, |edges| edges.len()))
                }),
            ))
        }
        EngineScan::ReceiptRecordRows => {
            vault
                .with_write_txn(|wtxn| {
                    for index in 0..PAST {
                        suppression(vault, wtxn, index)?;
                    }
                    Ok(())
                })
                .expect("seed");
            let window = crate::deletion::window_label_from_timestamp(LEARNED_AT);
            Some((
                PAST,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    let records = crate::receipt::canonical_records_in_window(
                        &vault.store,
                        &txn,
                        &window,
                        |_| Ok(()),
                    )?;
                    Ok(records.len())
                }),
            ))
        }
    }
}

#[test]
fn no_engine_scan_refuses_for_its_row_count() {
    let mut refused = Vec::new();
    for scan in EngineScan::ALL {
        let dir = tempfile::tempdir().expect("vault dir");
        let vault = Vault::open(dir.path(), crate::VaultConfig::default()).expect("open");
        vault.set_scan_threshold(scan, ROW).expect("lower the row");
        let Some((served, read)) = seed(&vault, scan) else {
            continue;
        };
        for _ in 0..2 {
            match read() {
                Ok(rows) => assert_eq!(rows, served, "{} read every row", scan.code()),
                Err(error) => refused.push(format!("{}: {:?}", scan.code(), error.kind())),
            }
        }
        let checks = vault.scan_checks().expect("checks");
        let raised: Vec<_> = checks
            .iter()
            .filter(|check| check.scan == scan.code())
            .collect();
        assert_eq!(raised.len(), 1, "{} raised its check once", scan.code());
        assert_eq!(raised[0].threshold, ROW);
    }
    assert!(
        refused.is_empty(),
        "scans refused past their row: {refused:?}"
    );
}

/// Class-A row 49: a canonical window capture walks the whole local receipt
/// index, however many receipts other windows hold. Main refused the walk
/// at its 100,001st row, before reading any window.
#[test]
fn a_canonical_receipt_window_reads_past_the_old_cap() {
    const PAST_THE_OLD_CAP: usize = 100_001;
    const CHUNK: usize = 10_000;
    let dir = tempfile::tempdir().expect("vault dir");
    let config = crate::VaultConfig {
        map_size: 1024 * 1024 * 1024,
        ..crate::VaultConfig::default()
    };
    let vault = Vault::open(dir.path(), config).expect("open");
    for start in (0..PAST_THE_OLD_CAP).step_by(CHUNK) {
        vault
            .with_write_txn(|wtxn| {
                for index in start..(start + CHUNK).min(PAST_THE_OLD_CAP) {
                    suppression(&vault, wtxn, index)?;
                }
                Ok(())
            })
            .expect("seed");
    }
    let next_month = crate::deletion::window_label_from_timestamp(LEARNED_AT + 40 * 86_400);
    let txn = vault.store.env.read_txn().expect("read");
    let records =
        crate::receipt::canonical_records_in_window(&vault.store, &txn, &next_month, |_| Ok(()))
            .expect("a window walk never refuses for count");
    assert!(records.is_empty());
    let this_month = crate::deletion::window_label_from_timestamp(LEARNED_AT);
    let records =
        crate::receipt::canonical_records_in_window(&vault.store, &txn, &this_month, |_| Ok(()))
            .expect("a window walk never refuses for count");
    assert_eq!(records.len(), PAST_THE_OLD_CAP);
}

/// H58: a memory timeline names every record of its supersession chain.
/// Main refused a chain past 10,000 records.
#[test]
fn a_memory_timeline_reads_past_the_old_cap() {
    const PAST_THE_OLD_CAP: usize = 10_001;
    let dir = tempfile::tempdir().expect("vault dir");
    let config = crate::VaultConfig {
        map_size: 256 * 1024 * 1024,
        ..crate::VaultConfig::default()
    };
    let vault = Vault::open(dir.path(), config).expect("open");
    vault
        .with_write_txn(|wtxn| supersession_chain(&vault, wtxn, 0x56, PAST_THE_OLD_CAP))
        .expect("seed");
    let timeline = vault
        .memory_timeline(&id(0x56, PAST_THE_OLD_CAP / 2))
        .expect("a timeline never refuses for count");
    assert_eq!(timeline.records.len(), PAST_THE_OLD_CAP);
}
