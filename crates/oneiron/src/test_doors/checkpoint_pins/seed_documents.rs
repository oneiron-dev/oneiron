//! The checkpoint-pins door's document seeds: core entity and edge rows,
//! NOTEs, entity documents and entity revisions. Malformed core rows go
//! through the store's test-door writers, byte for byte.

use super::*;
use crate::store::test_door_rows::{
    put_edge_in_row_bytes_in_txn, put_edge_out_row_bytes_in_txn, put_entity_row_bytes_in_txn,
};

/// One fixed row per placement branch of `entity_row_placement`: an
/// ordinary PERSON row, a row of each custody kind, CLAIM rows of each
/// predicate branch and an undecodable one, NOTE rows of each author
/// branch, an author carrier and a plain identity op, an unknown kind, a
/// short row and a bad-key row; an `authored_by` edge in each direction, a
/// plain edge and an undecodable one.
pub(super) fn seed_entities(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    put_entity_row_bytes_in_txn(
        &vault.store,
        txn,
        id(0xf0)?.as_bytes(),
        &entity_row(ENTITY_TYPE_PERSON, b"pins-person"),
    )?;
    put_entity_row_bytes_in_txn(
        &vault.store,
        txn,
        id(0xf1)?.as_bytes(),
        &entity_row(ENTITY_TYPE_SECRET_CUSTODY, b"pins-secret"),
    )?;
    put_entity_row_bytes_in_txn(
        &vault.store,
        txn,
        id(0xf2)?.as_bytes(),
        &entity_row(ENTITY_TYPE_WORLD_KEY_PAD, b"pins-pad"),
    )?;
    put_entity_row_bytes_in_txn(
        &vault.store,
        txn,
        id(0xf3)?.as_bytes(),
        &entity_row(ENTITY_TYPE_ASSET, b"pins-asset"),
    )?;
    let ordinary = encode_claim_body(&claim_body("pins.pred", id(0xf4)?)?)?;
    put_entity_row_bytes_in_txn(
        &vault.store,
        txn,
        id(0xf4)?.as_bytes(),
        &entity_row(ENTITY_TYPE_CLAIM, &ordinary),
    )?;
    let dreamer = encode_claim_body(&claim_body(DREAMER_STEP_PREDICATE, id(0xf5)?)?)?;
    put_entity_row_bytes_in_txn(
        &vault.store,
        txn,
        id(0xf5)?.as_bytes(),
        &entity_row(ENTITY_TYPE_CLAIM, &dreamer),
    )?;
    let origin = encode_claim_body(&claim_body(ORIGIN_CHANGE_PREDICATE, id(0xf6)?)?)?;
    put_entity_row_bytes_in_txn(
        &vault.store,
        txn,
        id(0xf6)?.as_bytes(),
        &entity_row(ENTITY_TYPE_CLAIM, &origin),
    )?;
    put_entity_row_bytes_in_txn(
        &vault.store,
        txn,
        id(0xf7)?.as_bytes(),
        &entity_row(ENTITY_TYPE_CLAIM, b"\xff\xff"),
    )?;
    put_entity_row_bytes_in_txn(
        &vault.store,
        txn,
        id(0xf8)?.as_bytes(),
        &entity_row(ENTITY_TYPE_NOTE, b""),
    )?;
    let no_one = encode_note_core(&NoteCore {
        kind: NoteKind::OpinionTake,
        author_ref: NoteActor::Erased,
        source_revision_ref: [0xf9; 16],
    })?;
    put_entity_row_bytes_in_txn(
        &vault.store,
        txn,
        id(0xf9)?.as_bytes(),
        &entity_row(ENTITY_TYPE_NOTE, &no_one),
    )?;
    let live = encode_note_core(&NoteCore {
        kind: NoteKind::OpinionTake,
        author_ref: NoteActor::Actor(id(0xfb)?),
        source_revision_ref: [0xfa; 16],
    })?;
    put_entity_row_bytes_in_txn(
        &vault.store,
        txn,
        id(0xfa)?.as_bytes(),
        &entity_row(ENTITY_TYPE_NOTE, &live),
    )?;
    put_entity_row_bytes_in_txn(
        &vault.store,
        txn,
        id(0xfb)?.as_bytes(),
        &entity_row(ENTITY_TYPE_NOTE, b"not-a-core"),
    )?;
    let carrier = identity_row(pins_author_attribution_action(
        id(0xfc)?,
        [0xfc; 32],
        WriteActor::new(id(0xfd)?, EdgeActorClass::Human),
    ))?;
    put_entity_row_bytes_in_txn(&vault.store, txn, id(0xfc)?.as_bytes(), &carrier)?;
    let op = identity_row(pins_undo_action(id(0xfd)?))?;
    put_entity_row_bytes_in_txn(&vault.store, txn, id(0xfd)?.as_bytes(), &op)?;
    put_entity_row_bytes_in_txn(
        &vault.store,
        txn,
        id(0xfe)?.as_bytes(),
        &entity_row(ENTITY_TYPE_SUSPICIOUS_WAKE, b"x"),
    )?;
    put_entity_row_bytes_in_txn(&vault.store, txn, id(0x10)?.as_bytes(), b"short")?;
    put_entity_row_bytes_in_txn(&vault.store, txn, b"bad", b"short")?;
    let authored = id(0xf0)?;
    let actor = id(0xf1)?;
    let edge_value = encode_edge_value(
        EdgeKind::AuthoredBy,
        0.9,
        1_700_000_000_000,
        Vad::NEUTRAL,
        None,
    )?;
    let out_key = Store::encode_edge_key(&authored, EdgeKind::AuthoredBy, &actor);
    put_edge_out_row_bytes_in_txn(&vault.store, txn, &out_key, &edge_value)?;
    let in_key = Store::encode_edge_key(&actor, EdgeKind::AuthoredBy, &authored);
    put_edge_in_row_bytes_in_txn(&vault.store, txn, &in_key, &edge_value)?;
    let plain_value = encode_edge_value(
        EdgeKind::ClaimOf,
        1.0,
        1_700_000_000_000,
        Vad::NEUTRAL,
        None,
    )?;
    let plain_key = Store::encode_edge_key(&id(0xf2)?, EdgeKind::ClaimOf, &id(0xf3)?);
    put_edge_out_row_bytes_in_txn(&vault.store, txn, &plain_key, &plain_value)?;
    let mut bad_key = Store::encode_edge_key(&id(0xf4)?, EdgeKind::ClaimOf, &id(0xf5)?);
    bad_key[16] = 250;
    put_edge_out_row_bytes_in_txn(&vault.store, txn, &bad_key, &plain_value)?;
    Ok(())
}

/// A NOTE head with its marker, an override, seals, forks and receipts
/// with actors and erased, an undecided fork with its proposal document
/// beside it, an exact and an apart document, one- and two-NOTE bundles
/// and an empty one, operation rows, every pin table, and title rows.
pub(super) fn seed_note(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    let at = 1_700_000_000_012;
    let note = id(0x20)?;
    let head = id(0x21)?;
    let actor = id(0x22)?;
    set_head(&vault.store, txn, note, head, 7)?;
    N_OVERRIDE.put(
        vault,
        txn,
        &note,
        &NoteOverrides {
            context: Some(ContextDefault::VaultReadable),
            ..Default::default()
        },
    )?;
    N_SEAL.put(
        vault,
        txn,
        &note,
        &NoteSeal {
            note,
            document: head,
            frontier: vec![0x20; 8],
            sealed_by: NoteActor::Actor(actor),
            sealed_at: at,
        },
    )?;
    N_SEAL.put(
        vault,
        txn,
        &id(0x2b)?,
        &NoteSeal {
            note: id(0x2b)?,
            document: head,
            frontier: vec![0x21; 8],
            sealed_by: NoteActor::Erased,
            sealed_at: at,
        },
    )?;
    let fork = |fork: EntityId, decided: bool, by: NoteActor| NoteFork {
        note,
        fork,
        parent: head,
        frontier: vec![0x22; 8],
        recovery_merge: None,
        actor: by,
        rewrite: false,
        proposal: None,
        decided,
    };
    N_FORK.put(
        vault,
        txn,
        &id(0x23)?,
        &fork(id(0x23)?, true, NoteActor::Actor(actor)),
    )?;
    N_FORK.put(
        vault,
        txn,
        &id(0x24)?,
        &fork(id(0x24)?, false, NoteActor::Actor(actor)),
    )?;
    N_FORK.put(
        vault,
        txn,
        &id(0x26)?,
        &NoteFork {
            note: id(0x25)?,
            fork: id(0x26)?,
            parent: head,
            frontier: vec![0x23; 8],
            recovery_merge: None,
            actor: NoteActor::Erased,
            rewrite: false,
            proposal: None,
            decided: true,
        },
    )?;
    N_FORK.put(
        vault,
        txn,
        &id(0x11)?,
        &NoteFork {
            note: id(0x2b)?,
            fork: id(0x24)?,
            parent: head,
            frontier: vec![0x24; 8],
            recovery_merge: None,
            actor: NoteActor::Actor(actor),
            rewrite: false,
            proposal: None,
            decided: false,
        },
    )?;
    let beside = pins_note_proposal_snapshot(
        &note,
        "pins proposal",
        Some((id(0x24)?, actor)),
        7,
        at as i64,
    )?;
    put_pins_note_proposal_doc_in_txn(&vault.store, txn, &note, &id(0x24)?, &beside)?;
    let exact = pins_note_proposal_snapshot(&id(0x25)?, "pins exact", None, 8, at as i64)?;
    put_pins_note_proposal_doc_in_txn(&vault.store, txn, &id(0x25)?, &id(0x26)?, &exact)?;
    put_pins_note_proposal_doc_in_txn(&vault.store, txn, &id(0x2b)?, &id(0x24)?, &exact)?;
    N_RECEIPT.put(
        vault,
        txn,
        &id(0x27)?,
        &NoteLandingReceipt {
            id: id(0x27)?,
            note,
            fork: id(0x23)?,
            previous_head: head,
            head: id(0x23)?,
            verdict: NoteVerdict::Merge,
            actor: NoteActor::Actor(actor),
            at,
        },
    )?;
    N_RECEIPT.put(
        vault,
        txn,
        &id(0x29)?,
        &NoteLandingReceipt {
            id: id(0x29)?,
            note: id(0x2b)?,
            fork: id(0x23)?,
            previous_head: head,
            head: id(0x23)?,
            verdict: NoteVerdict::Switch,
            actor: NoteActor::Erased,
            at,
        },
    )?;
    N_BUNDLE.put(
        vault,
        txn,
        &id(0x28)?,
        &NoteReviewBundle {
            id: id(0x28)?,
            waiting: vec![fork(id(0x29)?, false, NoteActor::Actor(actor))],
            landed: Vec::new(),
            explainer: "pins explainer".to_owned(),
        },
    )?;
    N_BUNDLE.put(
        vault,
        txn,
        &id(0x2a)?,
        &NoteReviewBundle {
            id: id(0x2a)?,
            waiting: vec![fork(id(0x29)?, false, NoteActor::Actor(actor))],
            landed: vec![NoteLandingReceipt {
                id: id(0x29)?,
                note: id(0x2b)?,
                fork: id(0x23)?,
                previous_head: head,
                head: id(0x23)?,
                verdict: NoteVerdict::Merge,
                actor: NoteActor::Actor(actor),
                at,
            }],
            explainer: "pins shared explainer".to_owned(),
        },
    )?;
    N_BUNDLE.put(
        vault,
        txn,
        &id(0x2c)?,
        &NoteReviewBundle {
            id: id(0x2c)?,
            waiting: Vec::new(),
            landed: Vec::new(),
            explainer: String::new(),
        },
    )?;
    let request = id(0x2c)?;
    let sync_key = format!("{}:{}", note.to_hex(), request.to_hex()).into_bytes();
    N_SYNC.put(
        vault,
        txn,
        &sync_key,
        &serde_json::json!({"pins": "receipt"}),
    )?;
    N_SYNC.put(
        vault,
        txn,
        &b"pins-unowned".to_vec(),
        &serde_json::json!({"pins": "unowned"}),
    )?;
    put_pins_fork_authority_in_txn(&vault.store, txn, &note, &id(0x23)?, [0x6d; 32])?;
    let operation = NoteOperationReceipt {
        request_id: request,
        command_hash: [0x2d; 32],
        outcome: NoteScalarEditOutcome::Applied(NoteDocumentView {
            document: note,
            frontier: vec![0x2e; 4],
            markdown: "pins".to_owned(),
            title: None,
            pins: Vec::new(),
            authorship: Vec::new(),
        }),
    };
    put_pins_receipt_by_request_in_txn(
        &vault.store,
        txn,
        &note,
        &request,
        NoteActor::Actor(actor),
        &operation,
    )?;
    let pin = NotePin {
        claim: id(0x2d)?,
        document: id(0x2e)?,
        frontier: b"pins-frontier".to_vec(),
        start_cursor: b"pins-cursor-left".to_vec(),
        end_cursor: b"pins-cursor-right".to_vec(),
        quote_hash: [0x71; 32],
        quote_text: "pins quote".to_owned(),
    };
    put_pins_pin_in_txn(&vault.store, txn, &id(0x2f)?, &pin)?;
    put_pins_request_in_txn(
        &vault.store,
        txn,
        &id(0x2f)?,
        &request,
        &id(0x2e)?,
        &id(0x2d)?,
    )?;
    put_pins_title_in_txn(&vault.store, txn, &actor, "Pins Title", &note)?;
    N_TITLE_RESERVATION.put(vault, txn, &"pins-bad-key".to_owned(), &note)?;
    N_TITLE_BY_NOTE.put(vault, txn, &HexId(id(0x2b)?), &b"bad".to_vec())?;
    Ok(())
}

/// A head with its document slot's snapshot and update, a citation
/// floor, a settled and a pending fork with their snapshots, a pin, a
/// purge receipt, a receipt, and a two-member proposal bundle.
pub(super) fn seed_entity_doc(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    let at = 1_700_000_000_013;
    let entity = id(0x30)?;
    let actor = id(0x32)?;
    let writer = WriteActor::new(actor, EdgeActorClass::Human);
    let stamp = ActorStamp {
        token: id(0x33)?,
        class: EdgeActorClass::Human,
    };
    let (snapshot, updates, frontier) = EntityDoc::pins_doc_rows(
        &entity,
        "pins entity text",
        "pins append ",
        writer,
        stamp,
        7,
        at,
    )?;
    let incarnation = id(0x3f)?.to_hex();
    put_pins_head_in_txn(
        &vault.store,
        txn,
        &entity,
        &PinsEntityDocHead {
            incarnation: incarnation.clone(),
            document: entity.to_hex(),
            field: TextField::Utf8Body,
            generation: 2,
            pending: 1,
            birth_frontier: None,
        },
    )?;
    ED_SNAPSHOT.put(vault, txn, &DocumentSlot::of(entity), &snapshot)?;
    ED_UPDATE.put(
        vault,
        txn,
        &DocumentUpdateKey {
            slot: DocumentSlot::of(entity),
            seq: UpdateSeq::Generation(2),
        },
        &updates,
    )?;
    let mut qualified = incarnation.into_bytes();
    qualified.extend_from_slice(&frontier);
    put_pins_citation_floor_in_txn(
        &vault.store,
        txn,
        &entity,
        &id(0x3a)?,
        vec![qualified],
        false,
    )?;
    let record =
        |fork: EntityId, proposal: EntityId, on: EntityId, status: ForkStatus| ForkRecord {
            fork: fork.to_hex(),
            proposal: proposal.to_hex(),
            entity: on.to_hex(),
            parent_document: on.to_hex(),
            base: frontier.clone(),
            actor: DocActor::Actor(actor),
            opened_at: at,
            rewrite: false,
            status,
            read_refs: Vec::new(),
            keep: None,
            delta_receipt: None,
        };
    ED_FORK.put(
        vault,
        txn,
        &id(0x34)?.to_hex(),
        &record(id(0x34)?, id(0x35)?, entity, ForkStatus::Merged),
    )?;
    put_pins_fork_snapshot_in_txn(&vault.store, txn, &id(0x34)?.to_hex(), &snapshot, &frontier)?;
    ED_FORK.put(
        vault,
        txn,
        &id(0x36)?.to_hex(),
        &record(id(0x36)?, id(0x35)?, entity, ForkStatus::Pending),
    )?;
    put_pins_fork_snapshot_in_txn(&vault.store, txn, &id(0x36)?.to_hex(), &snapshot, &frontier)?;
    put_pins_citation_pin_in_txn(
        &vault.store,
        txn,
        &entity,
        &id(0x37)?,
        &PinsCitationPin {
            document: entity.to_hex(),
            frontier: frontier.clone(),
            start: b"pins-start".to_vec(),
            end: b"pins-end".to_vec(),
            quote: "pins quote".to_owned(),
            hash: [0x71; 32],
            actor: DocActor::Actor(actor),
        },
    )?;
    ED_PURGE.put(
        vault,
        txn,
        &HexPair(HexId(entity), HexId(id(0x3d)?)),
        &PurgeReceipt {
            receipt: id(0x3d)?.to_hex(),
            entity: entity.to_hex(),
            document: entity.to_hex(),
            actor: DocActor::Actor(actor),
            requested: frontier.clone(),
            applied: frontier.clone(),
            at,
            live_text_hash: [0x74; 32],
        },
    )?;
    ED_RECEIPT.put(
        vault,
        txn,
        &HexPair(HexId(entity), HexId(id(0x38)?)),
        &TextReceipt {
            receipt: id(0x38)?.to_hex(),
            proposal: id(0x35)?.to_hex(),
            fork: id(0x34)?.to_hex(),
            entity: entity.to_hex(),
            actor: DocActor::Actor(actor),
            verb: SettleVerb::Merge,
            at,
            before: frontier.clone(),
            after: frontier.clone(),
            read_refs: Vec::new(),
        },
    )?;
    ED_BUNDLE.put(
        vault,
        txn,
        &id(0x39)?.to_hex(),
        &ProposalBundle {
            proposal: id(0x39)?.to_hex(),
            author: DocActor::Actor(actor),
            forks: vec![
                record(id(0x3b)?, id(0x39)?, entity, ForkStatus::Pending),
                record(id(0x3c)?, id(0x39)?, id(0x31)?, ForkStatus::Merged),
            ],
            settled: false,
            opener_lineage: Vec::new(),
        },
    )?;
    Ok(())
}

/// A revision state, document, frontier, identity and timeline row of one
/// entity, its refill marker and staged index and phonetic rows, an
/// unclassified document, and a carrier's actor-keyed rows.
pub(super) fn seed_entity_revision(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    let at = 1_700_000_000_014;
    let entity = id(0x40)?;
    let core = encode_note_core(&NoteCore {
        kind: NoteKind::OpinionTake,
        author_ref: NoteActor::Erased,
        source_revision_ref: [0x40; 16],
    })?;
    let raw = entity_row(ENTITY_TYPE_NOTE, &core);
    let (snapshot, frontiers) = pins_revision_doc_bytes(7, &[raw], at as i64)?;
    let revision = pins_revision_reference(&entity, &frontiers);
    put_pins_entity_revision_state_in_txn(
        &vault.store,
        txn,
        &entity,
        revision,
        revision,
        at,
        true,
    )?;
    put_pins_entity_revision_doc_in_txn(&vault.store, txn, &entity, &snapshot)?;
    put_pins_entity_revision_frontier_in_txn(
        &vault.store,
        txn,
        &entity,
        revision,
        &pins_frontier_document_value(&frontiers),
    )?;
    ER_IDENTITY.put(vault, txn, &revision, &entity)?;
    ER_TIMELINE.put(vault, txn, &(entity, 1), &revision)?;
    ER_REFILL.put(vault, txn, &entity, &())?;
    put_pins_pending_index_in_txn(
        &vault.store,
        txn,
        &entity,
        revision,
        Some(vec![("title".to_owned(), "pins".to_owned())]),
        Some(vec![0.5]),
    )?;
    put_pins_pending_phonetic_in_txn(
        &vault.store,
        txn,
        &entity,
        revision,
        vec!["pins".to_owned()],
    )?;
    ER_DOC.put(vault, txn, &id(0x41)?, &vec![0xd0; 32])?;
    let carrier = id(0x42)?;
    let carried = identity_row(pins_author_attribution_action(
        carrier,
        [0x42; 32],
        WriteActor::new(id(0x43)?, EdgeActorClass::Human),
    ))?;
    put_entity_row_bytes_in_txn(&vault.store, txn, carrier.as_bytes(), &carried)?;
    let held = [0x44; 16];
    put_pins_entity_revision_state_in_txn(&vault.store, txn, &carrier, held, held, at, false)?;
    put_pins_entity_revision_frontier_in_txn(
        &vault.store,
        txn,
        &carrier,
        held,
        &pins_frontier_document_value(&frontiers),
    )?;
    ER_IDENTITY.put(vault, txn, &held, &carrier)?;
    ER_TIMELINE.put(vault, txn, &(carrier, 2), &held)?;
    Ok(())
}
