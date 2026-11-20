//! The fixture table of the checkpoint pins door: every key and every value
//! the door asks each window root about, family by family. Every id, byte and
//! Loro peer is fixed, as the parent module says. Compiled only under
//! `--cfg oneiron_test_support`; never API.

use std::collections::{BTreeMap, BTreeSet};

use loro::cursor::Side;
use loro::{LoroDoc, VersionVector};
use oneiron_contracts::affect::Vad;
use serde::Serialize;

use super::{
    ACTOR, AGENT, FIXED_AT, MESSAGE, OTHER, QUOTE_PEER, ROOM, ROW, Table, WRITER_PROOF_LEN,
    add_parts, fixed, json, msgpack, refused, row_bytes,
};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    encode_claim_body,
};
use crate::compaction::EpochScope;
use crate::deletion::window_document_format::FORMAT_KEY;
use crate::deletion::{WithdrawnCutoff, WithdrawnReplacement};
use crate::edge::{EdgeActorClass, EdgeKind, encode_edge_value};
use crate::entity_doc::{CarriedDocument, CitationPin, DocActor, TextAnchor};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::Scope;
use crate::federation::record_scope::origin_positions::{OriginPosition, OriginRow};
use crate::identity_topology::{
    StoredIdentityOpAction, StoredIdentityOpEvent, encode_identity_topology_event_body,
};
use crate::model_step_record::DREAMER_STEP_PREDICATE;
use crate::note::{NoteActor, NoteFork, NoteLandingReceipt, NoteReviewBundle, NoteVerdict};
use crate::office_body::{OfficeBodyProposal, ProposalHeader};
use crate::origin::change_index::ORIGIN_CHANGE_PREDICATE;
use crate::origin::{REPO_MANIFEST_VERSION, RepoManifest, RepoPortableId};
use crate::recovery::{CanonicalHead, CanonicalHeadMove};
use crate::registry::{
    ENTITY_TYPE_ASSET, ENTITY_TYPE_CLAIM, ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT, ENTITY_TYPE_NOTE,
    ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN,
};
use crate::room_codec::document_pins::{PartedPin, carrier_key};
use crate::source_audience::carried::{
    self, encode_binding, encode_policy, encode_withheld, record_key,
};
use crate::source_audience::{SourceAudienceKind, SourceAudiencePolicy};
use crate::store::note_body::{NoteCore, NoteKind, encode_note_core};
use crate::store::row_birth::RowBirth;
use crate::sync::bridge::format_edge_key;
use crate::sync::carrier_parts::{Parts, part_key};
use crate::sync::room_parts::generic_manifest_bytes;
use crate::sync::selector::HELD_EDIT_CAUSALITY_KEY;
use crate::sync::withdrawn_cutoffs::epoch_floor_key;
use crate::typed_body::{BodyActor, CarriedFork, ForkSnapshot, TypedBodyFork, TypedForkState};
use crate::workspace_roster::{RoomClaimReceipt, RoomSideRow, RoomTurn};
use crate::write_envelope::WriteActor;
use crate::write_envelope::provenance::made_by::{MadeBy, MadeByClass, MadeByProcess};

/// Every key and value, family by family.
pub(super) fn build_table() -> Result<Table> {
    let mut table = Table::default();
    add_plain(&mut table);
    add_entities(&mut table)?;
    add_edges(&mut table)?;
    add_birth_and_position(&mut table)?;
    add_cutoffs(&mut table);
    add_notes(&mut table)?;
    add_room_rows(&mut table)?;
    add_pins(&mut table)?;
    add_message_documents(&mut table)?;
    add_office_proposal(&mut table)?;
    add_typed_body_rows(&mut table)?;
    add_repo_head(&mut table)?;
    add_turn_programs(&mut table)?;
    add_source_audiences(&mut table)?;
    add_custody_keys(&mut table);
    Ok(table)
}

/// The keys and values no family owns: an id in its spelling, a part key,
/// bytes of the lengths some maps read, and an empty and a one-byte value. The
/// 16 zero bytes are a valid epoch floor and a valid retained claim world; the
/// 32 zero bytes a valid peer origin digest; the 112 a valid writer proof.
fn add_plain(table: &mut Table) {
    table.key("id", fixed(ROW).to_hex());
    table.key("id_upper", fixed(ROW).to_hex().to_uppercase());
    table.key("id_other", fixed(OTHER).to_hex());
    table.key("id_short", "11".repeat(15));
    // A well-formed part key over a fixed digest: the dispatch reads its
    // spelling, never its digest.
    table.key("part_fixed", part_key(&[0x5a; 32]));
    table.key("part_x", "part/x");
    table.key("part_empty", "part/");
    table.key("held_edit_causality", HELD_EDIT_CAUSALITY_KEY);
    table.key("empty_key", "");
    table.key("x_key", "x");
    table.value("empty_value", b"");
    table.value("x_value", b"x");
    table.value("zero16", [0_u8; 16]);
    table.value("zero32", [0_u8; 32]);
    table.value("zero112", [0_u8; WRITER_PROOF_LEN]);
}

/// A CLAIM entity row of `predicate` about the fixed row.
fn claim_row(predicate: &str) -> Result<Vec<u8>> {
    let body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(fixed(ROW)),
        rmpv::Value::from("pins"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    Ok(row_bytes(ENTITY_TYPE_CLAIM, &encode_claim_body(&body)?))
}

/// A NOTE entity row whose core names `author`.
fn note_row(author: NoteActor) -> Result<Vec<u8>> {
    let core = NoteCore {
        kind: NoteKind::OpinionTake,
        author_ref: author,
        source_revision_ref: [ROW; 16],
    };
    Ok(row_bytes(ENTITY_TYPE_NOTE, &encode_note_core(&core)?))
}

/// An identity-topology author carrier: it attributes the fixed actor.
fn author_carrier_row() -> Result<Vec<u8>> {
    let event = StoredIdentityOpEvent {
        seq: 1,
        validated_at_write: false,
        invalidated: false,
        at: FIXED_AT,
        actor: None,
        source: ClaimSource::UserStated,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: StoredIdentityOpAction::AuthorAttribution {
            target: fixed(OTHER),
            core_digest: [0x0c; 32],
            actor: WriteActor::new(fixed(ACTOR), EdgeActorClass::Human),
        },
    };
    Ok(row_bytes(
        ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
        &encode_identity_topology_event_body(&event)?,
    ))
}

/// The `entities` rows: one of each kind the owners above tell apart, a CLAIM
/// of each predicate family, a NOTE of each author, and an author carrier.
fn add_entities(table: &mut Table) -> Result<()> {
    table.value("row_person", row_bytes(ENTITY_TYPE_PERSON, b"pins-person"));
    table.value("row_asset", row_bytes(ENTITY_TYPE_ASSET, b"pins-asset"));
    table.value("row_turn", row_bytes(ENTITY_TYPE_TURN, b"pins-turn"));
    table.value("row_claim", claim_row("pins.pred")?);
    table.value("row_claim_dreamer", claim_row(DREAMER_STEP_PREDICATE)?);
    table.value("row_claim_origin", claim_row(ORIGIN_CHANGE_PREDICATE)?);
    table.value("row_note_shell", row_bytes(ENTITY_TYPE_NOTE, b""));
    table.value("row_note_erased", note_row(NoteActor::Erased)?);
    table.value(
        "row_note_authored",
        note_row(NoteActor::Actor(fixed(ACTOR)))?,
    );
    table.value("row_author_carrier", author_carrier_row()?);
    Ok(())
}

/// An `authored_by` edge and a plain edge, each under its key and as its
/// value.
fn add_edges(table: &mut Table) -> Result<()> {
    let source = fixed(ROW);
    table.key(
        "edge_authored_by",
        format_edge_key(&source, EdgeKind::AuthoredBy, &fixed(ACTOR)),
    );
    table.key(
        "edge_mentions",
        format_edge_key(&source, EdgeKind::Mentions, &fixed(OTHER)),
    );
    for (label, kind) in [
        ("edge_authored_by_value", EdgeKind::AuthoredBy),
        ("edge_mentions_value", EdgeKind::Mentions),
    ] {
        table.value(
            label,
            encode_edge_value(kind, 0.9, FIXED_AT, Vad::NEUTRAL, None)?,
        );
    }
    Ok(())
}

/// A row birth of the fixed row, and an origin position of it.
fn add_birth_and_position(table: &mut Table) -> Result<()> {
    let made_by = MadeBy {
        inputs: Vec::new(),
        process: MadeByProcess {
            actor: fixed(ACTOR),
            class: MadeByClass::Stated,
            identity: "pins".to_owned(),
            version: "1".to_owned(),
            params_hash: "0".repeat(64),
        },
        at: FIXED_AT,
        trigger: None,
    };
    table.value("row_birth", msgpack(&RowBirth::stated(made_by))?);
    let position = OriginPosition {
        row: OriginRow {
            id: fixed(ROW),
            kind: ENTITY_TYPE_ASSET,
            facet: fixed(OTHER),
            logical_digest: [0x0a; 32],
            birth_digest: None,
            file_reference: None,
        },
        scope: Scope::top(),
        sources: Vec::new(),
    };
    table.value("origin_position", position.encode()?);
    Ok(())
}

/// The epoch floor keys of a session and of a conversation, and a floor key no
/// scope reads; a withdrawn generation's cutoff (its key is the id).
fn add_cutoffs(table: &mut Table) {
    let session = fixed(0x61);
    table.key(
        "epoch_floor_session",
        epoch_floor_key(&EpochScope::of_session(session)),
    );
    table.key(
        "epoch_floor_conversation",
        epoch_floor_key(&EpochScope {
            session,
            conversation: Some(fixed(0x62)),
        }),
    );
    table.key("epoch_floor_x", "epoch_floor/x");
    let cutoff = WithdrawnCutoff {
        generation: 1,
        replacement: WithdrawnReplacement::Shell,
    };
    table.value("cutoff9", cutoff.encode());
}

/// A review bundle as a window carries it (`sync::note`'s private shape).
#[derive(Serialize)]
struct BundleCarrier<'a> {
    bundle: &'a NoteReviewBundle,
    complete: bool,
}

/// A NOTE fork of the fixed row's NOTE, opened by `actor`.
fn note_fork(actor: NoteActor) -> NoteFork {
    NoteFork {
        note: fixed(OTHER),
        fork: fixed(ROW),
        parent: fixed(0x13),
        frontier: vec![1, 2, 3],
        recovery_merge: None,
        actor,
        rewrite: false,
        proposal: None,
        decided: false,
    }
}

/// The five NOTE maps' rows: a proposal document and its format marker, a head,
/// a landing receipt, a fork of each opener and a review bundle.
fn add_notes(table: &mut Table) -> Result<()> {
    table.key(
        "note_doc",
        format!(
            "note_proposal_doc:v1:{}:{}",
            fixed(ROW).to_hex(),
            fixed(OTHER).to_hex()
        ),
    );
    table.key("note_format", FORMAT_KEY);
    table.value("note_doc_text", msgpack(&String::from("pins"))?);
    table.value("note_format_value", b"proposal-values-v3");
    let head = CanonicalHead {
        entity_id: *fixed(ROW).as_bytes(),
        head: *fixed(0x15).as_bytes(),
    };
    table.value("note_head", msgpack(&head)?);
    let receipt = NoteLandingReceipt {
        id: fixed(ROW),
        note: fixed(OTHER),
        fork: fixed(0x13),
        previous_head: fixed(0x14),
        head: fixed(0x15),
        verdict: NoteVerdict::Merge,
        actor: NoteActor::Actor(fixed(ACTOR)),
        at: 1,
    };
    let moved = CanonicalHeadMove {
        id: *fixed(ROW).as_bytes(),
        entity_id: *fixed(OTHER).as_bytes(),
        receipt: msgpack(&receipt)?,
    };
    table.value("note_receipt", msgpack(&moved)?);
    table.value(
        "note_fork_authored",
        msgpack(&note_fork(NoteActor::Actor(fixed(ACTOR))))?,
    );
    table.value("note_fork_erased", msgpack(&note_fork(NoteActor::Erased))?);
    let bundle = NoteReviewBundle {
        id: fixed(ROW),
        waiting: vec![note_fork(NoteActor::Actor(fixed(ACTOR)))],
        landed: vec![receipt],
        explainer: "pins".to_owned(),
    };
    let carrier = BundleCarrier {
        bundle: &bundle,
        complete: true,
    };
    table.value("note_bundle", msgpack(&carrier)?);
    Ok(())
}

/// A turn row of the fixed row, naming an actor, an agent and a message.
fn turn_row() -> RoomTurn {
    RoomTurn {
        turn_id: fixed(ROW).to_hex(),
        room_id: fixed(ROOM).to_hex(),
        actor: fixed(ACTOR).to_hex(),
        addressed_agents: BTreeSet::from([fixed(AGENT).to_hex()]),
        message_ids: vec![fixed(MESSAGE).to_hex()],
        reply_to: None,
        thread_of: None,
        at: 1,
        task_ids: Vec::new(),
        converted_project: None,
        quotes: BTreeMap::new(),
    }
}

/// A claim of the turn `turn`, riding with it.
fn side_claim(turn: u8) -> RoomSideRow {
    RoomSideRow::Claim {
        claim: RoomClaimReceipt {
            room_id: fixed(ROOM).to_hex(),
            turn_id: fixed(turn).to_hex(),
            actor: fixed(ACTOR).to_hex(),
            receipt_ref: "receipt".to_owned(),
            at: 1,
        },
    }
}

/// The room turn map's row whole, as a manifest and as a part; the room side
/// map's claim of two turns, whole, and the first as a manifest and as a part.
fn add_room_rows(table: &mut Table) -> Result<()> {
    let turn = json(&turn_row())?;
    let parts = add_parts(table, "turn_part", &turn)?;
    table.value("turn_whole", turn);
    table.value("turn_manifest", generic_manifest_bytes(&parts)?);
    let claim = side_claim(ROW);
    let fact = json(&claim)?;
    table.key(
        "fact_claim",
        crate::sync::room_facts::carrier_key(&claim, &fact),
    );
    let other = side_claim(OTHER);
    let other_fact = json(&other)?;
    table.key(
        "fact_claim_other",
        crate::sync::room_facts::carrier_key(&other, &other_fact),
    );
    let parts = add_parts(table, "fact_part", &fact)?;
    table.value("fact_whole", fact);
    table.value("fact_manifest", generic_manifest_bytes(&parts)?);
    Ok(())
}

/// The text a pin quotes, written once at a fixed Loro peer: every pin the door
/// builds shares its frontier and cursors.
struct Quoted {
    frontier: Vec<u8>,
    start: Vec<u8>,
    end: Vec<u8>,
}

fn quoted() -> Result<Quoted> {
    let text = LoroDoc::new();
    text.set_peer_id(QUOTE_PEER)
        .map_err(|_| refused("a quoted text peer that does not set"))?;
    let body = text.get_text("body");
    body.insert(0, "quoted")
        .map_err(|_| refused("a quoted text that does not write"))?;
    text.commit();
    let cursor = |at: usize, side: Side| {
        body.get_cursor(at, side)
            .map(|cursor| cursor.encode())
            .ok_or_else(|| refused("a quote cursor"))
    };
    Ok(Quoted {
        frontier: text.oplog_frontiers().encode(),
        start: cursor(0, Side::Right)?,
        end: cursor(1, Side::Left)?,
    })
}

/// A whole pin of the quoted message by `citation`, naming `actor`.
fn pin(citation: EntityId, actor: DocActor, quoted: &Quoted) -> Result<CitationPin> {
    let quote = "q".repeat(64);
    let message = fixed(MESSAGE).to_hex();
    let pin: CitationPin = serde_json::from_value(serde_json::json!({
        "citation": citation.to_hex(),
        "entity": message,
        "document": fixed(0x44).to_hex(),
        "anchor": {
            "entity": message,
            "frontier": quoted.frontier,
            "start": quoted.start,
            "end": quoted.end,
            "hash": TextAnchor::quote_hash(&quote),
            "quote": quote,
        },
        "actor": serde_json::to_value(actor)
            .map_err(|_| refused("an actor that does not encode"))?,
    }))
    .map_err(|error| refused(&format!("a pin that does not decode: {error}")))?;
    if pin.carried_ids().is_none() {
        return Err(refused("a pin that is not whole"));
    }
    Ok(pin)
}

/// The pin map's rows: a whole pin naming an actor and one naming no one, each
/// under its own key, and the first in parts (a manifest naming its actor, and
/// the part naming no one).
fn add_pins(table: &mut Table) -> Result<()> {
    let text = quoted()?;
    let message = fixed(MESSAGE);
    let own = pin(fixed(ROW), DocActor::Actor(fixed(ACTOR)), &text)?;
    table.key("pin", carrier_key(message, fixed(ROW), &own)?);
    let other = pin(fixed(OTHER), DocActor::Erased, &text)?;
    table.key("pin_other", carrier_key(message, fixed(OTHER), &other)?);
    table.value("pin_whole_authored", msgpack(&own)?);
    table.value("pin_whole_erased", msgpack(&other)?);
    let parts = add_parts(table, "pin_part", &msgpack(&own.actor_erased())?)?;
    let manifest = PartedPin {
        parts,
        actor: DocActor::Actor(fixed(ACTOR)),
    };
    table.value("pin_manifest", msgpack(&manifest)?);
    Ok(())
}

/// A message document's head as a window carries it (`sync::message_docs`'
/// private shape).
#[derive(Serialize)]
struct MessageHead<'a> {
    head: &'a CarriedDocument,
    snapshot: &'a Parts,
}

/// A message document's head under the fixed message, its snapshot one part.
fn add_message_documents(table: &mut Table) -> Result<()> {
    let snapshot = add_parts(table, "message_part", b"checkpoint-pins-snapshot")?;
    let head = CarriedDocument {
        entity: fixed(ROW).to_hex(),
        document: fixed(OTHER).to_hex(),
        incarnation: fixed(0x13).to_hex(),
        version: VersionVector::new().encode(),
        shallow: Vec::new(),
        switched: None,
        succeeds: None,
    };
    let head_row = MessageHead {
        head: &head,
        snapshot: &snapshot,
    };
    table.value("message_head", msgpack(&head_row)?);
    Ok(())
}

/// An office proposal of the artifact the fixed row names, with no member.
fn add_office_proposal(table: &mut Table) -> Result<()> {
    let proposal = OfficeBodyProposal {
        header: ProposalHeader {
            proposal: fixed(OTHER),
            artifact: fixed(ROW),
            opener: BodyActor::Erased,
            run_root: None,
            opened_at: 1,
        },
        members: Vec::new(),
        settlement: None,
        asks: Vec::new(),
        ask_refused: Vec::new(),
    };
    table.key(
        "office_proposal",
        format!("{}/{}", fixed(ROW).to_hex(), fixed(OTHER).to_hex()),
    );
    table.value("office_proposal_value", msgpack(&proposal)?);
    Ok(())
}

/// An erased commit receipt as a window carries it (`typed_body`'s private
/// shape, its receipt field a tagged state).
#[derive(Serialize)]
struct ErasedReceiptRow {
    entity: EntityId,
    peer: u64,
    birth: Vec<u8>,
    receipt: ErasedReceiptState,
}

/// The state an erased receipt is tagged with.
#[derive(Serialize)]
struct ErasedReceiptState {
    state: &'static str,
    at: u64,
}

/// A typed body fork of the fixed body, opened by `opener` and `state`.
fn body_fork(opener: BodyActor, state: TypedForkState) -> TypedBodyFork {
    TypedBodyFork {
        entity: fixed(ROW),
        fork: fixed(OTHER),
        opener,
        base: vec![0xb1; 8],
        commits: 1,
        opened_at: 1,
        state,
        version: vec![0x61; 4],
    }
}

/// A fork of the fixed body as a window carries it.
fn carried_fork(record: TypedBodyFork, snapshot: Option<ForkSnapshot>) -> CarriedFork {
    CarriedFork {
        entity: fixed(ROW),
        fork: fixed(OTHER),
        birth: vec![0xb0; 8],
        record,
        companion: Vec::new(),
        snapshot,
    }
}

/// The typed body map's rows: an erased commit receipt, and forks (open with
/// its snapshot in parts, open with it whole, discarded, open and naming its
/// opener).
fn add_typed_body_rows(table: &mut Table) -> Result<()> {
    let body = fixed(ROW);
    table.key(
        "typed_receipt",
        format!("r/{}/{:016x}", body.to_hex(), 7_u64),
    );
    table.key(
        "typed_fork",
        format!("f/{}/{}", body.to_hex(), fixed(OTHER).to_hex()),
    );
    let receipt = ErasedReceiptRow {
        entity: body,
        peer: 7,
        birth: vec![0xb0; 8],
        receipt: ErasedReceiptState {
            state: "erased",
            at: 1,
        },
    };
    table.value("typed_receipt_erased", msgpack(&receipt)?);
    let parts = add_parts(table, "typed_fork_part", &[0xd2; 32])?;
    let open = || body_fork(BodyActor::Erased, TypedForkState::Open);
    table.value(
        "typed_fork_open_parts",
        msgpack(&carried_fork(open(), Some(ForkSnapshot::Parts(parts))))?,
    );
    table.value(
        "typed_fork_open_whole",
        msgpack(&carried_fork(
            open(),
            Some(ForkSnapshot::Whole(vec![0xd1; 32])),
        ))?,
    );
    let discarded = body_fork(
        BodyActor::Erased,
        TypedForkState::Discarded {
            by: BodyActor::Erased,
            at: 1,
        },
    );
    table.value(
        "typed_fork_discarded",
        msgpack(&carried_fork(discarded, None))?,
    );
    let named_opener = body_fork(BodyActor::Actor(fixed(ACTOR)), TypedForkState::Open);
    table.value(
        "typed_fork_opener_named",
        msgpack(&carried_fork(
            named_opener,
            Some(ForkSnapshot::Whole(vec![0xd1; 32])),
        ))?,
    );
    Ok(())
}

/// A repo head as a window carries it (`sync::repo_manifests`' private shape).
#[derive(Serialize)]
struct RepoHead<'a> {
    code: EntityId,
    body: &'a Parts,
}

/// A repo head of the fixed CODE entity under its portable id, its manifest
/// one part; a second portable id, the key another repo's head is filed under.
fn add_repo_head(table: &mut Table) -> Result<()> {
    let portable = RepoPortableId::from_hex(&"07".repeat(32))
        .ok_or_else(|| refused("a portable id that does not parse"))?;
    table.key("repo_portable", portable.to_hex());
    table.key("repo_portable_other", "08".repeat(32));
    let manifest = RepoManifest {
        portable,
        version: REPO_MANIFEST_VERSION,
        code: fixed(ROW),
        minted_at: 1,
        origin_name: None,
        visible_refs: Vec::new(),
        lfs_pointers: Vec::new(),
        epoch: 0,
        updated_at: 1,
        writer: None,
    }
    .encode()?;
    let parts = add_parts(table, "repo_part", &manifest)?;
    let head = RepoHead {
        code: fixed(ROW),
        body: &parts,
    };
    table.value("repo_head", msgpack(&head)?);
    Ok(())
}

/// A disarmed arming row filed under its registration's key, and an admitted
/// wake row filed under its turn and its registration (the wake key is the
/// turn's hex then the registration's).
fn add_turn_programs(table: &mut Table) -> Result<()> {
    let id =
        |id: EntityId| serde_json::to_value(id).map_err(|_| refused("an id that does not encode"));
    table.key(
        "wake",
        format!("{}{}", fixed(ROW).to_hex(), fixed(OTHER).to_hex()),
    );
    let arming = serde_json::json!({
        "disarmed": {
            "actor": id(fixed(ACTOR))?,
            "registration": id(fixed(ROW))?,
            "at": 1,
        },
    });
    table.value("arming_disarmed", json(&arming)?);
    let admission = [0_u8; 32];
    let wake = serde_json::json!({
        "admitted": {
            "turn": id(fixed(ROW))?,
            "registration": id(fixed(OTHER))?,
            "admission": admission,
        },
    });
    table.value("wake_admitted", json(&wake)?);
    Ok(())
}

/// A source audience binding, the two withholding markers (the machine that
/// withheld the row named, and not) and a policy revision, under their keys.
fn add_source_audiences(table: &mut Table) -> Result<()> {
    table.key("audience_record", record_key(&fixed(ROW)));
    table.key("audience_withheld", carried::withheld_key(&fixed(ROW)));
    table.key("audience_policy", carried::policy_key(&fixed(OTHER), 1));
    table.value("audience_binding", encode_binding(&fixed(OTHER))?);
    table.value("audience_withheld_none", encode_withheld(None)?);
    table.value(
        "audience_withheld_by",
        encode_withheld(Some(&fixed(ACTOR)))?,
    );
    let policy = SourceAudiencePolicy {
        kind: SourceAudienceKind::Source {
            readers: BTreeSet::from([fixed(ACTOR)]),
            open: false,
        },
        created_by: Some(fixed(ACTOR)),
        created_at: 1,
        revision: 1,
    };
    table.value("audience_policy_value", encode_policy(&policy)?);
    Ok(())
}

/// The custody map's key spellings: a protected input's, a witness part's, a
/// sealed export output's digest key, and a transition's piece key. No value is
/// valid without a vault: a custody transition, a relayed input, a witness part
/// and an export output are minted by the secret custody client.
fn add_custody_keys(table: &mut Table) {
    let digest = "11".repeat(32);
    table.key("custody_input", format!("input:{digest}"));
    table.key("custody_witness", format!("witness:{digest}"));
    table.key("custody_export_output", format!("export_output:{digest}"));
    table.key("custody_piece", format!("{}.00000000", fixed(ROW).to_hex()));
}
