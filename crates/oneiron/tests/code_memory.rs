//! ARCH-0050 R6 L2 memory-over-code attachment mechanics — public contract
//! suite (ONE-1608).
//!
//! Every test here reaches ONLY `Vault`. Nothing in this file names `Store`,
//! a heed transaction, or a raw metadata key: if a rule cannot be observed
//! through the public door, it is not a public contract. Codec, key, pure
//! merge-algebra, and crate-seam side-effect coverage lives in
//! `src/code_memory.rs`'s in-module block instead.

use oneiron::claim::ScopedReadActorKey;
use oneiron::code_memory::{
    AlwaysOnCodeMemoryContract, AnchorTransfer, AnchorTransferKind, AttachCodeMemory,
    BlocksWriteContext, CODE_MEMORY_MAX_ALWAYS_ON_CONTRACTS, CODE_MEMORY_MAX_VALUES_PER_SLOT,
    CODE_MEMORY_PPR_DEPTH, CodeMemoryAnchor, CodeMemoryContractKind, CodeMemoryLocator,
    CodeMemoryPayloadRef, CodeMemoryPullRequest, CodeMemoryPullResult, CodeMemoryRevision,
    CodeMemorySlotName, CodeMemorySlotValue, ProvenanceMaterialKind, SlotInsertOutcome,
};
use oneiron::deletion::DeleteReason;
use oneiron::note::TakeTarget;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EdgeKind, EntityId, Error, TimeRange, Vault, VaultConfig, WriteActor,
};
use rmpv::Value;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const ENTITY_TYPE_CODE_SYMBOL: u8 = 104;
const ENTITY_TYPE_PERSON: u8 = 4;
const ENTITY_TYPE_MACHINE: u8 = 102;

/// The fixture's NOTE author, and the subject its takes are about. Both are
/// ordinary PERSONs: `put_entity` still admits every non-NOTE type.
const NOTE_AUTHOR: u8 = 0x11;
const NOTE_SUBJECT: u8 = 0x12;

fn vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    (dir, vault)
}

fn id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("valid entity id")
}

fn range(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

fn seed(vault: &Vault, byte: u8, entity_type: u8) -> EntityId {
    let entity = id(byte);
    vault
        .put_entity(
            &entity,
            entity_type,
            range(1_780_000_000),
            1_780_000_000,
            b"x",
        )
        .expect("seed entity");
    entity
}

fn symbol(vault: &Vault, byte: u8) -> EntityId {
    seed(vault, byte, ENTITY_TYPE_CODE_SYMBOL)
}

/// Mints ONE fresh NOTE through `Memory::author_take` — since ARCH-0032
/// landed, that is the only door that writes a NOTE body at all, because the
/// raw `put_entity` used by [`seed`] refuses `ENTITY_TYPE_NOTE` outright.
///
/// The door stamps the author itself and mints an internal `EntityId::now()`,
/// so a caller can choose neither: the receipt's id is the only handle, and
/// every call therefore yields a DISTINCT note. That is what the multi-note
/// tests below rely on now that fixed `[byte; 16]` note ids are unreachable.
///
/// The take is deliberately about an off-graph PERSON rather than a symbol
/// under test. `author_take` mints a real `About` edge alongside the NOTE, and
/// pointing it at a `CODE_SYMBOL` would inject a traversable path into the PPR
/// fixtures below; a note that hangs off nothing under test keeps every
/// relevance assertion measuring what it names.
fn note_entity(vault: &Vault) -> EntityId {
    let author = seed(vault, NOTE_AUTHOR, ENTITY_TYPE_PERSON);
    let subject = seed(vault, NOTE_SUBJECT, ENTITY_TYPE_PERSON);
    let receipt = vault
        .memory(author, EdgeActorClass::Human)
        .author_take(TakeTarget::Subject(subject), "fixture take")
        .expect("mint a NOTE through the author_take door");
    EntityId::from_hex(&receipt.id_hex).expect("receipt carries a 32-hex id")
}

fn note(vault: &Vault) -> CodeMemoryPayloadRef {
    CodeMemoryPayloadRef::NoteEntity(note_entity(vault))
}

/// A real type-0 CLAIM written through the public claim door, so the
/// CLAIM-specific `ScopedRead` clamp sees a body it can actually decode.
fn claim(vault: &Vault, byte: u8, subject: EntityId) -> EntityId {
    let claim_id = id(byte);
    let body = ClaimBody::new(
        "code.memory.contract_note",
        ClaimSubject::Entity(subject),
        Value::from("opaque L2 payload"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    vault
        .put_claim(&claim_id, &body, range(1_780_000_000), 1_780_000_000)
        .expect("seed CLAIM through the public door");
    claim_id
}

/// A CLAIM whose entity row is a SOFT-DELETE SHELL: the pinned 25-byte header
/// and no body at all.
///
/// The claim is deleted BEFORE the returned ref is attached anywhere, because
/// deleting a payload sweeps every code-memory row that names it — attaching
/// afterwards is the only way a live slot can point at a shell. Nothing in
/// `attach_code_memory` resolves a payload, by design: NOTE/CLAIM bodies are
/// opaque to L2 in both directions.
fn deleted_shell_claim(vault: &Vault, byte: u8, subject: EntityId) -> CodeMemoryPayloadRef {
    let claim_id = claim(vault, byte, subject);
    assert!(
        vault
            .delete_entity_with_reason(&claim_id, DeleteReason::UserDelete)
            .expect("soft delete")
            .existed,
        "the fixture must actually delete something"
    );
    assert!(
        vault.is_deleted_shell(&claim_id).expect("shell probe"),
        "a user delete keeps the header-only shell this fixture is about"
    );
    CodeMemoryPayloadRef::Claim(claim_id)
}

/// The payloads a pull returned, in the order it returned them.
fn pulled_payloads(pulled: &CodeMemoryPullResult) -> Vec<CodeMemoryPayloadRef> {
    pulled
        .notes
        .iter()
        .map(|labelled| labelled.data.payload)
        .collect()
}

fn slot() -> CodeMemorySlotName {
    CodeMemorySlotName::new("interface.contract").expect("valid slot name")
}

fn other_slot() -> CodeMemorySlotName {
    CodeMemorySlotName::new("policy.contract").expect("valid slot name")
}

fn locator(path: &str) -> CodeMemoryLocator {
    CodeMemoryLocator {
        path_at_revision: path.to_owned(),
        revision: CodeMemoryRevision::Commit("9d561405a81ffbf2".to_owned()),
        validity: range(1_780_000_000),
    }
}

fn anchor(symbol_id: EntityId, path: &str) -> CodeMemoryAnchor {
    CodeMemoryAnchor {
        symbol_id,
        locator: locator(path),
    }
}

fn value(
    payload: CodeMemoryPayloadRef,
    actor: EntityId,
    content: u8,
    recorded_at: u64,
) -> CodeMemorySlotValue {
    CodeMemorySlotValue {
        payload,
        actor_id: actor,
        valid_time: range(recorded_at),
        recorded_at,
        content_hash: [content; 32],
        provenance_claim_id: id(content),
    }
}

fn attach(
    vault: &Vault,
    symbol_id: EntityId,
    path: &str,
    slot_name: CodeMemorySlotName,
    value: CodeMemorySlotValue,
) -> oneiron::Result<SlotInsertOutcome> {
    vault.attach_code_memory(AttachCodeMemory {
        anchor: anchor(symbol_id, path),
        slot: slot_name,
        value,
    })
}

fn contract(
    symbol_id: EntityId,
    slot_name: CodeMemorySlotName,
    payload: CodeMemoryPayloadRef,
    kind: CodeMemoryContractKind,
    actor: EntityId,
) -> AlwaysOnCodeMemoryContract {
    AlwaysOnCodeMemoryContract {
        symbol_id,
        slot: slot_name,
        payload,
        kind,
        actor_id: actor,
        valid_time: range(1_780_000_500),
        recorded_at: 1_780_000_500,
        provenance_claim_id: id(0x5A),
    }
}

fn transfer(
    kind: AnchorTransferKind,
    from: EntityId,
    to: EntityId,
    actor: EntityId,
) -> AnchorTransfer {
    AnchorTransfer {
        kind,
        from_symbol_id: from,
        to_symbol_id: to,
        from_locator: locator("src/before.rs"),
        to_locator: locator("src/after.rs"),
        actor_id: actor,
        observed_at: 1_780_000_900,
        provenance_claim_id: id(0x5B),
    }
}

/// The `path_at_revision` STORED on `symbol_id`'s attachment row for
/// `payload` — the locator half of the dual anchor as it actually persists,
/// read back through the public attachment door.
fn attachment_path(vault: &Vault, symbol_id: EntityId, payload: CodeMemoryPayloadRef) -> String {
    let rows = vault
        .code_memory_attachments(symbol_id)
        .expect("attachment rows");
    let row = rows
        .into_iter()
        .find(|attachment| attachment.payload == payload)
        .expect("the surviving payload keeps an attachment row");
    row.anchor.locator.path_at_revision
}

fn human(vault: &Vault, byte: u8) -> WriteActor {
    WriteActor::new(seed(vault, byte, ENTITY_TYPE_PERSON), EdgeActorClass::Human)
}

fn blocks_context(actor: &WriteActor) -> BlocksWriteContext<'_> {
    BlocksWriteContext {
        actor,
        source: ClaimSource::UserStated,
    }
}

fn reader_key() -> ScopedReadActorKey {
    ScopedReadActorKey::new("code-memory-reader").expect("non-blank actor ref")
}

// ---------------------------------------------------------------------------
// Anchor identity and transfer
// ---------------------------------------------------------------------------

/// The symbol id is the PRIMARY anchor. A note attached to symbol A is
/// readable by A and by nothing else — a second symbol at the same
/// `path_at_revision` owns nothing.
#[test]
fn symbol_id_is_primary_anchor() {
    let (_dir, vault) = vault();
    let first = symbol(&vault, 0x21);
    let second = symbol(&vault, 0x22);
    let actor = id(0x31);
    let payload = note(&vault);

    attach(
        &vault,
        first,
        "src/shared.rs",
        slot(),
        value(payload, actor, 0x51, 1_000),
    )
    .expect("attach to the symbol anchor");

    let attached = vault.code_memory_attachments(first).expect("read A");
    assert_eq!(attached.len(), 1);
    assert_eq!(attached[0].payload, payload);
    assert_eq!(attached[0].anchor.symbol_id, first);
    assert_eq!(attached[0].slot, slot());

    assert!(
        vault
            .code_memory_attachments(second)
            .expect("read B")
            .is_empty(),
        "the SAME path under a different symbol id resolves to nothing"
    );
    assert!(
        vault.code_memory_slots(second).expect("read B").is_empty(),
        "a locator is not identity, so B owns no slot either"
    );
}

/// A stale `path_at_revision` is a LOCATOR. The public surface exposes no
/// path-keyed lookup at all, and re-minting a symbol at the old path captures
/// nothing.
#[test]
fn stale_path_is_not_identity_and_path_reuse_captures_nothing() {
    let (_dir, vault) = vault();
    let original = symbol(&vault, 0x23);
    let payload = note(&vault);
    attach(
        &vault,
        original,
        "src/moved.rs",
        slot(),
        value(payload, id(0x32), 0x52, 1_000),
    )
    .expect("attach");

    // A NEW symbol id minted at the very same path — the "delete and
    // recreate" case — inherits nothing.
    let reused_path = symbol(&vault, 0x24);
    assert!(
        vault
            .code_memory_attachments(reused_path)
            .expect("read")
            .is_empty()
    );
    assert!(
        !vault
            .code_memory_attachments(original)
            .expect("read")
            .is_empty(),
        "the original keeps its attachment"
    );
}

/// Explicit `Rename` re-points slots, attachment rows, AND always-on
/// registrations onto the target and retires the source. The receipt is
/// queryable from BOTH endpoints and never as a raw key.
#[test]
fn rename_transfer_follows_the_symbol() {
    let (_dir, vault) = vault();
    let from = symbol(&vault, 0x25);
    let to = symbol(&vault, 0x26);
    let actor = id(0x33);
    let payload = note(&vault);

    attach(
        &vault,
        from,
        "src/before.rs",
        slot(),
        value(payload, actor, 0x53, 1_000),
    )
    .expect("attach");
    vault
        .register_always_on_contract(contract(
            from,
            slot(),
            payload,
            CodeMemoryContractKind::Interface,
            actor,
        ))
        .expect("register");

    let receipt = vault
        .transfer_code_memory_anchor(&transfer(AnchorTransferKind::Rename, from, to, actor))
        .expect("explicit rename");
    assert_eq!(receipt.moved_attachments, 1);

    let moved = vault.code_memory_slots(to).expect("destination slots");
    assert_eq!(moved.len(), 1);
    assert_eq!(moved[0].values.len(), 1);
    assert_eq!(moved[0].values[0].actor_id, actor);
    assert_eq!(moved[0].values[0].provenance_claim_id, id(0x53));
    assert_eq!(
        vault
            .code_memory_always_on_contracts(to)
            .expect("destination contracts")
            .len(),
        1
    );

    assert!(vault.code_memory_slots(from).expect("source").is_empty());
    assert!(
        vault
            .code_memory_attachments(from)
            .expect("source")
            .is_empty()
    );
    assert!(
        vault
            .code_memory_always_on_contracts(from)
            .expect("source")
            .is_empty(),
        "a rename leaves no ALWAYS_ON row behind"
    );

    for endpoint in [from, to] {
        let records = vault.code_memory_transfers(endpoint).expect("receipts");
        assert_eq!(records.len(), 1, "queryable from both endpoints");
        assert_eq!(records[0].kind, AnchorTransferKind::Rename);
        assert_eq!(records[0].from_symbol_id, from);
        assert_eq!(records[0].to_symbol_id, to);
        assert_eq!(records[0].moved_attachments, 1);
        assert_eq!(records[0].actor_id, actor);
    }
}

/// A byte-identical replay is an idempotent upsert of its own deterministic
/// receipt: one record, unchanged destination.
#[test]
fn replayed_transfer_is_idempotent() {
    let (_dir, vault) = vault();
    let from = symbol(&vault, 0x27);
    let to = symbol(&vault, 0x28);
    let actor = id(0x34);
    attach(
        &vault,
        from,
        "src/before.rs",
        slot(),
        value(note(&vault), actor, 0x54, 1_000),
    )
    .expect("attach");

    let declared = transfer(AnchorTransferKind::Copy, from, to, actor);
    vault
        .transfer_code_memory_anchor(&declared)
        .expect("first apply");
    let after_first = vault.code_memory_slots(to).expect("destination");
    vault
        .transfer_code_memory_anchor(&declared)
        .expect("replay");

    assert_eq!(
        vault.code_memory_transfers(to).expect("receipts").len(),
        1,
        "a byte-identical replay upserts ONE receipt"
    );
    assert_eq!(
        vault.code_memory_slots(to).expect("destination"),
        after_first,
        "destination state is unchanged by the replay"
    );
}

/// `Copy` clones and leaves the source completely intact; a copied symbol
/// receives nothing until the explicit transfer runs.
#[test]
fn copy_does_not_auto_clone() {
    let (_dir, vault) = vault();
    let from = symbol(&vault, 0x29);
    let to = symbol(&vault, 0x2A);
    let actor = id(0x35);
    let payload = note(&vault);

    attach(
        &vault,
        from,
        "src/before.rs",
        slot(),
        value(payload, actor, 0x55, 1_000),
    )
    .expect("attach");
    vault
        .register_always_on_contract(contract(
            from,
            slot(),
            payload,
            CodeMemoryContractKind::Policy,
            actor,
        ))
        .expect("register");

    assert!(
        vault.code_memory_slots(to).expect("copy target").is_empty(),
        "an identical-content copy receives nothing before an explicit transfer"
    );

    vault
        .transfer_code_memory_anchor(&transfer(AnchorTransferKind::Copy, from, to, actor))
        .expect("explicit copy");

    assert_eq!(vault.code_memory_slots(to).expect("target").len(), 1);
    assert_eq!(
        vault
            .code_memory_always_on_contracts(to)
            .expect("target")
            .len(),
        1
    );
    assert_eq!(
        vault.code_memory_slots(from).expect("source").len(),
        1,
        "copy retains the source slot"
    );
    assert_eq!(
        vault
            .code_memory_always_on_contracts(from)
            .expect("source")
            .len(),
        1,
        "copy retains the source always-on row"
    );
}

/// A destination collision resolves through the canonical union, never an
/// overwrite; `moved_attachments` is the SOURCE pre-merge cardinality, so a
/// fully deduped transfer still reports a nonzero count.
#[test]
fn transfer_merges_destination_slot() {
    let (_dir, vault) = vault();
    let from = symbol(&vault, 0x2B);
    let to = symbol(&vault, 0x2C);
    let actor = id(0x36);
    let payload = note(&vault);
    let shared = value(payload, actor, 0x56, 1_000);

    attach(&vault, from, "src/before.rs", slot(), shared.clone()).expect("source attach");
    attach(&vault, to, "src/after.rs", slot(), shared.clone()).expect("destination pre-fill");
    attach(
        &vault,
        to,
        "src/after.rs",
        slot(),
        value(note(&vault), id(0x37), 0x57, 2_000),
    )
    .expect("destination second writer");

    let receipt = vault
        .transfer_code_memory_anchor(&transfer(AnchorTransferKind::Copy, from, to, actor))
        .expect("transfer");
    assert_eq!(
        receipt.moved_attachments, 1,
        "a fully deduped transfer is legal and reports the pre-merge source count"
    );

    let merged = vault.code_memory_slots(to).expect("destination");
    assert_eq!(merged.len(), 1);
    assert_eq!(
        merged[0].values.len(),
        2,
        "union keeps both writers; the colliding value dedupes to one"
    );
    assert!(merged[0].conflict_visible);
    assert!(merged[0].values.contains(&shared));
}

/// The capacity bound aborts the WHOLE transfer: the source stays intact, the
/// destination is unmutated, and no receipt survives.
#[test]
fn transfer_is_atomic() {
    let (_dir, vault) = vault();
    let from = symbol(&vault, 0x2D);
    let to = symbol(&vault, 0x2E);
    let actor = id(0x38);

    attach(
        &vault,
        from,
        "src/before.rs",
        slot(),
        value(note(&vault), actor, 0x58, 1_000),
    )
    .expect("source attach");
    let filler_payload = note(&vault);
    for index in 0..CODE_MEMORY_MAX_VALUES_PER_SLOT {
        let mut filler = value(filler_payload, id(0x39), 0x59, 2_000);
        filler.content_hash[0] = u8::try_from(index % 251).expect("byte");
        filler.content_hash[1] = u8::try_from(index / 251).expect("byte");
        attach(&vault, to, "src/after.rs", slot(), filler).expect("destination fills to the bound");
    }
    let before_destination = vault.code_memory_slots(to).expect("destination");

    let error = vault
        .transfer_code_memory_anchor(&transfer(AnchorTransferKind::Copy, from, to, actor))
        .expect_err("an over-capacity destination must refuse the whole transfer");
    assert!(matches!(
        error,
        Error::CodeMemoryLimitExceeded {
            kind: "slot values",
            ..
        }
    ));

    assert_eq!(
        vault.code_memory_slots(to).expect("destination"),
        before_destination,
        "destination is byte-for-byte unchanged"
    );
    assert_eq!(
        vault.code_memory_slots(from).expect("source").len(),
        1,
        "source is fully intact"
    );
    assert!(
        vault
            .code_memory_transfers(to)
            .expect("receipts")
            .is_empty(),
        "no transfer receipt survives an aborted transfer"
    );
}

/// A transfer whose source carries no slot value is the typed invalid-transfer
/// case, and so are same-symbol and non-`CODE_SYMBOL` endpoints.
#[test]
fn invalid_anchor_transfers_are_typed() {
    let (_dir, vault) = vault();
    let from = symbol(&vault, 0x61);
    let to = symbol(&vault, 0x62);
    let actor = id(0x3A);

    for candidate in [
        transfer(AnchorTransferKind::Rename, from, to, actor),
        transfer(AnchorTransferKind::Rename, from, from, actor),
        transfer(AnchorTransferKind::Rename, from, id(0x63), actor),
    ] {
        let error = vault
            .transfer_code_memory_anchor(&candidate)
            .expect_err("invalid transfer");
        assert!(matches!(
            error,
            Error::CodeMemoryInvalidAnchorTransfer { .. }
        ));
    }
}

/// The LOCATOR IS PER PAYLOAD, never per operation.
///
/// A second attach into the same slot may not restamp the first payload's
/// `path_at_revision`, and a transfer relabels only what it actually moved:
/// a destination-only payload keeps the locator it was attached under even
/// though the merged slot is rewritten around it.
#[test]
fn locators_survive_later_attaches_and_untouched_transfers() {
    let (_dir, vault) = vault();
    let from = symbol(&vault, 0xE0);
    let to = symbol(&vault, 0xE1);
    let first = note(&vault);
    let second = note(&vault);
    let destination_only = note(&vault);
    let actor = id(0xE2);

    attach(
        &vault,
        from,
        "src/first.rs",
        slot(),
        value(first, actor, 0xB1, 1_000),
    )
    .expect("first attach");
    attach(
        &vault,
        from,
        "src/second.rs",
        slot(),
        value(second, actor, 0xB2, 2_000),
    )
    .expect("a second attach into the SAME slot");

    assert_eq!(
        attachment_path(&vault, from, first),
        "src/first.rs",
        "the older payload keeps the locator it was attached under"
    );
    assert_eq!(attachment_path(&vault, from, second), "src/second.rs");

    // The destination already holds an unrelated payload in the same slot.
    attach(
        &vault,
        to,
        "src/destination.rs",
        slot(),
        value(destination_only, id(0xE3), 0xB3, 3_000),
    )
    .expect("destination pre-fill");

    vault
        .transfer_code_memory_anchor(&transfer(AnchorTransferKind::Copy, from, to, actor))
        .expect("explicit copy");

    assert_eq!(
        attachment_path(&vault, to, destination_only),
        "src/destination.rs",
        "a payload this transfer never moved is not relabelled by `to_locator`"
    );
    for moved in [first, second] {
        assert_eq!(
            attachment_path(&vault, to, moved),
            "src/after.rs",
            "a payload that DID move carries the transfer's own locator"
        );
    }

    assert_eq!(
        attachment_path(&vault, from, first),
        "src/first.rs",
        "a copy leaves the source locators untouched too"
    );
    assert_eq!(attachment_path(&vault, from, second), "src/second.rs");
}

/// A symbol carrying ONLY standalone always-on contracts is a legal
/// registration, so it is transferable: the rename re-points the always-on
/// rows and reports zero moved slot values rather than refusing.
#[test]
fn contract_only_symbol_transfers() {
    let (_dir, vault) = vault();
    let from = symbol(&vault, 0xE4);
    let to = symbol(&vault, 0xE5);
    let actor = id(0xE6);
    let payload = note(&vault);

    vault
        .register_always_on_contract(contract(
            from,
            slot(),
            payload,
            CodeMemoryContractKind::Interface,
            actor,
        ))
        .expect("registration never requires a slot value");
    assert!(
        vault.code_memory_slots(from).expect("source").is_empty(),
        "precondition: the source carries no slot value at all"
    );

    let receipt = vault
        .transfer_code_memory_anchor(&transfer(AnchorTransferKind::Rename, from, to, actor))
        .expect("a contract-only symbol may still be renamed");
    assert_eq!(
        receipt.moved_attachments, 0,
        "the count measures slot values; the contract moved regardless"
    );

    let moved = vault
        .code_memory_always_on_contracts(to)
        .expect("destination contracts");
    assert_eq!(moved.len(), 1);
    assert_eq!(
        moved[0].symbol_id, to,
        "the always-on row re-points onto the destination symbol"
    );
    assert_eq!(moved[0].payload, payload);
    assert_eq!(moved[0].kind, CodeMemoryContractKind::Interface);
    assert!(
        vault
            .code_memory_always_on_contracts(from)
            .expect("source contracts")
            .is_empty(),
        "the rename leaves no always-on row pinned to the old symbol"
    );
    assert_eq!(
        vault.code_memory_transfers(to).expect("receipts").len(),
        1,
        "the transfer is recorded like any other"
    );
}

/// Contract collisions resolve exactly like slot collisions: the destination
/// registration stands. A transfer never writes source kind/actor/time/
/// provenance over an existing destination `(symbol, slot, payload)` row.
#[test]
fn transfer_preserves_a_colliding_destination_contract() {
    let (_dir, vault) = vault();
    let from = symbol(&vault, 0xEC);
    let to = symbol(&vault, 0xED);
    let source_actor = id(0xEE);
    let destination_actor = id(0xEF);
    let payload = note(&vault);

    // The SAME (symbol, slot, payload) key on both sides, registered with
    // deliberately different metadata on every field a transfer could clobber.
    let mut destination = contract(
        to,
        slot(),
        payload,
        CodeMemoryContractKind::Policy,
        destination_actor,
    );
    destination.valid_time = range(1_780_000_111);
    destination.recorded_at = 1_780_000_111;
    destination.provenance_claim_id = id(0xF0);
    vault
        .register_always_on_contract(destination.clone())
        .expect("the destination registers first");

    let mut source = contract(
        from,
        slot(),
        payload,
        CodeMemoryContractKind::Interface,
        source_actor,
    );
    source.valid_time = range(1_780_000_222);
    source.recorded_at = 1_780_000_222;
    source.provenance_claim_id = id(0xF1);
    vault
        .register_always_on_contract(source)
        .expect("the source registers the colliding key");
    attach(
        &vault,
        from,
        "src/before.rs",
        slot(),
        value(note(&vault), source_actor, 0xF2, 1_000),
    )
    .expect("a slot value so the transfer moves both families at once");

    vault
        .transfer_code_memory_anchor(&transfer(AnchorTransferKind::Copy, from, to, source_actor))
        .expect("transfer");

    assert_eq!(
        vault.code_memory_slots(to).expect("destination").len(),
        1,
        "the transfer really ran: the slot value landed"
    );
    let contracts = vault
        .code_memory_always_on_contracts(to)
        .expect("destination contracts");
    assert_eq!(
        contracts.len(),
        1,
        "the colliding destination key stays exactly one row"
    );
    assert_eq!(
        contracts[0], destination,
        "the destination registration survives field for field; there is no last-writer-wins"
    );
}

// ---------------------------------------------------------------------------
// Slots
// ---------------------------------------------------------------------------

/// Two actors submitting the SAME content hash stay two values with distinct
/// actor/time/provenance, and the conflict is visible DATA.
#[test]
fn equal_bytes_different_actors_remain_distinct() {
    let (_dir, vault) = vault();
    let anchor_symbol = symbol(&vault, 0x64);
    let payload = note(&vault);

    attach(
        &vault,
        anchor_symbol,
        "src/a.rs",
        slot(),
        value(payload, id(0x3B), 0x5A, 1_000),
    )
    .expect("first writer");
    attach(
        &vault,
        anchor_symbol,
        "src/a.rs",
        slot(),
        value(payload, id(0x3C), 0x5A, 2_000),
    )
    .expect("second writer");

    let slots = vault.code_memory_slots(anchor_symbol).expect("slots");
    assert_eq!(slots[0].values.len(), 2);
    assert!(slots[0].conflict_visible);
    let actors: Vec<EntityId> = slots[0].values.iter().map(|value| value.actor_id).collect();
    assert!(actors.contains(&id(0x3B)) && actors.contains(&id(0x3C)));
}

/// One actor, same content key, two orders: both report
/// `DeduplicatedWithinActor` and the canonical-minimum survivor wins either
/// way. There is NO last-write-wins.
#[test]
fn equal_bytes_same_actor_dedupe_has_no_lww() {
    for reverse in [false, true] {
        let (_dir, vault) = vault();
        let anchor_symbol = symbol(&vault, 0x65);
        let actor = id(0x3D);
        let older = value(note(&vault), actor, 0x5B, 1_000);
        let newer = value(note(&vault), actor, 0x5B, 2_000);
        let order = if reverse {
            vec![newer.clone(), older.clone()]
        } else {
            vec![older.clone(), newer.clone()]
        };

        let mut outcomes = Vec::new();
        for candidate in order {
            outcomes.push(
                attach(&vault, anchor_symbol, "src/a.rs", slot(), candidate).expect("attach"),
            );
        }
        assert_eq!(outcomes[0], SlotInsertOutcome::Inserted);
        assert_eq!(outcomes[1], SlotInsertOutcome::DeduplicatedWithinActor);

        let slots = vault.code_memory_slots(anchor_symbol).expect("slots");
        assert_eq!(slots[0].values, vec![older.clone()]);
        assert!(!slots[0].conflict_visible);

        // The attachment index mirrors the SURVIVING body exactly: the loser's
        // payload keeps no row.
        let payloads: Vec<CodeMemoryPayloadRef> = vault
            .code_memory_attachments(anchor_symbol)
            .expect("attachments")
            .into_iter()
            .map(|attachment| attachment.payload)
            .collect();
        assert_eq!(payloads, vec![older.payload]);
        assert!(!payloads.contains(&newer.payload));
    }
}

/// Conflicting older and newer values from DIFFERENT actors both survive; no
/// public method selects the newer one.
#[test]
fn no_lww_across_actors() {
    let (_dir, vault) = vault();
    let anchor_symbol = symbol(&vault, 0x66);
    let older = value(note(&vault), id(0x3E), 0x5C, 1_000);
    let newer = value(note(&vault), id(0x3F), 0x5D, 9_000);

    attach(&vault, anchor_symbol, "src/a.rs", slot(), older.clone()).expect("older");
    attach(&vault, anchor_symbol, "src/a.rs", slot(), newer.clone()).expect("newer");

    let slots = vault.code_memory_slots(anchor_symbol).expect("slots");
    assert_eq!(slots[0].values.len(), 2);
    assert!(slots[0].values.contains(&older));
    assert!(slots[0].values.contains(&newer));
    assert!(slots[0].conflict_visible);
}

/// The 257th distinct value returns the typed limit error and leaves the
/// stored slot unchanged.
#[test]
fn slot_limit_is_transactional() {
    let (_dir, vault) = vault();
    let anchor_symbol = symbol(&vault, 0x67);
    let payload = note(&vault);
    for index in 0..CODE_MEMORY_MAX_VALUES_PER_SLOT {
        let mut filler = value(payload, id(0x2F), 0x5E, 1_000);
        filler.content_hash[0] = u8::try_from(index % 251).expect("byte");
        filler.content_hash[1] = u8::try_from(index / 251).expect("byte");
        attach(&vault, anchor_symbol, "src/a.rs", slot(), filler).expect("value fits");
    }
    let before = vault.code_memory_slots(anchor_symbol).expect("slots");

    let mut overflow = value(payload, id(0x2F), 0x5F, 1_000);
    overflow.content_hash = [0xFE; 32];
    let error = attach(&vault, anchor_symbol, "src/a.rs", slot(), overflow)
        .expect_err("the 257th distinct value must be refused");
    assert!(matches!(
        error,
        Error::CodeMemoryLimitExceeded {
            kind: "slot values",
            limit: CODE_MEMORY_MAX_VALUES_PER_SLOT
        }
    ));
    assert_eq!(
        vault.code_memory_slots(anchor_symbol).expect("slots"),
        before
    );
}

/// An anchor that is not a live `CODE_SYMBOL` is refused typed — the identity
/// rule is enforced at the write door, not documented at it.
#[test]
fn attachment_requires_a_live_code_symbol_anchor() {
    let (_dir, vault) = vault();
    let not_a_symbol = seed(&vault, 0x68, ENTITY_TYPE_PERSON);
    let error = attach(
        &vault,
        not_a_symbol,
        "src/a.rs",
        slot(),
        value(note(&vault), id(0x2C), 0x60, 1_000),
    )
    .expect_err("a PERSON is not a code anchor");
    assert!(matches!(error, Error::CodeMemoryInvalidAnchor { .. }));
}

// ---------------------------------------------------------------------------
// `EdgeKind::Blocks`
// ---------------------------------------------------------------------------

/// Byte 24 is the binding reservation, byte 23 keeps ONE-1924's `blocked_by`,
/// byte 20 keeps ONE-1414's `same_as`, and the stored prior is `Some(1.0)`.
#[test]
fn blocks_discriminant_is_24() {
    assert_eq!(EdgeKind::Blocks as u8, 24);
    assert_eq!(EdgeKind::try_from_u8(24), Some(EdgeKind::Blocks));
    assert_eq!(EdgeKind::Blocks.default_weight(), Some(1.0));
    assert_eq!(EdgeKind::try_from_u8(23), Some(EdgeKind::BlockedBy));
    assert_eq!(EdgeKind::try_from_u8(20), Some(EdgeKind::SameAs));
    assert!(EdgeKind::try_from_u8(25).is_none());
}

/// `discovered-from` reuses the EXISTING `derived_from` kind. No alias is
/// added: the census of decodable bytes contains no second discovered-from.
#[test]
fn derived_from_is_reused_for_discovered_from() {
    let (_dir, vault) = vault();
    let discovered = symbol(&vault, 0x69);
    let source = symbol(&vault, 0x6A);
    vault
        .put_edge(&discovered, EdgeKind::DerivedFrom, &source, 0.2)
        .expect("discovered-from is an ordinary derived_from edge");

    assert_eq!(EdgeKind::DerivedFrom as u8, 8);
    let blocks_bytes: Vec<u8> = (0..=u8::MAX)
        .filter(|byte| EdgeKind::try_from_u8(*byte) == Some(EdgeKind::Blocks))
        .collect();
    assert_eq!(
        blocks_bytes,
        vec![24],
        "byte 24 is the only readiness byte; no discovered-from alias exists"
    );
}

/// BOTH generic public edge doors reject `blocks`, and no graph mutation
/// happens on the refusal.
#[test]
fn generic_edge_doors_reject_blocks() {
    let (_dir, vault) = vault();
    let blocker = symbol(&vault, 0x6B);
    let blocked = symbol(&vault, 0x6C);

    let create = vault
        .put_edge(&blocker, EdgeKind::Blocks, &blocked, 1.0)
        .expect_err("generic creation is reserved");
    assert!(matches!(create, Error::ReservedEdgeKind("blocks")));

    let delete = vault
        .delete_edge(&blocker, EdgeKind::Blocks, &blocked)
        .expect_err("generic deletion is reserved");
    assert!(matches!(delete, Error::ReservedEdgeKind("blocks")));

    assert!(
        vault.blocks_dependencies(blocker).expect("read").is_empty(),
        "a refused generic write leaves no edge behind"
    );
}

/// A `blocks` write that would close a cycle — direct or transitive — fails
/// typed and writes nothing.
#[test]
fn blocks_cycles_are_typed_and_not_written() {
    let (_dir, vault) = vault();
    let a = symbol(&vault, 0x6D);
    let b = symbol(&vault, 0x6E);
    let c = symbol(&vault, 0x6F);
    let actor = human(&vault, 0x70);

    vault
        .insert_blocks_edge(a, b, blocks_context(&actor))
        .expect("A blocks B");
    vault
        .insert_blocks_edge(b, c, blocks_context(&actor))
        .expect("B blocks C");

    let transitive = vault
        .insert_blocks_edge(c, a, blocks_context(&actor))
        .expect_err("C -> A would close the readiness cycle");
    assert!(matches!(transitive, Error::CodeMemoryBlocksCycle { .. }));

    let reflexive = vault
        .insert_blocks_edge(a, a, blocks_context(&actor))
        .expect_err("A -> A is the same cycle family");
    assert!(matches!(reflexive, Error::CodeMemoryBlocksCycle { .. }));

    assert_eq!(vault.blocks_dependencies(a).expect("read"), vec![b]);
    assert_eq!(vault.blocks_dependencies(b).expect("read"), vec![c]);
    assert!(vault.blocks_dependencies(c).expect("read").is_empty());
}

/// A non-`blocks` path between the same endpoints never fabricates a cycle:
/// the acyclicity walk is kind-local.
#[test]
fn blocks_cycle_check_is_kind_local() {
    let (_dir, vault) = vault();
    let a = symbol(&vault, 0x71);
    let b = symbol(&vault, 0x72);
    let actor = human(&vault, 0x73);

    vault
        .put_edge(&b, EdgeKind::DerivedFrom, &a, 0.2)
        .expect("an ordinary structural path B -> A");
    vault
        .insert_blocks_edge(a, b, blocks_context(&actor))
        .expect("a derived_from path is not a readiness path");
    assert_eq!(vault.blocks_dependencies(a).expect("read"), vec![b]);
}

/// Authority is bound to the ACTOR ENTITY, not the caller's assertion:
/// Human/Agent on a non-permit-requiring source pass; `System`, a forged
/// class, an unresolvable actor, and a permit-requiring source are typed
/// refusals that write nothing.
#[test]
fn blocks_authority_is_gated() {
    let (_dir, vault) = vault();
    let a = symbol(&vault, 0x74);
    let b = symbol(&vault, 0x75);
    let c = symbol(&vault, 0x76);

    let agent = WriteActor::new(
        seed(&vault, 0x77, ENTITY_TYPE_PERSON),
        EdgeActorClass::Agent,
    );
    vault
        .insert_blocks_edge(a, b, blocks_context(&agent))
        .expect("an Agent on a user-stated source is admitted");

    let machine = WriteActor::new(
        seed(&vault, 0x78, ENTITY_TYPE_MACHINE),
        EdgeActorClass::System,
    );
    let system = vault
        .insert_blocks_edge(a, c, blocks_context(&machine))
        .expect_err("System actors may not mint readiness dependencies");
    assert!(matches!(system, Error::CodeMemoryBlocksActorDenied(_)));

    // A MACHINE entity presented through a `WriteActor` ASSERTING Human: the
    // stored entity type refuses the class, so the assertion buys nothing.
    let forged = WriteActor::new(id(0x78), EdgeActorClass::Human);
    let mismatch = vault
        .insert_blocks_edge(a, c, blocks_context(&forged))
        .expect_err("a forged actor class is refused");
    assert!(matches!(mismatch, Error::CodeMemoryBlocksActorDenied(_)));

    let ghost = WriteActor::new(id(0x79), EdgeActorClass::Human);
    let unresolved = vault
        .insert_blocks_edge(a, c, blocks_context(&ghost))
        .expect_err("an unresolvable actor is refused");
    assert!(matches!(unresolved, Error::CodeMemoryBlocksActorDenied(_)));

    let human_actor = human(&vault, 0x7A);
    for source in [
        ClaimSource::Imported,
        ClaimSource::ToolOutput,
        ClaimSource::Generated,
    ] {
        let untrusted = vault
            .insert_blocks_edge(
                a,
                c,
                BlocksWriteContext {
                    actor: &human_actor,
                    source,
                },
            )
            .expect_err("a permit-requiring source is refused");
        assert!(matches!(
            untrusted,
            Error::CodeMemoryBlocksSourceUntrusted { .. }
        ));
    }

    assert_eq!(
        vault.blocks_dependencies(a).expect("read"),
        vec![b],
        "every refusal wrote nothing"
    );
}

/// Readiness endpoints are TYPED, exactly like attach/transfer/pull anchors:
/// a ghost id and a live non-`CODE_SYMBOL` entity are typed refusals on
/// EITHER side, and neither persists a row.
#[test]
fn blocks_endpoints_must_be_live_code_symbols() {
    let (_dir, vault) = vault();
    let anchor_symbol = symbol(&vault, 0xE7);
    let actor = human(&vault, 0xE8);
    let ghost = id(0xE9);
    let not_a_symbol = seed(&vault, 0xEA, ENTITY_TYPE_PERSON);

    for (from, to) in [
        (anchor_symbol, ghost),
        (ghost, anchor_symbol),
        (anchor_symbol, not_a_symbol),
        (not_a_symbol, anchor_symbol),
    ] {
        let error = vault
            .insert_blocks_edge(from, to, blocks_context(&actor))
            .expect_err("readiness needs a live CODE_SYMBOL on both ends");
        assert!(matches!(error, Error::CodeMemoryInvalidAnchor { .. }));
    }

    for endpoint in [anchor_symbol, ghost, not_a_symbol] {
        let dependencies = vault.blocks_dependencies(endpoint).expect("read");
        assert!(
            dependencies.is_empty(),
            "every refusal wrote nothing on either index"
        );
    }

    // The control: the same actor and source write cleanly between two live
    // symbols, so the refusals above measure endpoint typing and nothing else.
    let downstream = symbol(&vault, 0xEB);
    vault
        .insert_blocks_edge(anchor_symbol, downstream, blocks_context(&actor))
        .expect("two live CODE_SYMBOLs still pass the same door");
    assert_eq!(
        vault.blocks_dependencies(anchor_symbol).expect("read"),
        vec![downstream]
    );
}

/// The dedicated door is the ONLY retirement path, and it survives a vault
/// reopen plus the exact seven-stage maintenance chain in between.
#[test]
fn blocks_survives_maintenance_and_reopen_then_retires_through_the_door() {
    let dir = tempfile::tempdir().expect("temporary vault");
    let a;
    let b;
    {
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
        a = symbol(&vault, 0x7B);
        b = symbol(&vault, 0x7C);
        let actor = human(&vault, 0x7D);
        vault
            .insert_blocks_edge(a, b, blocks_context(&actor))
            .expect("insert");

        // The exact seven-stage chain. `MaintenanceBuilder` defaults every
        // stage OFF, so a bare `run()` would prove nothing.
        vault
            .maintain()
            .rebuild_hnsw()
            .cleanup_ppr_cache(0)
            .compact_postings()
            .recompute_short_id_hashes()
            .clear_text_index()
            .run_hard_erase_sweep()
            .cleanup_attempt_queue_leases(1)
            .run()
            .expect("full maintenance pass");
        assert_eq!(
            vault.blocks_dependencies(a).expect("read"),
            vec![b],
            "no maintenance stage may destroy a readiness edge"
        );
    }

    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("reopen vault");
    assert_eq!(
        vault.blocks_dependencies(a).expect("read"),
        vec![b],
        "the readiness edge is durable across reopen"
    );

    let actor = human(&vault, 0x7E);
    assert!(
        vault
            .remove_blocks_edge(a, b, blocks_context(&actor))
            .expect("dedicated retirement"),
    );
    assert!(vault.blocks_dependencies(a).expect("read").is_empty());
    assert!(
        matches!(
            vault.delete_edge(&a, EdgeKind::Blocks, &b),
            Err(Error::ReservedEdgeKind("blocks"))
        ),
        "generic deletion stays reserved even after the edge is gone"
    );
}

/// PPR never traverses `blocks`: a symbol reachable ONLY through a readiness
/// edge is absent from an L2 pull, while `blocks_dependencies` still sees it.
#[test]
fn blocks_is_excluded_from_default_ppr() {
    let (_dir, vault) = vault();
    let seed_symbol = symbol(&vault, 0x7F);
    let downstream = symbol(&vault, 0x80);
    let actor = human(&vault, 0x81);
    let payload = note(&vault);

    vault
        .insert_blocks_edge(seed_symbol, downstream, blocks_context(&actor))
        .expect("readiness edge");
    attach(
        &vault,
        downstream,
        "src/downstream.rs",
        slot(),
        value(payload, id(0x83), 0x84, 1_000),
    )
    .expect("attach downstream");

    let pulled = vault
        .pull_code_memory(reader_key(), CodeMemoryPullRequest::new(vec![seed_symbol]))
        .expect("pull");
    assert!(
        pulled.notes.is_empty(),
        "no PPR mass crosses a readiness edge, so the downstream note is unreachable"
    );
    assert_eq!(
        vault.blocks_dependencies(seed_symbol).expect("read"),
        vec![downstream],
        "the dedicated read surface still sees the dependency"
    );
}

// ---------------------------------------------------------------------------
// Pull and labelling
// ---------------------------------------------------------------------------

/// Every pulled value is provenance-labelled DATA carrying its own slot
/// value's actor, valid/recorded time, and provenance claim.
#[test]
fn all_pulled_values_are_labelled_data() {
    let (_dir, vault) = vault();
    let anchor_symbol = symbol(&vault, 0x85);
    let payload = note(&vault);
    let actor = id(0x87);
    let attached = value(payload, actor, 0x88, 1_234);
    attach(&vault, anchor_symbol, "src/a.rs", slot(), attached.clone()).expect("attach");
    vault
        .register_always_on_contract(contract(
            anchor_symbol,
            other_slot(),
            payload,
            CodeMemoryContractKind::Policy,
            actor,
        ))
        .expect("register");

    let pulled = vault
        .pull_code_memory(
            reader_key(),
            CodeMemoryPullRequest::new(vec![anchor_symbol]),
        )
        .expect("pull");

    assert_eq!(pulled.notes.len(), 1);
    let labelled = &pulled.notes[0];
    assert_eq!(labelled.material_kind, ProvenanceMaterialKind::Data);
    assert_eq!(labelled.provenance.actor_id, attached.actor_id);
    assert_eq!(labelled.provenance.valid_time, attached.valid_time);
    assert_eq!(labelled.provenance.recorded_at, attached.recorded_at);
    assert_eq!(
        labelled.provenance.provenance_claim_id,
        attached.provenance_claim_id
    );
    assert_eq!(labelled.data, attached);

    assert_eq!(pulled.always_on_contracts.len(), 1);
    let contract_label = &pulled.always_on_contracts[0];
    assert_eq!(contract_label.material_kind, ProvenanceMaterialKind::Data);
    assert_eq!(contract_label.provenance.actor_id, actor);
    assert_eq!(contract_label.provenance.recorded_at, 1_780_000_500);
    assert_eq!(contract_label.data.kind, CodeMemoryContractKind::Policy);
}

/// The ScopedRead clamp runs on EVERY referenced entity BEFORE the caller's
/// note limit is applied.
///
/// The denied note is attached FIRST and is canonically smaller. With a limit
/// of TWO, both values fit the global examined-value budget, so the permitted
/// one survives while the denied one is removed by the same snapshot-local
/// admission predicate used by the pull.
#[test]
fn scoped_read_clamps_before_ranking() {
    let (_dir, vault) = vault();
    let anchor_symbol = symbol(&vault, 0x89);
    let permitted = note(&vault);
    // A ref that resolves to nothing: the canonical clamp answers `None`, so
    // this note can never survive whatever the local policy says.
    let denied = CodeMemoryPayloadRef::NoteEntity(id(0x8B));

    attach(
        &vault,
        anchor_symbol,
        "src/a.rs",
        slot(),
        value(denied, id(0x8C), 0x8D, 100),
    )
    .expect("attach the clamp-denied note first");
    attach(
        &vault,
        anchor_symbol,
        "src/a.rs",
        slot(),
        value(permitted, id(0x8E), 0x8F, 200),
    )
    .expect("attach the permitted note");

    let mut request = CodeMemoryPullRequest::new(vec![anchor_symbol]);
    request.limit = 2;
    let pulled = vault.pull_code_memory(reader_key(), request).expect("pull");

    assert_eq!(pulled.notes.len(), 1);
    assert_eq!(
        pulled.notes[0].data.payload, permitted,
        "the permitted note survives; the denied payload never reaches the limit cut"
    );
    assert!(
        pulled.notes.iter().all(|note| note.data.payload != denied),
        "no denied metadata leaks into the result"
    );
}

/// Pull uses the CANONICAL clamp rather than reimplementing scope membership:
/// a CLAIM-payload note is present in the pull exactly when
/// `Vault::scoped_read(..).get(..)` — the landed CLAIM-specific door — admits
/// the same id for the same actor key. A non-CLAIM NOTE ref passes that door
/// today, and this test records that rather than fabricating a NOTE-specific
/// denial.
#[test]
fn always_on_remains_scoped_through_the_canonical_clamp() {
    let (_dir, vault) = vault();
    let anchor_symbol = symbol(&vault, 0xD0);
    let subject = seed(&vault, 0xD1, ENTITY_TYPE_PERSON);
    let claim_id = claim(&vault, 0xD2, subject);
    let claim_payload = CodeMemoryPayloadRef::Claim(claim_id);
    let plain = note(&vault);

    attach(
        &vault,
        anchor_symbol,
        "src/a.rs",
        slot(),
        value(claim_payload, id(0xD4), 0xD5, 100),
    )
    .expect("attach the claim-backed note");
    attach(
        &vault,
        anchor_symbol,
        "src/a.rs",
        slot(),
        value(plain, id(0xD6), 0xD7, 200),
    )
    .expect("attach the plain note");

    let clamp_admits_claim = vault
        .scoped_read(reader_key())
        .get(&claim_id)
        .expect("canonical clamp")
        .is_some();

    let pulled = vault
        .pull_code_memory(
            reader_key(),
            CodeMemoryPullRequest::new(vec![anchor_symbol]),
        )
        .expect("pull");
    let claim_in_pull = pulled
        .notes
        .iter()
        .any(|note| note.data.payload == claim_payload);

    assert_eq!(
        claim_in_pull, clamp_admits_claim,
        "pull never widens or narrows the canonical CLAIM clamp"
    );
    assert!(
        pulled.notes.iter().any(|note| note.data.payload == plain),
        "a live non-CLAIM NOTE ref passes the claim-specific clamp today"
    );
}

/// A header-only CLAIM payload is SKIPPED, never an error.
///
/// The pull decides every payload inside its OWN read transaction. The
/// canonical `ScopedRead` clamp answers a header-only CLAIM by consulting
/// `is_deleted_shell`, which opens a read transaction of its own — and nested
/// read transactions on one thread are forbidden, so reaching it under the
/// pull's `RoTxn` would fail the whole read instead of dropping one unreadable
/// payload. The shell is attached FIRST, so it is the first thing the sweep
/// meets.
#[test]
fn a_header_only_claim_payload_is_skipped_rather_than_failing_the_pull() {
    let (_dir, vault) = vault();
    let anchor_symbol = symbol(&vault, 0xB0);
    let subject = seed(&vault, 0xB1, ENTITY_TYPE_PERSON);
    let shell = deleted_shell_claim(&vault, 0xB2, subject);
    let permitted = note(&vault);

    attach(
        &vault,
        anchor_symbol,
        "src/a.rs",
        slot(),
        value(shell, id(0x01), 0x01, 100),
    )
    .expect("a slot may name a payload this module never resolves");
    attach(
        &vault,
        anchor_symbol,
        "src/a.rs",
        slot(),
        value(permitted, id(0x02), 0x02, 200),
    )
    .expect("attach the readable note");

    let pulled = vault
        .pull_code_memory(
            reader_key(),
            CodeMemoryPullRequest::new(vec![anchor_symbol]),
        )
        .expect("an unreadable payload must never fail the pull");

    assert_eq!(
        pulled_payloads(&pulled),
        vec![permitted],
        "the shell is skipped and the readable note still comes back"
    );
}

/// The global examined-value budget counts denied payloads across slots.
///
/// A denial-heavy prefix may therefore return short by design. With two
/// denials in the first two canonical slots and two readable values after
/// them, limits 2, 3, and 4 examine exactly that many values globally and
/// return respectively zero, the first readable value, and both readable
/// values. This proves that admission cannot run past the budget and that the
/// admitted prefix keeps canonical slot order.
#[test]
fn denied_values_consume_one_global_examined_budget_across_slots() {
    let (_dir, vault) = vault();
    let anchor_symbol = symbol(&vault, 0xB4);
    let subject = seed(&vault, 0xB5, ENTITY_TYPE_PERSON);

    let unresolvable = CodeMemoryPayloadRef::NoteEntity(id(0xB6));
    let shell = deleted_shell_claim(&vault, 0xB7, subject);
    let first = note(&vault);
    let second = note(&vault);

    for (index, (slot_name, payload)) in [
        ("slot.00", unresolvable),
        ("slot.01", shell),
        ("slot.02", first),
        ("slot.03", second),
    ]
    .into_iter()
    .enumerate()
    {
        attach(
            &vault,
            anchor_symbol,
            "src/a.rs",
            CodeMemorySlotName::new(slot_name).expect("valid slot name"),
            value(
                payload,
                id(u8::try_from(index + 1).expect("small index")),
                0x10,
                100,
            ),
        )
        .expect("attach");
    }

    for (limit, expected) in [(2, Vec::new()), (3, vec![first]), (4, vec![first, second])] {
        let mut request = CodeMemoryPullRequest::new(vec![anchor_symbol]);
        request.limit = limit;
        let pulled = vault.pull_code_memory(reader_key(), request).expect("pull");
        assert_eq!(
            pulled_payloads(&pulled),
            expected,
            "denied values consume the global budget before later slots are scanned"
        );
    }
}

/// The bounded slot sweep keeps CANONICAL order while respecting the global
/// examined-value budget.
///
/// The pull streams slot bodies and stops before decoding another slot once
/// `limit` values have been examined. The first slot is a denied shell, so it
/// consumes the first unit and can make the result short; later readable slots
/// still arrive in canonical order only when the budget reaches them.
#[test]
fn bounded_slot_streaming_keeps_canonical_order_and_respects_denial_budget() {
    let (_dir, vault) = vault();
    let anchor_symbol = symbol(&vault, 0xB8);
    let subject = seed(&vault, 0xB9, ENTITY_TYPE_PERSON);
    let denied = deleted_shell_claim(&vault, 0xBA, subject);

    attach(
        &vault,
        anchor_symbol,
        "src/a.rs",
        CodeMemorySlotName::new("slot.00").expect("valid slot name"),
        value(denied, id(0x01), 0x01, 100),
    )
    .expect("the canonically first slot holds a denied shell");

    let mut readable = Vec::new();
    for index in 1..6u8 {
        let payload = note(&vault);
        readable.push(payload);
        attach(
            &vault,
            anchor_symbol,
            "src/a.rs",
            CodeMemorySlotName::new(format!("slot.{index:02}")).expect("valid slot name"),
            value(payload, id(index), 0x02, 100),
        )
        .expect("attach one readable note per later slot");
    }

    for (limit, expected) in [
        (1, Vec::new()),
        (2, readable[..1].to_vec()),
        (3, readable[..2].to_vec()),
    ] {
        let mut request = CodeMemoryPullRequest::new(vec![anchor_symbol]);
        request.limit = limit;
        let pulled = vault.pull_code_memory(reader_key(), request).expect("pull");
        assert_eq!(
            pulled_payloads(&pulled),
            expected,
            "the global budget preserves canonical admitted order and may return short under denial"
        );
    }
}

/// Always-on registration accepts interface/policy NOTE refs only. A `Claim`
/// ref, an unresolvable ref, and a non-NOTE ref are typed refusals.
#[test]
fn always_on_is_interface_or_policy_note_only() {
    let (_dir, vault) = vault();
    let anchor_symbol = symbol(&vault, 0x90);
    let actor = id(0x91);

    for kind in [
        CodeMemoryContractKind::Interface,
        CodeMemoryContractKind::Policy,
    ] {
        let payload = note(&vault);
        vault
            .register_always_on_contract(contract(anchor_symbol, slot(), payload, kind, actor))
            .expect("interface and policy NOTE refs register");
    }

    let subject = seed(&vault, 0x95, ENTITY_TYPE_PERSON);
    for rejected in [
        // A `Claim` TAG is refused even when it names a live NOTE entity.
        CodeMemoryPayloadRef::Claim(note_entity(&vault)),
        // A ref that resolves to nothing.
        CodeMemoryPayloadRef::NoteEntity(id(0x96)),
        // Live, but the wrong entity type — positive NOTE typing (ARCH-0032,
        // `ENTITY_TYPE_NOTE = 106`) is enforced, not merely "not a CLAIM".
        CodeMemoryPayloadRef::NoteEntity(claim(&vault, 0x97, subject)),
        CodeMemoryPayloadRef::NoteEntity(seed(&vault, 0x9F, ENTITY_TYPE_PERSON)),
    ] {
        let error = vault
            .register_always_on_contract(contract(
                anchor_symbol,
                slot(),
                rejected,
                CodeMemoryContractKind::Interface,
                actor,
            ))
            .expect_err("only live NOTE entity refs register");
        assert!(matches!(error, Error::CodeMemoryAlwaysOnInvalid(_)));
    }

    assert_eq!(
        vault
            .code_memory_always_on_contracts(anchor_symbol)
            .expect("read")
            .len(),
        2,
        "every refusal wrote nothing"
    );
}

/// The eight-key bound is per-symbol REGISTRATION capacity: an idempotent
/// re-registration does not consume a ninth slot, and the ninth DISTINCT key
/// is a typed refusal that mutates nothing.
#[test]
fn always_on_bound_is_eight_per_symbol() {
    let (_dir, vault) = vault();
    let anchor_symbol = symbol(&vault, 0x98);
    let actor = id(0x99);

    let mut payloads = Vec::new();
    for _ in 0..CODE_MEMORY_MAX_ALWAYS_ON_CONTRACTS {
        let payload = note(&vault);
        payloads.push(payload);
        vault
            .register_always_on_contract(contract(
                anchor_symbol,
                slot(),
                payload,
                CodeMemoryContractKind::Interface,
                actor,
            ))
            .expect("eight distinct keys register");
    }

    vault
        .register_always_on_contract(contract(
            anchor_symbol,
            slot(),
            payloads[0],
            CodeMemoryContractKind::Policy,
            actor,
        ))
        .expect("an idempotent upsert of an existing key never consumes a ninth slot");

    let ninth = note(&vault);
    let error = vault
        .register_always_on_contract(contract(
            anchor_symbol,
            slot(),
            ninth,
            CodeMemoryContractKind::Interface,
            actor,
        ))
        .expect_err("the ninth distinct key is refused");
    assert!(matches!(
        error,
        Error::CodeMemoryLimitExceeded {
            kind: "always-on contracts per symbol",
            limit: CODE_MEMORY_MAX_ALWAYS_ON_CONTRACTS
        }
    ));
    assert_eq!(
        vault
            .code_memory_always_on_contracts(anchor_symbol)
            .expect("read")
            .len(),
        CODE_MEMORY_MAX_ALWAYS_ON_CONTRACTS
    );
}

/// The eight-key rule is per-symbol registration capacity, NOT a global pull
/// cap: a pull spanning two retained symbols returns every registered
/// contract for both, in canonical `(symbol, slot, payload)` order.
#[test]
fn pull_spanning_symbols_returns_all_registered_contracts() {
    let (_dir, vault) = vault();
    let first = symbol(&vault, 0xAA);
    let second = symbol(&vault, 0xAB);
    let actor = id(0xAC);

    for anchor_symbol in [first, second] {
        for _ in 0..5 {
            let payload = note(&vault);
            vault
                .register_always_on_contract(contract(
                    anchor_symbol,
                    slot(),
                    payload,
                    CodeMemoryContractKind::Interface,
                    actor,
                ))
                .expect("register");
        }
    }

    let pulled = vault
        .pull_code_memory(
            reader_key(),
            CodeMemoryPullRequest::new(vec![first, second]),
        )
        .expect("pull");
    assert_eq!(
        pulled.always_on_contracts.len(),
        10,
        "pull applies no second global always-on cut"
    );

    let ordering: Vec<(EntityId, String, CodeMemoryPayloadRef)> = pulled
        .always_on_contracts
        .iter()
        .map(|labelled| {
            (
                labelled.data.symbol_id,
                labelled.data.slot.as_str().to_owned(),
                labelled.data.payload,
            )
        })
        .collect();
    let mut sorted = ordering.clone();
    sorted.sort();
    assert_eq!(ordering, sorted, "canonical (symbol, slot, payload) order");
}

/// The pull entry is bounded and unscored: `CODE_MEMORY_PPR_DEPTH` is the
/// pinned constant, seeds must be live `CODE_SYMBOL`s, the caller limit is
/// clamped to the hard maximum, and the note cut applies AFTER the clamp.
#[test]
fn relevance_pull_is_bounded() {
    let (_dir, vault) = vault();
    let anchor_symbol = symbol(&vault, 0xC0);
    let payload = note(&vault);
    attach(
        &vault,
        anchor_symbol,
        "src/a.rs",
        slot(),
        value(payload, id(0xC2), 0xC3, 1_000),
    )
    .expect("attach");

    assert_eq!(CODE_MEMORY_PPR_DEPTH, 2, "depth is pinned, not tunable");

    let empty = vault
        .pull_code_memory(reader_key(), CodeMemoryPullRequest::new(Vec::new()))
        .expect_err("a seedless pull is refused");
    assert!(matches!(empty, Error::CodeMemoryInvalidAnchor { .. }));

    let not_a_symbol = seed(&vault, 0xC4, ENTITY_TYPE_PERSON);
    let wrong_seed = vault
        .pull_code_memory(reader_key(), CodeMemoryPullRequest::new(vec![not_a_symbol]))
        .expect_err("a non-CODE_SYMBOL seed is refused");
    assert!(matches!(wrong_seed, Error::CodeMemoryInvalidAnchor { .. }));

    let mut over_limit = CodeMemoryPullRequest::new(vec![anchor_symbol]);
    over_limit.limit = 100_000;
    let overflow = vault
        .pull_code_memory(reader_key(), over_limit)
        .expect_err("the caller limit is bounded by the hard maximum");
    assert!(matches!(
        overflow,
        Error::CodeMemoryLimitExceeded {
            kind: "pull note limit",
            ..
        }
    ));

    let mut thresholded = CodeMemoryPullRequest::new(vec![anchor_symbol]);
    thresholded.minimum_relevance = 2.0;
    assert!(
        vault
            .pull_code_memory(reader_key(), thresholded)
            .expect("pull")
            .notes
            .is_empty(),
        "below-threshold symbols are dropped before their notes are collected"
    );

    let pulled = vault
        .pull_code_memory(
            reader_key(),
            CodeMemoryPullRequest::new(vec![anchor_symbol]),
        )
        .expect("pull");
    assert_eq!(pulled.notes.len(), 1);
}

// ---------------------------------------------------------------------------
// Deletion lifecycle
// ---------------------------------------------------------------------------

/// Row counts across all four public L2 readers for one symbol.
fn row_counts(vault: &Vault, symbol_id: EntityId) -> (usize, usize, usize, usize) {
    let slots = vault
        .code_memory_slots(symbol_id)
        .expect("slot rows are readable");
    let rows = vault
        .code_memory_attachments(symbol_id)
        .expect("attachment rows are readable");
    let always_on = vault
        .code_memory_always_on_contracts(symbol_id)
        .expect("always-on rows are readable");
    let moves = vault
        .code_memory_transfers(symbol_id)
        .expect("transfer receipts are readable");
    (slots.len(), rows.len(), always_on.len(), moves.len())
}

/// Deleting the ANCHOR takes its L2 rows with it, in the same transaction.
///
/// Attachments, slots, always-on registrations, and transfer receipts are
/// `vault_meta` rows rather than entities, so nothing else in the delete path
/// reaches them: every reader below would otherwise keep answering for a
/// symbol that no longer exists. The copy destination is the control — it
/// keeps the material the transfer gave it, because only the deleted anchor's
/// rows are swept.
#[test]
fn deleting_a_symbol_clears_every_code_memory_row() {
    let (_dir, vault) = vault();
    let anchor_symbol = symbol(&vault, 0xE3);
    let destination = symbol(&vault, 0xE4);
    let actor = id(0xE5);
    let payload = note(&vault);
    let contract_payload = note(&vault);

    attach(
        &vault,
        anchor_symbol,
        "src/a.rs",
        slot(),
        value(payload, actor, 0xE6, 100),
    )
    .expect("attach");
    vault
        .register_always_on_contract(contract(
            anchor_symbol,
            other_slot(),
            contract_payload,
            CodeMemoryContractKind::Interface,
            actor,
        ))
        .expect("register");
    vault
        .transfer_code_memory_anchor(&transfer(
            AnchorTransferKind::Copy,
            anchor_symbol,
            destination,
            actor,
        ))
        .expect("copy the anchor's material onto a second symbol");

    assert_eq!(
        row_counts(&vault, anchor_symbol),
        (1, 1, 1, 1),
        "slot, attachment, always-on, and transfer rows all exist before the delete"
    );

    vault
        .batch()
        .delete(&anchor_symbol)
        .commit()
        .expect("delete the anchor symbol");

    assert!(
        vault.get(&anchor_symbol).expect("read").is_none(),
        "the anchor entity itself is gone"
    );
    assert_eq!(
        row_counts(&vault, anchor_symbol),
        (0, 0, 0, 0),
        "no public reader answers for a dead anchor, including its transfer history"
    );
    assert_eq!(
        vault.code_memory_slots(destination).expect("read").len(),
        1,
        "the copy destination keeps the material the transfer gave it"
    );
}

/// Deleting a PAYLOAD takes every reference to it with it, under any symbol.
///
/// The always-on bound is eight LIVE contracts per symbol, but registration
/// counts KEYS: without this sweep eight deleted NOTEs would hold a live
/// symbol at capacity forever while the readers went on publishing refs to
/// material that no longer exists. The surviving note is the control — the
/// sweep removes references, not slots.
#[test]
fn deleting_a_payload_clears_its_refs_and_frees_the_always_on_bound() {
    let (_dir, vault) = vault();
    let anchor_symbol = symbol(&vault, 0xE7);
    let actor = id(0xE8);
    let survivor = note(&vault);
    attach(
        &vault,
        anchor_symbol,
        "src/a.rs",
        slot(),
        value(survivor, actor, 0xE9, 100),
    )
    .expect("attach the surviving note");

    let mut payloads = Vec::new();
    for index in 0..CODE_MEMORY_MAX_ALWAYS_ON_CONTRACTS {
        let payload = note(&vault);
        payloads.push(payload);
        vault
            .register_always_on_contract(contract(
                anchor_symbol,
                slot(),
                payload,
                CodeMemoryContractKind::Interface,
                actor,
            ))
            .expect("eight distinct keys register");
        let content = 0xEA + u8::try_from(index).expect("index fits a byte");
        attach(
            &vault,
            anchor_symbol,
            "src/a.rs",
            slot(),
            value(payload, actor, content, 200 + index as u64),
        )
        .expect("the same payload also rides a slot value");
    }

    let ninth = note(&vault);
    let refused = vault
        .register_always_on_contract(contract(
            anchor_symbol,
            slot(),
            ninth,
            CodeMemoryContractKind::Interface,
            actor,
        ))
        .expect_err("eight live registrations fill the symbol");
    assert!(matches!(
        refused,
        Error::CodeMemoryLimitExceeded {
            kind: "always-on contracts per symbol",
            limit: CODE_MEMORY_MAX_ALWAYS_ON_CONTRACTS
        }
    ));

    for payload in &payloads {
        vault
            .batch()
            .delete(&payload.entity_id())
            .commit()
            .expect("hard-delete the NOTE payload");
    }

    let contracts = vault
        .code_memory_always_on_contracts(anchor_symbol)
        .expect("read");
    assert!(
        contracts.is_empty(),
        "no reader publishes a contract whose NOTE was deleted"
    );
    let payload_refs: Vec<CodeMemoryPayloadRef> = vault
        .code_memory_slots(anchor_symbol)
        .expect("read")
        .iter()
        .flat_map(|slot| slot.values.iter().map(|value| value.payload))
        .collect();
    assert_eq!(
        payload_refs,
        vec![survivor],
        "slot bodies keep the live payload and lose every deleted one"
    );
    let attached: Vec<CodeMemoryPayloadRef> = vault
        .code_memory_attachments(anchor_symbol)
        .expect("read")
        .into_iter()
        .map(|attachment| attachment.payload)
        .collect();
    assert_eq!(
        attached,
        vec![survivor],
        "the attachment index tracks the rewritten slot body exactly"
    );

    vault
        .register_always_on_contract(contract(
            anchor_symbol,
            slot(),
            ninth,
            CodeMemoryContractKind::Interface,
            actor,
        ))
        .expect("the bound counts live registrations, so a ninth NOTE fits now");
    let after = vault
        .code_memory_always_on_contracts(anchor_symbol)
        .expect("read");
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].payload, ninth);
}
