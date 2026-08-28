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
    CodeMemoryPayloadRef, CodeMemoryPullRequest, CodeMemoryRevision, CodeMemorySlotName,
    CodeMemorySlotValue, ProvenanceMaterialKind, SlotInsertOutcome,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EdgeActorClass,
    EdgeKind, EntityId, Error, TimeRange, Vault, VaultConfig, WriteActor,
};
use rmpv::Value;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const ENTITY_TYPE_CODE_SYMBOL: u8 = 104;
const ENTITY_TYPE_NOTE: u8 = 106;
const ENTITY_TYPE_PERSON: u8 = 4;
const ENTITY_TYPE_MACHINE: u8 = 102;

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
        .put_entity(&entity, entity_type, range(1_780_000_000), 1_780_000_000, b"x")
        .expect("seed entity");
    entity
}

fn symbol(vault: &Vault, byte: u8) -> EntityId {
    seed(vault, byte, ENTITY_TYPE_CODE_SYMBOL)
}

fn note(vault: &Vault, byte: u8) -> CodeMemoryPayloadRef {
    CodeMemoryPayloadRef::NoteEntity(seed(vault, byte, ENTITY_TYPE_NOTE))
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
    let payload = note(&vault, 0x41);

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
    let payload = note(&vault, 0x42);
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
    let payload = note(&vault, 0x43);

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
        value(note(&vault, 0x44), actor, 0x54, 1_000),
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
    let payload = note(&vault, 0x45);

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
    let payload = note(&vault, 0x46);
    let shared = value(payload, actor, 0x56, 1_000);

    attach(&vault, from, "src/before.rs", slot(), shared.clone()).expect("source attach");
    attach(&vault, to, "src/after.rs", slot(), shared.clone()).expect("destination pre-fill");
    attach(
        &vault,
        to,
        "src/after.rs",
        slot(),
        value(note(&vault, 0x47), id(0x37), 0x57, 2_000),
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
        value(note(&vault, 0x48), actor, 0x58, 1_000),
    )
    .expect("source attach");
    let filler_payload = note(&vault, 0x49);
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
        vault.code_memory_transfers(to).expect("receipts").is_empty(),
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

// ---------------------------------------------------------------------------
// Slots
// ---------------------------------------------------------------------------

/// Two actors submitting the SAME content hash stay two values with distinct
/// actor/time/provenance, and the conflict is visible DATA.
#[test]
fn equal_bytes_different_actors_remain_distinct() {
    let (_dir, vault) = vault();
    let anchor_symbol = symbol(&vault, 0x64);
    let payload = note(&vault, 0x4A);

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
        let older = value(note(&vault, 0x4B), actor, 0x5B, 1_000);
        let newer = value(note(&vault, 0x4C), actor, 0x5B, 2_000);
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
    let older = value(note(&vault, 0x4D), id(0x3E), 0x5C, 1_000);
    let newer = value(note(&vault, 0x4E), id(0x3F), 0x5D, 9_000);

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
    let payload = note(&vault, 0x4F);
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
        value(note(&vault, 0x2B), id(0x2C), 0x60, 1_000),
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
        vault
            .blocks_dependencies(blocker)
            .expect("read")
            .is_empty(),
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

    let agent = WriteActor::new(seed(&vault, 0x77, ENTITY_TYPE_PERSON), EdgeActorClass::Agent);
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
    let payload = note(&vault, 0x82);

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
    let payload = note(&vault, 0x86);
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
        .pull_code_memory(reader_key(), CodeMemoryPullRequest::new(vec![anchor_symbol]))
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
/// The denied note is attached FIRST and is canonically smaller, so a
/// pull that cut to `limit = 1` before clamping would return it and drop the
/// permitted one. Getting the permitted note back is the ordering proof.
#[test]
fn scoped_read_clamps_before_ranking() {
    let (_dir, vault) = vault();
    let anchor_symbol = symbol(&vault, 0x89);
    let permitted = note(&vault, 0x8A);
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
    request.limit = 1;
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
    let plain = note(&vault, 0xD3);

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
        .pull_code_memory(reader_key(), CodeMemoryPullRequest::new(vec![anchor_symbol]))
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
        let payload = note(&vault, if kind == CodeMemoryContractKind::Interface { 0x92 } else { 0x93 });
        vault
            .register_always_on_contract(contract(anchor_symbol, slot(), payload, kind, actor))
            .expect("interface and policy NOTE refs register");
    }

    let subject = seed(&vault, 0x95, ENTITY_TYPE_PERSON);
    for rejected in [
        // A `Claim` TAG is refused even when it names a live NOTE entity.
        CodeMemoryPayloadRef::Claim(seed(&vault, 0x94, ENTITY_TYPE_NOTE)),
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
    for offset in 0..CODE_MEMORY_MAX_ALWAYS_ON_CONTRACTS {
        let payload = note(&vault, 0xB0 + u8::try_from(offset).expect("byte"));
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

    let ninth = note(&vault, 0xB9);
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

    for (index, anchor_symbol) in [first, second].into_iter().enumerate() {
        for offset in 0..5u8 {
            let payload = note(
                &vault,
                0xB0 + u8::try_from(index).expect("byte") * 8 + offset,
            );
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
    let payload = note(&vault, 0xC1);
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
        .pull_code_memory(
            reader_key(),
            CodeMemoryPullRequest::new(vec![not_a_symbol]),
        )
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
        .pull_code_memory(reader_key(), CodeMemoryPullRequest::new(vec![anchor_symbol]))
        .expect("pull");
    assert_eq!(pulled.notes.len(), 1);
}
