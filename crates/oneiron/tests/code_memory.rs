//! ARCH-0050 R6 L2 memory-over-code attachment mechanics — public contract
//! suite (ONE-1608).
//!
//! Every test here reaches ONLY `Vault`. Nothing in this file names `Store`,
//! a heed transaction, or a raw metadata key: if a rule cannot be observed
//! through the public door, it is not a public contract. Codec, key, pure
//! merge-algebra, and crate-seam side-effect coverage lives in
//! `src/code_memory.rs`'s in-module block instead.

use oneiron::authority::{HostSlipIssuer, SlipCaveat};
use oneiron::claim::{ScopedReadActorKey, base_world_id};
use oneiron::code_document::CodeSpanAnchor;
use oneiron::code_memory::{
    AlwaysOnCodeMemoryContract, AnchorTransfer, AnchorTransferKind, AttachCodeMemory,
    BlocksWriteContext, CODE_MEMORY_MAX_ALWAYS_ON_CONTRACTS, CodeMemoryAnchor,
    CodeMemoryContractKind, CodeMemoryLocator, CodeMemoryPayloadRef, CodeMemoryPullRequest,
    CodeMemoryPullResult, CodeMemorySlotName, CodeMemorySlotValue, ProvenanceMaterialKind,
    SlotInsertOutcome,
};
use oneiron::deletion::DeleteReason;
use oneiron::error::{CodeError, RegistryError};
use oneiron::federation::{Scope, ScopeAxis, ScopeId, Sensitivity, SensitivityCeiling};
use oneiron::note::TakeTarget;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EdgeKind, EntityId, Error, TimeRange, Vault, VaultConfig, WriteActor,
};
use rmpv::Value;
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

use oneiron::registry::{ENTITY_TYPE_CODE_SYMBOL, ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON};

/// The fixture's NOTE author, and the subject its takes are about. Both are
/// ordinary PERSONs: `put_entity` still admits every non-NOTE type.
const NOTE_AUTHOR: u8 = 0x11;
const NOTE_SUBJECT: u8 = 0x12;

fn vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    // The host installs this device's keystore after each open; the deletion
    // and signing doors load this install's keys from it (P6c).
    vault.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
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
    )
    .expect("fixture");
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

/// A locator is a cursor-anchored span on the symbol's file document at one
/// version (FIX 7810, 029b5966b0a, replaced the path-at-revision locator).
/// Each `path` gets its own cursors, so two paths never share a locator.
fn locator(path: &str) -> CodeMemoryLocator {
    CodeMemoryLocator {
        span: CodeSpanAnchor {
            document_id: [0xD0; 32],
            start: path.as_bytes().to_vec(),
            end: path.as_bytes().to_vec(),
            content_hash: [0xD1; 32],
        },
        version: vec![(1, 0)],
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

/// The locator STORED on `symbol_id`'s attachment row for `payload` — the
/// locator half of the dual anchor as it actually persists, read back
/// through the public attachment door.
fn attachment_locator(
    vault: &Vault,
    symbol_id: EntityId,
    payload: CodeMemoryPayloadRef,
) -> CodeMemoryLocator {
    let rows = vault
        .code_memory_attachments(symbol_id)
        .expect("attachment rows");
    let row = rows
        .into_iter()
        .find(|attachment| attachment.payload == payload)
        .expect("the surviving payload keeps an attachment row");
    row.anchor.locator
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

/// Explicit base-world read proof for positives: the host root slip
/// attenuated to base `read` only. Never a wildcard global fixture beyond
/// base, and never a plain key (plain keys with no grant deny by design).
fn base_read_scope() -> Scope {
    Scope {
        worlds: ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())])),
        facets: ScopeAxis::All,
        bands: ScopeAxis::All,
        audience: ScopeAxis::All,
        verbs: ScopeAxis::Some(BTreeSet::from(["read".to_owned()])),
        sensitivity: SensitivityCeiling::AtMost(Sensitivity::Restricted),
    }
}

fn reader_key_for(vault: &Vault) -> ScopedReadActorKey {
    let issuer = HostSlipIssuer::from_secret(b"code-memory-test-host-secret").expect("host issuer");
    let mut slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("host root slip");
    issuer
        .attenuate(
            &mut slip,
            SlipCaveat {
                scope: Some(base_read_scope()),
                ..Default::default()
            },
        )
        .expect("narrow root to base read");
    let challenge = b"code-memory-read";
    let proof_bytes = issuer
        .binding_proof(&slip, challenge)
        .expect("binding proof");
    let verified = vault
        .verify_capability_slip(&issuer.public_key(), &slip, challenge, &proof_bytes)
        .expect("verified base-read slip");
    ScopedReadActorKey::from_verified_slip(&verified).expect("read key")
}

// ---------------------------------------------------------------------------
// Anchor identity and transfer
// ---------------------------------------------------------------------------

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

/// The LOCATOR IS PER PAYLOAD, never per operation.
///
/// A second attach into the same slot may not restamp the first payload's
/// locator, and a transfer relabels only what it actually moved:
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
        attachment_locator(&vault, from, first),
        locator("src/first.rs"),
        "the older payload keeps the locator it was attached under"
    );
    assert_eq!(
        attachment_locator(&vault, from, second),
        locator("src/second.rs")
    );

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
        attachment_locator(&vault, to, destination_only),
        locator("src/destination.rs"),
        "a payload this transfer never moved is not relabelled by `to_locator`"
    );
    for moved in [first, second] {
        assert_eq!(
            attachment_locator(&vault, to, moved),
            locator("src/after.rs"),
            "a payload that DID move carries the transfer's own locator"
        );
    }

    assert_eq!(
        attachment_locator(&vault, from, first),
        locator("src/first.rs"),
        "a copy leaves the source locators untouched too"
    );
    assert_eq!(
        attachment_locator(&vault, from, second),
        locator("src/second.rs")
    );
}

// ---------------------------------------------------------------------------
// Slots
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// `EdgeKind::Blocks`
// ---------------------------------------------------------------------------

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
    assert!(matches!(
        create,
        Error::Registry(RegistryError::ReservedEdgeKind("blocks"))
    ));

    let delete = vault
        .delete_edge(&blocker, EdgeKind::Blocks, &blocked)
        .expect_err("generic deletion is reserved");
    assert!(matches!(
        delete,
        Error::Registry(RegistryError::ReservedEdgeKind("blocks"))
    ));

    assert!(
        vault.blocks_dependencies(blocker).expect("read").is_empty(),
        "a refused generic write leaves no edge behind"
    );
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
    assert!(matches!(
        system,
        Error::Code(CodeError::CodeMemoryBlocksActorDenied(_))
    ));

    // A MACHINE entity presented through a `WriteActor` ASSERTING Human: the
    // stored entity type refuses the class, so the assertion buys nothing.
    let forged = WriteActor::new(id(0x78), EdgeActorClass::Human);
    let mismatch = vault
        .insert_blocks_edge(a, c, blocks_context(&forged))
        .expect_err("a forged actor class is refused");
    assert!(matches!(
        mismatch,
        Error::Code(CodeError::CodeMemoryBlocksActorDenied(_))
    ));

    let ghost = WriteActor::new(id(0x79), EdgeActorClass::Human);
    let unresolved = vault
        .insert_blocks_edge(a, c, blocks_context(&ghost))
        .expect_err("an unresolvable actor is refused");
    assert!(matches!(
        unresolved,
        Error::Code(CodeError::CodeMemoryBlocksActorDenied(_))
    ));

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
            Error::Code(CodeError::CodeMemoryBlocksSourceUntrusted { .. })
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
            Err(Error::Registry(RegistryError::ReservedEdgeKind("blocks")))
        ),
        "generic deletion stays reserved even after the edge is gone"
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
            reader_key_for(&vault),
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
            reader_key_for(&vault),
            CodeMemoryPullRequest::new(vec![anchor_symbol]),
        )
        .expect("an unreadable payload must never fail the pull");

    assert_eq!(
        pulled_payloads(&pulled),
        vec![permitted],
        "the shell is skipped and the readable note still comes back"
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
        assert!(matches!(
            error,
            Error::Code(CodeError::CodeMemoryAlwaysOnInvalid(_))
        ));
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
/// counts KEYS: without this sweep eight deleted NOTEs would count against a
/// live symbol forever while the readers went on publishing refs to
/// material that no longer exists. The bound is observed, never refused
/// (rule 5, FIX 8562): a ninth live registration is kept. The surviving
/// note is the control — the sweep removes references, not slots.
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
    // Rule 5 (f8b2b9107a0, FIX 8562): eight live registrations reach the
    // bound, which is observed and never refuses; the ninth is kept.
    vault
        .register_always_on_contract(contract(
            anchor_symbol,
            slot(),
            ninth,
            CodeMemoryContractKind::Interface,
            actor,
        ))
        .expect("a ninth live registration is kept past the bound");
    assert_eq!(
        vault
            .code_memory_always_on_contracts(anchor_symbol)
            .expect("read")
            .len(),
        CODE_MEMORY_MAX_ALWAYS_ON_CONTRACTS + 1,
        "the bound keeps every contract"
    );

    for payload in &payloads {
        vault
            .batch()
            .delete(&payload.entity_id())
            .commit()
            .expect("hard-delete the NOTE payload");
    }

    let contracts: Vec<CodeMemoryPayloadRef> = vault
        .code_memory_always_on_contracts(anchor_symbol)
        .expect("read")
        .into_iter()
        .map(|contract| contract.payload)
        .collect();
    assert_eq!(
        contracts,
        vec![ninth],
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
        .expect("re-registering the live ninth is an idempotent upsert");
    let after = vault
        .code_memory_always_on_contracts(anchor_symbol)
        .expect("read");
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].payload, ninth);
}
