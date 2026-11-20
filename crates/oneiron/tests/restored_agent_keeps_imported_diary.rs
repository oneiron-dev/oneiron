//! Fix list row RESTORED-AGENT-KEEPS-IMPORTED-DIARY (the lead's ruling
//! IMPORTED-DIARY-RESUBMISSION-INTENT = B, 21 Nov: "a restore should bring
//! things back as they were"). A whole-vault restore brings an agent's diary
//! back with its author kept as an imported one and no `AuthoredBy` edge,
//! and the agent's definition back disabled and proposed. Once the owner
//! reviews and enables the restored agent, it is the author of its own
//! imported diary entries again: it lists and reads them, the diary gate
//! judges another reader's read of them, and it can submit the diary pair
//! link the restore left out again.
//!
//! * `an_enabled_restored_agent_lists_its_imported_diary`: before the
//!   owner's enable the agent's own diary read lists no imported entry;
//!   after it, the entry with its text. A second restored agent with no
//!   grant is never covered.
//! * `an_enabled_restored_agent_reads_its_imported_diary_entry`: the agent's
//!   single NOTE read of the entry holds it before the enable and reads its
//!   text after.
//! * `enabled_restored_agents_resubmit_their_diary_pair_link`: the source's
//!   diary pair link stays out of the restore, counted; once the owner
//!   enables both agents, one of them submits the link again and it holds.
//!
//! Red on main c8a36a0461b: each test's first assertion after the enable
//! fails (no entry listed, the read holds the entry, the link submission is
//! refused: the agent owns no endpoint). Green on the fix.
//!
//! Vaults in tempdirs; every step goes through public doors. The source is
//! rooted, so its owner holds the root owner binding `grant_diary_read`
//! asks for, as `whole_vault_restore_claim_pair_same_as.rs` roots it; the
//! owner's whole-diary grants let the export carry both agents' diaries.
//! The destination installs a keystore and this install's signing keys and
//! opens at least one wall-clock second after its source (sleep 1100 ms).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron --all-features --test restored_agent_keeps_imported_diary`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;
use std::sync::Arc;

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::authority::MachineRole;
use oneiron::batch::export::WholeVaultImportReceipt;
use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeKind;
use oneiron::memory::DiaryReadOutcome;
use oneiron::note::{NoteKind, NoteReadRequest, NoteScope, NoteWriteEnvelope};
use oneiron::store::GateDecisionId;
use oneiron::{
    ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, EdgeActorClass, EntityId, TimeRange,
    Vault, VaultConfig, WriteActor,
};

const NOW: u64 = 1_700_000_000;
const FIRST_MARKDOWN: &str = "the first agent's private thought";
const SECOND_MARKDOWN: &str = "the second agent's private thought";

fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof")
}

/// An enabled, active agent definition the owner creates as `name`.
fn definition(name: &str) -> AgentDefinition {
    AgentDefinition::new(
        name,
        "restored diary fixture",
        "1",
        Some("Keep a diary.\n".to_owned()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::Base,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        rmpv::Value::Map(vec![(
            rmpv::Value::from("definedVia"),
            rmpv::Value::from("define_agent"),
        )]),
        None,
        true,
        None,
    )
}

fn put_diary(vault: &Vault, agent: EntityId, markdown: &str) -> EntityId {
    let receipt = vault
        .memory(agent, EdgeActorClass::Agent)
        .author_note(&NoteWriteEnvelope {
            kind: NoteKind::Diary,
            scope: NoteScope::ActorPrivate { owner_ref: agent },
            markdown: markdown.into(),
            source_revision_ref: [0x7a; 16],
            mask: None,
        })
        .expect("the agent writes a diary entry");
    EntityId::from_hex(&receipt.id_hex).expect("the diary receipt's note id")
}

fn holds_link(vault: &Vault, a: EntityId, b: EntityId) -> bool {
    vault
        .edge_exists(&a, EdgeKind::SameAs, &b)
        .expect("read the link")
        || vault
            .edge_exists(&b, EdgeKind::SameAs, &a)
            .expect("read the link")
}

/// The receipt's `unrestored_same_as_links`, read from its debug text.
fn unrestored_same_as_links(receipt: &WholeVaultImportReceipt) -> Option<usize> {
    let text = format!("{receipt:?}");
    let rest = text.split("unrestored_same_as_links: ").nth(1)?;
    rest.split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()
}

/// A destination the owner restored a source into: two agents, each with
/// one diary entry, the first agent's link between the two entries in the
/// source, and the restore's receipt. Neither agent is enabled yet.
struct Restored {
    _dirs: [tempfile::TempDir; 2],
    dest: Vault,
    dest_owner: AuthenticatedOwner,
    first: EntityId,
    second: EntityId,
    first_entry: EntityId,
    second_entry: EntityId,
    receipt: WholeVaultImportReceipt,
}

fn restored() -> Restored {
    let source_dir = tempfile::tempdir().expect("tempdir");
    let source =
        Vault::open_owned(source_dir.path(), VaultConfig::device()).expect("open the source");
    source.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    source
        .prepare_install_signing()
        .expect("load the source's signing keys");
    let issuer = source
        .bootstrap_host_slip_issuer()
        .expect("the source's host issuer");
    source
        .ensure_host_root_slip(&issuer)
        .expect("root the source under its host");
    source
        .provision_engine_machine_identities(&issuer)
        .expect("the source's engine machine identities");
    source
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("the source's serving install profile");
    let proof = owner_proof(&source);
    let owner = source
        .ensure_embedded_owner_actor()
        .expect("the source's owner");
    let first = EntityId::now();
    let second = EntityId::now();
    for (agent, name) in [(first, "ada"), (second, "bo")] {
        source
            .create_agent_definition_as(
                &proof,
                &agent,
                &definition(name),
                TimeRange {
                    start: NOW,
                    end: NOW,
                },
                NOW,
            )
            .expect("the owner creates the agent");
    }
    let first_entry = put_diary(&source, first, FIRST_MARKDOWN);
    let second_entry = put_diary(&source, second, SECOND_MARKDOWN);
    let as_owner = source.memory(owner, EdgeActorClass::Human);
    for agent in [first, second] {
        as_owner
            .grant_diary_read(
                &proof,
                WriteActor::new(owner, EdgeActorClass::Human),
                agent,
                &[],
            )
            .expect("the owner may read, and so export, the agent's diary");
    }
    source
        .memory(first, EdgeActorClass::Agent)
        .link_diary_coreference(first_entry, second_entry)
        .expect("the first agent links the diary pair");
    assert!(
        holds_link(&source, first_entry, second_entry),
        "precondition: the source holds the diary pair link"
    );
    let archive = source
        .export_whole_vault(true)
        .expect("whole-vault export")
        .bytes()
        .to_vec();

    // testkit-lint: allow(sleep) built-in pack seeds use real wall seconds
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let dest_dir = tempfile::tempdir().expect("temp dir");
    let dest = Vault::open(dest_dir.path(), VaultConfig::device()).expect("open vault");
    dest.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    dest.prepare_install_signing()
        .expect("load this install's signing keys");
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner's restore completes");
    assert!(
        dest.entity_exists(&first_entry).expect("read the diary")
            && dest.entity_exists(&second_entry).expect("read the diary"),
        "precondition: both diary entries come back, as imported notes"
    );
    Restored {
        _dirs: [source_dir, dest_dir],
        dest,
        dest_owner,
        first,
        second,
        first_entry,
        second_entry,
        receipt,
    }
}

impl Restored {
    /// The owner reviews restored agent `agent` and turns it on, as after
    /// any restore.
    fn enable(&self, agent: EntityId) {
        let mut definition = self
            .dest
            .get_agent_definition(&agent)
            .expect("read the restored definition")
            .expect("the destination holds the restored agent");
        assert!(
            !definition.enabled && definition.source == ClaimSource::Imported,
            "precondition: the restore brings the agent back switched off, marked imported"
        );
        definition.enabled = true;
        definition.approval_status = ClaimApprovalStatus::Approved;
        definition.version = "2".to_owned();
        self.dest
            .update_agent_definition_as(
                &self.dest_owner,
                &agent,
                &definition,
                TimeRange { start: 2, end: 2 },
                2,
            )
            .expect("the owner enables the restored agent");
    }

    /// The ids and texts `reader`'s read of `agent`'s diary returns, or
    /// `None` when it is not granted.
    fn diary(&self, reader: EntityId, agent: EntityId) -> Option<Vec<(EntityId, String)>> {
        match self
            .dest
            .memory(reader, EdgeActorClass::Agent)
            .read_agent_diary(None, agent, "self review")
        {
            Ok(DiaryReadOutcome::Granted { entries, .. }) => Some(
                entries
                    .into_iter()
                    .map(|entry| (entry.id, entry.markdown))
                    .collect(),
            ),
            _ => None,
        }
    }

    /// The text `reader`'s single NOTE read of `note` returns, `None` when
    /// the read holds it, or the refusal.
    fn read(&self, reader: EntityId, note: EntityId) -> Result<Option<String>, String> {
        self.dest
            .memory(reader, EdgeActorClass::Agent)
            .read_note(&NoteReadRequest {
                note_ref: note.to_hex(),
                reason: Some("self review".to_owned()),
                version: None,
                spans: Vec::new(),
            })
            .map(|result| result.value.map(|view| view.markdown))
            .map_err(|error| format!("{error:?}"))
    }
}

#[test]
fn an_enabled_restored_agent_lists_its_imported_diary() {
    let restored = restored();
    let first = restored.first;
    assert!(
        !restored
            .diary(first, first)
            .unwrap_or_default()
            .iter()
            .any(|(id, _)| *id == restored.first_entry),
        "before the owner's enable the restored agent lists no imported entry"
    );
    restored.enable(first);
    assert_eq!(
        restored.diary(first, first),
        Some(vec![(restored.first_entry, FIRST_MARKDOWN.to_owned())]),
        "once enabled, the restored agent lists its own imported diary entry"
    );
    restored.enable(restored.second);
    assert_eq!(
        restored.diary(restored.second, first),
        None,
        "another agent with no grant is not covered for the restored diary"
    );
    assert_eq!(
        restored.diary(restored.second, restored.second),
        Some(vec![(restored.second_entry, SECOND_MARKDOWN.to_owned())]),
        "the second agent lists only its own entry"
    );
}

#[test]
fn an_enabled_restored_agent_reads_its_imported_diary_entry() {
    let restored = restored();
    let first = restored.first;
    assert!(
        !matches!(restored.read(first, restored.first_entry), Ok(Some(_))),
        "before the owner's enable the read holds the imported entry"
    );
    restored.enable(first);
    assert_eq!(
        restored.read(first, restored.first_entry),
        Ok(Some(FIRST_MARKDOWN.to_owned())),
        "once enabled, the restored agent reads its own imported entry"
    );
    assert!(
        !matches!(restored.read(first, restored.second_entry), Ok(Some(_))),
        "the other agent's imported entry stays held"
    );
}

#[test]
fn enabled_restored_agents_resubmit_their_diary_pair_link() {
    let restored = restored();
    let (first_entry, second_entry) = (restored.first_entry, restored.second_entry);
    assert!(
        !holds_link(&restored.dest, first_entry, second_entry),
        "precondition: the diary pair link stays out of the restore"
    );
    assert_eq!(
        unrestored_same_as_links(&restored.receipt),
        Some(1),
        "precondition: the receipt counts the diary pair link left out"
    );
    restored.enable(restored.first);
    restored.enable(restored.second);
    restored
        .dest
        .memory(restored.first, EdgeActorClass::Agent)
        .link_diary_coreference(first_entry, second_entry)
        .expect("the enabled restored agent submits its diary pair link");
    assert!(
        holds_link(&restored.dest, first_entry, second_entry),
        "the resubmitted diary pair link holds"
    );
}
