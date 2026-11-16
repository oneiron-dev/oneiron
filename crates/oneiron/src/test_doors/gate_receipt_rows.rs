//! Doors for `tests/gate_receipt_rows.rs` and `tests/gate_receipt_mint.rs`
//! (UC-03 PR 0): one Gate ledger row read back by its id, the read frontier
//! of the policy the vault resolves to now, and the receipt draft minted
//! through the one writer with each of its forms, and through its bound half.
//! For `tests/gate_receipt_closed_outcome.rs` (UC-03 PR 2-1a): a row stored
//! with a word written before stage 1f. For `tests/gate_owner_answer_words.rs`
//! (UC-03 PR 5): whether the owner restore group's read takes a row.

use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::gate_reason::GateReceiptOutcome;
use crate::store::{
    GateDecisionId, GateDecisionRecord, GateEnginePart, GateReceipt, GateSystemNoticeRecord,
    PolicyBasis, ReceiptActor,
};
use crate::vault::Vault;
use crate::write_envelope::WriteActor;
use oneiron_contracts::RecordedSeconds;

/// The Gate ledger row `decision` names, as the store decodes it.
pub fn gate_row(vault: &Vault, decision: GateDecisionId) -> Result<Option<GateDecisionRecord>> {
    let txn = vault.store.env.read_txn()?;
    vault.store.gate_decision_in_txn(&txn, decision)
}

/// The read frontier of the policy manifest the vault resolves to now.
pub fn policy_frontier(vault: &Vault) -> Result<[u8; 32]> {
    let txn = vault.store.env.read_txn()?;
    crate::gate::resolve_policy_manifest(&vault.store, &txn)?.read_frontier_hash()
}

/// The content kind of the drafts below.
pub const GUARD_KIND: &str = "uc03_receipt_guard";
/// Their reason code.
pub const GUARD_REASON: &str = "gate.uc03.receipt_guard";
/// The receipt reason of the full draft.
pub const GUARD_RECEIPT_REASON: &str = "gate.allow.uc03_receipt_guard";
/// The read frontier of the full draft.
pub const GUARD_FRONTIER: [u8; 32] = [7; 32];
/// The policy version of the full draft.
pub const GUARD_POLICY_VERSION: &str = "0.9";

/// A draft with every optional field set, about `claim`, decided by the
/// person `owner`, recorded through `Store::record_gate_receipt_in_txn`.
/// The row it appended.
pub fn record_full_receipt(
    vault: &Vault,
    owner: EntityId,
    claim: EntityId,
) -> Result<GateDecisionRecord> {
    let mut receipt = GateReceipt::new(
        GateReceiptOutcome::ApprovedAmended,
        GUARD_KIND,
        GUARD_REASON,
        ReceiptActor::human(owner),
        b"guard-handle".to_vec(),
        PolicyBasis::versioned(GUARD_FRONTIER, GUARD_POLICY_VERSION),
    );
    receipt.about = Some(claim);
    receipt.grant_ref = Some("uc03:guard".to_owned());
    receipt.details = vec!["first:1".to_owned(), "second:2".to_owned()];
    receipt.notices = GateSystemNoticeRecord::receipt_details("uc03_other", vec!["third:3".into()]);
    receipt.receipt_reasons = vec![GUARD_RECEIPT_REASON.to_owned()];
    vault.with_write_txn(|txn| vault.store.record_gate_receipt_in_txn(txn, receipt))
}

/// The six actor forms, minted (not appended) in one transaction: a person,
/// an agent row, the engine, two engine parts, and a class kept verbatim.
/// Each row's `(actor_class, actor_ref)`.
pub fn minted_actor_fields(
    vault: &Vault,
    person: EntityId,
    agent: EntityId,
) -> Result<Vec<(String, Option<String>)>> {
    let actors = [
        ReceiptActor::human(person),
        ReceiptActor::Row(WriteActor::new(agent, EdgeActorClass::Agent)),
        ReceiptActor::Engine,
        ReceiptActor::Part(GateEnginePart::PolicyModel, Some("plane:owner".to_owned())),
        ReceiptActor::Part(GateEnginePart::BookingHttpGuard, None),
        ReceiptActor::Verbatim {
            class: "pack-connection".to_owned(),
            actor_ref: Some("connection:1".to_owned()),
        },
    ];
    vault.with_write_txn(|txn| {
        actors
            .into_iter()
            .map(|actor| {
                let receipt = guard_receipt(actor, PolicyBasis::NOT_READ);
                let row = vault.store.mint_gate_receipt_in_txn(txn, receipt)?;
                Ok((row.actor_class, row.actor_ref))
            })
            .collect()
    })
}

/// The four policy-basis forms, minted (not appended) in one transaction:
/// no policy read, a frontier, a versioned frontier, and the basis of the
/// versioned row. Each row's `(read_frontier_hash, policy_manifest_version)`.
pub fn minted_basis_fields(vault: &Vault) -> Result<Vec<([u8; 32], String)>> {
    vault.with_write_txn(|txn| {
        let mut fields = Vec::new();
        let mut versioned = None;
        for basis in [
            PolicyBasis::NOT_READ,
            PolicyBasis::frontier([3; 32]),
            PolicyBasis::versioned(GUARD_FRONTIER, GUARD_POLICY_VERSION),
        ] {
            let row = vault
                .store
                .mint_gate_receipt_in_txn(txn, guard_receipt(ReceiptActor::Engine, basis))?;
            fields.push((row.read_frontier_hash, row.policy_manifest_version.clone()));
            versioned = Some(row);
        }
        if let Some(earlier) = versioned {
            let basis = PolicyBasis::of(&earlier);
            let row = vault
                .store
                .mint_gate_receipt_in_txn(txn, guard_receipt(ReceiptActor::Engine, basis))?;
            fields.push((row.read_frontier_hash, row.policy_manifest_version));
        }
        Ok(fields)
    })
}

/// A draft that binds `decision` and records a decision made at `at`,
/// recorded through `Store::record_gate_receipt_in_txn`.
pub fn record_bound_receipt(
    vault: &Vault,
    decision: GateDecisionId,
    at: u64,
) -> Result<GateDecisionRecord> {
    let mut receipt = guard_receipt(ReceiptActor::Engine, PolicyBasis::NOT_READ);
    receipt.id = Some(decision);
    receipt.decided_at = Some(RecordedSeconds::from_secs(at));
    vault.with_write_txn(|txn| vault.store.record_gate_receipt_in_txn(txn, receipt))
}

/// The guard draft with `decision` and `at` as given, built by the mint's
/// bound half alone (`GateReceipt::mint_bound`), with no vault.
pub fn mint_bound_receipt(
    decision: Option<GateDecisionId>,
    at: Option<u64>,
) -> Result<GateDecisionRecord> {
    let mut receipt = guard_receipt(ReceiptActor::Engine, PolicyBasis::NOT_READ);
    receipt.id = decision;
    receipt.decided_at = at.map(RecordedSeconds::from_secs);
    receipt.mint_bound()
}

/// Two drafts that take fresh ids and the recording clock, recorded in one
/// transaction. Both rows, in order.
pub fn record_two_fresh_receipts(vault: &Vault) -> Result<[GateDecisionRecord; 2]> {
    vault.with_write_txn(|txn| {
        let first = vault.store.record_gate_receipt_in_txn(
            txn,
            guard_receipt(ReceiptActor::Engine, PolicyBasis::NOT_READ),
        )?;
        let second = vault.store.record_gate_receipt_in_txn(
            txn,
            guard_receipt(ReceiptActor::Engine, PolicyBasis::NOT_READ),
        )?;
        Ok([first, second])
    })
}

/// A row stored as a writer before UC-03 stage 1f stored it: the smallest
/// draft minted, its outcome replaced by `word` and its content kind by
/// `content_kind`, then appended through the ledger's own append. The row as
/// appended.
pub fn append_held_word_row(
    vault: &Vault,
    word: &str,
    content_kind: &str,
) -> Result<GateDecisionRecord> {
    vault.with_write_txn(|txn| {
        let mut row = vault.store.mint_gate_receipt_in_txn(
            txn,
            guard_receipt(ReceiptActor::Engine, PolicyBasis::NOT_READ),
        )?;
        word.clone_into(&mut row.outcome);
        content_kind.clone_into(&mut row.content_kind);
        vault.store.append_gate_decision_in_txn(txn, &row)?;
        Ok(row)
    })
}

/// Whether the owner restore group's receipt read (DESIGN R16,
/// `owner_restore_receipt_in_txn`) takes the row `decision` names as an
/// owner archive-restore yes. For `tests/gate_owner_answer_words.rs` (UC-03 PR 5).
pub fn owner_restore_receipt_taken(vault: &Vault, decision: GateDecisionId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    Ok(
        crate::batch::export::owner_restore_receipt_in_txn(&vault.store, &txn, &decision.to_hex())?
            .is_some(),
    )
}

/// The smallest draft: `noted`, the guard kind and reason, a one-byte handle.
fn guard_receipt(actor: ReceiptActor, basis: PolicyBasis) -> GateReceipt {
    GateReceipt::new(
        GateReceiptOutcome::Noted,
        GUARD_KIND,
        GUARD_REASON,
        actor,
        vec![1],
        basis,
    )
}
