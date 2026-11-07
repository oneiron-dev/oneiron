//! The topology-audit receipt projector (FIX 7817): one `Gate` receipt per
//! candidate, from its three tables. The post-hoc review is the gate
//! ladder's rung that replaces the pre-check for reversible automatic
//! classes (ARCH-0055 §8), so it projects as the engine's own gate verdict,
//! as the held-out skill-edit verdicts do: same kind, own store, own field
//! class. It leaves the topology events' own receipts as they are. A receipt
//! is local review evidence, never a seal or an owner ruling: it names the
//! reviewed event and its disposition, whether the recipe selected it and
//! under which revision, the attempt that reviewed it, its outcome, its
//! correction and its decision receipt's question.
//!
//! Each answer says its evidence class (L08-A 20:15): a recipe's answer is a
//! declared model judgment, its scorer in the decision receipt and its
//! prompt in the recipe revision; an outcome the reads settled is the
//! engine's. Neither is an owner decision, a human acceptance or a verified
//! success or failure, and nothing here feeds a feedback or attribution
//! lane: a pass invents no positive, and an unknown stays unknown.

use std::collections::BTreeMap;

use super::{
    INTENTS, RESULTS, SELECTIONS, TopologyAuditCorrection, TopologyAuditIntent,
    TopologyAuditResult, TopologyAuditSelection,
};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Result;
use crate::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use crate::vault::Vault;

/// Every candidate's receipt that `query` matches, read in `rtxn`.
///
/// # Errors
///
/// Storage errors, or a row that does not decode.
pub(crate) fn topology_audit_receipts(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let mut receipts = Vec::new();
    for (audit, intent) in INTENTS.scan(&vault.store, rtxn)? {
        let selection = SELECTIONS.get(&vault.store, rtxn, &audit)?;
        let result = RESULTS.get(&vault.store, rtxn, &audit)?;
        let mut fields = scope_fields(&intent);
        let mut occurred_at = intent.created_at;
        let mut actor = None;
        let mut outcome = "pending";
        if let Some(selection) = &selection {
            occurred_at = selection.selected_at;
            selection_fields(selection, &mut fields);
            if !selection.selected {
                outcome = "skipped";
            }
        }
        if let Some(result) = &result {
            occurred_at = result.completed_at;
            actor = result.reviewer.map(|reviewer| reviewer.to_hex());
            outcome = result.outcome.as_str();
            result_fields(result, &mut fields);
        }
        let receipt = ReceiptRecord {
            receipt_id: format!("topology_audit:{}", bytes_to_hex_lower(&audit)),
            receipt_kind: ReceiptKind::Gate,
            occurred_at,
            actor,
            on_behalf_of: None,
            outcome: outcome.to_owned(),
            job_ref: None,
            trigger_ref: Some(format!("event:{}", intent.event.to_hex())),
            policy_trace: Vec::new(),
            fields,
        };
        if query.matches(&receipt) {
            receipts.push(receipt);
        }
    }
    Ok(receipts)
}

/// A selection's fields: the recipe and revision that selected, whether it
/// selected and why, the attempt and its decision's question.
fn selection_fields(selection: &TopologyAuditSelection, fields: &mut BTreeMap<String, String>) {
    fields.insert("recipe".to_owned(), selection.recipe.to_hex());
    fields.insert(
        "recipe_revision".to_owned(),
        bytes_to_hex_lower(&selection.recipe_revision),
    );
    fields.insert("selected".to_owned(), selection.selected.to_string());
    fields.insert("selection_reason".to_owned(), selection.reason.clone());
    fields.insert(
        "selection_attempt".to_owned(),
        bytes_to_hex_lower(&selection.selection_attempt),
    );
    if let Some(question) = decision_question(selection.decision_receipt.as_deref()) {
        fields.insert("selection_decision".to_owned(), question);
    }
    fields.insert(
        "selection_evidence_class".to_owned(),
        selection.evidence.as_str().to_owned(),
    );
}

/// A result's fields: the attempt that reviewed, why, its decision's
/// question and its correction.
fn result_fields(result: &TopologyAuditResult, fields: &mut BTreeMap<String, String>) {
    fields.insert(
        "review_attempt".to_owned(),
        bytes_to_hex_lower(&result.review_attempt),
    );
    fields.insert("review_reason".to_owned(), result.reason.clone());
    if let Some(question) = decision_question(result.decision_receipt.as_deref()) {
        fields.insert("review_decision".to_owned(), question);
    }
    fields.insert(
        "review_evidence_class".to_owned(),
        result.evidence.as_str().to_owned(),
    );
    match &result.correction {
        Some(TopologyAuditCorrection::Undone { event }) => {
            fields.insert("correction".to_owned(), "undone".to_owned());
            fields.insert("correction_event".to_owned(), event.to_hex());
        }
        Some(TopologyAuditCorrection::Refused { reason }) => {
            fields.insert("correction".to_owned(), format!("refused:{reason}"));
        }
        None => {}
    }
}

/// The fields every candidate's receipt carries: its id, the reviewed
/// event and disposition, and its scope.
fn scope_fields(intent: &TopologyAuditIntent) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("audit_id".to_owned(), bytes_to_hex_lower(&intent.audit_id)),
        ("event".to_owned(), intent.event.to_hex()),
        ("disposition".to_owned(), intent.disposition.to_hex()),
        ("op_kind".to_owned(), intent.scope.op_kind.clone()),
        ("target_class".to_owned(), intent.scope.target_class.clone()),
        ("scope_actor".to_owned(), intent.scope.actor.clone()),
    ])
}

/// The question id a stored decision receipt names, as its JSON spells it.
fn decision_question(receipt: Option<&str>) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(receipt?).ok()?;
    let question = value.get("question")?.as_str()?;
    EntityId::from_hex(question).ok().map(|id| id.to_hex())
}
