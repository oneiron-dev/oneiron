//! The receipt of each answer the host sends a connector's questions
//! (ONE-2510, FIX 3840): receipt-only, on the owner-local gate ledger, as
//! the sandbox's egress receipts are.
//!
//! Each answer, and each round the host ends unanswered, leaves one gate
//! ledger record: the original call's principal, grant, governing key and
//! parent intent, the round, each question's disposition (accept, decline,
//! cancel, expired), the digest of the exact responses and how their POST
//! went. Ids, digests and dispositions only: never an answer, a question or
//! the round's handle. It decides nothing: it is written after the send
//! decision was made and the bytes went (or did not), and a receipt that
//! cannot be written is logged by its caller, never a refusal.

use crate::Vault;
use crate::entity_id::bytes_to_hex_lower;
use crate::store::{GateDecisionId, GateDecisionRecord, GateSystemNoticeRecord};

use super::execution::ConnectorElicitationBinding;

/// The receipt's content kind on the gate ledger.
const RECEIPT_KIND: &str = "elicitation_answer";

/// The audit channel its details are written under.
const RECEIPT_CHANNEL: &str = "connector.elicitation_answer";

/// Its one reason code.
const RECEIPT_REASON: &str = "gate.connector.elicitation_answer";

/// The actor class a receipt names its principal under.
const RECEIPT_ACTOR_CLASS: &str = "connector_caller";

/// The most dispositions one detail line lists, so each stays well within
/// the gate notice's body bound; a longer round takes more lines, in order.
const DISPOSITIONS_PER_DETAIL: usize = 64;

/// What one question of a round was answered with, as it went or as the
/// host ended it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElicitationDisposition {
    Accept,
    Decline,
    Cancel,
    /// The round lapsed unanswered; the host ended it.
    Expired,
}

impl ElicitationDisposition {
    fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Decline => "decline",
            Self::Cancel => "cancel",
            Self::Expired => "expired",
        }
    }
}

/// How the POST that carried an answer went, or that none was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElicitationEgress {
    /// The connector took it.
    Accepted,
    /// The connector refused it.
    Refused,
    /// It never left.
    Unsent,
    /// It may have reached the connector.
    Uncertain,
    /// Nothing was sent for this round.
    NotSent,
}

impl ElicitationEgress {
    fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Refused => "refused",
            Self::Unsent => "unsent",
            Self::Uncertain => "uncertain",
            Self::NotSent => "not_sent",
        }
    }
}

/// One answer's receipt: what was sent for one round of one live question
/// set, under which call.
#[derive(Debug, Clone, Copy)]
pub struct ConnectorElicitationReceipt<'a> {
    pub binding: &'a ConnectorElicitationBinding,
    /// The original call's ledger intent.
    pub parent_intent: Option<[u8; 32]>,
    /// The digest of the live question set's handle, never the handle.
    pub question_set: [u8; 32],
    pub generation: u64,
    /// Each question's disposition, in the order of its key.
    pub dispositions: &'a [ElicitationDisposition],
    /// The digest of the exact responses sent, or of none.
    pub answer_digest: [u8; 32],
    pub egress: ElicitationEgress,
}

impl ConnectorElicitationReceipt<'_> {
    /// The receipt's audit lines: ids, digests and dispositions.
    fn details(&self) -> Vec<String> {
        let binding = self.binding;
        let mut details = vec![
            format!("connector name={}", binding.name),
            format!("connector server={}", binding.server),
            format!("connector tool={}", binding.tool),
            format!(
                "call principal={} grant={} key={} endpoint_digest={} parent_intent={}",
                binding.principal_ref,
                binding.grant_id.to_hex(),
                binding.key_ref.to_hex(),
                bytes_to_hex_lower(blake3::hash(binding.endpoint.as_bytes()).as_bytes()),
                self.parent_intent
                    .map_or_else(|| "none".to_owned(), |intent| bytes_to_hex_lower(&intent)),
            ),
            format!(
                "round question_set={} generation={} questions={} egress={} answer_digest={}",
                bytes_to_hex_lower(&self.question_set),
                self.generation,
                self.dispositions.len(),
                self.egress.as_str(),
                bytes_to_hex_lower(&self.answer_digest),
            ),
        ];
        for (at, chunk) in self
            .dispositions
            .chunks(DISPOSITIONS_PER_DETAIL)
            .enumerate()
        {
            let from = at * DISPOSITIONS_PER_DETAIL;
            let listed: Vec<&str> = chunk
                .iter()
                .map(|disposition| disposition.as_str())
                .collect();
            details.push(format!("dispositions from={from} {}", listed.join(",")));
        }
        details
    }
}

impl Vault {
    /// Writes one answer's receipt on the gate ledger and returns its ref
    /// (`gate:<id>`). Receipt-only: it decides nothing and admits nothing.
    ///
    /// # Errors
    ///
    /// Storage errors. Its caller logs them; the answer it receipts has
    /// already gone or not.
    pub fn append_connector_elicitation_receipt(
        &self,
        receipt: &ConnectorElicitationReceipt<'_>,
    ) -> crate::Result<String> {
        let mut txn = self.store.env.write_txn()?;
        let created_at = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
        let decision_id = GateDecisionId::from_bytes(self.store.clock.ulid()?);
        self.store.append_gate_decision_in_txn(
            &mut txn,
            &GateDecisionRecord {
                version: 0,
                decision_id,
                created_at,
                outcome: receipt.egress.as_str().to_owned(),
                reason_codes: vec![RECEIPT_REASON.to_owned()],
                receipt_reasons: Vec::new(),
                system_notices: GateSystemNoticeRecord::receipt_details(
                    RECEIPT_CHANNEL,
                    receipt.details(),
                ),
                actor_class: RECEIPT_ACTOR_CLASS.to_owned(),
                actor_ref: Some(receipt.binding.principal_ref.clone()),
                content_kind: RECEIPT_KIND.to_owned(),
                policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.into(),
                claim_id: None,
                grant_ref: Some(receipt.binding.grant_id.to_hex()),
                diff_handle: receipt.answer_digest.to_vec(),
                read_frontier_hash: [0; 32],
                redacted_at: None,
            },
        )?;
        txn.commit()?;
        Ok(format!("gate:{}", decision_id.to_hex()))
    }
}
