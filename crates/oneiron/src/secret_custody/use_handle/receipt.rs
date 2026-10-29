//! A use's Gate records (FIX 2622): the intent a use commits before its
//! send, and the outcome it appends once the send and the clearing are
//! done, linked to that intent. A crash between them leaves the intent
//! alone, its send `pending`: sent or not, unknown. Nothing writes an
//! invented outcome for it. A refused admission writes one outcome, with no
//! intent.

use super::{
    SECRET_USE_REASON, SecretUseDecision, SecretUseReceipt, SecretUseSend, SecretUser,
    SentPresentation,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord};
use crate::vault::Vault;

/// The Gate content kind of every use's record.
const SECRET_USE_CONTENT_KIND: &str = "secret_use";

/// Domain of a use record's diff handle: a digest of what was used, by
/// what, never of the value.
const USE_DIFF_DOMAIN: &[u8] = b"oneiron.secret_use.v1";

/// Which of a use's records one is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UsePhase {
    /// Committed before the send, its send `pending`.
    Intent,
    /// Appended after the send, linked to its intent; a refused
    /// admission's one record.
    Outcome,
}

impl UsePhase {
    /// The word in the record's details.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Intent => "intent",
            Self::Outcome => "outcome",
        }
    }
}

/// One use as its Gate records keep it.
#[derive(Clone)]
pub(super) struct Used<'a> {
    pub(super) user: SecretUser,
    pub(super) handle: String,
    pub(super) secret: EntityId,
    pub(super) generation: u32,
    pub(super) operation: &'a str,
    pub(super) effector: &'a str,
    /// The grant a lease-aware use redeemed (FIX 4313), if any.
    pub(super) grant: Option<EntityId>,
}

impl Used<'_> {
    /// This use at the generation its send released for the handle's own
    /// record, never the admitted one in its place when it said (FIX 8052).
    pub(super) fn at_sent(&self, sent: Option<SentPresentation>) -> Self {
        Self {
            generation: sent
                .filter(|sent| sent.custody == self.secret)
                .map_or(self.generation, |sent| sent.generation),
            ..self.clone()
        }
    }

    /// This use's Gate record of `phase` and its receipt: an outcome names
    /// the intent it answers; `presented` is what its send actually
    /// presented, when it said.
    pub(super) fn record(
        &self,
        vault: &Vault,
        phase: UsePhase,
        intent: Option<GateDecisionId>,
        decision: SecretUseDecision,
        send: SecretUseSend,
        presented: Option<SentPresentation>,
    ) -> Result<SecretUseReceipt> {
        let decision_id = GateDecisionId::from_bytes(vault.store.clock.ulid()?);
        let generation = self.generation.to_be_bytes();
        let parts: [&[u8]; 5] = [
            USE_DIFF_DOMAIN,
            self.secret.as_bytes(),
            &generation,
            self.operation.as_bytes(),
            self.effector.as_bytes(),
        ];
        let mut digest = blake3::Hasher::new();
        for part in parts {
            digest.update(&(part.len() as u64).to_be_bytes());
            digest.update(part);
        }
        let mut details = vec![
            format!("use:{}", self.operation),
            format!("handle:{}", self.handle),
            format!("generation:{}", self.generation),
            format!("effector:{}", self.effector),
            format!("decision:{}", decision.as_str()),
            format!("send:{}", send.as_str()),
            format!("phase:{}", phase.as_str()),
        ];
        if let Some(intent) = intent {
            details.push(format!("intent:{}", intent.to_hex()));
        }
        if let Some(grant) = self.grant {
            details.push(format!("grant:{}", grant.to_hex()));
        }
        if let Some(presented) = presented {
            details.push(format!("presented:{}", presented.custody.to_hex()));
            details.push(format!("presented_generation:{}", presented.generation));
        }
        let used_at = vault.with_write_txn_grouped(|txn| {
            let created_at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
            let record = GateDecisionRecord {
                version: GATE_DECISION_LEDGER_VERSION,
                decision_id,
                created_at,
                outcome: match decision {
                    SecretUseDecision::Used => "approved",
                    SecretUseDecision::Refused => "denied",
                }
                .into(),
                reason_codes: vec![SECRET_USE_REASON.into()],
                receipt_reasons: Vec::new(),
                system_notices: crate::store::GateSystemNoticeRecord::receipt_details(
                    SECRET_USE_CONTENT_KIND,
                    details,
                ),
                actor_class: self.user.actor_class.gate_actor_class().into(),
                actor_ref: Some(self.user.actor.to_hex()),
                content_kind: SECRET_USE_CONTENT_KIND.into(),
                policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.into(),
                claim_id: None,
                grant_ref: None,
                diff_handle: digest.finalize().as_bytes().to_vec(),
                read_frontier_hash: [0; 32],
                context: Default::default(),
                redacted_at: None,
            };
            vault.store.append_gate_decision_in_txn(txn, &record)?;
            Ok(created_at)
        })?;
        Ok(SecretUseReceipt {
            handle: self.handle.clone(),
            generation: self.generation,
            presented,
            effector: self.effector.to_owned(),
            operation: self.operation.to_owned(),
            decision,
            send,
            receipt: decision_id,
            used_at,
        })
    }
}
