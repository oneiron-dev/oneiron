//! A use's Gate records (FIX 2622): the intent a use commits before its
//! send, and the outcome it appends once the send and the clearing are
//! done, linked to that intent. A crash between them leaves the intent
//! alone, its send `pending`: sent or not, unknown. Nothing writes an
//! invented outcome for it. A refused admission writes one outcome, with no
//! intent.
//!
//! A held `connector.call` keeps what its use was ([`SecretUseContext`]) on
//! its row, and a resume that sends it later writes a pair of its own for
//! that pass, before and after the send, from what the host saw it send
//! (FIX 2822): both name the first use's intent, so every later pair links
//! to the first.

use serde::{Deserialize, Serialize};

use super::{
    SECRET_USE_REASON, SecretUseDecision, SecretUseReceipt, SecretUseSend, SecretUser,
    SentPresentation,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::secret_custody::RunSecretHolder;
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

/// What a `self.use` connector call keeps of the use that made it
/// (FIX 2822): the use's intent record, who used which record's handle at
/// which generation, for what, and the run whose seat found the record.
/// Ids and names only, never a value. A resume that sends the call writes
/// its own records, linked to that intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SecretUseContext {
    /// The use's intent record: the first of a held call's.
    pub(crate) intent: GateDecisionId,
    pub(crate) actor: EntityId,
    #[serde(with = "crate::secret_custody::run_bound::actor_class_byte")]
    pub(crate) actor_class: EdgeActorClass,
    pub(crate) handle: String,
    pub(crate) custody: EntityId,
    /// The record's generation the use admitted.
    pub(crate) generation: u32,
    pub(crate) operation: String,
    pub(crate) effector: String,
    /// The grant a lease-aware use redeemed (FIX 4313), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) grant: Option<EntityId>,
    /// The run whose seat found the record, when the user's own run did
    /// (FIX 8334).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) run: Option<RunSecretHolder>,
}

impl SecretUseContext {
    /// Whether `other` is this use again, but for the intent and the
    /// generation each admitted: the same actor, record, operation,
    /// effector, grant and run. A held call its caller makes again is.
    pub(crate) fn same_use(&self, other: &Self) -> bool {
        self.actor == other.actor
            && self.actor_class == other.actor_class
            && self.handle == other.handle
            && self.custody == other.custody
            && self.operation == other.operation
            && self.effector == other.effector
            && self.grant == other.grant
            && self.run == other.run
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
    /// For a held call's send a resume makes, the first use's intent
    /// record (FIX 2822).
    pub(super) first_intent: Option<GateDecisionId>,
}

/// The use a held call's resumed send makes, as `context` keeps it.
fn resumed_use(context: &SecretUseContext) -> Used<'_> {
    Used {
        user: SecretUser::new(context.actor, context.actor_class),
        handle: context.handle.clone(),
        secret: context.custody,
        generation: context.generation,
        operation: &context.operation,
        effector: &context.effector,
        grant: context.grant,
        first_intent: Some(context.intent),
    }
}

impl Vault {
    /// Commits the intent record of a held `self.use` call's send that a
    /// resume makes, before that send (FIX 2822): used, its send `pending`,
    /// naming the first use's intent `context` keeps. Its id, for
    /// [`Self::finish_resumed_secret_use`].
    ///
    /// # Errors
    /// Storage faults.
    pub(crate) fn begin_resumed_secret_use(
        &self,
        context: &SecretUseContext,
    ) -> Result<GateDecisionId> {
        let intent = resumed_use(context).record(
            self,
            UsePhase::Intent,
            None,
            SecretUseDecision::Used,
            SecretUseSend::Pending,
            None,
        )?;
        Ok(intent.receipt)
    }

    /// Appends the outcome of that resumed send, linked to its intent
    /// record `intent`: `send`, as the host saw it, and what it presented,
    /// at the generation it released (FIX 2822).
    ///
    /// # Errors
    /// Storage faults.
    pub(crate) fn finish_resumed_secret_use(
        &self,
        context: &SecretUseContext,
        intent: GateDecisionId,
        send: SecretUseSend,
        presented: Option<SentPresentation>,
    ) -> Result<()> {
        resumed_use(context)
            .at_sent(presented)
            .record(
                self,
                UsePhase::Outcome,
                Some(intent),
                SecretUseDecision::Used,
                send,
                presented,
            )
            .map(drop)
    }
}

impl Used<'_> {
    /// What a connector call keeps of this use once its intent record is
    /// `intent`, its record found by `run` when the user's run found it
    /// (FIX 2822).
    pub(super) fn context(
        &self,
        intent: GateDecisionId,
        run: Option<RunSecretHolder>,
    ) -> SecretUseContext {
        SecretUseContext {
            intent,
            actor: self.user.actor,
            actor_class: self.user.actor_class,
            handle: self.handle.clone(),
            custody: self.secret,
            generation: self.generation,
            operation: self.operation.to_owned(),
            effector: self.effector.to_owned(),
            grant: self.grant,
            run,
        }
    }

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
        if let Some(first) = self.first_intent {
            details.push(format!("first_intent:{}", first.to_hex()));
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
