//! The one Gate receipt writer. A caller fills a [`GateReceipt`] draft with
//! what it decided; the store mints the [`GateDecisionRecord`] from it and
//! fills the rest: the id, the time, the ledger version, the actor's class
//! and reference, the policy version and the read frontier.
//!
//! Engine-only (an attestation): the draft and both store doors are
//! `pub(crate)`, so an agent reaches them only through a verb whose door
//! decides.

// UC-03 PR 0 lands the draft and the mint alone; the stage-1 PRs move the
// 68 hand-built literals onto it, starting with PR 1a-i.
#![allow(dead_code, reason = "first callers: UC-03 stage 1")]

use std::borrow::Cow;

use heed::RwTxn;

use super::context::GateDecisionContext;
use super::types::{
    GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord, GateEnginePart,
    GateSystemNoticeRecord,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;
use crate::store::gate_reason::GateReceiptOutcome;
use crate::store::policy_record::POLICY_SCHEMA_VERSION;
use crate::write_envelope::WriteActor;
use oneiron_contracts::RecordedSeconds;

/// What a caller says about one decision. Not a ledger row: only
/// [`Store::mint_gate_receipt_in_txn`] turns it into one.
#[derive(Debug, Clone)]
pub(crate) struct GateReceipt {
    /// What happened to the thing the row is about.
    pub(crate) outcome: GateReceiptOutcome,
    /// The row's `content_kind`.
    pub(crate) kind: Cow<'static, str>,
    /// The row's `reason_codes`: at least one, each starting `gate.` (the
    /// append vets them).
    pub(crate) reasons: Vec<String>,
    /// Who decided; fills `actor_class` and `actor_ref`.
    pub(crate) actor: ReceiptActor,
    /// The row's `diff_handle`, 1 to 128 bytes (the append vets it).
    pub(crate) handle: Vec<u8>,
    /// The policy the decision stood on; fills `read_frontier_hash` and
    /// `policy_manifest_version`.
    pub(crate) basis: PolicyBasis,
    /// The row's `claim_id`.
    pub(crate) about: Option<EntityId>,
    pub(crate) grant_ref: Option<String>,
    /// `key:value` audit details, written as receipt-detail notices on the
    /// `kind` channel ([`GateSystemNoticeRecord::receipt_details`]), ahead of
    /// [`Self::notices`].
    pub(crate) details: Vec<String>,
    pub(crate) notices: Vec<GateSystemNoticeRecord>,
    pub(crate) receipt_reasons: Vec<String>,
    pub(crate) context: GateDecisionContext,
    /// `None`: the mint takes a fresh id. `Some` binds an id another row
    /// already holds; a bound id that is taken fails at the append.
    pub(crate) id: Option<GateDecisionId>,
    /// `None`: the mint reads the vault's recording clock in the write
    /// transaction. `Some` records a decision made earlier.
    pub(crate) decided_at: Option<RecordedSeconds>,
}

impl GateReceipt {
    /// A draft with the six things every caller says; everything else is
    /// empty, and the mint takes the id and the time.
    pub(crate) fn new(
        outcome: GateReceiptOutcome,
        kind: impl Into<Cow<'static, str>>,
        reason: impl Into<String>,
        actor: ReceiptActor,
        handle: impl Into<Vec<u8>>,
        basis: PolicyBasis,
    ) -> Self {
        Self {
            outcome,
            kind: kind.into(),
            reasons: vec![reason.into()],
            actor,
            handle: handle.into(),
            basis,
            about: None,
            grant_ref: None,
            details: Vec::new(),
            notices: Vec::new(),
            receipt_reasons: Vec::new(),
            context: GateDecisionContext::default(),
            id: None,
            decided_at: None,
        }
    }
}

/// Who a Gate receipt says decided.
#[derive(Debug, Clone)]
pub(crate) enum ReceiptActor {
    /// An actor row: class from its edge class (`human`, `agent`, `system`),
    /// ref its entity id.
    Row(WriteActor),
    /// The engine acting by rule, with no actor row: class `system`, no ref.
    Engine,
    /// A named engine part that is not an actor row, with its ref if it has
    /// one.
    Part(GateEnginePart, Option<String>),
    /// The class and ref an untrusted caller sent, or an earlier row carried,
    /// kept as they are.
    Verbatim {
        class: String,
        actor_ref: Option<String>,
    },
}

impl ReceiptActor {
    /// A person's actor row.
    pub(crate) const fn human(actor: EntityId) -> Self {
        Self::Row(WriteActor::new(actor, EdgeActorClass::Human))
    }

    /// The row's `actor_class` and `actor_ref`.
    fn class_and_ref(self) -> (String, Option<String>) {
        match self {
            Self::Row(actor) => (
                actor.actor_class().gate_actor_class().to_owned(),
                Some(actor.entity_ref().to_hex()),
            ),
            Self::Engine => (EdgeActorClass::System.gate_actor_class().to_owned(), None),
            Self::Part(part, actor_ref) => (part.as_str().to_owned(), actor_ref),
            Self::Verbatim { class, actor_ref } => (class, actor_ref),
        }
    }
}

/// The policy one decision stood on: the read frontier it was judged against
/// and the policy version, one fact written as two fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyBasis {
    frontier: Option<[u8; 32]>,
    version: Cow<'static, str>,
}

impl PolicyBasis {
    /// No policy was read to make this decision. Stored as 32 zero bytes
    /// under the current policy schema version.
    pub(crate) const NOT_READ: Self = Self {
        frontier: None,
        version: Cow::Borrowed(POLICY_SCHEMA_VERSION),
    };

    /// Judged against `hash`, under the current policy schema version.
    pub(crate) const fn frontier(hash: [u8; 32]) -> Self {
        Self {
            frontier: Some(hash),
            version: Cow::Borrowed(POLICY_SCHEMA_VERSION),
        }
    }

    /// The basis of the earlier row this row answers: its frontier and its
    /// policy version.
    pub(crate) fn of(row: &GateDecisionRecord) -> Self {
        Self {
            frontier: (row.read_frontier_hash != [0; 32]).then_some(row.read_frontier_hash),
            version: Cow::Owned(row.policy_manifest_version.clone()),
        }
    }

    /// Judged against `hash`, under a named policy version (the booking
    /// guard; a pending ask's binding).
    pub(crate) fn versioned(hash: [u8; 32], version: impl Into<Cow<'static, str>>) -> Self {
        Self {
            frontier: Some(hash),
            version: version.into(),
        }
    }
}

impl Store {
    /// Mints `receipt` and appends it to the ledger in `txn`. The default
    /// door.
    pub(crate) fn record_gate_receipt_in_txn(
        &self,
        txn: &mut RwTxn<'_>,
        receipt: GateReceipt,
    ) -> Result<GateDecisionRecord> {
        let record = self.mint_gate_receipt_in_txn(txn, receipt)?;
        self.append_gate_decision_in_txn(txn, &record)?;
        Ok(record)
    }

    /// Mints `receipt` without appending it, for a door that appends the row
    /// later or through another append door (a deletion's sidecar, a claim
    /// write's savepoint, an off-record room, a policy verdict's sealed row,
    /// the egress floor, a bundle's member index).
    ///
    /// A fresh id comes from the store clock, moved past any id the ledger
    /// already holds. The time is the vault's recording clock in `txn`, in
    /// whole seconds, unless the draft records an earlier decision.
    pub(crate) fn mint_gate_receipt_in_txn(
        &self,
        txn: &mut RwTxn<'_>,
        receipt: GateReceipt,
    ) -> Result<GateDecisionRecord> {
        let GateReceipt {
            outcome,
            kind,
            reasons,
            actor,
            handle,
            basis,
            about,
            grant_ref,
            details,
            notices,
            receipt_reasons,
            context,
            id,
            decided_at,
        } = receipt;
        let decision_id = match id {
            Some(id) => id,
            None => self.fresh_gate_decision_id_in_txn(
                &*txn,
                GateDecisionId::from_bytes(self.clock.ulid()?),
            )?,
        };
        let created_at = match decided_at {
            Some(at) => at.secs(),
            None => crate::ports::recorded_at_in_txn(self, txn)?,
        };
        let mut system_notices = GateSystemNoticeRecord::receipt_details(&kind, details);
        system_notices.extend(notices);
        let (actor_class, actor_ref) = actor.class_and_ref();
        let PolicyBasis { frontier, version } = basis;
        Ok(GateDecisionRecord {
            version: GATE_DECISION_LEDGER_VERSION,
            decision_id,
            created_at,
            outcome: outcome.as_str().to_owned(),
            reason_codes: reasons,
            receipt_reasons,
            system_notices,
            actor_class,
            actor_ref,
            content_kind: kind.into_owned(),
            policy_manifest_version: version.into_owned(),
            claim_id: about.map(|claim| *claim.as_bytes()),
            grant_ref,
            diff_handle: handle,
            // No policy read is stored as 32 zero bytes, as before the draft.
            read_frontier_hash: frontier.unwrap_or([0; 32]),
            context,
            redacted_at: None,
        })
    }
}
