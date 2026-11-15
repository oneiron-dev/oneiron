//! The shared fixture of the identity-ramp offer tests: a vault whose owner
//! applied SendWithApproval to an agent's dedicated email identity, and the
//! reviewed sends that earn the scope's graduation offer. Each review is a
//! durable outbound receipt (through `test_doors::identity_ramp`) plus the
//! agent's evidence row over it, on a task of its own.
#![allow(dead_code)] // each integration binary uses a subset of these helpers

use std::collections::BTreeMap;

use oneiron::agent_inbox_lens::{AgentInboxLensItem, AgentInboxLensQuery};
use oneiron::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment, ChannelIdentityStep,
    SelfHeldShape,
};
use oneiron::channel_identity_autonomy::{
    ChannelIdentityActionEnvelope, ChannelIdentityAutonomyRequest, ChannelIdentityAutonomyRung,
    DEFAULT_GRADUATION_UNCHANGED_STREAK, DraftReviewOutcome, GraduationEvidence,
    GraduationScopeKey, MailboxReadEnvelope,
};
use oneiron::channel_identity_selection::RelationshipContext;
use oneiron::consent::AuthenticatedOwner;
use oneiron::receipt::{ReceiptKind, ReceiptRecord};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::identity_ramp::persist_reviewed_send;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};

pub(crate) const COUNTERPARTY_CLASS: &str = "known";
/// The item id prefix of a ramp offer's INBOX row, spelled here so the pile
/// test builds where the engine names no such row.
pub(crate) const RAMP_ITEM_PREFIX: &str = "ramp:";
pub(crate) const MAX_ACTIONS: u32 = 3;
pub(crate) const WINDOW_SECS: u64 = 86_400;

pub(crate) struct RampFixture {
    _dir: tempfile::TempDir,
    pub(crate) vault: Vault,
    pub(crate) owner_id: EntityId,
    pub(crate) owner: AuthenticatedOwner,
    pub(crate) scope: GraduationScopeKey,
    /// The posture the owner applied.
    pub(crate) request: ChannelIdentityAutonomyRequest,
}

impl RampFixture {
    /// The owner applies SendWithApproval to the agent's identity, with an
    /// action envelope of three sends a day to known counterparties.
    pub(crate) fn at_send_with_approval() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
        let owner_id = vault
            .ensure_embedded_owner_actor()
            .expect("the vault's owner");
        let owner = vault
            .authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        let identity_ref = EntityId::now();
        let actor_ref = EntityId::now();
        let identity = ChannelIdentity::requested(
            "email",
            "agent@example.test",
            SelfHeldShape::DedicatedAddress,
            ChannelIdentityBinding::agent(actor_ref),
            1,
        )
        .step(
            ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Manual),
            2,
        )
        .expect("bind")
        .step(ChannelIdentityStep::Fulfill, 3)
        .expect("fulfil");
        vault
            .create_channel_identity(&identity_ref, &identity)
            .expect("the agent's email identity");
        let request = ChannelIdentityAutonomyRequest {
            actor_ref,
            relationship_context: RelationshipContext::WorkDeal,
            rung: ChannelIdentityAutonomyRung::SendWithApproval,
            read_envelope: MailboxReadEnvelope {
                identity_ref,
                label_allowlist: vec!["inbox".to_owned()],
                thread_allowlist: Vec::new(),
                full_mailbox: false,
                not_before: None,
                not_after: None,
            },
            action_envelope: Some(ChannelIdentityActionEnvelope {
                identity_ref,
                relationship_context: RelationshipContext::WorkDeal,
                counterparty_class: Some(COUNTERPARTY_CLASS.to_owned()),
                max_actions: MAX_ACTIONS,
                window_secs: WINDOW_SECS,
            }),
        };
        vault
            .apply_channel_identity_autonomy(&request, &owner)
            .expect("the owner applies SendWithApproval");
        let scope = GraduationScopeKey {
            actor_ref,
            identity_ref,
            relationship_context: RelationshipContext::WorkDeal,
            verb_class: "mail.send".to_owned(),
            counterparty_class: Some(COUNTERPARTY_CLASS.to_owned()),
        };
        Self {
            _dir: dir,
            vault,
            owner_id,
            owner,
            scope,
            request,
        }
    }

    /// One reviewed send at `at` on a task of its own, approved untouched,
    /// recorded as the agent's evidence. Returns the receipt id.
    pub(crate) fn review(&self, at: u64) -> String {
        let receipt = ReceiptRecord {
            receipt_id: format!("outbound-review:{}", EntityId::now().to_hex()),
            receipt_kind: ReceiptKind::Outbound,
            occurred_at: at,
            actor: Some(self.scope.actor_ref.to_hex()),
            on_behalf_of: None,
            outcome: "failed".to_owned(),
            job_ref: None,
            trigger_ref: None,
            policy_trace: Vec::new(),
            fields: BTreeMap::from([
                (
                    "channel_identity_ref".to_owned(),
                    self.scope.identity_ref.to_hex(),
                ),
                (
                    "relationship_context".to_owned(),
                    self.scope.relationship_context.as_str().to_owned(),
                ),
                ("verb_class".to_owned(), self.scope.verb_class.clone()),
                (
                    "counterparty_class".to_owned(),
                    COUNTERPARTY_CLASS.to_owned(),
                ),
                ("review_outcome".to_owned(), "approved_untouched".to_owned()),
            ]),
        };
        let receipt_ref = receipt.receipt_id.clone();
        assert!(
            persist_reviewed_send(&self.vault, EntityId::now(), receipt)
                .expect("persist the reviewed send"),
            "the reviewed send is written"
        );
        self.vault
            .record_graduation_evidence(
                GraduationEvidence {
                    scope: self.scope.clone(),
                    outcome: DraftReviewOutcome::ApprovedUntouched,
                    receipt_ref: receipt_ref.clone(),
                    occurred_at: at,
                },
                &WriteActor::new(self.scope.actor_ref, EdgeActorClass::Agent),
            )
            .expect("the agent's evidence");
        receipt_ref
    }

    /// `count` reviews at instants 1..=count. Returns the last instant.
    pub(crate) fn reviews(&self, count: u32) -> u64 {
        let count = u64::from(count);
        for at in 1..=count {
            self.review(at);
        }
        count
    }

    /// The pinned default streak of reviews: the offer is earned. Returns
    /// the newest review's instant.
    pub(crate) fn earn_offer(&self) -> u64 {
        self.reviews(DEFAULT_GRADUATION_UNCHANGED_STREAK)
    }

    /// The owner's inbox rows that carry a ramp offer.
    pub(crate) fn ramp_rows(&self) -> Vec<AgentInboxLensItem> {
        ramp_rows_of(
            self.vault
                .agent_inbox_lens(AgentInboxLensQuery {
                    identity_ref: None,
                    limit: 500,
                    before: None,
                })
                .expect("the owner's inbox lens"),
        )
    }

    /// The agent's own slice's rows that carry a ramp offer.
    pub(crate) fn agent_slice_ramp_rows(&self) -> Vec<AgentInboxLensItem> {
        ramp_rows_of(
            self.vault
                .agent_inbox_slice(self.scope.actor_ref, 500, None)
                .expect("the agent's inbox slice"),
        )
    }
}

fn ramp_rows_of(items: Vec<AgentInboxLensItem>) -> Vec<AgentInboxLensItem> {
    items
        .into_iter()
        .filter(|item| item.item_id.starts_with(RAMP_ITEM_PREFIX))
        .collect()
}
