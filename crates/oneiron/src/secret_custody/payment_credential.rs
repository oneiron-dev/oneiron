//! Payment credentials on a host whose runner fence is unproven (L8-60;
//! CROSS-ARCH-0019 `#fence-unproven`, ARCH-0069 `#broker-unproven`: the
//! owner's pick A on OSH-5, 2026-10-08; RULING L8-60-PAYMENT-MARKER = A,
//! 14 Nov).
//!
//! Only the owner knows which credential pays, so he marks it: his answer is
//! a row beside the custody record (`store::secret_payment_marks`), keyed by
//! the record id, and the record's pinned codec does not change. Until he
//! answers, the record's label hint pre-fills it: a key a scan found as a
//! Stripe key is a payment credential. He can change the mark at any time,
//! or clear it back to the hint.
//!
//! The server seeds this host's fact at serve start
//! ([`Vault::set_payment_credential_release`]): whether its runner fence is
//! proven (Landlock ABI 3 or later on Linux, Seatbelt on macOS), and whether
//! its self-hoster lifted the withholding with the serve flag. While the
//! fence is unproven and the withholding stands, both value doors refuse a
//! payment credential with [`SecretError::PaymentCredentialWithheld`]: the
//! bound door ([`Vault::get_secret_value_in_txn`], every T0 and T1 binding
//! release) and the reveal door ([`super::reveal_value_in_txn`], an agent's
//! granted reveal). Every other credential stays at its rung, and the run
//! goes on. The owner's own read of his secret is no release to a runner,
//! and nothing here withholds it. A vault no server seeded withholds: its
//! fence is unproven.

use std::sync::PoisonError;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SecretError};
use crate::store::secret_payment_marks::{PAYMENT_MARK, SecretPaymentMark};
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord};
use crate::vault::Vault;

/// Gate reason code: the owner marked a credential as a payment credential,
/// or as not one.
const PAYMENT_MARK_REASON_SET: &str = "gate.secret.payment_mark.set";
/// Gate reason code: the owner cleared his payment mark back to the label
/// hint.
const PAYMENT_MARK_REASON_CLEARED: &str = "gate.secret.payment_mark.cleared";

/// The Gate content kind of a payment-mark ruling.
const PAYMENT_MARK_CONTENT_KIND: &str = "secret_payment_mark";

/// This host's release fact for payment credentials, which the server seeds
/// at serve start. The default, a host that proves no fence and lifted
/// nothing, withholds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PaymentCredentialRelease {
    /// This host proves the runner fence: Landlock ABI 3 or later on Linux,
    /// Seatbelt on macOS (ARCH-0066 tooth #9).
    pub runner_fence_proven: bool,
    /// The self-hoster lifted the withholding with the serve flag: he owns
    /// the host and its risk (CROSS-ARCH-0019 `#fence-unproven`).
    pub withholding_lifted: bool,
}

impl PaymentCredentialRelease {
    /// Whether the value doors withhold a payment credential on this host:
    /// its runner fence is unproven and its self-hoster lifted nothing.
    #[must_use]
    pub const fn withholds(self) -> bool {
        !self.runner_fence_proven && !self.withholding_lifted
    }
}

/// What the owner's payment mark on one credential leaves behind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretPaymentMarkSet {
    /// The owner's stored answer; `None` after he cleared it.
    pub marked: Option<bool>,
    /// What the record's label hint says: a scanned Stripe key is a payment
    /// credential. It pre-fills the mark while the owner has not answered.
    pub suggested: bool,
    /// Whether the value doors treat the credential as a payment credential
    /// now: the owner's answer, else the hint.
    pub payment: bool,
    /// The act's Gate receipt.
    pub receipt: String,
}

impl Vault {
    /// Sets this host's release fact for payment credentials. The server
    /// calls it at serve start, from the organ host's fence probe and the
    /// serve flag; it holds in memory only, and a reopened vault withholds
    /// again until its host seeds it.
    pub fn set_payment_credential_release(&self, release: PaymentCredentialRelease) {
        *self
            .payment_credential_release
            .write()
            .unwrap_or_else(PoisonError::into_inner) = release;
    }

    /// This host's release fact for payment credentials, as last seeded.
    #[must_use]
    pub fn payment_credential_release(&self) -> PaymentCredentialRelease {
        *self
            .payment_credential_release
            .read()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The owner says whether the custody record `secret` is a payment
    /// credential (`Some`), or clears his answer back to the record's label
    /// hint (`None`). A Gate record keeps the ruling, and the stored mark
    /// links to it by its receipt. An owner act: no agent grant reaches it.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`](crate::error::GateError::ConsentOwnerNotAuthenticated)
    /// when the proof is not the live owner's.
    /// [`SecretError::SecretRefNotFound`] when no custody record has this id.
    pub fn set_secret_payment_mark(
        &self,
        owner: &AuthenticatedOwner,
        secret: &EntityId,
        payment: Option<bool>,
    ) -> Result<SecretPaymentMarkSet> {
        self.with_write_txn_grouped(|txn| {
            let actor = super::handle_labels::live_owner_in_txn(
                self,
                owner,
                txn,
                "only the vault owner marks a payment credential",
            )?;
            if super::read_secret_custody_meta_in_txn(&self.store, txn, secret)?.is_none() {
                return Err(Error::Secret(SecretError::SecretRefNotFound {
                    name: secret.to_hex(),
                }));
            }
            let decision = append_payment_mark_ruling_in_txn(self, txn, actor, secret, payment)?;
            let receipt = super::handle_labels::gate_ref(decision);
            match payment {
                Some(payment) => PAYMENT_MARK.put(
                    &self.store,
                    txn,
                    secret,
                    &SecretPaymentMark {
                        payment,
                        receipt: receipt.clone(),
                    },
                )?,
                None => {
                    PAYMENT_MARK.delete(&self.store, txn, secret)?;
                }
            }
            let suggested =
                super::handle_labels::payment_suggested_in_txn(&self.store, txn, secret)?;
            Ok(SecretPaymentMarkSet {
                marked: payment,
                suggested,
                payment: payment.unwrap_or(suggested),
                receipt,
            })
        })
    }
}

/// Refuses the custody record `id`, named `name`, at a value door while this
/// host withholds payment credentials and the record is one: the owner's
/// mark says so, or, with no mark, its label hint does.
pub(crate) fn refuse_withheld_payment_credential_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    id: &EntityId,
    name: &str,
) -> Result<()> {
    if !vault.payment_credential_release().withholds() {
        return Ok(());
    }
    let payment = match PAYMENT_MARK.get(&vault.store, txn, id)? {
        Some(mark) => mark.payment,
        None => super::handle_labels::payment_suggested_in_txn(&vault.store, txn, id)?,
    };
    if payment {
        return Err(Error::Secret(SecretError::PaymentCredentialWithheld {
            secret_ref: name.to_owned(),
        }));
    }
    Ok(())
}

/// Appends the owner's payment mark, or its clear, to the Gate receipt
/// family, in `txn`. The details name pointers only: the custody id and
/// which act.
fn append_payment_mark_ruling_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    actor: EntityId,
    secret: &EntityId,
    payment: Option<bool>,
) -> Result<GateDecisionId> {
    let (reason, action) = match payment {
        Some(true) => (PAYMENT_MARK_REASON_SET, "action:payment"),
        Some(false) => (PAYMENT_MARK_REASON_SET, "action:not_payment"),
        None => (PAYMENT_MARK_REASON_CLEARED, "action:cleared"),
    };
    let decision_id = GateDecisionId::from_bytes(vault.store.clock.ulid()?);
    let record = GateDecisionRecord {
        version: GATE_DECISION_LEDGER_VERSION,
        decision_id,
        created_at: crate::ports::recorded_at_in_txn(&vault.store, txn)?,
        outcome: "approved".into(),
        reason_codes: vec![reason.into()],
        receipt_reasons: Vec::new(),
        system_notices: crate::store::GateSystemNoticeRecord::receipt_details(
            PAYMENT_MARK_CONTENT_KIND,
            vec![format!("custody:{}", secret.to_hex()), action.to_owned()],
        ),
        actor_class: "human".into(),
        actor_ref: Some(actor.to_hex()),
        content_kind: PAYMENT_MARK_CONTENT_KIND.into(),
        policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.into(),
        claim_id: None,
        grant_ref: None,
        diff_handle: secret.as_bytes().to_vec(),
        read_frontier_hash: [0; 32],
        context: Default::default(),
        redacted_at: None,
    };
    vault.store.append_gate_decision_in_txn(txn, &record)?;
    Ok(decision_id)
}
