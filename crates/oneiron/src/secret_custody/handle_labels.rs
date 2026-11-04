//! An owner's display label on a secret handle (L04 s43 FIX 12541,
//! engine part).
//!
//! A custody handle can carry a user-set name. The label row names the
//! custody record and holds the label text plus the Gate receipt of the set;
//! the Gate row behind the receipt carries who set it and when, so the label
//! row carries neither. The suggestion is computed at card-read time from
//! the already-stored value-free scan kind, never persisted. No scan of the
//! label, no migration, no automatic labeling.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use crate::secret_custody::types::SECRET_NAME_MAX_BYTES;
use crate::store::secret_handle_labels::LABEL;
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord, Store};
use crate::vault::Vault;

pub use crate::store::secret_handle_labels::SecretHandleLabel;
pub(crate) use crate::store::secret_handle_labels::erase_secret_handle_label_in_txn;

/// Gate reason code: the owner set a handle's label.
const HANDLE_LABEL_REASON_SET: &str = "gate.secret.handle_label.set";
/// Gate reason code: the owner cleared a handle's label.
const HANDLE_LABEL_REASON_CLEARED: &str = "gate.secret.handle_label.cleared";

/// The Gate content kind of a handle-label ruling.
const HANDLE_LABEL_CONTENT_KIND: &str = "secret_handle_label";

/// The scan-reason prefix a kind suggestion strips.
const SCAN_REASON_PREFIX: &str = "gate.secret_scan.";

/// Provider prefixes that suggest a label, longest first so `sk-proj-`
/// wins over `sk-`.
const PREFIX_LABELS: &[(&str, &str)] = &[
    ("github_pat_", "GitHub token"),
    ("sk-proj-", "OpenAI key"),
    ("pk_live_", "Stripe live key"),
    ("pk_test_", "Stripe test key"),
    ("sk_live_", "Stripe live key"),
    ("rk_live_", "Stripe live key"),
    ("xoxb-", "Slack token"),
    ("xoxp-", "Slack token"),
    ("xoxa-", "Slack token"),
    ("xoxr-", "Slack token"),
    ("xoxs-", "Slack token"),
    ("ghp_", "GitHub token"),
    ("gho_", "GitHub token"),
    ("ghu_", "GitHub token"),
    ("ghs_", "GitHub token"),
    ("ghr_", "GitHub token"),
    ("AIza", "Google API key"),
    ("AKIA", "AWS access key"),
    ("ASIA", "AWS access key"),
    ("sk-", "OpenAI key"),
];

/// What setting or clearing a handle's label leaves behind: the stored
/// label (`None` after a clear), the kind suggestion the card falls back
/// to, and the act's Gate receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretHandleLabelSet {
    pub label: Option<String>,
    pub suggested_label: Option<String>,
    pub receipt: String,
}

/// The stored label on the custody record `custody`, if the owner set one.
pub(crate) fn secret_handle_label_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    custody: &EntityId,
) -> Result<Option<SecretHandleLabel>> {
    LABEL.get(store, txn, custody)
}

/// The kind suggestion for the custody record `custody`: the value-free
/// scan kind its mask origin names, mapped to a label. `None` for a record
/// an owner registered, or a kind with no suggestion.
pub(crate) fn suggested_secret_handle_label_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    custody: &EntityId,
) -> Result<Option<String>> {
    let Some(origin) = crate::batch::secret_scan::mask_origin_in_txn(store, txn, custody)? else {
        return Ok(None);
    };
    let kind = origin
        .reason
        .strip_prefix(SCAN_REASON_PREFIX)
        .unwrap_or(&origin.reason);
    Ok(suggest_secret_handle_label_for_kind(kind).map(str::to_owned))
}

/// The label a scan kind suggests, if any. Generic and depth codes
/// (`detected`, `blocklist`, `sensitive_env`, `known_value`, depth codes)
/// suggest nothing.
pub fn suggest_secret_handle_label_for_kind(kind: &str) -> Option<&'static str> {
    match kind {
        "openai_key" => Some("OpenAI key"),
        "stripe_key" => Some("Stripe key"),
        "github_token" => Some("GitHub token"),
        "google_api_key" => Some("Google API key"),
        "slack_token" => Some("Slack token"),
        "aws_access_key_id" => Some("AWS access key"),
        "private_key" => Some("Private key"),
        "mnemonic" => Some("Recovery phrase"),
        _ => None,
    }
}

/// The label a value's provider prefix suggests, by longest-prefix match.
/// Pure: callable only where the value is legitimately in hand.
pub fn suggest_secret_handle_label_for_prefix(value: &[u8]) -> Option<&'static str> {
    PREFIX_LABELS
        .iter()
        .find(|(prefix, _)| value.starts_with(prefix.as_bytes()))
        .map(|(_, label)| *label)
}

impl Vault {
    /// Sets the owner's display label on the handle's custody record, or
    /// clears it back to the kind suggestion when `label` is `None` or
    /// blank. Either way a Gate record keeps the ruling, and the set's
    /// receipt is the label row's link to it. The label is a name, so it is
    /// validated like one — trimmed, one line, no NUL, at most
    /// [`SECRET_NAME_MAX_BYTES`] bytes — and never scanned.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] when the proof is not the
    /// live owner's. What handle resolution returns for a handle no live
    /// custody record names. [`GateError::InvalidConsentBound`] for a label
    /// past the byte cap, or one holding a line break or NUL.
    pub fn set_secret_handle_label(
        &self,
        owner: &AuthenticatedOwner,
        handle: &str,
        label: Option<&str>,
    ) -> Result<SecretHandleLabelSet> {
        self.with_write_txn_grouped(|txn| {
            let actor = live_owner_in_txn(self, owner, txn, "only the vault owner names a handle")?;
            let (handle, custody) =
                crate::secret_custody::reveal::resolve_handle_in_txn(&self.store, txn, handle)?;
            let trimmed = label.map(str::trim).filter(|text| !text.is_empty());
            if let Some(text) = trimmed {
                if text.len() > SECRET_NAME_MAX_BYTES {
                    return Err(Error::Gate(GateError::InvalidConsentBound(
                        "a handle label is longer than 255 bytes",
                    )));
                }
                if text.contains(['\n', '\r', '\0']) {
                    return Err(Error::Gate(GateError::InvalidConsentBound(
                        "a handle label is one line without NUL",
                    )));
                }
                let decision =
                    append_label_ruling_in_txn(self, txn, actor, &handle, &custody, true)?;
                let receipt = gate_ref(decision);
                LABEL.put(
                    &self.store,
                    txn,
                    &custody,
                    &SecretHandleLabel {
                        label: text.to_owned(),
                        receipt: receipt.clone(),
                    },
                )?;
                Ok(SecretHandleLabelSet {
                    label: Some(text.to_owned()),
                    suggested_label: suggested_secret_handle_label_in_txn(
                        &self.store,
                        txn,
                        &custody,
                    )?,
                    receipt,
                })
            } else {
                let decision =
                    append_label_ruling_in_txn(self, txn, actor, &handle, &custody, false)?;
                LABEL.delete(&self.store, txn, &custody)?;
                Ok(SecretHandleLabelSet {
                    label: None,
                    suggested_label: suggested_secret_handle_label_in_txn(
                        &self.store,
                        txn,
                        &custody,
                    )?,
                    receipt: gate_ref(decision),
                })
            }
        })
    }
}

/// The owner's proof, rechecked at the owner tier in `txn`: the acting
/// owner.
fn live_owner_in_txn(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    txn: &RoTxn<'_>,
    refusal: &'static str,
) -> Result<EntityId> {
    let actor = owner.revalidate_in_txn(vault, txn)?;
    if !crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &actor)? {
        return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
            refusal,
        )));
    }
    Ok(actor)
}

fn gate_ref(decision: GateDecisionId) -> String {
    format!("gate:{}", decision.to_hex())
}

/// Appends the owner's label set or clear to the Gate receipt family, in
/// `txn`. The details name pointers only — the handle, the custody id and
/// which act — never the label bytes.
fn append_label_ruling_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    actor: EntityId,
    handle: &str,
    custody: &EntityId,
    set: bool,
) -> Result<GateDecisionId> {
    let (reason, action) = if set {
        (HANDLE_LABEL_REASON_SET, "action:set")
    } else {
        (HANDLE_LABEL_REASON_CLEARED, "action:cleared")
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
            HANDLE_LABEL_CONTENT_KIND,
            vec![
                format!("handle:{handle}"),
                format!("custody:{}", custody.to_hex()),
                action.to_owned(),
            ],
        ),
        actor_class: "human".into(),
        actor_ref: Some(actor.to_hex()),
        content_kind: HANDLE_LABEL_CONTENT_KIND.into(),
        policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.into(),
        claim_id: None,
        grant_ref: None,
        diff_handle: custody.as_bytes().to_vec(),
        read_frontier_hash: [0; 32],
        context: Default::default(),
        redacted_at: None,
    };
    vault.store.append_gate_decision_in_txn(txn, &record)?;
    Ok(decision_id)
}
