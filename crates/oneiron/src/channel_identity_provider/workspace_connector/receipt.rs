//! A workspace write's Gate records (FIX 4862; L3-17), kept as a secret use
//! keeps its own: the intent a write commits before its send, its send
//! `pending`, and the outcome it appends after, linked to that intent. Each
//! is written in its caller's transaction, beside the write's claim on its
//! invocation ([`super::invocation`]). A crash between them leaves the
//! intent alone: sent or not, unknown. Nothing writes an invented outcome
//! for it.
//!
//! Each record names the tool, the connector, the file, the request's
//! digest, the credential's custody name and its effector. The outcome adds
//! what the send came to, the grant generation the door released, and
//! digests of the provider's reply and of the readback. No token, no file
//! content and no request body.

use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord};
use crate::vault::Vault;

use super::WorkspaceApi;

/// The Gate content kind of every workspace write's records.
const WORKSPACE_EFFECT_CONTENT_KIND: &str = "workspace_effect";

/// Domain of a record's diff handle: a digest of what was written where,
/// never of the content.
const WORKSPACE_EFFECT_DOMAIN: &[u8] = b"oneiron.workspace_effect.v1";

/// The send reached the provider, and it answered with a success.
pub(super) const SEND_DELIVERED: &str = "delivered";
/// Nothing reached the provider.
pub(super) const SEND_NOT_SENT: &str = "not_sent";
/// The send may have reached the provider, and no answer came back.
pub(super) const SEND_UNCERTAIN: &str = "uncertain";

/// The Gate reason code of every write's records of the connector
/// `catalog_name`: `connector.google.sheets.effect` for Sheets.
#[must_use]
pub fn workspace_effect_reason(catalog_name: &str) -> String {
    format!("connector.{catalog_name}.effect")
}

/// One write as its Gate records keep it.
pub(super) struct WorkspaceEffect<'a> {
    pub(super) actor: EntityId,
    pub(super) actor_class: EdgeActorClass,
    pub(super) module: &'static dyn WorkspaceApi,
    /// The tool's name.
    pub(super) tool: &'static str,
    /// The id of the file written.
    pub(super) target: &'a str,
    /// The request's digest, lower hex.
    pub(super) request: String,
    /// The custody name of the grant the send presents.
    pub(super) credential: &'a str,
}

/// What a write's send came to, as its outcome record says it.
pub(super) struct EffectResult {
    /// [`SEND_DELIVERED`], `rejected_<status>`, [`SEND_NOT_SENT`] or
    /// [`SEND_UNCERTAIN`].
    pub(super) send: String,
    /// The grant's generation the door released, when it released one.
    pub(super) generation: Option<u32>,
    /// The digest of the provider's reply, when it answered.
    pub(super) reply: Option<String>,
    /// The digest of the readback, when it read.
    pub(super) readback: Option<String>,
}

impl WorkspaceEffect<'_> {
    /// Appends the intent record in `txn`, before the send. Its id, for
    /// [`Self::outcome_in_txn`].
    pub(super) fn intent_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
    ) -> Result<GateDecisionId> {
        self.record_in_txn(vault, txn, None, None)
    }

    /// Appends the outcome record in `txn`, linked to `intent`.
    pub(super) fn outcome_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        intent: GateDecisionId,
        result: &EffectResult,
    ) -> Result<GateDecisionId> {
        self.record_in_txn(vault, txn, Some(intent), Some(result))
    }

    fn record_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        intent: Option<GateDecisionId>,
        result: Option<&EffectResult>,
    ) -> Result<GateDecisionId> {
        let decision_id = GateDecisionId::from_bytes(vault.store.clock.ulid()?);
        let connector = self.module.catalog_name();
        let parts: [&[u8]; 5] = [
            WORKSPACE_EFFECT_DOMAIN,
            connector.as_bytes(),
            self.tool.as_bytes(),
            self.target.as_bytes(),
            self.request.as_bytes(),
        ];
        let mut digest = blake3::Hasher::new();
        for part in parts {
            digest.update(&(part.len() as u64).to_be_bytes());
            digest.update(part);
        }
        let mut details = vec![
            format!("effect:{}", self.tool),
            format!("connector:{connector}"),
            format!("{}:{}", self.module.target().kind, self.target),
            format!("request:{}", self.request),
            format!("credential:{}", self.credential),
            format!("effector:{}", self.module.connection().effector),
        ];
        match result {
            None => {
                details.push("phase:intent".to_owned());
                details.push("send:pending".to_owned());
            }
            Some(result) => {
                details.push("phase:outcome".to_owned());
                details.push(format!("send:{}", result.send));
                if let Some(generation) = result.generation {
                    details.push(format!("generation:{generation}"));
                }
                if let Some(reply) = &result.reply {
                    details.push(format!("reply:{reply}"));
                }
                if let Some(readback) = &result.readback {
                    details.push(format!("readback:{readback}"));
                }
            }
        }
        if let Some(intent) = intent {
            details.push(format!("intent:{}", intent.to_hex()));
        }
        let created_at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        let record = GateDecisionRecord {
            version: GATE_DECISION_LEDGER_VERSION,
            decision_id,
            created_at,
            outcome: "approved".into(),
            reason_codes: vec![workspace_effect_reason(connector)],
            receipt_reasons: Vec::new(),
            system_notices: crate::store::GateSystemNoticeRecord::receipt_details(
                WORKSPACE_EFFECT_CONTENT_KIND,
                details,
            ),
            actor_class: self.actor_class.gate_actor_class().into(),
            actor_ref: Some(self.actor.to_hex()),
            content_kind: WORKSPACE_EFFECT_CONTENT_KIND.into(),
            policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.into(),
            claim_id: None,
            grant_ref: None,
            diff_handle: digest.finalize().as_bytes().to_vec(),
            read_frontier_hash: [0; 32],
            context: Default::default(),
            redacted_at: None,
        };
        vault.store.append_gate_decision_in_txn(txn, &record)?;
        Ok(decision_id)
    }
}
