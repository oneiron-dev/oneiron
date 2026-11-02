//! The OpenAI proxy's own connector (ARCH-0028): the proxy registers as a
//! connector with its own key and takes an ARCH-0072 grant slate at
//! admission. Each paired actor holds one catalog key on [`PROXY_CONNECTOR`],
//! its catalog name the actor's, over a fixed two-row slate the owner
//! stamps. No probe suite runs: the engine is the connector, so the key
//! activates under a proxy admission receipt. A revoked or removed key keeps
//! its catalog name for the vault's life, so a re-admission takes the next
//! free generation of the actor's name.

use std::collections::BTreeMap;

use serde_json::json;

use super::super::qualification::ConnectorQualificationReceipt;
use super::super::record::{
    ConnectorCallClass, ConnectorCatalogEntry, ConnectorKeyRecord, ConnectorKeySpec,
    ConnectorKeyStatus, invalid_body,
};
use super::super::slate::{
    ConnectorGrantSlate, SlateDataClass, SlateDisposition, SlateDraftRow, SlateOwnerOverride,
    SlateToolManifest, read_connector_slate_in_txn,
};
use super::super::txn::{
    CATALOG_NAME_INDEX, append_connector_key_op_record, governing_connector_key,
    rewrite_connector_key_in_txn,
};
use super::catalog_views::ActorConnectorRegistration;
use super::registration::catalog_key_record;
use crate::Vault;
use crate::authority::PairingRedeemed;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::{GateDecisionId, Store};

/// The connector the OpenAI proxy registers as.
pub const PROXY_CONNECTOR: &str = "openai_proxy";

/// The revision the proxy's key pins: the engine's own proxy, not a
/// negotiated MCP one.
const PROXY_PROTOCOL_REVISION: &str = "openai_proxy.v1";

/// The catalog line each paired actor's proxy entry carries.
const PROXY_SUMMARY: &str =
    "The OpenAI-compatible memory proxy for one paired actor: recall, inject, forward, remember.";

/// Seals what a proxy admission receipt's digest covers.
const PROXY_ADMISSION_DOMAIN: &[u8] = b"oneiron/openai-proxy-admission/v1";

/// The two legs the proxy runs on each call, as its slate's tools, with
/// their draft rows at the default setting. The inputs are the ones the
/// proxy sends: the newest user text, and the exchange it proposes.
fn proxy_slate_draft() -> (Vec<SlateToolManifest>, Vec<SlateDraftRow>) {
    let legs = [
        (
            "vault.recall",
            json!({
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"]
            }),
            true,
            "The proxy recalls the vault for each call's newest user message.",
        ),
        (
            "vault.remember",
            json!({
                "type": "object",
                "properties": {
                    "user": {"type": "string"},
                    "assistant": {"type": "string"},
                    "model": {"type": "string"}
                },
                "required": ["user", "assistant", "model"]
            }),
            false,
            "The proxy proposes each exchange back, pinned Proposed.",
        ),
    ];
    let mut manifest = Vec::with_capacity(legs.len());
    let mut rows = Vec::with_capacity(legs.len());
    for (name, schema, reads, rationale) in legs {
        manifest.push(SlateToolManifest {
            name: name.to_owned(),
            data_class: SlateDataClass::Personal,
            header_parameters: Vec::new(),
            resolved_input_schema: Some(schema),
            trigger: None,
            destroys: false,
            spends: false,
            sends_outward: false,
            legacy_ask: false,
            read_only: reads,
            idempotent: reads,
            price: None,
        });
        rows.push(SlateDraftRow {
            tool: name.to_owned(),
            disposition: SlateDisposition::Auto,
            data_class: SlateDataClass::Personal,
            rationale: rationale.to_owned(),
        });
    }
    (manifest, rows)
}

/// What a proxy admission receipt names: the actor, and the slate the owner
/// stamped for it.
fn admission_digest(actor: &EntityId, slate: &ConnectorGrantSlate) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PROXY_ADMISSION_DOMAIN);
    hasher.update(actor.as_bytes());
    hasher.update(&slate.manifest_hash());
    hasher.update(&slate.grant_hash());
    hasher.finalize().to_hex().to_string()
}

/// The actor's catalog name on the proxy connector: `openai_proxy_<actor
/// hex>`, then `_<n>` from 1 for each admission after a revoked or removed
/// key, whose name stays taken.
fn proxy_catalog_name(store: &Store, txn: &heed::RoTxn<'_>, actor: &EntityId) -> Result<String> {
    let first = format!("{PROXY_CONNECTOR}_{}", actor.to_hex());
    if !CATALOG_NAME_INDEX.contains(store, txn, &first)? {
        return Ok(first);
    }
    for generation in 1..=u32::MAX {
        let name = format!("{first}_{generation}");
        if !CATALOG_NAME_INDEX.contains(store, txn, &name)? {
            return Ok(name);
        }
    }
    Err(invalid_body("no free proxy catalog name"))
}

impl Vault {
    /// The owner admits the OpenAI proxy for `actor`. The proxy's fixed
    /// slate is drafted and stamped under the owner; then the actor's
    /// catalog key on [`PROXY_CONNECTOR`] is registered and activated in one
    /// transaction, under a proxy admission receipt. A live registration is
    /// returned as it stands, so a re-pair admits nothing twice. A key the
    /// actor already holds that is not live, and not revoked, is refused: the
    /// owner's switch and stamp own it.
    pub fn admit_proxy_connector(
        &self,
        owner: &AuthenticatedOwner,
        actor: EntityId,
        at: u64,
    ) -> Result<ActorConnectorRegistration> {
        if let Some(live) =
            self.with_write_txn_grouped(|txn| self.proxy_admission_in_txn(txn, owner, actor))?
        {
            return Ok(live);
        }
        let (manifest, rows) = proxy_slate_draft();
        let drafted =
            serde_json::to_string(&rows).map_err(|_| invalid_body("proxy slate draft"))?;
        let slate_ref = self.store_connector_slate(&manifest, &drafted)?;
        let slate = self.override_connector_slate(owner, slate_ref, 0, &BTreeMap::new())?;
        let key_ref = self.store.clock.entity_id()?;
        self.with_write_txn_grouped(|wtxn| {
            if let Some(live) = self.proxy_admission_in_txn(wtxn, owner, actor)? {
                return Ok(live);
            }
            // The key binds the stamp this admission made, or none.
            if read_connector_slate_in_txn(self, wtxn, slate_ref)?.as_ref() != Some(&slate) {
                return Err(Error::ConcurrentWrite("connector slate revision"));
            }
            let pending = catalog_key_record(
                ConnectorCatalogEntry {
                    name: proxy_catalog_name(&self.store, wtxn, &actor)?,
                    connector: PROXY_CONNECTOR.to_owned(),
                    summary: PROXY_SUMMARY.to_owned(),
                    verbs: manifest.iter().map(|tool| tool.name.clone()).collect(),
                    call_class: ConnectorCallClass::ScopedMcp,
                    registered_at: at,
                },
                ConnectorKeySpec {
                    connector: PROXY_CONNECTOR.to_owned(),
                    actor_entity_ref: Some(actor),
                    budgets: Vec::new(),
                    secret_ref: None,
                    slate_ref: Some(slate_ref),
                    protocol_revision: Some(PROXY_PROTOCOL_REVISION.to_owned()),
                },
                at,
            )?;
            self.register_connector_key_in_txn(wtxn, &key_ref, &pending)?;
            let active = ConnectorKeyRecord {
                qualification_receipt: Some(ConnectorQualificationReceipt::proxy_admission(
                    admission_digest(&actor, &slate),
                    PROXY_PROTOCOL_REVISION.to_owned(),
                    slate.manifest_hash(),
                    at,
                )?),
                status: ConnectorKeyStatus::Active,
                status_changed_at: Some(at),
                slate_revision: Some(slate.revision()),
                consent_required: false,
                ..pending
            };
            active.validate()?;
            rewrite_connector_key_in_txn(&self.store, wtxn, &key_ref, &active)?;
            let policy = crate::gate::resolve_policy_manifest(&self.store, &*wtxn)?;
            append_connector_key_op_record(
                &self.store,
                wtxn,
                &key_ref,
                "gate.connector_key.proxy_admit",
                &active,
                policy.read_frontier_hash()?,
                at,
            )?;
            Ok(ActorConnectorRegistration {
                key_ref,
                key: active,
                slate_ref,
                slate: slate.clone(),
            })
        })
    }

    /// Revalidates every admission guard in the writer that creates the key.
    fn proxy_admission_in_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        actor: EntityId,
    ) -> Result<Option<ActorConnectorRegistration>> {
        owner.revalidate_in_txn(self, txn)?;
        if let Some(live) = self.live_connector_registration_in_txn(txn, PROXY_CONNECTOR, &actor)? {
            return Ok(Some(live));
        }
        if governing_connector_key(&self.store, txn, PROXY_CONNECTOR, Some(&actor))?.is_some_and(
            |(_, key)| {
                key.actor_entity_ref == Some(actor) && key.status != ConnectorKeyStatus::Revoked
            },
        ) {
            return Err(invalid_body(
                "the actor's proxy connector key is not live: switch it on or stamp its slate",
            ));
        }
        if !crate::ports::EntityStoreRead::port_entity_present(&self.store, txn, &actor)? {
            return Err(invalid_body("no actor by that id"));
        }
        Ok(None)
    }

    /// Withdraws only the proxy's remember capability. The read row, key
    /// status, credential and memory stay unchanged. The reviewed key and
    /// slate, owner proof, restamp and key adoption share this one writer.
    pub fn revoke_proxy_connector_write(
        &self,
        owner: &AuthenticatedOwner,
        actor: EntityId,
        key: EntityId,
        expected_revision: u64,
        at: u64,
    ) -> Result<ActorConnectorRegistration> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let registration = self
                .live_connector_registration_in_txn(txn, PROXY_CONNECTOR, &actor)?
                .ok_or(Error::EntityNotFound)?;
            if registration.key_ref != key || registration.slate.revision() != expected_revision {
                return Err(Error::ConcurrentWrite("proxy connector registration"));
            }
            if registration.slate.tool_setting("vault.remember") == SlateDisposition::NeverAllow {
                return Ok(registration);
            }
            let slate = self.stamp_slate_in_txn(
                txn,
                owner,
                registration.slate_ref,
                expected_revision,
                &BTreeMap::from([(
                    "vault.remember".to_owned(),
                    SlateOwnerOverride {
                        disposition: SlateDisposition::NeverAllow,
                    },
                )]),
                None,
            )?;
            let key = self.adopt_connector_slate_stamp_in_txn(txn, &key, at)?;
            Ok(ActorConnectorRegistration {
                key,
                slate,
                ..registration
            })
        })
    }

    /// The owner who made a redeemed link admits the OpenAI proxy for its
    /// holder, so a link-paired actor needs no second step. That owner
    /// authenticated when the link was made, and each transaction of the
    /// admission revalidates them as a live owner of this vault. A link no
    /// owner made admits nothing (`None`).
    pub fn admit_linked_proxy_connector(
        &self,
        redeemed: &PairingRedeemed,
        at: u64,
    ) -> Result<Option<ActorConnectorRegistration>> {
        let Some(owner) = redeemed.link_owner else {
            return Ok(None);
        };
        let actor = EntityId::from_hex(&redeemed.slip.claims.holder_ref)?;
        let owner = self.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
        self.admit_proxy_connector(&owner, actor, at).map(Some)
    }
}
