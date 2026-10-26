//! The connector-call driver: tool resolution, schema reads and the durable
//! pass that turns a gate decision into a step.
//! Entry: `Vault::drive_connector_call`. Defines its own items.

use serde_json::Value;

use crate::Vault;
use crate::connector_key::{
    CONNECTOR_ISSUER_HOLD_REASON, ConnectorCallRoute, ConnectorKeyRecord, ConnectorKeyStatus,
    ConnectorScopeEvidence, ScopeExceedCall, ScopedCapabilityProvenance, SlateDataClass,
    SlateDisposition, canonical_scoped_server_segment,
};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::memory::Memory;
use crate::outbound_grant::StandingOutboundGrant;
use crate::outbound_intent_ledger::{
    IntentEscalationReason, IntentLedgerError, OutboundToolDescriptor, abandon_record,
};

use super::authority::OutboundBindingAuthority;
use super::connector_call::{
    ConnectorAwaitingInput, ConnectorCallCaller, ConnectorCallHost, ConnectorCallOutcome,
    ConnectorToolSchema, PendingConnectorCall, SettledConnectorCall, UntrustedToolResult, now_ms,
};
use super::connector_call_dispatch::{escalation_code, step_from_host};
use super::connector_call_erase::put_pending_call_in_txn;
use super::scope::{
    DataClass, ScopedMcpCallContext, ScopedMcpConsentDecision, ScopedMcpEscalationReason,
};
use super::tool_call::{ConnectorToolCallPreparation, ToolCallDescriptor};

/// The reason a call that names a custody record gets on a host that cannot
/// present one: it is refused unsent.
const CONNECTOR_CALL_CREDENTIAL_UNSUPPORTED: &str = "connector_call_credential_unsupported";

/// The tool beneath one grant, for a schema read: the governing key the
/// grant mints and the tool's approved schema there.
struct GoverningTool {
    key_id: EntityId,
    key: ConnectorKeyRecord,
    schema: Value,
}

/// What one pass came to, before the pending row is settled.
pub(super) enum Step {
    Delivered {
        intent: Option<[u8; 32]>,
        result: Option<UntrustedToolResult>,
    },
    Held {
        decision_ref: Option<String>,
        reasons: Vec<String>,
        /// The prepared request the Gate's hold named its press for.
        ask: Option<super::approval::HeldConnectorAsk>,
    },
    Refused {
        decision_ref: Option<String>,
        reasons: Vec<String>,
    },
    Retryable {
        intent: [u8; 32],
        reasons: Vec<String>,
    },
    Unsettled {
        intent: [u8; 32],
        reasons: Vec<String>,
    },
    /// Definitely never delivered, and no retry of it will be (FIX 2553):
    /// the connector moved from the endpoint the call froze.
    NotDelivered {
        intent: [u8; 32],
        reasons: Vec<String>,
    },
    /// Delivered, and the connector asked for input instead of answering.
    AwaitingInput {
        intent: Option<[u8; 32]>,
        input: ConnectorAwaitingInput,
    },
}

fn held(reason: &str) -> Step {
    Step::Held {
        decision_ref: None,
        reasons: vec![reason.to_owned()],
        ask: None,
    }
}

pub(super) fn refused(reason: &str) -> Step {
    Step::Refused {
        decision_ref: None,
        reasons: vec![reason.to_owned()],
    }
}

impl Step {
    /// The reasons a hold or a refusal carries.
    fn into_reasons(self) -> Vec<String> {
        match self {
            Self::Held { reasons, .. }
            | Self::Refused { reasons, .. }
            | Self::Retryable { reasons, .. }
            | Self::Unsettled { reasons, .. }
            | Self::NotDelivered { reasons, .. } => reasons,
            Self::Delivered { .. } | Self::AwaitingInput { .. } => Vec::new(),
        }
    }
}

impl Vault {
    /// One tool's approved input schema for the caller `memory` is bound
    /// to, through the same route, grant and governing key a call of it
    /// takes. Reads only; nothing is held, sent or written. Each catalog
    /// key, grant, governing key and slate it reads lists on the answer,
    /// however the read ends (FIX 5816).
    pub fn connector_tool_schema(
        &self,
        memory: &Memory<'_>,
        name: &str,
        tool: &str,
    ) -> Result<ConnectorToolSchema, IntentLedgerError> {
        if !std::ptr::eq(memory.vault(), self) {
            return Err(IntentLedgerError::InvalidInput(
                "the caller's scope is bound to another vault",
            ));
        }
        let mut read = Vec::new();
        let schema =
            self.connector_tool_schema_reading(&memory.actor().to_hex(), name, tool, &mut read);
        memory.produced_from(read);
        schema
    }

    /// [`Self::connector_tool_schema`] for `principal_ref`, listing each row
    /// it reads in `read`.
    fn connector_tool_schema_reading(
        &self,
        principal_ref: &str,
        name: &str,
        tool: &str,
        read: &mut Vec<EntityId>,
    ) -> Result<ConnectorToolSchema, IntentLedgerError> {
        let unavailable = |stop: Step| ConnectorToolSchema::Unavailable {
            reasons: stop.into_reasons(),
        };
        let (route, catalog_key) = self.route_connector_call_listing(name)?;
        read.extend(catalog_key);
        let Some(route) = route else {
            return Ok(unavailable(refused("connector_not_routable")));
        };
        let Some(server) = canonical_scoped_server_segment(&route.name) else {
            return Ok(unavailable(refused("connector_name_not_scoped")));
        };
        let governed = match self.governing_tool(principal_ref, &server, tool, read)? {
            Ok(governed) => governed,
            Err(stop) => return Ok(unavailable(stop)),
        };
        // A tool its setting removes (FIX 990), its holder's own narrow
        // included (FIX 987), is not callable: there is no schema to call by.
        if self.connector_tool_setting(&governed.key_id, tool)? == SlateDisposition::NeverAllow {
            return Ok(unavailable(refused(escalation_code(
                ScopedMcpEscalationReason::ConnectorSlateNeverAllow,
            ))));
        }
        let (_, destructive_hint, _) =
            self.connector_tool_class(&governed.key, &route, tool, read)?;
        Ok(ConnectorToolSchema::Approved {
            input_schema: governed.schema,
            destructive_hint,
        })
    }

    /// One pass and what it leaves durable. `call_ref` names the row the
    /// call already holds; `new_ref`, the ref a first hold takes (a fresh
    /// one when `None`). A terminal outcome of a call with a row keeps that
    /// row, settled, for the settler's acknowledgement; one with none
    /// writes nothing.
    pub(super) fn drive_connector_call<H: ConnectorCallHost>(
        &self,
        call_ref: Option<EntityId>,
        new_ref: Option<EntityId>,
        mut pending: PendingConnectorCall,
        host: &mut H,
    ) -> Result<(ConnectorCallOutcome, Option<Vec<EntityId>>), IntentLedgerError> {
        // A custody record a host presented for an earlier send is never
        // this pass's; the record and grant this call names are its own.
        drop(host.take_sent_custody());
        let named = pending
            .credential
            .into_iter()
            .chain(pending.grant.map(|grant| grant.grant()));
        pending.list_rows(named.collect::<Vec<_>>());
        // A call that names a custody record sends with it or not at all.
        let mut scope_evidence = None;
        let step = if host.present_credential(pending.credential, pending.grant) {
            // A call its row already holds resumes through the ledger row it
            // admitted, if any; only a call with none resolves and prepares
            // live.
            let resumed = match call_ref {
                Some(_) => self.resume_connector_call_intent(&pending, host)?,
                None => None,
            };
            match resumed {
                Some(step) => step,
                None => self.connector_call_step(&mut pending, host, &mut scope_evidence)?,
            }
        } else {
            refused(CONNECTOR_CALL_CREDENTIAL_UNSUPPORTED)
        };
        // The record the host's door resolved for a send (FIX 5455).
        match host.take_sent_custody() {
            Some(custody) => pending.list_rows(custody),
            None => pending.source_rows = None,
        }
        let rows = pending.source_rows.clone();
        let step = self.connector_reply_cleared(host.clears_at_door(), &pending, step);
        let keep = |call_ref: Option<EntityId>, pending: &PendingConnectorCall| {
            let call_ref = call_ref.or(new_ref).unwrap_or_else(EntityId::now);
            self.with_write_txn(|txn| {
                put_pending_call_in_txn(&self.store, txn, &call_ref, pending)
            })?;
            Ok::<_, IntentLedgerError>(call_ref)
        };
        let settle = |call_ref: Option<EntityId>, settled: SettledConnectorCall| {
            if let Some(call_ref) = call_ref {
                let row = PendingConnectorCall {
                    settled: Some(settled),
                    ..pending.clone()
                };
                self.with_write_txn(|txn| {
                    put_pending_call_in_txn(&self.store, txn, &call_ref, &row)
                })?;
            }
            Ok::<_, IntentLedgerError>(())
        };
        let outcome = match step {
            Step::Delivered { intent, result } => {
                settle(call_ref, SettledConnectorCall::Delivered { intent })?;
                ConnectorCallOutcome::Delivered { intent, result }
            }
            // The call reached the connector, which asked for input: the
            // call's row, kept for a first call too, holds the round for its
            // caller to poll, and the host keeps it current (FIX 3837).
            // A row that cannot keep them leaves no caller to answer them.
            Step::AwaitingInput { intent, input } => {
                let row = PendingConnectorCall {
                    held_reasons: Vec::new(),
                    input: Some(super::connector_call_input::PendingConnectorInput::kept(
                        intent, &input,
                    )),
                    ..pending.clone()
                };
                match keep(call_ref, &row) {
                    Ok(call_ref) => {
                        host.bind_awaiting_call(&input.handle, call_ref);
                        ConnectorCallOutcome::AwaitingInput {
                            call_ref,
                            intent,
                            input,
                        }
                    }
                    Err(error) => {
                        host.abandon_awaiting_input(&input.handle);
                        return Err(error);
                    }
                }
            }
            Step::Refused {
                decision_ref,
                reasons,
            } => {
                settle(
                    call_ref,
                    SettledConnectorCall::Refused {
                        decision_ref: decision_ref.clone(),
                        reasons: reasons.clone(),
                    },
                )?;
                ConnectorCallOutcome::Refused {
                    decision_ref,
                    reasons,
                }
            }
            Step::Unsettled { intent, reasons } => {
                settle(
                    call_ref,
                    SettledConnectorCall::Unsettled {
                        intent,
                        reasons: reasons.clone(),
                    },
                )?;
                ConnectorCallOutcome::PendingDelivery {
                    intent,
                    call_ref: None,
                    reasons,
                }
            }
            Step::Held {
                decision_ref,
                reasons,
                ask,
            } => {
                // FIX 6424 part 3: the row keeps this hold's ask as its
                // current one (none for an administrative hold).
                let mut row = pending.clone();
                super::approval::retain_held_ask(&mut row, ask.as_ref());
                // A hold for consent alone binds a code consent wait in the
                // same writer, when the call came from a code run.
                let (call_ref, code_owned) =
                    self.keep_held_connector_call(call_ref.or(new_ref), &row, &reasons)?;
                // FIX 988: a typed scope exceed is kept, once per logical
                // call, as evidence for the owner's revision offer.
                if let Some(evidence) = scope_evidence {
                    crate::connector_key::keep_connector_scope_signal(
                        self,
                        evidence,
                        call_ref,
                        decision_ref.as_deref(),
                        ask.as_ref().map(|ask| ask.approval_digest.as_str()),
                    );
                }
                // The hold is durable: ask the owner about it, once. The
                // settler's pass repairs an ask that did not queue here. A
                // code consent wait asks its own question instead.
                if !code_owned
                    && let Err(error) = self.queue_connector_call_owner_ask(&call_ref, &reasons)
                {
                    tracing::warn!(
                        call_ref = %call_ref.to_hex(),
                        %error,
                        "connector call owner ask not queued"
                    );
                }
                ConnectorCallOutcome::Held {
                    call_ref,
                    decision_ref,
                    reasons,
                    approval_digest: ask.map(|ask| ask.approval_digest),
                }
            }
            Step::Retryable { intent, reasons } => ConnectorCallOutcome::PendingDelivery {
                intent,
                call_ref: Some(keep(call_ref, &pending)?),
                reasons,
            },
            // The ledger stops the send, so nothing resends it, and the call
            // reads its definite non-delivery at once: its caller re-issues
            // it against the connector as now installed (FIX 2553).
            Step::NotDelivered { intent, reasons } => {
                abandon_record(
                    self,
                    intent,
                    IntentEscalationReason::BindingInvalid,
                    now_ms(),
                )?;
                settle(
                    call_ref,
                    SettledConnectorCall::Refused {
                        decision_ref: None,
                        reasons: reasons.clone(),
                    },
                )?;
                ConnectorCallOutcome::Refused {
                    decision_ref: None,
                    reasons,
                }
            }
        };
        Ok((outcome, rows))
    }

    /// One pass: route, grant, governing key, approved schema, prepare,
    /// execute. Records the grant it ran under on `pending`, and lists there
    /// each row it reads to pick them (FIX 5455). A typed scope exceed on
    /// its own grant lands in `scope_evidence` (FIX 988).
    fn connector_call_step<H: ConnectorCallHost>(
        &self,
        pending: &mut PendingConnectorCall,
        host: &mut H,
        scope_evidence: &mut Option<ConnectorScopeEvidence>,
    ) -> Result<Step, IntentLedgerError> {
        let (route, catalog_key) = self.route_connector_call_listing(&pending.name)?;
        pending.list_rows(catalog_key);
        let Some(route) = route else {
            return Ok(refused("connector_not_routable"));
        };
        let Some(server) = canonical_scoped_server_segment(&route.name) else {
            return Ok(refused("connector_name_not_scoped"));
        };
        let Some(endpoint) = host.tool_endpoint(&route) else {
            return Ok(refused("connector_endpoint_not_installed"));
        };
        let preferred = pending
            .grant_id
            .as_deref()
            .and_then(|hex| EntityId::from_hex(hex).ok());
        let mut read = Vec::new();
        let found = self.connector_call_grant(
            &pending.principal_ref,
            &server,
            &pending.tool,
            preferred,
            &mut read,
        )?;
        pending.list_rows(read);
        let Some((grant_id, grant)) = found else {
            return Ok(held("standing_grant_required"));
        };
        pending.grant_id = Some(grant_id.to_hex());
        // The gate binds the same actor from the same principal reference.
        let actor = EntityId::from_hex(&pending.principal_ref).unwrap_or(grant_id);
        let Some(capability) = ScopedCapabilityProvenance::mint(&server, &grant_id) else {
            return Ok(refused("connector_name_not_scoped"));
        };
        let Some((key_id, key)) = self.connector_key_for(capability.connector(), Some(&actor))?
        else {
            return Ok(held("connector_key_unregistered"));
        };
        pending.list_rows([key_id]);
        match key.status {
            ConnectorKeyStatus::Active => {}
            ConnectorKeyStatus::Revoked => return Ok(refused("connector_key_revoked")),
            ConnectorKeyStatus::Suspended => return Ok(held("connector_key_suspended")),
            ConnectorKeyStatus::Pending => return Ok(held("connector_key_pending")),
        }
        // FIX 988: a row that depends on a credential binding whose issuer
        // changed holds until the owner accepts its re-ask.
        let issuer_held = {
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            crate::connector_key::connector_issuer_hold_in_txn(
                &self.store,
                &txn,
                &key_id,
                &key,
                &pending.tool,
            )?
        };
        if issuer_held {
            return Ok(held(CONNECTOR_ISSUER_HOLD_REASON));
        }
        let Some(manifest) = key.retained_manifest.as_ref() else {
            return Ok(held("connector_manifest_unapproved"));
        };
        let Some(schema) = manifest
            .tools()
            .iter()
            .find(|tool| tool.name == pending.tool)
            .map(|tool| tool.input_schema.clone())
        else {
            return Ok(if key.pending_manifest.is_some() {
                held("connector_manifest_drift")
            } else {
                refused("connector_tool_unknown")
            });
        };
        if key.tool_requires_confirmation(&pending.tool) {
            return Ok(held("connector_manifest_drift"));
        }
        if key.protocol_revision.is_none() {
            return Ok(held("connector_protocol_unpinned"));
        }
        let mut slates = Vec::new();
        let (payload_data_class, destructive_hint, replay) =
            self.connector_tool_class(&key, &route, &pending.tool, &mut slates)?;
        pending.list_rows(slates);
        let arguments: Value = serde_json::from_str(&pending.arguments)
            .map_err(|_| IntentLedgerError::InvalidRecord("held connector call arguments"))?;
        let call = ScopedMcpCallContext {
            server,
            tool: pending.tool.clone(),
            payload_data_class,
            resolved_endpoint: endpoint,
        };
        let descriptor = ToolCallDescriptor {
            schema: &schema,
            destructive_hint,
            // The slate row's declared hints: a tool declared neither
            // read-only nor idempotent is effectful and not idempotent.
            replay,
        };
        // FIX 990: the tool's setting, read with the key. An `always ask`
        // call still goes to its admission, which spends the owner's press
        // on exactly this call if one is waiting and else holds it naming
        // the digest; `never allow` mints nothing to send.
        let prepared = match self.prepare_connector_tool_call(
            &key_id,
            call,
            descriptor,
            &arguments,
            pending.mutation,
        ) {
            Ok(ConnectorToolCallPreparation::Ready(prepared)) => prepared,
            Ok(ConnectorToolCallPreparation::ConsentRequired { candidate }) => candidate,
            Ok(ConnectorToolCallPreparation::Denied { reason }) => {
                return Ok(refused(escalation_code(reason)));
            }
            Err(Error::InvalidConfig(_)) => return Ok(refused("connector_arguments_invalid")),
            Err(error) => return Err(error.into()),
        };
        // A code consent pass sends only the frozen bytes its wait bound.
        if let Some(stop) =
            super::connector_call_code::before_send(pending, &prepared, grant_id, key_id)
        {
            return Ok(stop);
        }
        let authority = OutboundBindingAuthority::for_vault(self)?;
        // A question the connector asks binds to this caller and grant.
        host.bind_caller(Some(ConnectorCallCaller {
            principal_ref: pending.principal_ref.clone(),
            grant_id,
            name: pending.name.clone(),
        }));
        // A reply or questions left from an earlier send are never this
        // call's, and no caller holds such questions (FIX 3844).
        drop(host.take_result());
        if let Some(left) = host.take_awaiting_input() {
            host.abandon_awaiting_input(&left.handle);
        }
        let sent = prepared.call().clone();
        // An off-record caller's admitted request stays sealed in the ledger (FIX 9372).
        let dispatch = prepared.keeping_no_record(pending.off_record).execute(
            self,
            &authority,
            grant_id,
            &grant,
            &pending.principal_ref,
            pending.attempt_id,
            pending.call_seq,
            now_ms(),
            &mut *host,
        )?;
        if let ScopedMcpConsentDecision::Escalate(reason) = dispatch.decision {
            *scope_evidence = crate::connector_key::connector_scope_evidence(
                reason,
                &grant,
                grant_id,
                key_id,
                ScopeExceedCall {
                    connector: &pending.name,
                    principal_ref: &pending.principal_ref,
                    attempt: pending.attempt_id.as_bytes(),
                    call_seq: pending.call_seq,
                    call: &sent,
                },
            );
        }
        Ok(step_from_host(&dispatch, host))
    }

    /// The principal's grant for `server` and `tool`, the governing key it
    /// mints and the tool's approved schema there, for a schema read. It
    /// follows `connector_call_step`'s resolution step for step (the same
    /// grant lookup, capability, governing key, status and manifest checks);
    /// a stop is the hold or refusal a call meets there. Each grant and
    /// key it reads is listed in `read` (FIX 5816).
    fn governing_tool(
        &self,
        principal_ref: &str,
        server: &str,
        tool: &str,
        read: &mut Vec<EntityId>,
    ) -> Result<std::result::Result<GoverningTool, Step>, IntentLedgerError> {
        let Some((grant_id, _)) =
            self.connector_call_grant(principal_ref, server, tool, None, read)?
        else {
            return Ok(Err(held("standing_grant_required")));
        };
        // The gate binds the same actor from the same principal reference.
        let actor = EntityId::from_hex(principal_ref).unwrap_or(grant_id);
        let Some(capability) = ScopedCapabilityProvenance::mint(server, &grant_id) else {
            return Ok(Err(refused("connector_name_not_scoped")));
        };
        let Some((key_id, key)) = self.connector_key_for(capability.connector(), Some(&actor))?
        else {
            return Ok(Err(held("connector_key_unregistered")));
        };
        read.push(key_id);
        match key.status {
            ConnectorKeyStatus::Active => {}
            ConnectorKeyStatus::Revoked => return Ok(Err(refused("connector_key_revoked"))),
            ConnectorKeyStatus::Suspended => return Ok(Err(held("connector_key_suspended"))),
            ConnectorKeyStatus::Pending => return Ok(Err(held("connector_key_pending"))),
        }
        let Some(manifest) = key.retained_manifest.as_ref() else {
            return Ok(Err(held("connector_manifest_unapproved")));
        };
        let Some(schema) = manifest
            .tools()
            .iter()
            .find(|found| found.name == tool)
            .map(|found| found.input_schema.clone())
        else {
            return Ok(Err(if key.pending_manifest.is_some() {
                held("connector_manifest_drift")
            } else {
                refused("connector_tool_unknown")
            }));
        };
        Ok(Ok(GoverningTool {
            key_id,
            key,
            schema,
        }))
    }

    /// The principal's live scoped grant for exactly this server and tool:
    /// the one the call last ran under when it still matches, else the first
    /// in index order. Each grant it reads is listed in `read`.
    fn connector_call_grant(
        &self,
        principal_ref: &str,
        server: &str,
        tool: &str,
        preferred: Option<EntityId>,
        read: &mut Vec<EntityId>,
    ) -> crate::Result<Option<(EntityId, StandingOutboundGrant)>> {
        let (ids, floor) = {
            let txn = self.store.env.read_txn()?;
            let floor =
                crate::gate::resolve_policy_manifest(&self.store, &txn)?.read_frontier_hash()?;
            let ids = crate::outbound_grant::standing_outbound_grant_ids_for_principal(
                &self.store,
                &txn,
                principal_ref,
            )?;
            (ids, floor)
        };
        let mut first = None;
        for id in ids {
            let Some(grant) = self.get_standing_outbound_grant(&id)? else {
                continue;
            };
            read.push(id);
            if grant.principal_ref != principal_ref || !grant.is_active_under_policy(&floor) {
                continue;
            }
            let Some(scope) = grant.scope.scoped_mcp_grant() else {
                continue;
            };
            if scope.server != server || scope.tool != tool {
                continue;
            }
            if preferred == Some(id) {
                return Ok(Some((id, grant)));
            }
            if first.is_none() {
                first = Some((id, grant));
            }
        }
        Ok(first)
    }

    /// The tool's payload class, destructive flag and declared replay hints
    /// from its slate row on the governing key, else on the catalog key. A
    /// tool no slate names is Unclassified, which the grant check holds for
    /// the owner. Each slate it reads is listed in `read`.
    pub(super) fn connector_tool_class(
        &self,
        governing: &ConnectorKeyRecord,
        route: &ConnectorCallRoute,
        tool: &str,
        read: &mut Vec<EntityId>,
    ) -> crate::Result<(DataClass, bool, OutboundToolDescriptor)> {
        let catalog_slate = self
            .get_connector_key(&route.key_ref)?
            .and_then(|key| key.slate_ref);
        for slate_id in [governing.slate_ref, catalog_slate].into_iter().flatten() {
            let slate = self.connector_slate(slate_id)?;
            if slate.is_some() {
                read.push(slate_id);
            }
            if let Some(slate) = slate
                && let Some(row) = slate.tool(tool)
            {
                let class = match row.data_class {
                    SlateDataClass::Public => DataClass::Public,
                    SlateDataClass::Personal => DataClass::Personal,
                    SlateDataClass::Secret => DataClass::Secret,
                    SlateDataClass::Header => DataClass::Unclassified,
                };
                let replay = OutboundToolDescriptor {
                    read_only_hint: Some(row.read_only),
                    idempotency_supported_hint: Some(row.idempotent),
                };
                return Ok((class, row.destroys, replay));
            }
        }
        let replay = OutboundToolDescriptor {
            read_only_hint: None,
            idempotency_supported_hint: None,
        };
        Ok((DataClass::Unclassified, false, replay))
    }
}
