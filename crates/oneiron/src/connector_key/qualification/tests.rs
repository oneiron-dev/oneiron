use super::*;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    Lists,
    Headers,
    ResultType,
    Key,
    HiddenWrite,
    MissingWriteTrace,
    DuplicateWriteTrace,
    ConstantEffect,
    Quote,
    Claim,
    Scope,
    Trace,
    Foreign,
    Replay,
    Tokens,
    Budget,
    ReadOnly,
    RefusedCommitted,
}
struct Stub {
    fault: Fault,
    connections: Cell<usize>,
    effects: Rc<RefCell<BTreeMap<String, u64>>>,
}
struct Connection {
    fault: Fault,
    number: usize,
    effects: Rc<RefCell<BTreeMap<String, u64>>>,
}
impl QualificationConnector for Stub {
    fn connect(&self) -> Result<Box<dyn QualificationConnection + '_>, QualificationFailure> {
        let number = self.connections.get();
        self.connections.set(number + 1);
        Ok(Box::new(Connection {
            fault: self.fault,
            number,
            effects: self.effects.clone(),
        }))
    }
    fn effect_state(&self) -> Result<Vec<u8>, QualificationFailure> {
        Ok(serde_json::to_vec(&*self.effects.borrow()).unwrap())
    }
}
impl QualificationConnection for Connection {
    fn tools_list(&mut self) -> Result<Vec<ProbeTool>, QualificationFailure> {
        Ok(vec![ProbeTool {
            name: if self.fault == Fault::Lists && self.number == 1 {
                "different".into()
            } else {
                "memory".into()
            },
            input_schema: if self.fault == Fault::Key {
                json!({"type":"object"})
            } else {
                json!({"type":"object","properties":{"idempotency_key":{"type":"string"}}})
            },
            trigger: None,
            result_types: BTreeSet::from([if self.fault == Fault::ResultType {
                "unknown".into()
            } else {
                "record".into()
            }]),
            writes: self.fault != Fault::HiddenWrite && self.fault != Fault::ReadOnly,
        }])
    }
    fn call(&mut self, request: &ProbeRequest) -> Result<ProbeReply, QualificationFailure> {
        let mut headers = BTreeMap::from([
            ("Mcp-Method".into(), "tools/call".into()),
            ("Mcp-Name".into(), request.name.clone()),
        ]);
        if self.fault == Fault::Headers {
            headers.insert("Mcp-Name".into(), "wrong".into());
        }
        let body = json!({"jsonrpc":"2.0","id":request.id,"method":"tools/call","params":{"name":request.name,"arguments":request.arguments}});
        let mut disposition = if request.arguments["outside"] == true {
            ProbeDisposition::NoRecord
        } else {
            ProbeDisposition::Answer
        };
        if self.fault == Fault::RefusedCommitted
            && request.arguments["write"] == true
            && request.arguments["timeout_once"] != true
        {
            disposition = ProbeDisposition::Refused;
        }
        let mut writes = Vec::new();
        if request.arguments["write"] == true {
            let key = request.arguments["idempotency_key"].as_str().unwrap();
            let key = if self.fault == Fault::ConstantEffect {
                key.trim_end_matches("-distinct")
            } else {
                key
            };
            let mut effects = self.effects.borrow_mut();
            let prior = effects.contains_key(key);
            if !prior || self.fault == Fault::Replay {
                *effects.entry(key.into()).or_default() += 1;
            }
            if request.arguments["timeout_once"] == true && !prior {
                disposition = ProbeDisposition::Timeout;
            }
            writes.push(ProbeWrite {
                reference: key.into(),
                predicate: if self.fault == Fault::Scope {
                    "private.secret".into()
                } else {
                    "profile.name".into()
                },
                citations: vec![ProbeCitation {
                    source_ref: "turn".into(),
                    start: 0,
                    end: 3,
                    quote: if self.fault == Fault::Quote {
                        b"lie".to_vec()
                    } else {
                        b"Ada".to_vec()
                    },
                }],
            });
        }
        let mut kinds = vec![
            ProbeTraceKind::Start,
            ProbeTraceKind::Retrieval,
            ProbeTraceKind::ForeignAsk,
        ];
        if self.fault != Fault::Foreign {
            kinds.push(ProbeTraceKind::Quarantine);
        }
        if !writes.is_empty() && self.fault != Fault::MissingWriteTrace {
            kinds.push(ProbeTraceKind::Write);
            if self.fault == Fault::DuplicateWriteTrace {
                kinds.push(ProbeTraceKind::Write);
            }
        }
        kinds.push(ProbeTraceKind::End);
        let mut trace: Vec<_> = kinds
            .into_iter()
            .enumerate()
            .map(|(i, kind)| ProbeTraceEvent {
                sequence: i as u64,
                request_id: request.id.clone(),
                reference: Some(if kind == ProbeTraceKind::Write {
                    writes[0].reference.clone()
                } else if kind == ProbeTraceKind::Retrieval {
                    "turn".into()
                } else {
                    "foreign".into()
                }),
                kind,
            })
            .collect();
        if self.fault == Fault::Trace {
            trace[1].sequence = 99;
        }
        let no_record = disposition == ProbeDisposition::NoRecord;
        Ok(ProbeReply {
            request_headers: headers,
            request_body: body,
            disposition,
            result_type: "record".into(),
            result: if no_record {
                Value::Null
            } else {
                json!({"record":"Ada"})
            },
            writes,
            answer_claim_refs: if no_record {
                vec![]
            } else {
                vec![if self.fault == Fault::Claim {
                    "fabricated".into()
                } else {
                    "claim".into()
                }]
            },
            retrieval_refs: if no_record {
                vec![]
            } else {
                vec!["turn".into()]
            },
            trace,
            tokens: if self.fault == Fault::Tokens { 100 } else { 1 },
            budget_units: if self.fault == Fault::Budget { 100 } else { 1 },
        })
    }
}
struct Oracle;
impl GroundingOracle for Oracle {
    fn source_bytes(&self, reference: &str) -> Option<Vec<u8>> {
        (reference == "turn").then(|| b"Ada Lovelace".to_vec())
    }
    fn claim_sources(&self, reference: &str) -> Option<Vec<String>> {
        (reference == "claim").then(|| vec!["turn".into()])
    }
}
fn plan() -> QualificationPlan {
    let case = |id: &str, args: Value| QualificationCase {
        call: ProbeRequest {
            id: id.into(),
            name: "memory".into(),
            arguments: args,
        },
        in_scope: true,
        allowed_predicates: BTreeSet::from(["profile.name".into()]),
    };
    let mut outside = case(
        "outside",
        json!({"outside":true,"idempotency_key":"outside-key"}),
    );
    outside.in_scope = false;
    QualificationPlan {
        reads: vec![case("read", json!({"idempotency_key":"read-key"})), outside],
        write: Some(case(
            "write",
            json!({"write":true,"idempotency_key":"write-key"}),
        )),
        timeout_retry: Some(case(
            "timeout",
            json!({"write":true,"timeout_once":true,"idempotency_key":"timeout-key"}),
        )),
        handled_result_types: BTreeSet::from(["record".into()]),
        limits: QualificationLimits {
            tokens: 10,
            latency_ms: 1000,
            budget_units: 10,
        },
    }
}
#[test]
fn independent_connections_grounding_and_retries_qualify_one_effect_per_key() {
    let stub = Stub {
        fault: Fault::None,
        connections: Cell::new(0),
        effects: Rc::default(),
    };
    let report = qualify_connector(&stub, &plan(), &Oracle).unwrap();
    assert_eq!(
        report.exercised_result_types,
        BTreeSet::from(["record".into()])
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&stub.effect_state().unwrap()).unwrap(),
        json!({"write-key":1,"timeout-key":1,"write-key-distinct":1,"timeout-key-distinct":1})
    );
}
#[test]
fn probes_refuse_each_broken_connector_contract() {
    for (fault, expected) in [
        (Fault::Lists, QualificationFailure::StatelessMismatch),
        (Fault::Headers, QualificationFailure::HeaderMismatch),
        (Fault::ResultType, QualificationFailure::ResultType),
        (Fault::Key, QualificationFailure::IdempotencyArgument),
        (Fault::HiddenWrite, QualificationFailure::IncompletePlan),
        (Fault::MissingWriteTrace, QualificationFailure::Trace),
        (Fault::DuplicateWriteTrace, QualificationFailure::Trace),
        (Fault::ConstantEffect, QualificationFailure::Replay),
        (Fault::Quote, QualificationFailure::Grounding),
        (Fault::Claim, QualificationFailure::Grounding),
        (Fault::Scope, QualificationFailure::Scope),
        (Fault::Trace, QualificationFailure::Trace),
        (Fault::Foreign, QualificationFailure::ForeignAsk),
        (Fault::Replay, QualificationFailure::Replay),
        (Fault::Tokens, QualificationFailure::Envelope),
        (Fault::Budget, QualificationFailure::Envelope),
    ] {
        let stub = Stub {
            fault,
            connections: Cell::new(0),
            effects: Rc::default(),
        };
        assert_eq!(qualify_connector(&stub, &plan(), &Oracle), Err(expected));
    }
    let stub = Stub {
        fault: Fault::None,
        connections: Cell::new(0),
        effects: Rc::default(),
    };
    for reads in [
        vec![],
        vec![plan().reads[0].clone()],
        vec![plan().reads[1].clone()],
    ] {
        let stub = Stub {
            fault: Fault::None,
            connections: Cell::new(0),
            effects: Rc::default(),
        };
        let mut incomplete = plan();
        incomplete.reads = reads;
        assert_eq!(
            qualify_connector(&stub, &incomplete, &Oracle),
            Err(QualificationFailure::IncompletePlan)
        );
    }
    let mut invalid = plan();
    invalid
        .write
        .as_mut()
        .unwrap()
        .call
        .arguments
        .as_object_mut()
        .unwrap()
        .remove("idempotency_key");
    assert_eq!(
        qualify_connector(&stub, &invalid, &Oracle),
        Err(QualificationFailure::IdempotencyArgument)
    );
}

#[test]
fn write_probes_refuse_request_ids_as_idempotency_keys() {
    for timeout_retry in [false, true] {
        let stub = Stub {
            fault: Fault::None,
            connections: Cell::new(0),
            effects: Rc::default(),
        };
        let mut invalid = plan();
        let call = if timeout_retry {
            &mut invalid.timeout_retry.as_mut().unwrap().call
        } else {
            &mut invalid.write.as_mut().unwrap().call
        };
        call.arguments["idempotency_key"] = Value::String(call.id.clone());
        assert_eq!(
            qualify_connector(&stub, &invalid, &Oracle),
            Err(QualificationFailure::IdempotencyArgument)
        );
    }
}

#[test]
fn read_only_suite_has_no_write_probe_and_refused_effect_fails() {
    let stub = Stub {
        fault: Fault::ReadOnly,
        connections: Cell::new(0),
        effects: Rc::default(),
    };
    let mut read_plan = plan();
    read_plan.write = None;
    read_plan.timeout_retry = None;
    let report = qualify_connector(&stub, &read_plan, &Oracle).expect("read-only connector");
    assert_eq!(report.calls, read_plan.reads.len() * 2);
    assert_eq!(stub.effect_state().unwrap(), b"{}".to_vec());
    let refusing = Stub {
        fault: Fault::RefusedCommitted,
        connections: Cell::new(0),
        effects: Rc::default(),
    };
    assert_eq!(
        qualify_connector(&refusing, &plan(), &Oracle),
        Err(QualificationFailure::Replay)
    );
}

#[test]
fn pending_slate_key_only_activates_after_full_probes_and_owner_stamp() -> crate::error::Result<()>
{
    use crate::connector_key::{
        ConnectorCallClass, ConnectorCatalogEntry, ConnectorKeySpec, ConnectorKeyStatus,
        SlateDataClass, SlateToolManifest, draft_connector_slate,
    };
    use crate::{EntityId, Vault, VaultConfig};
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let manifest = vec![SlateToolManifest {
        name: "memory".into(),
        data_class: SlateDataClass::Personal,
        header_parameters: vec![],
        trigger: None,
        resolved_input_schema: Some(
            json!({"type":"object","properties":{"idempotency_key":{"type":"string"}}}),
        ),
        destroys: false,
        spends: false,
        sends_outward: false,
        legacy_ask: false,
    }];
    let slate_id = vault.store_connector_slate(
        &manifest,
        &serde_json::to_string(&draft_connector_slate(&manifest)).unwrap(),
    )?;
    let (key_id, pending) = vault.register_connector(
        ConnectorCatalogEntry {
            name: "memory".into(),
            connector: "memory".into(),
            summary: "Memory connector".into(),
            verbs: vec!["read".into()],
            call_class: ConnectorCallClass::ScopedMcp,
            registered_at: 0,
        },
        ConnectorKeySpec {
            slate_ref: Some(slate_id),
            protocol_revision: Some("2026-09-01".into()),
            ..ConnectorKeySpec::new("memory")
        },
        100,
    )?;
    // The same owner's consent cannot be replayed onto a second key.
    assert!(
        vault
            .register_connector(
                ConnectorCatalogEntry {
                    name: "other_memory".into(),
                    connector: "other_memory".into(),
                    summary: "Other connector".into(),
                    verbs: vec![],
                    call_class: ConnectorCallClass::ScopedMcp,
                    registered_at: 0,
                },
                ConnectorKeySpec {
                    slate_ref: Some(slate_id),
                    protocol_revision: Some("2026-09-01".into()),
                    ..ConnectorKeySpec::new("other_memory")
                },
                100,
            )
            .is_err()
    );
    assert!(vault.describe_connector("other_memory")?.is_none());
    assert_eq!(pending.status, ConnectorKeyStatus::Pending);
    assert_eq!(
        vault.get_connector_key(&key_id)?.unwrap().status,
        ConnectorKeyStatus::Pending
    );
    assert!(vault.route_connector_call("memory")?.is_none());
    // A revision before first approval cannot launder the missing stamp.
    let revised = vault.revise_connector_protocol(&key_id, "2026-09-02", slate_id, 100)?;
    assert!(revised.consent_required);
    let revised = vault.revise_connector_protocol(&key_id, "2026-09-01", slate_id, 100)?;
    assert!(revised.consent_required);
    let good = || Stub {
        fault: Fault::None,
        connections: Cell::new(0),
        effects: Rc::default(),
    };
    let stub = good();
    assert!(
        vault
            .qualify_connector_key(&key_id, "2026-09-01", &stub, &plan(), &Oracle, 101)
            .is_err()
    );
    assert_eq!(stub.connections.get(), 0, "no probe write before consent");
    assert_eq!(
        vault.get_connector_key(&key_id)?.unwrap().status,
        ConnectorKeyStatus::Pending
    );

    let owner = EntityId::now();
    vault.put_entity(
        &owner,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let auth = vault.authenticate_owner(
        owner,
        &owner.to_hex(),
        true,
        crate::store::GateDecisionId::from_bytes(*EntityId::now().as_bytes()),
    )?;
    vault.override_connector_slate(&auth, slate_id, 0, &BTreeMap::new())?;
    let broken = Stub {
        fault: Fault::Headers,
        connections: Cell::new(0),
        effects: Rc::default(),
    };
    assert!(matches!(
        vault.qualify_connector_key(&key_id, "2026-09-01", &broken, &plan(), &Oracle, 102),
        Err(crate::connector_key::ConnectorQualificationError::Probe(
            QualificationFailure::HeaderMismatch
        ))
    ));
    assert!(vault.route_connector_call("memory")?.is_none());
    let refusing = Stub {
        fault: Fault::RefusedCommitted,
        connections: Cell::new(0),
        effects: Rc::default(),
    };
    assert!(matches!(
        vault.qualify_connector_key(&key_id, "2026-09-01", &refusing, &plan(), &Oracle, 102),
        Err(crate::connector_key::ConnectorQualificationError::Probe(
            QualificationFailure::Replay
        ))
    ));
    assert_eq!(
        vault.get_connector_key(&key_id)?.unwrap().status,
        ConnectorKeyStatus::Pending
    );
    assert!(vault.route_connector_call("memory")?.is_none());
    let (active, report) = vault
        .qualify_connector_key(&key_id, "2026-09-01", &good(), &plan(), &Oracle, 103)
        .unwrap();
    assert_eq!(report.calls, 14);
    assert_eq!(active.status, ConnectorKeyStatus::Active);
    assert_eq!(vault.get_connector_key(&key_id)?.unwrap(), active);
    assert!(vault.route_connector_call("memory")?.is_some());

    let pending = vault.revise_connector_protocol(&key_id, "2026-09-02", slate_id, 104)?;
    assert_eq!(pending.status, ConnectorKeyStatus::Pending);
    assert_eq!(pending.protocol_revision.as_deref(), Some("2026-09-02"));
    assert!(vault.route_connector_call("memory")?.is_none());
    assert!(
        vault
            .qualify_connector_key(&key_id, "2026-09-01", &good(), &plan(), &Oracle, 105)
            .is_err()
    );
    let (requalified, _) = vault
        .qualify_connector_key(&key_id, "2026-09-02", &good(), &plan(), &Oracle, 106)
        .unwrap();
    assert_eq!(requalified.status, ConnectorKeyStatus::Active);
    assert_eq!(requalified.slate_revision, Some(1));
    Ok(())
}

#[test]
fn read_only_key_qualifies_and_revision_expansion_needs_graded_consent() -> crate::error::Result<()>
{
    use crate::connector_key::{
        ConnectorCallClass, ConnectorCatalogEntry, ConnectorKeySpec, ConnectorKeyStatus,
        SlateDataClass, SlateToolManifest, draft_connector_slate,
    };
    use crate::{EntityId, Vault, VaultConfig};
    let tmp = tempfile::tempdir()?;
    let vault = Vault::open(tmp.path(), VaultConfig::default())?;
    let read_tool = SlateToolManifest {
        name: "memory".into(),
        data_class: SlateDataClass::Personal,
        header_parameters: vec![],
        trigger: None,
        resolved_input_schema: Some(
            json!({"type":"object","properties":{"idempotency_key":{"type":"string"}}}),
        ),
        destroys: false,
        spends: false,
        sends_outward: false,
        legacy_ask: false,
    };
    let make_slate = |manifest: &[SlateToolManifest]| -> crate::error::Result<EntityId> {
        vault.store_connector_slate(
            manifest,
            &serde_json::to_string(&draft_connector_slate(manifest))
                .map_err(|_| crate::error::Error::InvariantViolation("test slate encode"))?,
        )
    };
    let slate = make_slate(std::slice::from_ref(&read_tool))?;
    let (id, pending) = vault.register_connector(
        ConnectorCatalogEntry {
            name: "readable_feed".into(),
            connector: "readable".into(),
            summary: "Readable connector".into(),
            verbs: vec!["read".into()],
            call_class: ConnectorCallClass::CounterpartyComm,
            registered_at: 0,
        },
        ConnectorKeySpec {
            slate_ref: Some(slate),
            protocol_revision: Some("A".into()),
            ..ConnectorKeySpec::new("readable")
        },
        100,
    )?;
    assert_eq!(pending.status, ConnectorKeyStatus::Pending);
    let owner = EntityId::now();
    vault.put_entity(
        &owner,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let auth = vault.authenticate_owner(
        owner,
        &owner.to_hex(),
        true,
        crate::store::GateDecisionId::from_bytes(*EntityId::now().as_bytes()),
    )?;
    vault.override_connector_slate(&auth, slate, 0, &BTreeMap::new())?;
    let read_only = || Stub {
        fault: Fault::ReadOnly,
        connections: Cell::new(0),
        effects: Rc::default(),
    };
    let mut read_plan = plan();
    read_plan.write = None;
    read_plan.timeout_retry = None;
    assert_eq!(
        vault
            .qualify_connector_key(&id, "A", &read_only(), &read_plan, &Oracle, 101)
            .unwrap()
            .0
            .status,
        ConnectorKeyStatus::Active
    );
    assert_eq!(vault.search_connector_catalog("readable-feed")?.len(), 1);
    assert_eq!(vault.search_connector_catalog("connector")?.len(), 1);
    assert_eq!(vault.search_connector_catalog("")?.len(), 1);
    let route = vault
        .route_connector_call("readable_feed")?
        .expect("qualified route");
    assert!(route.budgeted_as_sends);
    assert_eq!(route.call_class, ConnectorCallClass::CounterpartyComm);
    assert_eq!(route.verbs, vec!["read".to_owned()]);

    // A narrowed declaration carries the prior owner's consent without a tap.
    let mut narrower = draft_connector_slate(std::slice::from_ref(&read_tool));
    narrower[0].disposition = crate::connector_key::SlateDisposition::ConfirmFirst;
    let narrow_slate = vault.store_connector_slate(
        std::slice::from_ref(&read_tool),
        &serde_json::to_string(&narrower).unwrap(),
    )?;
    vault.revise_connector_protocol(&id, "B", narrow_slate, 102)?;
    assert!(vault.route_connector_call("readable_feed")?.is_none());
    vault
        .qualify_connector_key(&id, "B", &read_only(), &read_plan, &Oracle, 103)
        .unwrap();

    let mut expanded = read_tool.clone();
    expanded.sends_outward = true;
    let expanded_slate = make_slate(&[expanded])?;
    let pending = vault.revise_connector_protocol(&id, "C", expanded_slate, 104)?;
    assert!(pending.consent_required);
    let pending = vault.revise_connector_protocol(&id, "C2", expanded_slate, 104)?;
    assert!(
        pending.consent_required,
        "unapproved expansion survives later drift"
    );
    let pending = vault.revise_connector_protocol(&id, "C", expanded_slate, 104)?;
    assert!(pending.consent_required);
    let stub = read_only();
    assert!(
        vault
            .qualify_connector_key(&id, "C", &stub, &read_plan, &Oracle, 105)
            .is_err()
    );
    assert_eq!(stub.connections.get(), 0);
    assert!(vault.route_connector_call("readable_feed")?.is_none());
    vault.override_connector_slate(&auth, expanded_slate, 0, &BTreeMap::new())?;
    assert_eq!(
        vault
            .qualify_connector_key(&id, "C", &read_only(), &read_plan, &Oracle, 106)
            .unwrap()
            .0
            .status,
        ConnectorKeyStatus::Active
    );
    // Removing declared send authority is a narrowing, not another approval.
    let mut narrowed_rows = draft_connector_slate(std::slice::from_ref(&read_tool));
    narrowed_rows[0].disposition = crate::connector_key::SlateDisposition::ConfirmFirst;
    let narrower_declaration = vault.store_connector_slate(
        &[read_tool],
        &serde_json::to_string(&narrowed_rows).unwrap(),
    )?;
    let pending = vault.revise_connector_protocol(&id, "D", narrower_declaration, 107)?;
    assert!(!pending.consent_required);
    assert_eq!(
        vault
            .qualify_connector_key(&id, "D", &read_only(), &read_plan, &Oracle, 108)
            .unwrap()
            .0
            .status,
        ConnectorKeyStatus::Active
    );
    Ok(())
}

#[test]
fn mid_probe_revision_round_trip_cannot_activate_stale_attempt() -> crate::error::Result<()> {
    use crate::connector_key::{
        ConnectorCallClass, ConnectorCatalogEntry, ConnectorKeySpec, ConnectorKeyStatus,
        SlateDataClass, SlateToolManifest, draft_connector_slate,
    };
    use crate::{EntityId, Vault, VaultConfig};
    struct Drift<'a> {
        vault: &'a Vault,
        id: EntityId,
        slate: EntityId,
        triggered: Cell<bool>,
        inner: Stub,
    }
    impl QualificationConnector for Drift<'_> {
        fn connect(&self) -> Result<Box<dyn QualificationConnection + '_>, QualificationFailure> {
            self.inner.connect()
        }
        fn effect_state(&self) -> Result<Vec<u8>, QualificationFailure> {
            if !self.triggered.replace(true) {
                self.vault
                    .revise_connector_protocol(&self.id, "B", self.slate, 102)
                    .expect("leave A during probes");
                self.vault
                    .revise_connector_protocol(&self.id, "A", self.slate, 103)
                    .expect("return to A during probes");
            }
            self.inner.effect_state()
        }
    }
    let tmp = tempfile::tempdir()?;
    let vault = Vault::open(tmp.path(), VaultConfig::default())?;
    let tool = SlateToolManifest {
        name: "memory".into(),
        data_class: SlateDataClass::Personal,
        header_parameters: vec![],
        trigger: None,
        resolved_input_schema: Some(
            json!({"type":"object","properties":{"idempotency_key":{"type":"string"}}}),
        ),
        destroys: false,
        spends: false,
        sends_outward: false,
        legacy_ask: false,
    };
    let slate = vault.store_connector_slate(
        std::slice::from_ref(&tool),
        &serde_json::to_string(&draft_connector_slate(std::slice::from_ref(&tool))).unwrap(),
    )?;
    let (id, _) = vault.register_connector(
        ConnectorCatalogEntry {
            name: "memory".into(),
            connector: "memory".into(),
            summary: "Memory".into(),
            verbs: vec!["read".into()],
            call_class: ConnectorCallClass::ScopedMcp,
            registered_at: 0,
        },
        ConnectorKeySpec {
            slate_ref: Some(slate),
            protocol_revision: Some("A".into()),
            ..ConnectorKeySpec::new("memory")
        },
        100,
    )?;
    let owner = EntityId::now();
    vault.put_entity(
        &owner,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let auth = vault.authenticate_owner(
        owner,
        &owner.to_hex(),
        true,
        crate::store::GateDecisionId::from_bytes(*EntityId::now().as_bytes()),
    )?;
    vault.override_connector_slate(&auth, slate, 0, &BTreeMap::new())?;
    let drifting = Drift {
        vault: &vault,
        id,
        slate,
        triggered: Cell::new(false),
        inner: Stub {
            fault: Fault::None,
            connections: Cell::new(0),
            effects: Rc::default(),
        },
    };
    assert!(
        vault
            .qualify_connector_key(&id, "A", &drifting, &plan(), &Oracle, 104)
            .is_err()
    );
    assert!(drifting.triggered.get());
    assert_eq!(
        vault.get_connector_key(&id)?.unwrap().status,
        ConnectorKeyStatus::Pending
    );
    assert!(vault.route_connector_call("memory")?.is_none());
    Ok(())
}

#[test]
fn resolved_schema_delta_is_bound_before_effectful_probes() -> crate::error::Result<()> {
    use crate::connector_key::{
        ConnectorCallClass, ConnectorCatalogEntry, ConnectorKeySpec, ConnectorKeyStatus,
        SlateDataClass, SlateToolManifest, draft_connector_slate,
    };
    use crate::{EntityId, Vault, VaultConfig};
    struct SchemaStub {
        inner: Stub,
        schema: Value,
    }
    struct SchemaConnection<'a> {
        inner: Box<dyn QualificationConnection + 'a>,
        schema: Value,
    }
    impl QualificationConnection for SchemaConnection<'_> {
        fn tools_list(&mut self) -> Result<Vec<ProbeTool>, QualificationFailure> {
            let mut tools = self.inner.tools_list()?;
            tools[0].input_schema = self.schema.clone();
            Ok(tools)
        }
        fn call(&mut self, request: &ProbeRequest) -> Result<ProbeReply, QualificationFailure> {
            self.inner.call(request)
        }
    }
    impl QualificationConnector for SchemaStub {
        fn connect(&self) -> Result<Box<dyn QualificationConnection + '_>, QualificationFailure> {
            Ok(Box::new(SchemaConnection {
                inner: self.inner.connect()?,
                schema: self.schema.clone(),
            }))
        }
        fn effect_state(&self) -> Result<Vec<u8>, QualificationFailure> {
            self.inner.effect_state()
        }
    }
    let stub = |schema: Value| SchemaStub {
        inner: Stub {
            fault: Fault::ReadOnly,
            connections: Cell::new(0),
            effects: Rc::default(),
        },
        schema,
    };
    let tmp = tempfile::tempdir()?;
    let vault = Vault::open(tmp.path(), VaultConfig::default())?;
    let schema = json!({"type":"object","properties":{"query":{"type":"string","enum":["a","b"]}}});
    let mut tool = SlateToolManifest {
        name: "memory".into(),
        data_class: SlateDataClass::Public,
        header_parameters: vec![],
        resolved_input_schema: Some(schema.clone()),
        trigger: None,
        destroys: false,
        spends: false,
        sends_outward: false,
        legacy_ask: false,
    };
    let make_slate = |tool: &SlateToolManifest| -> crate::error::Result<EntityId> {
        let tools = std::slice::from_ref(tool);
        vault.store_connector_slate(
            tools,
            &serde_json::to_string(&draft_connector_slate(tools)).unwrap(),
        )
    };
    let first = make_slate(&tool)?;
    let (id, _) = vault.register_connector(
        ConnectorCatalogEntry {
            name: "memory".into(),
            connector: "memory".into(),
            summary: "Memory".into(),
            verbs: vec!["read".into()],
            call_class: ConnectorCallClass::ScopedMcp,
            registered_at: 0,
        },
        ConnectorKeySpec {
            slate_ref: Some(first),
            protocol_revision: Some("A".into()),
            ..ConnectorKeySpec::new("memory")
        },
        100,
    )?;
    let owner = EntityId::now();
    vault.put_entity(
        &owner,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let auth = vault.authenticate_owner(
        owner,
        &owner.to_hex(),
        true,
        crate::store::GateDecisionId::from_bytes(*EntityId::now().as_bytes()),
    )?;
    vault.override_connector_slate(&auth, first, 0, &BTreeMap::new())?;
    let mut read_plan = plan();
    read_plan.write = None;
    read_plan.timeout_retry = None;
    vault
        .qualify_connector_key(&id, "A", &stub(schema), &read_plan, &Oracle, 101)
        .unwrap();
    let changed = json!({"type":"object","properties":{"query":{"type":"string","enum":["a","b"],"default":"b"}}});
    // Reusing a prior slate under the new wire declaration fails before calls.
    vault.revise_connector_protocol(&id, "B", first, 102)?;
    let mismatched = stub(changed.clone());
    assert!(
        vault
            .qualify_connector_key(&id, "B", &mismatched, &read_plan, &Oracle, 103)
            .is_err()
    );
    assert_eq!(mismatched.inner.effects.borrow().len(), 0);
    assert_eq!(
        vault.get_connector_key(&id)?.unwrap().status,
        ConnectorKeyStatus::Pending
    );
    // A typed delta with the changed default needs an owner decision.
    tool.resolved_input_schema = Some(changed.clone());
    let expanded = make_slate(&tool)?;
    vault.revise_connector_protocol(&id, "C", expanded, 104)?;
    let unapproved = stub(changed.clone());
    assert!(
        vault
            .qualify_connector_key(&id, "C", &unapproved, &read_plan, &Oracle, 105)
            .is_err()
    );
    assert_eq!(unapproved.inner.connections.get(), 0);
    vault.override_connector_slate(&auth, expanded, 0, &BTreeMap::new())?;
    vault
        .qualify_connector_key(&id, "C", &stub(changed), &read_plan, &Oracle, 106)
        .unwrap();
    // Removing a permitted enum value is a provable narrowing, no second tap.
    tool.resolved_input_schema = Some(
        json!({"type":"object","properties":{"query":{"type":"string","enum":["b"],"default":"b"}}}),
    );
    let narrowed = make_slate(&tool)?;
    let row = vault.revise_connector_protocol(&id, "D", narrowed, 107)?;
    assert!(!row.consent_required);
    vault
        .qualify_connector_key(
            &id,
            "D",
            &stub(tool.resolved_input_schema.unwrap()),
            &read_plan,
            &Oracle,
            108,
        )
        .unwrap();
    Ok(())
}

#[test]
fn reordered_rows_cannot_enable_tool_without_owner_stamp() -> crate::error::Result<()> {
    use crate::connector_key::{
        ConnectorCallClass, ConnectorCatalogEntry, ConnectorKeySpec, ConnectorKeyStatus,
        SlateDataClass, SlateToolManifest, draft_connector_slate,
    };
    use crate::{EntityId, Vault, VaultConfig};
    struct TwoTools {
        inner: Stub,
    }
    struct TwoConnections<'a> {
        inner: Box<dyn QualificationConnection + 'a>,
    }
    impl QualificationConnection for TwoConnections<'_> {
        fn tools_list(&mut self) -> Result<Vec<ProbeTool>, QualificationFailure> {
            let first = self.inner.tools_list()?.remove(0);
            Ok(["A", "B"]
                .into_iter()
                .map(|name| ProbeTool {
                    name: name.into(),
                    ..first.clone()
                })
                .collect())
        }
        fn call(&mut self, request: &ProbeRequest) -> Result<ProbeReply, QualificationFailure> {
            self.inner.call(request)
        }
    }
    impl QualificationConnector for TwoTools {
        fn connect(&self) -> Result<Box<dyn QualificationConnection + '_>, QualificationFailure> {
            Ok(Box::new(TwoConnections {
                inner: self.inner.connect()?,
            }))
        }
        fn effect_state(&self) -> Result<Vec<u8>, QualificationFailure> {
            self.inner.effect_state()
        }
    }
    let make_connector = || TwoTools {
        inner: Stub {
            fault: Fault::ReadOnly,
            connections: Cell::new(0),
            effects: Rc::default(),
        },
    };
    let tmp = tempfile::tempdir()?;
    let vault = Vault::open(tmp.path(), VaultConfig::default())?;
    let tool = |name: &str| SlateToolManifest {
        name: name.into(),
        data_class: SlateDataClass::Public,
        header_parameters: vec![],
        resolved_input_schema: Some(json!({"type":"object",
            "properties":{"idempotency_key":{"type":"string"}}})),
        trigger: None,
        destroys: false,
        spends: false,
        sends_outward: false,
        legacy_ask: false,
    };
    let manifest = vec![tool("A"), tool("B")];
    let mut old_rows = draft_connector_slate(&manifest);
    old_rows[0].enabled = false;
    let old = vault.store_connector_slate(&manifest, &serde_json::to_string(&old_rows).unwrap())?;
    let (id, _) = vault.register_connector(
        ConnectorCatalogEntry {
            name: "twotools".into(),
            connector: "twotools".into(),
            summary: "Two tools".into(),
            verbs: vec!["read".into()],
            call_class: ConnectorCallClass::ScopedMcp,
            registered_at: 0,
        },
        ConnectorKeySpec {
            slate_ref: Some(old),
            protocol_revision: Some("A".into()),
            ..ConnectorKeySpec::new("twotools")
        },
        100,
    )?;
    let owner = EntityId::now();
    vault.put_entity(
        &owner,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let auth = vault.authenticate_owner(
        owner,
        &owner.to_hex(),
        true,
        crate::store::GateDecisionId::from_bytes(*EntityId::now().as_bytes()),
    )?;
    vault.override_connector_slate(&auth, old, 0, &BTreeMap::new())?;
    let mut read_plan = plan();
    read_plan.write = None;
    read_plan.timeout_retry = None;
    read_plan.reads[0].call.name = "A".into();
    read_plan.reads[1].call.name = "B".into();
    vault
        .qualify_connector_key(&id, "A", &make_connector(), &read_plan, &Oracle, 101)
        .unwrap();
    let mut next_rows = draft_connector_slate(&manifest);
    next_rows[1].enabled = false;
    next_rows.reverse();
    let next =
        vault.store_connector_slate(&manifest, &serde_json::to_string(&next_rows).unwrap())?;
    let pending = vault.revise_connector_protocol(&id, "B", next, 102)?;
    assert!(
        pending.consent_required,
        "A became enabled even with permuted row order"
    );
    let unapproved = make_connector();
    assert!(
        vault
            .qualify_connector_key(&id, "B", &unapproved, &read_plan, &Oracle, 103)
            .is_err()
    );
    assert_eq!(unapproved.inner.connections.get(), 0);
    assert_eq!(
        vault.get_connector_key(&id)?.unwrap().status,
        ConnectorKeyStatus::Pending
    );
    vault.override_connector_slate(&auth, next, 0, &BTreeMap::new())?;
    assert_eq!(
        vault
            .qualify_connector_key(&id, "B", &make_connector(), &read_plan, &Oracle, 104)
            .unwrap()
            .0
            .status,
        ConnectorKeyStatus::Active
    );
    Ok(())
}
