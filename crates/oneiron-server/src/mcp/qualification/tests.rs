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
            result_types: BTreeSet::from([if self.fault == Fault::ResultType {
                "unknown".into()
            } else {
                "record".into()
            }]),
            writes: self.fault != Fault::HiddenWrite,
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
        write: case("write", json!({"write":true,"idempotency_key":"write-key"})),
        timeout_retry: case(
            "timeout",
            json!({"write":true,"timeout_once":true,"idempotency_key":"timeout-key"}),
        ),
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
        (
            Fault::HiddenWrite,
            QualificationFailure::IdempotencyArgument,
        ),
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
    let mut invalid = plan();
    invalid
        .write
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
