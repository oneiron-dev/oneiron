//! The version handshake of the asks design (ARCH-0075
//! `#organ-host-design-asks`): a session speaks the lower minor of both
//! sides, so a 1.1 organ under an engine that speaks 1.0 sends no ask; its
//! verb is told `unsupported` and the call goes on.
#![cfg(unix)]

use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::thread;

use oneiron_organ_protocol::{
    Answer, AskCode, Call, CallContext, DEFAULT_FRAME_LIMIT, FromOrgan, Hello, Limits, Organ,
    OrganError, OrganIdentity, Outcome, PROTOCOL, ProtocolVersion, ToOrgan, VerbSpec, recv_frame,
    send_frame, serve_stream,
};

/// Asks once and reports the refusal code it got.
struct Asking;

impl Organ for Asking {
    fn identity(&self) -> OrganIdentity {
        OrganIdentity {
            name: "asking".into(),
            version: "1".into(),
        }
    }

    fn verbs(&self) -> Vec<VerbSpec> {
        vec![VerbSpec {
            name: "asking.ask".into(),
            schema: 1,
            kinds: Vec::new(),
        }]
    }

    fn call(&self, call: &CallContext<'_>) -> Result<Answer, OrganError> {
        let report = match call.ask("anything", rmpv::Value::Nil) {
            Ok(_) => "answered".into(),
            Err(refusal) => rmpv::ext::to_value(refusal.code).unwrap_or(rmpv::Value::Nil),
        };
        Ok(Answer {
            report,
            ..Answer::default()
        })
    }
}

#[test]
fn a_1_1_organ_under_a_1_0_engine_sends_no_ask() {
    let (engine, organ) = UnixStream::pair().expect("pair");
    let served = thread::spawn(move || serve_stream(Arc::new(Asking), &organ));
    let old = ProtocolVersion { major: 1, minor: 0 };
    let limits = Limits {
        threads: 1,
        memory_bytes: 64 * 1024 * 1024,
        max_call_frame: DEFAULT_FRAME_LIMIT,
        max_reply_frame: DEFAULT_FRAME_LIMIT,
    };
    let hello = ToOrgan::Hello(Hello {
        protocol: old,
        engine: "test".into(),
        organ: "asking".into(),
        limits,
    });
    send_frame(&engine, &hello, &[], DEFAULT_FRAME_LIMIT).expect("hello");
    let (ack, _) = recv_frame::<FromOrgan>(&engine, DEFAULT_FRAME_LIMIT).expect("ack");
    let FromOrgan::HelloAck(ack) = ack else {
        panic!("not an ack: {ack:?}");
    };
    // The organ offers its own version; the session is the lower one.
    assert_eq!(ack.protocol, PROTOCOL);
    assert_eq!(PROTOCOL.session(old), Some(old));
    let call = ToOrgan::Call(Call {
        id: 1,
        verb: "asking.ask".into(),
        schema: 1,
        args: rmpv::Value::Nil,
        body: None,
        inputs: Vec::new(),
        deadline_ms: 10_000,
    });
    send_frame(&engine, &call, &[], DEFAULT_FRAME_LIMIT).expect("call");
    // The very next frame is the reply: no ask came first.
    let (next, _) = recv_frame::<FromOrgan>(&engine, DEFAULT_FRAME_LIMIT).expect("reply");
    let FromOrgan::Reply(reply) = next else {
        panic!("a 1.0 session got {next:?}");
    };
    let Outcome::Proposal(proposal) = reply.outcome else {
        panic!("the call failed: {:?}", reply.outcome);
    };
    assert_eq!(
        proposal.report,
        rmpv::ext::to_value(AskCode::Unsupported).expect("code")
    );
    drop(engine);
    served.join().expect("served").expect("clean end");
}
