//! The version handshake of the asks design (ARCH-0075
//! `#organ-host-design-asks`). Protocol 2.0 (5b61e287afc, #4328) is a major
//! bump with asks built in, and it refuses a 1.x engine at hello: such an
//! engine gets no session, so it is never sent an ask.
#![cfg(unix)]

use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::thread;

use oneiron_organ_protocol::{
    Answer, CallContext, DEFAULT_FRAME_LIMIT, FrameError, FromOrgan, Hello, Limits, Organ,
    OrganError, OrganIdentity, PROTOCOL, ProtocolVersion, ToOrgan, Value, VerbSpec, recv_frame,
    send_frame, serve_stream, to_value,
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
        let report = match call.ask("anything", Value::Nil) {
            Ok(_) => "answered".into(),
            Err(refusal) => to_value(&refusal.code).unwrap_or(Value::Nil),
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
    // Protocol 2.0 (5b61e287afc) refuses a 1.x engine at hello: no ack, no
    // session, so no call is served and no ask is ever sent.
    let ack = recv_frame::<FromOrgan>(&engine, DEFAULT_FRAME_LIMIT);
    assert!(matches!(&ack, Err(FrameError::Closed)), "{ack:?}");
    assert_eq!(PROTOCOL.session(old), None);
    drop(engine);
    let served = served.join().expect("served");
    assert!(
        matches!(
            &served,
            Err(FrameError::Protocol("the engine speaks another major"))
        ),
        "{served:?}"
    );
}
