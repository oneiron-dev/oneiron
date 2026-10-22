//! A diagnostics organ for the host's own checks: the runtime's built-in
//! verbs (`organ.touch`, `organ.echo`) plus `probe.sleep`, `probe.crash`,
//! `probe.fork`, `probe.outputs` and `probe.ask`. Hostile modes stand in for
//! a broken organ: `--deaf` answers the handshake and then never reads its
//! socket, `--drip` sends its `hello_ack` one byte at a time, `--ask-twice`
//! sends a second ask before the first is answered, `--ask-once` asks and
//! then ignores the call and its cancel, and `--stale-asks` asks for calls
//! that are not in flight. `--v1-0` is an organ built against
//! protocol 1.0: it acks 1.0, echoes, and dies on any message 1.0 lacks.

#[cfg(unix)]
mod probe {
    use std::time::{Duration, Instant};

    use oneiron_organ_protocol::{
        Answer, AskCode, CallContext, ErrorCode, Organ, OrganError, OrganIdentity, OutputBytes,
        Value, VerbSpec, touch_fold,
    };

    pub(super) struct Probe;

    impl Organ for Probe {
        fn identity(&self) -> OrganIdentity {
            OrganIdentity {
                name: "probe".into(),
                version: env!("CARGO_PKG_VERSION").into(),
            }
        }

        fn verbs(&self) -> Vec<VerbSpec> {
            [
                "probe.sleep",
                "probe.crash",
                "probe.fork",
                "probe.outputs",
                "probe.ask",
            ]
            .map(|name| VerbSpec {
                name: name.into(),
                schema: 1,
                kinds: Vec::new(),
            })
            .into()
        }

        /// `probe.sleep {ms, obey_cancel}` sleeps; with `obey_cancel` false
        /// it ignores cancels, as a hostile organ would. `probe.fork` leaves
        /// a child behind and reports its pid. `probe.outputs {count, bytes}`
        /// answers with `count` outputs of `bytes` bytes each.
        /// `probe.ask {verb, value, times, fail}` asks `times` times, going on
        /// past refusals, and reports each answer (its value, the length and
        /// fold of its bytes) or refusal code; a cancel ends it as cancelled.
        /// With `fail`, it ends in an error once it has asked.
        fn call(&self, call: &CallContext<'_>) -> Result<Answer, OrganError> {
            let field = |key: &str| {
                call.args
                    .as_map()
                    .and_then(|map| map.iter().find(|(k, _)| k.as_str() == Some(key)))
                    .map(|(_, value)| value.clone())
            };
            match call.verb {
                "probe.sleep" => {
                    let ms = field("ms").and_then(|v| v.as_u64()).unwrap_or(0);
                    let obey = field("obey_cancel")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true);
                    let until = Instant::now() + Duration::from_millis(ms);
                    while Instant::now() < until {
                        if obey {
                            call.check_cancel()?;
                        }
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Ok(Answer::default())
                }
                "probe.crash" => std::process::abort(),
                "probe.ask" => {
                    let verb = field("verb")
                        .and_then(|v| v.as_str().map(str::to_owned))
                        .unwrap_or_default();
                    let value = field("value").unwrap_or(Value::Nil);
                    let times = field("times").and_then(|v| v.as_u64()).unwrap_or(1);
                    let mut report = Vec::new();
                    for _ in 0..times {
                        let line = match call.ask(&verb, value.clone()) {
                            Ok(reply) => {
                                let data = reply.data.as_deref().unwrap_or_default();
                                Value::Map(vec![
                                    ("answered".into(), reply.value),
                                    ("len".into(), (data.len() as u64).into()),
                                    ("fold".into(), touch_fold(data).into()),
                                ])
                            }
                            Err(refusal) if refusal.code == AskCode::Cancelled => {
                                return Err(OrganError::new(ErrorCode::Cancelled, "cancelled"));
                            }
                            Err(refusal) => {
                                // The code by its wire name, as an organ reads it.
                                let code = oneiron_organ_protocol::to_value(&refusal.code)
                                    .unwrap_or_default();
                                Value::Map(vec![("refused".into(), code)])
                            }
                        };
                        report.push(line);
                    }
                    if field("fail").and_then(|v| v.as_bool()) == Some(true) {
                        return Err(OrganError::new(ErrorCode::Internal, "failed after asking"));
                    }
                    Ok(Answer {
                        report: Value::Array(report),
                        ..Answer::default()
                    })
                }
                "probe.outputs" => {
                    let count = field("count").and_then(|v| v.as_u64()).unwrap_or(0);
                    let bytes = field("bytes").and_then(|v| v.as_u64()).unwrap_or(0);
                    let bytes = usize::try_from(bytes).unwrap_or(usize::MAX);
                    Ok(Answer {
                        outputs: (0..count)
                            .map(|n| OutputBytes {
                                name: format!("out-{n}"),
                                media_type: "application/octet-stream".into(),
                                bytes: vec![0x5a; bytes],
                            })
                            .collect(),
                        ..Answer::default()
                    })
                }
                "probe.fork" => {
                    #[expect(
                        clippy::disallowed_methods,
                        reason = "a hostile organ's own fork, outside the server"
                    )]
                    // SAFETY: the child only calls pause(2), which is
                    // async-signal-safe, until a signal ends it.
                    let pid = unsafe { libc::fork() };
                    if pid == 0 {
                        loop {
                            // SAFETY: pause(2) takes no arguments.
                            unsafe {
                                libc::pause();
                            }
                        }
                    }
                    Ok(Answer {
                        report: i64::from(pid).into(),
                        ..Answer::default()
                    })
                }
                other => Err(OrganError::new(ErrorCode::UnknownVerb, other)),
            }
        }
    }
}

/// Organs that break the protocol on purpose.
#[cfg(unix)]
mod rogue {
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::time::{Duration, Instant};

    use oneiron_organ_protocol::{
        Ask, DEFAULT_FRAME_LIMIT, FromOrgan, HelloAck, Notes, OrganIdentity, Outcome, PROTOCOL,
        Proposal, ProtocolVersion, Reply, ToOrgan, Value, VerbSpec, recv_frame, send_frame,
    };

    fn socket() -> UnixStream {
        // SAFETY: the host starts this process with the organ socket on fd 3
        // and nothing else here owns it.
        unsafe { UnixStream::from_raw_fd(3) }
    }

    fn ack_for(organ: String) -> FromOrgan {
        ack_at(organ, PROTOCOL)
    }

    fn ack_at(organ: String, protocol: ProtocolVersion) -> FromOrgan {
        FromOrgan::HelloAck(HelloAck {
            protocol,
            organ: OrganIdentity {
                name: organ,
                version: env!("CARGO_PKG_VERSION").into(),
            },
            verbs: vec![VerbSpec {
                name: "organ.echo".into(),
                schema: 1,
                kinds: Vec::new(),
            }],
        })
    }

    fn hello_organ(stream: &UnixStream) -> Option<String> {
        match recv_frame::<ToOrgan>(stream, DEFAULT_FRAME_LIMIT) {
            Ok((ToOrgan::Hello(hello), _)) => Some(hello.organ),
            _ => None,
        }
    }

    /// Answers the handshake, then never reads again.
    pub(super) fn deaf() {
        let stream = socket();
        let Some(organ) = hello_organ(&stream) else {
            return;
        };
        if send_frame(&stream, &ack_for(organ), &[], DEFAULT_FRAME_LIMIT).is_err() {
            return;
        }
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }

    fn ask(call: u64, id: u32) -> FromOrgan {
        FromOrgan::Ask(Ask {
            call,
            id,
            verb: "probe.answer".into(),
            value: Value::Nil,
        })
    }

    /// Answers the handshake, then meets each call with asks as `asks`
    /// writes them, never waiting for an answer; reads until the end.
    fn asking(asks: impl Fn(u64) -> Vec<FromOrgan>) {
        let stream = socket();
        let Some(organ) = hello_organ(&stream) else {
            return;
        };
        if send_frame(&stream, &ack_for(organ), &[], DEFAULT_FRAME_LIMIT).is_err() {
            return;
        }
        while let Ok((message, _)) = recv_frame::<ToOrgan>(&stream, DEFAULT_FRAME_LIMIT) {
            if let ToOrgan::Call(call) = message {
                for ask in asks(call.id) {
                    if send_frame(&stream, &ask, &[], DEFAULT_FRAME_LIMIT).is_err() {
                        return;
                    }
                }
            }
        }
    }

    /// Sends a second ask before the first is answered.
    pub(super) fn ask_twice() {
        asking(|call| vec![ask(call, 1), ask(call, 2)]);
    }

    /// Asks once per call, then never answers the call or takes its cancel.
    pub(super) fn ask_once() {
        asking(|call| vec![ask(call, 1)]);
    }

    /// Asks a hundred times for a call that is not in flight.
    pub(super) fn stale_asks() {
        asking(|call| (0..100).map(|n| ask(call + 1000, n)).collect());
    }

    fn reply(call: u64) -> FromOrgan {
        FromOrgan::Reply(Reply {
            id: call,
            outcome: Outcome::Proposal(Proposal {
                body: None,
                outputs: Vec::new(),
                report: Value::Nil,
                notes: Notes::default(),
            }),
        })
    }

    /// Answers the handshake, then meets the `n`th call with the frames
    /// `meet` returns and a nap without reading. It exits at once if it is
    /// ever sent an answer: these modes never wait for one, so an answer is
    /// the host's mistake.
    fn never_answered(meet: impl Fn(u64, usize) -> (Vec<FromOrgan>, Duration)) {
        let stream = socket();
        let Some(organ) = hello_organ(&stream) else {
            return;
        };
        if send_frame(&stream, &ack_for(organ), &[], DEFAULT_FRAME_LIMIT).is_err() {
            return;
        }
        let mut calls = 0;
        while let Ok((message, _)) = recv_frame::<ToOrgan>(&stream, DEFAULT_FRAME_LIMIT) {
            match message {
                ToOrgan::Call(call) => {
                    let (frames, nap) = meet(call.id, calls);
                    calls += 1;
                    for frame in frames {
                        if send_frame(&stream, &frame, &[], DEFAULT_FRAME_LIMIT).is_err() {
                            return;
                        }
                    }
                    std::thread::sleep(nap);
                }
                ToOrgan::Answer(_) => return,
                _ => {}
            }
        }
    }

    /// Asks, and replies right behind the ask, so the ask waits in the
    /// host's queue after the call is over.
    pub(super) fn ask_then_reply() {
        never_answered(|call, _| (vec![ask(call, 1), reply(call)], Duration::ZERO));
    }

    /// Asks on its first call, then stops reading for 1.5 s, so a large
    /// frame holds the host's writer; later calls get a reply at once.
    pub(super) fn ask_then_nap() {
        never_answered(|call, n| {
            if n == 0 {
                (vec![ask(call, 1)], Duration::from_millis(1500))
            } else {
                (vec![reply(call)], Duration::ZERO)
            }
        });
    }

    /// Waits for the test to create `path`, up to a minute: longer than
    /// the deadline of the call it orders, so a slow host can fail that
    /// call but never make the organ act before its signal.
    fn signalled(path: &Path) {
        let until = Instant::now() + Duration::from_secs(60);
        while !path.exists() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Answers the handshake, then asks for its first call without reading
    /// it, once the call has landed and fills the socket (the call is the
    /// first on the socket, so its id is 1).
    fn ask_while_full() -> Option<UnixStream> {
        let stream = socket();
        let organ = hello_organ(&stream)?;
        send_frame(&stream, &ack_for(organ), &[], DEFAULT_FRAME_LIMIT).ok()?;
        let mut landed = [libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        // SAFETY: poll(2) over one live pollfd, with no timeout.
        if unsafe { libc::poll(landed.as_mut_ptr(), 1, -1) } < 1 {
            return None;
        }
        // The call went in one write; let all of it land.
        std::thread::sleep(Duration::from_millis(200));
        send_frame(&stream, &ask(1, 1), &[], DEFAULT_FRAME_LIMIT).ok()?;
        Some(stream)
    }

    /// Asks while its first call fills the socket. Once the test's handler
    /// has run (`signals/handled`) and its answer has had 200 ms to start
    /// waiting for room, it replies, while the call still fills the socket;
    /// it reads again only once the test has its reply (`signals/go`).
    /// Later calls get a reply at once. It exits if it is ever sent an
    /// answer.
    pub(super) fn reply_while_full(signals: &Path) {
        let Some(stream) = ask_while_full() else {
            return;
        };
        signalled(&signals.join("handled"));
        std::thread::sleep(Duration::from_millis(200));
        if send_frame(&stream, &reply(1), &[], DEFAULT_FRAME_LIMIT).is_err() {
            return;
        }
        signalled(&signals.join("go"));
        let mut first = true;
        while let Ok((message, _)) = recv_frame::<ToOrgan>(&stream, DEFAULT_FRAME_LIMIT) {
            match message {
                // Replied to already.
                ToOrgan::Call(_) if first => first = false,
                ToOrgan::Call(call) => {
                    if send_frame(&stream, &reply(call.id), &[], DEFAULT_FRAME_LIMIT).is_err() {
                        return;
                    }
                }
                ToOrgan::Answer(_) => return,
                _ => {}
            }
        }
    }

    /// Asks while its first call fills the socket, and never replies. It
    /// reads again only once the test has seen the call's grant revoked
    /// (`signals/revoked`), and notes any answer it is sent
    /// (`signals/answered`).
    pub(super) fn revoked_while_full(signals: &Path) {
        let Some(stream) = ask_while_full() else {
            return;
        };
        signalled(&signals.join("revoked"));
        while let Ok((message, _)) = recv_frame::<ToOrgan>(&stream, DEFAULT_FRAME_LIMIT) {
            if let ToOrgan::Answer(_) = message {
                let _ = std::fs::write(signals.join("answered"), b"");
            }
        }
    }

    /// Asks on its first call, and replies to it once the test's handler
    /// has started (`signals/handled`), so the reply comes while the handler
    /// runs; later calls get a reply at once. It notes any cancel it is
    /// sent (`signals/cancelled`), and exits if it is ever sent an answer.
    pub(super) fn reply_while_handled(signals: &Path) {
        let stream = socket();
        let Some(organ) = hello_organ(&stream) else {
            return;
        };
        if send_frame(&stream, &ack_for(organ), &[], DEFAULT_FRAME_LIMIT).is_err() {
            return;
        }
        let mut first = true;
        while let Ok((message, _)) = recv_frame::<ToOrgan>(&stream, DEFAULT_FRAME_LIMIT) {
            let call = match message {
                ToOrgan::Call(call) => call,
                ToOrgan::Cancel { .. } => {
                    let _ = std::fs::write(signals.join("cancelled"), b"");
                    continue;
                }
                ToOrgan::Answer(_) => return,
                _ => continue,
            };
            if first {
                first = false;
                if send_frame(&stream, &ask(call.id, 1), &[], DEFAULT_FRAME_LIMIT).is_err() {
                    return;
                }
                signalled(&signals.join("handled"));
            }
            if send_frame(&stream, &reply(call.id), &[], DEFAULT_FRAME_LIMIT).is_err() {
                return;
            }
        }
    }

    /// An organ that acks protocol 1.0, which a 2.0 host refuses at the
    /// handshake; served anyway, it echoes each call's args, and exits on any
    /// message 1.0 does not have.
    pub(super) fn v1_0() {
        let stream = socket();
        let Some(organ) = hello_organ(&stream) else {
            return;
        };
        let old = ProtocolVersion { major: 1, minor: 0 };
        if send_frame(&stream, &ack_at(organ, old), &[], DEFAULT_FRAME_LIMIT).is_err() {
            return;
        }
        while let Ok((message, _)) = recv_frame::<ToOrgan>(&stream, DEFAULT_FRAME_LIMIT) {
            let call = match message {
                ToOrgan::Call(call) => call,
                ToOrgan::Cancel { .. } => continue,
                _ => return,
            };
            let reply = FromOrgan::Reply(Reply {
                id: call.id,
                outcome: Outcome::Proposal(Proposal {
                    body: None,
                    outputs: Vec::new(),
                    report: call.args,
                    notes: Notes::default(),
                }),
            });
            if send_frame(&stream, &reply, &[], DEFAULT_FRAME_LIMIT).is_err() {
                return;
            }
        }
    }

    /// Sends a valid `hello_ack` a byte every 100 ms: each read makes
    /// progress, so only a deadline over the whole frame stops it.
    pub(super) fn drip() {
        let mut stream = socket();
        let Some(organ) = hello_organ(&stream) else {
            return;
        };
        let Ok(body) = oneiron_organ_protocol::to_vec(&ack_for(organ)) else {
            return;
        };
        let Ok(len) = u32::try_from(body.len()) else {
            return;
        };
        // One frame, the message's last: `len: u32 LE | more: 0 | body`.
        for byte in len.to_le_bytes().iter().chain(&[0]).chain(&body) {
            if stream.write_all(&[*byte]).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    match std::env::args().nth(1).as_deref() {
        Some("--deaf") => {
            rogue::deaf();
            std::process::ExitCode::SUCCESS
        }
        Some("--drip") => {
            rogue::drip();
            std::process::ExitCode::SUCCESS
        }
        Some("--ask-twice") => {
            rogue::ask_twice();
            std::process::ExitCode::SUCCESS
        }
        Some("--ask-once") => {
            rogue::ask_once();
            std::process::ExitCode::SUCCESS
        }
        Some("--stale-asks") => {
            rogue::stale_asks();
            std::process::ExitCode::SUCCESS
        }
        Some("--ask-then-reply") => {
            rogue::ask_then_reply();
            std::process::ExitCode::SUCCESS
        }
        Some("--reply-while-full") => {
            let signals = std::env::args().nth(2).unwrap_or_default();
            rogue::reply_while_full(std::path::Path::new(&signals));
            std::process::ExitCode::SUCCESS
        }
        Some("--revoked-while-full") => {
            let signals = std::env::args().nth(2).unwrap_or_default();
            rogue::revoked_while_full(std::path::Path::new(&signals));
            std::process::ExitCode::SUCCESS
        }
        Some("--reply-while-handled") => {
            let signals = std::env::args().nth(2).unwrap_or_default();
            rogue::reply_while_handled(std::path::Path::new(&signals));
            std::process::ExitCode::SUCCESS
        }
        Some("--ask-then-nap") => {
            rogue::ask_then_nap();
            std::process::ExitCode::SUCCESS
        }
        Some("--v1-0") => {
            rogue::v1_0();
            std::process::ExitCode::SUCCESS
        }
        _ => oneiron_organ_protocol::serve(probe::Probe),
    }
}

#[cfg(not(unix))]
fn main() {}
