//! A diagnostics organ for the host's own checks: the runtime's built-in
//! verbs (`organ.touch`, `organ.echo`) plus `probe.sleep`, `probe.crash`,
//! `probe.fork` and `probe.outputs`. Two hostile modes stand in for a broken organ:
//! `--deaf` answers the handshake and then never reads its socket, and
//! `--drip` sends its `hello_ack` one byte at a time.

#[cfg(unix)]
mod probe {
    use std::time::{Duration, Instant};

    use oneiron_organ_protocol::{
        Answer, CallContext, ErrorCode, Organ, OrganError, OrganIdentity, OutputBytes, VerbSpec,
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
            ["probe.sleep", "probe.crash", "probe.fork", "probe.outputs"]
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
    use std::os::fd::FromRawFd;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    use oneiron_organ_protocol::{
        DEFAULT_FRAME_LIMIT, FromOrgan, HelloAck, OrganIdentity, PROTOCOL, ToOrgan, VerbSpec,
        recv_frame, send_frame,
    };

    fn socket() -> UnixStream {
        // SAFETY: the host starts this process with the organ socket on fd 3
        // and nothing else here owns it.
        unsafe { UnixStream::from_raw_fd(3) }
    }

    fn ack_for(organ: String) -> FromOrgan {
        FromOrgan::HelloAck(HelloAck {
            protocol: PROTOCOL,
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

    /// Sends a valid `hello_ack` a byte every 100 ms: each read makes
    /// progress, so only a deadline over the whole frame stops it.
    pub(super) fn drip() {
        let mut stream = socket();
        let Some(organ) = hello_organ(&stream) else {
            return;
        };
        let Ok(body) = rmp_serde::to_vec_named(&ack_for(organ)) else {
            return;
        };
        let Ok(len) = u32::try_from(body.len()) else {
            return;
        };
        for byte in len.to_le_bytes().iter().chain(&body) {
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
        _ => oneiron_organ_protocol::serve(probe::Probe),
    }
}

#[cfg(not(unix))]
fn main() {}
