//! A diagnostics organ for the host's own checks: the runtime's built-in
//! verbs (`organ.touch`, `organ.echo`) plus `probe.sleep` and `probe.crash`.

#[cfg(unix)]
mod probe {
    use std::time::{Duration, Instant};

    use oneiron_organ_protocol::{
        Answer, CallContext, ErrorCode, Organ, OrganError, OrganIdentity, VerbSpec,
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
            ["probe.sleep", "probe.crash"]
                .map(|name| VerbSpec {
                    name: name.into(),
                    schema: 1,
                    kinds: Vec::new(),
                })
                .into()
        }

        /// `probe.sleep {ms, obey_cancel}` sleeps; with `obey_cancel` false
        /// it ignores cancels, as a hostile organ would.
        fn call(&self, call: &CallContext<'_>) -> Result<Answer, OrganError> {
            match call.verb {
                "probe.sleep" => {
                    let field = |key: &str| {
                        call.args
                            .as_map()
                            .and_then(|map| map.iter().find(|(k, _)| k.as_str() == Some(key)))
                            .map(|(_, value)| value.clone())
                    };
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
                other => Err(OrganError::new(ErrorCode::UnknownVerb, other)),
            }
        }
    }
}

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    oneiron_organ_protocol::serve(probe::Probe)
}

#[cfg(not(unix))]
fn main() {}
