//! `infer run` and `infer summarize` flags, parsed by hand like the other
//! subcommands: every flag takes one value, and the repeatable ones collect.

use std::path::PathBuf;
use std::str::FromStr;

pub(super) const USAGE: &str = "usage: oneiron-bench infer run --arm-id ID --transport direct|own-server\n\
  --models-toml FILE --model PROVIDER:MODEL --cases /ABS/cases.jsonl --out /ABS/rows.jsonl\n\
  [--reps 1] [--only CASE_ID]... [--warmup 1] [--sampling shipped|greedy|card]\n\
  [--schema on|off] [--cache-bust on|off] [--keep-outputs /ABS/DIR]\n\
  [--concurrency 1] [--stagger-ms 0] [--draft-depth N]\n\
  [--engine-cmd PATH [--engine-env KEY=VALUE]... --engine-health URL [--engine-ready-timeout 900]]\n\
  [--gpu-index 0] [--vram-poll-ms 100] [--server oneiron-server]   (--server: own-server only)\n\
       oneiron-bench infer summarize --out ROWS.jsonl [--out ROWS.jsonl]...";

/// Which production path a call takes to the engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Transport {
    /// `ModelRuntime` and `RunBackend` in this process, over the
    /// `oneiron-llm-openai` wire.
    Direct,
    /// `OwnServerBackend` and `RemoteLlmClient` to a loopback `oneiron-server`
    /// that routes to the same provider.
    OwnServer,
}

impl Transport {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::OwnServer => "own-server",
        }
    }
}

/// The sampling params a request carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Sampling {
    /// What the Dreamer's extraction call sends: no sampling field at all.
    Shipped,
    /// Temperature 0, top_k 1.
    Greedy,
    /// The model card's recipe.
    Card,
}

impl Sampling {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Shipped => "shipped",
            Self::Greedy => "greedy",
            Self::Card => "card",
        }
    }
}

/// An engine the bench starts itself, and how it knows it is up.
pub(super) struct EngineArgs {
    pub(super) cmd: PathBuf,
    pub(super) env: Vec<(String, String)>,
    pub(super) health: String,
    pub(super) ready_timeout_secs: u64,
}

/// The parsed `infer run` flags.
pub(super) struct RunArgs {
    pub(super) arm_id: String,
    pub(super) transport: Transport,
    pub(super) models_toml: PathBuf,
    pub(super) model: String,
    pub(super) cases: PathBuf,
    pub(super) out: PathBuf,
    pub(super) reps: u32,
    pub(super) only: Vec<String>,
    pub(super) warmup: u32,
    pub(super) sampling: Sampling,
    pub(super) schema: bool,
    pub(super) cache_bust: bool,
    pub(super) keep_outputs: Option<PathBuf>,
    pub(super) engine: Option<EngineArgs>,
    pub(super) gpu_index: u32,
    pub(super) vram_poll_ms: u64,
    pub(super) server: Option<PathBuf>,
    /// Calls in flight at once from this client: worker tasks sharing one
    /// arm, backend and meter.
    pub(super) concurrency: u32,
    /// Worker k makes its first call k times this many ms after its
    /// cohort's start.
    pub(super) stagger_ms: u64,
    /// The engine's draft depth as the operator declares it, a label only:
    /// identity is compared within one depth.
    pub(super) draft_depth: Option<u32>,
}

fn number<T: FromStr>(flag: &str, value: &str) -> Result<T, String> {
    value
        .parse()
        .map_err(|_| format!("{flag} expects a number, got `{value}`"))
}

fn positive<T: FromStr + PartialOrd + Default>(flag: &str, value: &str) -> Result<T, String> {
    let n: T = number(flag, value)?;
    if n > T::default() {
        Ok(n)
    } else {
        Err(format!("{flag} must be positive"))
    }
}

fn on_off(flag: &str, value: &str) -> Result<bool, String> {
    match value {
        "on" => Ok(true),
        "off" => Ok(false),
        other => Err(format!("{flag} is on or off, not `{other}`")),
    }
}

fn absolute(flag: &str, path: PathBuf) -> Result<PathBuf, String> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(format!("{flag} must be an absolute path"))
    }
}

pub(super) fn parse_run(args: &[String]) -> Result<RunArgs, String> {
    let mut arm_id = None;
    let mut transport = None;
    let mut models_toml = None;
    let mut model = None;
    let mut cases = None;
    let mut out = None;
    let mut reps = 1;
    let mut only = Vec::new();
    let mut warmup = 1;
    let mut sampling = Sampling::Greedy;
    let mut schema = true;
    let mut cache_bust = true;
    let mut keep_outputs = None;
    let mut engine_cmd = None;
    let mut engine_env = Vec::new();
    let mut engine_health = None;
    let mut ready_timeout_secs = 900;
    let mut gpu_index = 0;
    let mut vram_poll_ms = 100;
    let mut server = None;
    let mut concurrency = 1;
    let mut stagger_ms = 0;
    let mut draft_depth = None;
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let value = it
            .next()
            .ok_or_else(|| format!("`{flag}` needs a value\n{USAGE}"))?;
        match flag.as_str() {
            "--arm-id" => arm_id = Some(value.trim().to_owned()).filter(|id| !id.is_empty()),
            "--transport" => {
                transport = Some(match value.as_str() {
                    "direct" => Transport::Direct,
                    "own-server" => Transport::OwnServer,
                    other => {
                        return Err(format!(
                            "--transport is direct or own-server, not `{other}`"
                        ));
                    }
                });
            }
            "--models-toml" => models_toml = Some(PathBuf::from(value)),
            "--model" => model = Some(value.trim().to_owned()),
            "--cases" => cases = Some(absolute(flag, PathBuf::from(value))?),
            "--out" => out = Some(absolute(flag, PathBuf::from(value))?),
            "--reps" => reps = positive(flag, value)?,
            "--only" => only.push(value.clone()),
            "--warmup" => warmup = number(flag, value)?,
            "--sampling" => {
                sampling = match value.as_str() {
                    "shipped" => Sampling::Shipped,
                    "greedy" => Sampling::Greedy,
                    "card" => Sampling::Card,
                    other => {
                        return Err(format!(
                            "--sampling is shipped, greedy or card, not `{other}`"
                        ));
                    }
                };
            }
            "--schema" => schema = on_off(flag, value)?,
            "--cache-bust" => cache_bust = on_off(flag, value)?,
            "--keep-outputs" => keep_outputs = Some(absolute(flag, PathBuf::from(value))?),
            "--engine-cmd" => engine_cmd = Some(PathBuf::from(value)),
            "--engine-env" => {
                let (key, val) = value
                    .split_once('=')
                    .filter(|(key, _)| !key.is_empty())
                    .ok_or("--engine-env is KEY=VALUE")?;
                engine_env.push((key.to_owned(), val.to_owned()));
            }
            "--engine-health" => engine_health = Some(value.clone()),
            "--engine-ready-timeout" => ready_timeout_secs = positive(flag, value)?,
            "--gpu-index" => gpu_index = number(flag, value)?,
            "--vram-poll-ms" => vram_poll_ms = positive(flag, value)?,
            "--server" => server = Some(PathBuf::from(value)),
            "--concurrency" => concurrency = positive(flag, value)?,
            "--stagger-ms" => stagger_ms = number(flag, value)?,
            "--draft-depth" => draft_depth = Some(number(flag, value)?),
            other => return Err(format!("unknown `infer run` flag `{other}`\n{USAGE}")),
        }
    }
    let required = |name: &str| format!("`infer run` requires {name}\n{USAGE}");
    let transport = transport.ok_or_else(|| required("--transport"))?;
    let engine = match (engine_cmd, engine_health) {
        (Some(cmd), Some(health)) => Some(EngineArgs {
            cmd,
            env: engine_env,
            health,
            ready_timeout_secs,
        }),
        (Some(_), None) => return Err("--engine-cmd needs --engine-health URL".to_owned()),
        (None, health) => {
            if health.is_some() || !engine_env.is_empty() {
                return Err("--engine-env and --engine-health need --engine-cmd".to_owned());
            }
            None
        }
    };
    match (transport, &server) {
        (Transport::OwnServer, None) => {
            return Err("--transport own-server needs --server <oneiron-server binary>".to_owned());
        }
        (Transport::Direct, Some(_)) => {
            return Err("--server applies to --transport own-server only".to_owned());
        }
        _ => {}
    }
    Ok(RunArgs {
        arm_id: arm_id.ok_or_else(|| required("--arm-id"))?,
        transport,
        models_toml: models_toml.ok_or_else(|| required("--models-toml"))?,
        model: model
            .filter(|model| !model.is_empty())
            .ok_or_else(|| required("--model"))?,
        cases: cases.ok_or_else(|| required("--cases"))?,
        out: out.ok_or_else(|| required("--out"))?,
        reps,
        only,
        warmup,
        sampling,
        schema,
        cache_bust,
        keep_outputs,
        engine,
        gpu_index,
        vram_poll_ms,
        server,
        concurrency,
        stagger_ms,
        draft_depth,
    })
}

/// The `infer summarize` flags: one or more result files.
pub(super) fn parse_summarize(args: &[String]) -> Result<Vec<PathBuf>, String> {
    let mut outs = Vec::new();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let value = it
            .next()
            .ok_or_else(|| format!("`{flag}` needs a value\n{USAGE}"))?;
        match flag.as_str() {
            "--out" => outs.push(PathBuf::from(value)),
            other => return Err(format!("unknown `infer summarize` flag `{other}`\n{USAGE}")),
        }
    }
    if outs.is_empty() {
        return Err(format!("`infer summarize` requires --out\n{USAGE}"));
    }
    Ok(outs)
}
