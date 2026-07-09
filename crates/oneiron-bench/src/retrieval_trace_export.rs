use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use oneiron::{
    RetrievalScoreBreakdown, RetrievalScoreComponent, RetrievalSignal, RetrievalTrace,
    RetrievalTraceChannelRecord, RetrievalTraceForkHash, RetrievalTraceStage,
    RetrievalTraceStageRecord, Vault, VaultConfig,
};
use serde::{Deserialize, Serialize};

pub(crate) const RETRIEVAL_TRACE_EXPORT_CONTRACT_VERSION: &str =
    "oneiron.retrieval_trace_export.v1";
const RETRIEVAL_TRACE_RECORD_TYPE: &str = "retrieval_trace";
const DEFAULT_TRACE_EXPORT_DIMENSIONS: usize = 1024;
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

#[derive(Debug, thiserror::Error)]
pub(crate) enum RetrievalTraceExportError {
    #[error("trace-export usage requested")]
    HelpRequested,
    #[error("missing required trace-export argument: {0}")]
    MissingArgument(&'static str),
    #[error("invalid trace-export argument `{0}`")]
    InvalidArgument(String),
    #[error("invalid fork hash `{value}`: {reason}")]
    InvalidForkHash { value: String, reason: String },
    #[error("retrieval trace not found for fork hash {0}")]
    TraceNotFound(String),
    #[cfg(test)]
    #[error("invalid retrieval trace export row: {0}")]
    InvalidExportRow(String),
    #[error("invalid captured retrieval trace {fork_hash}: {reason}")]
    InvalidTrace { fork_hash: String, reason: String },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("oneiron engine error: {0}")]
    Oneiron(#[from] oneiron::Error),
}

type ExportResult<T> = Result<T, RetrievalTraceExportError>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct TraceExportArgs {
    vault_path: PathBuf,
    output_path: Option<PathBuf>,
    fork_hashes: Vec<RetrievalTraceForkHash>,
    dimensions: usize,
    embedding_model: Option<String>,
}

impl TraceExportArgs {
    fn vault_config(&self) -> VaultConfig {
        let mut cfg = VaultConfig::device();
        cfg.dimensions = self.dimensions;
        cfg.embedding_model = self.embedding_model.clone();
        cfg
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RetrievalTraceExportRow {
    contract_version: String,
    record_type: String,
    fork_hash: String,
    stages: RetrievalTraceStagesExport,
}

impl RetrievalTraceExportRow {
    fn from_trace(trace: &RetrievalTrace) -> Self {
        Self {
            contract_version: RETRIEVAL_TRACE_EXPORT_CONTRACT_VERSION.to_owned(),
            record_type: RETRIEVAL_TRACE_RECORD_TYPE.to_owned(),
            fork_hash: encode_hex(&trace.fork_hash),
            stages: RetrievalTraceStagesExport {
                per_channel: trace
                    .per_channel
                    .iter()
                    .map(RetrievalTraceChannelExport::from_channel)
                    .collect(),
                fused: RetrievalTraceStageExport::from_stage(&trace.fused),
                blended: RetrievalTraceStageExport::from_stage(&trace.blended),
                reranked: RetrievalTraceStageExport::from_stage(&trace.reranked),
                final_stage: RetrievalTraceStageExport::from_stage(&trace.final_stage),
            },
        }
    }

    #[cfg(test)]
    fn try_to_trace(&self) -> ExportResult<RetrievalTrace> {
        if self.contract_version != RETRIEVAL_TRACE_EXPORT_CONTRACT_VERSION {
            return Err(RetrievalTraceExportError::InvalidExportRow(format!(
                "unsupported contractVersion `{}`",
                self.contract_version
            )));
        }
        if self.record_type != RETRIEVAL_TRACE_RECORD_TYPE {
            return Err(RetrievalTraceExportError::InvalidExportRow(format!(
                "unsupported recordType `{}`",
                self.record_type
            )));
        }

        Ok(RetrievalTrace {
            fork_hash: parse_fixed_hex::<32>(&self.fork_hash)?,
            per_channel: self
                .stages
                .per_channel
                .iter()
                .map(RetrievalTraceChannelExport::try_to_channel)
                .collect::<ExportResult<Vec<_>>>()?,
            fused: self.stages.fused.try_to_stage()?,
            blended: self.stages.blended.try_to_stage()?,
            reranked: self.stages.reranked.try_to_stage()?,
            final_stage: self.stages.final_stage.try_to_stage()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RetrievalTraceStagesExport {
    per_channel: Vec<RetrievalTraceChannelExport>,
    fused: RetrievalTraceStageExport,
    blended: RetrievalTraceStageExport,
    reranked: RetrievalTraceStageExport,
    #[serde(rename = "final")]
    final_stage: RetrievalTraceStageExport,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RetrievalTraceChannelExport {
    stage: RetrievalTraceStage,
    signal: RetrievalSignal,
    candidates: Vec<RetrievalTraceCandidateExport>,
}

impl RetrievalTraceChannelExport {
    fn from_channel(channel: &RetrievalTraceChannelRecord) -> Self {
        Self {
            stage: channel.stage,
            signal: channel.signal,
            candidates: channel
                .candidates
                .iter()
                .map(RetrievalTraceCandidateExport::from_candidate)
                .collect(),
        }
    }

    #[cfg(test)]
    fn try_to_channel(&self) -> ExportResult<RetrievalTraceChannelRecord> {
        Ok(RetrievalTraceChannelRecord {
            stage: self.stage,
            signal: self.signal,
            candidates: self
                .candidates
                .iter()
                .map(RetrievalTraceCandidateExport::try_to_candidate)
                .collect::<ExportResult<Vec<_>>>()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RetrievalTraceStageExport {
    stage: RetrievalTraceStage,
    candidates: Vec<RetrievalTraceCandidateExport>,
}

impl RetrievalTraceStageExport {
    fn from_stage(stage: &RetrievalTraceStageRecord) -> Self {
        Self {
            stage: stage.stage,
            candidates: stage
                .candidates
                .iter()
                .map(RetrievalTraceCandidateExport::from_candidate)
                .collect(),
        }
    }

    #[cfg(test)]
    fn try_to_stage(&self) -> ExportResult<RetrievalTraceStageRecord> {
        Ok(RetrievalTraceStageRecord {
            stage: self.stage,
            candidates: self
                .candidates
                .iter()
                .map(RetrievalTraceCandidateExport::try_to_candidate)
                .collect::<ExportResult<Vec<_>>>()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RetrievalTraceCandidateExport {
    result_id: String,
    final_rank: u32,
    final_score: f32,
    components: Vec<RetrievalScoreComponent>,
}

impl RetrievalTraceCandidateExport {
    fn from_candidate(candidate: &RetrievalScoreBreakdown) -> Self {
        Self {
            result_id: encode_hex(&candidate.result_id),
            final_rank: candidate.final_rank,
            final_score: candidate.final_score,
            components: candidate.components.clone(),
        }
    }

    #[cfg(test)]
    fn try_to_candidate(&self) -> ExportResult<RetrievalScoreBreakdown> {
        Ok(RetrievalScoreBreakdown {
            result_id: parse_fixed_hex::<16>(&self.result_id)?,
            final_rank: self.final_rank,
            final_score: self.final_score,
            components: self.components.clone(),
        })
    }
}

pub(crate) fn run(args: &[String]) -> ExitCode {
    match run_trace_export(args) {
        Ok(count) => {
            eprintln!("exported {count} retrieval trace row(s)");
            ExitCode::SUCCESS
        }
        Err(RetrievalTraceExportError::HelpRequested) => {
            print_help();
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("BEAM trace export failed: {err}");
            print_help();
            ExitCode::FAILURE
        }
    }
}

fn run_trace_export(args: &[String]) -> ExportResult<usize> {
    let args = parse_args(args)?;
    if !args.vault_path.exists() {
        return Err(RetrievalTraceExportError::InvalidArgument(format!(
            "--vault path does not exist: {}",
            args.vault_path.display()
        )));
    }

    let vault = Vault::open(&args.vault_path, args.vault_config())?;
    match &args.output_path {
        Some(path) => {
            let mut file = File::create(path)?;
            export_traces_jsonl(&vault, &args.fork_hashes, &mut file)
        }
        None => {
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            export_traces_jsonl(&vault, &args.fork_hashes, &mut lock)
        }
    }
}

fn parse_args(args: &[String]) -> ExportResult<TraceExportArgs> {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        return Err(RetrievalTraceExportError::HelpRequested);
    }

    let mut vault_path = None;
    let mut output_path = None;
    let mut fork_hashes = Vec::new();
    let mut dimensions = DEFAULT_TRACE_EXPORT_DIMENSIONS;
    let mut embedding_model = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--vault" => {
                let value = required_value(args, index, "--vault")?;
                vault_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--out" | "--output" => {
                let value = required_value(args, index, "--out")?;
                output_path = (value != "-").then(|| PathBuf::from(value));
                index += 2;
            }
            "--fork-hash" => {
                let value = required_value(args, index, "--fork-hash")?;
                fork_hashes.push(parse_fork_hash(value)?);
                index += 2;
            }
            "--dimensions" => {
                let value = required_value(args, index, "--dimensions")?;
                dimensions = value.parse::<usize>().map_err(|_| {
                    RetrievalTraceExportError::InvalidArgument(format!(
                        "--dimensions expects a positive integer, got `{value}`"
                    ))
                })?;
                if dimensions == 0 {
                    return Err(RetrievalTraceExportError::InvalidArgument(
                        "--dimensions expects a positive integer".to_owned(),
                    ));
                }
                index += 2;
            }
            "--embedding-model" => {
                let value = required_value(args, index, "--embedding-model")?;
                if value.is_empty() {
                    return Err(RetrievalTraceExportError::InvalidArgument(
                        "--embedding-model must not be empty".to_owned(),
                    ));
                }
                embedding_model = Some(value.to_owned());
                index += 2;
            }
            other => return Err(RetrievalTraceExportError::InvalidArgument(other.to_owned())),
        }
    }

    let vault_path = vault_path.ok_or(RetrievalTraceExportError::MissingArgument("--vault"))?;
    if fork_hashes.is_empty() {
        return Err(RetrievalTraceExportError::MissingArgument("--fork-hash"));
    }

    Ok(TraceExportArgs {
        vault_path,
        output_path,
        fork_hashes,
        dimensions,
        embedding_model,
    })
}

fn required_value<'a>(
    args: &'a [String],
    index: usize,
    flag: &'static str,
) -> ExportResult<&'a str> {
    args.get(index + 1)
        .map(String::as_str)
        .filter(|value| !value.starts_with("--"))
        .ok_or(RetrievalTraceExportError::MissingArgument(flag))
}

pub(crate) fn export_traces_jsonl(
    vault: &Vault,
    fork_hashes: &[RetrievalTraceForkHash],
    writer: &mut impl Write,
) -> ExportResult<usize> {
    let traces = load_traces(vault, fork_hashes)?;
    for trace in &traces {
        validate_trace(trace)?;
        serde_json::to_writer(&mut *writer, &RetrievalTraceExportRow::from_trace(trace))?;
        writer.write_all(b"\n")?;
    }
    Ok(traces.len())
}

fn load_traces(
    vault: &Vault,
    fork_hashes: &[RetrievalTraceForkHash],
) -> ExportResult<Vec<RetrievalTrace>> {
    let mut traces = Vec::with_capacity(fork_hashes.len());
    for fork_hash in fork_hashes {
        let trace = vault
            .retrieval_trace_by_fork_hash(*fork_hash)?
            .ok_or_else(|| RetrievalTraceExportError::TraceNotFound(encode_hex(fork_hash)))?;
        if trace.fork_hash != *fork_hash {
            return Err(RetrievalTraceExportError::InvalidTrace {
                fork_hash: encode_hex(fork_hash),
                reason: "loaded trace fork_hash does not match lookup key".to_owned(),
            });
        }
        traces.push(trace);
    }
    Ok(traces)
}

fn validate_trace(trace: &RetrievalTrace) -> ExportResult<()> {
    for channel in &trace.per_channel {
        if channel.stage != RetrievalTraceStage::PerChannel {
            return Err(invalid_trace(
                trace,
                "per_channel entry has non-per_channel stage",
            ));
        }
    }
    validate_stage(
        trace,
        trace.fused.stage,
        RetrievalTraceStage::Fused,
        "fused",
    )?;
    validate_stage(
        trace,
        trace.blended.stage,
        RetrievalTraceStage::Blended,
        "blended",
    )?;
    validate_stage(
        trace,
        trace.reranked.stage,
        RetrievalTraceStage::Reranked,
        "reranked",
    )?;
    validate_stage(
        trace,
        trace.final_stage.stage,
        RetrievalTraceStage::Final,
        "final",
    )
}

fn validate_stage(
    trace: &RetrievalTrace,
    actual: RetrievalTraceStage,
    expected: RetrievalTraceStage,
    name: &'static str,
) -> ExportResult<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(invalid_trace(
            trace,
            format!("{name} stage is tagged {actual:?}, expected {expected:?}"),
        ))
    }
}

fn invalid_trace(trace: &RetrievalTrace, reason: impl Into<String>) -> RetrievalTraceExportError {
    RetrievalTraceExportError::InvalidTrace {
        fork_hash: encode_hex(&trace.fork_hash),
        reason: reason.into(),
    }
}

fn parse_fork_hash(value: &str) -> ExportResult<RetrievalTraceForkHash> {
    parse_fixed_hex::<32>(value)
}

fn parse_fixed_hex<const N: usize>(value: &str) -> ExportResult<[u8; N]> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len() != N * 2 {
        return Err(RetrievalTraceExportError::InvalidForkHash {
            value: value.to_owned(),
            reason: format!("expected {} hex characters", N * 2),
        });
    }

    let mut bytes = [0_u8; N];
    let raw = value.as_bytes();
    for index in 0..N {
        let high = decode_hex_nibble(raw[index * 2]).ok_or_else(|| {
            RetrievalTraceExportError::InvalidForkHash {
                value: value.to_owned(),
                reason: "contains a non-hex character".to_owned(),
            }
        })?;
        let low = decode_hex_nibble(raw[index * 2 + 1]).ok_or_else(|| {
            RetrievalTraceExportError::InvalidForkHash {
                value: value.to_owned(),
                reason: "contains a non-hex character".to_owned(),
            }
        })?;
        bytes[index] = (high << 4) | low;
    }
    Ok(bytes)
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push(HEX_DIGITS[(byte >> 4) as usize] as char);
        hex.push(HEX_DIGITS[(byte & 0x0f) as usize] as char);
    }
    hex
}

fn print_help() {
    println!(
        "usage: oneiron-bench beam trace-export --vault <PATH> --fork-hash <HEX64> [--fork-hash <HEX64> ...] [--out <PATH>|-] [--dimensions N] [--embedding-model MODEL]\n\
         \n\
         Reads typed msgpack RetrievalTrace records from a vault by content-addressed fork hash\n\
         and writes one JSONL row per trace for the BEAM deterministic-arm reader.\n\
         \n\
         options:\n\
           --vault <PATH>             vault directory containing retrieval telemetry\n\
           --fork-hash <HEX64>        RET-TRACE-3 fork hash to export; may repeat\n\
           --out <PATH>|-             JSONL output path; default stdout\n\
           --dimensions N             vault vector dimensions; default 1024\n\
           --embedding-model MODEL    vault embedding model id when required by vector metadata"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use oneiron::{EntityId, TimeRange};

    fn test_vault_config() -> VaultConfig {
        let mut cfg = VaultConfig::device();
        cfg.map_size = 32 * 1024 * 1024;
        cfg.dimensions = 4;
        cfg.max_readers = 16;
        cfg
    }

    fn put_text(vault: &Vault, id: EntityId, text: &str) -> oneiron::Result<()> {
        vault
            .batch()
            .put(
                &id,
                oneiron::registry::ENTITY_TYPE_SUMMARY,
                TimeRange { start: 1, end: 1 },
                1,
                b"payload",
            )
            .text(&id, &[("body", text)])
            .commit()
    }

    fn captured_trace_fixture() -> (tempfile::TempDir, Vault, RetrievalTrace) {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(tempdir.path(), test_vault_config()).expect("vault opens");
        put_text(&vault, EntityId::now(), "trace stage fixture alpha").expect("fixture text");
        put_text(&vault, EntityId::now(), "trace stage fixture beta").expect("fixture text");

        let results = vault
            .query()
            .search_text("trace stage fixture", 10)
            .capture_retrieval_trace(true)
            .run_with_telemetry()
            .expect("captured retrieval");
        assert!(!results.value.is_empty());
        let run_id = results.run_id.expect("trace run id");
        let run = vault
            .retrieval_run(run_id)
            .expect("retrieval run lookup")
            .expect("retrieval run stored");
        let trace = run.trace.expect("trace captured");
        assert_ne!(trace.fork_hash, [0_u8; 32]);

        (tempdir, vault, trace)
    }

    fn decode_exported_row(jsonl: &[u8]) -> RetrievalTraceExportRow {
        let text = std::str::from_utf8(jsonl).expect("jsonl utf8");
        let mut lines = text.lines();
        let row: RetrievalTraceExportRow =
            serde_json::from_str(lines.next().expect("one JSONL row")).expect("row json");
        assert!(lines.next().is_none(), "fixture exports one row");
        row
    }

    #[test]
    fn exports_captured_trace_fixture_as_jsonl_round_trip() {
        let (_tempdir, vault, trace) = captured_trace_fixture();
        let mut jsonl = Vec::new();

        let rows = export_traces_jsonl(&vault, &[trace.fork_hash], &mut jsonl).expect("export");

        assert_eq!(rows, 1);
        let row = decode_exported_row(&jsonl);
        assert_eq!(
            row.contract_version,
            RETRIEVAL_TRACE_EXPORT_CONTRACT_VERSION
        );
        assert_eq!(row.record_type, RETRIEVAL_TRACE_RECORD_TYPE);
        assert_eq!(row.fork_hash, encode_hex(&trace.fork_hash));
        assert_eq!(row.try_to_trace().expect("row reconstructs trace"), trace);
    }

    #[test]
    fn exported_jsonl_preserves_all_retrieval_trace_stages() {
        let (_tempdir, vault, trace) = captured_trace_fixture();
        let mut jsonl = Vec::new();

        export_traces_jsonl(&vault, &[trace.fork_hash], &mut jsonl).expect("export");
        let row = decode_exported_row(&jsonl);

        assert!(!row.stages.per_channel.is_empty());
        assert!(
            row.stages
                .per_channel
                .iter()
                .all(|channel| channel.stage == RetrievalTraceStage::PerChannel)
        );
        assert_eq!(row.stages.fused.stage, RetrievalTraceStage::Fused);
        assert_eq!(row.stages.blended.stage, RetrievalTraceStage::Blended);
        assert_eq!(row.stages.reranked.stage, RetrievalTraceStage::Reranked);
        assert_eq!(row.stages.final_stage.stage, RetrievalTraceStage::Final);
    }

    #[test]
    fn exported_jsonl_preserves_beam_scored_trace_fields_losslessly() {
        let (_tempdir, vault, trace) = captured_trace_fixture();
        let mut jsonl = Vec::new();

        export_traces_jsonl(&vault, &[trace.fork_hash], &mut jsonl).expect("export");
        let reconstructed = decode_exported_row(&jsonl)
            .try_to_trace()
            .expect("row reconstructs trace");

        assert_eq!(reconstructed.fork_hash, trace.fork_hash);
        assert_eq!(reconstructed.per_channel, trace.per_channel);
        assert_eq!(reconstructed.fused.candidates, trace.fused.candidates);
        assert_eq!(reconstructed.blended.candidates, trace.blended.candidates);
        assert_eq!(reconstructed.reranked.candidates, trace.reranked.candidates);
        assert_eq!(
            reconstructed.final_stage.candidates,
            trace.final_stage.candidates
        );
    }

    #[test]
    fn parses_repeated_fork_hashes_and_stdout_output() {
        let fork_hash = [0xAB_u8; 32];
        let args = parse_args(&[
            "--vault".to_owned(),
            "/tmp/oneiron-vault".to_owned(),
            "--fork-hash".to_owned(),
            encode_hex(&fork_hash),
            "--out".to_owned(),
            "-".to_owned(),
            "--dimensions".to_owned(),
            "4".to_owned(),
        ])
        .expect("args parse");

        assert_eq!(args.vault_path, PathBuf::from("/tmp/oneiron-vault"));
        assert_eq!(args.output_path, None);
        assert_eq!(args.fork_hashes, vec![fork_hash]);
        assert_eq!(args.dimensions, 4);
    }
}
