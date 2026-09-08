//! Deterministic and vanilla arms plus adapter dispatch.

use super::community::run_community_beam;
use super::model::{ArmKind, FixtureCase, FixtureClass};
use super::ppr_vad::PprVadSweepArm;
use super::report::{context_pack_report, serialized_context_pack_ids};
use super::report_model::{ArmOutcome, ArmReport, LoadedDataset};
use super::runner::{print_help, run_builtin_smoke, run_manifest_path};
use super::scorer::BeamArmAdapter;
use super::util::arm_not_ready;
use super::{BEAM_CONTEXT_PACK_FORMAT, BeamError, BeamResult, LOW_CONFIDENCE_RETRIEVAL_LIMIT};
use crate::retrieval_trace_export;
use oneiron::{ContextPack, ContextPackBuilder, FieldProfile, PackStats, Vault};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;

pub(super) struct DeterministicContextPackArm;
impl BeamArmAdapter for DeterministicContextPackArm {
    fn kind(&self) -> ArmKind {
        ArmKind::Deterministic
    }

    fn run(
        &self,
        vault: &Vault,
        _loaded: &LoadedDataset,
        case: &FixtureCase,
    ) -> BeamResult<ArmReport> {
        if case.pending_vector_count > 0 {
            return Err(BeamError::PendingEmbeddings {
                case_id: case.case_id.clone(),
                pending_vectors: case.pending_vector_count,
            });
        }

        let pack = run_deterministic_context_pack(vault, case)?;
        let report = context_pack_report(&pack, case);

        if report.result_count < case.expected_min_results {
            return Err(BeamError::DeterministicExpectation {
                case_id: case.case_id.clone(),
                expected: case.expected_min_results,
                actual: report.result_count,
            });
        }

        Ok(ArmReport {
            arm: self.kind(),
            outcome: ArmOutcome::Completed {
                context_pack: Box::new(report),
            },
        })
    }
}
pub(super) struct VanillaRagArm;
impl BeamArmAdapter for VanillaRagArm {
    fn kind(&self) -> ArmKind {
        ArmKind::VanillaRag
    }

    fn run(
        &self,
        vault: &Vault,
        loaded: &LoadedDataset,
        case: &FixtureCase,
    ) -> BeamResult<ArmReport> {
        if case.pending_vector_count > 0 {
            return Err(BeamError::PendingEmbeddings {
                case_id: case.case_id.clone(),
                pending_vectors: case.pending_vector_count,
            });
        }
        let query_vector = loaded
            .query_vector_by_case_id
            .get(case.case_id.as_str())
            .ok_or_else(|| BeamError::MissingQueryEmbedding {
                case_id: case.case_id.clone(),
            })?;

        let pack = run_vanilla_rag_context_pack(vault, case, query_vector)?;
        let report = context_pack_report(&pack, case);

        if report.result_count < case.expected_min_results {
            return Err(BeamError::VanillaRagExpectation {
                case_id: case.case_id.clone(),
                expected: case.expected_min_results,
                actual: report.result_count,
            });
        }

        Ok(ArmReport {
            arm: self.kind(),
            outcome: ArmOutcome::Completed {
                context_pack: Box::new(report),
            },
        })
    }
}
pub(super) struct NotReadyArm {
    pub(super) kind: ArmKind,
}
impl BeamArmAdapter for NotReadyArm {
    fn kind(&self) -> ArmKind {
        self.kind
    }

    fn run(
        &self,
        _vault: &Vault,
        _loaded: &LoadedDataset,
        _case: &FixtureCase,
    ) -> BeamResult<ArmReport> {
        Ok(ArmReport {
            arm: self.kind,
            outcome: ArmOutcome::NotReady {
                not_ready: arm_not_ready(self.kind),
            },
        })
    }
}
pub(crate) fn run(args: &[String]) -> ExitCode {
    match args {
        [] => {
            print_help();
            ExitCode::SUCCESS
        }
        [sub] if sub == "smoke" => match run_builtin_smoke()
            .and_then(|report| serde_json::to_string_pretty(&report).map_err(BeamError::from))
        {
            Ok(report_json) => {
                println!("{report_json}");
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("BEAM smoke failed: {err}");
                ExitCode::FAILURE
            }
        },
        [sub, manifest_path] if sub == "run" => match run_manifest_path(Path::new(manifest_path))
            .and_then(|report| serde_json::to_string_pretty(&report).map_err(BeamError::from))
        {
            Ok(report_json) => {
                println!("{report_json}");
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("BEAM run failed: {err}");
                ExitCode::FAILURE
            }
        },
        [sub, fixture_path] if sub == "community" => {
            match run_community_beam(Path::new(fixture_path))
                .and_then(|report| serde_json::to_string_pretty(&report).map_err(BeamError::from))
            {
                Ok(report) => {
                    println!("{report}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("BEAM community diagnostics failed: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        [sub, rest @ ..] if sub == "trace-export" => retrieval_trace_export::run(rest),
        [sub] => {
            eprintln!("unknown BEAM subcommand: {sub}");
            print_help();
            ExitCode::FAILURE
        }
        other => {
            eprintln!("unknown BEAM invocation: {other:?}");
            print_help();
            ExitCode::FAILURE
        }
    }
}
pub(super) fn adapter_for(kind: ArmKind) -> Box<dyn BeamArmAdapter> {
    match kind {
        ArmKind::Deterministic => Box::new(DeterministicContextPackArm),
        ArmKind::VanillaRag => Box::new(VanillaRagArm),
        ArmKind::PprVadSweep => Box::new(PprVadSweepArm),
        ArmKind::BackboneSolo | ArmKind::Agentic | ArmKind::Chat => Box::new(NotReadyArm { kind }),
    }
}
pub(super) fn configured_context_pack_builder<'a>(
    vault: &'a Vault,
    case: &FixtureCase,
) -> ContextPackBuilder<'a> {
    let text_search_limit = if case.fixture_class == FixtureClass::LowConfidence && case.limit == 0
    {
        LOW_CONFIDENCE_RETRIEVAL_LIMIT
    } else {
        case.limit
    };
    let builder = vault
        .context_pack()
        .search_text(&case.query, text_search_limit)
        .field_profile(FieldProfile::Standard)
        .format(BEAM_CONTEXT_PACK_FORMAT)
        .merge_neighbors(false)
        .include_stats(true)
        .token_budget(case.token_budget);

    match (case.fixture_class, &case.temporal_search) {
        (FixtureClass::TemporalStaleness, Some(range)) => builder
            .search_temporal(range.start, range.end, case.limit)
            .limit(case.limit),
        (FixtureClass::LowConfidence, _) => builder.limit(case.limit),
        _ => builder,
    }
}
pub(super) struct BudgetedContextPack {
    pub(super) raw: ContextPack,
    pub(super) serialized: Vec<u8>,
    pub(super) serialized_tokens: u64,
    pub(super) serialized_stats: PackStats,
    pub(super) serialized_elapsed_us: u64,
    pub(super) serialized_ids: SerializedContextPackIds,
    pub(super) temporal_result_ids: BTreeSet<String>,
}
pub(super) fn run_deterministic_context_pack(
    vault: &Vault,
    case: &FixtureCase,
) -> BeamResult<BudgetedContextPack> {
    run_budgeted_context_pack(|| configured_context_pack_builder(vault, case), vault, case)
}
pub(super) fn run_vanilla_rag_context_pack(
    vault: &Vault,
    case: &FixtureCase,
    query_vector: &[f32],
) -> BeamResult<BudgetedContextPack> {
    run_budgeted_context_pack(
        || configured_vanilla_rag_context_pack_builder(vault, case, query_vector),
        vault,
        case,
    )
}
pub(super) fn configured_vanilla_rag_context_pack_builder<'a>(
    vault: &'a Vault,
    case: &FixtureCase,
    query_vector: &'a [f32],
) -> ContextPackBuilder<'a> {
    let retrieval_limit = if case.fixture_class == FixtureClass::LowConfidence && case.limit == 0 {
        LOW_CONFIDENCE_RETRIEVAL_LIMIT
    } else {
        case.limit
    };

    vault
        .context_pack()
        .search_text(&case.query, retrieval_limit)
        .search_vector(query_vector, retrieval_limit)
        .field_profile(FieldProfile::Standard)
        .format(BEAM_CONTEXT_PACK_FORMAT)
        .merge_neighbors(false)
        .include_stats(true)
        .token_budget(case.token_budget)
        .limit(case.limit)
}
#[derive(Default)]
pub(super) struct SerializedContextPackIds {
    pub(super) results: HashSet<String>,
    pub(super) neighbors: HashSet<String>,
    pub(super) text_by_id: BTreeMap<String, String>,
}
#[derive(Clone, Copy)]
pub(super) enum SerializedContextPackSection {
    Results,
    Neighbors,
}
pub(super) struct ActiveSerializedContextPackSection {
    pub(super) section: SerializedContextPackSection,
    pub(super) section_indent: usize,
    pub(super) group_indent: Option<usize>,
    pub(super) row_indent: Option<usize>,
    pub(super) row_id: Option<String>,
}
pub(super) fn run_budgeted_context_pack<'a, F>(
    build_context_pack: F,
    vault: &Vault,
    case: &FixtureCase,
) -> BeamResult<BudgetedContextPack>
where
    F: Fn() -> ContextPackBuilder<'a>,
{
    let pack = build_context_pack().run()?;
    let serialized_start = Instant::now();
    let serialized_with_stats = build_context_pack().run_serialized_with_stats()?.value;
    let serialized_elapsed_us = serialized_start.elapsed().as_micros() as u64;
    let serialized = serialized_with_stats.bytes;
    let serialized_text = std::str::from_utf8(&serialized)?;
    let serialized_tokens = serialized_with_stats.stats.tokens.total_tokens as u64;
    let serialized_ids = serialized_context_pack_ids(serialized_text);
    let temporal_result_ids = temporal_result_ids(vault, case)?;

    Ok(BudgetedContextPack {
        raw: pack,
        serialized,
        serialized_tokens,
        serialized_stats: serialized_with_stats.stats,
        serialized_elapsed_us,
        serialized_ids,
        temporal_result_ids,
    })
}
pub(super) fn temporal_result_ids(
    vault: &Vault,
    case: &FixtureCase,
) -> BeamResult<BTreeSet<String>> {
    if case.fixture_class != FixtureClass::TemporalStaleness {
        return Ok(BTreeSet::new());
    }
    let Some(range) = &case.temporal_search else {
        return Ok(BTreeSet::new());
    };
    let results = vault
        .query()
        .search_temporal(range.start, range.end, case.limit)
        .limit(case.limit)
        .run()?;

    Ok(results
        .into_iter()
        .map(|entity| entity.id.to_hex())
        .collect())
}
