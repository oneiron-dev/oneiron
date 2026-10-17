//! The run rows as typed calls (OF-181).
//!
//! One decoder turns a run row's JSON input into the typed `self.*` call a
//! code run makes, for the component bridge and for the app's action
//! registry alike. The registry serves two sets beside a code run: the four
//! memory rows, which run on ordinary storage, and the rows that act on a
//! live agent run, which run only when the host binds that run's lease.

use super::{
    JS_SAFE_INTEGER, MemoryClaimInput, MemoryEdgeInput, MemorySearchInput, MemorySupersedeInput,
    MemoryTimeRange, SelfCall, SelfMemoryPutClaimCall, SelfMemoryPutEdgeCall, SelfMemorySearchCall,
    SelfMemorySupersedeClaimCall,
};
use crate::task_verb::sdk::RunVerb;
use crate::{ClaimCandidate, ClaimSubject, EdgeKind, EntityId, Error, Result, TimeRange};
use serde_json::Value;

/// The memory run rows, which need no live run.
pub(crate) const MEMORY_RUN_VERBS: [RunVerb; 4] = [
    RunVerb::VaultSearch,
    RunVerb::VaultClaimsPut,
    RunVerb::VaultClaimsSupersede,
    RunVerb::VaultEdgesPut,
];

/// The run rows that act on their caller's live agent run and read nothing
/// else of it: the attempt, its lease and its actor. A host serves them as
/// actions only under that run's lease. The fold rows need the run's own log
/// at its step boundary; `self.skills.call`, `self.spawn`, `summarize` and
/// `tasks.wait` need the running sandbox (its bridge, its results, its park);
/// and the leader's rows need the host's planner. None of those is here.
pub(crate) const LIVE_RUN_VERBS: [RunVerb; 4] = [
    RunVerb::TasksRefuse,
    RunVerb::SelfAgentsSpawn,
    RunVerb::SelfTeamStart,
    RunVerb::SelfTeamRecord,
];

/// The typed `self.*` call a run row makes, `now` in unix seconds: the call,
/// effect and gate the row had as a hand-written import. Every row has its
/// arm here, so a run row is never served undecoded, and the component
/// bridge and the action registry decode it the same way.
pub(crate) fn run_verb_call(verb: RunVerb, input: Value, now: u64) -> Result<SelfCall> {
    Ok(match verb {
        RunVerb::VaultSearch => {
            let args: MemorySearchInput = decode(input)?;
            SelfCall::MemorySearch(SelfMemorySearchCall::new(
                args.query,
                args.limit.map_or(20, |limit| limit as usize),
            ))
        }
        RunVerb::VaultClaimsPut => {
            let args: MemoryClaimInput = decode(input)?;
            let confidence = args.confidence.map(js_f32).transpose()?;
            let occurred = args.occurred.unwrap_or(MemoryTimeRange {
                start: now,
                end: now,
            });
            let (start, end) = (js_time(occurred.start)?, js_time(occurred.end)?);
            if start > end {
                return Err(failure("invalid claim time range"));
            }
            let candidate = ClaimCandidate::new(
                args.predicate,
                ClaimSubject::Entity(EntityId::from_hex(&args.subject)?),
                json_value(args.value),
                confidence.unwrap_or(1.0),
            );
            SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
                EntityId::from_hex(&args.id)?,
                candidate,
                TimeRange { start, end },
                args.learned_at.map_or(Ok(now), js_time)?,
            ))
        }
        RunVerb::VaultClaimsSupersede => {
            let args: MemorySupersedeInput = decode(input)?;
            SelfCall::MemorySupersedeClaim(SelfMemorySupersedeClaimCall::new(
                EntityId::from_hex(&args.new_id)?,
                EntityId::from_hex(&args.old_id)?,
                js_time(args.now)?,
            ))
        }
        RunVerb::VaultEdgesPut => {
            let args: MemoryEdgeInput = decode(input)?;
            let weight = args.weight.map(js_f32).transpose()?;
            let kind =
                EdgeKind::from_name(&args.kind).ok_or_else(|| failure("invalid edge kind"))?;
            let weight = weight
                .or_else(|| kind.default_weight())
                .ok_or(failure("edge weight required"))?;
            SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
                EntityId::from_hex(&args.src)?,
                kind,
                EntityId::from_hex(&args.tgt)?,
                weight,
            ))
        }
        RunVerb::SelfFold => {
            let args: crate::compaction::FoldMarkInput = decode(input)?;
            SelfCall::Fold(crate::compaction::SelfFoldCall::Mark {
                from: args.from,
                through: args.through,
                note: args.note,
            })
        }
        RunVerb::SelfCompact => {
            let args: crate::compaction::FoldCompactInput = decode(input)?;
            SelfCall::Fold(crate::compaction::SelfFoldCall::Compact { note: args.note })
        }
        RunVerb::SelfUnfold => {
            let args: crate::compaction::FoldUnfoldInput = decode(input)?;
            SelfCall::Fold(crate::compaction::SelfFoldCall::Unfold {
                fold: crate::compaction::parse_fold_handle(&args.fold)?,
            })
        }
        RunVerb::SelfFolds => {
            let _: crate::compaction::FoldsInput = decode(input)?;
            SelfCall::Fold(crate::compaction::SelfFoldCall::List)
        }
        RunVerb::TasksRefuse => {
            let args: crate::code_run::TaskRefuseInput = decode(input)?;
            SelfCall::TasksRefuse(crate::code_run::SelfTaskRefuseCall {
                task_ref: args
                    .task_ref
                    .as_deref()
                    .map(EntityId::from_hex)
                    .transpose()?,
                domain: match args.domain {
                    crate::code_run::TaskRefuseDomain::Bond => {
                        crate::agent_def::RefusalDomain::Bond
                    }
                    crate::code_run::TaskRefuseDomain::Logistics => {
                        crate::agent_def::RefusalDomain::Logistics
                    }
                },
                reason_ref: args.reason_ref,
                at: args.at.map_or(Ok(now), js_time)?,
            })
        }
        RunVerb::SelfSkillsCall => {
            let args: crate::code_run::SkillCallInput = decode(input)?;
            SelfCall::SkillsCall(crate::code_run::SelfSkillCall {
                skill: EntityId::from_hex(&args.skill)?,
                args: args.args,
            })
        }
        RunVerb::SelfAgentsSpawn => {
            let args: crate::code_run::AgentSpawnInput = decode(input)?;
            SelfCall::AgentsSpawn(Box::new(args.into_call()?))
        }
        RunVerb::SelfLeaderAdvice => {
            let args: crate::code_run::LeaderAdviceInput = decode(input)?;
            SelfCall::Leader(crate::code_run::SelfLeaderCall::Advice { top: args.top })
        }
        RunVerb::SelfLeaderPattern => {
            let args: crate::code_run::LeaderPatternInput = decode(input)?;
            SelfCall::Leader(crate::code_run::SelfLeaderCall::Pattern {
                skill: EntityId::from_hex(&args.skill)?,
            })
        }
        RunVerb::SelfSpawn => {
            let args: crate::code_run::ReaderSpawnInput = decode(input)?;
            SelfCall::ReaderSpawn(Box::new(crate::code_run::SelfReaderSpawnCall {
                source: reader_source(args.source)?,
                ask: args.ask,
                intent_key: args.intent_key,
                bound: None,
            }))
        }
        RunVerb::Summarize => {
            let args: crate::code_run::SummarizeInput = decode(input)?;
            SelfCall::Summarize(Box::new(crate::code_run::SelfSummarizeCall {
                reference: args.r#ref,
                effort: args.effort.map(|effort| match effort {
                    crate::code_run::SummarizeInputEffort::Low => {
                        crate::code_run::SummarizeEffort::Low
                    }
                    crate::code_run::SummarizeInputEffort::Medium => {
                        crate::code_run::SummarizeEffort::Medium
                    }
                    crate::code_run::SummarizeInputEffort::High => {
                        crate::code_run::SummarizeEffort::High
                    }
                }),
                group: args.group,
                defer: args.defer.unwrap_or(false),
                bound: None,
            }))
        }
        RunVerb::SelfTeamStart => SelfCall::Team(crate::team::SelfTeamCall::Start(decode(input)?)),
        RunVerb::SelfTeamRecord => {
            SelfCall::Team(crate::team::SelfTeamCall::Record(decode(input)?))
        }
        RunVerb::TasksWait => {
            let args: crate::code_run::TaskWaitSetRequest = decode(input)?;
            SelfCall::TasksWaitSet(crate::code_run::TaskWaitSetCall {
                tasks: args.tasks,
                all: args.all,
                n_of: args.n_of,
                until: args.until.map(js_time).transpose()?,
                step_key: args.step_key,
            })
        }
    })
}

/// The result a `self.spawn` source names: its ref as a string, or a card's
/// `ref` or `handle`.
fn reader_source(source: Value) -> Result<String> {
    match source {
        Value::String(text) => Ok(text),
        Value::Object(mut fields) => ["ref", "handle"]
            .into_iter()
            .find_map(|key| match fields.remove(key) {
                Some(Value::String(text)) => Some(text),
                _ => None,
            })
            .ok_or_else(|| failure("spawn source must be a result ref or card")),
        _ => Err(failure("spawn source must be a result ref or card")),
    }
}

fn failure(detail: &str) -> Error {
    Error::InvalidConfig(detail.to_owned())
}

fn decode<T: serde::de::DeserializeOwned>(input: Value) -> Result<T> {
    serde_json::from_value(input).map_err(|_| failure("invalid typed component arguments"))
}

/// A caller's integer for a time field, inside JavaScript's safe range.
fn js_time(value: u64) -> Result<u64> {
    if value > JS_SAFE_INTEGER {
        return Err(failure("invalid guest integer"));
    }
    Ok(value)
}

/// A caller's number for an `f32` field. A number past `f32`'s range is
/// refused, not rounded to its edge or to infinity.
fn js_f32(value: f64) -> Result<f32> {
    if !value.is_finite() || value.abs() > f64::from(f32::MAX) {
        return Err(failure("invalid guest number"));
    }
    Ok(value as f32)
}

fn json_value(value: Value) -> rmpv::Value {
    match value {
        Value::Null => rmpv::Value::Nil,
        Value::Bool(v) => rmpv::Value::Boolean(v),
        Value::Number(v) => {
            if let Some(v) = v.as_u64() {
                rmpv::Value::from(v)
            } else if let Some(v) = v.as_i64() {
                rmpv::Value::from(v)
            } else {
                rmpv::Value::F64(v.as_f64().unwrap_or_default())
            }
        }
        Value::String(v) => rmpv::Value::from(v),
        Value::Array(v) => rmpv::Value::Array(v.into_iter().map(json_value).collect()),
        Value::Object(v) => rmpv::Value::Map(
            v.into_iter()
                .map(|(k, v)| (rmpv::Value::from(k), json_value(v)))
                .collect(),
        ),
    }
}
