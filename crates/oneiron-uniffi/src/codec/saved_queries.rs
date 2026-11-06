//! Owned filter and matcher JSON in saved-query definition outputs.

use oneiron::campaign::surface::{
    SavedQueryEvaluationReceipt, SavedQueryFilterSpec, SavedQueryMatcherSpec, SavedQueryReadResult,
    SavedQueryRecordView,
};
use serde_json::Value;

use super::{Lift, OneironError, WireJson, internal, lift_record};

pub(crate) fn lift_saved_query_record(
    verb: &str,
    mut record: SavedQueryRecordView,
) -> Result<crate::SavedQueryRecordView, OneironError> {
    let filter = std::mem::replace(&mut record.definition.filter, empty_filter());
    let matcher = std::mem::replace(
        &mut record.definition.matcher,
        SavedQueryMatcherSpec::Hard {
            expression: empty_filter(),
        },
    );
    // Both opaque subtrees are consumed before either error can return.
    let filter = lift_filter(verb, filter);
    let matcher = lift_matcher(verb, matcher);
    let filter = filter?;
    let matcher = matcher?;
    let mut output: crate::SavedQueryRecordView = lift_record(verb, &record)?;
    output.definition.filter = filter;
    output.definition.matcher = matcher;
    Ok(output)
}

pub(crate) fn lift_saved_query_read(
    verb: &str,
    mut read: SavedQueryReadResult,
) -> Result<crate::SavedQueryReadResult, OneironError> {
    let record = read
        .record
        .take()
        .map(|record| lift_saved_query_record(verb, record))
        .transpose()?;
    let mut output: crate::SavedQueryReadResult = lift_record(verb, &read)?;
    output.record = record;
    Ok(output)
}

pub(crate) fn lift_saved_query_evaluation(
    verb: &str,
    mut receipt: SavedQueryEvaluationReceipt,
) -> Result<crate::SavedQueryEvaluationReceipt, OneironError> {
    let mut providers = Vec::with_capacity(receipt.outcomes.len());
    for outcome in &mut receipt.outcomes {
        let mut values = Vec::new();
        if let Some(judge) = &mut outcome.judge {
            values.reserve(judge.generations.len());
            for generation in &mut judge.generations {
                values.push(WireJson::lift(std::mem::take(
                    &mut generation.usage.raw_provider,
                )));
            }
        }
        providers.push(values);
    }
    // Every generation has been consumed, even when an earlier one failed.
    let providers = providers
        .into_iter()
        .map(|values| values.into_iter().collect::<Result<Vec<_>, _>>())
        .collect::<Result<Vec<_>, _>>()?;
    let mut output: crate::SavedQueryEvaluationReceipt = lift_record(verb, &receipt)?;
    for (outcome, values) in output.outcomes.iter_mut().zip(providers) {
        if let Some(judge) = &mut outcome.judge {
            for (generation, value) in judge.generations.iter_mut().zip(values) {
                generation.usage.raw_provider = value;
            }
        }
    }
    Ok(output)
}

fn empty_filter() -> SavedQueryFilterSpec {
    SavedQueryFilterSpec::All { terms: Vec::new() }
}

fn lift_matcher(
    verb: &str,
    matcher: SavedQueryMatcherSpec,
) -> Result<crate::SavedQueryMatcherSpec, OneironError> {
    match matcher {
        SavedQueryMatcherSpec::Hard { expression } => Ok(crate::SavedQueryMatcherSpec::Hard {
            expression: lift_filter(verb, expression)?,
        }),
        mut matcher @ SavedQueryMatcherSpec::LlmJudge { .. } => {
            let SavedQueryMatcherSpec::LlmJudge { rubric, .. } = &mut matcher else {
                unreachable!()
            };
            let rubric = match std::mem::take(rubric) {
                Value::Null => None,
                value => Some(WireJson::lift(value)?),
            };
            let mut output = lift_record(verb, &matcher)?;
            if let crate::SavedQueryMatcherSpec::LlmJudge { rubric: target, .. } = &mut output {
                *target = rubric;
            }
            Ok(output)
        }
        other => lift_record(verb, &other),
    }
}

enum Child {
    Terms(Vec<SavedQueryFilterSpec>),
    Term(Box<SavedQueryFilterSpec>),
    Value(Value),
}

impl Child {
    fn key(&self) -> &'static str {
        match self {
            Self::Terms(_) => "terms",
            Self::Term(_) => "term",
            Self::Value(_) => "value",
        }
    }

    fn into_step(self) -> Step {
        match self {
            Self::Terms(terms) => Step::Terms(terms.into_iter(), true),
            Self::Term(term) => Step::Filter(*term),
            Self::Value(value) => Step::Value(value),
        }
    }
}

enum Step {
    Filter(SavedQueryFilterSpec),
    Terms(std::vec::IntoIter<SavedQueryFilterSpec>, bool),
    Fields(serde_json::map::IntoIter, Option<Child>, bool),
    Value(Value),
}

fn lift_filter(verb: &str, filter: SavedQueryFilterSpec) -> Result<WireJson, OneironError> {
    let mut canonical_json = String::new();
    let mut error = None;
    let mut steps = vec![Step::Filter(filter)];
    while let Some(step) = steps.pop() {
        match step {
            Step::Filter(mut filter) => {
                let child = match &mut filter {
                    SavedQueryFilterSpec::All { terms } | SavedQueryFilterSpec::Any { terms } => {
                        Some(Child::Terms(std::mem::take(terms)))
                    }
                    SavedQueryFilterSpec::Not { term } => Some(Child::Term(std::mem::replace(
                        term,
                        Box::new(empty_filter()),
                    ))),
                    SavedQueryFilterSpec::Claim { value, .. } => {
                        Some(Child::Value(std::mem::take(value)))
                    }
                    SavedQueryFilterSpec::TaskOwner { .. }
                    | SavedQueryFilterSpec::EdgeExists { .. } => None,
                };
                // Native serde chooses the field names, values and active map order.
                // Only the detached child slot is replaced during the stack walk.
                match serde_json::to_value(&filter) {
                    Ok(Value::Object(fields)) => {
                        canonical_json.push('{');
                        steps.push(Step::Fields(fields.into_iter(), child, true));
                    }
                    Ok(_) => unreachable!("a saved-query filter serializes as a tagged object"),
                    Err(failure) => {
                        error.get_or_insert_with(|| {
                            internal(format!("could not encode {verb}'s result: {failure}"))
                        });
                        if let Some(child) = child {
                            steps.push(child.into_step());
                        }
                    }
                }
            }
            Step::Terms(mut terms, first) => {
                if first {
                    canonical_json.push('[');
                }
                if let Some(term) = terms.next() {
                    if !first {
                        canonical_json.push(',');
                    }
                    steps.push(Step::Terms(terms, false));
                    steps.push(Step::Filter(term));
                } else {
                    canonical_json.push(']');
                }
            }
            Step::Fields(mut fields, child, first) => {
                if let Some((key, value)) = fields.next() {
                    if !first {
                        canonical_json.push(',');
                    }
                    append_json(&mut canonical_json, &mut error, super::encode(verb, &key));
                    canonical_json.push(':');
                    let (next, child) = match child {
                        Some(child) if key == child.key() => (child.into_step(), None),
                        other => (Step::Value(value), other),
                    };
                    steps.push(Step::Fields(fields, child, false));
                    steps.push(next);
                } else {
                    canonical_json.push('}');
                }
            }
            Step::Value(value) => {
                append_json(&mut canonical_json, &mut error, WireJson::lift(value));
            }
        }
    }
    match error {
        Some(error) => Err(error),
        None => Ok(WireJson { canonical_json }),
    }
}

fn append_json(
    output: &mut String,
    error: &mut Option<OneironError>,
    value: Result<WireJson, OneironError>,
) {
    match value {
        Ok(value) => output.push_str(&value.canonical_json),
        Err(failure) => {
            error.get_or_insert(failure);
        }
    }
}
