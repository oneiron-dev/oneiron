//! Wire encoders (domain types with EntityIds hand-rendered to hex JSON).

use serde_json::{Map as JsonMap, Value};

use super::{CampaignRecord, MembershipPage, MembershipRow};
use crate::saved_query::{
    EvalPolicy, FilterAst, MatcherSpec, QueryScope, SavedQueryLifecycle, SavedQueryRecord,
};

/// Encodes a campaign record for the wire.
#[must_use]
pub fn campaign_record_to_json(record: &CampaignRecord) -> Value {
    let mut definition = JsonMap::new();
    definition.insert(
        "schema_version".to_owned(),
        Value::from(record.definition.schema_version),
    );
    definition.insert(
        "owner_actor".to_owned(),
        Value::String(record.definition.owner_actor.to_hex()),
    );
    definition.insert(
        "name".to_owned(),
        Value::String(record.definition.name.clone()),
    );
    definition.insert(
        "definition_version".to_owned(),
        Value::from(record.definition.definition_version),
    );
    definition.insert(
        "lifecycle".to_owned(),
        Value::String(record.definition.lifecycle.as_str().to_owned()),
    );

    let mut root = JsonMap::new();
    root.insert(
        "campaign_ref".to_owned(),
        Value::String(record.campaign_ref.to_hex()),
    );
    root.insert("definition".to_owned(), Value::Object(definition));
    root.insert("created_at".to_owned(), Value::from(record.created_at));
    root.insert("updated_at".to_owned(), Value::from(record.updated_at));
    Value::Object(root)
}

/// Encodes a saved-query record for the wire.
///
/// Hand-written for the reason [`SavedQueryDefinition`](crate::saved_query::SavedQueryDefinition) documents: its types
/// carry [`EntityId`]s and are deliberately not serde-derived, and the
/// `saved_query` module is a CA-07 non-claim, so this surface converts CA-02's types
/// rather than changing them.
#[must_use]
pub fn saved_query_record_to_json(record: &SavedQueryRecord) -> Value {
    let mut definition = JsonMap::new();
    definition.insert(
        "schema_version".to_owned(),
        Value::from(record.definition.schema_version),
    );
    definition.insert(
        "owner_actor".to_owned(),
        Value::String(record.definition.owner_actor.to_hex()),
    );
    definition.insert("scope".to_owned(), scope_to_json(&record.definition.scope));
    definition.insert(
        "definition_version".to_owned(),
        Value::from(record.definition.definition_version),
    );
    definition.insert(
        "filter".to_owned(),
        filter_to_json(&record.definition.filter),
    );
    definition.insert(
        "matcher".to_owned(),
        matcher_to_json(&record.definition.matcher),
    );
    definition.insert("eval".to_owned(), eval_to_json(record.definition.eval));
    definition.insert(
        "lifecycle".to_owned(),
        saved_query_lifecycle_to_json(&record.definition.lifecycle),
    );

    let mut root = JsonMap::new();
    root.insert(
        "query_ref".to_owned(),
        Value::String(record.query_ref.to_hex()),
    );
    root.insert("definition".to_owned(), Value::Object(definition));
    root.insert("created_at".to_owned(), Value::from(record.created_at));
    root.insert("updated_at".to_owned(), Value::from(record.updated_at));
    Value::Object(root)
}

fn saved_query_lifecycle_to_json(lifecycle: &SavedQueryLifecycle) -> Value {
    let mut root = JsonMap::new();
    match lifecycle {
        SavedQueryLifecycle::Active => {
            root.insert("state".to_owned(), Value::String("active".to_owned()));
        }
        SavedQueryLifecycle::Paused { error } => {
            root.insert("state".to_owned(), Value::String("paused".to_owned()));
            root.insert("error".to_owned(), Value::String(error.clone()));
        }
        SavedQueryLifecycle::Archived => {
            root.insert("state".to_owned(), Value::String("archived".to_owned()));
        }
    }
    Value::Object(root)
}

fn scope_to_json(scope: &QueryScope) -> Value {
    let mut root = JsonMap::new();
    root.insert(
        "worlds".to_owned(),
        Value::Array(
            scope
                .worlds
                .iter()
                .map(|world| Value::String(world.to_hex()))
                .collect(),
        ),
    );
    root.insert(
        "facets".to_owned(),
        Value::Array(
            scope
                .facets
                .iter()
                .map(|facet| Value::String(facet.clone()))
                .collect(),
        ),
    );
    Value::Object(root)
}

fn filter_to_json(filter: &FilterAst) -> Value {
    let mut root = JsonMap::new();
    match filter {
        FilterAst::All { terms } | FilterAst::Any { terms } => {
            let op = if matches!(filter, FilterAst::All { .. }) {
                "all"
            } else {
                "any"
            };
            root.insert("op".to_owned(), Value::String(op.to_owned()));
            root.insert(
                "terms".to_owned(),
                Value::Array(terms.iter().map(filter_to_json).collect()),
            );
        }
        FilterAst::Not { term } => {
            root.insert("op".to_owned(), Value::String("not".to_owned()));
            root.insert("term".to_owned(), filter_to_json(term));
        }
        FilterAst::Claim {
            predicate,
            cmp,
            value,
        } => {
            root.insert("op".to_owned(), Value::String("claim".to_owned()));
            root.insert("predicate".to_owned(), Value::String(predicate.clone()));
            root.insert("cmp".to_owned(), Value::String(cmp.as_str().to_owned()));
            root.insert("value".to_owned(), value.clone());
        }
        FilterAst::EdgeExists { edge_kind, target } => {
            root.insert("op".to_owned(), Value::String("edge_exists".to_owned()));
            root.insert("edge_kind".to_owned(), Value::String(edge_kind.clone()));
            root.insert(
                "target".to_owned(),
                target.map_or(Value::Null, |id| Value::String(id.to_hex())),
            );
        }
    }
    Value::Object(root)
}

fn matcher_to_json(matcher: &MatcherSpec) -> Value {
    let mut root = JsonMap::new();
    match matcher {
        MatcherSpec::Hard { expression } => {
            root.insert("kind".to_owned(), Value::String("hard".to_owned()));
            root.insert("expression".to_owned(), filter_to_json(expression));
        }
        MatcherSpec::SemanticThreshold {
            exemplar_ref,
            minimum_similarity_micros,
        } => {
            root.insert(
                "kind".to_owned(),
                Value::String("semantic_threshold".to_owned()),
            );
            root.insert(
                "exemplar_ref".to_owned(),
                Value::String(exemplar_ref.to_hex()),
            );
            root.insert(
                "minimum_similarity_micros".to_owned(),
                Value::from(*minimum_similarity_micros),
            );
        }
        MatcherSpec::LlmJudge {
            model_id,
            rubric,
            rubric_version,
        } => {
            root.insert("kind".to_owned(), Value::String("llm_judge".to_owned()));
            root.insert("model_id".to_owned(), Value::String(model_id.clone()));
            root.insert("rubric".to_owned(), rubric.clone());
            root.insert(
                "rubric_version".to_owned(),
                Value::String(rubric_version.clone()),
            );
        }
    }
    Value::Object(root)
}

fn eval_to_json(eval: EvalPolicy) -> Value {
    let mut root = JsonMap::new();
    root.insert(
        "mode".to_owned(),
        Value::String(eval.mode.as_str().to_owned()),
    );
    root.insert(
        "max_entities_per_wake".to_owned(),
        Value::from(eval.max_entities_per_wake),
    );
    root.insert(
        "max_judges_per_wake".to_owned(),
        Value::from(eval.max_judges_per_wake),
    );
    Value::Object(root)
}

pub(super) fn membership_page_to_json(page: &MembershipPage) -> Value {
    let mut root = JsonMap::new();
    root.insert(
        "rows".to_owned(),
        Value::Array(page.rows.iter().map(membership_row_to_json).collect()),
    );
    root.insert(
        "next_cursor".to_owned(),
        page.next_cursor
            .as_ref()
            .map_or(Value::Null, |cursor| Value::String(cursor.clone())),
    );
    Value::Object(root)
}

fn membership_row_to_json(row: &MembershipRow) -> Value {
    let mut root = JsonMap::new();
    root.insert(
        "entity_ref".to_owned(),
        Value::String(row.entity_ref.to_hex()),
    );
    root.insert("state".to_owned(), Value::String(row.state.clone()));
    root.insert("entered_valid".to_owned(), Value::from(row.entered_valid));
    root.insert(
        "entered_detected".to_owned(),
        Value::from(row.entered_detected),
    );
    root.insert(
        "exited_valid".to_owned(),
        row.exited_valid.map_or(Value::Null, Value::from),
    );
    root.insert(
        "exited_detected".to_owned(),
        row.exited_detected.map_or(Value::Null, Value::from),
    );
    root.insert(
        "cause".to_owned(),
        row.cause
            .as_ref()
            .map_or(Value::Null, |cause| Value::String(cause.clone())),
    );
    Value::Object(root)
}
