use super::*;

#[test]
fn rejects_unsupported_metric_definition_schema_version() {
    let mut definitions: Of360MetricDefinitionSet =
        serde_json::from_str(OF360_METRIC_DEFINITIONS_JSON).expect("definitions JSON");
    definitions.schema_version = OF360_SCHEMA_VERSION + 1;

    let err = validate_metric_definitions(&definitions).expect_err("unsupported schema version");
    assert!(matches!(
        err,
        Of360EvalError::UnsupportedMetricDefinitionSchemaVersion { actual }
            if actual == OF360_SCHEMA_VERSION + 1
    ));
}
