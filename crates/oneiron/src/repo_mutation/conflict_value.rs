use std::collections::{BTreeSet, HashMap};

use rmpv::Value;

use crate::claim::{PREDICATE_CONFLICT_OPEN, PREDICATE_CONFLICT_RESOLVED};
use crate::codebase::RepoRef;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::git::{validate_git_object_hash, validate_git_ref_label, validate_relative_repo_path};

pub const REPO_CONFLICT_CLAIM_VALUE_SCHEMA_VERSION: u8 = 1;
pub const REPO_CONFLICT_OPEN_VALUE_KEYS: [&str; 8] = [
    "schema_version",
    "kind",
    "repo_ref",
    "branch",
    "base_tree",
    "ours_tree",
    "theirs_tree",
    "conflicted_paths",
];
pub const REPO_CONFLICT_RESOLUTION_VALUE_KEYS: [&str; 7] = [
    "schema_version",
    "kind",
    "repo_ref",
    "branch",
    "open_conflict_claim_id",
    "resolved_tree",
    "resolved_paths",
];

const REPO_CONFLICT_KIND_REPO_BRANCH: &str = "repo_branch";
const MAX_REPO_CONFLICT_PATHS: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RepoConflictOpenValue {
    pub(super) repo_ref: RepoRef,
    pub(super) branch: String,
    pub(super) base_tree: String,
    pub(super) ours_tree: String,
    pub(super) theirs_tree: String,
    pub(super) conflicted_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RepoConflictResolutionValue {
    pub(super) repo_ref: RepoRef,
    pub(super) branch: String,
    pub(super) open_conflict_claim_id: EntityId,
    pub(super) resolved_tree: String,
    pub(super) resolved_paths: Vec<String>,
}

pub(super) fn normalize_repo_conflict_paths(paths: Vec<String>) -> Result<Vec<String>> {
    let mut normalized = BTreeSet::new();
    for path in paths {
        validate_relative_repo_path(&path)?;
        normalized.insert(path);
        if normalized.len() > MAX_REPO_CONFLICT_PATHS {
            return Err(Error::InvalidRepoMutationRecord(
                "repo conflict path list exceeds max count",
            ));
        }
    }
    Ok(normalized.into_iter().collect())
}

pub(super) fn encode_repo_conflict_open_value(value: &RepoConflictOpenValue) -> Value {
    Value::Map(vec![
        (
            Value::from(REPO_CONFLICT_OPEN_VALUE_KEYS[0]),
            Value::from(u64::from(REPO_CONFLICT_CLAIM_VALUE_SCHEMA_VERSION)),
        ),
        (
            Value::from(REPO_CONFLICT_OPEN_VALUE_KEYS[1]),
            Value::from(REPO_CONFLICT_KIND_REPO_BRANCH),
        ),
        (
            Value::from(REPO_CONFLICT_OPEN_VALUE_KEYS[2]),
            Value::from(value.repo_ref.canonical()),
        ),
        (
            Value::from(REPO_CONFLICT_OPEN_VALUE_KEYS[3]),
            Value::from(value.branch.clone()),
        ),
        (
            Value::from(REPO_CONFLICT_OPEN_VALUE_KEYS[4]),
            Value::from(value.base_tree.clone()),
        ),
        (
            Value::from(REPO_CONFLICT_OPEN_VALUE_KEYS[5]),
            Value::from(value.ours_tree.clone()),
        ),
        (
            Value::from(REPO_CONFLICT_OPEN_VALUE_KEYS[6]),
            Value::from(value.theirs_tree.clone()),
        ),
        (
            Value::from(REPO_CONFLICT_OPEN_VALUE_KEYS[7]),
            Value::Array(
                value
                    .conflicted_paths
                    .iter()
                    .cloned()
                    .map(Value::from)
                    .collect(),
            ),
        ),
    ])
}

pub(super) fn encode_repo_conflict_resolution_value(value: &RepoConflictResolutionValue) -> Value {
    Value::Map(vec![
        (
            Value::from(REPO_CONFLICT_RESOLUTION_VALUE_KEYS[0]),
            Value::from(u64::from(REPO_CONFLICT_CLAIM_VALUE_SCHEMA_VERSION)),
        ),
        (
            Value::from(REPO_CONFLICT_RESOLUTION_VALUE_KEYS[1]),
            Value::from(REPO_CONFLICT_KIND_REPO_BRANCH),
        ),
        (
            Value::from(REPO_CONFLICT_RESOLUTION_VALUE_KEYS[2]),
            Value::from(value.repo_ref.canonical()),
        ),
        (
            Value::from(REPO_CONFLICT_RESOLUTION_VALUE_KEYS[3]),
            Value::from(value.branch.clone()),
        ),
        (
            Value::from(REPO_CONFLICT_RESOLUTION_VALUE_KEYS[4]),
            Value::Binary(value.open_conflict_claim_id.as_bytes().to_vec()),
        ),
        (
            Value::from(REPO_CONFLICT_RESOLUTION_VALUE_KEYS[5]),
            Value::from(value.resolved_tree.clone()),
        ),
        (
            Value::from(REPO_CONFLICT_RESOLUTION_VALUE_KEYS[6]),
            Value::Array(
                value
                    .resolved_paths
                    .iter()
                    .cloned()
                    .map(Value::from)
                    .collect(),
            ),
        ),
    ])
}

pub(crate) fn validate_repo_conflict_claim_value(predicate: &str, value: &Value) -> Result<()> {
    match predicate {
        PREDICATE_CONFLICT_OPEN => decode_repo_conflict_open_value(value).map(|_| ()),
        PREDICATE_CONFLICT_RESOLVED => decode_repo_conflict_resolution_value(value).map(|_| ()),
        _ => Ok(()),
    }
}

pub(super) fn decode_repo_conflict_open_value(value: &Value) -> Result<RepoConflictOpenValue> {
    let map = collect_value_map(value, &REPO_CONFLICT_OPEN_VALUE_KEYS)?;
    validate_schema_version(&map)?;
    validate_kind(&map)?;
    let repo_ref = RepoRef::parse(string_field(
        &map,
        REPO_CONFLICT_OPEN_VALUE_KEYS[2],
        "repo conflict repo_ref must be a string",
    )?)?;
    let branch = string_field_owned(
        &map,
        REPO_CONFLICT_OPEN_VALUE_KEYS[3],
        "repo conflict branch must be a string",
    )?;
    validate_git_ref_label(&branch)?;
    let base_tree = hash_field(&map, REPO_CONFLICT_OPEN_VALUE_KEYS[4])?;
    let ours_tree = hash_field(&map, REPO_CONFLICT_OPEN_VALUE_KEYS[5])?;
    let theirs_tree = hash_field(&map, REPO_CONFLICT_OPEN_VALUE_KEYS[6])?;
    let conflicted_paths = string_array_field(&map, REPO_CONFLICT_OPEN_VALUE_KEYS[7])?;
    if conflicted_paths.is_empty() {
        return Err(Error::InvalidClaimBody(
            "repo conflict claim requires at least one conflicted path",
        ));
    }
    Ok(RepoConflictOpenValue {
        repo_ref,
        branch,
        base_tree,
        ours_tree,
        theirs_tree,
        conflicted_paths,
    })
}

pub(super) fn decode_repo_conflict_resolution_value(
    value: &Value,
) -> Result<RepoConflictResolutionValue> {
    let map = collect_value_map(value, &REPO_CONFLICT_RESOLUTION_VALUE_KEYS)?;
    validate_schema_version(&map)?;
    validate_kind(&map)?;
    let repo_ref = RepoRef::parse(string_field(
        &map,
        REPO_CONFLICT_RESOLUTION_VALUE_KEYS[2],
        "repo conflict resolution repo_ref must be a string",
    )?)?;
    let branch = string_field_owned(
        &map,
        REPO_CONFLICT_RESOLUTION_VALUE_KEYS[3],
        "repo conflict resolution branch must be a string",
    )?;
    validate_git_ref_label(&branch)?;
    let open_conflict_claim_id = entity_id_field(&map, REPO_CONFLICT_RESOLUTION_VALUE_KEYS[4])?;
    let resolved_tree = hash_field(&map, REPO_CONFLICT_RESOLUTION_VALUE_KEYS[5])?;
    let resolved_paths = string_array_field(&map, REPO_CONFLICT_RESOLUTION_VALUE_KEYS[6])?;
    if resolved_paths.is_empty() {
        return Err(Error::InvalidClaimBody(
            "repo conflict resolution requires at least one resolved path",
        ));
    }
    Ok(RepoConflictResolutionValue {
        repo_ref,
        branch,
        open_conflict_claim_id,
        resolved_tree,
        resolved_paths,
    })
}

fn collect_value_map<'a>(
    value: &'a Value,
    expected_keys: &[&str],
) -> Result<HashMap<&'a str, &'a Value>> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidClaimBody(
            "repo conflict claim value must be a map",
        ));
    };
    if entries.len() != expected_keys.len() {
        return Err(Error::InvalidClaimBody(
            "repo conflict claim value keys must match the pinned schema",
        ));
    }

    let mut map = HashMap::with_capacity(entries.len());
    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidClaimBody(
                "repo conflict claim value keys must be strings",
            ));
        };
        if !expected_keys.contains(&key) {
            return Err(Error::InvalidClaimBody(
                "repo conflict claim value contains an unknown key",
            ));
        }
        if map.insert(key, value).is_some() {
            return Err(Error::InvalidClaimBody(
                "repo conflict claim value contains a duplicate key",
            ));
        }
    }
    for expected in expected_keys {
        if !map.contains_key(expected) {
            return Err(Error::InvalidClaimBody(
                "repo conflict claim value is missing a required key",
            ));
        }
    }
    Ok(map)
}

fn validate_schema_version(map: &HashMap<&str, &Value>) -> Result<()> {
    let raw = map
        .get("schema_version")
        .and_then(|value| value.as_u64())
        .ok_or(Error::InvalidClaimBody(
            "repo conflict schema_version must be an integer",
        ))?;
    if raw == u64::from(REPO_CONFLICT_CLAIM_VALUE_SCHEMA_VERSION) {
        Ok(())
    } else {
        Err(Error::InvalidClaimBody(
            "unsupported repo conflict claim schema_version",
        ))
    }
}

fn validate_kind(map: &HashMap<&str, &Value>) -> Result<()> {
    let kind = string_field(map, "kind", "repo conflict kind must be repo_branch")?;
    if kind == REPO_CONFLICT_KIND_REPO_BRANCH {
        Ok(())
    } else {
        Err(Error::InvalidClaimBody(
            "repo conflict kind must be repo_branch",
        ))
    }
}

fn string_field<'a>(
    map: &'a HashMap<&str, &Value>,
    key: &str,
    context: &'static str,
) -> Result<&'a str> {
    map.get(key)
        .and_then(|value| value.as_str())
        .ok_or(Error::InvalidClaimBody(context))
}

fn string_field_owned(
    map: &HashMap<&str, &Value>,
    key: &str,
    context: &'static str,
) -> Result<String> {
    Ok(string_field(map, key, context)?.to_owned())
}

fn hash_field(map: &HashMap<&str, &Value>, key: &str) -> Result<String> {
    let hash = string_field(map, key, "repo conflict tree hash must be a string")?.to_owned();
    validate_git_object_hash(&hash, "repo conflict tree hash must be a 40-hex object id")?;
    Ok(hash)
}

fn entity_id_field(map: &HashMap<&str, &Value>, key: &str) -> Result<EntityId> {
    let Value::Binary(bytes) = map
        .get(key)
        .ok_or(Error::InvalidClaimBody("repo conflict entity id missing"))?
    else {
        return Err(Error::InvalidClaimBody(
            "repo conflict entity id must be binary",
        ));
    };
    let raw: [u8; 16] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidClaimBody("repo conflict entity id must be 16 bytes"))?;
    EntityId::from_bytes(raw).map_err(|_| Error::InvalidClaimBody("invalid entity id"))
}

fn string_array_field(map: &HashMap<&str, &Value>, key: &str) -> Result<Vec<String>> {
    let Value::Array(values) = map
        .get(key)
        .ok_or(Error::InvalidClaimBody("repo conflict path array missing"))?
    else {
        return Err(Error::InvalidClaimBody(
            "repo conflict paths must be an array",
        ));
    };
    let mut paths = Vec::with_capacity(values.len());
    for value in values {
        let Some(path) = value.as_str() else {
            return Err(Error::InvalidClaimBody(
                "repo conflict paths must be strings",
            ));
        };
        paths.push(path.to_owned());
    }
    normalize_repo_conflict_paths(paths).map_err(|error| match error {
        Error::InvalidRepoMutationRecord(_) => {
            Error::InvalidClaimBody("repo conflict path is invalid")
        }
        other => other,
    })
}
