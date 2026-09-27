//! Bounded preflight for schemas evaluated on the host side of the sandbox.
//! Wasmtime fuel and deadlines do not interrupt native jsonschema callbacks.

use serde_json::Value;
use std::collections::{HashMap, HashSet};

const MAX_SCHEMA_NODES: usize = 1024;
const MAX_VALUE_NODES: usize = 2048;
const MAX_SCHEMA_DEPTH: usize = 32;
const MAX_VALUE_DEPTH: usize = 24;
const MAX_JSON_BYTES: usize = 128 * 1024;
const MAX_COMPOSITION_BRANCHES: usize = 32;
const MAX_EVALUATION_STEPS: usize = 8192;

pub(super) fn check(schema: &Value, value: &Value) -> Result<(), String> {
    bounded_tree(schema, MAX_SCHEMA_NODES, MAX_SCHEMA_DEPTH)?;
    bounded_tree(value, MAX_VALUE_NODES, MAX_VALUE_DEPTH)?;
    check_reference_cycles(schema)
}

fn bounded_tree(root: &Value, node_limit: usize, depth_limit: usize) -> Result<(), String> {
    let mut pending = vec![(root, 0)];
    let mut nodes = 0usize;
    let mut bytes = 0usize;
    while let Some((value, depth)) = pending.pop() {
        nodes += 1;
        if nodes > node_limit || depth > depth_limit {
            return Err("JSON schema validation input exceeds structural budget".into());
        }
        match value {
            Value::Object(fields) => {
                for (name, child) in fields {
                    bytes = bytes.saturating_add(name.len());
                    pending.push((child, depth + 1));
                }
            }
            Value::Array(items) => {
                pending.extend(items.iter().map(|child| (child, depth + 1)));
            }
            Value::String(text) => bytes = bytes.saturating_add(text.len()),
            _ => bytes = bytes.saturating_add(8),
        }
        if bytes > MAX_JSON_BYTES {
            return Err("JSON schema validation input exceeds byte budget".into());
        }
    }
    Ok(())
}

// Graph edges between schema positions that can run on the SAME instance.
// Edges under properties/items/contains move to a child value; these are safe
// recursive schemas because each descent consumes one of the bounded value nodes.
// Definitions are indexed but not executed until a $ref reaches them.
fn check_reference_cycles(schema: &Value) -> Result<(), String> {
    let mut pending = vec![(String::new(), schema)];
    let mut edges: HashMap<String, Vec<String>> = HashMap::new();
    let mut work_edges: HashMap<String, Vec<(String, bool)>> = HashMap::new();
    let mut compositions = 0usize;
    while let Some((path, node)) = pending.pop() {
        let Some(fields) = node.as_object() else {
            edges.insert(path.clone(), Vec::new());
            work_edges.insert(path, Vec::new());
            continue;
        };
        let mut same_instance = Vec::new();
        let mut work_children = Vec::new();
        if fields.contains_key("$dynamicRef") || fields.contains_key("$recursiveRef") {
            return Err("dynamic schema references cannot be bounded".into());
        }
        if !path.is_empty() && fields.contains_key("$id") {
            return Err("nested schema resource identifiers cannot be bounded".into());
        }
        if let Some(reference) = fields.get("$ref") {
            let Some(reference) = reference.as_str() else {
                return Err("invalid JSON schema reference".into());
            };
            let Some(pointer) = reference.strip_prefix('#') else {
                return Err("external JSON schema reference refused".into());
            };
            if !pointer.is_empty() && !pointer.starts_with('/') {
                return Err("schema anchor reference cannot be bounded".into());
            }
            if schema.pointer(pointer).is_none() {
                return Err("unresolved local JSON schema reference".into());
            }
            same_instance.push(pointer.to_owned());
            work_children.push((pointer.to_owned(), false));
        }
        for (keyword, entry) in fields {
            let (children, consumes) = match keyword.as_str() {
                "allOf" | "anyOf" | "oneOf" | "prefixItems" => {
                    let Some(items) = entry.as_array() else {
                        continue;
                    };
                    if matches!(keyword.as_str(), "allOf" | "anyOf" | "oneOf") {
                        compositions = compositions.saturating_add(items.len());
                        if compositions > MAX_COMPOSITION_BRANCHES {
                            return Err("JSON schema composition exceeds work budget".into());
                        }
                    }
                    (
                        items
                            .iter()
                            .enumerate()
                            .map(|(i, v)| (i.to_string(), v))
                            .collect::<Vec<_>>(),
                        keyword == "prefixItems",
                    )
                }
                "properties" | "patternProperties" | "dependentSchemas" | "dependencies"
                | "$defs" | "definitions" => {
                    let Some(map) = entry.as_object() else {
                        continue;
                    };
                    (
                        map.iter()
                            .map(|(name, v)| (escape(name), v))
                            .collect::<Vec<_>>(),
                        matches!(keyword.as_str(), "properties" | "patternProperties"),
                    )
                }
                "items"
                | "additionalItems"
                | "additionalProperties"
                | "unevaluatedItems"
                | "unevaluatedProperties"
                | "contains"
                | "propertyNames"
                | "contentSchema"
                | "not"
                | "if"
                | "then"
                | "else" => (
                    vec![(String::new(), entry)],
                    !matches!(
                        keyword.as_str(),
                        "not" | "if" | "then" | "else" | "contentSchema"
                    ),
                ),
                _ => continue,
            };
            for (name, child) in children {
                if !child.is_object() && !child.is_boolean() {
                    continue;
                }
                let child_path = if name.is_empty() {
                    format!("{path}/{}", escape(keyword))
                } else {
                    format!("{path}/{}/{}", escape(keyword), name)
                };
                if !matches!(keyword.as_str(), "$defs" | "definitions") {
                    work_children.push((child_path.clone(), consumes));
                    if !consumes {
                        same_instance.push(child_path.clone());
                    }
                }
                pending.push((child_path, child));
            }
        }
        edges.insert(path.clone(), same_instance);
        work_edges.insert(path, work_children);
    }
    if edges
        .values()
        .flatten()
        .any(|target| !edges.contains_key(target))
    {
        return Err("JSON schema reference target is not a bounded schema".into());
    }
    let mut done = HashSet::new();
    let mut active = HashSet::new();
    for path in edges.keys() {
        visit(path, &edges, &mut active, &mut done, 0)?;
    }
    // Acyclic same-instance references can still create exponential work when
    // recursion fans out at each child value. Budget the worst-case expansion
    // over the bounded instance depth before calling native validation.
    let mut memo = HashMap::new();
    evaluation_cost("", MAX_VALUE_DEPTH, &work_edges, &mut memo)?;
    Ok(())
}

fn evaluation_cost(
    path: &str,
    remaining_depth: usize,
    edges: &HashMap<String, Vec<(String, bool)>>,
    memo: &mut HashMap<(String, usize), usize>,
) -> Result<usize, String> {
    let key = (path.to_owned(), remaining_depth);
    if let Some(cost) = memo.get(&key) {
        return Ok(*cost);
    }
    let mut cost = 1usize;
    if let Some(children) = edges.get(path) {
        for (child, consumes_value) in children {
            if *consumes_value && remaining_depth == 0 {
                continue;
            }
            let child_cost = evaluation_cost(
                child,
                remaining_depth - usize::from(*consumes_value),
                edges,
                memo,
            )?;
            cost = cost.saturating_add(child_cost);
            if cost > MAX_EVALUATION_STEPS {
                return Err("JSON schema evaluation exceeds work budget".into());
            }
        }
    }
    memo.insert(key, cost);
    Ok(cost)
}

fn escape(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

fn visit<'a>(
    path: &'a str,
    edges: &'a HashMap<String, Vec<String>>,
    active: &mut HashSet<&'a str>,
    done: &mut HashSet<&'a str>,
    depth: usize,
) -> Result<(), String> {
    if depth > MAX_SCHEMA_DEPTH || !active.insert(path) {
        return Err("non-progressing or over-deep JSON schema reference".into());
    }
    if let Some(children) = edges.get(path) {
        for child in children {
            if !done.contains(child.as_str()) {
                visit(child, edges, active, done, depth + 1)?;
            }
        }
    }
    active.remove(path);
    done.insert(path);
    Ok(())
}
