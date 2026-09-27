//! Closed Draft 2020-12 tool-schema profile: resource-aware nodes, not a JSON rewrite.
//!
//! A resolved tree can only exist after every schema position, resource, ref
//! and literal value fits this bounded profile. Unknown semantic keywords are
//! refused. Canonicalization follows typed links and lifts only a lone branch
//! with no validating sibling; structural inequality is a conservative hold.
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

const MAX_NODES: usize = 8192;
const MAX_DEPTH: usize = 32;
const DRAFT: &str = "https://json-schema.org/draft/2020-12/schema";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SchemaProfile {
    Draft202012,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SchemaResourceId(String);
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SchemaNodeId {
    resource: SchemaResourceId,
    pointer: String,
}
impl SchemaNodeId {
    fn child(&self, key: &str) -> Self {
        let escaped = key.replace('~', "~0").replace('/', "~1");
        Self {
            resource: self.resource.clone(),
            pointer: format!("{}/{}", self.pointer, escaped),
        }
    }
    fn label(&self) -> String {
        format!("{}#{}", self.resource.0, self.pointer)
    }
}
#[derive(Debug)]
enum SchemaField {
    Literal(Value),
    Node(SchemaNodeId),
    Nodes(Vec<SchemaNodeId>),
    Map(BTreeMap<String, SchemaNodeId>),
}
#[derive(Debug)]
struct SchemaNode {
    fields: BTreeMap<String, SchemaField>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TextRole {
    Text,
    ParameterDescription,
}
#[derive(Debug)]
pub(super) struct SchemaText {
    pub role: TextRole,
    pub location: String,
    pub text: String,
}

#[derive(Debug)]
pub(super) struct ResolvedToolSchema {
    _profile: SchemaProfile,
    root: SchemaNodeId,
    nodes: BTreeMap<SchemaNodeId, SchemaNode>,
    canonical: Value,
}
struct Builder {
    nodes: BTreeMap<SchemaNodeId, SchemaNode>,
    resources: BTreeSet<SchemaResourceId>,
    remaining: usize,
}
impl Builder {
    fn debit(&mut self, depth: usize) -> Result<(), String> {
        if depth > MAX_DEPTH || self.remaining == 0 {
            return Err("schema resource bound exceeded".into());
        }
        self.remaining -= 1;
        Ok(())
    }
    fn literal(&mut self, value: &Value, depth: usize) -> Result<Value, String> {
        self.debit(depth)?;
        match value {
            Value::Object(fields) => {
                let mut copy = Map::new();
                for (name, child) in fields {
                    copy.insert(name.clone(), self.literal(child, depth + 1)?);
                }
                Ok(Value::Object(copy))
            }
            Value::Array(items) => Ok(Value::Array(
                items
                    .iter()
                    .map(|item| self.literal(item, depth + 1))
                    .collect::<Result<_, _>>()?,
            )),
            _ => Ok(value.clone()),
        }
    }
    fn schema(
        &mut self,
        raw: &Value,
        location: SchemaNodeId,
        depth: usize,
    ) -> Result<SchemaNodeId, String> {
        self.debit(depth)?;
        let fields = raw
            .as_object()
            .ok_or_else(|| format!("{}: schema must be an object", location.label()))?;
        let id = if let Some(value) = fields.get("$id") {
            let name = value.as_str().ok_or("$id must be a string")?;
            if !name.starts_with("https://")
                || name.contains('#')
                || name.len() > 1024
                || !name.is_ascii()
                || name.chars().any(char::is_whitespace)
            {
                return Err(format!("{}: unsupported $id resource", location.label()));
            }
            let resource = SchemaResourceId(name.to_owned());
            if !self.resources.insert(resource.clone()) {
                return Err("duplicate schema resource id".into());
            }
            SchemaNodeId {
                resource,
                pointer: String::new(),
            }
        } else {
            location
        };
        if self.nodes.contains_key(&id) {
            return Err(format!("{}: duplicate schema node", id.label()));
        }
        let mut parsed = BTreeMap::new();
        for (key, value) in fields {
            let field = match key.as_str() {
                "$schema" => {
                    if value.as_str() != Some(DRAFT) {
                        return Err(format!("{}: unsupported schema dialect", id.label()));
                    }
                    SchemaField::Literal(self.literal(value, depth + 1)?)
                }
                "$id" => SchemaField::Literal(self.literal(value, depth + 1)?),
                "$ref" => {
                    let Some(pointer) = value.as_str().and_then(|v| v.strip_prefix('#')) else {
                        return Err(format!("{}: external or invalid schema ref", id.label()));
                    };
                    if (!pointer.is_empty() && !pointer.starts_with('/')) || pointer.contains('%') {
                        return Err(format!("{}: unsupported schema ref", id.label()));
                    }
                    SchemaField::Literal(self.literal(value, depth + 1)?)
                }
                "$defs" | "properties" | "dependentSchemas" => {
                    let entries = value
                        .as_object()
                        .ok_or_else(|| format!("{}: {key} must be an object", id.label()))?;
                    let mut mapped = BTreeMap::new();
                    for (name, child) in entries {
                        let at = id.child(key).child(name);
                        mapped.insert(name.clone(), self.schema(child, at, depth + 1)?);
                    }
                    SchemaField::Map(mapped)
                }
                "allOf" | "anyOf" | "oneOf" | "prefixItems" => {
                    let items = value
                        .as_array()
                        .filter(|items| !items.is_empty())
                        .ok_or_else(|| format!("{}: empty or invalid {key}", id.label()))?;
                    let mut children = Vec::new();
                    for (index, child) in items.iter().enumerate() {
                        children.push(self.schema(
                            child,
                            id.child(key).child(&index.to_string()),
                            depth + 1,
                        )?);
                    }
                    SchemaField::Nodes(children)
                }
                "items"
                | "additionalProperties"
                | "unevaluatedProperties"
                | "contains"
                | "not"
                | "if"
                | "then"
                | "else"
                | "propertyNames"
                | "unevaluatedItems" => {
                    if value == &Value::Bool(true) || value == &Value::Bool(false) {
                        SchemaField::Literal(self.literal(value, depth + 1)?)
                    } else {
                        SchemaField::Node(self.schema(value, id.child(key), depth + 1)?)
                    }
                }
                "type" | "enum" | "const" | "required" | "dependentRequired" | "minimum"
                | "maximum" | "exclusiveMinimum" | "exclusiveMaximum" | "multipleOf"
                | "minLength" | "maxLength" | "minItems" | "maxItems" | "uniqueItems"
                | "minProperties" | "maxProperties" | "minContains" | "maxContains" | "title"
                | "description" | "$comment" | "default" | "examples" | "readOnly"
                | "writeOnly" | "deprecated" | "x-mcp-header" => {
                    SchemaField::Literal(self.literal(value, depth + 1)?)
                }
                _ => return Err(format!("{}: unsupported schema keyword {key}", id.label())),
            };
            parsed.insert(key.clone(), field);
        }
        self.nodes.insert(id.clone(), SchemaNode { fields: parsed });
        Ok(id)
    }
}
impl ResolvedToolSchema {
    pub(super) fn parse(raw: &Value) -> Result<Self, String> {
        let mut builder = Builder {
            nodes: BTreeMap::new(),
            resources: BTreeSet::new(),
            remaining: MAX_NODES,
        };
        let root = builder.schema(
            raw,
            SchemaNodeId {
                resource: SchemaResourceId("oneiron:tool-root".into()),
                pointer: String::new(),
            },
            0,
        )?;
        // Grammar/profile vetting above refuses unknown semantics. Validate
        // supported keyword value shapes with the pinned Draft 2020-12 engine;
        // this is a syntax check, not an equivalence oracle.
        jsonschema::validator_for(raw)
            .map_err(|error| format!("invalid Draft 2020-12 schema: {error}"))?;
        let mut result = Self {
            _profile: SchemaProfile::Draft202012,
            root,
            nodes: builder.nodes,
            canonical: Value::Null,
        };
        let mut stack = BTreeSet::new();
        let mut remaining = MAX_NODES;
        // An unused definition is still schema input, so its unresolved or
        // cyclic references cannot hide under a successful root projection.
        for id in result.nodes.keys() {
            result.project(id, &mut stack, &mut remaining)?;
        }
        result.canonical = result.project(&result.root, &mut stack, &mut remaining)?;
        Ok(result)
    }
    pub(super) fn canonical(&self) -> &Value {
        &self.canonical
    }
    fn target(&self, id: &SchemaNodeId, text: &str) -> Result<SchemaNodeId, String> {
        let pointer = text.strip_prefix('#').ok_or("external schema ref")?;
        let target = SchemaNodeId {
            resource: id.resource.clone(),
            pointer: pointer.to_owned(),
        };
        if !self.nodes.contains_key(&target) {
            return Err(format!("{}: unresolved schema ref {text}", id.label()));
        }
        Ok(target)
    }
    fn project(
        &self,
        id: &SchemaNodeId,
        stack: &mut BTreeSet<SchemaNodeId>,
        budget: &mut usize,
    ) -> Result<Value, String> {
        if *budget == 0 || stack.len() >= MAX_DEPTH {
            return Err("schema resolution bound exceeded".into());
        }
        *budget -= 1;
        if !stack.insert(id.clone()) {
            return Err(format!("{}: cyclic schema ref", id.label()));
        }
        let node = self
            .nodes
            .get(id)
            .ok_or_else(|| format!("{}: schema node missing", id.label()))?;
        let mut object = Map::new();
        let mut reference = None;
        for (key, field) in &node.fields {
            // Definitions and identifiers affect lookup, not validation; they
            // were parsed and scanned but can be omitted after resolution.
            if matches!(key.as_str(), "$id" | "$schema" | "$defs") {
                continue;
            }
            if key == "$ref" {
                let SchemaField::Literal(Value::String(text)) = field else {
                    return Err("invalid ref field".into());
                };
                reference = Some(self.project(&self.target(id, text)?, stack, budget)?);
                continue;
            }
            let value = match field {
                SchemaField::Literal(value) => value.clone(),
                SchemaField::Node(child) => self.project(child, stack, budget)?,
                SchemaField::Nodes(children) => {
                    let mut list = Vec::new();
                    for child in children {
                        let value = self.project(child, stack, budget)?;
                        if key != "allOf" || !list.contains(&value) {
                            list.push(value);
                        }
                    }
                    Value::Array(list)
                }
                SchemaField::Map(children) => {
                    let mut map = Map::new();
                    for (name, child) in children {
                        map.insert(name.clone(), self.project(child, stack, budget)?);
                    }
                    Value::Object(map)
                }
            };
            object.insert(key.clone(), value);
        }
        if let Some(reference) = reference {
            match object.get_mut("allOf") {
                Some(Value::Array(branches)) => branches.push(reference),
                _ => {
                    object.insert("allOf".into(), Value::Array(vec![reference]));
                }
            }
        }
        // Only a single branch with NO other keyword can be lifted. In
        // particular, `unevaluatedProperties` must remain beside allOf.
        if object.len() == 1
            && let Some(Value::Array(branches)) = object.get("allOf")
            && branches.len() == 1
            && branches[0].is_object()
        {
            let result = branches[0].clone();
            stack.remove(id);
            return Ok(result);
        }
        stack.remove(id);
        Ok(Value::Object(object))
    }
    pub(super) fn text(&self) -> Result<Vec<SchemaText>, String> {
        let mut found = Vec::new();
        let mut visited = BTreeSet::new();
        self.visit(&self.root, false, &mut visited, &mut found)?;
        // Also scan unreferenced definitions: no hidden instruction may live
        // in the exact source and wait for a future ref swap.
        for id in self.nodes.keys() {
            self.visit(id, false, &mut visited, &mut found)?;
        }
        Ok(found)
    }
    fn visit(
        &self,
        id: &SchemaNodeId,
        parameter: bool,
        visited: &mut BTreeSet<(SchemaNodeId, bool)>,
        found: &mut Vec<SchemaText>,
    ) -> Result<(), String> {
        if !visited.insert((id.clone(), parameter)) {
            return Ok(());
        }
        let node = self.nodes.get(id).ok_or("missing schema node")?;
        for (key, field) in &node.fields {
            found.push(SchemaText {
                role: TextRole::Text,
                location: id.label(),
                text: key.clone(),
            });
            match field {
                SchemaField::Literal(value) => {
                    let role = if key == "description" && parameter {
                        TextRole::ParameterDescription
                    } else {
                        TextRole::Text
                    };
                    literal_text(value, role, &id.label(), found);
                    if key == "$ref"
                        && let Some(text) = value.as_str()
                    {
                        self.visit(&self.target(id, text)?, parameter, visited, found)?;
                    }
                }
                SchemaField::Node(child) => self.visit(child, parameter, visited, found)?,
                SchemaField::Nodes(children) => {
                    for child in children {
                        self.visit(child, parameter, visited, found)?;
                    }
                }
                SchemaField::Map(children) => {
                    for (name, child) in children {
                        found.push(SchemaText {
                            role: TextRole::Text,
                            location: id.label(),
                            text: name.clone(),
                        });
                        self.visit(child, parameter || key == "properties", visited, found)?;
                    }
                }
            }
        }
        Ok(())
    }
}
fn literal_text(value: &Value, role: TextRole, location: &str, output: &mut Vec<SchemaText>) {
    match value {
        Value::String(text) => output.push(SchemaText {
            role,
            location: location.into(),
            text: text.clone(),
        }),
        Value::Array(items) => {
            for item in items {
                literal_text(item, TextRole::Text, location, output);
            }
        }
        Value::Object(fields) => {
            for (name, item) in fields {
                output.push(SchemaText {
                    role: TextRole::Text,
                    location: location.into(),
                    text: name.clone(),
                });
                literal_text(item, TextRole::Text, location, output);
            }
        }
        _ => {}
    }
}
