//! Closed Python install profile over a maintained grammar, not token spelling.
//!
//! This policy is an install rule, not the runtime sandbox. Only analyzed
//! statements and resolved call bindings can clear. Unsupported syntax, AST
//! recovery, reassignment of callable bindings and dynamic flows refuse.
use icu_normalizer::ComposingNormalizer;
use std::collections::{BTreeMap, BTreeSet};
use tree_sitter::{Node, Parser};

const MAX_SCRIPT_BYTES: usize = 256 * 1024;
const MAX_AST_NODES: usize = 8192;
const MAX_DEPTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Binding {
    Data,
    LocalFunction,
    Library(&'static str),
    LibraryCall(&'static str, String),
}
#[derive(Debug, Clone, PartialEq, Eq)]
enum CallTarget {
    Local,
    Library,
    Print,
    Length,
}
#[derive(Debug, Clone, PartialEq, Eq)]
enum ScriptEffect {
    LocalCall,
    LibraryCall,
    PureBuiltin,
}
#[derive(Debug)]
struct AnalyzedScript {
    _effects: Vec<ScriptEffect>,
}
struct Analyzer<'a> {
    source: &'a [u8],
    bindings: BTreeMap<String, Binding>,
    effects: Vec<ScriptEffect>,
    remaining: usize,
    allowed_calls: &'a BTreeSet<String>,
}

pub(super) fn screen_script(
    path: &str,
    source: &str,
    allowed_calls: &BTreeSet<String>,
) -> Option<String> {
    AnalyzedScript::parse(path, source, allowed_calls).err()
}
impl AnalyzedScript {
    fn parse(path: &str, source: &str, allowed_calls: &BTreeSet<String>) -> Result<Self, String> {
        if !path.ends_with(".py") {
            return Err("unsupported script format for sandbox screening".into());
        }
        if source.len() > MAX_SCRIPT_BYTES {
            return Err("Python script profile byte bound exceeded".into());
        }
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .map_err(|_| "Python parser grammar unavailable")?;
        let tree = parser
            .parse(source, None)
            .ok_or("Python parsing interrupted")?;
        if tree.root_node().has_error() {
            return Err("unverifiable script syntax".into());
        }
        let mut analyzer = Analyzer {
            source: source.as_bytes(),
            bindings: BTreeMap::new(),
            effects: Vec::new(),
            remaining: MAX_AST_NODES,
            allowed_calls,
        };
        analyzer.statement(tree.root_node(), 0)?;
        Ok(Self {
            _effects: analyzer.effects,
        })
    }
}
impl Analyzer<'_> {
    fn charge(&mut self, node: Node<'_>, depth: usize) -> Result<(), String> {
        if depth > MAX_DEPTH || self.remaining == 0 {
            return Err("Python AST profile bound exceeded".into());
        }
        self.remaining -= 1;
        if node.has_error() || node.is_missing() {
            return Err("unverifiable script syntax".into());
        }
        Ok(())
    }
    fn bytes<'a>(&'a self, node: Node<'_>) -> Result<&'a str, String> {
        std::str::from_utf8(&self.source[node.byte_range()])
            .map_err(|_| "Python source is not UTF-8".into())
    }
    fn name(&self, node: Node<'_>) -> Result<String, String> {
        if node.kind() != "identifier" {
            return Err(format!("unsupported Python binding name {}", node.kind()));
        }
        let raw = self.bytes(node)?;
        let normalized = ComposingNormalizer::new_nfkc().normalize(raw);
        // Grammar accepts Unicode XID names but our bounded policy supports
        // ASCII names only. Never quietly skip a normalized executable name.
        if !raw.is_ascii()
            || !raw.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || raw != normalized
        {
            return Err("unverifiable script syntax".into());
        }
        Ok(raw.to_owned())
    }
    fn child<'tree>(node: Node<'tree>, field: &str) -> Result<Node<'tree>, String> {
        node.child_by_field_name(field)
            .ok_or_else(|| format!("unsupported Python {} {field}", node.kind()))
    }
    fn named(node: Node<'_>) -> Vec<Node<'_>> {
        let mut cursor = node.walk();
        node.named_children(&mut cursor).collect()
    }
    fn safe_module(name: &str) -> Option<&'static str> {
        match name {
            "math" => Some("math"),
            "json" => Some("json"),
            _ => None,
        }
    }
    fn supported_function(module: &str, name: &str) -> bool {
        match module {
            "math" => matches!(
                name,
                "sqrt" | "floor" | "ceil" | "sin" | "cos" | "isfinite" | "log"
            ),
            "json" => matches!(name, "loads" | "dumps"),
            _ => false,
        }
    }
    fn allowed_function(&self, module: &str, name: &str) -> bool {
        Self::supported_function(module, name)
            && self.allowed_calls.contains(&format!("{module}.{name}"))
    }
    fn import_name(&self, node: Node<'_>) -> Result<(String, String), String> {
        let (target, alias) = if node.kind() == "aliased_import" {
            (
                Self::child(node, "name")?,
                Some(Self::child(node, "alias")?),
            )
        } else {
            (node, None)
        };
        if target.kind() != "dotted_name" {
            return Err("unsupported Python import syntax".into());
        }
        let parts = Self::named(target);
        if parts.len() != 1 {
            return Err("call outside the sandbox: dotted import".into());
        }
        let name = self.name(parts[0])?;
        let binding = alias
            .map(|node| self.name(node))
            .transpose()?
            .unwrap_or_else(|| name.clone());
        Ok((name, binding))
    }
    fn imports(&mut self, node: Node<'_>) -> Result<(), String> {
        match node.kind() {
            "import_statement" => {
                let mut cursor = node.walk();
                let entries: Vec<_> = node.children_by_field_name("name", &mut cursor).collect();
                if entries.is_empty() {
                    return Err("unsupported Python import syntax".into());
                }
                for entry in entries {
                    let (name, bound) = self.import_name(entry)?;
                    let module =
                        Self::safe_module(&name).ok_or("call outside the sandbox: import")?;
                    self.bindings.insert(bound, Binding::Library(module));
                }
            }
            "import_from_statement" => {
                let origin = Self::child(node, "module_name")?;
                if origin.kind() != "dotted_name" {
                    return Err("unsupported Python relative import".into());
                }
                let parts = Self::named(origin);
                if parts.len() != 1 {
                    return Err("call outside the sandbox: dotted import".into());
                }
                let module = Self::safe_module(&self.name(parts[0])?)
                    .ok_or("call outside the sandbox: import")?;
                let mut cursor = node.walk();
                let entries: Vec<_> = node.children_by_field_name("name", &mut cursor).collect();
                if entries.is_empty() {
                    return Err("unsupported Python wildcard import".into());
                }
                for entry in entries {
                    let (name, bound) = self.import_name(entry)?;
                    if !Self::supported_function(module, &name) {
                        return Err("call outside the sandbox: import".into());
                    }
                    self.bindings
                        .insert(bound, Binding::LibraryCall(module, name));
                }
            }
            _ => return Err("unsupported Python import syntax".into()),
        }
        Ok(())
    }
    fn statement(&mut self, node: Node<'_>, depth: usize) -> Result<(), String> {
        self.charge(node, depth)?;
        match node.kind() {
            "module" | "block" => {
                for child in Self::named(node) {
                    self.statement(child, depth + 1)?;
                }
            }
            "comment" | "pass_statement" => {}
            "import_statement" | "import_from_statement" => self.imports(node)?,
            "expression_statement" => {
                let children = Self::named(node);
                if children.len() != 1 {
                    return Err("unsupported Python expression statement".into());
                }
                let expression = children[0];
                if expression.kind() == "assignment" {
                    self.assignment(expression, depth + 1)?;
                } else {
                    self.expression(expression, depth + 1)?;
                }
            }
            "return_statement" => {
                for child in Self::named(node) {
                    self.expression(child, depth + 1)?;
                }
            }
            "function_definition" => self.function(node, depth + 1)?,
            _ => return Err(format!("unsupported Python statement {}", node.kind())),
        }
        Ok(())
    }
    fn function(&mut self, node: Node<'_>, depth: usize) -> Result<(), String> {
        let name = self.name(Self::child(node, "name")?)?;
        if matches!(name.as_str(), "eval" | "exec" | "open" | "__import__") {
            return Err("call outside the sandbox".into());
        }
        let mut cursor = node.walk();
        let has_async = node
            .children(&mut cursor)
            .any(|child| child.kind() == "async");
        if node.child_by_field_name("return_type").is_some()
            || node.child_by_field_name("type_parameters").is_some()
            || has_async
        {
            return Err("unsupported Python function signature".into());
        }
        let parameters = Self::child(node, "parameters")?;
        let body = Self::child(node, "body")?;
        // Function bodies are checked independently. Free-variable capture or
        // global binding changes would make a previously checked call stale.
        let mut local = Self {
            source: self.source,
            bindings: BTreeMap::new(),
            effects: Vec::new(),
            remaining: self.remaining,
            allowed_calls: self.allowed_calls,
        };
        for param in Self::named(parameters) {
            let name = local.name(param)?;
            local.bindings.insert(name, Binding::Data);
        }
        local.statement(body, depth + 1)?;
        self.remaining = local.remaining;
        self.effects.extend(local.effects);
        self.bindings.insert(name, Binding::LocalFunction);
        Ok(())
    }
    fn assignment(&mut self, node: Node<'_>, depth: usize) -> Result<(), String> {
        self.charge(node, depth)?;
        // Module/function annotations can execute expressions in Python.
        // They are outside this closed profile, even with a harmless RHS.
        if node.child_by_field_name("type").is_some() {
            return Err("unsupported Python annotation".into());
        }
        let left = Self::child(node, "left")?;
        let name = self.name(left)?;
        // An imported module or callable cannot be laundered by a local alias.
        let right = Self::child(node, "right")?;
        self.expression(right, depth + 1)?;
        self.bindings.insert(name, Binding::Data);
        Ok(())
    }
    fn call_target(&self, node: Node<'_>) -> Result<CallTarget, String> {
        match node.kind() {
            "identifier" => {
                let name = self.name(node)?;
                match self.bindings.get(&name) {
                    Some(Binding::LocalFunction) => Ok(CallTarget::Local),
                    Some(Binding::LibraryCall(module, function))
                        if self.allowed_function(module, function) =>
                    {
                        Ok(CallTarget::Library)
                    }
                    Some(Binding::Data | Binding::Library(_)) => {
                        Err("unsupported Python callable flow".into())
                    }
                    _ if name == "print" && self.allowed_calls.contains("print") => {
                        Ok(CallTarget::Print)
                    }
                    _ if name == "len" && self.allowed_calls.contains("len") => {
                        Ok(CallTarget::Length)
                    }
                    _ => Err("call outside the sandbox".into()),
                }
            }
            "attribute" => {
                let object = Self::child(node, "object")?;
                if object.kind() != "identifier" {
                    return Err("call outside the sandbox".into());
                }
                let name = self.name(object)?;
                let attribute = self.name(Self::child(node, "attribute")?)?;
                if let Some(Binding::Library(module)) = self.bindings.get(&name)
                    && self.allowed_function(module, &attribute)
                {
                    Ok(CallTarget::Library)
                } else {
                    Err("call outside the sandbox".into())
                }
            }
            _ => Err("unsupported Python call target".into()),
        }
    }
    fn expression(&mut self, node: Node<'_>, depth: usize) -> Result<(), String> {
        self.charge(node, depth)?;
        match node.kind() {
            "identifier" => {
                let name = self.name(node)?;
                if matches!(
                    name.as_str(),
                    "eval"
                        | "exec"
                        | "open"
                        | "__import__"
                        | "compile"
                        | "getattr"
                        | "setattr"
                        | "globals"
                        | "locals"
                ) {
                    return Err("call outside the sandbox".into());
                }
                if !matches!(self.bindings.get(&name), Some(Binding::Data)) {
                    return Err("unsupported Python callable binding".into());
                }
            }
            "integer" | "float" | "true" | "false" | "none" => {}
            "string" => {
                for child in Self::named(node) {
                    if !matches!(
                        child.kind(),
                        "string_start" | "string_content" | "string_end"
                    ) {
                        return Err("unverifiable script syntax".into());
                    }
                }
            }
            "call" => {
                let target = self.call_target(Self::child(node, "function")?)?;
                let args = Self::child(node, "arguments")?;
                if args.kind() != "argument_list" {
                    return Err("unsupported Python argument list".into());
                }
                for arg in Self::named(args) {
                    self.expression(arg, depth + 1)?;
                }
                self.effects.push(match target {
                    CallTarget::Local => ScriptEffect::LocalCall,
                    CallTarget::Library => ScriptEffect::LibraryCall,
                    CallTarget::Print | CallTarget::Length => ScriptEffect::PureBuiltin,
                });
            }
            "list" | "tuple" | "expression_list" => {
                for child in Self::named(node) {
                    self.expression(child, depth + 1)?;
                }
            }
            "dictionary" => {
                for pair in Self::named(node) {
                    if pair.kind() != "pair" {
                        return Err("unsupported Python dictionary entry".into());
                    }
                    self.expression(Self::child(pair, "key")?, depth + 1)?;
                    self.expression(Self::child(pair, "value")?, depth + 1)?;
                }
            }
            "parenthesized_expression" => {
                let children = Self::named(node);
                if children.len() != 1 {
                    return Err("unsupported Python parentheses".into());
                }
                self.expression(children[0], depth + 1)?;
            }
            "binary_operator" => {
                self.expression(Self::child(node, "left")?, depth + 1)?;
                self.expression(Self::child(node, "right")?, depth + 1)?;
                let operator = self.bytes(Self::child(node, "operator")?)?;
                if !["+", "-", "*", "/"].contains(&operator) {
                    return Err("unsupported Python operator".into());
                }
            }
            _ => return Err(format!("unsupported Python expression {}", node.kind())),
        }
        Ok(())
    }
}
