//! Port of generate.py's Python emitters (614-628, 686-770, 832-843): the facade verbs as the mixin `_FacadeVerbs`
//! that `Oneiron` derives from, at `crates/oneiron-py/python/oneiron/_facade_verbs.py` and its stub `.pyi`.
//!
//! Every call into the shared `Inventory` (`py_type`, and `boundary_type`'s `py_stub`) happens where Python makes
//! it (H10): the runtime module walks the same rows as the stub and makes the same calls, though it prints none of
//! their types.

use super::common::{ArgumentValue, argument_kind, boundary_type, hand_declared, str_receiver};
use super::emit_ts::{VerbNode, VerbTree, capitalized_words, concat_left, row_of, row_type};
use super::row_access::{concat, item, json};
use super::{Generator, HEADER, RowId};
use crate::error::GenerateError;
use crate::facade_types::inventory::type_text;
use crate::py::builtins::is_keyword;
use crate::py::text::{splitlines, title};
use crate::py::value::{Dict, Value};

/// Port of generate.py:686-688 (py_doc): a row's description as the docstring of each Python method that calls it.
fn py_doc(row: &Dict) -> String {
    match row.get("description") {
        Some(description) if description.truthy() => {
            format!("        \"\"\"{}\"\"\"\n", description.str())
        }
        _ => String::new(),
    }
}

/// Port of generate.py:717-720 (leaf): the Python method a row ends in; a keyword (`continue`) takes the trailing
/// underscore PEP 8 gives it (`keyword.iskeyword`, nelly's 3.14.7 list).
fn leaf(name: &Value) -> Result<String, GenerateError> {
    let name = str_receiver(name, "rsplit")?;
    let part = name.rsplit_once('.').map_or(name, |(_, last)| last);
    Ok(if is_keyword(part) {
        format!("{part}_")
    } else {
        part.to_owned()
    })
}

/// `method_name or leaf(row['name'])`.
fn method_or_leaf(row: &Dict, method_name: Option<&str>) -> Result<String, GenerateError> {
    match method_name {
        Some(name) if !name.is_empty() => Ok(name.to_owned()),
        _ => leaf(item(row, "name")?),
    }
}

/// `row['name'].replace('.', '_')`.
fn native_method(row: &Dict) -> Result<String, GenerateError> {
    Ok(str_receiver(item(row, "name")?, "replace")?.replace('.', "_"))
}

/// `INVENTORY.py_type(text)` (the default prefix `Facade.`).
fn py_type(generator: &mut Generator, text: &str) -> Result<String, GenerateError> {
    generator.inventory_mut()?.py_type(text, "Facade.")
}

/// Port of generate.py:690-715 (python_facade): a typed binding's verb, as a method of the runtime mixin or as its
/// stub.
fn python_facade(
    generator: &mut Generator,
    row: &Dict,
    stub: bool,
    method_name: Option<&str>,
) -> Result<String, GenerateError> {
    let binding = item(row, "binding")?;
    if binding.dict_get("request")?.is_some_and(Value::truthy) {
        if stub {
            let name = method_or_leaf(row, method_name)?;
            let input = py_type(generator, row_type(row, "input")?)?;
            let output = py_type(generator, row_type(row, "output")?)?;
            let signature = format!("    def {name}(self, input: {input}) -> {output}:");
            let doc = py_doc(row);
            return Ok(if doc.is_empty() {
                format!("{signature} ...\n")
            } else {
                format!("{signature}\n{doc}")
            });
        }
        let name = method_or_leaf(row, method_name)?;
        let signature = format!("    def {name}(self, input: dict[str, Any]) -> Any:");
        let method = native_method(row)?;
        return Ok(format!(
            "{signature}\n{}        return json.loads(_translate(lambda: self._client.{method}(json.dumps(input, allow_nan=False))))\n",
            py_doc(row)
        ));
    }
    let args = binding.getitem("args")?;
    let arg_list = args.iterate()?;
    let mut declaration = vec!["self".to_owned()];
    let mut values = Vec::new();
    for (n, a) in arg_list.iter().enumerate() {
        let kind = a.getitem("kind")?;
        let info = argument_kind(kind)?;
        let name = a.getitem("name")?;
        if n == 1 && binding.dict_get("options")?.is_some_and(Value::truthy) {
            declaration.push("*".to_owned());
        }
        // `info.get('stub' if stub else 'py')`: every kind but `json` has both, and `json` takes the branch above.
        let typ: Option<String> = if stub && kind.is_str("json") {
            Some(boundary_type(
                generator,
                str_receiver(item(row, "input")?, "startswith")?,
                "py_stub",
                false,
            )?)
        } else {
            match info.get(if stub { "stub" } else { "py" }) {
                Some(ArgumentValue::Text(text)) => Some(text.to_owned()),
                _ => None,
            }
        };
        let default = if a.contains_str("default")? {
            Some(a.getitem("default")?.repr())
        } else if info.text("native_py")?.starts_with("Option<") {
            Some("None".to_owned())
        } else {
            None
        };
        // `name + ': ' + typ + (...)`: the name, then the type, must be strings.
        let left = concat_left(name)?;
        let typ = typ.ok_or_else(|| {
            GenerateError::type_error(r#"can only concatenate str (not "NoneType") to str"#)
        })?;
        let tail = default
            .as_ref()
            .map_or_else(String::new, |default| format!(" = {default}"));
        declaration.push(format!("{left}: {typ}{tail}"));
        let json = info.flag("json");
        let mut value = if json {
            let allow = if binding
                .dict_get("wire")?
                .is_some_and(|wire| wire.is_str("json"))
            {
                ", allow_nan=False"
            } else {
                ""
            };
            format!("json.dumps({left}{allow})")
        } else {
            left.to_owned()
        };
        if json && default.as_deref() == Some("None") {
            value += &format!(" if {left} is not None else None");
        }
        values.push(value);
    }
    if binding
        .dict_get("native")?
        .is_some_and(|native| native.is_str("agent_verb"))
    {
        let mut fields = Vec::new();
        for a in &arg_list {
            let name = a.getitem("name")?;
            fields.push(format!("{}: {}", json(name), concat(name)?));
        }
        values = vec![format!("json.dumps({{{}}})", fields.join(", "))];
    }
    let output = boundary_type(
        generator,
        str_receiver(item(row, "output")?, "startswith")?,
        if stub { "py_stub" } else { "py" },
        false,
    )?;
    let name = method_or_leaf(row, method_name)?;
    let signature = format!("    def {name}({}) -> {output}:", declaration.join(", "));
    if stub {
        return Ok(format!("{signature} ...\n"));
    }
    let docs = concat(binding.getitem("docs")?.getitem("py")?)?;
    let method = native_method(row)?;
    Ok(format!(
        "{signature}\n        \"\"\"{docs}\"\"\"\n        return json.loads(_translate(lambda: self._client.{method}({})))\n",
        values.join(", ")
    ))
}

/// The three texts of a generic-door verb's Python parameters: the runtime's, the stub's, and the input they send.
struct HandleShape {
    params: String,
    typed: String,
    value: String,
}

/// Port of generate.py:614-628 (py_handle_shape): a generic-door verb's Python parameters, those parameters as the
/// stub types them, and the input they send.
fn py_handle_shape(generator: &mut Generator, row: &Dict) -> Result<HandleShape, GenerateError> {
    let Some(handle_args) = row.get("handle_args") else {
        let empty = item(row, "input")?.is_str("EmptyRequest");
        let typ = py_type(generator, row_type(row, "input")?)?;
        return Ok(if empty {
            HandleShape {
                params: "spec=None".to_owned(),
                typed: format!("spec: {typ} | None = None"),
                value: "{} if spec is None else spec".to_owned(),
            }
        } else {
            HandleShape {
                params: "spec".to_owned(),
                typed: format!("spec: {typ}"),
                value: "spec".to_owned(),
            }
        });
    };
    let mut params = Vec::new();
    let mut typed = Vec::new();
    let mut fields = Vec::new();
    for a in handle_args.iterate()? {
        let name = a.getitem("name")?.clone();
        // `a.get('field', a['name'])` evaluates its default first.
        let field = a.dict_get("field")?.unwrap_or(&name).clone();
        let kind = a.getitem("type")?;
        let default = if a.contains_str("default")? {
            Some(json(a.getitem("default")?))
        } else if str_receiver(kind, "startswith")?.starts_with("Option<") {
            Some("None".to_owned())
        } else {
            None
        };
        let left = concat_left(&name)?;
        params.push(match &default {
            Some(default) => format!("{left}={default}"),
            None => left.to_owned(),
        });
        let typ = py_type(generator, type_text(kind)?)?;
        typed.push(match &default {
            Some(default) => format!("{left}: {typ} = {default}"),
            None => format!("{left}: {typ}"),
        });
        if field.is_str("$") {
            return Ok(HandleShape {
                params: params.join(", "),
                typed: typed.join(", "),
                value: left.to_owned(),
            });
        }
        fields.push(format!("{}: {left}", json(&field)));
    }
    Ok(HandleShape {
        params: params.join(", "),
        typed: typed.join(", "),
        value: format!("{{{}}}", fields.join(", ")),
    })
}

/// generate.py:731: the second `ask` overload's `spec_or_who` type.
const ASK_WHO: &str = "str | list[str] | set[str] | tuple[str, ...] | dict[str, Any] | None";

/// Port of generate.py:722-742 (python_handle_verb): a facade verb on the generic door, as a method of its namespace.
fn python_handle_verb(
    generator: &mut Generator,
    row: &Dict,
    stub: bool,
    name: Option<&str>,
) -> Result<String, GenerateError> {
    let name = method_or_leaf(row, name)?;
    let method = native_method(row)?;
    let output = py_type(generator, row_type(row, "output")?)?;
    if item(row, "name")?.is_str("ask") {
        if stub {
            let input = py_type(generator, row_type(row, "input")?)?;
            return Ok(format!(
                "    @overload\n    def {name}(self, spec_or_who: {input}) -> {output}: ...\n    @overload\n    def {name}(self, spec_or_who: {ASK_WHO}, what: dict[str, Any], until: int | None = None, default: str = \"ask_me\") -> {output}: ...\n"
            ));
        }
        return Ok(format!(
            "    def {name}(self, spec_or_who, what=None, until=None, default=\"ask_me\"):\n{}        if what is None:\n            input = spec_or_who\n        else:\n            who = {{\"people\": [spec_or_who]}} if isinstance(spec_or_who, str) else {{\"people\": list(spec_or_who)}} if isinstance(spec_or_who, (set, list, tuple)) else spec_or_who\n            input = {{\"who\": who, \"what\": what, \"until\": until, \"default\": default}}\n        return json.loads(_translate(lambda: self._client.{method}(json.dumps(input))))\n",
            py_doc(row)
        ));
    }
    let shape = py_handle_shape(generator, row)?;
    if stub {
        let typed = if shape.typed.is_empty() {
            String::new()
        } else {
            format!(", {}", shape.typed)
        };
        let doc = py_doc(row);
        let tail = if doc.is_empty() {
            " ...\n".to_owned()
        } else {
            format!("\n{doc}")
        };
        return Ok(format!("    def {name}(self{typed}) -> {output}:{tail}"));
    }
    let params = if shape.params.is_empty() {
        String::new()
    } else {
        format!(", {}", shape.params)
    };
    Ok(format!(
        "    def {name}(self{params}):\n{}        return json.loads(_translate(lambda: self._client.{method}(json.dumps({}))))\n",
        py_doc(row),
        shape.value
    ))
}

/// Port of generate.py:744-745 (python_verb): the typed binding's method, or the generic door's.
fn python_verb(
    generator: &mut Generator,
    id: RowId,
    stub: bool,
    name: Option<&str>,
) -> Result<String, GenerateError> {
    let row = row_of(generator, id);
    if row.contains_key("binding") {
        python_facade(generator, &row, stub, name)
    } else {
        python_handle_verb(generator, &row, stub, name)
    }
}

/// Port of generate.py:747-748 (python_namespace_class): `_` + each `_`-separated part `str.title()`d + `Verbs`.
fn python_namespace_class(path: &[String]) -> String {
    let joined = path.join("_");
    let parts: String = joined.split('_').map(title).collect();
    format!("_{parts}Verbs")
}

/// A node whose segment is a namespace class rather than a plain method (generate.py:761): it holds verbs, or names
/// none itself.
fn is_namespace(node: &VerbNode) -> bool {
    !node.children.is_empty() || node.row.is_none()
}

/// `path + [name]`.
fn extend(path: &[String], name: &str) -> Vec<String> {
    let mut longer = path.to_vec();
    longer.push(name.to_owned());
    longer
}

/// The walk of `python_class_verbs`: its `stub` flag and `owner`, and the `classes` text its `namespace` closure
/// appends to (Python's `nonlocal classes`).
struct ClassWalk<'o> {
    stub: bool,
    owner: &'o str,
    classes: String,
}

impl ClassWalk<'_> {
    /// generate.py:753-756 (python_class_verbs.accessor): the property that makes a namespace's class.
    fn accessor(&self, name: &str, path: &[String]) -> String {
        let cls = python_namespace_class(path);
        let owner = self.owner;
        let body = if self.stub {
            " ...".to_owned()
        } else {
            format!("\n        return {owner}.{cls}(self._client)")
        };
        format!("    @property\n    def {name}(self) -> \"{owner}.{cls}\":{body}\n")
    }

    /// generate.py:757-765 (python_class_verbs.namespace): one namespace's class, then its nested ones. Python's
    /// `(name, child) in nested` holds exactly for the children `nested` was built from (names are unique keys).
    fn namespace(
        &mut self,
        generator: &mut Generator,
        path: &[String],
        node: &VerbNode,
    ) -> Result<(), GenerateError> {
        let mut body = if self.stub {
            String::new()
        } else {
            "    def __init__(self, client: _NativeClient) -> None:\n        self._client = client\n"
                .to_owned()
        };
        if let Some(id) = node.row {
            body += &python_verb(generator, id, self.stub, Some("__call__"))?;
        }
        for (name, child) in &node.children {
            if is_namespace(child) {
                body += &self.accessor(name, &extend(path, name));
            } else if let Some(id) = child.row {
                body += &python_verb(generator, id, self.stub, None)?;
            }
        }
        if body.is_empty() {
            body = "    ...\n".to_owned();
        }
        self.classes += &format!("class {}:\n{body}", python_namespace_class(path));
        for (name, child) in &node.children {
            if is_namespace(child) {
                self.namespace(generator, &extend(path, name), child)?;
            }
        }
        Ok(())
    }
}

/// Port of generate.py:750-770 (python_class_verbs): the facade class body: a bare verb is a method, a namespace a
/// property whose class nests in it, under `owner`.
fn python_class_verbs(
    generator: &mut Generator,
    tree: &VerbTree,
    stub: bool,
    owner: &str,
) -> Result<String, GenerateError> {
    let mut walk = ClassWalk {
        stub,
        owner,
        classes: String::new(),
    };
    let mut members = String::new();
    for (name, node) in tree {
        match node.row {
            Some(id) if node.children.is_empty() => {
                members += &python_verb(generator, id, stub, None)?;
            }
            _ => {
                let path = vec![name.clone()];
                members += &walk.accessor(name, &path);
                walk.namespace(generator, &path, node)?;
            }
        }
    }
    for line in splitlines(&walk.classes) {
        if line.is_empty() {
            members.push('\n');
        } else {
            members += &format!("    {line}\n");
        }
    }
    Ok(members)
}

/// Port of generate.py:832-843 (python_facade_module): the facade verbs as the mixin `_FacadeVerbs` that `Oneiron`
/// derives from (`stub`: its `.pyi`).
pub(crate) fn python_facade_module(
    generator: &mut Generator,
    tree: &VerbTree,
    stub: bool,
) -> Result<String, GenerateError> {
    let body = python_class_verbs(generator, tree, stub, "_FacadeVerbs")?;
    let mut out = HEADER.replace("//", "#");
    out += "\"\"\"The facade verbs of ``Oneiron`` (untangle slice 4.3), as the mixin it derives from.\"\"\"\n\n";
    out += "from __future__ import annotations\n\n";
    if stub {
        let used = capitalized_words(&body);
        let declared = hand_declared(generator, "py")?;
        // `sorted(used & declared)`: `used` is a sorted set.
        let names: Vec<&str> = used
            .iter()
            .filter(|name| declared.contains(name.as_str()))
            .map(String::as_str)
            .collect();
        out += "from typing import Any, overload\n\nfrom . import facade_types as Facade\n";
        if !names.is_empty() {
            out += &format!("from . import {}\n", names.join(", "));
        }
    } else {
        out += "import json\nfrom typing import Any\n\n# Defined in the package before it imports this module.\nfrom . import _NativeClient, _translate\n";
    }
    out += "\n\nclass _FacadeVerbs:\n";
    out += &body;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // python3 -c "import keyword; print([(n.rsplit('.', 1)[-1] + ('_' if keyword.iskeyword(n.rsplit('.', 1)[-1]) else '')) for n in N])"
    #[test]
    fn leaf_is_the_last_segment_with_a_keyword_underscore() {
        let cases = [
            ("vault.recall", "recall"),
            ("tasks.continue", "continue_"),
            ("a.b.class", "class_"),
            ("match", "match"),
            ("x.None", "None_"),
            ("plain", "plain"),
            ("a.", ""),
        ];
        for (name, expected) in cases {
            assert_eq!(
                leaf(&Value::Str(name.to_owned())),
                Ok(expected.to_owned()),
                "{name:?}"
            );
        }
        assert_eq!(
            leaf(&Value::Int(1)).map_err(|error| error.to_string()),
            Err("AttributeError: 'int' object has no attribute 'rsplit'".to_owned())
        );
    }

    // python3 -c "print('_' + ''.join(p.title() for p in '_'.join(P).split('_')) + 'Verbs')"
    #[test]
    fn namespace_classes_title_each_part() {
        let class = |path: &[&str]| {
            python_namespace_class(
                &path
                    .iter()
                    .map(|part| (*part).to_owned())
                    .collect::<Vec<_>>(),
            )
        };
        assert_eq!(class(&["vault"]), "_VaultVerbs");
        assert_eq!(class(&["vault", "claims"]), "_VaultClaimsVerbs");
        assert_eq!(class(&["self", "check_in"]), "_SelfCheckInVerbs");
        assert_eq!(class(&["v2beta", "html5"]), "_V2BetaHtml5Verbs");
    }
}
