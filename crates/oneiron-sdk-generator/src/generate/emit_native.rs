//! Port of generate.py: the native bindings (G4a): the napi `agent_verbs.rs` and the PyO3 `#[pymethods]` file, built
//! by one loop of `outputs()` (the `napi_py` segment, generate.py:2452-2459) over `native_boundary`
//! (generate.py:485-539).

use super::common::{
    ArgumentKind, LONG_SIGNATURE, argument_kind, boundary_type, container_type, long_signature,
    native_binding, result_codec, str_format,
};
use super::row_access::{ByName, add_str, json, method_name, shown, text};
use super::{Generator, HEADER, RowId};
use crate::error::GenerateError;
use crate::py::value::{Dict, Value};

/// Port of generate.py:485-491 (napi_result): the napi conversion of an engine result, recursive over `Vec`.
pub(crate) fn napi_result(value: &str, expression: &str) -> Result<String, GenerateError> {
    let (container, inner) = container_type(value);
    if container == Some("Vec") {
        return Ok(format!(
            "{expression}.into_iter().map(|item| {{ {} }}).collect()",
            napi_result(inner, "item")?
        ));
    }
    let codec = result_codec(inner)?;
    let call = format!("{}({expression})", codec.convert);
    Ok(match codec.error {
        Some(error) => format!("{call}.map_err({error})"),
        None => format!("Ok({call})"),
    })
}

/// Port of generate.py:493-495 (native_args): the binding's `args`, or the one JSON `input` of the generic door.
pub(crate) fn native_args(row: &Dict) -> Result<Value, GenerateError> {
    match native_binding(row)? {
        Some(binding) if binding.truthy() => Ok(binding.getitem("args")?.clone()),
        _ => {
            let mut input = Dict::new();
            input.insert("name".to_owned(), Value::Str("input".to_owned()));
            input.insert("kind".to_owned(), Value::Str("json".to_owned()));
            Ok(Value::List(vec![Value::Dict(input)]))
        }
    }
}

/// One binding argument as `native_boundary` reads it: its parameter name, as `names` spells it, and its kind.
struct NativeArg {
    arg: Value,
    name: String,
    kind: &'static ArgumentKind,
}

/// Port of generate.py:496-539 (native_boundary): one facade row's method on the napi client (`language` `napi`) or
/// the PyO3 one (`py`).
pub(crate) fn native_boundary(
    generator: &mut Generator,
    id: RowId,
    language: &str,
) -> Result<String, GenerateError> {
    let row = &generator.rows[id];
    let method = method_name(row)?;
    let binding = native_binding(row)?.cloned();
    let args_value = native_args(row)?;
    let typed = match &binding {
        None => false,
        Some(binding) => !binding
            .dict_get("wire")?
            .is_some_and(|wire| wire.is_str("json")),
    };
    // `names = {a['name']: a['name'] + ('_json' if ... else '') for a in args}`
    let mut names: ByName<String> = ByName::default();
    for arg in args_value.iterate()? {
        let key = arg.getitem("name")?.clone();
        let base = arg.getitem("name")?;
        let json_kind = argument_kind(arg.getitem("kind")?)?.flag("json");
        let suffix = if json_kind && (language == "py" || !typed) {
            "_json"
        } else {
            ""
        };
        let spelled = format!("{}{suffix}", add_str(base)?);
        key.check_hashable("a dict key")?;
        // A key that is no `str` never got here: its `+ '_json'` failed first.
        names.insert(key.as_str().unwrap_or_default(), spelled);
    }
    let name_of = |arg: &Value| -> Result<String, GenerateError> {
        let name = arg.getitem("name")?;
        let name = name
            .as_str()
            .ok_or_else(|| GenerateError::exception("KeyError", name.repr()))?;
        names.get(name).cloned()
    };
    let mut args = Vec::new();
    for arg in args_value.iterate()? {
        let name = name_of(&arg)?;
        let kind = argument_kind(arg.getitem("kind")?)?;
        args.push(NativeArg { arg, name, kind });
    }
    let row_name = shown(row, "name")?;
    let head = if language == "napi" {
        if !binding.as_ref().is_some_and(Value::truthy) {
            // FIX 2884: a JS number reads as the typed decode behind it does (`js_json` in client.rs: safe whole
            // numbers back to integers).
            return Ok(format!(
                "#[napi] pub fn {method}(&self, input: serde_json::Value) -> napi::Result<serde_json::Value> {{ self.inner.agent_verb(\"{row_name}\", js_json(input)).map_err(facade_error) }}"
            ));
        }
        let mut declaration = Vec::new();
        for arg in &args {
            declaration.push(format!("{}: {}", arg.name, arg.kind.text("napi")?));
        }
        let declaration = declaration.join(", ");
        let output = if typed {
            let output = text(row, "output", "startswith")?.to_owned();
            boundary_type(generator, &output, "napi", false)?
        } else {
            "String".to_owned()
        };
        format!("#[napi] pub fn {method}(&self, {declaration}) -> napi::Result<{output}> {{")
    } else {
        let mut declaration = Vec::new();
        for arg in &args {
            declaration.push(format!("{}: {}", arg.name, arg.kind.text("native_py")?));
        }
        let declaration = declaration.join(", ");
        let mut signature = Vec::new();
        for arg in &args {
            let optional = if arg.kind.text("native_py")?.starts_with("Option<") {
                "=None"
            } else {
                ""
            };
            signature.push(format!("{}{optional}", arg.name));
        }
        let signature = signature.join(", ");
        let annotation = if signature.contains("=None") {
            format!("#[pyo3(signature = ({signature}))]")
        } else {
            String::new()
        };
        // Clippy caps a function at seven parameters: a long verb takes its receiver as a PyRef and its GIL token
        // from it.
        let count = args_value.py_len()?;
        let receiver = if count > 5 {
            "slf: PyRef<'_, Self>"
        } else {
            "&self, py: Python<'_>"
        };
        let params = count + if count > 5 { 1 } else { 2 };
        format!(
            "{annotation} {}fn {method}({receiver}, {declaration}) -> PyResult<String> {{",
            long_signature(params)
        )
    };
    let row = &generator.rows[id];
    let (mut setup, mut call);
    if typed {
        let mut lines = Vec::new();
        for arg in &args {
            let template = arg.kind.text_or(&format!("{language}_convert"), "");
            let default = json(arg.arg.dict_get("default")?.unwrap_or(&Value::None));
            lines.push(str_format(
                template,
                &[("name", &arg.name), ("default", &default)],
            )?);
        }
        setup = lines.join("\n");
        let arguments: Vec<String> = args
            .iter()
            .map(|arg| {
                format!(
                    "{}{}{}",
                    arg.kind.text_or("borrow", ""),
                    arg.name,
                    arg.kind.text_or("suffix", "")
                )
            })
            .collect();
        call = format!("self.inner.{method}({})", arguments.join(", "));
    } else {
        // `names[args[0]['name']]`
        let first = super::row_access::first(&args_value)?;
        let name = name_of(&first)?;
        setup = if language == "napi" {
            format!(
                "let input: serde_json::Value = serde_json::from_str(&{name}).map_err(|error| facade_error(oneiron::memory::MemoryError {{ code: oneiron::memory::MEMORY_CODE_BAD_REQUEST.to_owned(), message: format!(\"invalid keyed request: {{error}}\"), suggestions: vec![\"Use the documented keyed DTO.\".to_owned()], successor_short_id: None, gate_denial: None, read_receipt: None, policy_denial: None, wrong_root: None, hook: None, retry_after: None, resets_at: Vec::new(), reason_codes: Vec::new(), legal_hold: None, room_join_hold: None }}))?;"
            )
        } else {
            format!("let input: serde_json::Value = decode({name}, \"{row_name}\")?;")
        };
        call = format!("self.inner.agent_verb(\"{row_name}\", input)");
    }
    let body = if language == "napi" {
        let tail = if typed {
            napi_result(text(row, "output", "startswith")?, "output")?
        } else {
            "serde_json::to_string(&output).map_err(|error| boundary_error(error.to_string()))"
                .to_owned()
        };
        format!("{setup} let output = {call}.map_err(facade_error)?; {tail}")
    } else {
        let encode_output = if row
            .get("name")
            .is_some_and(|name| name.is_str("vault.recall"))
        {
            "encode_recall(&output)"
        } else {
            "encode(&output)"
        };
        if args_value.py_len()? > 5 {
            setup += " let inner = &slf.inner; let py = slf.py();";
            call = call.replacen("self.inner.", "inner.", 1);
        }
        format!("{setup} let output = py.detach(|| {call}).map_err(raise)?; {encode_output}")
    };
    Ok(head + &body + "}\n")
}

/// The `napi_py` segment's result: the napi file, and the PyO3 methods `outputs()` wraps into its own file
/// (generate.py:2531).
pub(crate) struct NativeTexts {
    pub(crate) napi: String,
    pub(crate) py: String,
}

/// Port of generate.py:2452-2459 (outputs: the `napi_py` segment): one loop over the facade rows feeds both native
/// bindings, the napi method of each row before its PyO3 one.
pub(crate) fn napi_py(
    generator: &mut Generator,
    facade_rows: &[RowId],
) -> Result<NativeTexts, GenerateError> {
    // `#[napi]` copies a method's attributes onto the glue it generates, where the lint never fires, so a long
    // verb's expectation sits on the module.
    let mut long_napi = false;
    for &id in facade_rows {
        if native_args(&generator.rows[id])?.py_len()? + 1 > 7 {
            long_napi = true;
            break;
        }
    }
    let mut napi = HEADER.to_owned() + "use super::*;\n";
    if long_napi {
        napi += &format!("#[{LONG_SIGNATURE}]\n");
    }
    napi += "#[napi]\nimpl NativeClient {\n";
    let mut py = String::new();
    for &id in facade_rows {
        method_name(&generator.rows[id])?;
        napi += &native_boundary(generator, id, "napi")?;
        py += &native_boundary(generator, id, "py")?;
    }
    napi += "}\n";
    Ok(NativeTexts { napi, py })
}
