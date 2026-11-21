//! One facade verb as a TypeScript member ([`ts_verb`]): a typed binding's verb (its native call, or the JSON-wire
//! call through `keyedJson` with the result read back) or a generic-door verb (its `handle_args`, or else its whole
//! input). No parameter or destructured field of a verb shadows a name its body reads ([`TS_BODY_READS`]).

use super::super::common::{
    argument_kind, boundary_type, container_type, js_binding_names, js_method, str_receiver,
};
use super::super::row_access::{concat, item, json};
use super::super::{Generator, RowId};
use super::{
    TsVerb, concat_left, contains, dict_items, option_inner, row_of, row_type, subscript, ts_doc,
    ts_input,
};
use crate::error::GenerateError;
use crate::facade_types::index_error;
use crate::py::value::{Dict, Value};

/// A JSON-wire binding's result as the native client returns it.
fn ts_wire_type(generator: &mut Generator, row: &Dict) -> Result<String, GenerateError> {
    let fields = item(row, "binding")?.dict_get("output_fields")?;
    if let Some(fields) = fields.filter(|fields| fields.truthy()) {
        let mut parts = Vec::new();
        for (name, kind) in dict_items(fields)? {
            let kind = str_receiver(kind, "startswith")?;
            parts.push(format!(
                "{name}: {}",
                boundary_type(generator, kind, "ts", true)?
            ));
        }
        return Ok(format!("{{{}}}", parts.join("; ")));
    }
    let output = str_receiver(item(row, "output")?, "startswith")?;
    boundary_type(generator, output, "ts", true)
}

/// The TypeScript expression that turns a wire value into its handle type (an `Option` is `null`-checked, a `Vec`
/// mapped, a `KeyValueItem` converted).
fn ts_from_wire(kind: &str, value: &str) -> String {
    let (container, inner) = container_type(kind);
    if container == Some("Option") {
        return format!("{value} === null ? null : {}", ts_from_wire(inner, value));
    }
    if container == Some("Vec") && inner != "String" {
        return format!("{value}.map(item => {})", ts_from_wire(inner, "item"));
    }
    if inner == "KeyValueItem" {
        format!("itemFromWire({value})")
    } else {
        value.to_owned()
    }
}

/// A typed binding's verb.
fn ts_facade(generator: &mut Generator, row: &Dict) -> Result<TsVerb, GenerateError> {
    let binding = item(row, "binding")?;
    let method = js_method(str_receiver(item(row, "name")?, "replace")?);
    if binding.dict_get("request")?.is_some_and(Value::truthy) {
        let output = generator
            .inventory_mut()?
            .ts_type(row_type(row, "output")?, "Facade.")?;
        let doc = Value::Str(ts_doc(row));
        let params = ts_input(generator, row)?;
        let body = format!("this.#client.{method}(input) as {output}");
        return Ok(TsVerb {
            doc,
            params,
            output,
            body,
        });
    }
    let args = binding.getitem("args")?;
    let output = boundary_type(
        generator,
        str_receiver(item(row, "output")?, "startswith")?,
        "ts",
        false,
    )?;
    let arg_list = args.iterate()?;
    let options = binding.dict_get("options")?.is_some_and(Value::truthy);
    let mut names = Vec::new();
    for a in &arg_list {
        names.push(js_method(str_receiver(a.getitem("name")?, "replace")?));
    }
    // The parameters bind the arguments' names; the body reads the names of [`TS_BODY_READS`], and with options
    // `opts` is a parameter too.
    let more: &[&str] = if options { &["opts"] } else { &[] };
    let bindings = js_binding_names(&names, &ts_fixed_names(more));
    let mut declaration: Vec<String> = Vec::new();
    for (a, name) in arg_list.iter().zip(&bindings) {
        let kind = a.getitem("kind")?;
        let optional = !kind.is_str("json")
            && argument_kind(kind)?
                .text("native_ts")?
                .ends_with(" | undefined")
            && !a.contains_str("default")?;
        let typ = if kind.is_str("json") {
            boundary_type(
                generator,
                str_receiver(item(row, "input")?, "startswith")?,
                "ts",
                false,
            )?
        } else {
            argument_kind(kind)?
                .text("native_ts")?
                .replace(" | undefined", "")
        };
        let default = if a.contains_str("default")? {
            format!(" = {}", json(a.getitem("default")?))
        } else {
            String::new()
        };
        let mark = if optional { "?" } else { "" };
        declaration.push(format!("{name}{mark}: {typ}{default}"));
    }
    let arguments: Vec<String> = if options {
        let first = declaration.first().cloned().ok_or_else(index_error)?;
        let options = concat(binding.getitem("options")?)?;
        declaration = vec![first, format!("opts: {options} = {{}}")];
        let mut arguments = vec![bindings.first().cloned().ok_or_else(index_error)?];
        for a in arg_list.iter().skip(1) {
            let name = js_method(str_receiver(a.getitem("name")?, "replace")?);
            let default = if a.contains_str("default")? {
                format!(" ?? {}", json(a.getitem("default")?))
            } else {
                String::new()
            };
            arguments.push(format!("opts.{name}{default}"));
        }
        arguments
    } else {
        bindings.clone()
    };
    let body = if binding
        .dict_get("native")?
        .is_some_and(|native| native.is_str("agent_verb"))
    {
        let mut fields = Vec::new();
        for (a, name) in arg_list.iter().zip(&bindings) {
            let left = concat_left(a.getitem("name")?)?;
            fields.push(format!("{left}: {name}"));
        }
        format!(
            "this.#client.{method}({{{}}}) as {output}",
            fields.join(", ")
        )
    } else if binding
        .dict_get("wire")?
        .is_some_and(|wire| wire.is_str("json"))
    {
        let request = bindings.first().ok_or_else(index_error)?;
        ts_wire_body(generator, row, binding, request, &method)?
    } else {
        format!("this.#client.{method}({})", arguments.join(", "))
    };
    let doc = binding.getitem("docs")?.getitem("ts")?.clone();
    Ok(TsVerb {
        doc,
        params: declaration.join(", "),
        output,
        body,
    })
}

/// The names a facade verb's body reads beside its own bindings: the handle `host` (a namespace member's), the two
/// symbols it reaches the native client through, the `key-value.js` helpers it calls and the `JSON` global. A
/// parameter or a destructured field of the same name would shadow it inside the verb, so each binding list of a
/// facade verb passes these to [`js_binding_names`] as fixed.
pub(super) const TS_BODY_READS: [&str; 6] = [
    "host",
    "facadeCall",
    "facadeClient",
    "JSON",
    "keyedJson",
    "itemFromWire",
];

/// [`TS_BODY_READS`] and `more`, the other names one binding list's scope binds or reads.
pub(super) fn ts_fixed_names<'a>(more: &[&'a str]) -> Vec<&'a str> {
    let mut names: Vec<&'a str> = TS_BODY_READS.to_vec();
    names.extend_from_slice(more);
    names
}

/// The fixed names of `ts_wire_body`'s destructure: the block binds `rest` and `result` and reads `request`, the
/// binding of the request parameter, beside the names of [`TS_BODY_READS`].
pub(super) fn wire_block_fixed(request: &str) -> Vec<&str> {
    ts_fixed_names(&["rest", "result", request])
}

/// `ts_wire_body`'s destructure: each input field's entry and the name it binds, in field order. A field binds its
/// own name unless [`js_binding_names`] renames it (a reserved word, or a name of `fixed`); then the entry renames it
/// (`default: default_`), since the name is still a valid key.
pub(super) fn destructure_entries(fields: &[String], fixed: &[&str]) -> Vec<(String, String)> {
    js_binding_names(fields, fixed)
        .into_iter()
        .zip(fields)
        .map(|(alias, field)| {
            let entry = if alias == *field {
                alias.clone()
            } else {
                format!("{field}: {alias}")
            };
            (entry, alias)
        })
        .collect()
}

/// `ts_facade`'s JSON-wire branch: the call through `keyedJson` and the result read back. `request` is the binding of
/// the request parameter.
fn ts_wire_body(
    generator: &mut Generator,
    row: &Dict,
    binding: &Value,
    request: &str,
    method: &str,
) -> Result<String, GenerateError> {
    let no_fields = Value::Dict(Dict::new());
    let fields = binding.dict_get("input_fields")?.unwrap_or(&no_fields);
    let mut request = request.to_owned();
    let mut setup = String::new();
    if fields.truthy() {
        let defaults = binding.dict_get("input_defaults")?.unwrap_or(&no_fields);
        let names = fields.iterate()?;
        let mut keys = Vec::new();
        for name in &names {
            keys.push(concat_left(name)?.to_owned());
        }
        let entries = destructure_entries(&keys, &wire_block_fixed(&request));
        let mut destructure = Vec::new();
        for (name, (entry, _)) in names.iter().zip(&entries) {
            // `name + (' = ' + json.dumps(defaults[name]) if name in defaults else '')`: the subscript with the field
            // as it is, then the concatenation.
            let default = if contains(defaults, name)? {
                format!(" = {}", json(&subscript(defaults, name)?))
            } else {
                String::new()
            };
            destructure.push(format!("{entry}{default}"));
        }
        setup = format!(
            "const {{ {}, ...rest }} = {request};",
            destructure.join(", ")
        );
        let mut renamed = Vec::new();
        for ((_, wire), (_, alias)) in dict_items(fields)?.iter().zip(&entries) {
            renamed.push(format!("{}: {alias}", concat_left(wire)?));
        }
        request = format!("{{ ...rest, {} }}", renamed.join(", "));
    }
    let call = format!(
        "JSON.parse(this.#client.{method}(keyedJson({request}))) as {}",
        ts_wire_type(generator, row)?
    );
    let result = match binding
        .dict_get("output_fields")?
        .filter(|fields| fields.truthy())
    {
        Some(fields) => {
            let mut parts = Vec::new();
            for (name, kind) in dict_items(fields)? {
                let kind = str_receiver(kind, "startswith")?;
                parts.push(format!(
                    "{}: {}",
                    js_method(name),
                    ts_from_wire(kind, &format!("result.{name}"))
                ));
            }
            format!("{{{}}}", parts.join(", "))
        }
        None => ts_from_wire(str_receiver(item(row, "output")?, "startswith")?, "result"),
    };
    Ok(format!(
        "{{ {setup} const result = {call}; return {result} }}"
    ))
}

/// A generic-door verb's TypeScript parameters and the input they send (its `handle_args`, or else its whole input).
fn ts_handle_shape(
    generator: &mut Generator,
    row: &Dict,
) -> Result<(String, String), GenerateError> {
    let Some(handle_args) = row.get("handle_args") else {
        return Ok((ts_input(generator, row)?, "input".to_owned()));
    };
    let handle_args = handle_args.iterate()?;
    let mut names = Vec::new();
    for a in &handle_args {
        names.push(js_method(str_receiver(a.getitem("name")?, "replace")?));
    }
    // The body reads the names of [`TS_BODY_READS`] beside the parameters.
    let bindings = js_binding_names(&names, &TS_BODY_READS);
    let mut params = Vec::new();
    let mut fields = Vec::new();
    for (a, name) in handle_args.iter().zip(bindings) {
        // `a.get('field', a['name'])` evaluates its default first.
        let own = a.getitem("name")?;
        let field = a.dict_get("field")?.unwrap_or(own).clone();
        let kind = a.getitem("type")?;
        if a.contains_str("default")? {
            params.push(format!("{name} = {}", json(a.getitem("default")?)));
        } else {
            let kind = str_receiver(kind, "startswith")?;
            if kind.starts_with("Option<") {
                let typ = boundary_type(generator, option_inner(kind), "ts", false)?;
                params.push(format!("{name}?: {typ}"));
            } else {
                let typ = boundary_type(generator, kind, "ts", false)?;
                params.push(format!("{name}: {typ}"));
            }
        }
        if field.is_str("$") {
            return Ok((params.join(", "), name));
        }
        fields.push(if field.is_str(&name) {
            name
        } else {
            format!("{}: {name}", field.str())
        });
    }
    Ok((params.join(", "), format!("{{{}}}", fields.join(", "))))
}

/// The `ask` verb's overloaded parameters.
const ASK_PARAMS: &str = "...args: [spec: TaskAskSpec] | [who: TaskAskWho | undefined, what: TaskAskQuestion, until?: number | null, defaultBranch?: TaskAskDefault]";

/// A facade verb on the generic door: its doc, parameters, result type and body.
fn ts_handle_verb(generator: &mut Generator, row: &Dict) -> Result<TsVerb, GenerateError> {
    let name = item(row, "name")?;
    let method = js_method(str_receiver(name, "replace")?);
    if name.is_str("ask") {
        let body = format!(
            "{{ const input: TaskAskSpec | TaskAskShort = args.length === 1 ? args[0] : {{who: typeof args[0] === \"string\" ? {{people: [args[0]]}} : Array.isArray(args[0]) ? {{people: args[0]}} : args[0], what: args[1], until: args[2], default: args[3]}}; return this.#client.{method}(input) as TaskAskReceipt }}"
        );
        return Ok(TsVerb {
            doc: Value::Str(ts_doc(row)),
            params: ASK_PARAMS.to_owned(),
            output: "TaskAskReceipt".to_owned(),
            body,
        });
    }
    let (params, value) = ts_handle_shape(generator, row)?;
    let output = generator
        .inventory_mut()?
        .ts_type(row_type(row, "output")?, "Facade.")?;
    let body = format!("this.#client.{method}({value}) as {output}");
    Ok(TsVerb {
        doc: Value::Str(ts_doc(row)),
        params,
        output,
        body,
    })
}

/// The typed binding's verb, or the generic door's.
pub(super) fn ts_verb(generator: &mut Generator, id: RowId) -> Result<TsVerb, GenerateError> {
    let row = row_of(generator, id);
    if row.contains_key("binding") {
        ts_facade(generator, &row)
    } else {
        ts_handle_verb(generator, &row)
    }
}
