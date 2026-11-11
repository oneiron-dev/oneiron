//! The remote client: `crates/oneiron-remote/src/generated/agent_verbs.rs`, the `remote` segment of `outputs()` and
//! `remote_boundary`.

use super::common::{argument_kind, long_signature, rust_type, str_format, str_receiver};
use super::row_access::{
    add_str, admission_text, concat, first, get_in, item, json, method_name, shown, text,
};
use super::{Generator, HEADER, RowId};
use crate::error::GenerateError;
use crate::py::re::{sub_input_word, sub_whole_input_borrow};
use crate::py::value::{Dict, Value};

/// What `remote_boundary` returns: the method's parameters, the statement that assembles its input, and the value
/// the typed call encodes.
pub(crate) struct RemoteBoundary {
    pub(crate) declaration: String,
    pub(crate) setup: String,
    pub(crate) value: Value,
}

/// `row.get('binding', {})`: the binding, `None` when the row has none (Python's `{}`).
fn binding(row: &Dict) -> Option<&Value> {
    row.get("binding")
}

/// One facade row's typed method on the remote client.
pub(crate) fn remote_boundary(row: &Dict) -> Result<RemoteBoundary, GenerateError> {
    let binding = binding(row);
    let args = match binding {
        None => None,
        Some(binding) => binding.dict_get("args")?,
    };
    let typed = match (binding, args) {
        (Some(binding), Some(args)) if args.truthy() => !binding
            .dict_get("wire")?
            .is_some_and(|wire| wire.is_str("json")),
        _ => false,
    };
    let (Some(binding), Some(args), true) = (binding, args, typed) else {
        return Ok(RemoteBoundary {
            declaration: format!("input: &{}", rust_type(item(row, "input")?)?),
            setup: String::new(),
            value: Value::Str("input".to_owned()),
        });
    };
    let args = args.iterate()?;
    let mut declaration = Vec::new();
    for arg in &args {
        let name = add_str(arg.getitem("name")?)?;
        declaration.push(format!(
            "{name}: {}",
            argument_kind(arg.getitem("kind")?)?.text("rust")?
        ));
    }
    let declaration = declaration.join(", ");
    if binding.dict_get("assemble")?.is_some_and(Value::truthy) {
        let mut values = Vec::new();
        for arg in &args {
            let name = arg.getitem("name")?;
            let template = argument_kind(arg.getitem("kind")?)?.text("field")?;
            values.push((
                name.clone(),
                str_format(template, &[("name", &name.str())])?,
            ));
        }
        let mut fields = Vec::new();
        for (name, value) in &values {
            if name.is_str(value) {
                fields.push(value.clone());
            } else {
                fields.push(format!("{}: {value}", add_str(name)?));
            }
        }
        let mut fields = fields.join(", ");
        if item(row, "name")?.is_str("describe")
            || binding.dict_get("defaults")?.is_some_and(Value::truthy)
        {
            fields += ", ..Default::default()";
        }
        let setup = format!(
            "let input = {} {{ {fields} }};",
            rust_type(item(row, "input")?)?
        );
        return Ok(RemoteBoundary {
            declaration,
            setup,
            value: Value::Str("&input".to_owned()),
        });
    }
    // `args[0]['name']` on the binding's `args` value itself.
    let first_arg = first(binding.dict_get("args")?.unwrap_or(&Value::None))?;
    Ok(RemoteBoundary {
        declaration,
        setup: String::new(),
        value: first_arg.getitem("name")?.clone(),
    })
}

/// The `remote` segment of `outputs()`: the remote client's `agent_verb` door and one typed method per facade row.
pub(crate) fn remote(
    generator: &Generator,
    facade_rows: &[RowId],
) -> Result<String, GenerateError> {
    let rows = generator.rows.select(facade_rows);
    let mut remote = HEADER.to_owned() + "use super::*;\n";
    remote += REMOTE_AGENT_VERB_OUTPUT;
    remote += "impl OneironClient {\n";
    remote += AGENT_VERB_HEAD;
    for row in &rows {
        let output = text(row, "output", "startswith")?;
        let output = if output.starts_with("Vec<") || output.starts_with("Option<") {
            output.replace("crate::", "oneiron::")
        } else {
            rust_type(item(row, "output")?)?
        };
        remote += &format!(
            "{} => remote_agent_verb_output::<{output}>(client, verb, &input),\n",
            json(item(row, "name")?)
        );
    }
    remote += AGENT_VERB_TAIL;
    remote += TYPED_AGENT_VERB;
    for row in &rows {
        let method = method_name(row)?;
        let out = text(row, "output", "replace")?.replace("crate::", "oneiron::");
        let boundary = remote_boundary(row)?;
        // The typed check runs before encoding: JSON has no NaN, so a non-finite float would reach validate_input
        // as null.
        let mut checks =
            admission_text(row, "validate", Some("replace"))?.replace("crate::", "oneiron::");
        let value_input = str_receiver(&boundary.value, "startswith")?;
        if !value_input.starts_with('&') {
            // Drop only the whole-request borrow; field borrows remain required.
            checks = sub_whole_input_borrow(&checks, value_input)?;
            checks = sub_input_word(&checks, value_input)?;
        }
        // `r.get('binding', {}).get('docs', {}).get('remote', '')`
        if let Some(docs) = get_in(row, "binding", "docs")?
            && let Some(doc) = docs.dict_get("remote")?
        {
            remote += concat(doc)?;
        }
        let params = 1 + match binding(row) {
            Some(binding)
                if binding.dict_get("args")?.is_some_and(Value::truthy)
                    && !item(row, "binding")?
                        .dict_get("wire")?
                        .is_some_and(|wire| wire.is_str("json")) =>
            {
                item(row, "binding")?.getitem("args")?.py_len()?
            }
            _ => 1,
        };
        remote += &long_signature(params);
        let declaration = &boundary.declaration;
        let input_value = &boundary.setup;
        let name = shown(row, "name")?;
        remote += &format!(
            "pub fn {method}(&self, {declaration}) -> Result<{out}, MemoryError> {{
            {input_value}{checks}
            let value = serde_json::to_value({value_input}).map_err(|_| crate::error::bad_request(\"SDK input encoding failed\", &[\"Send the documented typed SDK input.\"]))?;
            self.typed_agent_verb(\"{name}\", value)
        }}
"
        );
    }
    remote += "}\n";
    Ok(remote)
}

/// `remote_agent_verb_output`: one remote call, decoded as the verb's typed result and encoded back to JSON.
const REMOTE_AGENT_VERB_OUTPUT: &str =
    "fn remote_agent_verb_output<R: serde::de::DeserializeOwned + serde::Serialize>(
        client: &RemoteClient, verb: &str, input: &serde_json::Value,
    ) -> Result<serde_json::Value, MemoryError> {
        let output: R = client.call(verb, input)?;
        serde_json::to_value(output).map_err(|error| crate::error::transport_error(
            format!(\"the remote SDK could not encode {verb}'s decoded result: {error}\")
        ))
    }
";

/// The head of `agent_verb`: its facade and input checks and its backend match, up to the remote verb arms.
const AGENT_VERB_HEAD: &str = "pub fn agent_verb(&self, verb: &str, input: serde_json::Value) -> Result<serde_json::Value, MemoryError> {
        self.ensure_dispatch_pid()?;
        if !oneiron::task_verb::sdk::AgentVerb::from_name(verb).is_some_and(oneiron::task_verb::sdk::AgentVerb::is_facade) { return Err(oneiron::task_verb::sdk::wrong_root(verb).unwrap_or_else(|| crate::error::bad_request(\"unknown SDK agent verb\", &[\"Use a verb from the SDK catalog.\"]))); }
        oneiron::task_verb::sdk::validate_input(verb, &input)?;
        match &self.backend {
            Backend::Embedded(client) => client.invoke(verb, input),
            Backend::Remote(client) => match verb {
";

/// The end of `agent_verb`: the remote unknown-verb arm and the closing braces.
const AGENT_VERB_TAIL: &str = "_ => Err(crate::error::bad_request(\"unknown SDK agent verb\", &[\"Use a verb from the SDK catalog.\"])),
        },
    }
}
";

/// `typed_agent_verb`: one typed call over either backend.
const TYPED_AGENT_VERB: &str = "fn typed_agent_verb<R: serde::de::DeserializeOwned>(&self, verb: &str, input: serde_json::Value) -> Result<R, MemoryError> {
        match &self.backend {
            Backend::Remote(client) => {
                self.ensure_dispatch_pid()?;
                oneiron::task_verb::sdk::validate_input(verb, &input)?;
                client.call(verb, &input)
            }
            Backend::Embedded(_) => {
                let result = self.agent_verb(verb, input)?;
                serde_json::from_value(result).map_err(|error| crate::error::transport_error(
                    format!(\"the embedded SDK answered {verb} with a body this verb could not decode: {error}\")
                ))
            }
        }
    }
";
