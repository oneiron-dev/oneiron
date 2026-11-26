//! The stable reason codes of a `tool_args_invalid` refusal (FIX
//! CODE-MODE-DENIAL-REASONS): what was wrong with a tool's arguments, then
//! the field it names when it names one. A run's denied verb call and an MCP
//! tool error both carry them, so a caller learns what to change without
//! the refusal echoing its arguments.

use super::McpGatewayError;

/// What a decode error was, as serde words the errors its `de::Error`
/// provides, keyed by the words each message starts with.
const DECODE_KINDS: [(&str, &str); 7] = [
    ("missing field `", "args.missing_field"),
    ("unknown field `", "args.unknown_field"),
    ("duplicate field `", "args.duplicate_field"),
    ("unknown variant `", "args.unknown_variant"),
    ("invalid type: ", "args.wrong_type"),
    ("invalid value: ", "args.invalid_value"),
    ("invalid length ", "args.invalid_length"),
];

/// The code of a decode error serde did not word as one of its own.
const UNDECODABLE: &str = "args.undecodable";

/// What a tool's own field check refused, keyed by its message
/// (`McpVerbArguments::validate`); any other message is an invalid field.
const FIELD_CHECK_KINDS: [(&str, &str); 2] = [
    ("is required", "args.missing_field"),
    ("is not valid for this verb", "args.unknown_field"),
];

/// The code of a field a tool's own check refused for any other reason.
const INVALID_FIELD: &str = "args.invalid_field";

/// The prefix of the code that names the field a refusal is about.
const FIELD_PREFIX: &str = "args.field.";

/// The longest field name a code names.
const FIELD_NAME_MAX: usize = 64;

/// The reason codes of one decode error's message: its kind, then, for a
/// missing field, the field the input's type declares. An unknown or a
/// duplicate field's name, a variant, a type or a value serde quotes is the
/// caller's own text and never becomes a code.
pub(super) fn decode_reason_codes(message: &str) -> Vec<String> {
    let Some((lead, kind)) = DECODE_KINDS
        .iter()
        .find(|(lead, _)| message.starts_with(lead))
    else {
        return vec![UNDECODABLE.to_owned()];
    };
    // Only a missing field's name is the schema's own; an unknown or a
    // duplicate one is the caller's key, which no code repeats.
    let field = (*kind == "args.missing_field")
        .then(|| message[lead.len()..].split('`').next())
        .flatten();
    field_reason_codes(kind, field)
}

/// `kind`, then the code naming `field` when it is a plain name: ASCII
/// letters, digits and `_`, `.` between the parts of a path, and `[n]` for
/// an array item (`items[0].text`).
pub(super) fn field_reason_codes(kind: &str, field: Option<&str>) -> Vec<String> {
    let mut codes = vec![kind.to_owned()];
    if let Some(field) = field.filter(|field| plain_field_name(field)) {
        codes.push(format!("{FIELD_PREFIX}{field}"));
    }
    codes
}

fn plain_field_name(field: &str) -> bool {
    !field.is_empty()
        && field.len() <= FIELD_NAME_MAX
        && field.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'[' | b']'))
        })
}

impl McpGatewayError {
    /// A verb's typed input serde could not decode. The message stays the
    /// fixed one: serde's words can quote an argument's value.
    pub(super) fn typed_input_refused(error: &serde_json::Error) -> Self {
        let mut refused = Self::new(
            -32602,
            "tool_args_invalid",
            "invalid typed agent-verb argument",
        );
        refused.reason_codes = decode_reason_codes(&error.to_string());
        refused
    }

    /// A verb's input names a field its schema does not declare.
    pub(super) fn unknown_input_field(tool: &str, field: &str) -> Self {
        let mut refused = Self::new(
            -32602,
            "tool_args_invalid",
            format!("{tool} input names unknown field `{field}`"),
        );
        // The field is the caller's own key: the message names it, under the
        // message's release rules, and no code repeats it.
        refused.reason_codes = field_reason_codes("args.unknown_field", None);
        refused
    }

    /// A tool argument the verb's input needs is absent (`field` is the
    /// tool's own argument name).
    pub(super) fn missing_argument(field: &str) -> Self {
        Self::typed_argument_refused("args.missing_field", field)
    }

    /// A tool argument is not the shape the verb's input needs.
    pub(super) fn wrong_argument_type(field: &str) -> Self {
        Self::typed_argument_refused("args.wrong_type", field)
    }

    /// An envelope argument names another value than the input names for it.
    pub(super) fn mismatched_argument(field: &str) -> Self {
        Self::typed_argument_refused("args.field_mismatch", field)
    }

    fn typed_argument_refused(kind: &str, field: &str) -> Self {
        let mut refused = Self::new(
            -32602,
            "tool_args_invalid",
            "invalid typed agent-verb argument",
        );
        refused.reason_codes = field_reason_codes(kind, Some(field));
        refused
    }

    /// A field a tool's own check refused, with the words it refused it in.
    pub(super) fn with_field_check_reason(mut self, field: &str, message: &str) -> Self {
        let kind = FIELD_CHECK_KINDS
            .iter()
            .find(|(words, _)| message == *words)
            .map_or(INVALID_FIELD, |(_, kind)| kind);
        self.reason_codes = field_reason_codes(kind, Some(field));
        self
    }

    /// A field whose value the call does not take, by `field`, the path the
    /// call's own schema gives it; the value never becomes a code.
    pub(super) fn with_invalid_field_reason(mut self, field: &str) -> Self {
        self.reason_codes = field_reason_codes(INVALID_FIELD, Some(field));
        self
    }

    /// The reason codes of a tool's undecodable arguments.
    pub(super) fn with_decode_reason(mut self, message: &str) -> Self {
        self.reason_codes = decode_reason_codes(message);
        self
    }
}
