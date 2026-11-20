//! What `contract.describe` answers from: the op table's discovery rows, the
//! JSON schemas of a call and a reply, and the description built from them.

use super::{
    CONTRACT_SCHEMA, Call, ContractError, DOCX_MEDIA_TYPE, Description, InputInfo, JSON_MEDIA_TYPE,
    OpInfo, OutputSpec, PPTX_MEDIA_TYPE, Reply, XLSX_MEDIA_TYPE,
};
use schemars::JsonSchema;
use serde_json::Value;

/// One op's discovery row: wire name, summary, inputs and outputs.
struct OpSpec {
    name: &'static str,
    summary: &'static str,
    inputs: &'static [(&'static str, &'static [&'static str], bool)],
    outputs: &'static [(&'static str, &'static str)],
    port: Option<&'static str>,
}

const DOCX: &[&str] = &[DOCX_MEDIA_TYPE];
const XLSX: &[&str] = &[XLSX_MEDIA_TYPE];
const PPTX: &[&str] = &[PPTX_MEDIA_TYPE];
const IMAGES: &[&str] = &["image/png", "image/jpeg", "image/svg+xml"];
const FONTS: &[&str] = &["font/ttf", "font/otf", "font/sfnt"];

const OPS: &[OpSpec] = &[
    OpSpec {
        name: "contract.describe",
        summary: "The op table, its media types and the call, reply and error schemas.",
        inputs: &[],
        outputs: &[],
        port: None,
    },
    OpSpec {
        name: "docx.read",
        summary: "The DOCX body blocks and scoped header, footer, footnote, endnote and comment stories.",
        inputs: &[("document", DOCX, false)],
        outputs: &[],
        port: None,
    },
    OpSpec {
        name: "docx.revise",
        summary: "Apply one tracked revision transaction as Word's own revision marks.",
        inputs: &[("document", DOCX, false)],
        outputs: &[("document", DOCX_MEDIA_TYPE)],
        port: None,
    },
    OpSpec {
        name: "docx.validate",
        summary: "Run the blocking OOXML linker, and check a transaction's grammar when given.",
        inputs: &[("document", DOCX, false)],
        outputs: &[],
        port: None,
    },
    OpSpec {
        name: "docx.project",
        summary: "Write block changes onto the DOCX they were read from, as one tracked revision.",
        inputs: &[("source", DOCX, false)],
        outputs: &[("document", DOCX_MEDIA_TYPE)],
        port: None,
    },
    OpSpec {
        name: "xlsx.read",
        summary: "Every worksheet's cells, the defined names and the cell formats.",
        inputs: &[("workbook", XLSX, false)],
        outputs: &[],
        port: None,
    },
    OpSpec {
        name: "xlsx.project",
        summary: "Write cell and defined-name changes; formulas land without cached values. The reply names what the projection adapted.",
        inputs: &[("source", XLSX, false)],
        outputs: &[("workbook", XLSX_MEDIA_TYPE)],
        port: None,
    },
    OpSpec {
        name: "xlsx.mark_full_calc",
        summary: "Have the opening application recalculate the whole workbook.",
        inputs: &[("workbook", XLSX, false)],
        outputs: &[("workbook", XLSX_MEDIA_TYPE)],
        port: None,
    },
    OpSpec {
        name: "xlsx.recalc",
        summary: "Recalculate formula caches natively at the caller's clock and location.",
        inputs: &[("workbook", XLSX, false)],
        outputs: &[("workbook", XLSX_MEDIA_TYPE)],
        port: Some("recalc"),
    },
    OpSpec {
        name: "deck.read",
        summary: "The slides and shapes a deck transaction targets, with fingerprints and marks.",
        inputs: &[("deck", PPTX, false)],
        outputs: &[],
        port: None,
    },
    OpSpec {
        name: "deck.transaction",
        summary: "Run one checked deck transaction; the candidate is re-opened and diffed.",
        inputs: &[("deck", PPTX, false), ("assets[].input", IMAGES, true)],
        outputs: &[("deck", PPTX_MEDIA_TYPE)],
        port: None,
    },
    OpSpec {
        name: "deck.create",
        summary: "Plan and emit a new deck from a kept brief over a template, or ask per page.",
        inputs: &[
            ("brief.input", &[JSON_MEDIA_TYPE], false),
            ("template", PPTX, false),
            ("fonts", FONTS, true),
            ("assets.*.input", IMAGES, true),
        ],
        outputs: &[("deck", PPTX_MEDIA_TYPE)],
        port: None,
    },
    OpSpec {
        name: "pptx.comments",
        summary: "Add, reply to and resolve modern comment threads; only comment parts change.",
        inputs: &[("deck", PPTX, false)],
        outputs: &[("deck", PPTX_MEDIA_TYPE)],
        port: None,
    },
    OpSpec {
        name: "pptx.comments.inspect",
        summary: "The slide and shape identities comments anchor to, and unanchored threads.",
        inputs: &[("deck", PPTX, false)],
        outputs: &[],
        port: None,
    },
];

fn owned(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

fn schema_value<T: JsonSchema>() -> Value {
    serde_json::to_value(schemars::schema_for!(T)).expect("a JSON schema always serializes")
}

/// The JSON schema of a [`Call`].
#[must_use]
pub fn call_schema() -> Value {
    schema_value::<Call>()
}

/// The JSON schema of a [`Reply`].
#[must_use]
pub fn reply_schema() -> Value {
    schema_value::<Reply>()
}

/// The schema-5 op table, as `contract.describe` answers it.
#[must_use]
pub fn describe() -> Description {
    Description {
        schema: CONTRACT_SCHEMA,
        ops: OPS
            .iter()
            .map(|spec| OpInfo {
                name: spec.name.to_owned(),
                summary: spec.summary.to_owned(),
                inputs: spec
                    .inputs
                    .iter()
                    .map(|(field, media_types, repeated)| InputInfo {
                        field: (*field).to_owned(),
                        media_types: owned(media_types),
                        repeated: *repeated,
                    })
                    .collect(),
                outputs: spec
                    .outputs
                    .iter()
                    .map(|(name, media_type)| OutputSpec {
                        name: (*name).to_owned(),
                        media_type: (*media_type).to_owned(),
                    })
                    .collect(),
                port: spec.port.map(str::to_owned),
            })
            .collect(),
        call_schema: call_schema(),
        reply_schema: reply_schema(),
        error_schema: schema_value::<ContractError>(),
    }
}
