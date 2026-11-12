//! Moved from `crates/oneiron/src/connector_key/slate.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// The four DEC-0006 capability settings. Declaration order is strictness,
/// so `Ord` reads "tighter": always allow < auto < always ask < never allow.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SlateDisposition {
    /// Bypasses the per-call ask inside the bound; never the catastrophe floor.
    AlwaysAllow,
    /// The default: the per-call verdict, learning through standing grants.
    Auto,
    /// Asks for every call, even one a standing grant covers.
    AlwaysAsk,
    /// Removes the tool from the connector's callable catalog.
    NeverAllow,
}

impl SlateDisposition {
    pub const ALL: [Self; 4] = [
        Self::AlwaysAllow,
        Self::Auto,
        Self::AlwaysAsk,
        Self::NeverAllow,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::AlwaysAllow => "always_allow",
            Self::Auto => "auto",
            Self::AlwaysAsk => "always_ask",
            Self::NeverAllow => "never_allow",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|setting| setting.as_str() == value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SlateDataClass {
    Public,
    Personal,
    Secret,
    Header,
}

impl SlateDataClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Personal => "personal",
            Self::Secret => "secret",
            Self::Header => "header",
        }
    }
}

/// The owner and holder edges' key for the elicitation row, beside tool
/// names. MCP tool names are `[A-Za-z0-9_.-]`, so no tool can take it, and
/// a slate refuses a tool that tries.
pub const ELICITATION_ROW_KEY: &str = "@elicitation";

/// A slate row's typed identity: one declared tool, or the one MCP client
/// capability ARCH-0072 gives a permission row. Elicitation is never a
/// callable tool; sampling, roots and logging are not rows (DEC-0006).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SlateCapability<'a> {
    Tool(&'a str),
    Elicitation,
}

impl<'a> SlateCapability<'a> {
    /// An edge row key: [`ELICITATION_ROW_KEY`] is the elicitation row, any
    /// other key names a tool.
    pub fn parse(key: &'a str) -> Self {
        if key == ELICITATION_ROW_KEY {
            Self::Elicitation
        } else {
            Self::Tool(key)
        }
    }

    /// The key the owner and holder edges name this row by.
    pub fn key(self) -> &'a str {
        match self {
            Self::Tool(name) => name,
            Self::Elicitation => ELICITATION_ROW_KEY,
        }
    }
}

/// The slate's one elicitation declaration (ARCH-0072: "one typed row per
/// declared capability, including elicitation"). Elicitation is an MCP
/// client capability, so no server lists it: MCP admission declares it for
/// every connector it admits, and the call host decides per revision
/// whether to declare it on the wire. A tool's legacy ask form folds into
/// this one declaration and never makes a second permission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SlateElicitationManifest {
    /// The tools whose legacy ask form this row also covers.
    pub legacy_ask_tools: BTreeSet<String>,
}

impl SlateElicitationManifest {
    /// The one declaration `tools` carry: admission's own when `declared`,
    /// with every tool's legacy ask folded in. None when neither asks.
    pub fn of(tools: &[SlateToolManifest], declared: bool) -> Option<Self> {
        let legacy_ask_tools: BTreeSet<String> = tools
            .iter()
            .filter(|tool| tool.legacy_ask)
            .map(|tool| tool.name.clone())
            .collect();
        (declared || !legacy_ask_tools.is_empty()).then_some(Self { legacy_ask_tools })
    }
}

/// Immutable pack identity included in the slate's manifest hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SlatePackSource {
    pub source_ref: String,
    pub content_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SlateManifest {
    /// Immutable pack identity, inside the manifest hash and owner stamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack_source: Option<SlatePackSource>,
    pub tools: Vec<SlateToolManifest>,
    pub elicitation: Option<SlateElicitationManifest>,
}

impl SlateManifest {
    /// `tools`, with the elicitation declaration admission makes when
    /// `declared` (every admitted MCP connector) and any legacy ask folded
    /// in.
    pub fn new(tools: Vec<SlateToolManifest>, declared: bool) -> Self {
        let elicitation = SlateElicitationManifest::of(&tools, declared);
        Self {
            tools,
            elicitation,
            pack_source: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SlateToolManifest {
    pub name: String,
    pub data_class: SlateDataClass,
    pub header_parameters: Vec<String>,
    /// Host-resolved input declaration, including defaults and constraints.
    /// Unresolved refs/composition are refused rather than guessed at admission.
    #[serde(default)]
    pub resolved_input_schema: Option<serde_json::Value>,
    #[serde(default)]
    pub trigger: Option<String>,
    pub destroys: bool,
    pub spends: bool,
    pub sends_outward: bool,
    /// The tool asks through the legacy form. That folds into the slate's
    /// one elicitation row; the tool's own row carries no ask permission.
    pub legacy_ask: bool,
    /// The connector's declared `readOnlyHint` and `idempotentHint`. A call
    /// to a read-only tool that destroys nothing, or to an idempotent one,
    /// retries after an ambiguous reply instead of abandoning the intent.
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub idempotent: bool,
    /// The price one call of this tool declares (FIX 8689): its connector's,
    /// or the owner's at registration where the connector declares none. A
    /// Spend row that preauthorizes reserves it before the call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price: Option<super::ConnectorSpendEstimate>,
}

impl SlateToolManifest {
    /// Irreversible or header-bearing: `auto` already asks per call for these.
    /// A legacy ask raises the elicitation row's floor, not the tool's.
    pub fn floor(&self) -> bool {
        self.destroys
            || self.spends
            || self.sends_outward
            || !self.header_parameters.is_empty()
            || self.data_class == SlateDataClass::Header
    }

    /// A parameter that reaches the wire as a header is its own data class.
    pub fn row_data_class(&self) -> SlateDataClass {
        if self.header_parameters.is_empty() {
            self.data_class
        } else {
            SlateDataClass::Header
        }
    }
}

/// The only model-output shape admitted. Owner overrides are deliberately not
/// fields of this type; serde rejects them rather than trusting a model stamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SlateDraftRow {
    /// The row's key: a tool name, or [`ELICITATION_ROW_KEY`].
    pub tool: String,
    pub disposition: SlateDisposition,
    pub data_class: SlateDataClass,
    pub rationale: String,
}

impl SlateDraftRow {
    /// The row's typed identity.
    pub fn capability(&self) -> SlateCapability<'_> {
        SlateCapability::parse(&self.tool)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SlateOwnerOverride {
    pub disposition: SlateDisposition,
}

/// An autonomous tightening by the key's holder. It needs no stamp and is
/// provenance-marked, so it never reads as an owner tap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SlateHolderNarrow {
    pub disposition: SlateDisposition,
    pub actor: String,
    pub at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SlateRow {
    /// The latest explicit owner act on this row, or its fresh draft identity.
    /// Unchanged rows carry it across slate revisions.
    pub settings_act: EntityId,
    pub draft: SlateDraftRow,
    pub owner_override: Option<SlateOwnerOverride>,
    pub holder_narrow: Option<SlateHolderNarrow>,
}

impl SlateRow {
    /// What the owner accepted: the override, else the stamped draft.
    pub fn stamped_disposition(&self) -> SlateDisposition {
        self.owner_override
            .as_ref()
            .map_or(self.draft.disposition, |o| o.disposition)
    }

    /// What a call meets: the stamped setting, tightened by any holder narrow.
    pub fn effective_disposition(&self) -> SlateDisposition {
        self.holder_narrow
            .as_ref()
            .map_or(self.stamped_disposition(), |narrow| {
                narrow.disposition.max(self.stamped_disposition())
            })
    }

    pub fn enabled(&self) -> bool {
        self.effective_disposition() != SlateDisposition::NeverAllow
    }
}
