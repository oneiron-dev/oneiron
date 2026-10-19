//! The closed outline wire grammar. Validation stays in docedit's Brief::parse.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeckOutline {
    pub communication: OutlineCommunication,
    pub language: String,
    #[serde(default)]
    pub accessibility: Vec<String>,
    pub pages: Vec<OutlinePage>,
    #[serde(default)]
    pub datasets: Vec<OutlineDataset>,
    #[serde(default)]
    pub assets: Vec<OutlineAsset>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OutlineCommunication {
    pub audience: String,
    pub outcome: String,
    pub main_message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OutlinePage {
    pub id: String,
    pub job: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub division: Option<OutlineDivision>,
    pub blocks: Vec<OutlineBlock>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OutlineDivision { Fixed, Split }

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OutlinePriority { Required, Optional }

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OutlineCarrier { Chart, Table, Share }

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OutlineBlock {
    Title {
        id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        priority: Option<OutlinePriority>,
        text: String,
    },
    Claim {
        id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        priority: Option<OutlinePriority>,
        text: String,
        #[serde(default)]
        qualifications: Vec<String>,
        evidence: Vec<OutlinePin>,
    },
    Data {
        id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        priority: Option<OutlinePriority>,
        dataset: String,
        carriers: Vec<OutlineCarrier>,
    },
    Asset {
        id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        priority: Option<OutlinePriority>,
        asset: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OutlinePin {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<String>,
    pub document: String,
    pub version: String,
    pub start: String,
    pub end: String,
    pub quote: String,
    /// BLAKE3 of the UTF-8 quote, in hex.
    pub quote_hash: String,
    #[serde(default)]
    pub drift: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OutlineDataset {
    pub id: String,
    pub columns: Vec<OutlineColumn>,
    #[serde(default)]
    pub rows: Vec<Vec<Option<OutlineCell>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing: Option<String>,
    pub sources: Vec<String>,
    #[serde(default)]
    pub merges: Vec<OutlineMerge>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum OutlineCell { Number(f64), Text(String) }

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OutlineColumn {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: OutlineColumnKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<OutlineNumberFormat>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OutlineColumnKind { Number, Text, Date }

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OutlineNumberFormat {
    #[serde(default)]
    pub decimals: u8,
    #[serde(default)]
    pub grouping: bool,
    #[serde(default)]
    pub percent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OutlineMerge {
    /// Data row index, excluding the header.
    pub row: usize,
    pub col: usize,
    pub rows: usize,
    pub cols: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OutlineAsset {
    pub id: String,
    pub kind: OutlineAssetKind,
    pub content: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OutlineAssetKind { Factual, Illustration }
