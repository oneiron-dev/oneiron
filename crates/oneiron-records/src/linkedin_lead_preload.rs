//! Moved from `crates/oneiron/src/linkedin_lead_preload.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedInLeadCorpus {
    pub schema_version: u16,
    pub companies: Vec<LinkedInCompanySeed>,
    pub contacts: Vec<LinkedInContactSeed>,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedInCompanySeed {
    pub external_id: String,
    pub display_name: String,
    pub profile_url: Option<String>,
    pub website_domain: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedInContactSeed {
    pub external_id: String,
    pub display_name: String,
    pub company_external_id: String,
    pub title: Option<String>,
    pub profile_url: Option<String>,
}
