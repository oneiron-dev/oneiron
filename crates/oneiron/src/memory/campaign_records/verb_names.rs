//! Stable names and discovery tables of campaign and standing-query verbs.

/// `self.*` verb: create a CAMPAIGN owned by the authenticated principal.
pub const SELF_CAMPAIGN_CREATE: &str = "self.campaign.create";

/// `self.*` verb: launch a Draft campaign or resume a Paused one.
pub const SELF_CAMPAIGN_LAUNCH: &str = "self.campaign.launch";

/// `self.*` verb: read one CAMPAIGN the principal owns.
pub const SELF_CAMPAIGN_READ: &str = "self.campaign.read";

/// `self.*` verb: replace a CAMPAIGN's definition under a version CAS.
pub const SELF_CAMPAIGN_UPDATE: &str = "self.campaign.update";

/// `self.*` verb: archive a CAMPAIGN — a lifecycle transition, never a delete.
pub const SELF_CAMPAIGN_ARCHIVE: &str = "self.campaign.archive";

/// `self.*` verb: page a CAMPAIGN's cohort, read-only.
pub const SELF_CAMPAIGN_MEMBERS: &str = "self.campaign.members";

/// `self.*` verb: create a SAVED_QUERY owned by the authenticated principal.
pub const SELF_SAVED_QUERY_CREATE: &str = "self.saved_query.create";

/// `self.*` verb: read one SAVED_QUERY the principal owns.
pub const SELF_SAVED_QUERY_READ: &str = "self.saved_query.read";

/// `self.*` verb: replace a SAVED_QUERY's definition under a version CAS.
pub const SELF_SAVED_QUERY_UPDATE: &str = "self.saved_query.update";

/// `self.*` verb: archive a SAVED_QUERY — a lifecycle transition.
pub const SELF_SAVED_QUERY_ARCHIVE: &str = "self.saved_query.archive";

/// `self.*` verb: page a SAVED_QUERY's derived membership, read-only.
pub const SELF_SAVED_QUERY_MEMBERS: &str = "self.saved_query.members";

/// `self.*` verb: evaluate a SAVED_QUERY manually now, with one receipt per
/// visited entity (verdict, evidence hash, memo hit, judge run).
///
/// An SDK row like the program verbs, not a verb of this sync dispatch: a
/// rubric judge runs on the server's own model seats, so the server's host
/// door answers it and an embedded vault refuses it as host-only. It is
/// therefore not in [`CAMPAIGN_SELF_VERBS`].
pub const SELF_SAVED_QUERY_EVALUATE: &str = "self.saved_query.evaluate";

/// `vault.*` verb: create a campaign program under a campaign the caller owns.
pub const VAULT_CAMPAIGN_PROGRAM_CREATE: &str = "vault.campaign.program.create";

/// `vault.*` verb: read one campaign program under a campaign the caller owns.
pub const VAULT_CAMPAIGN_PROGRAM_READ: &str = "vault.campaign.program.read";

/// `vault.*` verb: replace a campaign program's definition whole, under a CAS.
pub const VAULT_CAMPAIGN_PROGRAM_UPDATE: &str = "vault.campaign.program.update";

/// `vault.*` verb: archive a campaign program; a lifecycle transition, never a
/// delete.
pub const VAULT_CAMPAIGN_PROGRAM_ARCHIVE: &str = "vault.campaign.program.archive";

/// The campaign program verbs, in dispatch order.
///
/// They are SDK rows (`scripts/sdk/agent-verbs.json`), so the verb table
/// lists them to MCP, code mode and discovery; this door serves them to the
/// resource routes. They are not in [`CAMPAIGN_SELF_VERBS`], which discovery
/// advertises as bare code-mode tokens.
pub const CAMPAIGN_PROGRAM_VERBS: &[&str] = &[
    VAULT_CAMPAIGN_PROGRAM_CREATE,
    VAULT_CAMPAIGN_PROGRAM_READ,
    VAULT_CAMPAIGN_PROGRAM_UPDATE,
    VAULT_CAMPAIGN_PROGRAM_ARCHIVE,
];

/// The whole surface vocabulary, in dispatch order.
///
/// Discovery advertises exactly this slice, and [`CampaignSurfaceVerb::parse`]
/// admits exactly these strings, so a verb that exists is discoverable and a
/// verb that is discoverable is callable.
pub const CAMPAIGN_SELF_VERBS: &[&str] = &[
    SELF_CAMPAIGN_CREATE,
    SELF_CAMPAIGN_LAUNCH,
    SELF_CAMPAIGN_READ,
    SELF_CAMPAIGN_UPDATE,
    SELF_CAMPAIGN_ARCHIVE,
    SELF_CAMPAIGN_MEMBERS,
    SELF_SAVED_QUERY_CREATE,
    SELF_SAVED_QUERY_READ,
    SELF_SAVED_QUERY_UPDATE,
    SELF_SAVED_QUERY_ARCHIVE,
    SELF_SAVED_QUERY_MEMBERS,
];
