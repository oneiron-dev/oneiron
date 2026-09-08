//! CA-07's SDK surface: one `self.*` verb vocabulary over the CRM pack.
//!
//! This module is the ONLY place the campaign and saved-query domain APIs are
//! given transport-shaped names. Both reach — the HTTP routers in
//! `oneiron-server` and the MCP gateway's existing generic dialect — call
//! `invoke_campaign_surface` and serialize the same `SurfaceReply`, so the
//! transports own no campaign semantics and cannot drift from each other.
//!
//! Three laws shape everything below.
//!
//! * **The verb list is closed.** `CAMPAIGN_SELF_VERBS` is the whole
//!   vocabulary; `CampaignSurfaceVerb::parse` admits nothing else, so an
//!   unknown or prefix-confusable name is a typed rejection rather than a
//!   silently-routed call.
//! * **`owner_actor` comes from the bound actor.** Every write is dispatched
//!   through the caller's `Memory`, whose actor is the authenticated
//!   principal, and no create/update request type carries an owner field. A
//!   caller payload therefore cannot select another actor even by accident.
//! * **Archive is a lifecycle transition.** Neither family gains a hard-delete
//!   verb: an archived record stays addressable, which is what makes it
//!   auditable (ARCH-0059).
//!
//! CA-00 minted CAMPAIGN's structural kind and stopped there — the pack's
//! ratified separation law is that a campaign never stores a member list, so
//! there was no campaign record for a cohort to hang off. The minimal record
//! below (identity, name, version, lifecycle) is that missing half, deliberately
//! kept to what an addressable, versioned, archivable campaign needs. Membership
//! stays where CA-01 put it: `campaign.member` claims on the PERSON.

mod campaign;
mod codec_json;
mod membership;
mod parse;
#[cfg(test)]
mod tests;
mod verbs;

pub use self::campaign::{
    CAMPAIGN_NAME_MAX_BYTES, CAMPAIGN_SCHEMA_VERSION, CampaignDefinition, CampaignLifecycle,
    CampaignRecord, CreateCampaignRequest, UpdateCampaignRequest, archive_campaign,
    create_campaign, read_campaign, update_campaign,
};
pub use self::codec_json::{campaign_record_to_json, saved_query_record_to_json};
pub use self::membership::{
    MEMBERSHIP_PAGE_DEFAULT_LIMIT, MEMBERSHIP_PAGE_MAX_LIMIT, MembershipPage,
    MembershipReadRequest, MembershipRow, read_campaign_members, read_saved_query_members,
};
pub use self::verbs::{
    CAMPAIGN_SELF_VERBS, CampaignSurfaceVerb, SELF_CAMPAIGN_ARCHIVE, SELF_CAMPAIGN_CREATE,
    SELF_CAMPAIGN_MEMBERS, SELF_CAMPAIGN_READ, SELF_CAMPAIGN_UPDATE, SELF_SAVED_QUERY_ARCHIVE,
    SELF_SAVED_QUERY_CREATE, SELF_SAVED_QUERY_MEMBERS, SELF_SAVED_QUERY_READ,
    SELF_SAVED_QUERY_UPDATE, SurfaceCall, SurfaceReply, invoke_campaign_surface,
};

// The flat surface.rs module used to provide these names to the sibling test
// module through `use super::*`: its own private crate/std import header, and
// every surface-internal item the tests name bare. After the directory split
// the seam re-imports both so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::parse::*;
#[cfg(test)]
use crate::saved_query::{
    CreateSavedQueryRequest, EvalMode, EvalPolicy, MatcherSpec, MembershipEvent,
    MembershipTransition, QueryScope, SAVED_QUERY_SCHEMA_VERSION, parse_filter_ast,
};
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use crate::{EntityId, Vault};
#[cfg(test)]
use serde_json::Value;
