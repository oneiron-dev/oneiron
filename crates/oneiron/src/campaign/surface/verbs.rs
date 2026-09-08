//! Closed verb vocabulary and the single shared dispatch door.

use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value};

use super::codec_json::membership_page_to_json;
use super::parse::{
    parse_create_campaign_request, parse_create_saved_query_request, parse_membership_request,
    parse_update_campaign_request, parse_update_saved_query_request, required_entity_ref,
    required_u64,
};
use super::{campaign_record_to_json, saved_query_record_to_json};
use crate::memory::{Memory, MemoryError, MemoryResult};

/// `self.*` verb: create a CAMPAIGN owned by the authenticated principal.
pub const SELF_CAMPAIGN_CREATE: &str = "self.campaign.create";

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

/// The whole surface vocabulary, in dispatch order.
///
/// Discovery advertises exactly this slice, and [`CampaignSurfaceVerb::parse`]
/// admits exactly these strings, so a verb that exists is discoverable and a
/// verb that is discoverable is callable.
pub const CAMPAIGN_SELF_VERBS: &[&str] = &[
    SELF_CAMPAIGN_CREATE,
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

/// A parsed surface verb.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CampaignSurfaceVerb {
    /// [`SELF_CAMPAIGN_CREATE`].
    CampaignCreate,
    /// [`SELF_CAMPAIGN_READ`].
    CampaignRead,
    /// [`SELF_CAMPAIGN_UPDATE`].
    CampaignUpdate,
    /// [`SELF_CAMPAIGN_ARCHIVE`].
    CampaignArchive,
    /// [`SELF_CAMPAIGN_MEMBERS`].
    CampaignMembers,
    /// [`SELF_SAVED_QUERY_CREATE`].
    SavedQueryCreate,
    /// [`SELF_SAVED_QUERY_READ`].
    SavedQueryRead,
    /// [`SELF_SAVED_QUERY_UPDATE`].
    SavedQueryUpdate,
    /// [`SELF_SAVED_QUERY_ARCHIVE`].
    SavedQueryArchive,
    /// [`SELF_SAVED_QUERY_MEMBERS`].
    SavedQueryMembers,
}

impl CampaignSurfaceVerb {
    /// Every verb, in the order [`CAMPAIGN_SELF_VERBS`] advertises them.
    pub const ALL: [Self; 10] = [
        Self::CampaignCreate,
        Self::CampaignRead,
        Self::CampaignUpdate,
        Self::CampaignArchive,
        Self::CampaignMembers,
        Self::SavedQueryCreate,
        Self::SavedQueryRead,
        Self::SavedQueryUpdate,
        Self::SavedQueryArchive,
        Self::SavedQueryMembers,
    ];

    /// Parses a verb name against the closed list.
    ///
    /// Exact equality, deliberately: a prefix, a suffix, or a case variant of a
    /// real verb is not a real verb. Nothing here trims or normalizes, so the
    /// string a caller sent is the string that must match.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|verb| verb.as_str() == value)
    }

    /// The wire name of this verb.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CampaignCreate => SELF_CAMPAIGN_CREATE,
            Self::CampaignRead => SELF_CAMPAIGN_READ,
            Self::CampaignUpdate => SELF_CAMPAIGN_UPDATE,
            Self::CampaignArchive => SELF_CAMPAIGN_ARCHIVE,
            Self::CampaignMembers => SELF_CAMPAIGN_MEMBERS,
            Self::SavedQueryCreate => SELF_SAVED_QUERY_CREATE,
            Self::SavedQueryRead => SELF_SAVED_QUERY_READ,
            Self::SavedQueryUpdate => SELF_SAVED_QUERY_UPDATE,
            Self::SavedQueryArchive => SELF_SAVED_QUERY_ARCHIVE,
            Self::SavedQueryMembers => SELF_SAVED_QUERY_MEMBERS,
        }
    }

    /// Whether this verb mutates durable state.
    ///
    /// Membership verbs are reads even though they are named after a cohort:
    /// they project the enrollment CA-03 already wrote and enqueue nothing.
    #[must_use]
    pub const fn is_write(self) -> bool {
        matches!(
            self,
            Self::CampaignCreate
                | Self::CampaignUpdate
                | Self::CampaignArchive
                | Self::SavedQueryCreate
                | Self::SavedQueryUpdate
                | Self::SavedQueryArchive
        )
    }
}

/// One surface invocation: a verb name and its JSON body.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SurfaceCall {
    /// Verb name; must be one of [`CAMPAIGN_SELF_VERBS`].
    pub verb: String,
    /// Verb-specific request body.
    pub body: Value,
}

/// One surface result, echoing the verb that produced it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SurfaceReply {
    /// Canonical verb name.
    pub verb: String,
    /// Verb-specific response body.
    pub body: Value,
}

/// Executes one surface call against the caller's bound facade.
///
/// The single door both transports share. Verb resolution happens here and
/// nowhere else, so the HTTP routers and the MCP gateway cannot disagree about
/// what a verb means — the only thing a transport chooses is how it built the
/// [`SurfaceCall`].
///
/// # Errors
///
/// A verb outside [`CAMPAIGN_SELF_VERBS`] and every malformed body are
/// `BAD_REQUEST`; the domain's own not-found, stale-version, and gate outcomes
/// propagate through [`MemoryError`] unchanged.
pub fn invoke_campaign_surface(
    facade: &Memory<'_>,
    call: SurfaceCall,
) -> MemoryResult<SurfaceReply> {
    let verb = CampaignSurfaceVerb::parse(&call.verb).ok_or_else(|| {
        MemoryError::bad_request_with(
            format!("{:?} is not a campaign surface verb", call.verb),
            &["Call one of the verbs advertised in CAMPAIGN_SELF_VERBS."],
        )
    })?;
    let body = call.body;
    let now = crate::unix_seconds_now();
    let payload = match verb {
        CampaignSurfaceVerb::CampaignCreate => {
            let request = parse_create_campaign_request(&body)?;
            campaign_record_to_json(&facade.campaign_create(&request, now)?)
        }
        CampaignSurfaceVerb::CampaignRead => {
            let campaign_ref = required_entity_ref(&body, "campaign_ref")?;
            optional_record_json(
                facade.campaign_read(campaign_ref)?.as_ref(),
                campaign_record_to_json,
            )
        }
        CampaignSurfaceVerb::CampaignUpdate => {
            let campaign_ref = required_entity_ref(&body, "campaign_ref")?;
            let request = parse_update_campaign_request(&body)?;
            campaign_record_to_json(&facade.campaign_update(campaign_ref, &request, now)?)
        }
        CampaignSurfaceVerb::CampaignArchive => {
            let campaign_ref = required_entity_ref(&body, "campaign_ref")?;
            let expected = required_u64(&body, "expected_definition_version")?;
            campaign_record_to_json(&facade.campaign_archive(campaign_ref, expected, now)?)
        }
        CampaignSurfaceVerb::CampaignMembers => {
            let request = parse_membership_request(&body, "campaign_ref")?;
            membership_page_to_json(&facade.campaign_members(&request)?)
        }
        CampaignSurfaceVerb::SavedQueryCreate => {
            let request = parse_create_saved_query_request(&body)?;
            saved_query_record_to_json(&facade.saved_query_create(&request, now)?)
        }
        CampaignSurfaceVerb::SavedQueryRead => {
            let query_ref = required_entity_ref(&body, "query_ref")?;
            optional_record_json(
                facade.saved_query_read(query_ref)?.as_ref(),
                saved_query_record_to_json,
            )
        }
        CampaignSurfaceVerb::SavedQueryUpdate => {
            let query_ref = required_entity_ref(&body, "query_ref")?;
            let request = parse_update_saved_query_request(&body)?;
            saved_query_record_to_json(&facade.saved_query_update(query_ref, &request, now)?)
        }
        CampaignSurfaceVerb::SavedQueryArchive => {
            let query_ref = required_entity_ref(&body, "query_ref")?;
            let expected = required_u64(&body, "expected_definition_version")?;
            saved_query_record_to_json(&facade.saved_query_archive(query_ref, expected, now)?)
        }
        CampaignSurfaceVerb::SavedQueryMembers => {
            let request = parse_membership_request(&body, "query_ref")?;
            membership_page_to_json(&facade.saved_query_members(&request)?)
        }
    };
    Ok(SurfaceReply {
        verb: verb.as_str().to_owned(),
        body: payload,
    })
}

/// Wraps a read result so "absent" and "present" have one shape.
fn optional_record_json<T>(record: Option<&T>, encode: impl FnOnce(&T) -> Value) -> Value {
    let mut root = JsonMap::new();
    root.insert("found".to_owned(), Value::Bool(record.is_some()));
    root.insert("record".to_owned(), record.map_or(Value::Null, encode));
    Value::Object(root)
}
