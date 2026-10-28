//! Site skills (CUA E10; DESIGN-2 §3 "hub seed"): the knowledge a hub
//! skill holds for one exact site, and the program seeds its folder holds.
//!
//! A skill names its site by exact origin, the scheme, host and effective
//! port of an http or https URL, as the `url` crate parses them, and by
//! path prefixes on it (`routes`, none for the whole site). An `open`
//! whose page lands there after its redirects carries the loadable skills
//! that match, each with its `SKILL.md` body whole, as the observation's
//! `site_skills`; a load that fails is a note beside them, never a failed
//! open. The host's [`SiteSkillLoader`] holds the skills and their lease
//! checks; the browser only asks it.
//!
//! A skill's seeds are never admitted programs. `library.find` lists them
//! apart from the library's cards, as `candidates`, and `library.propose`
//! takes one by its handle: the host resolves its exact bytes and their
//! provenance, and the proposal then passes the same two checks as any
//! other. The seed is the program's one body; a skill holds no second copy
//! of its steps.

use crate::{ProposeInput, WorkflowSeed};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The exact origin of an http or https URL, as the `url` crate parses
/// it: equal only to the same scheme, host and effective port (CALL 1).
/// Credentials, the path, the query and the fragment are no part of it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SiteOrigin {
    /// `http` or `https`.
    pub scheme: String,
    /// The host as the parser gives it: lower-cased, an internationalised
    /// name in its ASCII form, an IPv6 address in brackets.
    pub host: String,
    /// The port the URL names, else its scheme's default.
    pub port: u16,
}

impl SiteOrigin {
    /// The exact origin of `url`. Any other scheme, or a URL that does not
    /// parse, is refused by name.
    pub fn parse(url: &str) -> Result<Self, OriginError> {
        Self::of(&url::Url::parse(url)?)
    }

    fn of(url: &url::Url) -> Result<Self, OriginError> {
        let scheme = url.scheme();
        if !matches!(scheme, "http" | "https") {
            return Err(OriginError::Scheme(scheme.to_owned()));
        }
        let host = url
            .host_str()
            .filter(|host| !host.is_empty())
            .ok_or(OriginError::NoHost)?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| OriginError::Scheme(scheme.to_owned()))?;
        Ok(Self {
            scheme: scheme.to_owned(),
            host: host.to_owned(),
            port,
        })
    }

    /// Whether `path` falls in `routes`: under one of its path prefixes, or
    /// anywhere when it names none (CALL 1).
    #[must_use]
    pub fn route_matches(path: &str, routes: &[String]) -> bool {
        routes.is_empty() || routes.iter().any(|route| path.starts_with(route.as_str()))
    }
}

/// Why a URL has no exact site origin. Its words never hold the URL's
/// credentials, query or fragment.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OriginError {
    /// The URL does not parse, in the parser's words.
    #[error("the URL does not parse: {0}")]
    Parse(String),
    /// Its scheme, which is not http or https.
    #[error("only an http or https URL names a site, not {0}")]
    Scheme(String),
    #[error("the URL names no host")]
    NoHost,
}

impl From<url::ParseError> for OriginError {
    fn from(error: url::ParseError) -> Self {
        Self::Parse(error.to_string())
    }
}

/// What a site-skill load asks for: the exact origin of the page and its
/// path, never its query or fragment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SiteSkillQuery {
    pub origin: SiteOrigin,
    /// The URL's path as the parser gives it, `/` for none.
    pub path: String,
}

impl SiteSkillQuery {
    /// The query for the page at `url`.
    pub fn parse(url: &str) -> Result<Self, OriginError> {
        let url = url::Url::parse(url)?;
        Ok(Self {
            origin: SiteOrigin::of(&url)?,
            path: url.path().to_owned(),
        })
    }
}

/// One loadable skill whose site matches the page exactly: its knowledge,
/// whole, and the program seeds its folder holds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SiteSkillMatch {
    pub skill_id: String,
    /// The revision of the skill that loaded.
    pub revision: String,
    /// The skill's `SKILL.md` body, exact and whole.
    pub knowledge: String,
    /// The programs its folder seeds, each a candidate `library.propose`
    /// takes by its handle; none is in the library until a proposal of it
    /// passes both checks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub seeds: Vec<SeedCandidate>,
}

/// A skill folder's program seed, as `library.find` lists it: the handle
/// `library.propose` takes, the file's path in its pack, the digest of its
/// exact bytes, and its licence. It is no admitted program.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SeedCandidate {
    pub candidate: String,
    pub path: String,
    pub digest: String,
    pub license: String,
}

/// A candidate as the host resolved it: the program its exact bytes hold,
/// and their provenance.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SeedBody {
    pub program: ProposeInput,
    pub seed: WorkflowSeed,
}

/// Why a site skill did not load or a seed did not resolve: a stable code
/// and the words that name the case.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema, thiserror::Error)]
#[error("{code} ({detail})")]
pub struct SiteSkillError {
    pub code: SiteSkillErrorCode,
    pub detail: String,
}

impl SiteSkillError {
    #[must_use]
    pub fn new(code: SiteSkillErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

/// The stable codes of [`SiteSkillError`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SiteSkillErrorCode {
    /// The run holds no skill-load lease (CALL 8).
    NoLease,
    /// The page's URL names no exact site origin.
    Origin,
    /// The host's skill read failed.
    Loader,
    /// The host resolves no seed by that handle.
    Unresolved,
    /// No `open` or `find` of this browser listed the candidate.
    NotIssued,
    /// The resolved seed's digest is not the one its candidate was listed
    /// with: its bytes changed (CALL 7).
    DigestMismatch,
    /// This browser's host loads no site skills.
    NoLoader,
}

impl SiteSkillErrorCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoLease => "no_lease",
            Self::Origin => "origin",
            Self::Loader => "loader",
            Self::Unresolved => "unresolved",
            Self::NotIssued => "not_issued",
            Self::DigestMismatch => "digest_mismatch",
            Self::NoLoader => "no_loader",
        }
    }
}

impl std::fmt::Display for SiteSkillErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<OriginError> for SiteSkillError {
    fn from(error: OriginError) -> Self {
        Self::new(SiteSkillErrorCode::Origin, error.to_string())
    }
}

/// The host's site skills: the loadable skills whose site matches a page
/// exactly, and the seed a candidate handle names. The host checks its
/// run's skill-load lease at each call.
pub trait SiteSkillLoader: Send + Sync {
    /// The loadable skills whose origin equals `query`'s and whose routes
    /// take its path. A match never activates a skill that is not loadable.
    fn site_skills(&self, query: &SiteSkillQuery) -> Result<Vec<SiteSkillMatch>, SiteSkillError>;

    /// The program and provenance `candidate`'s exact bytes hold, checked
    /// against the digest its import pinned (CALL 7).
    fn seed(&self, candidate: &str) -> Result<SeedBody, SiteSkillError>;
}
