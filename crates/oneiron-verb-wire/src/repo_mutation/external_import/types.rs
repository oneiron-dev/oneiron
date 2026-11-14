//! Moved from `crates/oneiron/src/repo_mutation/external_import/types.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_model::llm::BrokerIsolation;
use serde::Deserialize;
use serde::Serialize;

/// Which authenticated door route the stock push takes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExternalImportDoor {
    /// The ordinary `/git` route, admitted by the caller's own standing.
    Raw,
    /// The checkout-lease route of a live checkout at its epoch.
    Checkout { checkout: String, epoch: u64 },
}

/// `vault.code.imports.get`'s request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExternalImportLookup {
    pub repo: String,
    pub code_repo: EntityId,
    /// The import's source claim id.
    pub import: EntityId,
    pub door: ExternalImportDoor,
}

/// How one import attempt's Git-LFS fetch went out (FIX 19876): the route
/// its batch calls and object actions took, the broker's isolation and how
/// many credential echoes it rewrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ExternalImportLfsTransfer {
    /// Who sent the requests, recorded before the first.
    pub route: ExternalImportLfsRoute,
    /// How the credential broker is kept apart from this vault's process,
    /// once an exchange reached it; `None` when none did, or when the
    /// attempt did not record its end.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub broker_isolation: Option<BrokerIsolation>,
    /// How many action header values of the batch replies the broker
    /// rewrote to its placeholder, each the binding's credential handed
    /// back for an action; the broker installed it again only on an action
    /// at the source's own origin. A count, never a value; zero for an
    /// anonymous source.
    #[serde(default)]
    pub credential_rewrites: u64,
}

/// Who sent an import's Git-LFS requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExternalImportLfsRoute {
    /// The serving host's credential broker, which alone installed the
    /// import's binding when it named one.
    Broker,
}

/// Where an import stands, derived from its saved facts and the door's
/// own receive records; never stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExternalImportPhase {
    /// Nothing decided yet, or the seed landed and the head awaits a send.
    Pending,
    /// The outside fetch or its proof refused.
    FetchRefused,
    /// The outside ref names another commit than the frozen head.
    SourceMoved,
    /// No exact base, an ambiguous one, or an imported ref holding another
    /// commit: this import alone is held.
    HeldBase,
    /// The door refused a send (lease, admission or scan).
    DoorRefused,
    /// A send was dispatched and no receive record proves its outcome yet.
    TransportUnknown,
    /// The door received the exact base to head update.
    Received,
}

/// Why a request does not normalize: a stable code and a safe detail.
pub type Malformed = (&'static str, String);

impl ExternalImportDoor {
    /// The checkout-lease ticket this route redeems, once well formed.
    pub fn ticket(&self) -> std::result::Result<Option<String>, Malformed> {
        match self {
            Self::Raw => Ok(None),
            Self::Checkout { checkout, epoch } => {
                if checkout.len() != 32
                    || !checkout
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    || *epoch == 0
                {
                    return Err((
                        "checkout_lease_invalid",
                        "a checkout door names a 32 lower-hex checkout and a positive epoch"
                            .to_owned(),
                    ));
                }
                Ok(Some(format!("{checkout}.{epoch}")))
            }
        }
    }
}

/// The https origin and canonical URL of an outside repository.
pub fn canonical_repository(url: &str) -> std::result::Result<(String, String), Malformed> {
    let url = url.trim();
    let malformed = || {
        (
            "source_repository_invalid",
            "repository must be an https Git URL with a host and a path, and no userinfo, \
             query or fragment"
                .to_owned(),
        )
    };
    let Some(rest) = url
        .get(..8)
        .filter(|scheme| scheme.eq_ignore_ascii_case("https://"))
        .and_then(|_| url.get(8..))
    else {
        return Err(malformed());
    };
    let (authority, path) = rest.split_once('/').ok_or_else(malformed)?;
    let path = path.trim_end_matches('/');
    if authority.is_empty()
        || path.is_empty()
        || url.contains(['@', '?', '#', '\\', ' '])
        || url.bytes().any(|byte| byte.is_ascii_control())
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(malformed());
    }
    let origin = format!("https://{}", authority.to_ascii_lowercase());
    Ok((origin.clone(), format!("{origin}/{path}")))
}
