//! Model packs (FIX 5365, MODEL PACKS = A): the hub form of a seasonal
//! model stack. A pack maps each role to its variants, one per kind of
//! access, each a model and when to use it, with a changelog and the bench
//! evidence behind its picks. Its season is a [`ModelStackId`]; following
//! the latest pack or pinning a season is a [`ModelStackPreference`]; its
//! retirement schedule is a [`ModelStackDeprecation`]. The hub's install
//! receipt and content hash are its signature: this type is only ever read
//! from an installed pack's bytes.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use oneiron_model::llm::ModelId;

use super::model_versioning::{ModelStackDeprecation, ModelStackId, ModelStackPreference};

/// The `knowledge/model-pack.json` format this engine reads. An engine call
/// (CALLS, FIX 5365): a pack in any other format is refused at its source,
/// never read loosely.
pub const MODEL_PACK_FORMAT_VERSION: u32 = 1;

/// A model pack's identity: its hub pack name, author-scoped and lowercase
/// (`oneiron.season-autumn-2026`), under the hub's own pack name rules.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ModelPackId(String);

impl ModelPackId {
    pub fn new(value: impl Into<String>) -> std::result::Result<Self, ModelPackError> {
        let value = value.into();
        let valid = value.len() <= 256
            && value.contains('.')
            && value.split('.').all(|part| {
                part.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
                    && part.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'_' | b'-')
                    })
            });
        if valid {
            Ok(Self(value))
        } else {
            Err(ModelPackError::InvalidPackId { id: value })
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ModelPackId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The kind of access a variant runs on (agent-runtime #model-packs: "our
/// hosted credits, a Claude or ChatGPT seat, the person's own keys, or a
/// local GPU only"). A provider is the provider segment of the variant's
/// model id: a Claude seat is `Seat { provider: "anthropic" }`, a ChatGPT
/// seat `Seat { provider: "openai" }`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ModelPackAccess {
    /// Our hosted credits.
    Hosted { provider: String },
    /// A vendor subscription seat the person signed in.
    Seat { provider: String },
    /// The person's own provider key.
    OwnKey { provider: String },
    /// A local GPU only: the person's own device or node.
    LocalGpu,
}

impl ModelPackAccess {
    /// The provider this access reaches, when it names one.
    #[must_use]
    pub fn provider(&self) -> Option<&str> {
        match self {
            Self::Hosted { provider } | Self::Seat { provider } | Self::OwnKey { provider } => {
                Some(provider.as_str())
            }
            Self::LocalGpu => None,
        }
    }

    /// Whether this access can carry `model`. An engine call (CALLS, FIX
    /// 5365): a provider-bound access names the model id's own provider
    /// segment, so the access a host's offers hold and the access a pack
    /// names are spelled the same way; a local GPU carries any model.
    #[must_use]
    pub fn carries(&self, model: &ModelId) -> bool {
        self.provider()
            .is_none_or(|provider| provider == model.provider())
    }
}

/// One way a pack fills a role: a model on one kind of access, and when to
/// use it, in the same "model + when" shape as a per-agent model list entry
/// (#agent-models).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelPackVariant {
    pub access: ModelPackAccess,
    pub model: ModelId,
    pub when: String,
}

/// One changelog line: what a version of the pack changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelPackChangelogEntry {
    pub version: String,
    pub summary: String,
}

/// The bench evidence behind one pick: the role and model it measured, what
/// it found, and where the full result is (a path in the pack or a URL).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelPackBenchRef {
    pub role: String,
    pub model: ModelId,
    pub summary: String,
    pub reference: String,
}

/// A validated model pack, as read from an installed pack's data file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModelPack {
    /// The hub pack name.
    pub id: ModelPackId,
    /// The pack manifest's version.
    pub version: String,
    pub season: ModelStackId,
    /// The day the pack was released, in days since the Unix epoch.
    pub released_epoch_day: u32,
    /// Each role, by its key, and its variants in the pack's order of
    /// preference: the first one the person can run is the pick.
    pub roles: BTreeMap<String, Vec<ModelPackVariant>>,
    pub changelog: Vec<ModelPackChangelogEntry>,
    pub bench: Vec<ModelPackBenchRef>,
    /// The pack a vault moves to when this one retires.
    pub successor: Option<ModelPackId>,
    /// When the pack's notices start and when it stops being served.
    pub retirement: Option<ModelStackDeprecation>,
}

/// The data file's shape: everything but the identity, which the pack
/// manifest carries.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelPackDocument {
    format: u32,
    season: ModelStackId,
    released_epoch_day: u32,
    roles: BTreeMap<String, Vec<ModelPackVariant>>,
    #[serde(default)]
    changelog: Vec<ModelPackChangelogEntry>,
    #[serde(default)]
    bench: Vec<ModelPackBenchRef>,
    #[serde(default)]
    successor: Option<ModelPackId>,
    #[serde(default)]
    retirement: Option<ModelStackDeprecation>,
}

impl ModelPack {
    /// Reads the pack `id` at `version` from its data file's bytes.
    pub fn parse(
        id: ModelPackId,
        version: impl Into<String>,
        bytes: &[u8],
    ) -> std::result::Result<Self, ModelPackError> {
        let document: ModelPackDocument = serde_json::from_slice(bytes)
            .map_err(|error| ModelPackError::Document(error.to_string()))?;
        if document.format != MODEL_PACK_FORMAT_VERSION {
            return Err(ModelPackError::Format {
                found: document.format,
            });
        }
        let pack = Self {
            id,
            version: version.into(),
            season: document.season,
            released_epoch_day: document.released_epoch_day,
            roles: document.roles,
            changelog: document.changelog,
            bench: document.bench,
            successor: document.successor,
            retirement: document.retirement,
        };
        pack.validate()?;
        Ok(pack)
    }

    /// Whether the pack is still served on `as_of_epoch_day`: it has no
    /// retirement, or its retirement day has not come.
    #[must_use]
    pub fn is_served_on(&self, as_of_epoch_day: u32) -> bool {
        self.retirement
            .is_none_or(|retirement| !retirement.is_retired(as_of_epoch_day))
    }

    /// The variants the pack lists for `role`, in its order; none when the
    /// pack does not fill the role.
    #[must_use]
    pub fn variants(&self, role: &str) -> &[ModelPackVariant] {
        self.roles.get(role).map(Vec::as_slice).unwrap_or_default()
    }

    fn validate(&self) -> std::result::Result<(), ModelPackError> {
        ModelPackId::new(self.id.as_str())?;
        if let Some(successor) = &self.successor {
            ModelPackId::new(successor.as_str())?;
            if *successor == self.id {
                return Err(ModelPackError::OwnSuccessor);
            }
        }
        ModelStackId::new(self.season.as_str()).map_err(|_| ModelPackError::InvalidSeason)?;
        if self.version.trim().is_empty() {
            return Err(ModelPackError::BlankText { field: "version" });
        }
        if self.roles.is_empty() {
            return Err(ModelPackError::NoRoles);
        }
        for (role, variants) in &self.roles {
            if role.trim().is_empty() || role.trim() != role.as_str() {
                return Err(ModelPackError::InvalidRole { role: role.clone() });
            }
            if variants.is_empty() {
                return Err(ModelPackError::EmptyRole { role: role.clone() });
            }
            let mut seen = BTreeSet::new();
            for variant in variants {
                if variant.when.trim().is_empty() {
                    return Err(ModelPackError::BlankText { field: "when" });
                }
                if variant
                    .access
                    .provider()
                    .is_some_and(|provider| provider.trim().is_empty())
                    || !variant.access.carries(&variant.model)
                {
                    return Err(ModelPackError::AccessProvider {
                        role: role.clone(),
                        model: variant.model.clone(),
                    });
                }
                if !seen.insert((&variant.access, &variant.model)) {
                    return Err(ModelPackError::DuplicateVariant {
                        role: role.clone(),
                        model: variant.model.clone(),
                    });
                }
            }
        }
        for entry in &self.changelog {
            if entry.version.trim().is_empty() || entry.summary.trim().is_empty() {
                return Err(ModelPackError::BlankText { field: "changelog" });
            }
        }
        for evidence in &self.bench {
            if evidence.role.trim().is_empty()
                || evidence.summary.trim().is_empty()
                || evidence.reference.trim().is_empty()
            {
                return Err(ModelPackError::BlankText { field: "bench" });
            }
        }
        Ok(())
    }
}

/// The order packs are newest in. An engine call (CALLS, FIX 5367): the
/// later release day is newer; on one day, the greater pack id, so the
/// order never depends on install order.
#[must_use]
pub fn model_pack_recency(pack: &ModelPack) -> (u32, &ModelPackId) {
    (pack.released_epoch_day, &pack.id)
}

/// The pack a vault follows among `items` on `as_of_epoch_day` (FIX 5367):
/// the newest served pack, or with a pinned season the newest served pack
/// of that season. An engine call (CALLS, FIX 5367): a retired pack is
/// never followed, and a pin whose season no served pack carries follows
/// the latest pack until the retirement migration (FIX 5368) moves it.
pub fn select_model_pack<'a, T>(
    items: &'a [T],
    pack_of: impl Fn(&'a T) -> &'a ModelPack,
    preference: &ModelStackPreference,
    as_of_epoch_day: u32,
) -> Option<&'a T> {
    let newest = |season: Option<&ModelStackId>| {
        items
            .iter()
            .filter(|item| {
                let pack = pack_of(*item);
                pack.is_served_on(as_of_epoch_day)
                    && season.is_none_or(|season| pack.season == *season)
            })
            .max_by(|left, right| {
                model_pack_recency(pack_of(*left)).cmp(&model_pack_recency(pack_of(*right)))
            })
    };
    match preference {
        ModelStackPreference::AutoUpgrade => newest(None),
        ModelStackPreference::Pinned { stack } => newest(Some(stack)).or_else(|| newest(None)),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ModelPackError {
    #[error("model pack data does not read as its format: {0}")]
    Document(String),
    #[error("model pack format {found} is not the format this engine reads")]
    Format { found: u32 },
    #[error("model pack id {id:?} is not an author-scoped lowercase pack name")]
    InvalidPackId { id: String },
    #[error("model pack season is not a valid stack id")]
    InvalidSeason,
    #[error("a model pack names itself as its successor")]
    OwnSuccessor,
    #[error("a model pack fills no role")]
    NoRoles,
    #[error("model pack role key {role:?} is blank or unnormalized")]
    InvalidRole { role: String },
    #[error("model pack role {role} lists no variant")]
    EmptyRole { role: String },
    #[error("model pack {field} text is blank")]
    BlankText { field: &'static str },
    #[error("model pack role {role} names an access whose provider is not {model}'s provider")]
    AccessProvider { role: String, model: ModelId },
    #[error("model pack role {role} lists {model} twice on one access")]
    DuplicateVariant { role: String, model: ModelId },
}
