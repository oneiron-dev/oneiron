//! Model packs (FIX 5365, MODEL PACKS = A): the hub form of a seasonal
//! model stack. A pack maps each role to its variants, one per kind of
//! access, each a model and when to use it, with a changelog and the bench
//! evidence behind its picks. Its season is a [`ModelStackId`]; following
//! the latest pack, pinning a season or pinning one pack is a
//! [`ModelPackPreference`]; its retirement schedule, and each retiring
//! model's, is a [`ModelStackDeprecation`] (FIX 5368). The hub's install
//! receipt and content hash are its signature: this type is only ever read
//! from an installed pack's bytes.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use oneiron_model::llm::ModelId;

use super::model_versioning::{ModelStackDeprecation, ModelStackId};

/// The `knowledge/model-pack.json` format this engine reads. An engine call
/// (CALLS, FIX 5365): a pack in any other format is refused at its source,
/// never read loosely.
pub const MODEL_PACK_FORMAT_VERSION: u32 = 1;

/// The days before a retirement day on which the owner is told: Eiri
/// DEC-0004 #deprecation's announcement (60), warning (30) and soft
/// deadline (7); the day itself is the migration. An engine call (CALLS,
/// FIX 5368): each mark is one inbox notice to each owner, for a retiring
/// pack and for each retiring model a role resolves to.
pub const MODEL_PACK_RETIREMENT_NOTICE_DAYS: [u32; 3] = [60, 30, 7];

/// How many successors a retirement follows to find a served pack. An
/// engine call (CALLS, FIX 5368): a chain longer than this, or one that
/// loops, finds none, and the vault follows the latest served pack.
pub const MODEL_PACK_SUCCESSOR_HOPS: usize = 8;

/// A model pack's identity: its hub pack name, author-scoped and lowercase
/// (`oneiron.season-autumn-2026`), under the hub's own pack name rules.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
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

/// A model the pack marks retiring (FIX 5368): when its notices start and
/// when it stops being served, and the model the roles that use it move to
/// on that day.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelPackModelRetirement {
    pub model: ModelId,
    pub retirement: ModelStackDeprecation,
    #[serde(default)]
    pub successor: Option<ModelId>,
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
    /// The models the pack marks retiring, one entry each.
    pub retiring_models: Vec<ModelPackModelRetirement>,
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
    #[serde(default)]
    retiring_models: Vec<ModelPackModelRetirement>,
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
            retiring_models: document.retiring_models,
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

    /// The retirement the pack marks for `model`, if it marks one.
    #[must_use]
    pub fn model_retirement(&self, model: &ModelId) -> Option<&ModelPackModelRetirement> {
        self.retiring_models
            .iter()
            .find(|retiring| retiring.model == *model)
    }

    /// `variant` as it runs on `as_of_epoch_day` (FIX 5368): itself while its
    /// model is served; from its model's retirement day, the same access and
    /// words on the first model of its successor chain that is still served,
    /// at most [`MODEL_PACK_SUCCESSOR_HOPS`] away. An engine call (CALLS, FIX
    /// 5368): a successor the variant's access does not carry (another
    /// provider's model on a provider-bound access), no successor, a chain
    /// that loops, or one longer than the bound drops the variant, and the
    /// role's next variant is its pick.
    #[must_use]
    pub fn variant_on(
        &self,
        variant: &ModelPackVariant,
        as_of_epoch_day: u32,
    ) -> Option<ModelPackVariant> {
        let mut model = &variant.model;
        let mut seen = BTreeSet::from([model]);
        for _ in 0..=MODEL_PACK_SUCCESSOR_HOPS {
            let Some(retiring) = self
                .model_retirement(model)
                .filter(|retiring| retiring.retirement.is_retired(as_of_epoch_day))
            else {
                return Some(ModelPackVariant {
                    access: variant.access.clone(),
                    model: model.clone(),
                    when: variant.when.clone(),
                });
            };
            model = retiring.successor.as_ref()?;
            if !variant.access.carries(model) || !seen.insert(model) {
                return None;
            }
        }
        None
    }

    /// The changelog line the owner's notices lead with. An engine call
    /// (CALLS, FIX 5369): the entry for the pack's own version, else the
    /// pack's first entry; none for a pack with no changelog.
    #[must_use]
    pub fn changelog_headline(&self) -> Option<&str> {
        self.changelog
            .iter()
            .find(|entry| entry.version == self.version)
            .or_else(|| self.changelog.first())
            .map(|entry| entry.summary.as_str())
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
        let mut retiring = BTreeSet::new();
        for entry in &self.retiring_models {
            if !retiring.insert(&entry.model) {
                return Err(ModelPackError::DuplicateRetiringModel {
                    model: entry.model.clone(),
                });
            }
            if entry.successor.as_ref() == Some(&entry.model) {
                return Err(ModelPackError::OwnModelSuccessor {
                    model: entry.model.clone(),
                });
            }
        }
        Ok(())
    }
}

/// The owner's model pack preference (FIX 5367, 5369): follow the latest
/// pack (the default), pin a season while a served pack of it is installed,
/// or pin one pack, as a revert to it does.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ModelPackPreference {
    #[default]
    AutoUpgrade,
    Pinned {
        stack: ModelStackId,
    },
    PinnedPack {
        pack: ModelPackId,
    },
}

/// The order packs are newest in. An engine call (CALLS, FIX 5367): the
/// later release day is newer; on one day, the greater pack id, so the
/// order never depends on install order.
#[must_use]
pub fn model_pack_recency(pack: &ModelPack) -> (u32, &ModelPackId) {
    (pack.released_epoch_day, &pack.id)
}

/// The newest pack among `items`, served or not, that `admits`.
fn newest<'a, T>(
    items: &'a [T],
    pack_of: &impl Fn(&'a T) -> &'a ModelPack,
    admits: impl Fn(&ModelPack) -> bool,
) -> Option<&'a T> {
    items
        .iter()
        .filter(|item| admits(pack_of(*item)))
        .max_by(|left, right| {
            model_pack_recency(pack_of(*left)).cmp(&model_pack_recency(pack_of(*right)))
        })
}

/// The newest served pack among `items` on `as_of_epoch_day` that `admits`.
fn newest_served<'a, T>(
    items: &'a [T],
    pack_of: &impl Fn(&'a T) -> &'a ModelPack,
    as_of_epoch_day: u32,
    admits: impl Fn(&ModelPack) -> bool,
) -> Option<&'a T> {
    newest(items, pack_of, |pack| {
        pack.is_served_on(as_of_epoch_day) && admits(pack)
    })
}

/// The first served pack on `start`'s successor chain among `items`: its
/// successor when installed and served, else that one's, at most
/// [`MODEL_PACK_SUCCESSOR_HOPS`] away.
fn served_successor<'a, T>(
    items: &'a [T],
    pack_of: &impl Fn(&'a T) -> &'a ModelPack,
    start: &ModelPack,
    as_of_epoch_day: u32,
) -> Option<&'a T> {
    let mut seen = BTreeSet::from([&start.id]);
    let mut next = start.successor.as_ref();
    for _ in 0..MODEL_PACK_SUCCESSOR_HOPS {
        let id = next?;
        if !seen.insert(id) {
            return None;
        }
        let item = items.iter().find(|item| pack_of(*item).id == *id)?;
        let pack = pack_of(item);
        if pack.is_served_on(as_of_epoch_day) {
            return Some(item);
        }
        next = pack.successor.as_ref();
    }
    None
}

/// The pack following the latest pack follows on `as_of_epoch_day` (FIX
/// 5367, 5368): the newest installed pack while it is served. An engine
/// call (CALLS, FIX 5368): once that pack has retired, the vault follows
/// its first served successor, as a vault following the latest moves to
/// the successor on the retirement day; with none, the newest served pack.
fn latest_served<'a, T>(
    items: &'a [T],
    pack_of: &impl Fn(&'a T) -> &'a ModelPack,
    as_of_epoch_day: u32,
) -> Option<&'a T> {
    let newest_installed = newest(items, pack_of, |_| true)?;
    let pack = pack_of(newest_installed);
    if pack.is_served_on(as_of_epoch_day) {
        return Some(newest_installed);
    }
    served_successor(items, pack_of, pack, as_of_epoch_day)
        .or_else(|| newest_served(items, pack_of, as_of_epoch_day, |_| true))
}

/// The pack a vault follows among `items` on `as_of_epoch_day` (FIX 5367,
/// 5368, 5369): following the latest, the newest installed pack, or once it
/// has retired its first served successor, else the newest served pack;
/// with a pinned season the newest served pack of that season; with a
/// pinned pack that pack. An engine call (CALLS, FIX 5367): a retired pack is never
/// followed, and a pin no served pack meets follows the latest pack until
/// the retirement migration ([`migrated_model_pack_preference`], FIX 5368)
/// moves it.
pub fn select_model_pack<'a, T>(
    items: &'a [T],
    pack_of: impl Fn(&'a T) -> &'a ModelPack,
    preference: &ModelPackPreference,
    as_of_epoch_day: u32,
) -> Option<&'a T> {
    let latest = || latest_served(items, &pack_of, as_of_epoch_day);
    match preference {
        ModelPackPreference::AutoUpgrade => latest(),
        ModelPackPreference::Pinned { stack } => {
            newest_served(items, &pack_of, as_of_epoch_day, |pack| {
                pack.season == *stack
            })
            .or_else(latest)
        }
        ModelPackPreference::PinnedPack { pack: id } => {
            newest_served(items, &pack_of, as_of_epoch_day, |pack| pack.id == *id).or_else(latest)
        }
    }
}

/// Where a pin moves on `as_of_epoch_day` once what it names has retired
/// (FIX 5368): `None` when it stays. An engine call (CALLS, FIX 5368):
/// following the latest pack stores no move, as [`select_model_pack`]
/// follows a retired newest pack's successor itself; a season pin no
/// served pack of its season meets moves to the season of the first served
/// successor of that season's newest pack; a pack pin whose pack retired
/// moves to its first served successor. A pin whose successor is not
/// installed and served stays, and the vault follows the latest pack until
/// a later pass finds the successor.
pub fn migrated_model_pack_preference<'a, T>(
    items: &'a [T],
    pack_of: impl Fn(&'a T) -> &'a ModelPack,
    preference: &ModelPackPreference,
    as_of_epoch_day: u32,
) -> Option<ModelPackPreference> {
    match preference {
        ModelPackPreference::AutoUpgrade => None,
        ModelPackPreference::Pinned { stack } => {
            if newest_served(items, &pack_of, as_of_epoch_day, |pack| {
                pack.season == *stack
            })
            .is_some()
            {
                return None;
            }
            let retired = newest(items, &pack_of, |pack| pack.season == *stack)?;
            let successor = served_successor(items, &pack_of, pack_of(retired), as_of_epoch_day)?;
            Some(ModelPackPreference::Pinned {
                stack: pack_of(successor).season.clone(),
            })
        }
        ModelPackPreference::PinnedPack { pack: id } => {
            let pinned = newest(items, &pack_of, |pack| pack.id == *id)?;
            if pack_of(pinned).is_served_on(as_of_epoch_day) {
                return None;
            }
            let successor = served_successor(items, &pack_of, pack_of(pinned), as_of_epoch_day)?;
            Some(ModelPackPreference::PinnedPack {
                pack: pack_of(successor).id.clone(),
            })
        }
    }
}

/// The notice mark `retirement` is at on `as_of_epoch_day` (FIX 5368): the
/// nearest of [`MODEL_PACK_RETIREMENT_NOTICE_DAYS`] at or above the days
/// left. An engine call (CALLS, FIX 5368): marks wait for the schedule's own
/// notice start, and a schedule first seen past a mark, or a pass that
/// missed one, sends the nearest mark's notice alone, never every mark it
/// passed. `None` before the notice start, more days ahead than the first
/// mark, and from the retirement day, which migrates instead.
#[must_use]
pub fn retirement_notice_mark(
    retirement: ModelStackDeprecation,
    as_of_epoch_day: u32,
) -> Option<u32> {
    if as_of_epoch_day < retirement.notice_starts_epoch_day
        || retirement.is_retired(as_of_epoch_day)
    {
        return None;
    }
    let left = retirement.retires_epoch_day - as_of_epoch_day;
    MODEL_PACK_RETIREMENT_NOTICE_DAYS
        .into_iter()
        .filter(|mark| left <= *mark)
        .min()
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
    #[error("model pack marks {model} retiring twice")]
    DuplicateRetiringModel { model: ModelId },
    #[error("model pack names {model} as its own successor")]
    OwnModelSuccessor { model: ModelId },
}
