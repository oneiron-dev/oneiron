//! Component catalogs an app declares (FIX 9891, 9893): the catalog name,
//! its semver `catalogVersion`, the descriptor that names its component
//! schemas, and the component atom a tree names from it.
//!
//! The engine negotiates the component set an app declares and never defines
//! it (ARCH-0048 G3). A component is data: its props are plain JSON that must
//! meet the schema its app declared, it declares no action, and every backing
//! read and action on its card stays under engine mediation. The built-in lens
//! atom kit is one supplied descriptor ([`GeneratedUiCatalogDescriptor::lens_atom_kit`]),
//! not the only legal catalog.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::lens::atom::LensText;
use crate::lens::validate::{MAX_LENS_TOKEN_BYTES, fallback_lens_text};
use crate::lens::wire_ids::{GeneratedUiCatalogName, GeneratedUiComponentName};
use crate::{Error, Result};

/// The wire name of the built-in lens atom kit.
const LENS_ATOM_KIT_CATALOG: &str = "lens_atom_kit";

/// The semver of the built-in kit's component set (CALLS "FIX 9893 built-in
/// catalog semver"). It is held apart from the u16 kit stamp
/// [`LENS_ATOM_KIT_VERSION`](crate::lens::LENS_ATOM_KIT_VERSION), which says
/// when a lens body is regenerated, and is never derived from it.
pub const LENS_ATOM_KIT_CATALOG_VERSION: &str = "3.0.0";

/// The catalog a card is authored for, a surface draws and a render targets:
/// the engine's built-in lens atom kit, or a catalog an app declared by name.
/// On the wire it is one string: `"lens_atom_kit"` or the app catalog's name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GeneratedUiCatalog {
    LensAtomKit,
    App(GeneratedUiCatalogName),
}

impl GeneratedUiCatalog {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::LensAtomKit => LENS_ATOM_KIT_CATALOG,
            Self::App(name) => name.as_str(),
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        if value == LENS_ATOM_KIT_CATALOG {
            return Ok(Self::LensAtomKit);
        }
        GeneratedUiCatalogName::new(value).map(Self::App)
    }
}

impl Serialize for GeneratedUiCatalog {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for GeneratedUiCatalog {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(de::Error::custom)
    }
}

impl schemars::JsonSchema for GeneratedUiCatalog {
    fn schema_name() -> String {
        "GeneratedUiCatalog".to_owned()
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        <String as schemars::JsonSchema>::json_schema(generator)
    }
}

/// A component set's semver (`MAJOR.MINOR.PATCH`, with an optional
/// `-prerelease` and `+build`), the ARCH-0048 G3 `catalogVersion` axis. It is
/// carried as the app declared it and gates nothing on the built-in kit.
#[derive(Debug, Clone, PartialEq, Eq, Hash, schemars::JsonSchema)]
pub struct GeneratedUiCatalogVersion(String);

impl GeneratedUiCatalogVersion {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_semver(&value)?;
        Ok(Self(value))
    }

    /// The built-in kit's component-set version, [`LENS_ATOM_KIT_CATALOG_VERSION`].
    #[must_use]
    pub fn lens_atom_kit() -> Self {
        Self(LENS_ATOM_KIT_CATALOG_VERSION.to_owned())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for GeneratedUiCatalogVersion {
    fn default() -> Self {
        Self::lens_atom_kit()
    }
}

impl fmt::Display for GeneratedUiCatalogVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for GeneratedUiCatalogVersion {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for GeneratedUiCatalogVersion {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// The semver a decoded envelope carries for `catalog`: the one it names, else
/// the built-in kit's own. An app catalog always names its semver.
pub(super) fn catalog_version_or_kit(
    catalog: &GeneratedUiCatalog,
    version: Option<GeneratedUiCatalogVersion>,
) -> Result<GeneratedUiCatalogVersion> {
    match (version, catalog) {
        (Some(version), _) => Ok(version),
        (None, GeneratedUiCatalog::LensAtomKit) => Ok(GeneratedUiCatalogVersion::lens_atom_kit()),
        (None, GeneratedUiCatalog::App(_)) => Err(Error::InvalidConfig(
            "a generated-ui app catalog must declare its catalogVersion".to_string(),
        )),
    }
}

/// Semver 2.0.0 grammar: three numeric core parts without leading zeros, then
/// dot-separated pre-release and build identifiers of ASCII alnum and `-`.
fn validate_semver(value: &str) -> Result<()> {
    let invalid = || {
        Error::InvalidConfig(format!(
            "generated-ui catalogVersion {value:?} must be a semver MAJOR.MINOR.PATCH"
        ))
    };
    if value.len() > MAX_LENS_TOKEN_BYTES {
        return Err(invalid());
    }
    let (rest, build) = match value.split_once('+') {
        Some((rest, build)) => (rest, Some(build)),
        None => (value, None),
    };
    let (core, pre) = match rest.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (rest, None),
    };
    let numeric = |part: &str| {
        !part.is_empty()
            && part.bytes().all(|byte| byte.is_ascii_digit())
            && (part == "0" || !part.starts_with('0'))
    };
    let identifier = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    };
    let parts = core.split('.').collect::<Vec<_>>();
    if parts.len() != 3 || !parts.iter().all(|part| numeric(part)) {
        return Err(invalid());
    }
    if let Some(pre) = pre
        && !pre.split('.').all(|part| {
            identifier(part) && (!part.bytes().all(|byte| byte.is_ascii_digit()) || numeric(part))
        })
    {
        return Err(invalid());
    }
    if let Some(build) = build
        && !build.split('.').all(identifier)
    {
        return Err(invalid());
    }
    Ok(())
}

/// One component an app's catalog declares: its name and the JSON Schema
/// (Draft 2020-12) its props meet. `true` or `{}` admits any props.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GeneratedUiComponentSchema {
    pub name: GeneratedUiComponentName,
    #[serde(default = "admit_any_props")]
    pub schema: serde_json::Value,
}

fn admit_any_props() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

impl GeneratedUiComponentSchema {
    /// Whether `props` meets this declaration's schema. A schema that does not
    /// compile admits nothing, so its component lowers to text.
    pub(super) fn admits(&self, props: &serde_json::Value) -> bool {
        jsonschema::draft202012::new(&self.schema).is_ok_and(|validator| validator.is_valid(props))
    }
}

/// A component catalog as its app declares it (CALLS "FIX 9891 app catalog
/// descriptor"): its name, its semver and its named component schemas. A
/// surface profile names the same three fields inline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GeneratedUiCatalogDescriptor {
    pub catalog: GeneratedUiCatalog,
    pub catalog_version: GeneratedUiCatalogVersion,
    /// An app catalog's components. The built-in kit names none here: its
    /// components are the engine's closed [`LensAtom`](crate::lens::LensAtom)
    /// set, negotiated through a surface's `primitives`.
    #[serde(default)]
    pub components: Vec<GeneratedUiComponentSchema>,
}

impl GeneratedUiCatalogDescriptor {
    /// The built-in lens atom kit at [`LENS_ATOM_KIT_CATALOG_VERSION`].
    #[must_use]
    pub fn lens_atom_kit() -> Self {
        Self {
            catalog: GeneratedUiCatalog::LensAtomKit,
            catalog_version: GeneratedUiCatalogVersion::lens_atom_kit(),
            components: Vec::new(),
        }
    }
}

/// A node drawn by a component the app declared (FIX 9891): the app catalog
/// and component it names, and its props as plain JSON data. It is kept on a
/// surface that declares that catalog and component and whose schema the props
/// meet; on any other surface it lowers to its node's `fallbackText`. It
/// declares no action and grants no read: the card's manifest and backing refs
/// stay engine-authored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GeneratedUiComponentAtom {
    pub catalog: GeneratedUiCatalogName,
    pub name: GeneratedUiComponentName,
    #[serde(default = "admit_any_props")]
    pub props: serde_json::Value,
}

impl GeneratedUiComponentAtom {
    pub(in crate::lens) fn validate(&self) -> Result<()> {
        if !self.props.is_object() {
            return Err(Error::InvalidConfig(
                "generated-ui component props must be a JSON object".to_string(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub(in crate::lens) fn fallback_text(&self) -> LensText {
        fallback_lens_text("component", self.name.as_str().to_owned())
    }
}
