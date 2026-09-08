//! Versioned [`GeneratedLens`] envelope: wire pair, load-action decision, allocation-guarded wire validation.

use crate::lens::atom::{LENS_ATOM_KIT_VERSION, LensNode, LensNodeSeed};
use crate::lens::validate::validate_lens_tree;
use crate::{Error, Result};
use serde::{Deserialize, Deserializer, Serialize, de};
use std::fmt;

pub const GENERATED_UI_WIRE_VERSION: u16 = 2;

pub const GENERATED_UI_SEGMENT_CONTENT_TYPE: &str =
    "application/vnd.oneiron.generated-ui.segment+json";

/// The oldest atom-kit version an envelope may declare. There is no valid v1 envelope:
/// v1 predates the mandatory per-node `fallbackText`, so it is rejected by version
/// rather than sharing v2 semantics.
const MIN_LENS_ATOM_KIT_VERSION: u16 = 2;

/// The highest minimum catalog version any atom in this tree needs. A tree that uses
/// only pre-v3 atoms answers `2` however far [`LENS_ATOM_KIT_VERSION`] has moved on.
fn contained_atom_kit_version(root: &LensNode) -> u16 {
    let mut minimum = MIN_LENS_ATOM_KIT_VERSION;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        minimum = minimum.max(node.atom.primitive().minimum_catalog_version());
        stack.extend(node.children.iter());
    }
    minimum
}

/// The apps-contract revision a lens body was generated against. It answers "was this
/// body compiled for the shell contracts this build ships?", which is a different
/// question from [`LENS_ATOM_KIT_VERSION`]'s "which atoms may this tree contain?".
/// The first stamped revision is `1`; it moves independently of the atom-kit constant.
pub const LENS_APPS_CONTRACT_VERSION: u16 = 1;

/// The version pair carried in a lens body. Both components are body data, so a decoded
/// revision can be compared against the running constants without re-parsing anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LensVersionStamp {
    kit_version: u16,
    apps_contract_version: u16,
}

impl LensVersionStamp {
    #[must_use]
    pub const fn new(kit_version: u16, apps_contract_version: u16) -> Self {
        Self {
            kit_version,
            apps_contract_version,
        }
    }

    /// The pair a freshly regenerated body must carry. Regeneration always targets this
    /// pair; a stale body is never auto-stamped with it.
    #[must_use]
    pub const fn current() -> Self {
        Self::new(LENS_ATOM_KIT_VERSION, LENS_APPS_CONTRACT_VERSION)
    }

    #[must_use]
    pub const fn kit_version(self) -> u16 {
        self.kit_version
    }

    #[must_use]
    pub const fn apps_contract_version(self) -> u16 {
        self.apps_contract_version
    }
}

/// What a shell loader must do with a decoded lens body. This names caller work rather
/// than performing it: there is no queue trait, storage import, or mount mutation here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LensLoadAction {
    MountCurrent,
    MountLastGoodAndQueueRegeneration {
        stored: LensVersionStamp,
        live: LensVersionStamp,
    },
}

/// Exact pair equality means current. "Differs" is symmetric: a stamp older *or* newer
/// than the running constants both mount the decoded body as last-good and queue
/// regeneration against the live pair.
#[must_use]
pub const fn lens_load_action(stored: LensVersionStamp, live: LensVersionStamp) -> LensLoadAction {
    if stored.kit_version == live.kit_version
        && stored.apps_contract_version == live.apps_contract_version
    {
        LensLoadAction::MountCurrent
    } else {
        LensLoadAction::MountLastGoodAndQueueRegeneration { stored, live }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GeneratedLens {
    kit_version: u16,
    apps_contract_version: u16,
    root: LensNode,
}

impl GeneratedLens {
    /// Stamp the live pair, [`LensVersionStamp::current`]: a body built here was by
    /// construction compiled against the atom kit and the shell contracts this build
    /// ships, so it is exactly what [`lens_load_action`] calls current and what
    /// [`regenerate_lens`] accepts as a candidate for the requested target.
    ///
    /// Neither component is derived from the tree. The contained-atom minimum is a
    /// *floor* an envelope may not under-declare (see the tree validator below), never
    /// the stamp: stamping it would mint bodies that are born stale against the running
    /// constants, so every freshly built pre-v3 card would report
    /// [`LensLoadAction::MountLastGoodAndQueueRegeneration`] and a regenerator using
    /// this constructor could never match its own target. The accepted consequence is
    /// that a v2-only surface re-negotiates after a kit bump like any other body.
    ///
    /// The apps-contract component records the shell contracts this body was generated
    /// against, so it is likewise always the running [`LENS_APPS_CONTRACT_VERSION`].
    pub fn new(root: LensNode) -> Result<Self> {
        let current = LensVersionStamp::current();
        let lens = Self {
            kit_version: current.kit_version(),
            apps_contract_version: current.apps_contract_version(),
            root,
        };
        lens.validate()?;
        Ok(lens)
    }

    #[must_use]
    pub const fn kit_version(&self) -> u16 {
        self.kit_version
    }

    #[must_use]
    pub const fn apps_contract_version(&self) -> u16 {
        self.apps_contract_version
    }

    #[must_use]
    pub const fn version_stamp(&self) -> LensVersionStamp {
        LensVersionStamp::new(self.kit_version, self.apps_contract_version)
    }

    #[must_use]
    pub fn root(&self) -> &LensNode {
        &self.root
    }

    #[must_use]
    pub fn into_root(self) -> LensNode {
        self.root
    }

    pub(super) fn validate(&self) -> Result<()> {
        validate_lens_tree(&self.root)?;
        // Version negotiation is decided after decode, against the atoms actually
        // present: an envelope may not under-declare its way past a surface check.
        let required = contained_atom_kit_version(&self.root);
        if self.kit_version < required {
            return Err(Error::InvalidConfig(format!(
                "generated lens atom kit version {} must be at least {required} for its atoms",
                self.kit_version
            )));
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for GeneratedLens {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            KitVersion,
            AppsContractVersion,
            Root,
        }

        struct GeneratedLensVisitor;

        impl<'de> de::Visitor<'de> for GeneratedLensVisitor {
            type Value = GeneratedLens;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("generated lens envelope")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut kit_version = None;
                let mut apps_contract_version = None;
                let mut root = None;
                let mut skipped_root_before_versions = false;

                while let Some(field) = map.next_key::<Field>()? {
                    match field {
                        Field::KitVersion => {
                            if kit_version.is_some() {
                                return Err(de::Error::duplicate_field("kit_version"));
                            }
                            // Deliberately no window check: a stamp older or newer than
                            // the running constants is stale *state*, not a decode
                            // error, so a decodable last-good body still loads while
                            // regeneration is queued. `lens_load_action` owns that
                            // decision; unknown atom kinds and invalid payloads still
                            // fail closed below through the closed-enum tree validator.
                            kit_version = Some(map.next_value::<u16>()?);
                        }
                        Field::AppsContractVersion => {
                            if apps_contract_version.is_some() {
                                return Err(de::Error::duplicate_field("apps_contract_version"));
                            }
                            apps_contract_version = Some(map.next_value::<u16>()?);
                        }
                        Field::Root => {
                            if root.is_some() || skipped_root_before_versions {
                                return Err(de::Error::duplicate_field("root"));
                            }
                            // Either stamp field may come first, but both must precede
                            // the tree: skipping the body preserves the shipped
                            // allocation guard against an unversioned oversized root.
                            if kit_version.is_none() || apps_contract_version.is_none() {
                                map.next_value::<de::IgnoredAny>()?;
                                skipped_root_before_versions = true;
                            } else {
                                root = Some(map.next_value::<LensNode>()?);
                            }
                        }
                    }
                }

                // Fixed post-map order: missing kit_version, then missing
                // apps_contract_version, then precedence, then a missing root.
                let kit_version =
                    kit_version.ok_or_else(|| de::Error::missing_field("kit_version"))?;
                let apps_contract_version = apps_contract_version
                    .ok_or_else(|| de::Error::missing_field("apps_contract_version"))?;
                if skipped_root_before_versions {
                    return Err(de::Error::custom(
                        "generated lens version fields must precede root",
                    ));
                }
                let root = root.ok_or_else(|| de::Error::missing_field("root"))?;
                let lens = GeneratedLens {
                    kit_version,
                    apps_contract_version,
                    root,
                };
                lens.validate().map_err(de::Error::custom)?;
                Ok(lens)
            }

            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                // Positional form: 0 = kit_version, 1 = apps_contract_version, 2 = root.
                // The pair is not compared to the live constants here either.
                let kit_version = seq
                    .next_element::<u16>()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let apps_contract_version = seq
                    .next_element::<u16>()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let root = seq
                    .next_element_seed(LensNodeSeed { depth: 1 })?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;
                if seq.next_element::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::invalid_length(4, &self));
                }

                let lens = GeneratedLens {
                    kit_version,
                    apps_contract_version,
                    root,
                };
                lens.validate().map_err(de::Error::custom)?;
                Ok(lens)
            }
        }

        deserializer.deserialize_struct(
            "GeneratedLens",
            &["kit_version", "apps_contract_version", "root"],
            GeneratedLensVisitor,
        )
    }
}
