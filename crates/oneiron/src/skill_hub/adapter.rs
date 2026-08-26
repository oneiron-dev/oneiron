use std::collections::BTreeMap;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::package::{HubIndexEntry, HubPackage};
use super::record::{HubPin, HubRef, SkillHubKind};

/// Pluggable package-fetch boundary behind the hub doors.
pub trait SkillHubAdapter {
    /// Hub entity whose refs this adapter resolves.
    fn hub_id(&self) -> EntityId;

    /// Adapter kind compatible with the hub record.
    fn kind(&self) -> SkillHubKind;

    /// Fetches a package for a structured ref.
    fn fetch_package(&self, hub_ref: &HubRef) -> Result<HubPackage>;

    /// Returns discovery rows when the adapter exposes an index.
    fn discover(&self) -> Result<Vec<HubIndexEntry>> {
        Ok(Vec::new())
    }
}

#[derive(Debug, Clone, Default)]
struct AdapterPackageStore {
    packages: BTreeMap<(String, HubPin), HubPackage>,
}

impl AdapterPackageStore {
    fn insert(&mut self, ref_string: impl Into<String>, pin: HubPin, package: HubPackage) {
        self.packages.insert((ref_string.into(), pin), package);
    }

    fn fetch(&self, hub_ref: &HubRef) -> Result<HubPackage> {
        self.packages
            .get(&(hub_ref.ref_string.clone(), hub_ref.pin.clone()))
            .cloned()
            .ok_or(Error::InvalidSkillBody("hub ref package was not found"))
    }
}

macro_rules! package_adapter {
    ($name:ident, $kind:expr) => {
        #[doc = "In-process package source for the generic adapter boundary."]
        #[derive(Debug, Clone)]
        pub struct $name {
            hub_id: EntityId,
            store: AdapterPackageStore,
        }

        impl $name {
            /// Constructs an empty adapter bound to one hub entity.
            #[must_use]
            pub fn new(hub_id: EntityId) -> Self {
                Self {
                    hub_id,
                    store: AdapterPackageStore::default(),
                }
            }

            /// Adds a fetchable offline package.
            pub fn insert_package(
                &mut self,
                ref_string: impl Into<String>,
                pin: HubPin,
                package: HubPackage,
            ) {
                self.store.insert(ref_string, pin, package);
            }
        }

        impl SkillHubAdapter for $name {
            fn hub_id(&self) -> EntityId {
                self.hub_id
            }

            fn kind(&self) -> SkillHubKind {
                $kind
            }

            fn fetch_package(&self, hub_ref: &HubRef) -> Result<HubPackage> {
                if hub_ref.hub_id != self.hub_id {
                    return Err(Error::InvalidSkillBody(
                        "adapter cannot fetch a ref from another hub",
                    ));
                }
                self.store.fetch(hub_ref)
            }
        }
    };
}

package_adapter!(GitSkillHubAdapter, SkillHubKind::Git);
package_adapter!(LocalDirSkillHubAdapter, SkillHubKind::LocalDir);

/// Generic discovery-index adapter with injected index and package data.
#[derive(Debug, Clone)]
pub struct HttpIndexSkillHubAdapter {
    hub_id: EntityId,
    index: Vec<HubIndexEntry>,
    store: AdapterPackageStore,
}

impl HttpIndexSkillHubAdapter {
    /// Constructs an adapter bound to one hub entity.
    #[must_use]
    pub fn new(hub_id: EntityId, index: Vec<HubIndexEntry>) -> Self {
        Self {
            hub_id,
            index,
            store: AdapterPackageStore::default(),
        }
    }

    /// Adds a package fetchable from an index row's ref string.
    pub fn insert_package(
        &mut self,
        ref_string: impl Into<String>,
        pin: HubPin,
        package: HubPackage,
    ) {
        self.store.insert(ref_string, pin, package);
    }
}

impl SkillHubAdapter for HttpIndexSkillHubAdapter {
    fn hub_id(&self) -> EntityId {
        self.hub_id
    }

    fn kind(&self) -> SkillHubKind {
        SkillHubKind::HttpIndex
    }

    fn fetch_package(&self, hub_ref: &HubRef) -> Result<HubPackage> {
        if hub_ref.hub_id != self.hub_id {
            return Err(Error::InvalidSkillBody(
                "adapter cannot fetch a ref from another hub",
            ));
        }
        self.store.fetch(hub_ref)
    }

    fn discover(&self) -> Result<Vec<HubIndexEntry>> {
        Ok(self.index.clone())
    }
}
