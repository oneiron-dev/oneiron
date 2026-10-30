//! Which model routes a call on some worlds may take, and in what order: the
//! worlds' model orders (DEC-0005 #world-privacy-models; FIX 11309), the one
//! rung choice every model input asks before it walks its own rungs. A world
//! that inherits leaves the vault's order (the caller's deployment posture)
//! as it is; a world's own order is the owner's pick for that world, so no
//! rung it does not name takes the world's rows, and a cloud provider is
//! never a silent fallback.

use super::{AuthorityFold, EffectiveModelOrder, ModelOrder};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// The routes a call on some worlds may take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorldModelRoutes {
    /// Every world inherits the vault's order: the caller's own rungs, in
    /// its own order.
    Inherit,
    /// Only these routes, in this order. Empty when the worlds' orders name
    /// no route in common: no rung takes the call.
    Ordered(Vec<String>),
}

impl WorldModelRoutes {
    /// The meet of two choices: an inheriting one adds nothing; two orders
    /// keep the routes both name, in `self`'s order. Stricter wins, never
    /// the last writer.
    #[must_use]
    pub fn meet(self, other: Self) -> Self {
        match (self, other) {
            (Self::Inherit, other) => other,
            (ordered, Self::Inherit) => ordered,
            (Self::Ordered(mut left), Self::Ordered(right)) => {
                left.retain(|route| right.contains(route));
                Self::Ordered(left)
            }
        }
    }

    /// `rungs`, each named by `route`, in the order this choice takes them:
    /// all of them, in their own order, under [`Self::Inherit`]; else only
    /// the rungs a route names, in the routes' order.
    #[must_use]
    pub fn order<'a, T>(&self, rungs: &'a [T], route: impl Fn(&T) -> &str) -> Vec<&'a T> {
        match self {
            Self::Inherit => rungs.iter().collect(),
            Self::Ordered(routes) => {
                let mut ordered = Vec::new();
                for named in routes {
                    ordered.extend(rungs.iter().filter(|rung| route(*rung) == named.as_str()));
                }
                ordered
            }
        }
    }

    /// Whether a rung named `route` may take the call.
    #[must_use]
    pub fn admits(&self, route: &str) -> bool {
        match self {
            Self::Inherit => true,
            Self::Ordered(routes) => routes.iter().any(|named| named == route),
        }
    }
}

impl From<&ModelOrder> for WorldModelRoutes {
    fn from(order: &ModelOrder) -> Self {
        match order {
            ModelOrder::Inherit => Self::Inherit,
            ModelOrder::Ordered(routes) => Self::Ordered(routes.clone()),
        }
    }
}

impl AuthorityFold {
    /// The routes a call reading `worlds` may take (FIX 11309): the meet of
    /// each world's order ([`WorldModelRoutes::meet`]), a world nobody
    /// edited inheriting. A world whose concurrent edits named different
    /// orders is judged by every live edit's own order, met the same way.
    /// Under a conflicted vault root the fold knows no world's order, and
    /// the read setting already keeps every world from leaving: the vault's
    /// order stands.
    #[must_use]
    pub fn world_model_routes(
        &self,
        worlds: impl IntoIterator<Item = EntityId>,
    ) -> WorldModelRoutes {
        if self.vault_root_is_conflicted() {
            return WorldModelRoutes::Inherit;
        }
        let mut routes = WorldModelRoutes::Inherit;
        for world in worlds {
            let Some(folded) = self.worlds.get(&world) else {
                continue;
            };
            let own = match &folded.effective.models {
                EffectiveModelOrder::Inherit => WorldModelRoutes::Inherit,
                EffectiveModelOrder::Ordered(order) => WorldModelRoutes::Ordered(order.clone()),
                EffectiveModelOrder::Conflicted => folded
                    .live_settings
                    .values()
                    .map(|settings| WorldModelRoutes::from(&settings.models))
                    .fold(WorldModelRoutes::Inherit, WorldModelRoutes::meet),
            };
            routes = routes.meet(own);
        }
        routes
    }
}

impl Vault {
    /// [`AuthorityFold::world_model_routes`] as this vault's authority fold
    /// reads in `txn`: the rung choice a model call on `worlds` asks.
    ///
    /// # Errors
    ///
    /// Storage errors, or an authority log that does not fold.
    pub(crate) fn world_model_routes_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        worlds: impl IntoIterator<Item = EntityId>,
    ) -> Result<WorldModelRoutes> {
        Ok(self
            .authority_view_readonly_in_txn(txn)?
            .world_model_routes(worlds))
    }

    /// [`Self::world_model_routes_in_txn`] in a read of its own.
    ///
    /// # Errors
    ///
    /// Storage errors, or an authority log that does not fold.
    pub fn world_model_routes(
        &self,
        worlds: impl IntoIterator<Item = EntityId>,
    ) -> Result<WorldModelRoutes> {
        let rtxn = self.store.env.read_txn()?;
        self.world_model_routes_in_txn(&rtxn, worlds)
    }
}
