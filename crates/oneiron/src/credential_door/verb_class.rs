//! The credential door's class registry (OF-425). It holds two registries:
//!
//! - the door's own operation classes (`door.*`), a static table. A slip
//!   stores class names, not a snapshot of the verbs in each class;
//! - the API classes (`api.read`, `api.write`, `api.destructive`, `api.send`,
//!   `api.pay`, [`ApiVerbClass::registry_class`]), which classify an API
//!   call. Their rows are pack data, never engine policy (ARCH-0069
//!   #door-reads-action): the per-API verb-class tables of the installed
//!   packs that may carry one (`skill_hub::pack_catalog::verb_class_pack`).
use std::collections::BTreeSet;

use heed::RoTxn;
use oneiron_authority::federation::{Scope, ScopeAxis};

use super::api_action::ApiAction;
use crate::Vault;
use crate::error::Result;
use crate::secret_record::ApiVerbClass;

// The registry is resolved at evaluation, not expanded when a slip is minted.
// Only the checkout path mints door.push in production. The other classes
// describe the door's existing operation vocabulary for scoped grants.
const CLASSES: [(&str, &[&str]); 5] = [
    ("door.push", &["receive-pack"]),
    ("door.inject", &["inject"]),
    ("door.lease", &["lease"]),
    ("door.redeem", &["redeem"]),
    ("door.credential", &["inject", "lease", "redeem"]),
];

/// A preset is a six-axis federation Scope, with a CLASS on its verb axis.
pub(super) fn preset(class: &str) -> Option<Scope> {
    CLASSES.iter().find(|(name, _)| *name == class)?;
    Some(Scope {
        verbs: ScopeAxis::Some([class.to_owned()].into()),
        ..Scope::top()
    })
}

/// Resolve membership from the registry on every call. An unknown class or
/// unknown verb confers nothing, even if it appears in an attenuated scope.
pub(super) fn contains(class: &str, verb: &str) -> bool {
    CLASSES
        .iter()
        .find(|(name, _)| *name == class)
        .is_some_and(|(_, verbs)| verbs.contains(&verb))
}

/// Every class the registry says contains this verb, narrowest first.
pub(super) fn classes_for_verb(verb: &str) -> impl Iterator<Item = &'static str> {
    CLASSES
        .iter()
        .filter(move |(_, verbs)| verbs.contains(&verb))
        .map(|(name, _)| *name)
}

/// The narrowest registered class to request when a slip misses a verb.
pub(super) fn class_for_verb(verb: &str) -> Option<&'static str> {
    classes_for_verb(verb).next()
}

/// The API classes of each of `actions`, read in `txn` from every installed
/// table that may class a call: the union of each table's classes, so two
/// packs that class one action both apply and neither needs to outrank the
/// other. An empty set is unknown: no table classes the action.
pub(crate) fn api_verb_classes_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    actions: &[ApiAction],
) -> Result<Vec<BTreeSet<ApiVerbClass>>> {
    let tables = vault.installed_verb_class_tables_in_txn(txn)?;
    Ok(actions
        .iter()
        .map(|action| {
            tables
                .iter()
                .flat_map(|table| table.class_of(action))
                .collect()
        })
        .collect())
}

impl Vault {
    /// The API classes the installed verb-class tables give each of
    /// `actions`, in order; an empty set is unknown. A credential's lending
    /// is resolved against these, and the owner's tooling reads them to show
    /// what a call is.
    pub fn api_verb_classes(&self, actions: &[ApiAction]) -> Result<Vec<BTreeSet<ApiVerbClass>>> {
        let txn = self.store.env.read_txn()?;
        api_verb_classes_in_txn(self, &txn, actions)
    }
}
