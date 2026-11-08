//! The one resolver of an owner's agent Grant's verb classes (FIX 8735,
//! Engine 18:26 = A; DEC-0006 invariant 3).
//!
//! An owner's agent Grant names exact verbs and, beside them, optional verb
//! classes. A class admits a verb by its own spelling, by the built-in
//! outbound class registry (`outbound_grant::outbound_verb_in_class`), or by
//! the owner's verb-class row for that class in the reader's snapshot
//! (`gate::policy_manifest_doors`, `vault.agents.verb_classes.configure`).
//! A door that judges an agent Grant's verb reads the rows once per
//! judgment ([`AgentVerbClasses::for_grants_in_txn`]) and passes them in,
//! so the snapshot-free half of the standing rule stays snapshot-free. A
//! Grant that names no class reads no row and judges exactly as before; a
//! verb outside a classed Grant's exact verbs and classes is refused as
//! before. The envelope is the class set the Grant names: no count, value or
//! time bound rides it.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use super::{FederationGrant, Scope, ScopeAxis};
use crate::error::Result;

/// The verb a Grant lists to confer at all ([`FederationGrant::confers_at`]).
const CONFERRING_VERB: &str = "read";

/// The owner's verb-class rows as one judgment reads them: each class and
/// its member verbs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AgentVerbClasses {
    rows: BTreeMap<String, BTreeSet<String>>,
}

impl AgentVerbClasses {
    /// No owner rows: a classed Grant admits only its classes' own spellings
    /// and the built-in outbound classes.
    #[must_use]
    pub(crate) fn none() -> Self {
        Self::default()
    }

    /// The owner's rows `txn` holds, read through `store` only when one of
    /// `grants` names a class; [`Self::none`] otherwise, so a judgment over
    /// unclassed Grants reads nothing new.
    ///
    /// # Errors
    /// A store read failure.
    pub(crate) fn for_grants_in_txn<G: std::borrow::Borrow<FederationGrant>>(
        store: &crate::store::Store,
        txn: &heed::RoTxn<'_>,
        grants: impl IntoIterator<Item = G>,
    ) -> Result<Self> {
        if grants
            .into_iter()
            .all(|grant| grant.borrow().verb_classes.is_empty())
        {
            return Ok(Self::none());
        }
        Ok(Self {
            rows: crate::gate::policy_manifest_doors::agent_verb_class_rows_for_store_in_txn(
                store, txn,
            )?,
        })
    }

    /// Whether the class `class` admits `verb`: its own spelling, a member
    /// the built-in outbound registry lists for it, or a member of the
    /// owner's row for it.
    #[must_use]
    pub(crate) fn class_admits(&self, class: &str, verb: &str) -> bool {
        class == verb
            || crate::outbound_grant::outbound_verb_in_class(class, verb)
            || self
                .rows
                .get(class)
                .is_some_and(|verbs| verbs.contains(verb))
    }

    /// The verbs `class` names by spelling: its own and its owner row's
    /// members. The built-in outbound registry adds only send verbs, so a
    /// reader that enumerates one verb family other than those (the `ai.*`
    /// operations) reads it whole here.
    pub(crate) fn spelled_verbs<'a>(&'a self, class: &'a str) -> impl Iterator<Item = &'a str> {
        std::iter::once(class).chain(
            self.rows
                .get(class)
                .into_iter()
                .flat_map(|verbs| verbs.iter().map(String::as_str)),
        )
    }
}

impl FederationGrant {
    /// Whether one of the verb classes this Grant names admits `verb` under
    /// `classes`. False for every Grant that names none.
    #[must_use]
    pub(crate) fn class_admits_verb(&self, verb: &str, classes: &AgentVerbClasses) -> bool {
        self.verb_classes
            .iter()
            .any(|class| classes.class_admits(class, verb))
    }

    /// Whether this Grant admits `verb`: its explicit verb set lists it (a
    /// Grant over every verb lists none), or a class it names admits it.
    #[must_use]
    pub(crate) fn admits_verb(&self, verb: &str, classes: &AgentVerbClasses) -> bool {
        matches!(&self.authority_scope.verbs, ScopeAxis::Some(verbs) if verbs.contains(verb))
            || self.class_admits_verb(verb, classes)
    }

    /// This Grant's Scope for one judgment of `verb`: its own Scope, or,
    /// when a class it names admits `verb` that its verbs axis does not
    /// cover, that Scope with `verb` added to its explicit verbs. Every other
    /// axis is its own, so a door's resource checks read the Grant as they
    /// always did.
    #[must_use]
    pub(crate) fn scope_for_verb(&self, verb: &str, classes: &AgentVerbClasses) -> Cow<'_, Scope> {
        let verb = verb.to_owned();
        if self.authority_scope.verbs.contains(&verb) || !self.class_admits_verb(&verb, classes) {
            return Cow::Borrowed(&self.authority_scope);
        }
        let mut scope = self.authority_scope.clone();
        scope.verbs = match scope.verbs {
            ScopeAxis::Some(mut verbs) => {
                verbs.insert(verb);
                ScopeAxis::Some(verbs)
            }
            ScopeAxis::Bottom | ScopeAxis::All => ScopeAxis::Some(BTreeSet::from([verb])),
        };
        Cow::Owned(scope)
    }

    /// [`Self::confers_at`] with `read` (the verb a conferring Grant lists)
    /// admitted by a class this Grant names as well as by its exact verbs. A
    /// Grant that names no class confers exactly as [`Self::confers_at`]
    /// says.
    #[must_use]
    pub(crate) fn confers_with_classes_at(
        &self,
        now_secs: u64,
        classes: &AgentVerbClasses,
    ) -> bool {
        Self::scope_confers_at(
            &self.scope_for_verb(CONFERRING_VERB, classes),
            self.kind,
            self.expires_at,
            now_secs,
        )
    }
}
