//! The `verb_classes` key of the FEDERATION_GRANT body (FIX 8735): the verb
//! classes an owner gave his agent beside its exact verbs, in the one codec
//! his signed mint act uses too (`oneiron_authority::federation::
//! verb_classes`). Only an owner's Access agent grant carries the key, and
//! only when he named a class; every other body, and an agent grant without
//! classes, encodes exactly as before and decodes as naming none.

use std::collections::BTreeSet;

use oneiron_authority::federation::{
    decode_verb_classes_value, verb_class_name_is_valid, verb_classes_value,
};
use rmpv::Value;

use super::FederationGrant;
use crate::error::Result;
use crate::federation::FederationGrantKind;
use crate::federation::codec::{invalid_grant, optional_value};

pub(super) const KEY_VERB_CLASSES: &str = "verb_classes";

/// The body entry of `grant`'s verb classes, when it names any.
pub(super) fn body_entry(grant: &FederationGrant) -> Option<(Value, Value)> {
    (!grant.verb_classes.is_empty()).then(|| {
        (
            Value::from(KEY_VERB_CLASSES),
            verb_classes_value(&grant.verb_classes),
        )
    })
}

/// The verb classes a body names; none when the key is absent. A malformed
/// value refuses the body.
pub(super) fn decode_body_entry(entries: &[(Value, Value)]) -> Result<BTreeSet<String>> {
    optional_value(entries, KEY_VERB_CLASSES)
        .map(|value| decode_verb_classes_value(value).ok_or_else(invalid_grant))
        .transpose()
        .map(Option::unwrap_or_default)
}

/// Verb classes ride an owner's Access agent grant only, each a valid name.
pub(super) fn validate(grant: &FederationGrant) -> Result<()> {
    if grant.verb_classes.is_empty() {
        return Ok(());
    }
    if !grant.owner_agent
        || grant.kind != FederationGrantKind::Access
        || !grant
            .verb_classes
            .iter()
            .all(|class| verb_class_name_is_valid(class))
    {
        return Err(invalid_grant());
    }
    Ok(())
}
