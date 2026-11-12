//! The `inquiry_terms` key of the FEDERATION_GRANT body (INQUIRE-1; Engine
//! ruling INQUIRE-SHAPE Q1 = A): the terms of an inquiry edge, on the
//! member vault's Connect guest grant to one company. The key rides exactly
//! the grants whose verbs carry the class `inquire`, and such a grant
//! carries `inquire` alone over the one opened WORLD the terms name: the
//! company never reads the opened scope, it asks. Every other body encodes
//! exactly as before and decodes as carrying no terms.

use rmpv::Value;

use super::{FederationGrant, FederationGrantRole, FederationGrantScope};
use crate::error::Result;
use crate::federation::ScopeAxis;
use crate::federation::codec::{
    decode_canonical_entity_ref, invalid_grant, optional_value, required_value,
};
use crate::inquiry::{InquiryCheckInMode, InquiryKeep, InquiryTerms, InquiryTierCeiling};

/// The one body key of an inquiry edge's terms: a standalone literal, as
/// each optional tail key keeps its own.
pub(super) const KEY_INQUIRY_TERMS: &str = "inquiry_terms";

const INQUIRY_TERMS_VALUE_KEYS: [&str; 4] = [
    "opened_world",
    "tier_ceiling",
    "check_in_mode",
    "keep_allowed",
];

/// The body entry of `grant`'s inquiry terms, when it carries them.
pub(super) fn body_entry(grant: &FederationGrant) -> Option<(Value, Value)> {
    grant.inquiry_terms.as_ref().map(|terms| {
        (
            Value::from(KEY_INQUIRY_TERMS),
            Value::Map(vec![
                (
                    Value::from(INQUIRY_TERMS_VALUE_KEYS[0]),
                    Value::from(terms.opened_world.to_hex()),
                ),
                (
                    Value::from(INQUIRY_TERMS_VALUE_KEYS[1]),
                    Value::from(terms.tier_ceiling.as_str()),
                ),
                (
                    Value::from(INQUIRY_TERMS_VALUE_KEYS[2]),
                    Value::from(terms.check_in_mode.as_str()),
                ),
                (
                    Value::from(INQUIRY_TERMS_VALUE_KEYS[3]),
                    Value::from(terms.keep_allowed.as_str()),
                ),
            ]),
        )
    })
}

/// The inquiry terms a body carries; a malformed value or an unknown token
/// refuses the body.
pub(super) fn decode_body_entry(entries: &[(Value, Value)]) -> Result<Option<InquiryTerms>> {
    let Some(value) = optional_value(entries, KEY_INQUIRY_TERMS) else {
        return Ok(None);
    };
    let Value::Map(terms) = value else {
        return Err(invalid_grant());
    };
    super::validate_scope_keys(terms, &INQUIRY_TERMS_VALUE_KEYS)?;
    Ok(Some(InquiryTerms {
        opened_world: decode_canonical_entity_ref(required_value(
            terms,
            INQUIRY_TERMS_VALUE_KEYS[0],
        )?)?,
        tier_ceiling: InquiryTierCeiling::from_token(token(terms, INQUIRY_TERMS_VALUE_KEYS[1])?)
            .ok_or_else(invalid_grant)?,
        check_in_mode: InquiryCheckInMode::from_token(token(terms, INQUIRY_TERMS_VALUE_KEYS[2])?)
            .ok_or_else(invalid_grant)?,
        keep_allowed: InquiryKeep::from_token(token(terms, INQUIRY_TERMS_VALUE_KEYS[3])?)
            .ok_or_else(invalid_grant)?,
    }))
}

/// The string at `key` of a terms map; any other value refuses the body.
fn token<'terms>(terms: &'terms [(Value, Value)], key: &str) -> Result<&'terms str> {
    required_value(terms, key)?
        .as_str()
        .ok_or_else(invalid_grant)
}

/// The terms and the class go together: a grant carries `inquiry_terms`
/// exactly when its verbs carry `inquire`. Such a grant is a Connect guest
/// grant with no ask payload, its verbs are `inquire` alone, and its one
/// world is the opened WORLD the terms name.
pub(super) fn validate(grant: &FederationGrant) -> Result<()> {
    // Named, never through a top axis: an Owner's top-scope grant names no
    // class and carries no terms.
    let inquire = matches!(&grant.authority_scope.verbs, ScopeAxis::Some(verbs)
        if verbs.contains(crate::federation::INQUIRE_VERB_CLASS));
    match &grant.inquiry_terms {
        None if inquire => Err(invalid_grant()),
        None => Ok(()),
        Some(terms) => {
            let inquire_alone = matches!(&grant.authority_scope.verbs, ScopeAxis::Some(verbs)
                if verbs.len() == 1 && inquire);
            let opened_world_alone = matches!(&grant.authority_scope.worlds, ScopeAxis::Some(worlds)
                if worlds.len() == 1 && worlds.iter().all(|world| world.0 == terms.opened_world));
            if grant.role != FederationGrantRole::Guest
                || !matches!(grant.scope, FederationGrantScope::Connect { .. })
                || grant.guest.is_some()
                || !inquire_alone
                || !opened_world_alone
            {
                return Err(invalid_grant());
            }
            Ok(())
        }
    }
}
