//! Symmetric identity-pair claim vocabulary and structural validation.

use rmpv::Value;

use crate::write_envelope::claim_body::{ClaimBody, ClaimSubject};
use oneiron_contracts::entity_id::{ENTITY_ID_LEN, EntityId};
use oneiron_contracts::error::{Error, Result};

/// Predicate of the anti-merge claim (ARCH-0055 §9 G.1 row): symmetric
/// `entity.distinct_from` pair, conflict-set keyed by [`distinct_pair_key`](crate::write_envelope::identity_pair::distinct_pair_key).
/// Unlike the op events (engine-authored type-76 records), distinct_from
/// stays a public CLAIM: it is a statement about the world, not an action.
///
/// The write path is the literal-dispatch arm in
/// `crate::claim::validate_claim_body_and_decode`, which routes every
/// type-0 write of this predicate — the op door's and an agent's alike —
/// through `validate_distinct_from_claim_structure`. It is deliberately
/// NOT a `CLAIM_PREDICATE_REGISTRY` entry: that list is the core/companion/
/// persona LAYER schema list (`registered_predicates_carry_layer_prefix` pins
/// the prefix), and `entity.*` is a family namespace, not a layer — the
/// same reason the fifteen other predicate families validate through their
/// own dispatch arm without a registry row. The registry gates no write
/// (well-formed unknown predicates are accepted), so the arm alone is what
/// enforces the pair.
pub const PREDICATE_ENTITY_DISTINCT_FROM: &str = "entity.distinct_from";

/// Normalized distinct-pair keys (ONE-1746), shared by the type-76
/// `assert_distinct` event body AND the `entity.distinct_from` claim value:
/// one pair shape with one spelling, so the two surfaces cannot drift.
pub const BODY_KEY_PAIR_A: &str = "a";
pub const BODY_KEY_PAIR_B: &str = "b";
/// Normalized symmetric key for a distinct pair: `(min(a, b), max(a, b))`
/// (§9 G.1 `valueKeyFn`), so `assert_distinct(a, b)` and
/// `assert_distinct(b, a)` key to the same claim.
#[must_use]
pub fn distinct_pair_key(a: EntityId, b: EntityId) -> (EntityId, EntityId) {
    if a <= b { (a, b) } else { (b, a) }
}

/// The `entity.distinct_from` claim VALUE for a pair: the normalized
/// symmetric key, so (a, b) and (b, a) encode to identical bytes and the
/// pair is readable without dereferencing the claim's subject.
#[must_use]
pub fn distinct_claim_value(pair: (EntityId, EntityId)) -> Value {
    Value::Map(vec![
        (Value::from(BODY_KEY_PAIR_A), id_value(&pair.0)),
        (Value::from(BODY_KEY_PAIR_B), id_value(&pair.1)),
    ])
}

/// The [`distinct_claim_value`] inverse. Fail-closed: a value that is not a
/// normalized two-id map is not a distinct assertion.
pub fn decode_distinct_claim_pair(value: &Value) -> Result<(EntityId, EntityId)> {
    const PAIR_CONTEXT: &str = "entity.distinct_from claim value must be a normalized id pair";
    let map = value
        .as_map()
        .ok_or(Error::InvalidClaimBody(PAIR_CONTEXT))?;
    let id = |key| {
        let bytes: [u8; ENTITY_ID_LEN] = map_field(map, key)
            .and_then(Value::as_slice)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(Error::InvalidClaimBody(PAIR_CONTEXT))?;
        EntityId::from_bytes(bytes).map_err(|_| Error::InvalidClaimBody(PAIR_CONTEXT))
    };
    let (a, b) = (id(BODY_KEY_PAIR_A)?, id(BODY_KEY_PAIR_B)?);
    // Strictly ascending: `a == b` is the self-assertion the transition
    // table already refuses, and a descending pair is the unnormalized
    // encoding that would let one pair carry two distinct claims.
    if a >= b {
        return Err(Error::InvalidClaimBody(PAIR_CONTEXT));
    }
    Ok((a, b))
}

/// D18 structural validator for the `entity.distinct_from` predicate, run at
/// the shared type-0 write chokepoint on every door that can admit it.
///
/// The symmetry law lives HERE rather than in the op door because the claim
/// is public: an agent minting it directly must land the same single row the
/// engine's `assert_distinct` does. Two bounds do that — the value is the
/// NORMALIZED pair (so both directions encode identically), and the subject
/// is the pair's lexicographically-first entity (so both directions anchor
/// on the same subject and one `claims_for_subject` sweep finds them).
pub fn validate_distinct_from_claim_structure(body: &ClaimBody) -> Result<()> {
    let (a, _) = decode_distinct_claim_pair(&body.value)?;
    if body.subject != ClaimSubject::Entity(a) {
        return Err(Error::InvalidClaimBody(
            "entity.distinct_from subject must be the pair's lexicographically-first entity",
        ));
    }
    Ok(())
}

pub fn id_value(id: &EntityId) -> Value {
    Value::Binary(id.as_bytes().to_vec())
}

pub fn map_field<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(entry_key, _)| entry_key.as_str() == Some(key))
        .map(|(_, entry_value)| entry_value)
}
