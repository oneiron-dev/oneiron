//! Moved from `crates/oneiron/src/authority/slip.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use ed25519_dalek::Signature;
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use ed25519_dalek::VerifyingKey;
use oneiron_authority::authority::canonical;
use oneiron_authority::federation::Scope;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// A narrowing appended by a holder, without contacting the issuing host.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SlipCaveat {
    pub scope: Option<Scope>,
    pub expires_at: Option<u64>,
    pub ttl_secs: Option<u64>,
    pub single_use: bool,
    pub records: Option<BTreeSet<String>>,
    pub channels: Option<BTreeSet<String>>,
    #[serde(
        default,
        serialize_with = "serialize_pact",
        deserialize_with = "deserialize_pact"
    )]
    #[schemars(with = "Option<(oneiron_authority::federation::ScopeId, Vec<u8>)>")]
    pub pact: Option<(
        oneiron_contracts::entity_id::EntityId,
        oneiron_authority::federation::FederationDirectionScope,
    )>,
    /// A lower comm reach (FIX 3899): the verifier meets it with the slip's,
    /// so a caveat only lowers whom the holder may message. A wider reach is
    /// a new owner mint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comm: Option<super::CommReach>,
}

pub fn serialize_pact<S: serde::Serializer>(
    pact: &Option<(
        oneiron_contracts::entity_id::EntityId,
        oneiron_authority::federation::FederationDirectionScope,
    )>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    pact.as_ref()
        .map(|(grant, bound)| {
            super::encode_value(
                &oneiron_authority::federation::federation_direction_scope_value(bound),
            )
            .map(|bytes| (*grant, bytes))
        })
        .transpose()
        .map_err(serde::ser::Error::custom)?
        .serialize(serializer)
}

pub fn deserialize_pact<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<
    Option<(
        oneiron_contracts::entity_id::EntityId,
        oneiron_authority::federation::FederationDirectionScope,
    )>,
    D::Error,
> {
    let wire =
        Option::<(oneiron_authority::federation::ScopeId, Vec<u8>)>::deserialize(deserializer)?;
    wire.map(|(grant, bytes)| {
        let mut cursor = std::io::Cursor::new(&bytes);
        let value = rmpv::decode::read_value(&mut cursor).map_err(serde::de::Error::custom)?;
        let scope = oneiron_authority::federation::decode_federation_direction_scope_value(&value)
            .map_err(serde::de::Error::custom)?;
        let canonical = super::encode_value(
            &oneiron_authority::federation::federation_direction_scope_value(&scope),
        )
        .map_err(serde::de::Error::custom)?;
        if canonical != bytes {
            return Err(serde::de::Error::custom("noncanonical pact bound"));
        }
        Ok((grant.0, scope))
    })
    .transpose()
}
