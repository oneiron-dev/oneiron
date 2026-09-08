//! Interlocutor-set resolution and third-party party inputs for context-pack requests.

use super::super::{core_engine_error, parse_entity_id_param};
use super::controls::{
    CoreInterlocutorControls, CoreInterlocutorParty, MAX_INTERLOCUTOR_COUNTERPARTY_BYTES,
    MAX_INTERLOCUTOR_LABEL_BYTES, MAX_INTERLOCUTOR_THIRD_PARTIES,
};
use crate::auth::CoreAuth;
use crate::error::ApiError;

/// Resolves the effective interlocutor set for a core context-pack request
/// (OF-365 ILD-1, design §11).
///
/// Returns `None` exactly when no interlocutors block was supplied on an
/// owner-grade credential: that request/response pair stays byte-identical to
/// pre-ILD behavior. In every other case the resolved set is echoed as
/// stamps on the response.
///
/// Owner-grade is `CoreAuth::is_owner_grade` — un-narrowed on BOTH axes. A
/// delegated token narrowed by scope alone is NOT owner-grade, so it takes
/// the clamp like any other narrowed credential rather than silently
/// skipping the gate.
pub(crate) fn resolve_core_interlocutor_set(
    vault: &oneiron::Vault,
    auth: &CoreAuth,
    controls: Option<&CoreInterlocutorControls>,
) -> Result<Option<oneiron::InterlocutorSet>, ApiError> {
    if controls.is_none() && auth.is_owner_grade() {
        return Ok(None);
    }

    let mut owner_present = None;
    let mut parties = Vec::new();
    let mut voice_session_ref = None;
    if let Some(controls) = controls {
        if controls.owner_present == Some(true) && !auth.is_owner_grade() {
            return Err(ApiError::forbidden_scope("interlocutors.owner_present"));
        }
        if controls.third_parties.len() > MAX_INTERLOCUTOR_THIRD_PARTIES {
            return Err(ApiError::bad_request(
                format!(
                    "third_parties must contain at most {MAX_INTERLOCUTOR_THIRD_PARTIES} entries"
                ),
                Some("interlocutors.third_parties"),
            ));
        }
        owner_present = controls.owner_present;
        for (index, party) in controls.third_parties.iter().enumerate() {
            parties.push(core_interlocutor_party_input(party, index)?);
        }
        voice_session_ref = controls.voice_session_ref.clone();
    }

    // Merge-always (RATIFY-20260710 R8): on principal_ref auth the implicit
    // principal-derived party ALWAYS enters the resolved set, regardless of
    // block presence, so DEC-0005 scope intersection can only narrow.
    if let Some(principal_ref) = auth.principal_ref() {
        let principal_id = parse_entity_id_param(principal_ref, "principal_ref")?;
        let party = match vault.get_counterparty_contact(&principal_id) {
            Ok(Some(_)) => oneiron::InterlocutorPartyInput::ContactRef(principal_id),
            // Companion principals are person/persona ids, not contact rows.
            Ok(None) | Err(oneiron::Error::InvalidEntityType(_)) => {
                oneiron::InterlocutorPartyInput::UnknownLabel {
                    label: principal_id.to_hex(),
                    claimed_owner: false,
                }
            }
            Err(error) => {
                tracing::error!(
                    error = %error,
                    "core context-pack interlocutor principal lookup failed"
                );
                return Err(core_engine_error(
                    "core context-pack interlocutor principal lookup failed",
                    error,
                ));
            }
        };
        parties.push(party);
    }

    // Owner presence is a conjunction, never a request assertion: the
    // credential must be owner-grade AND the caller must not have narrowed
    // itself away. `owner_present == Some(true)` was already rejected above
    // for non-owner-grade auth, so the `&&` here is the belt to that
    // suspenders — a narrowed credential can only ever resolve to `false`.
    let owner_session = auth.is_owner_grade() && owner_present.unwrap_or(true);
    let input = oneiron::InterlocutorResolutionInput {
        owner_session,
        parties,
        voice_session_ref,
    };
    vault
        .resolve_interlocutors(&input)
        .map(Some)
        .map_err(|error| {
            tracing::error!(error = %error, "core context-pack interlocutor resolution failed");
            core_engine_error("core context-pack interlocutor resolution failed", error)
        })
}

pub(crate) fn core_interlocutor_party_input(
    party: &CoreInterlocutorParty,
    index: usize,
) -> Result<oneiron::InterlocutorPartyInput, ApiError> {
    let field_path = |field: &str| format!("interlocutors.third_parties[{index}].{field}");
    let reject_claimed_owner = |party: &CoreInterlocutorParty| {
        if party.claimed_owner.is_some() {
            Err(ApiError::bad_request(
                "claimed_owner is only valid alongside label",
                Some(&field_path("claimed_owner")),
            ))
        } else {
            Ok(())
        }
    };
    match (
        party.contact_ref.as_deref(),
        party.channel_identity_ref.as_deref(),
        party.counterparty.as_deref(),
        party.label.as_deref(),
    ) {
        (Some(contact_ref), None, None, None) => {
            reject_claimed_owner(party)?;
            let field = field_path("contact_ref");
            let id = oneiron::EntityId::from_hex(contact_ref).map_err(|_| {
                ApiError::bad_request(
                    "contact_ref must be a 32-character hex entity id",
                    Some(&field),
                )
            })?;
            Ok(oneiron::InterlocutorPartyInput::ContactRef(id))
        }
        (None, Some(channel_identity_ref), Some(counterparty), None) => {
            reject_claimed_owner(party)?;
            let field = field_path("channel_identity_ref");
            let identity_ref = oneiron::EntityId::from_hex(channel_identity_ref).map_err(|_| {
                ApiError::bad_request(
                    "channel_identity_ref must be a 32-character hex entity id",
                    Some(&field),
                )
            })?;
            if counterparty.trim().is_empty() {
                return Err(ApiError::bad_request(
                    "counterparty must be non-empty",
                    Some(&field_path("counterparty")),
                ));
            }
            // Engine invariant enforced at the boundary: an untrimmed or
            // over-long key would otherwise surface from the contact lookup
            // as an engine error instead of a client error.
            if counterparty.trim() != counterparty
                || counterparty.len() > MAX_INTERLOCUTOR_COUNTERPARTY_BYTES
            {
                return Err(ApiError::bad_request(
                    format!(
                        "counterparty must be trimmed and at most \
                         {MAX_INTERLOCUTOR_COUNTERPARTY_BYTES} bytes"
                    ),
                    Some(&field_path("counterparty")),
                ));
            }
            Ok(oneiron::InterlocutorPartyInput::ChannelCounterparty {
                identity_ref,
                counterparty: counterparty.to_owned(),
            })
        }
        (None, None, None, Some(label)) => {
            if label.trim().is_empty() {
                return Err(ApiError::bad_request(
                    "label must be non-empty",
                    Some(&field_path("label")),
                ));
            }
            if label.len() > MAX_INTERLOCUTOR_LABEL_BYTES {
                return Err(ApiError::bad_request(
                    format!("label must be at most {MAX_INTERLOCUTOR_LABEL_BYTES} bytes"),
                    Some(&field_path("label")),
                ));
            }
            Ok(oneiron::InterlocutorPartyInput::UnknownLabel {
                label: label.to_owned(),
                claimed_owner: party.claimed_owner.unwrap_or(false),
            })
        }
        _ => Err(ApiError::bad_request(
            "each third party must supply exactly one of contact_ref, \
             channel_identity_ref+counterparty, or label",
            Some(&format!("interlocutors.third_parties[{index}]")),
        )),
    }
}
