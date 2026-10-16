//! Interlocutor-set resolution and third-party party inputs for context-pack requests.

use super::super::{core_engine_error, parse_entity_id_param};
use super::controls::{
    CoreInterlocutorControls, CoreInterlocutorParty, MAX_INTERLOCUTOR_COUNTERPARTY_BYTES,
    MAX_INTERLOCUTOR_LABEL_BYTES, MAX_INTERLOCUTOR_THIRD_PARTIES,
};
use crate::auth::CoreAuth;
use crate::error::ApiError;
use std::collections::{BTreeMap, BTreeSet};

/// Resolves the effective interlocutor set for a core context-pack request
/// (OF-365 ILD-1, design §11).
///
/// Returns `None` exactly when no interlocutors block AND no room was
/// supplied on an owner-grade credential: that request/response pair stays
/// byte-identical to pre-ILD behavior. Room reads always receive the roster
/// clamp; the resolved set is echoed as stamps on the response.
///
/// Owner-grade is `CoreAuth::is_owner_grade` — un-narrowed on BOTH axes. A
/// delegated token narrowed by scope alone is NOT owner-grade, so it takes
/// the clamp like any other narrowed credential rather than silently
/// skipping the gate. `room` is a room read's [`RoomAudience`].
///
/// Every contact the set names is one `read`, the caller's own read, reads:
/// one it cannot read resolves as a missing one does, so a narrowed caller
/// learns no contact's existence, status, label or id by naming it. A voice
/// roster's segments carry no record scope, so it resolves only for the
/// owner's own unnarrowed read (`ScopedRead::is_unnarrowed_owner`).
pub(crate) fn resolve_core_interlocutor_set(
    vault: &oneiron::Vault,
    auth: &CoreAuth,
    read: &oneiron::claim::ScopedRead<'_>,
    controls: Option<&CoreInterlocutorControls>,
    room: Option<&RoomAudience>,
) -> Result<Option<oneiron::InterlocutorSet>, ApiError> {
    let room_reader = room.and_then(|room| room.reader);
    if controls.is_none() && room.is_none() && auth.is_owner_grade() {
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

    // Membership is durable; it is not evidence of physical presence. Include
    // every member conservatively, so an omitted or spoofed wire party cannot
    // remove a room participant from the disclosure meet. A member maps to a
    // contact dial only through a unique About link; ambiguous/missing links
    // remain unknown and therefore grant no absent-owner clearance. The
    // owner and the vault's own agents add no term when the room has a
    // proven reader (ARCH-0067 §8); the agents' own reads bound it instead
    // (`RoomAudience::agent_reads`). For a caller the room does not name
    // they stay unknown: an agent-only room never reads as the owner alone.
    if let Some(room) = room {
        for (member, party) in &room.others {
            parties.push(match party {
                oneiron::disclosure::RoomParty::VaultOwner
                | oneiron::disclosure::RoomParty::VaultAgent
                    if room_reader.is_some() =>
                {
                    continue;
                }
                oneiron::disclosure::RoomParty::Contact(contact)
                    if read.is_ref_readable(contact).map_err(|error| {
                        core_engine_error("room contact admission failed", error)
                    })? =>
                {
                    oneiron::InterlocutorPartyInput::ContactRef(*contact)
                }
                _ => oneiron::InterlocutorPartyInput::UnknownLabel {
                    label: member.to_hex(),
                    claimed_owner: false,
                },
            });
        }
    }

    // Scoped principal identity always narrows. The sole exception is the
    // room's already-proved reader: re-adding its exact id as an Unknown
    // would turn it back into a third party after roster resolution.
    if let Some(principal_ref) = auth.principal_ref() {
        let principal_id = parse_entity_id_param(principal_ref, "principal_ref")?;
        if room_reader != Some(principal_id) {
            let readable = read.is_ref_readable(&principal_id).map_err(|error| {
                core_engine_error(
                    "core context-pack interlocutor principal lookup failed",
                    error,
                )
            })?;
            let contact = if readable {
                vault.get_counterparty_contact(&principal_id)
            } else {
                Ok(None)
            };
            let party = match contact {
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
    }

    // Owner presence is a conjunction, never a request assertion: the
    // credential must be owner-grade AND the caller must not have narrowed
    // itself away. `owner_present == Some(true)` was already rejected above
    // for non-owner-grade auth, so the `&&` here is the belt to that
    // suspenders — a narrowed credential can only ever resolve to `false`.
    // A room's roster cannot prove presence. The embedder must explicitly
    // assert owner presence on an owner-grade credential; absent assertion
    // never promotes an in-room assembly to Supervised or OwnerAlone. A
    // room one of the vault's own agents reads is never the owner's session.
    let owner_session = auth.is_owner_grade()
        && owner_present.unwrap_or(room.is_none())
        && room.is_none_or(|room| room.reader.is_none() || room.owner_reads);
    let input = oneiron::InterlocutorResolutionInput {
        owner_session,
        parties,
        voice_session_ref,
    };
    let read_rosters = read.is_unnarrowed_owner();
    vault
        .resolve_interlocutors_under(&input, read, read_rosters)
        .map(Some)
        .map_err(|error| {
            tracing::error!(error = %error, "core context-pack interlocutor resolution failed");
            core_engine_error("core context-pack interlocutor resolution failed", error)
        })
}

/// A room read's audience: every member but the room's proven reader,
/// each as the room meet sees it, resolved in one snapshot.
pub(crate) struct RoomAudience {
    /// The member the caller is proven to read the room as: the vault
    /// owner (see [`bound_room_owner`]) or one of the vault's own agents
    /// reading on its own credential.
    pub(crate) reader: Option<oneiron::EntityId>,
    /// Whether that reader is the vault owner.
    pub(crate) owner_reads: bool,
    /// Every other member and its party.
    pub(crate) others: Vec<(oneiron::EntityId, oneiron::disclosure::RoomParty)>,
}

impl RoomAudience {
    pub(crate) fn resolve(
        vault: &oneiron::Vault,
        auth: &CoreAuth,
        members: &[oneiron::EntityId],
    ) -> Result<Self, ApiError> {
        let parties = vault
            .room_parties(members)
            .map_err(|error| core_engine_error("room contact resolution failed", error))?;
        let owner = bound_room_owner(vault, auth, members)?;
        let reader = owner.or_else(|| own_agent_reader(auth, members, &parties));
        Ok(Self {
            reader,
            owner_reads: owner.is_some(),
            others: members
                .iter()
                .copied()
                .zip(parties)
                .filter(|(member, _)| reader != Some(*member))
                .collect(),
        })
    }

    /// The read key of each other of the vault's own agents when the room
    /// has a proven reader: they add no clearance term, so the room reads
    /// only what each of them may read too, as a room turn's peers do.
    pub(crate) fn agent_reads(&self) -> Vec<oneiron::claim::ScopedReadActorKey> {
        if self.reader.is_none() {
            return Vec::new();
        }
        self.others
            .iter()
            .filter(|(_, party)| *party == oneiron::disclosure::RoomParty::VaultAgent)
            .filter_map(|(member, _)| {
                oneiron::claim::ScopedReadActorKey::new(member.to_hex())
                    .map(|key| key.require_access_grants(Some(*member)))
            })
            .collect()
    }
}

/// The room member the caller is proven to be the vault owner as, if any.
/// A bare host credential authenticates the caller but identifies no PERSON
/// in the room. Only an identified, owner-grade human slip with a live
/// owner-capable actor binding can exclude its exact holder from the
/// non-owner meet. The presence flag and PROJECT leader are not identity
/// evidence.
fn bound_room_owner(
    vault: &oneiron::Vault,
    auth: &CoreAuth,
    members: &[oneiron::EntityId],
) -> Result<Option<oneiron::EntityId>, ApiError> {
    if !auth.is_owner_grade() || auth.actor_class() != Some("human") {
        return Ok(None);
    }
    let Some(id) = auth
        .principal_ref()
        .and_then(|id| oneiron::EntityId::from_hex(id).ok())
        .filter(|id| members.contains(id))
        .filter(|id| {
            vault.get_entity_type(id).ok() == Some(Some(oneiron::registry::ENTITY_TYPE_PERSON))
        })
    else {
        return Ok(None);
    };
    let fold = vault
        .authority_fold()
        .map_err(|error| core_engine_error("room owner binding failed", error))?;
    Ok(oneiron::authority::actor_binding_is_active(&fold, &id, "human").then_some(id))
}

/// The room member an agent credential reads as, when it names one of the
/// vault's own agents in the room. Its own credential's read already
/// bounds it, so like the owner it adds no clearance term (ARCH-0067 §8).
fn own_agent_reader(
    auth: &CoreAuth,
    members: &[oneiron::EntityId],
    parties: &[oneiron::disclosure::RoomParty],
) -> Option<oneiron::EntityId> {
    if auth.actor_class() != Some("agent") {
        return None;
    }
    let id = oneiron::EntityId::from_hex(auth.principal_ref()?).ok()?;
    members
        .iter()
        .zip(parties)
        .any(|(member, party)| {
            *member == id && *party == oneiron::disclosure::RoomParty::VaultAgent
        })
        .then_some(id)
}

/// The disclosure clamp a resolved interlocutor set applies (OF-365 ILD-2):
/// its contacts' current clearance and the current Tier-A marks. `None` is
/// an unclamped owner session. A room read never takes owner presence as
/// clearance. `room` is set for a room read, with whether the room has a
/// proven reader ([`RoomAudience::reader`]).
pub(crate) fn resolve_core_disclosure(
    vault: &oneiron::Vault,
    interlocutors: Option<&oneiron::InterlocutorSet>,
    room: Option<bool>,
) -> Result<Option<oneiron::DisclosureContext>, ApiError> {
    resolve_core_disclosure_with_once(vault, interlocutors, room, &BTreeMap::new())
}

/// [`resolve_core_disclosure`] under the owner's `once` answers this
/// assembly spent ([`spend_core_once_disclosures`]): each answered contact is
/// held to its answer's Scope in place of its clearance.
pub(crate) fn resolve_core_disclosure_with_once(
    vault: &oneiron::Vault,
    interlocutors: Option<&oneiron::InterlocutorSet>,
    room: Option<bool>,
    once: &BTreeMap<oneiron::EntityId, oneiron::federation::Scope>,
) -> Result<Option<oneiron::DisclosureContext>, ApiError> {
    interlocutors
        .map(|set| {
            oneiron::DisclosureContext::resolve_with_once(
                vault,
                set.clone(),
                room.unwrap_or(false),
                once,
            )
        })
        .transpose()
        .map_err(|error| {
            tracing::error!(error = %error, "core context-pack disclosure resolution failed");
            core_engine_error("core context-pack disclosure resolution failed", error)
        })
}

/// Spends the owner's `once` answers this assembly delivers (OF-365). A room
/// read travels on `room:<room hex>` and a voice session on
/// `voice:<voice_session_ref>`; a pack with neither has no channel, and no
/// once answer applies to it.
pub(crate) fn spend_core_once_disclosures(
    vault: &oneiron::Vault,
    interlocutors: Option<&oneiron::InterlocutorSet>,
    room: Option<oneiron::EntityId>,
    voice_session_ref: Option<&str>,
) -> Result<BTreeMap<oneiron::EntityId, oneiron::federation::Scope>, ApiError> {
    let Some(set) = interlocutors else {
        return Ok(BTreeMap::new());
    };
    let channels = room
        .map(|room| oneiron::consent::contact_disclosure_room_channel(&room))
        .into_iter()
        .chain(voice_session_ref.map(oneiron::consent::contact_disclosure_voice_channel))
        .collect::<BTreeSet<_>>();
    vault
        .spend_once_contact_disclosures(set, &channels)
        .map_err(|error| {
            tracing::error!(error = %error, "core context-pack once disclosure failed");
            core_engine_error("core context-pack once disclosure failed", error)
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
