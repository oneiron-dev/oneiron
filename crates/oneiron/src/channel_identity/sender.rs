use super::decode_channel_identity_body;
use super::facts::ChannelIdentityFacts;
use super::keys::ACT_CLASS_CHANNEL_IDENTITY_OUTBOUND_SEND;
use super::lifecycle::ChannelIdentityState;
use super::record::ChannelIdentity;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::channel_identity_selection::{ChannelIdentityCandidate, ChannelIdentityFace};
use crate::counterparty_contact::normalize_channel_class;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::gate::class_policy::ActPosture;

use crate::ports::{EntityStoreRead, TombstoneStoreRead};
use crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY;
use crate::store::Store;

/// Resolves the OF-347 channel identity a connector key sends through.
///
/// ONE-1868 leg 2, optional enrichment: the opt-out verdict rests on
/// `(counterparty, channel_class)`, never on this value. Nothing new is minted —
/// the governing connector key (OF-277) names the sending actor, and the
/// ChannelIdentity bound to that actor on the connector's channel is the
/// identity that will carry the send. Missing, unregistered, or inactive
/// identities resolve to `None`. Multiple eligible identities instead return
/// [`Error::InvalidConfig`]: automatic selection must not send without a unique sender.
pub(crate) fn resolve_channel_identity_ref_for_connector(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    connector_key: &str,
    actor_entity_ref: Option<&EntityId>,
) -> crate::Result<Option<EntityId>> {
    let connector = connector_key.trim().to_ascii_lowercase().replace('-', "_");
    let Some((_, key_record)) =
        crate::connector_key::governing_connector_key(store, txn, &connector, actor_entity_ref)?
    else {
        return Ok(None);
    };
    let Some(bound_actor) = key_record
        .actor_entity_ref
        .or_else(|| actor_entity_ref.copied())
    else {
        return Ok(None);
    };

    let channel_class = normalize_channel_class(connector_key);
    let mut resolved = None;
    for entry in store.port_entity_ids_by_type(txn, ENTITY_TYPE_CHANNEL_IDENTITY, None)? {
        let id = entry?;
        // Channel and binding are facts, read from the identity's claim heads
        // (OF-272); only the custody check below reads the local row.
        let Some(facts) = super::channel_identity_facts_in_txn(store, txn, &id)? else {
            continue;
        };
        if normalize_channel_class(&facts.channel) != channel_class
            || facts.binding.actor_ref() != Some(bound_actor)
        {
            continue;
        }
        let identity = read_identity_row(store, txn, &id)?;
        // The posture comes from the vault's `act_policy` row for this
        // identity's subject class, resolved in THIS transaction — not from the
        // identity's class. A delegated row is denied by the row the default
        // manifest ships, and if the owner raises that row the capability check
        // behind `may_send_under` still refuses, because a read-only grant
        // carries no outbound scope.
        if !outbound_send_permitted(store, txn, &identity, facts.binding.actor_ref())? {
            continue;
        }
        if resolved.is_some() {
            return Err(Error::InvalidConfig(
                "ambiguous outbound sender: multiple eligible channel identities; select an explicit channel_identity_ref"
                    .to_owned(),
            ));
        }
        resolved = Some(id);
    }
    Ok(resolved)
}

/// The custody row of an indexed identity, refusing a dangling index.
fn read_identity_row(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> crate::Result<ChannelIdentity> {
    let Some(raw) = store.port_entity_record(txn, id)?.map(|row| row.encode()) else {
        return Err(Error::CorruptedIndex("channel identity entity row"));
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("channel identity entity header"));
    };
    if header.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
        return Err(Error::CorruptedIndex("channel identity entity type"));
    }
    decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..])
}

/// The host's face for one identity, from its facts; `None` leaves the
/// identity out of the selection.
pub type ChannelIdentityFaceClassifier<'a> =
    dyn FnMut(&EntityId, &ChannelIdentityFacts) -> crate::Result<Option<ChannelIdentityFace>> + 'a;

/// The selection candidates of one actor on one channel class, hydrated
/// from the identities' claim heads (OF-272): the id, the shape head, and
/// `active` when the state head is Active and custody may carry a send now.
/// The face is the host's (`classify_face`): a face is a role, not a shape,
/// and no fact states it. A deleted identity, or one with no heads, is no
/// candidate; an inactive one stays, so a pin on it is refused, not replaced.
pub(crate) fn channel_identity_selection_candidates_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    channel: &str,
    actor_ref: &EntityId,
    classify_face: &mut ChannelIdentityFaceClassifier<'_>,
) -> crate::Result<Vec<ChannelIdentityCandidate>> {
    let channel_class = normalize_channel_class(channel);
    let mut candidates = Vec::new();
    for entry in store.port_entity_ids_by_type(txn, ENTITY_TYPE_CHANNEL_IDENTITY, None)? {
        let id = entry?;
        if store.port_deletion_state(txn, &id)?.deleted {
            continue;
        }
        let Some(facts) = super::channel_identity_facts_in_txn(store, txn, &id)? else {
            continue;
        };
        if normalize_channel_class(&facts.channel) != channel_class
            || facts.binding.actor_ref() != Some(*actor_ref)
        {
            continue;
        }
        let Some(face) = classify_face(&id, &facts)? else {
            continue;
        };
        let identity = read_identity_row(store, txn, &id)?;
        let active = facts.state == ChannelIdentityState::Active
            && outbound_send_permitted(store, txn, &identity, Some(*actor_ref))?;
        candidates.push(ChannelIdentityCandidate {
            identity_ref: id,
            shape: facts.shape,
            face,
            active,
        });
    }
    Ok(candidates)
}

/// The actor the identity `id`'s binding head names, and whether the
/// identity may carry that actor's outbound send now: its state head Active
/// and the send permitted by the manifest's act policy, as a selection
/// candidate reads it. None for an identity with no heads or one the vault
/// holds for no actor. A read for projections (ARCH-0070 reach); the send
/// door asks again.
pub(crate) fn channel_identity_send_holder_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> crate::Result<Option<(EntityId, bool)>> {
    let Some(facts) = super::channel_identity_facts_in_txn(store, txn, id)? else {
        return Ok(None);
    };
    let Some(actor) = facts.binding.actor_ref() else {
        return Ok(None);
    };
    let identity = read_identity_row(store, txn, id)?;
    let may_send = facts.state == ChannelIdentityState::Active
        && outbound_send_permitted(store, txn, &identity, Some(actor))?;
    Ok(Some((actor, may_send)))
}

impl crate::Vault {
    /// The candidates [`resolve_channel_identity_selection`] chooses among
    /// for `actor_ref` on `channel`, read from claim heads on one snapshot.
    /// The host supplies the faces and, in its query, the relationship.
    ///
    /// [`resolve_channel_identity_selection`]: crate::channel_identity_selection::resolve_channel_identity_selection
    pub fn channel_identity_selection_candidates(
        &self,
        channel: &str,
        actor_ref: &EntityId,
        classify_face: &mut ChannelIdentityFaceClassifier<'_>,
    ) -> crate::Result<Vec<ChannelIdentityCandidate>> {
        let txn = self.store.env.read_txn()?;
        channel_identity_selection_candidates_in_txn(
            &self.store,
            &txn,
            channel,
            actor_ref,
            classify_face,
        )
    }
}

/// An explicit channel identity always wins; otherwise resolve it cheaply.
pub(crate) fn enrich_dispatch_channel_identity(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    connector_key: &str,
    actor_entity_ref: Option<&EntityId>,
    explicit: Option<EntityId>,
) -> crate::Result<Option<EntityId>> {
    match explicit {
        Some(id) => {
            let Some(raw) = store.port_entity_record(txn, &id)?.map(|row| row.encode()) else {
                return Ok(Some(id));
            };
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("channel identity sender header"))?;
            if header.entity_type == ENTITY_TYPE_CHANNEL_IDENTITY {
                // A pinned identity on a different channel class is metadata,
                // not the sender for THIS effect. Keep the gate's counterparty
                // verdict independent of a stale cross-channel enrichment.
                // Provider email rails map to the email class here too. The
                // class is the identity's channel head (OF-272).
                let facts = super::channel_identity_facts_in_txn(store, txn, &id)?;
                let same_class = facts.as_ref().is_none_or(|facts| {
                    normalize_channel_class(&facts.channel)
                        == normalize_channel_class(connector_key)
                });
                let holder = facts.and_then(|facts| facts.binding.actor_ref());
                let identity = decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
                if same_class && !outbound_send_permitted(store, txn, &identity, holder)? {
                    return Err(refuse_outbound_send(&identity));
                }
            }
            Ok(Some(id))
        }
        None => {
            resolve_channel_identity_ref_for_connector(store, txn, connector_key, actor_entity_ref)
        }
    }
}

/// Whether `identity` may carry an outbound effect in this vault right now.
///
/// Two independent questions, asked in the order that keeps them honest:
///
/// 1. POLICY — does the manifest's `act_policy` row for
///    `channel_identity.outbound_send` permit this subject class, for this
///    holder? A missing row is [`ActPosture::Deny`]: silence about an outbound
///    act is not permission, and the default manifest is never silent here.
/// 2. SUBSTRATE — does the row hold the capability the act needs? For a
///    self-held row that is a live state; for a delegated row it is an outbound
///    scope on the grant, which no read-only scope class can express.
///
/// Raising the manifest row therefore cannot by itself enable a send. What it
/// changes is which of the two refusals the vault reports, and who owns the
/// decision: the vault's policy data rather than an engine class ban.
///
/// A vault with no policy manifest at all has no row to ask. Its gate already
/// holds every external effect on `gate.pending.external_effect_authority`, so
/// only the substrate question is asked here: refusing on the missing row
/// would make the sender identity, not the gate, the source of that verdict.
/// A loaded manifest that is merely silent about this act still denies.
///
/// `holder` is the identity's binding head (OF-272): the policy row is asked
/// about the actor the facts name, and only the capability is the row's.
fn outbound_send_permitted(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    identity: &ChannelIdentity,
    holder: Option<EntityId>,
) -> crate::Result<bool> {
    let policy = crate::gate::resolve_policy_manifest(store, txn)?;
    let diagnostics = policy.diagnostics();
    if diagnostics.manifest_count == 0 && !diagnostics.loaded_manifest_forces_fail_closed() {
        return Ok(identity.holds_outbound_capability());
    }
    let posture: ActPosture = policy
        .resolved_act_posture(
            ACT_CLASS_CHANNEL_IDENTITY_OUTBOUND_SEND,
            identity.outbound_subject_class(),
            holder,
        )
        .unwrap_or_default();
    Ok(identity.may_send_under(posture))
}

/// The refusal for an explicit sender the vault will not send through.
///
/// The two reasons are reported apart on purpose: "this vault's policy bars the
/// class" and "the grant we hold carries no outbound scope" are different facts
/// for the owner who has to decide what to change.
fn refuse_outbound_send(identity: &ChannelIdentity) -> Error {
    let reason = if identity.holds_outbound_capability() {
        "this vault's act_policy row bars outbound send for this channel identity's subject class"
    } else {
        "channel identity holds no outbound send capability: a self-held row must be active, and \
         a delegated grant must carry an outbound scope"
    };
    Error::Record(crate::error::RecordError::InvalidChannelIdentityBody(
        reason,
    ))
}
