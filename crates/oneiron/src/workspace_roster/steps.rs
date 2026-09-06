//! Ordered onboarding writes and idempotent primitives.

use super::*;

// ---------------------------------------------------------------------------
// Authority
// ---------------------------------------------------------------------------

/// Requires the writer to hold an administrative federation grant over
/// `vault_id`.
///
/// Authority is a STORED grant, never an asserted actor class: a caller can
/// spell any [`crate::edge::EdgeActorClass`] it likes into a [`WriteActor`], so
/// treating `System` as privileged would make the check decorative.
/// [`FederationGrantRole::is_admin`] is the crate's own predicate for "may
/// administer membership", and `Delegate` is excluded by it — a one-hop
/// delegate cannot enroll members.
pub(super) fn require_workspace_authority(
    vault: &Vault,
    vault_id: u64,
    writer: &WriteActor,
) -> Result<()> {
    let txn = vault.store.env.read_txn()?;
    require_workspace_authority_in_txn(vault, &txn, vault_id, writer)
}

pub(super) fn require_workspace_authority_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    vault_id: u64,
    writer: &WriteActor,
) -> Result<()> {
    let member_ref = writer.entity_ref();
    let raw = vault
        .store
        .entities
        .get(txn, member_ref.as_bytes())?
        .ok_or_else(|| invalid("workspace writer must name a live authority-bearing entity"))?;
    let entity_type = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("workspace writer entity header"))?
        .entity_type;
    crate::provenance::validate_actor_class(entity_type, writer.actor_class())?;
    let scope = FederationGrantScope::vault(vault_id);
    let fold = vault.authority_fold_readonly_in_txn(txn)?;
    if fold.vault_root_is_conflicted()
        || (fold.vault_id.is_some()
            && !crate::authority::actor_binding_is_active(
                &fold,
                &member_ref,
                writer.actor_class().gate_actor_class(),
            ))
    {
        return Err(invalid("workspace writer has no active authority binding"));
    }
    for entry in vault
        .store
        .type_index
        .prefix_iter(txn, &[ENTITY_TYPE_FEDERATION_GRANT])?
    {
        let (key, _) = entry?;
        let id = entity_id_from_type_index_key(&key)?;
        let Some(grant) = read_federation_grant_in_txn(vault, txn, &id)? else {
            continue;
        };
        if grant.scope == scope
            && grant.member_ref == member_ref
            && grant.role.is_admin()
            && fold
                .pact_for_grant(&id)
                .is_none_or(|pact| pact.status == crate::authority::FederationPactStatus::Active)
        {
            return Ok(());
        }
    }
    Err(invalid(
        "workspace onboarding requires an admin federation grant over the target vault",
    ))
}

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------

/// Step 1: check every referenced entity kind, anchor the house mind to the
/// workspace `ORG`, and settle the preset row.
pub(super) fn validate_workspace_references(
    vault: &Vault,
    intent: &MemberOnboardingIntent,
) -> Result<()> {
    let workspace = &intent.workspace;
    require_kind(
        vault,
        &intent.person_ref,
        ENTITY_TYPE_PERSON,
        "member person_ref must name a live PERSON",
    )?;
    require_kind(
        vault,
        &workspace.org_ref,
        ENTITY_TYPE_ORG,
        "workspace org_ref must name a live ORG",
    )?;
    require_kind(
        vault,
        &intent.work_facet_ref,
        ENTITY_TYPE_FACET,
        "member work_facet_ref must name a live FACET",
    )?;
    require_kind(
        vault,
        &workspace.house_actor_ref,
        ENTITY_TYPE_AGENT_DEF,
        "house_actor_ref must name a live AGENT_DEF",
    )?;
    let house = vault
        .get_agent_definition(&workspace.house_actor_ref)?
        .ok_or_else(|| invalid("house_actor_ref must name a seeded AGENT_DEF"))?;
    let seeded = house
        .logical_id
        .as_deref()
        .map(crate::agent_def::legacy_logical_id_row)
        .transpose()?
        .flatten();
    if seeded != Some(workspace.house_actor_ref) {
        return Err(invalid("house_actor_ref must name a seeded AGENT_DEF"));
    }
    if let Some(identity_ref) = workspace.house_identity_ref {
        require_kind(
            vault,
            &identity_ref,
            ENTITY_TYPE_CHANNEL_IDENTITY,
            "house_identity_ref must name a live CHANNEL_IDENTITY",
        )?;
    }
    if let Some(companion) = &intent.companion_birth {
        require_kind(
            vault,
            &companion.work_facet_ref,
            ENTITY_TYPE_FACET,
            "companion work_facet_ref must name a live FACET",
        )?;
    }

    let mut minted = vec![
        (intent.actor_ref, ENTITY_TYPE_AGENT_DEF),
        (
            intent.grant_bundle.federation_grant_ref,
            ENTITY_TYPE_FEDERATION_GRANT,
        ),
    ];
    if let Some(companion) = &intent.companion_birth {
        minted.extend([
            (companion.person_ref, ENTITY_TYPE_PERSON),
            (companion.actor_ref, ENTITY_TYPE_AGENT_DEF),
            (
                companion.companion_record_ref,
                crate::companion::ENTITY_TYPE_COMPANION_REGISTER,
            ),
            (
                companion.profile_grant_ref,
                crate::registry::ENTITY_TYPE_ACCESS_GRANT,
            ),
        ]);
    }
    if let Some(mailbox) = &intent.delegated_mailbox {
        minted.push((mailbox.identity_ref, ENTITY_TYPE_CHANNEL_IDENTITY));
    }
    for (id, expected) in minted {
        if vault
            .get_entity_type(&id)?
            .is_some_and(|kind| kind != expected)
        {
            return Err(invalid(
                "caller-supplied entity id is occupied by a different kind",
            ));
        }
    }
    Ok(())
}

pub(super) fn establish_workspace(
    vault: &Vault,
    intent: &MemberOnboardingIntent,
    writer: &WriteActor,
) -> Result<()> {
    validate_workspace_references(vault, intent)?;
    let workspace = &intent.workspace;
    // The house mind IS the org holding a pen: the seeded row's subject anchor
    // is what makes that true, and it is the same generic anchor a member actor
    // uses. Nothing about it is house-specific except which subject it names.
    ensure_subject_anchor(
        vault,
        workspace.house_actor_ref,
        workspace.org_ref,
        writer,
        intent.occurred_at,
    )?;
    ensure_preset_row(vault, workspace)
}

/// Step 2: define the member's actor and anchor it to the member `PERSON`.
pub(super) fn link_member_actor(
    vault: &Vault,
    intent: &MemberOnboardingIntent,
    writer: &WriteActor,
) -> Result<()> {
    ensure_agent_definition(
        vault,
        &intent.actor_ref,
        &intent.actor_definition,
        intent.occurred_at,
    )?;
    ensure_subject_anchor(
        vault,
        intent.actor_ref,
        intent.person_ref,
        writer,
        intent.occurred_at,
    )
}

/// Step 3: write the one `(Member, Member)` grant for the shared org vault.
///
/// The role/preset pair comes from the already-validated bundle rather than
/// from constants here, so the widening fence lives in exactly one place
/// ([`MemberOnboardingIntent::validate_grant_bundle`]) and this writer cannot
/// disagree with it.
pub(super) fn grant_member_bundle(
    vault: &Vault,
    intent: &MemberOnboardingIntent,
    writer: &WriteActor,
) -> Result<()> {
    let id = intent.grant_bundle.federation_grant_ref;
    let expected = FederationGrant::new(
        FederationGrantScope::vault(intent.workspace.workspace_vault_id),
        intent.person_ref,
        intent.grant_bundle.role,
        intent.grant_bundle.preset,
    );

    // FEDERATION_GRANT is a Maintenance kind, so the public `put_entity` gate
    // refuses it by design and FED-SYNC owns `federation.rs`. The engine-side
    // `allow_maintenance` Put is the same door `access_grant.rs` and
    // `channel_identity.rs` use for their own maintenance kinds; the encoded
    // bytes are FED-SYNC's canonical encoder's, and `put_apply` re-validates
    // them on the way in. Moving this behind a future public
    // `Vault::create_federation_grant` is a pure refactor: the bytes do not
    // change.
    let data = encode_federation_grant_body(&expected)?;
    let occurred = TimeRange {
        start: intent.occurred_at,
        end: intent.occurred_at,
    };
    vault.with_write_txn(|wtxn| {
        require_workspace_authority_in_txn(
            vault,
            wtxn,
            intent.workspace.workspace_vault_id,
            writer,
        )?;
        if let Some(existing) = read_federation_grant_in_txn(vault, wtxn, &id)? {
            if existing != expected {
                return Err(invalid(
                    "federation_grant_ref is already bound to a different grant",
                ));
            }
            return Ok(());
        }
        apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            wtxn,
            vec![BatchOp::Put {
                id,
                entity_type: ENTITY_TYPE_FEDERATION_GRANT,
                occurred,
                learned_at: intent.occurred_at,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )
    })
}

/// Step 4: a companion is a full someone, not a mode of the member.
///
/// PERSON, substrate, actor, anchor, work facet, register record, and exactly
/// the one companion-profile read grant the intent named — nothing wider.
pub(super) fn birth_companion(
    vault: &Vault,
    intent: &MemberOnboardingIntent,
    companion: &CompanionBirthIntent,
    writer: &WriteActor,
) -> Result<()> {
    ensure_companion_person(vault, companion, intent.occurred_at)?;
    ensure_model_substrate(vault, companion.person_ref, writer, intent.occurred_at)?;

    // The quiz-born name lands in the actor's runtime-editable `display_name`
    // slot — the one place the engine already reads a persona name from, and
    // the one an owner can later edit through `update_agent_definition`.
    let mut definition = companion.actor_definition.clone();
    definition.display_name = Some(companion.display_name.clone());
    ensure_agent_definition(vault, &companion.actor_ref, &definition, intent.occurred_at)?;

    ensure_subject_anchor(
        vault,
        companion.actor_ref,
        companion.person_ref,
        writer,
        intent.occurred_at,
    )?;
    ensure_work_facet_edge(vault, companion.person_ref, companion.work_facet_ref)?;
    ensure_companion_record(vault, intent, companion, writer)?;
    ensure_companion_profile_grant(vault, intent, companion, writer)
}

/// Step 5: bind a member-held mailbox through the landed delegated door.
///
/// The custody NAME travels; the token does not exist in this call stack.
pub(super) fn bind_delegated_mailbox(
    vault: &Vault,
    intent: &MemberOnboardingIntent,
    mailbox: &DelegatedMailboxOnboarding,
) -> Result<()> {
    let grant = DelegatedGrant::new(&mailbox.custody_name, mailbox.scopes.clone());
    let binding = ChannelIdentityBinding::agent(intent.actor_ref);
    if let Some(existing) = vault.get_channel_identity(&mailbox.identity_ref)? {
        if !existing.is_delegated()
            || existing.assignment_key() != AssignmentKey::of(&mailbox.channel, &mailbox.address)
            || existing.binding != binding
            || existing.grant.as_ref() != Some(&grant)
            || existing.state != ChannelIdentityState::Requested
            || existing.state_changed_at != intent.occurred_at
        {
            return Err(invalid(
                "identity_ref is already bound to a different mailbox",
            ));
        }
        // Retrying after custody revocation must not treat a stale row as proof.
        vault.verify_delegated_custody(&mailbox.channel, &mailbox.address, &grant)?;
    } else {
        vault.provision_delegated_identity(
            &mailbox.identity_ref,
            DelegatedProvisionRequest {
                channel: mailbox.channel.clone(),
                address_or_handle: mailbox.address.clone(),
                binding,
                grant,
            },
            intent.occurred_at,
        )?;
    }
    // ONE-1829 is an external remaining leg, not a second lifecycle machine.
    // Leave the identity Requested (non-sending), the journal at CompanionBorn,
    // and the exact requested mode pinned in the intent digest.
    Err(Error::WorkspaceMailboxAutonomyNotReady {
        identity_ref: mailbox.identity_ref,
        requested_mode: mailbox.starting_mode.clone(),
    })
}

/// Step 6: record the member's roster row so the workspace read can find it.
pub(super) fn record_roster_member(vault: &Vault, intent: &MemberOnboardingIntent) -> Result<()> {
    let row = RosterMemberRow {
        person_ref: intent.person_ref,
        actor_ref: intent.actor_ref,
        companion_person_ref: intent.companion_birth.as_ref().map(|c| c.person_ref),
        companion_actor_ref: intent.companion_birth.as_ref().map(|c| c.actor_ref),
        companion_facet_ref: intent.companion_birth.as_ref().map(|c| c.work_facet_ref),
        identity_ref: intent.delegated_mailbox.as_ref().map(|m| m.identity_ref),
    };
    let key = roster_member_key(&intent.workspace.workspace_ref, &intent.person_ref);
    let encoded = encode_value(&roster_member_value(&row))?;
    vault.with_write_txn(|wtxn| {
        if let Some(raw) = vault.store.vault_meta.get(wtxn, &key)? {
            if decode_roster_member_row(&raw)? != row {
                return Err(invalid(
                    "member already has a different workspace roster row",
                ));
            }
            return Ok(());
        }
        vault.store.vault_meta.put(wtxn, &key, &encoded)?;
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Idempotent primitives
// ---------------------------------------------------------------------------

/// Anchors `actor_ref` to `subject_ref` unless it is already anchored there.
///
/// A DIFFERENT live anchor is a typed refusal, not a silent re-anchor: the
/// anchor answers "who is this", and quietly changing that answer would
/// re-attribute every routed event this actor has ever spoken.
pub(super) fn ensure_subject_anchor(
    vault: &Vault,
    actor_ref: EntityId,
    subject_ref: EntityId,
    writer: &WriteActor,
    at: u64,
) -> Result<()> {
    crate::subject_model::ensure_actor_subject(vault, actor_ref, subject_ref, *writer, at)
}

/// Defines `id` from `definition` unless an `AGENT_DEF` already sits there.
///
/// Existing rows are left alone rather than rewritten: the caller-supplied id
/// may already carry owner edits (a renamed `display_name`, a disabled row),
/// and onboarding is not the door that reconciles those.
pub(super) fn ensure_agent_definition(
    vault: &Vault,
    id: &EntityId,
    definition: &AgentDefinition,
    at: u64,
) -> Result<()> {
    let data = encode_agent_definition(definition)?;
    vault.with_write_txn(|txn| {
        if let Some(raw) = vault.store.entities.get(txn, id.as_bytes())? {
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_AGENT_DEF {
                return Err(Error::InvalidEntityType(header.entity_type));
            }
            let existing =
                crate::agent_def::decode_agent_definition(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            let mut expected = definition.clone();
            expected.display_name = existing.display_name.clone();
            expected.enabled = existing.enabled;
            if encode_agent_definition(&existing)? != encode_agent_definition(&expected)? {
                return Err(invalid(
                    "actor_ref is already bound to a different agent definition",
                ));
            }
            return Ok(());
        }
        put_roster_entity_in_txn(vault, txn, *id, ENTITY_TYPE_AGENT_DEF, data, at)
    })
}

/// Mints the companion `PERSON` row if it is absent.
///
/// The body is this module's own tiny map carrying the caller's display name —
/// the `comm.rs` party-person precedent. `PERSON` has no engine-wide body
/// contract, so inventing a richer one here would be inventing product shape.
pub(super) fn ensure_companion_person(
    vault: &Vault,
    companion: &CompanionBirthIntent,
    at: u64,
) -> Result<()> {
    let body = encode_value(&Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(WORKSPACE_ROSTER_SCHEMA_VERSION),
        ),
        (
            Value::from("display_name"),
            Value::from(companion.display_name.as_str()),
        ),
    ]))?;
    vault.with_write_txn(|txn| {
        if let Some(raw) = vault
            .store
            .entities
            .get(txn, companion.person_ref.as_bytes())?
        {
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_PERSON {
                return Err(Error::InvalidEntityType(header.entity_type));
            }
            if &raw[ENTITY_METADATA_HEADER_LEN..] != body.as_slice() {
                return Err(invalid(
                    "companion person_ref is already bound to a different person",
                ));
            }
            return Ok(());
        }
        put_roster_entity_in_txn(
            vault,
            txn,
            companion.person_ref,
            ENTITY_TYPE_PERSON,
            body,
            at,
        )
    })
}

/// Records `person_ref` as model-substrate unless it already is.
///
/// A person already recorded as `meat` is a typed refusal: substrate is a fact
/// about a someone, and overwriting it here would silently reclassify a human.
pub(super) fn ensure_model_substrate(
    vault: &Vault,
    person_ref: EntityId,
    writer: &WriteActor,
    at: u64,
) -> Result<()> {
    crate::subject_model::ensure_model_person(vault, person_ref, *writer, at)
}

/// Associates the companion person with its work facet.
pub(super) fn ensure_work_facet_edge(
    vault: &Vault,
    person_ref: EntityId,
    facet_ref: EntityId,
) -> Result<()> {
    let already = vault
        .edges_out(&person_ref)?
        .into_iter()
        .any(|edge| edge.kind == EdgeKind::HasFacet && edge.target == facet_ref);
    if already {
        return Ok(());
    }
    vault.put_edge(&person_ref, EdgeKind::HasFacet, &facet_ref, 1.0)
}

/// Writes the companion-register persona record if it is absent.
pub(super) fn ensure_companion_record(
    vault: &Vault,
    intent: &MemberOnboardingIntent,
    companion: &CompanionBirthIntent,
    writer: &WriteActor,
) -> Result<()> {
    let provenance = CompanionProvenance::new(
        writer.entity_ref(),
        writer.actor_class(),
        ClaimSource::Observed,
        ClaimApprovalStatus::Auto,
        Value::Map(vec![
            (
                Value::from("workspace_ref"),
                Value::from(intent.workspace.workspace_ref.as_str()),
            ),
            (
                Value::from("onboarding_id"),
                Value::from(intent.onboarding_id.as_str()),
            ),
        ]),
    );
    let record = CompanionRecord::persona(
        CompanionScope::personal(intent.person_ref),
        companion.actor_ref,
        Value::Map(vec![
            (
                Value::from("schema_version"),
                Value::from(WORKSPACE_ROSTER_SCHEMA_VERSION),
            ),
            (
                Value::from("display_name"),
                Value::from(companion.display_name.as_str()),
            ),
            (
                Value::from("work_facet_ref"),
                Value::from(companion.work_facet_ref.to_hex()),
            ),
        ]),
        provenance,
        CompanionExportClassification::LocalOnly,
    );
    if let Some(existing) = vault.get_companion_record(&companion.companion_record_ref)? {
        if existing.scope != record.scope
            || existing.subject != record.subject
            || existing.value != record.value
            || existing.lifecycle != record.lifecycle
            || existing.export_classification != record.export_classification
        {
            return Err(invalid(
                "companion_record_ref is already bound to a different companion",
            ));
        }
        return Ok(());
    }
    vault.create_companion_record(&companion.companion_record_ref, &record, intent.occurred_at)
}

/// Mints exactly the companion-profile READ grant the intent named.
///
/// One capability, one scope. Nothing here can widen: the constructor pins the
/// capability to the scope shape and [`AccessGrant::validate`] refuses any
/// other pairing.
pub(super) fn ensure_companion_profile_grant(
    vault: &Vault,
    intent: &MemberOnboardingIntent,
    companion: &CompanionBirthIntent,
    writer: &WriteActor,
) -> Result<()> {
    let expected = AccessGrant::companion_profile_read(
        intent.person_ref,
        intent.person_ref,
        companion.actor_ref,
        intent.occurred_at,
    );
    let id = companion.profile_grant_ref;
    let data = crate::access_grant::encode_access_grant_body(&expected)?;
    vault.with_write_txn(|txn| {
        require_workspace_authority_in_txn(
            vault,
            txn,
            intent.workspace.workspace_vault_id,
            writer,
        )?;
        if let Some(raw) = vault.store.entities.get(txn, id.as_bytes())? {
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != crate::registry::ENTITY_TYPE_ACCESS_GRANT {
                return Err(Error::InvalidEntityType(header.entity_type));
            }
            let existing =
                crate::access_grant::decode_access_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if existing != expected {
                return Err(invalid(
                    "profile_grant_ref is already bound to a different access grant",
                ));
            }
            return Ok(());
        }
        apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            txn,
            vec![BatchOp::Put {
                id,
                entity_type: crate::registry::ENTITY_TYPE_ACCESS_GRANT,
                occurred: TimeRange {
                    start: intent.occurred_at,
                    end: intent.occurred_at,
                },
                learned_at: intent.occurred_at,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )
    })
}

/// Writes the preset row, or verifies the stored one agrees with it.
pub(super) fn ensure_preset_row(vault: &Vault, preset: &WorkspaceRosterPreset) -> Result<()> {
    if let Some(stored) = read_preset(vault, &preset.workspace_ref)? {
        if &stored != preset {
            return Err(invalid(
                "workspace_ref is already bound to a different workspace preset",
            ));
        }
        return Ok(());
    }
    let key = preset_key(&preset.workspace_ref);
    let encoded = encode_value(&preset_value(preset))?;
    vault.with_write_txn(|wtxn| {
        if let Some(raw) = vault.store.vault_meta.get(wtxn, &key)? {
            if raw.as_ref() != encoded.as_slice() {
                return Err(invalid(
                    "workspace_ref is already bound to a different workspace preset",
                ));
            }
            return Ok(());
        }
        vault.store.vault_meta.put(wtxn, &key, &encoded)?;
        Ok(())
    })
}

/// The ordinary Put used by `define_agent` and `put_entity`, transaction-composed
/// for ensure-if-absent. No maintenance or reserved-predicate exemption here.
fn put_roster_entity_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    entity_type: u8,
    data: Vec<u8>,
    at: u64,
) -> Result<()> {
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        txn,
        vec![BatchOp::Put {
            id,
            entity_type,
            occurred: TimeRange { start: at, end: at },
            learned_at: at,
            data,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }],
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
        false,
        true,
    )
}
