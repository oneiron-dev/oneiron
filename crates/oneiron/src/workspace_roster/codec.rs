//! Roster reads, journal records, and canonical onboarding encodings.

use super::*;

// ---------------------------------------------------------------------------
// Roster reads
// ---------------------------------------------------------------------------

/// Builds the house-mind row.
///
/// `display_name` is the owner override when present and the deployment's
/// `venture_name` otherwise; both are runtime intent data and neither is
/// compiled in. `subject_ref` resolves through the anchor so a merged ORG reads
/// as its survivor, and falls back to the stated `org_ref` when the anchor is
/// ambiguous (a split shell) — the roster answers with what the writer stated
/// rather than guessing a head.
pub(super) fn house_mind_entry(
    vault: &Vault,
    preset: &WorkspaceRosterPreset,
) -> Result<WorkspaceRosterEntry> {
    let display_name = preset
        .house_display_name
        .clone()
        .unwrap_or_else(|| preset.venture_name.clone());
    let subject_ref =
        actor_subject_anchor(vault, &preset.house_actor_ref)?.unwrap_or(preset.org_ref);
    Ok(WorkspaceRosterEntry {
        workspace_ref: preset.workspace_ref.clone(),
        role: WorkspaceRosterRole::HouseMind,
        principal_ref: None,
        actor_ref: preset.house_actor_ref,
        subject_ref,
        facet_ref: None,
        identity_ref: preset.house_identity_ref,
        display_name,
    })
}

/// Builds one principal-companion row, or `None` for a member who has no
/// companion. Membership without a companion is a legal roster state; it simply
/// contributes no persona.
pub(super) fn companion_entry(
    vault: &Vault,
    preset: &WorkspaceRosterPreset,
    row: &RosterMemberRow,
) -> Result<Option<WorkspaceRosterEntry>> {
    let (Some(actor_ref), Some(person_ref)) = (row.companion_actor_ref, row.companion_person_ref)
    else {
        return Ok(None);
    };
    let definition = vault.get_agent_definition(&actor_ref)?;
    let display_name = definition
        .map(|definition| {
            definition
                .display_name
                .unwrap_or_else(|| definition.agent_id.clone())
        })
        .unwrap_or_default();
    let subject_ref = actor_subject_anchor(vault, &actor_ref)?.unwrap_or(person_ref);
    Ok(Some(WorkspaceRosterEntry {
        workspace_ref: preset.workspace_ref.clone(),
        role: WorkspaceRosterRole::PrincipalCompanion,
        principal_ref: Some(row.person_ref),
        actor_ref,
        subject_ref,
        facet_ref: row.companion_facet_ref,
        // A delegated mailbox is bound to the MEMBER actor, not this companion.
        // Only the shared house identity may represent this roster presence.
        identity_ref: preset.house_identity_ref,
        display_name,
    }))
}

// ---------------------------------------------------------------------------
// Keys, journal, codecs
// ---------------------------------------------------------------------------

pub(super) fn onboarding_key(onboarding_id: &str) -> Vec<u8> {
    let mut key = WORKSPACE_ONBOARDING_KEY_PREFIX.to_vec();
    key.extend_from_slice(onboarding_id.as_bytes());
    key
}

pub(super) fn preset_key(workspace_ref: &str) -> Vec<u8> {
    let mut key = WORKSPACE_ROSTER_PRESET_KEY_PREFIX.to_vec();
    key.extend_from_slice(workspace_ref.as_bytes());
    key
}

pub(super) fn roster_member_prefix(workspace_ref: &str) -> Vec<u8> {
    let mut key = WORKSPACE_ROSTER_MEMBER_KEY_PREFIX.to_vec();
    key.extend_from_slice(workspace_ref.as_bytes());
    key
}

pub(super) fn roster_member_key(workspace_ref: &str, person_ref: &EntityId) -> Vec<u8> {
    let mut key = roster_member_prefix(workspace_ref);
    key.push(ROSTER_KEY_SEPARATOR);
    key.extend_from_slice(person_ref.to_hex().as_bytes());
    key
}

pub(super) fn read_journal(vault: &Vault, key: &[u8]) -> Result<Option<OnboardingJournal>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault.store.vault_meta.get(&rtxn, key)? else {
        return Ok(None);
    };
    decode_journal(&raw).map(Some)
}

pub(super) fn write_journal(
    vault: &Vault,
    key: &[u8],
    intent: &MemberOnboardingIntent,
    record: &OnboardingJournal,
    writer: &WriteActor,
) -> Result<()> {
    let encoded = encode_value(&Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(WORKSPACE_ROSTER_SCHEMA_VERSION),
        ),
        (
            Value::from("onboarding_id"),
            Value::from(intent.onboarding_id.as_str()),
        ),
        (
            Value::from("intent_digest"),
            Value::Binary(record.intent_digest.to_vec()),
        ),
        (Value::from("step"), Value::from(record.step.as_str())),
        (
            Value::from("completed_at"),
            record.completed_at.map_or(Value::Nil, Value::from),
        ),
    ]))?;
    with_workspace_authority(vault, intent.workspace.workspace_vault_id, writer, |wtxn| {
        if let Some(raw) = vault.store.vault_meta.get(wtxn, key)? {
            let prior = decode_journal(&raw)?;
            if prior.intent_digest != record.intent_digest {
                return Err(invalid(
                    "onboarding_id was already used with different inputs",
                ));
            }
            if prior.step.rank() >= record.step.rank() {
                return Ok(());
            }
        }
        if record.step == MemberOnboardingStep::Started {
            reserve_member_in_txn(vault, wtxn, intent, &record.intent_digest)?;
        }
        vault.store.vault_meta.put(wtxn, key, &encoded)?;
        Ok(())
    })
}

/// An unfinished onboarding owns its member slot too. A second id must not
/// create another companion while the first journal is waiting for custody.
fn reserve_member_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    intent: &MemberOnboardingIntent,
    digest: &[u8; 32],
) -> Result<()> {
    let mut key = b"workspace_roster:member_intent:v1:".to_vec();
    key.extend_from_slice(intent.workspace.workspace_ref.as_bytes());
    key.push(ROSTER_KEY_SEPARATOR);
    key.extend_from_slice(intent.person_ref.as_bytes());
    if let Some(prior) = vault.store.vault_meta.get(txn, &key)?
        && prior.as_ref() != digest.as_slice()
    {
        return Err(invalid(
            "member already has a different workspace onboarding",
        ));
    }
    if let Some(companion) = &intent.companion_birth {
        let mut companion_key = b"workspace_roster:companion_principal:v1:".to_vec();
        companion_key.extend_from_slice(companion.person_ref.as_bytes());
        if let Some(prior) = vault.store.vault_meta.get(txn, &companion_key)?
            && prior.as_ref() != intent.person_ref.as_bytes().as_slice()
        {
            return Err(invalid(
                "companion person already belongs to a different principal",
            ));
        }
        vault
            .store
            .vault_meta
            .put(txn, &companion_key, intent.person_ref.as_bytes())?;
    }
    vault.store.vault_meta.put(txn, &key, digest)?;
    Ok(())
}

pub(super) fn decode_journal(bytes: &[u8]) -> Result<OnboardingJournal> {
    let entries = decode_map(bytes)?;
    if required(&entries, "schema_version")?.as_u64() != Some(WORKSPACE_ROSTER_SCHEMA_VERSION) {
        return Err(invalid("onboarding journal schema_version is unsupported"));
    }
    let digest_bytes = match required(&entries, "intent_digest")? {
        Value::Binary(bytes) => bytes.clone(),
        _ => return Err(invalid("onboarding journal intent_digest must be binary")),
    };
    let intent_digest: [u8; 32] = digest_bytes
        .try_into()
        .map_err(|_| invalid("onboarding journal intent_digest must be 32 bytes"))?;
    let step = required(&entries, "step")?
        .as_str()
        .and_then(MemberOnboardingStep::parse)
        .ok_or_else(|| invalid("onboarding journal step is unrecognized"))?;
    let completed_at = match required(&entries, "completed_at")? {
        Value::Nil => None,
        value => Some(
            value
                .as_u64()
                .ok_or_else(|| invalid("onboarding journal completed_at must be a u64"))?,
        ),
    };
    if (step == MemberOnboardingStep::Complete) != completed_at.is_some() {
        return Err(invalid("onboarding journal completion fields disagree"));
    }
    Ok(OnboardingJournal {
        intent_digest,
        step,
        completed_at,
    })
}

pub(super) fn preset_value(preset: &WorkspaceRosterPreset) -> Value {
    Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(WORKSPACE_ROSTER_SCHEMA_VERSION),
        ),
        (
            Value::from("workspace_ref"),
            Value::from(preset.workspace_ref.as_str()),
        ),
        (
            Value::from("workspace_vault_id"),
            Value::from(preset.workspace_vault_id),
        ),
        (Value::from("org_ref"), Value::from(preset.org_ref.to_hex())),
        (
            Value::from("venture_name"),
            Value::from(preset.venture_name.as_str()),
        ),
        (
            Value::from("house_display_name"),
            preset
                .house_display_name
                .as_deref()
                .map_or(Value::Nil, Value::from),
        ),
        (
            Value::from("house_actor_ref"),
            Value::from(preset.house_actor_ref.to_hex()),
        ),
        (
            Value::from("house_identity_ref"),
            optional_ref(preset.house_identity_ref),
        ),
    ])
}

pub(super) fn read_preset(
    vault: &Vault,
    workspace_ref: &str,
) -> Result<Option<WorkspaceRosterPreset>> {
    let key = preset_key(workspace_ref);
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault.store.vault_meta.get(&rtxn, &key)? else {
        return Ok(None);
    };
    let entries = decode_map(&raw)?;
    if required(&entries, "schema_version")?.as_u64() != Some(WORKSPACE_ROSTER_SCHEMA_VERSION) {
        return Err(invalid("workspace preset schema_version is unsupported"));
    }
    Ok(Some(WorkspaceRosterPreset {
        workspace_ref: required_str(&entries, "workspace_ref")?,
        workspace_vault_id: required(&entries, "workspace_vault_id")?
            .as_u64()
            .ok_or_else(|| invalid("workspace preset workspace_vault_id must be a u64"))?,
        org_ref: required_ref(&entries, "org_ref")?,
        venture_name: required_str(&entries, "venture_name")?,
        house_display_name: optional_string(&entries, "house_display_name")?,
        house_actor_ref: required_ref(&entries, "house_actor_ref")?,
        house_identity_ref: optional_entity(&entries, "house_identity_ref")?,
    }))
}

pub(super) fn roster_member_value(row: &RosterMemberRow) -> Value {
    Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(WORKSPACE_ROSTER_SCHEMA_VERSION),
        ),
        (
            Value::from("person_ref"),
            Value::from(row.person_ref.to_hex()),
        ),
        (
            Value::from("actor_ref"),
            Value::from(row.actor_ref.to_hex()),
        ),
        (
            Value::from("companion_person_ref"),
            optional_ref(row.companion_person_ref),
        ),
        (
            Value::from("companion_actor_ref"),
            optional_ref(row.companion_actor_ref),
        ),
        (
            Value::from("companion_facet_ref"),
            optional_ref(row.companion_facet_ref),
        ),
        (Value::from("identity_ref"), optional_ref(row.identity_ref)),
    ])
}

pub(super) fn decode_roster_member_row(bytes: &[u8]) -> Result<RosterMemberRow> {
    let entries = decode_map(bytes)?;
    if required(&entries, "schema_version")?.as_u64() != Some(WORKSPACE_ROSTER_SCHEMA_VERSION) {
        return Err(invalid("roster member schema_version is unsupported"));
    }
    Ok(RosterMemberRow {
        person_ref: required_ref(&entries, "person_ref")?,
        actor_ref: required_ref(&entries, "actor_ref")?,
        companion_person_ref: optional_entity(&entries, "companion_person_ref")?,
        companion_actor_ref: optional_entity(&entries, "companion_actor_ref")?,
        companion_facet_ref: optional_entity(&entries, "companion_facet_ref")?,
        identity_ref: optional_entity(&entries, "identity_ref")?,
    })
}

// ---------------------------------------------------------------------------
// Intent digest
// ---------------------------------------------------------------------------

/// Fingerprints the intent so a replay can prove it is the SAME request.
///
/// Hashing the canonical encoding rather than comparing structs keeps the
/// journal small and total: `AgentDefinition` is only `PartialEq`, so a stored
/// value comparison would have had to hand-roll float equality.
pub(super) fn intent_digest(intent: &MemberOnboardingIntent) -> Result<[u8; 32]> {
    let encoded = encode_value(&intent_canonical_value(intent)?)?;
    Ok(*blake3::hash(&encoded).as_bytes())
}

pub(super) fn intent_canonical_value(intent: &MemberOnboardingIntent) -> Result<Value> {
    let companion = match &intent.companion_birth {
        Some(companion) => companion_canonical_value(companion)?,
        None => Value::Nil,
    };
    Ok(Value::Map(vec![
        (
            Value::from("onboarding_id"),
            Value::from(intent.onboarding_id.as_str()),
        ),
        (Value::from("workspace"), preset_value(&intent.workspace)),
        (
            Value::from("person_ref"),
            Value::from(intent.person_ref.to_hex()),
        ),
        (
            Value::from("actor_ref"),
            Value::from(intent.actor_ref.to_hex()),
        ),
        (
            Value::from("actor_definition"),
            Value::Binary(encode_agent_definition(&intent.actor_definition)?),
        ),
        (
            Value::from("work_facet_ref"),
            Value::from(intent.work_facet_ref.to_hex()),
        ),
        (
            Value::from("grant_bundle"),
            grant_bundle_canonical_value(&intent.grant_bundle),
        ),
        (Value::from("companion_birth"), companion),
        (
            Value::from("delegated_mailbox"),
            intent
                .delegated_mailbox
                .as_ref()
                .map_or(Value::Nil, mailbox_canonical_value),
        ),
        (Value::from("occurred_at"), Value::from(intent.occurred_at)),
    ]))
}

pub(super) fn grant_bundle_canonical_value(bundle: &MemberGrantBundle) -> Value {
    Value::Map(vec![
        (
            Value::from("federation_grant_ref"),
            Value::from(bundle.federation_grant_ref.to_hex()),
        ),
        (Value::from("role"), Value::from(bundle.role.as_str())),
        (Value::from("preset"), Value::from(bundle.preset.as_str())),
        (
            Value::from("companion_profile_grant_ref"),
            optional_ref(bundle.companion_profile_grant_ref),
        ),
    ])
}

pub(super) fn companion_canonical_value(companion: &CompanionBirthIntent) -> Result<Value> {
    Ok(Value::Map(vec![
        (
            Value::from("person_ref"),
            Value::from(companion.person_ref.to_hex()),
        ),
        (
            Value::from("actor_ref"),
            Value::from(companion.actor_ref.to_hex()),
        ),
        (
            Value::from("work_facet_ref"),
            Value::from(companion.work_facet_ref.to_hex()),
        ),
        (
            Value::from("companion_record_ref"),
            Value::from(companion.companion_record_ref.to_hex()),
        ),
        (
            Value::from("profile_grant_ref"),
            Value::from(companion.profile_grant_ref.to_hex()),
        ),
        (
            Value::from("actor_definition"),
            Value::Binary(encode_agent_definition(&companion.actor_definition)?),
        ),
        (
            Value::from("display_name"),
            Value::from(companion.display_name.as_str()),
        ),
    ]))
}

pub(super) fn mailbox_canonical_value(mailbox: &DelegatedMailboxOnboarding) -> Value {
    Value::Map(vec![
        (
            Value::from("starting_mode"),
            Value::from(mailbox.starting_mode.as_str()),
        ),
        (
            Value::from("identity_ref"),
            Value::from(mailbox.identity_ref.to_hex()),
        ),
        (
            Value::from("channel"),
            Value::from(mailbox.channel.as_str()),
        ),
        (
            Value::from("address"),
            Value::from(mailbox.address.as_str()),
        ),
        (
            Value::from("custody_name"),
            Value::from(mailbox.custody_name.as_str()),
        ),
        (
            Value::from("scopes"),
            Value::Array(
                mailbox
                    .scopes
                    .iter()
                    .map(|scope| Value::from(scope.as_str()))
                    .collect(),
            ),
        ),
    ])
}

pub(super) fn outcome_of(
    intent: &MemberOnboardingIntent,
    completed_at: u64,
) -> MemberOnboardingOutcome {
    MemberOnboardingOutcome {
        onboarding_id: intent.onboarding_id.clone(),
        person_ref: intent.person_ref,
        actor_ref: intent.actor_ref,
        federation_grant_ref: intent.grant_bundle.federation_grant_ref,
        companion_person_ref: intent.companion_birth.as_ref().map(|c| c.person_ref),
        companion_actor_ref: intent.companion_birth.as_ref().map(|c| c.actor_ref),
        delegated_identity_ref: intent.delegated_mailbox.as_ref().map(|m| m.identity_ref),
        completed_at,
    }
}

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------

pub(super) fn invalid(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

pub(super) fn validate_name(value: &str, reason: &'static str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_NAME_BYTES
        || value.as_bytes().contains(&ROSTER_KEY_SEPARATOR)
    {
        return Err(invalid(reason));
    }
    Ok(())
}

pub(super) fn require_kind(
    vault: &Vault,
    id: &EntityId,
    expected: u8,
    reason: &'static str,
) -> Result<()> {
    if vault.get_entity_type(id)? != Some(expected) {
        return Err(invalid(reason));
    }
    Ok(())
}

pub(super) fn read_federation_grant_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<FederationGrant>> {
    let Some(raw) = vault.store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_FEDERATION_GRANT {
        return Err(Error::InvalidEntityType(header.entity_type));
    }
    decode_federation_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
}

pub(super) fn encode_value(value: &Value) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, value)
        .map_err(|_| invalid("workspace roster MessagePack encode failed"))?;
    Ok(buf)
}

pub(super) fn decode_map(bytes: &[u8]) -> Result<Vec<(Value, Value)>> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| invalid("workspace roster MessagePack decode failed"))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid("workspace roster body has trailing bytes"));
    }
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(invalid("workspace roster body must be a map")),
    }
}

pub(super) fn required<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
        .ok_or_else(|| invalid("workspace roster body is missing a required key"))
}

pub(super) fn required_str(entries: &[(Value, Value)], key: &str) -> Result<String> {
    required(entries, key)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid("workspace roster body field must be a string"))
}

pub(super) fn required_ref(entries: &[(Value, Value)], key: &str) -> Result<EntityId> {
    let hex = required(entries, key)?
        .as_str()
        .ok_or_else(|| invalid("workspace roster body ref must be a hex string"))?;
    EntityId::from_hex(hex).map_err(|_| invalid("workspace roster body ref is malformed"))
}

pub(super) fn optional_entity(entries: &[(Value, Value)], key: &str) -> Result<Option<EntityId>> {
    match required(entries, key)? {
        Value::Nil => Ok(None),
        value => {
            let hex = value
                .as_str()
                .ok_or_else(|| invalid("workspace roster body ref must be a hex string"))?;
            EntityId::from_hex(hex)
                .map(Some)
                .map_err(|_| invalid("workspace roster body ref is malformed"))
        }
    }
}

pub(super) fn optional_string(entries: &[(Value, Value)], key: &str) -> Result<Option<String>> {
    match required(entries, key)? {
        Value::Nil => Ok(None),
        value => value
            .as_str()
            .map(|text| Some(text.to_owned()))
            .ok_or_else(|| invalid("workspace roster body field must be a string")),
    }
}

pub(super) fn optional_ref(id: Option<EntityId>) -> Value {
    id.map_or(Value::Nil, |id| Value::from(id.to_hex()))
}
