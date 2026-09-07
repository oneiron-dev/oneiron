use super::*;

// ---------------------------------------------------------------------------
// Claim value codec
// ---------------------------------------------------------------------------

pub(super) fn encode_passport_value(
    passport: &ThreadPassport,
    references: &[CanonicalMessageId],
    in_reply_to: Option<&CanonicalMessageId>,
) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(THREAD_PASSPORT_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_IDENTITY_REF),
            Value::from(passport.identity_ref.to_hex()),
        ),
        (
            Value::from(KEY_MESSAGE_ID),
            Value::from(passport.message_id.as_str()),
        ),
        (
            Value::from(KEY_THREAD_REF),
            Value::from(passport.thread_ref.as_str()),
        ),
        (
            Value::from(KEY_ACTOR_REF),
            Value::from(passport.mask.actor_ref.to_hex()),
        ),
        (
            Value::from(KEY_FACET_REF),
            encode_optional_ref(passport.mask.facet_ref),
        ),
        (
            Value::from(KEY_OBSERVED_AT),
            Value::from(passport.observed_at),
        ),
        (
            Value::from(KEY_REFERENCES),
            Value::Array(
                references
                    .iter()
                    .map(|id| Value::from(id.as_str()))
                    .collect(),
            ),
        ),
        (
            Value::from(KEY_IN_REPLY_TO),
            in_reply_to.map_or(Value::Nil, |id| Value::from(id.as_str())),
        ),
    ])
}

pub(super) fn encode_alias_value(
    identity_ref: EntityId,
    from_thread_ref: &str,
    to_thread_ref: &str,
    observed_at: u64,
) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(THREAD_PASSPORT_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_IDENTITY_REF),
            Value::from(identity_ref.to_hex()),
        ),
        (
            Value::from(KEY_FROM_THREAD_REF),
            Value::from(from_thread_ref),
        ),
        (Value::from(KEY_TO_THREAD_REF), Value::from(to_thread_ref)),
        (Value::from(KEY_OBSERVED_AT), Value::from(observed_at)),
    ])
}

pub(super) fn encode_optional_ref(id: Option<EntityId>) -> Value {
    id.map_or(Value::Nil, |id| Value::from(id.to_hex()))
}

/// Every decode failure below is [`Error::CorruptedIndex`] on purpose: these
/// bytes came out of the store, so a shape the typed doors cannot have written
/// is a corrupt row, not a bad argument.
pub(super) fn corrupt(reason: &'static str) -> Error {
    Error::CorruptedIndex(reason)
}

pub(super) fn map_entries<'a>(
    value: &'a Value,
    reason: &'static str,
) -> Result<&'a [(Value, Value)]> {
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(corrupt(reason)),
    }
}

pub(super) fn map_entry<'a>(
    entries: &'a [(Value, Value)],
    key: &str,
    reason: &'static str,
) -> Result<&'a Value> {
    entries
        .iter()
        .find(|(entry_key, _)| entry_key.as_str() == Some(key))
        .map(|(_, value)| value)
        .ok_or_else(|| corrupt(reason))
}

pub(super) fn decode_ref(value: &Value, reason: &'static str) -> Result<EntityId> {
    value
        .as_str()
        .and_then(|hex| EntityId::from_hex(hex).ok())
        .ok_or_else(|| corrupt(reason))
}

pub(super) fn decode_optional_ref(value: &Value, reason: &'static str) -> Result<Option<EntityId>> {
    if matches!(value, Value::Nil) {
        Ok(None)
    } else {
        decode_ref(value, reason).map(Some)
    }
}

pub(super) fn decode_thread_ref(value: &Value, reason: &'static str) -> Result<String> {
    let raw = value.as_str().ok_or_else(|| corrupt(reason))?;
    validate_minted_thread_ref(raw).map_err(|_| corrupt(reason))?;
    Ok(raw.to_owned())
}

pub(super) fn decode_schema_version(
    entries: &[(Value, Value)],
    reason: &'static str,
) -> Result<()> {
    let version = map_entry(entries, KEY_SCHEMA_VERSION, reason)?
        .as_u64()
        .ok_or_else(|| corrupt(reason))?;
    if version == THREAD_PASSPORT_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(corrupt(reason))
    }
}

pub(super) fn decode_passport_value(subject: EntityId, value: &Value) -> Result<ThreadPassport> {
    const REASON: &str = "thread passport claim value is malformed";
    let entries = map_entries(value, REASON)?;
    validate_keys(entries, &THREAD_PASSPORT_BODY_KEYS)?;
    decode_relationships(value)?;
    decode_schema_version(entries, "thread passport claim schema version is unknown")?;
    let identity_ref = decode_ref(map_entry(entries, KEY_IDENTITY_REF, REASON)?, REASON)?;
    if identity_ref != subject {
        return Err(corrupt(
            "thread passport identity_ref disagrees with its claim subject",
        ));
    }
    let raw_message_id = map_entry(entries, KEY_MESSAGE_ID, REASON)?
        .as_str()
        .ok_or_else(|| corrupt(REASON))?;
    validate_canonical_message_id(raw_message_id)
        .map_err(|_| corrupt("stored thread passport message id is not canonical"))?;
    Ok(ThreadPassport {
        identity_ref,
        message_id: CanonicalMessageId(raw_message_id.to_owned()),
        thread_ref: decode_thread_ref(map_entry(entries, KEY_THREAD_REF, REASON)?, REASON)?,
        mask: ThreadMask {
            identity_ref,
            actor_ref: decode_ref(map_entry(entries, KEY_ACTOR_REF, REASON)?, REASON)?,
            facet_ref: decode_optional_ref(map_entry(entries, KEY_FACET_REF, REASON)?, REASON)?,
        },
        observed_at: map_entry(entries, KEY_OBSERVED_AT, REASON)?
            .as_u64()
            .ok_or_else(|| corrupt(REASON))?,
    })
}

pub(super) fn decode_alias_value(subject: EntityId, value: &Value) -> Result<(String, String)> {
    const REASON: &str = "thread alias claim value is malformed";
    let entries = map_entries(value, REASON)?;
    validate_keys(entries, &THREAD_ALIAS_BODY_KEYS)?;
    decode_schema_version(entries, "thread alias claim schema version is unknown")?;
    if decode_ref(map_entry(entries, KEY_IDENTITY_REF, REASON)?, REASON)? != subject {
        return Err(corrupt(
            "thread alias identity_ref disagrees with its claim subject",
        ));
    }
    map_entry(entries, KEY_OBSERVED_AT, REASON)?
        .as_u64()
        .ok_or_else(|| corrupt(REASON))?;
    let from = decode_thread_ref(map_entry(entries, KEY_FROM_THREAD_REF, REASON)?, REASON)?;
    let to = decode_thread_ref(map_entry(entries, KEY_TO_THREAD_REF, REASON)?, REASON)?;
    if from <= to {
        return Err(corrupt(
            "thread aliases must point to a smaller minted root",
        ));
    }
    Ok((from, to))
}

fn validate_keys(entries: &[(Value, Value)], expected: &[&str]) -> Result<()> {
    let keys: BTreeSet<_> = entries.iter().filter_map(|(key, _)| key.as_str()).collect();
    if entries.len() != expected.len()
        || keys.len() != entries.len()
        || !expected.iter().all(|key| keys.contains(key))
    {
        return Err(corrupt("thread claim keys must be exact and unique"));
    }
    Ok(())
}

fn validate_minted_thread_ref(value: &str) -> Result<()> {
    let Some(hash) = value.strip_prefix(THREAD_REF_PREFIX) else {
        return Err(corrupt("thread claim ref is not a minted email root"));
    };
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(corrupt("thread claim root hash is malformed"));
    }
    Ok(())
}

pub(super) fn decode_relationships(
    value: &Value,
) -> Result<(Vec<CanonicalMessageId>, Option<CanonicalMessageId>)> {
    const REASON: &str = "thread passport relationships are malformed";
    let entries = map_entries(value, REASON)?;
    let decode = |value: &Value| -> Result<CanonicalMessageId> {
        let raw = value.as_str().ok_or_else(|| corrupt(REASON))?;
        validate_canonical_message_id(raw).map_err(|_| corrupt(REASON))?;
        Ok(CanonicalMessageId(raw.to_owned()))
    };
    let Value::Array(raw) = map_entry(entries, KEY_REFERENCES, REASON)? else {
        return Err(corrupt(REASON));
    };
    let references = raw.iter().map(decode).collect::<Result<Vec<_>>>()?;
    if references.iter().collect::<BTreeSet<_>>().len() != references.len() {
        return Err(corrupt("thread passport references must be unique"));
    }
    let parent = map_entry(entries, KEY_IN_REPLY_TO, REASON)?;
    let in_reply_to = if parent.is_nil() {
        None
    } else {
        Some(decode(parent)?)
    };
    Ok((references, in_reply_to))
}

/// The shared structural door, including generic puts and replicated replay.
pub(crate) fn validate_thread_claim_structure(body: &ClaimBody) -> Result<()> {
    let validate = || -> Result<()> {
        let ClaimSubject::Entity(subject) = body.subject else {
            return Err(corrupt("thread claim subject must be an entity"));
        };
        let observed_at = if body.predicate == PREDICATE_THREAD_PASSPORT {
            decode_passport_value(subject, &body.value)?.observed_at
        } else {
            decode_alias_value(subject, &body.value)?;
            map_entry(
                map_entries(&body.value, "thread alias value")?,
                KEY_OBSERVED_AT,
                "thread alias timestamp",
            )?
            .as_u64()
            .ok_or_else(|| corrupt("thread alias timestamp"))?
        };
        if body.source != Some(ClaimSource::Observed)
            || body.valid_from != Some(observed_at)
            || !matches!(
                body.approval,
                ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
            )
            || body.stale
            || body.world.is_some()
            || body.rel.is_some()
            || body.scope.is_some()
            || (body.lifecycle == ClaimLifecycleStatus::Active && body.valid_to.is_some())
            || body.valid_to.is_some_and(|end| end < observed_at)
        {
            return Err(corrupt(
                "thread claims require unscoped observed provenance and matching metadata",
            ));
        }
        Ok(())
    };
    validate()
        .map_err(|_| Error::InvalidClaimBody("thread claim structure or provenance is invalid"))
}
