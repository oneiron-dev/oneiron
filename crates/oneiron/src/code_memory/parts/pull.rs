// Section 5 — pull read: ScopedRead clamp plus provenance-labelled DATA
// ---------------------------------------------------------------------------

/// The bounded always-on subset: interface and policy contracts only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeMemoryContractKind {
    Interface,
    Policy,
}

impl CodeMemoryContractKind {
    const fn tag(self) -> u8 {
        match self {
            Self::Interface => CONTRACT_TAG_INTERFACE,
            Self::Policy => CONTRACT_TAG_POLICY,
        }
    }

    fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            CONTRACT_TAG_INTERFACE => Ok(Self::Interface),
            CONTRACT_TAG_POLICY => Ok(Self::Policy),
            _ => Err(record_error()),
        }
    }
}

/// One registered always-on interface/policy contract.
///
/// Always-on status is ATTACHMENT METADATA, not a NOTE payload field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlwaysOnCodeMemoryContract {
    pub symbol_id: EntityId,
    pub slot: CodeMemorySlotName,
    pub payload: CodeMemoryPayloadRef,
    pub kind: CodeMemoryContractKind,
    pub actor_id: EntityId,
    pub valid_time: TimeRange,
    pub recorded_at: u64,
    pub provenance_claim_id: EntityId,
}

/// What an L2 pull returns is DATA. There is deliberately no instruction or
/// executable material kind in this enum, and none may be added: an L2 note
/// is context a caller reasons about, never a command it obeys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvenanceMaterialKind {
    Data,
}

/// The provenance label carried by every pulled item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeMemoryProvenance {
    pub actor_id: EntityId,
    pub valid_time: TimeRange,
    pub recorded_at: u64,
    pub provenance_claim_id: EntityId,
}

/// A pulled item and its label. There is no unlabelled read surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenanceLabelled<T> {
    pub data: T,
    pub provenance: CodeMemoryProvenance,
    pub material_kind: ProvenanceMaterialKind,
}

/// An L2 pull request. PULL, never push: nothing in this module calls back
/// into a caller with memory it did not ask for.
#[derive(Debug, Clone, PartialEq)]
pub struct CodeMemoryPullRequest {
    /// UNSCORED `CODE_SYMBOL` ids. PPR assigns relevance; callers do not.
    pub seed_symbols: Vec<EntityId>,
    /// Threshold on the inherited symbol relevance — the score type carried
    /// by `pipeline::ScoredEntity`.
    pub minimum_relevance: f32,
    /// Caller cut, applied EXACTLY ONCE and only to the note list.
    pub limit: usize,
    pub include_always_on_contracts: bool,
}

impl CodeMemoryPullRequest {
    /// A request over `seed_symbols` with the default note limit and no
    /// relevance floor.
    pub fn new(seed_symbols: Vec<EntityId>) -> Self {
        Self {
            seed_symbols,
            minimum_relevance: 0.0,
            limit: CODE_MEMORY_DEFAULT_PULL_LIMIT,
            include_always_on_contracts: true,
        }
    }
}

/// Provenance-labelled DATA returned by an L2 pull.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeMemoryPullResult {
    pub notes: Vec<ProvenanceLabelled<CodeMemorySlotValue>>,
    pub always_on_contracts: Vec<ProvenanceLabelled<AlwaysOnCodeMemoryContract>>,
}

/// ScopedRead-clamped L2 pull.
///
/// Read order is fixed and load-bearing:
///
/// 1. validate seeds / threshold / limit;
/// 2. ONE `RoTxn`: seeds must be live `CODE_SYMBOL`s, then the ACTOR-SCOPED,
///    compute-only PPR entry at [`CODE_MEMORY_PPR_DEPTH`], alpha `0.15`,
///    [`SeedWeighting::Specificity`] (`lambda_for_kind(Blocks) == None` keeps
///    readiness edges out of the walk). SCOPE BEFORE MASS: this `ScopedRead`
///    is the walk's node-visibility gate, so a seed the actor cannot read
///    carries no seed mass and no hop is taken through a node it cannot read
///    — a permitted symbol reachable only across a denied CLAIM bridge is
///    unreachable, in either edge direction, rather than merely unlabelled.
///    Clamping payloads after an unscoped ranking could not achieve that: the
///    mass had already crossed, so both membership and ORDER encoded graph
///    structure the actor may not see. Being compute-only is part of the same
///    boundary — the shared `ppr_cache` carries no actor, so this walk neither
///    reads nor writes it, and takes no dependency or graph-version write;
/// 3. keep every scored `CODE_SYMBOL` at or above `minimum_relevance` — the
///    caller's note limit is NOT applied to symbols;
/// 4. resolve slots and always-on registrations for those symbols in the same
///    transaction;
/// 5. `drop(rtxn)` BEFORE any [`ScopedRead::get_entity_parts`] call, which
///    opens its own read transaction (nested read transactions on one thread
///    are forbidden), and clamp every referenced entity. The walk gate above
///    admits the SYMBOLS a ranking may traverse; this clamp still decides each
///    PAYLOAD, and stays as defence in depth for both;
/// 6. sort surviving notes by descending inherited relevance then canonical
///    keys, and apply the caller limit exactly once, here;
/// 7. label everything `Data`.
pub fn pull_code_memory(
    vault: &Vault,
    scoped_read: &ScopedRead<'_>,
    request: CodeMemoryPullRequest,
) -> Result<CodeMemoryPullResult> {
    if request.seed_symbols.is_empty() {
        return Err(Error::CodeMemoryInvalidAnchor {
            reason: "pull requires at least one CODE_SYMBOL seed",
        });
    }
    if request.seed_symbols.len() > CODE_MEMORY_MAX_PULL_LIMIT {
        return Err(Error::CodeMemoryLimitExceeded {
            kind: "pull seed symbols",
            limit: CODE_MEMORY_MAX_PULL_LIMIT,
        });
    }
    if !request.minimum_relevance.is_finite() || request.minimum_relevance < 0.0 {
        return Err(Error::CodeMemoryInvalidAnchor {
            reason: "pull minimum relevance must be a finite non-negative score",
        });
    }
    if request.limit == 0 || request.limit > CODE_MEMORY_MAX_PULL_LIMIT {
        return Err(Error::CodeMemoryLimitExceeded {
            kind: "pull note limit",
            limit: CODE_MEMORY_MAX_PULL_LIMIT,
        });
    }

    let rtxn = vault.store.env.read_txn()?;
    for seed in &request.seed_symbols {
        if entity_type_in_txn(&vault.store, &rtxn, seed)? != Some(ENTITY_TYPE_CODE_SYMBOL) {
            return Err(Error::CodeMemoryInvalidAnchor {
                reason: "every pull seed must be a live CODE_SYMBOL entity",
            });
        }
    }

    let scores = ppr_query_scoped_in_txn(
        &vault.store,
        &rtxn,
        &request.seed_symbols,
        CODE_MEMORY_PPR_DEPTH,
        CODE_MEMORY_PPR_ALPHA,
        SeedWeighting::Specificity,
        scoped_read,
    )?;

    let mut retained: Vec<ScoredEntity> = Vec::new();
    for score in scores {
        if retained.len() == CODE_MEMORY_MAX_PULL_LIMIT {
            break;
        }
        if score.score < request.minimum_relevance {
            continue;
        }
        if entity_type_in_txn(&vault.store, &rtxn, &score.id)? == Some(ENTITY_TYPE_CODE_SYMBOL) {
            retained.push(score);
        }
    }

    let mut candidate_notes: Vec<(f32, EntityId, CodeMemorySlotName, CodeMemorySlotValue)> =
        Vec::new();
    let mut candidate_contracts: Vec<AlwaysOnCodeMemoryContract> = Vec::new();
    for scored in &retained {
        for slot in read_slots_for_symbol(&vault.store, &rtxn, &scored.id)? {
            for value in slot.values {
                candidate_notes.push((scored.score, scored.id, slot.name.clone(), value));
            }
        }
        if request.include_always_on_contracts {
            candidate_contracts.extend(read_always_on_for_symbol(&vault.store, &rtxn, &scored.id)?);
        }
    }

    // The clamp opens its OWN read transaction; the outer one must be gone
    // first (landed short-lived-txn pattern, `code_symbol::code_symbol_ppr_neighbors`).
    drop(rtxn);

    let mut permitted_notes = Vec::new();
    for (score, symbol_id, slot_name, value) in candidate_notes {
        if scoped_read
            .get_entity_parts(&value.payload.entity_id())?
            .is_none()
        {
            continue;
        }
        permitted_notes.push((score, symbol_id, slot_name, value));
    }

    permitted_notes.sort_by(|left, right| {
        right
            .0
            .total_cmp(&left.0)
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| left.2.cmp(&right.2))
            .then_with(|| left.3.sort_key().cmp(&right.3.sort_key()))
    });
    permitted_notes.truncate(request.limit);

    let notes = permitted_notes
        .into_iter()
        .map(|(_, _, _, value)| ProvenanceLabelled {
            provenance: CodeMemoryProvenance {
                actor_id: value.actor_id,
                valid_time: value.valid_time,
                recorded_at: value.recorded_at,
                provenance_claim_id: value.provenance_claim_id,
            },
            data: value,
            material_kind: ProvenanceMaterialKind::Data,
        })
        .collect();

    let mut always_on_contracts = Vec::new();
    if request.include_always_on_contracts {
        candidate_contracts.sort_by(|left, right| {
            (left.symbol_id, &left.slot, left.payload).cmp(&(
                right.symbol_id,
                &right.slot,
                right.payload,
            ))
        });
        for contract in candidate_contracts {
            if scoped_read
                .get_entity_parts(&contract.payload.entity_id())?
                .is_none()
            {
                continue;
            }
            always_on_contracts.push(ProvenanceLabelled {
                provenance: CodeMemoryProvenance {
                    actor_id: contract.actor_id,
                    valid_time: contract.valid_time,
                    recorded_at: contract.recorded_at,
                    provenance_claim_id: contract.provenance_claim_id,
                },
                data: contract,
                material_kind: ProvenanceMaterialKind::Data,
            });
        }
    }

    Ok(CodeMemoryPullResult {
        notes,
        always_on_contracts,
    })
}

/// Registers one always-on interface/policy contract.
///
/// Accepts ONLY a [`CodeMemoryPayloadRef::NoteEntity`] that resolves live to
/// `ENTITY_TYPE_NOTE` on a live `CODE_SYMBOL` anchor, under the per-symbol
/// bound of [`CODE_MEMORY_MAX_ALWAYS_ON_CONTRACTS`] distinct
/// `(symbol, slot, payload)` keys. Re-registering an existing key is an
/// idempotent upsert that does not consume a fresh slot.
///
/// POSITIVE NOTE TYPING (ARCH-0032 has landed, `ENTITY_TYPE_NOTE = 106`):
/// docs contracts outrank the blueprint's stale "no NOTE entity type exists
/// in v1" rule, so registration enforces the note type rather than the weaker
/// live-non-CLAIM predicate. The CLAIM clamp inside
/// `ScopedRead::get_entity_parts` is untouched and still governs reads.
pub fn register_always_on_contract(
    store: &Store,
    txn: &mut RwTxn<'_>,
    contract: AlwaysOnCodeMemoryContract,
) -> Result<()> {
    validate_code_symbol_anchor(store, txn, &contract.symbol_id)?;
    validate_time_range(contract.valid_time, "always-on contract valid time")?;
    let CodeMemoryPayloadRef::NoteEntity(note_id) = contract.payload else {
        return Err(Error::CodeMemoryAlwaysOnInvalid(
            "always-on contracts accept only NoteEntity payload refs",
        ));
    };
    let payload_type = entity_type_in_txn(store, txn, &note_id)?;
    if payload_type.is_none() {
        return Err(Error::CodeMemoryAlwaysOnInvalid(
            "always-on contract payload does not resolve to a live entity",
        ));
    }
    if payload_type != Some(ENTITY_TYPE_NOTE) {
        return Err(Error::CodeMemoryAlwaysOnInvalid(
            "always-on contract payload must be a NOTE entity",
        ));
    }

    let key = always_on_key(&contract.symbol_id, &contract.slot, contract.payload);
    if store.vault_meta.get(txn, &key)?.is_none() {
        let registered = count_prefix(store, txn, &always_on_symbol_prefix(&contract.symbol_id))?;
        if registered >= CODE_MEMORY_MAX_ALWAYS_ON_CONTRACTS {
            return Err(Error::CodeMemoryLimitExceeded {
                kind: "always-on contracts per symbol",
                limit: CODE_MEMORY_MAX_ALWAYS_ON_CONTRACTS,
            });
        }
    }
    write_always_on(store, txn, &contract)
}

