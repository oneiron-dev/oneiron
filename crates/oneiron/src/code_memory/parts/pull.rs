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

/// Payload admission for one pull candidate, decided ON THE CALLER'S SNAPSHOT.
///
/// [`ScopedRead::ppr_node_visible`] is the canonical readability predicate —
/// literally `ScopedRead::is_entity_readable_with_policy_in`, the same
/// admission [`ScopedRead::get_entity_parts`] applies — and it answers in the
/// transaction it is handed. That is what lets this module decide a candidate
/// and MATERIALIZE it against one coherent view.
///
/// It has one hole a pull must close itself. For a CLAIM whose row is
/// header-only, `ScopedRead` falls through to `Vault::is_deleted_shell`, which
/// opens a read transaction OF ITS OWN; nested read transactions on one thread
/// are forbidden, so reaching it under a live `rtxn` would fail the WHOLE pull
/// rather than skip one payload. A header-only CLAIM is unreadable either way
/// — it is a soft-delete shell, or a body no claim decoder can read — so the
/// answer is settled here, on this snapshot, and the payload is skipped.
///
/// Nothing else is decided locally: every other row goes to the canonical
/// predicate, so this can neither widen nor narrow what the lane admits.
fn payload_visible_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    scoped_read: &ScopedRead<'_>,
    payload: CodeMemoryPayloadRef,
) -> Result<bool> {
    let payload_id = payload.entity_id();
    if let Some(raw) = store.entities.get(rtxn, payload_id.as_bytes())? {
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type == ENTITY_TYPE_CLAIM && raw.len() == ENTITY_METADATA_HEADER_LEN {
            return Ok(false);
        }
    }
    scoped_read.ppr_node_visible(rtxn, &payload_id)
}

/// One admitted note candidate: inherited relevance, owning symbol, slot name,
/// and the slot value itself — the tuple the final ranking sorts on.
type PullNoteCandidates = Vec<(f32, EntityId, CodeMemorySlotName, CodeMemorySlotValue)>;

/// The bounded candidate sweep over `retained`, entirely inside `rtxn`.
///
/// Returns at most `request.limit` notes, every one of them already admitted
/// by [`payload_visible_in_txn`] on THIS snapshot, plus the always-on
/// registrations of every retained symbol (which the caller's note limit never
/// cuts).
///
/// TWO BOUNDS, BOTH LOAD-BEARING:
///
/// * a denied payload never consumes a place. Admission happens BEFORE the
///   candidate is counted, and it is the same decision that will still hold
///   when the result is built — so the sweep keeps scanning and backfills from
///   lower-ranked slots and symbols instead of returning short;
/// * slot bodies stream ([`stream_slots_for_symbol`]) and stop as soon as the
///   candidate set is full, so `request.limit` — not the stored slot count,
///   which carries no per-symbol ceiling — bounds the decode work and the live
///   memory. Once the notes are full and no contracts are wanted, the symbol
///   loop stops too.
///
/// STOPPING EARLY CANNOT LOSE A HIGHER-RANKED NOTE, because this sweep visits
/// candidates in EXACTLY the caller's final order. `ppr::sort_scores` hands
/// `retained` back as score-descending then id-ascending; a slot prefix cursor
/// yields slot names ascending; and a decoded slot body is
/// `CodeMemorySlotValue::sort_key`-ascending (`decode_slot` refuses any other
/// order). That is the `pull_code_memory` comparator, term for term — so the
/// first `limit` admitted candidates ARE the top `limit`, not merely the first
/// ones found.
fn collect_pull_candidates(
    vault: &Vault,
    rtxn: &RoTxn<'_>,
    scoped_read: &ScopedRead<'_>,
    request: &CodeMemoryPullRequest,
    retained: &[ScoredEntity],
) -> Result<(PullNoteCandidates, Vec<AlwaysOnCodeMemoryContract>)> {
    let note_limit = request.limit;
    let mut candidate_notes: PullNoteCandidates = Vec::with_capacity(note_limit);
    let mut candidate_contracts: Vec<AlwaysOnCodeMemoryContract> = Vec::new();

    for scored in retained {
        let notes_full = candidate_notes.len() == note_limit;
        if notes_full && !request.include_always_on_contracts {
            break;
        }
        if !notes_full {
            stream_slots_for_symbol(&vault.store, rtxn, &scored.id, |slot| {
                let CodeMemorySlot { name, values, .. } = slot;
                for value in values {
                    if !payload_visible_in_txn(&vault.store, rtxn, scoped_read, value.payload)? {
                        continue;
                    }
                    candidate_notes.push((scored.score, scored.id, name.clone(), value));
                    if candidate_notes.len() == note_limit {
                        return Ok(ControlFlow::Break(()));
                    }
                }
                Ok(ControlFlow::Continue(()))
            })?;
        }
        if request.include_always_on_contracts {
            candidate_contracts.extend(read_always_on_for_symbol(&vault.store, rtxn, &scored.id)?);
        }
    }

    Ok((candidate_notes, candidate_contracts))
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
/// 4. resolve slots and always-on registrations for those symbols, and clamp
///    every referenced PAYLOAD, all in THAT SAME transaction. The walk gate
///    above admits the SYMBOLS a ranking may traverse; the payload clamp stays
///    as defence in depth for both;
/// 5. sort surviving notes by descending inherited relevance then canonical
///    keys, and apply the caller limit exactly once;
/// 6. label everything `Data`.
///
/// ONE SNAPSHOT DECIDES ADMISSION AND THE RESULT. There is deliberately no
/// second, later clamp: re-asking [`ScopedRead::get_entity_parts`] after this
/// transaction closed would ask a NEWER snapshot, and a candidate that had
/// already consumed one of the caller's `limit` places could then be dropped
/// by that newer answer — a concurrent delete or policy change would make the
/// pull return fewer notes than the snapshot it ranked actually holds, with no
/// lower-ranked note ever collected to take the empty place. The in-transaction
/// predicate is the SAME admission `get_entity_parts` applies (see
/// [`payload_visible_in_txn`]), so coherence costs no scope.
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

    let (mut permitted_notes, mut candidate_contracts) =
        collect_pull_candidates(vault, &rtxn, scoped_read, &request, &retained)?;

    permitted_notes.sort_by(|left, right| {
        right
            .0
            .total_cmp(&left.0)
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| left.2.cmp(&right.2))
            .then_with(|| left.3.sort_key().cmp(&right.3.sort_key()))
    });
    // The caller's cut, applied EXACTLY ONCE and only to the note list. Bounded
    // admission already stops at the same number, so this cuts nothing today;
    // it stays because the limit is a contract of THIS function, and the one
    // place that enforces it should be visible here rather than inferred from
    // the sweep.
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
            // Same snapshot, same predicate as the notes above. Always-on
            // registrations carry no caller cut, so no place can be consumed
            // here — but a contract and a note naming the SAME payload must
            // never disagree about whether this actor may see it.
            if !payload_visible_in_txn(&vault.store, &rtxn, scoped_read, contract.payload)? {
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

    // Held deliberately this far: admission, ranking, and materialization all
    // answered from THIS snapshot, and nothing above may reopen a newer one.
    drop(rtxn);
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

