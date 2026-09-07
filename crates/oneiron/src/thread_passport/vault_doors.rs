use super::*;

// ---------------------------------------------------------------------------
// Typed Vault doors
// ---------------------------------------------------------------------------

impl Vault {
    /// Lands one inbound message in exactly one durable thread.
    ///
    /// The passport row, and every alias row the same message's references
    /// force, are written in ONE transaction: a bridging message that
    /// converges two roots must never leave a vault where the passport exists
    /// but the convergence does not.
    ///
    /// Idempotent by construction. Replaying the same provider event finds the
    /// active `(identity_ref × Message-ID)` row, returns it with its thread
    /// re-resolved through today's aliases. Identical evidence writes nothing.
    /// New reference evidence is appended without restamping the passport or
    /// mask. All readers reconcile physical duplicates to one logical row.
    ///
    /// A first write by a SECOND identity of a Message-ID the vault already
    /// threaded still writes its own passport row, but lands on the thread the
    /// first identity's row resolves to today rather than minting a parallel
    /// one. Whatever thread this call settles on, the returned
    /// [`ThreadPassportResolution::canonical_thread_ref`] is a fixed point of
    /// the alias graph and is therefore always safe to pin.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EntityNotFound`] or [`Error::InvalidEntityType`] when
    /// `identity_ref` is not a live `ChannelIdentity` record, and
    /// [`Error::CorruptedIndex`] when a stored passport or alias row cannot be
    /// decoded or the alias graph cycles.
    pub fn record_thread_passport(
        &self,
        input: ThreadPassportInput,
    ) -> Result<ThreadPassportResolution> {
        self.with_write_txn(|wtxn| {
            require_channel_identity(self, wtxn, input.identity_ref)?;
            let before = ThreadState::load(self, wtxn)?;
            let existing = before.logical_rows().into_iter().find(|row| {
                row.passport.identity_ref == input.identity_ref
                    && row.passport.message_id == input.message_id
            });
            let mut roots = BTreeSet::new();
            for message in std::iter::once(&input.message_id).chain(input.reference_chain()) {
                if let Some(thread) = before.message_threads.get(message) {
                    roots.insert(thread.clone());
                }
            }
            let chosen = roots
                .first()
                .cloned()
                .unwrap_or_else(|| input.message_id.minted_thread_ref());
            let passport = existing.as_ref().map_or_else(
                || ThreadPassport {
                    identity_ref: input.identity_ref,
                    message_id: input.message_id.clone(),
                    thread_ref: chosen,
                    mask: input.mask(),
                    observed_at: input.observed_at,
                },
                |row| row.passport.clone(),
            );
            let mut references = input.references.clone();
            let mut seen = BTreeSet::new();
            references.retain(|reference| seen.insert(reference.clone()));
            // Replays keep every original passport field. New header evidence
            // is append-only so concurrent observations cannot overwrite each
            // other through the entity-id CRDT. Logical readers deduplicate.
            let already_recorded = before.rows.iter().any(|row| {
                row.passport.identity_ref == input.identity_ref
                    && row.passport.message_id == input.message_id
                    && references
                        .iter()
                        .all(|reference| row.references.contains(reference))
                    && input
                        .in_reply_to
                        .as_ref()
                        .is_none_or(|parent| row.in_reply_to.as_ref() == Some(parent))
            });
            if !already_recorded {
                put_passport_claim(
                    self,
                    wtxn,
                    &passport,
                    &references,
                    input.in_reply_to.as_ref(),
                )?;
            }
            let after = ThreadState::load(self, wtxn)?;
            let canonical_thread_ref = resolve_thread_alias(&after.edges, &passport.thread_ref)?;
            let aliased_thread_refs: Vec<_> = roots
                .into_iter()
                .filter(|thread| *thread != canonical_thread_ref)
                .collect();
            // Evidence lands before its derived receipts, in the same txn.
            for from in &aliased_thread_refs {
                put_alias_claim(
                    self,
                    wtxn,
                    input.identity_ref,
                    from,
                    &canonical_thread_ref,
                    input.observed_at,
                )?;
            }
            Ok(ThreadPassportResolution {
                passport,
                canonical_thread_ref,
                aliased_thread_refs,
            })
        })
    }

    /// The active passport for one `(identity_ref × Message-ID)`, if any.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CorruptedIndex`] when a stored passport row cannot be
    /// decoded.
    pub fn thread_passport(
        &self,
        identity_ref: &EntityId,
        message_id: &CanonicalMessageId,
    ) -> Result<Option<ThreadPassport>> {
        let rtxn = self.store.env.read_txn()?;
        Ok(ThreadState::load(self, &rtxn)?
            .logical_rows()
            .into_iter()
            .find(|row| {
                row.passport.identity_ref == *identity_ref && row.passport.message_id == *message_id
            })
            .map(|row| row.passport))
    }

    /// Follows `thread_ref` through the alias graph to its fixed point.
    ///
    /// An unknown ref is its own fixed point: aliases record convergence, not
    /// existence.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidClaimBody`] for a malformed `thread_ref` and
    /// [`Error::CorruptedIndex`] for malformed stored routing evidence.
    /// Valid concurrent forks and long histories resolve as one component.
    pub fn canonical_thread_ref(&self, thread_ref: &str) -> Result<String> {
        validate_thread_ref(thread_ref)?;
        let rtxn = self.store.env.read_txn()?;
        canonical_thread_ref_in_txn(self, &rtxn, thread_ref)
    }

    /// Every active passport on `thread_ref`'s canonical thread, in pin order.
    ///
    /// The first element is the row whose mask the thread wears.
    ///
    /// # Errors
    ///
    /// As [`Vault::canonical_thread_ref`], plus decode failures on stored
    /// passport rows.
    pub fn thread_passports(&self, thread_ref: &str) -> Result<Vec<ThreadPassport>> {
        validate_thread_ref(thread_ref)?;
        let rtxn = self.store.env.read_txn()?;
        let state = ThreadState::load(self, &rtxn)?;
        let edges = &state.edges;
        let canonical = resolve_thread_alias(edges, thread_ref)?;
        let rows = state.logical_rows();
        Ok(passports_on_thread(rows, edges, &canonical)?
            .into_values()
            .collect())
    }

    /// The mask a thread already wears, judged against what a caller wants.
    ///
    /// The thread's FIRST passport pins the mask and nothing later moves it.
    /// A `requested` mask that disagrees comes back as
    /// [`StickyMaskDecision::Conflict`] carrying both sides — the composer
    /// decides what to say about it, and a human handoff stays message
    /// content. There is no arm that changes the pin, because changing the
    /// From address mid-thread breaks client threading, reply-history scoring,
    /// and allow-list continuity all at once.
    ///
    /// # Errors
    ///
    /// As [`Vault::canonical_thread_ref`], plus decode failures on stored
    /// passport rows.
    pub fn sticky_thread_mask(
        &self,
        thread_ref: &str,
        requested: Option<ThreadMask>,
    ) -> Result<StickyMaskDecision> {
        validate_thread_ref(thread_ref)?;
        let rtxn = self.store.env.read_txn()?;
        let state = ThreadState::load(self, &rtxn)?;
        let edges = &state.edges;
        let canonical = resolve_thread_alias(edges, thread_ref)?;
        let rows = state.logical_rows();
        let ordered = passports_on_thread(rows, edges, &canonical)?;
        let Some(pinning) = ordered.into_values().next() else {
            return Ok(StickyMaskDecision::Unset);
        };
        let pinned = pinning.mask;
        Ok(match requested {
            None => StickyMaskDecision::Keep(pinned),
            Some(requested) if requested == pinned => StickyMaskDecision::Keep(pinned),
            Some(requested) => StickyMaskDecision::Conflict { pinned, requested },
        })
    }

    /// Joins (or parts) `party` on `thread_ref`'s CANONICAL thread.
    ///
    /// A thin, alias-aware wrapper over the existing public
    /// [`crate::comm::record_comm_thread_event`]: membership stays a
    /// `comm.thread_member` claim with comm's own value shape, and this module
    /// adds only the guarantee that a party never lands on a thread ref that
    /// has since been converged away.
    ///
    /// # Errors
    ///
    /// As [`Vault::canonical_thread_ref`], plus
    /// [`Error::InvalidClaimBody`] when comm rejects the party or thread key.
    pub fn join_thread_party(
        &self,
        thread_ref: &str,
        party: &str,
        joined: bool,
        occurred_at: u64,
    ) -> Result<()> {
        validate_thread_ref(thread_ref)?;
        record_comm_thread_event(self, thread_ref, party, joined, occurred_at).map_err(|err| {
            match err {
                CommError::Engine(inner) => inner,
                _ => Error::InvalidClaimBody("comm rejected the thread membership event"),
            }
        })
    }
}
