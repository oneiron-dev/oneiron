//! Sealing one compaction window and returning its typed hook Pending.
//! Pure child of the executor compaction host.

use super::*;

impl EngineNativeExecutor<'_> {
    pub(super) fn seal_compaction_window(
        &self,
        driver: &mut crate::compaction::CompactionDriver,
        config: &EngineExecutorConfig,
        record: &CodeRunReplayRecord,
        watermark: u64,
        note: Option<String>,
        room: Option<u64>,
    ) -> EngineExecutorResult<
        std::result::Result<
            Option<(crate::compaction::CompactionRequest, CompactHooks)>,
            VerbHookStop,
        >,
    > {
        let run_id = config.run_id;
        let run_ref = self.gated_write.run_ref();
        // The run's position is its coverage rows, withdrawn summaries
        // included: erasing a summary never moves where the next one starts.
        let coverage = self.storage.code_run_compaction_coverage(run_id)?;
        let newest = coverage.iter().max_by_key(|row| row.epoch()).copied();
        let prior = newest.map(|row| (row.epoch(), row.last()));
        let start = prior.map_or(0, |(_, last)| last.saturating_add(1));
        if start > watermark {
            return Ok(Ok(None));
        }
        let session = crate::code_run::executor_compaction_session_id(run_ref, run_id)?;
        let turn_id = crate::code_run::executor_speech_turn_id_for_run(run_ref, run_id)?;
        let budget = driver.summary_token_budget();
        // The backend reads the rendered input: each step's JSON frame,
        // escapes included, beside the pins. That, not the steps' raw text,
        // sizes the window, within `room`.
        let oversized = || {
            crate::Error::InvalidConfig(
                "the compaction backend cannot take the next step's output whole".into(),
            )
        };
        let mut window = Vec::new();
        let mut pins: Vec<String> = Vec::new();
        // Two counts kept by parts, each part counted once: the pins as the
        // summary holds them, a line each, and the rendered input. Parts run
        // a token or so over their joined whole, so a count past its bound is
        // counted whole before it turns a step away, and goes on from there.
        let mut pin_lines = 0_u64;
        let mut input = None;
        for seq in start..=watermark {
            let message = super::compaction::window_message(
                super::compaction::step_message_id(run_id, seq),
                turn_id,
                seq,
                load_context_output(&self.storage, record, &script_output_path(seq))?,
                load_observation_window(
                    &self.storage,
                    record,
                    &observation_output_path(seq),
                    COMPACTION_OBSERVATION_WINDOW_BYTES,
                )?,
            );
            // A line several steps fail with is one pin, kept once.
            let pin =
                super::compaction::failure_pin(&message.content).filter(|pin| !pins.contains(pin));
            let mut added = crate::compaction::compaction_step_input_tokens(&message);
            if let Some(pin) = &pin {
                pin_lines = pin_lines.saturating_add(count_context_pack_tokens(pin) as u64 + 1);
                added = added.saturating_add(crate::compaction::compaction_pin_input_tokens(pin));
            }
            let pinned = pin.is_some();
            pins.extend(pin);
            window.push(message);
            // The summary holds every pin whole, inside its budget.
            if pinned && pin_lines > budget {
                pin_lines = count_context_pack_tokens(&pins.join("\n")) as u64;
            }
            let unpinnable = pinned && pin_lines > budget;
            let mut fits = !unpinnable;
            if fits && let Some(room) = room {
                let whole = || {
                    crate::compaction::compaction_input_tokens(
                        start,
                        &window,
                        &pins,
                        note.as_deref(),
                        budget,
                    )
                };
                let counted = match input.map(|counted: u64| counted.saturating_add(added)) {
                    Some(counted) if counted <= room => counted,
                    _ => whole(),
                };
                fits = counted <= room;
                input = Some(counted);
            }
            if !fits {
                window.pop();
                if pinned {
                    pins.pop();
                }
                if window.is_empty() {
                    return Err(if unpinnable {
                        crate::Error::InvalidConfig(
                            "the next step's failure line does not fit a summary".into(),
                        )
                    } else {
                        oversized()
                    }
                    .into());
                }
                break;
            }
        }
        // The backend takes the joined input whole or not at all: it is
        // counted whole once more, and a step it does not hold waits for the
        // next pass.
        while let Some(room) = room
            && crate::compaction::compaction_input_tokens(
                start,
                &window,
                &pins,
                note.as_deref(),
                budget,
            ) > room
        {
            window.pop();
            if window.is_empty() {
                return Err(oversized().into());
            }
            pins = super::compaction::window_pins(&window);
        }
        let fits = |pins: &[String]| {
            count_context_pack_tokens(&pins.join("\n")) as u64 <= budget
                && room.is_none_or(|room| {
                    crate::compaction::compaction_input_tokens(
                        start,
                        &window,
                        pins,
                        note.as_deref(),
                        budget,
                    ) <= room
                })
        };
        super::compaction::add_profile_pins(
            &mut pins,
            &window,
            &driver.memory_profile().verbatim_pins,
            &fits,
        );
        // A run bound to a room runs no hooks: their receipts would land on
        // record.
        let hooks = match &self.storage {
            crate::code_run::ExecutorStorage::Canonical(vault) => vault.pre_compact_hooks(
                crate::compaction::compact_invocation(run_id.as_bytes(), watermark),
                self.gated_write.actor().entity_ref(),
                &window,
                &mut pins,
                budget,
                &fits,
            ),
            crate::code_run::ExecutorStorage::Session(_) => CompactHooks::default(),
        };
        if let Some(stop) = hooks.pending() {
            return Ok(Err(stop.clone()));
        }
        // Nested provenance: the newest epoch stands for every id the calls
        // before its count served, and for the epochs before it, since those
        // are its own sources. Only the calls since then are read here, so a
        // long run never outgrows one summary's sources, and a record served
        // before the epoch and purged since withdrew that epoch instead.
        let captured = newest.map_or(0, |row| row.calls());
        let calls = usize::try_from(captured)
            .ok()
            .and_then(|from| record.bridge_calls.get(from..))
            .ok_or(crate::Error::CorruptedIndex(
                "compaction coverage names calls the run never made",
            ))?;
        // The host's own words: the run's speech since the newest epoch, and
        // that epoch, which its requests rendered.
        let mut host = vec![turn_id];
        for order in super::compaction::speech_orders(calls) {
            host.push(crate::code_run::executor_speech_message_id_in_run(
                run_ref, run_id, order,
            )?);
        }
        host.extend(newest.map(|row| row.summary_id()));
        let (sources, request_id) = match &self.storage {
            crate::code_run::ExecutorStorage::Canonical(vault) => {
                let rtxn = vault.store.env.read_txn().map_err(crate::Error::from)?;
                (
                    super::compaction::served_sources(&vault.store, &rtxn, calls, host)?,
                    vault.store.clock.entity_id()?,
                )
            }
            crate::code_run::ExecutorStorage::Session(binding) => binding.answered(|| {
                let view = binding.session.read_view()?;
                let rtxn = view.read().base().env.read_txn()?;
                Ok((
                    super::compaction::served_sources(&view, &rtxn, calls, host)?,
                    crate::store::ManifestDbs::clock(&view).entity_id()?,
                ))
            })?,
        };
        let prior = prior.map(|(epoch, last)| crate::compaction::PriorEpoch::new(epoch, last));
        let calls = u64::try_from(record.bridge_calls.len())
            .map_err(|_| crate::Error::ArithmeticOverflow("executor call count"))?;
        let request = driver.request_for_log(
            request_id, &session, window, pins, sources, prior, calls, note, run_id,
        )?;
        Ok(Ok(Some((request, hooks))))
    }
}
