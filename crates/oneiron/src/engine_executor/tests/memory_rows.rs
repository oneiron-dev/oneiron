//! The memory rows a run answers itself (`search`, `put_claim`,
//! `supersede_claim`, `put_edge`) are verb-table rows (ARCH-0028: one table):
//! the executor prompt declares them from the table, and a guest call through
//! each keeps the typed call, answer and refusal it had as a hand-written
//! import.
use super::*;

const MEMORY_ROWS: [&str; 4] = ["search", "put_claim", "supersede_claim", "put_edge"];

/// The one declaration the executor prompt gives `name`.
fn declaration<'a>(prompt: &'a str, name: &str) -> &'a str {
    let needle = format!("function {name}(");
    let mut lines = prompt.lines().filter(|line| line.contains(&needle));
    let line = lines
        .next()
        .unwrap_or_else(|| panic!("{name} is not declared"));
    assert!(lines.next().is_none(), "{name} is declared twice");
    line
}

/// Done-means: the rendered table lists the memory rows from their verb
/// definitions, each once, typed from the row's own input.
#[test]
fn the_executor_prompt_declares_the_memory_rows_from_the_verb_table() {
    let table = crate::task_verb::sdk::code_mode_declarations();
    let prompt = host::executor_system_prompt("wire");
    for name in MEMORY_ROWS {
        let declared = declaration(table, name);
        assert_eq!(declared, declaration(&prompt, name), "{name}");
    }
    for (name, fields) in [
        ("search", &["query: string", "limit?: "][..]),
        (
            "put_claim",
            &[
                "id: string",
                "predicate: string",
                "subject: string",
                "value: unknown",
                "confidence?: ",
                "occurred?: ",
                "learnedAt?: ",
            ],
        ),
        (
            "supersede_claim",
            &["newId: string", "oldId: string", "now: number"],
        ),
        (
            "put_edge",
            &["src: string", "kind: string", "tgt: string", "weight?: "],
        ),
    ] {
        let declared = declaration(table, name);
        for field in fields {
            assert!(declared.contains(field), "{name} lacks {field}: {declared}");
        }
    }
}

#[cfg(feature = "code-sandbox-wasmtime")]
fn real_guest() -> crate::code_sandbox::quickjs::QuickJsRuntimeFactory {
    use crate::code_sandbox::wasmtime_runtime::ComponentBudget;
    use sha2::{Digest, Sha256};
    let directory = std::env::var_os("ONEIRON_QUICKJS_ARTIFACT_DIR").map_or_else(
        || {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../components/code-run-quickjs/artifacts")
        },
        std::path::PathBuf::from,
    );
    let bytes = std::fs::read(directory.join("quickjs-first-party.wasm")).expect("pinned QuickJS");
    let pin: [u8; 32] = Sha256::digest(&bytes).into();
    crate::code_sandbox::quickjs::QuickJsRuntimeFactory::from_component(
        &bytes,
        pin,
        ComponentBudget::default(),
    )
    .expect("first-party component")
}

/// One single-step run of `program` through the real guest; the step's
/// `finish` text and its bridge rows as `effect kind`.
#[cfg(feature = "code-sandbox-wasmtime")]
fn run_program(
    vault: &Vault,
    run: u8,
    program: &str,
) -> EngineExecutorResult<(String, Vec<String>)> {
    let factory = real_guest();
    let backend = FixtureBackend::new([program]);
    let lease = BudgetLease::for_test("memory-rows");
    let gated = gated_actor_write(vault, &format!("run-memory-rows-{run}"));
    let mut runtime = factory.runtime().expect("real guest");
    let mut executor = EngineNativeExecutor::new(vault, &backend, &lease, &mut runtime, &gated);
    let config = executor_config(
        entity(run),
        EngineExecutorLimits {
            soft_steps: 1,
            hard_steps: 1,
        },
    );
    let outcome = block_on_ready(executor.run(&config))?;
    let answer = load_utf8_output(
        &ExecutorStorage::Canonical(vault),
        &outcome.replay_record,
        &observation_output_path(0),
    )?;
    let rows = outcome
        .replay_record
        .bridge_calls
        .iter()
        .map(|row| format!("{} {}", row.effect.as_str(), bridge_outcome_kind(row)))
        .collect();
    Ok((answer, rows))
}

/// A guest call through a memory row still works end to end: the run's search
/// and its claim writes keep their effect, replay row, answer shape and gated
/// write. Each row's typed call, `supersede_claim` and `put_edge` included, is
/// pinned at the guest boundary by
/// `native_quickjs_memory_rows_make_the_calls_their_imports_made`.
#[cfg(feature = "code-sandbox-wasmtime")]
#[test]
fn a_guest_call_through_each_memory_row_keeps_its_call_and_answer() {
    let (_dir, vault) = open_test_vault();
    let subject = seed_person(&vault, 0xB1);
    let [first, second] = [entity(0xC1), entity(0xC2)];
    let program = format!(
        "const subject = '{subject}'; const out = {{}}; try {{ \
         out.search = await self.memory.search({{query: 'sencha', limit: 3}}); \
         out.first = await self.memory.put_claim({{id: '{first}', subject, \
           predicate: 'profile.favorite_drink', value: 'sencha', confidence: 0.9, \
           occurred: {{start: 3, end: 4}}, learnedAt: 4}}); \
         out.second = await self.memory.put_claim({{id: '{second}', subject, \
           predicate: 'profile.favorite_drink', value: 'matcha'}}); \
         finish(JSON.stringify(out)); }} catch (error) {{ finish(`threw ${{error}}`); }}",
        subject = subject.to_hex(),
        first = first.to_hex(),
        second = second.to_hex(),
    );
    let (answer, rows) = run_program(&vault, 0x71, &program).expect("run");
    let answer: serde_json::Value =
        serde_json::from_str(&answer).unwrap_or_else(|_| panic!("{answer}; {rows:?}"));
    assert_eq!(
        answer,
        serde_json::json!({
            "search": {"results": []},
            "first": {"id": first.to_hex()},
            "second": {"id": second.to_hex()},
        })
    );
    assert_eq!(
        rows,
        [
            "self.memory.search memory_search",
            "self.memory.put_claim memory_write",
            "self.memory.put_claim memory_write",
        ]
    );
    let stored = vault.get_claim(&first).expect("read").expect("first claim");
    assert_eq!(stored.source, Some(crate::ClaimSource::Generated));
    assert_eq!(stored.value, Value::from("sencha"));
    assert_eq!(stored.confidence, 0.9);
    let stored = vault
        .get_claim(&second)
        .expect("read")
        .expect("second claim");
    assert_eq!(stored.value, Value::from("matcha"));
    assert_eq!(stored.confidence, 1.0);
}

/// A guest call through a memory row is refused as before: a non-finite
/// number (boxed or not), a time past JavaScript's safe range and an input
/// JSON cannot carry never reach the gate, the guest sees a stable code for
/// each, and a write the gate refuses stops the run with the gate's own error,
/// writing nothing.
#[cfg(feature = "code-sandbox-wasmtime")]
#[test]
fn a_guest_call_through_a_memory_row_is_refused_as_before() {
    let (_dir, vault) = open_test_vault();
    let subject = seed_person(&vault, 0xB2);
    let claim = entity(0xC3);
    let program = format!(
        "const subject = '{subject}'; const out = {{}}; \
         try {{ await self.memory.put_claim({{id: '{claim}', subject, predicate: 'p.q', value: 1, \
           confidence: NaN}}); out.nan = 'written'; }} catch (error) {{ out.nan = String(error); }} \
         try {{ await self.memory.put_edge({{src: '{claim}', kind: 'about', tgt: subject, \
           weight: Infinity}}); out.infinite = 'written'; }} catch (error) {{ out.infinite = String(error); }} \
         try {{ await self.memory.put_claim({{id: '{claim}', subject, predicate: 'p.q', value: 1, \
           learnedAt: 2 ** 53}}); out.unsafe = 'written'; }} catch (error) {{ out.unsafe = String(error); }} \
         try {{ await self.memory.put_claim({{id: '{claim}', subject, predicate: 'p.q', value: 1, \
           confidence: new Number(NaN)}}); out.boxed = 'written'; }} catch (error) {{ out.boxed = String(error); }} \
         const cyclic = {{}}; cyclic.self = cyclic; \
         try {{ await self.memory.put_claim({{id: '{claim}', subject, predicate: 'p.q', value: cyclic}}); \
           out.cyclic = 'written'; }} catch (error) {{ out.cyclic = String(error); }} \
         finish(JSON.stringify(out));",
        subject = subject.to_hex(),
        claim = claim.to_hex(),
    );
    let (answer, rows) = run_program(&vault, 0x72, &program).expect("run");
    let answer: serde_json::Value = serde_json::from_str(&answer).expect("guest answer");
    assert_eq!(
        answer,
        serde_json::json!({
            "nan": "RangeError: non_finite_verb_input",
            "infinite": "RangeError: non_finite_verb_input",
            "unsafe": "host_call_refused",
            "boxed": "RangeError: non_finite_verb_input",
            "cyclic": "TypeError: invalid_verb_input",
        })
    );
    assert!(rows.is_empty(), "{rows:?}");
    assert!(vault.get_claim(&claim).expect("read").is_none());

    let program = format!(
        "try {{ await self.memory.put_edge({{src: '{subject}', kind: 'same_as', \
           tgt: '{subject}', weight: 0}}); finish('written'); }} \
         catch (error) {{ finish(String(error)); }}",
        subject = subject.to_hex(),
    );
    let error = run_program(&vault, 0x73, &program).expect_err("same_as is refused");
    assert!(
        matches!(
            &error,
            EngineExecutorError::Engine(Error::InvalidClaimBody(reason))
                if *reason == "self.memory.put_edge rejects structural edge kinds"
        ),
        "{error:?}"
    );
    assert!(
        vault
            .targets(&subject, EdgeKind::SameAs, None)
            .expect("edges")
            .is_empty()
    );
}

/// A memory row's input is closed, as every row's is: a field it does not
/// list is refused before the gate, never dropped and written, and the guest
/// sees the refusal as a stable code.
#[cfg(feature = "code-sandbox-wasmtime")]
#[test]
fn a_memory_row_refuses_a_field_its_input_does_not_list() {
    let (_dir, vault) = open_test_vault();
    let subject = seed_person(&vault, 0xB3);
    let claim = entity(0xC4);
    let program = format!(
        "try {{ await self.memory.put_claim({{id: '{claim}', subject: '{subject}', \
           predicate: 'profile.favorite_drink', value: 'tea', source: 'user_stated'}}); \
           finish('written'); }} catch (error) {{ finish(String(error)); }}",
        subject = subject.to_hex(),
        claim = claim.to_hex(),
    );
    let (answer, rows) = run_program(&vault, 0x74, &program).expect("run");
    assert_eq!(answer, "host_call_refused");
    assert!(rows.is_empty(), "{rows:?}");
    assert!(vault.get_claim(&claim).expect("read").is_none());
}

/// A row's input is encoded once and the call sends that text, so neither a
/// getter nor an inherited `toJSON` can pass the finite check and then send a
/// different value.
#[cfg(feature = "code-sandbox-wasmtime")]
#[test]
fn a_memory_row_sends_the_input_its_check_saw() {
    let (_dir, vault) = open_test_vault();
    let subject = seed_person(&vault, 0xB4);
    let [getter, hooked] = [entity(0xC5), entity(0xC6)];
    let program = format!(
        "const fields = id => ({{id, subject: '{subject}', predicate: 'profile.favorite_drink', \
           value: 'tea'}}); \
         let reads = 0; const input = fields('{getter}'); \
         Object.defineProperty(input, 'confidence', {{enumerable: true, \
           get() {{ reads += 1; return reads === 1 ? 0.5 : NaN; }}}}); \
         await self.memory.put_claim(input); \
         let hooks = 0; \
         Object.defineProperty(Object.prototype, 'toJSON', {{configurable: true, value() {{ \
           if (this.id !== '{hooked}') return this; hooks += 1; \
           return {{...this, confidence: hooks === 1 ? 0.25 : NaN}}; }}}}); \
         await self.memory.put_claim(fields('{hooked}')); \
         finish(`${{reads}} ${{hooks}}`);",
        subject = subject.to_hex(),
        getter = getter.to_hex(),
        hooked = hooked.to_hex(),
    );
    let (answer, rows) = run_program(&vault, 0x75, &program).expect("run");
    assert_eq!(answer, "1 1");
    assert_eq!(
        rows,
        [
            "self.memory.put_claim memory_write",
            "self.memory.put_claim memory_write",
        ]
    );
    for (id, confidence) in [(getter, 0.5), (hooked, 0.25)] {
        let stored = vault.get_claim(&id).expect("read").expect("claim");
        assert_eq!(stored.confidence, confidence);
    }
}
