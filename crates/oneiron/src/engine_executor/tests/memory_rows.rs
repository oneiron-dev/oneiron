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
fn run_program(vault: &Vault, run: u8, program: &str) -> (String, Vec<String>) {
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
    let outcome = block_on_ready(executor.run(&config)).expect("run");
    let answer = load_utf8_output(
        &ExecutorStorage::Canonical(vault),
        &outcome.replay_record,
        &observation_output_path(0),
    )
    .expect("step observation");
    let rows = outcome
        .replay_record
        .bridge_calls
        .iter()
        .map(|row| format!("{} {}", row.effect.as_str(), bridge_outcome_kind(row)))
        .collect();
    (answer, rows)
}

/// A guest call through each memory row still works: the same typed call
/// (effect and replay row), the same answer shape, the same gated write.
#[cfg(feature = "code-sandbox-wasmtime")]
#[test]
fn a_guest_call_through_each_memory_row_keeps_its_call_and_answer() {
    let (_dir, vault) = open_test_vault();
    let subject = seed_person(&vault, 0xB1);
    let [first, second] = [entity(0xC1), entity(0xC2)];
    let program = format!(
        "const subject = '{subject}'; const out = {{}}; \
         out.search = await self.memory.search({{query: 'sencha', limit: 3}}); \
         out.first = await self.memory.put_claim({{id: '{first}', subject, \
           predicate: 'profile.favorite_drink', value: 'sencha', confidence: 0.9}}); \
         out.second = await self.memory.put_claim({{id: '{second}', subject, \
           predicate: 'profile.favorite_drink', value: 'matcha', occurred: {{start: 5, end: 9}}, \
           learnedAt: 11}}); \
         out.superseded = await self.memory.supersede_claim({{newId: '{second}', \
           oldId: '{first}', now: 12}}); \
         out.edge = await self.memory.put_edge({{src: '{second}', kind: 'about', tgt: subject}}); \
         finish(JSON.stringify(out));",
        subject = subject.to_hex(),
        first = first.to_hex(),
        second = second.to_hex(),
    );
    let (answer, rows) = run_program(&vault, 0xE1, &program);
    let answer: serde_json::Value = serde_json::from_str(&answer).expect("guest answer");
    assert_eq!(
        answer,
        serde_json::json!({
            "search": {"results": []},
            "first": {"id": first.to_hex()},
            "second": {"id": second.to_hex()},
            "superseded": {"id": second.to_hex()},
            "edge": {"src": second.to_hex(), "kind": "about", "tgt": subject.to_hex()},
        })
    );
    assert_eq!(
        rows,
        [
            "self.memory.search memory_search",
            "self.memory.put_claim memory_write",
            "self.memory.put_claim memory_write",
            "self.memory.supersede_claim memory_write",
            "self.memory.put_edge memory_edge_write",
        ]
    );
    let stored = vault
        .get_claim(&second)
        .expect("read")
        .expect("second claim");
    assert_eq!(stored.source, Some(crate::ClaimSource::Generated));
    assert_eq!(stored.value, Value::from("matcha"));
    assert_eq!(
        vault
            .targets(&second, EdgeKind::About, None)
            .expect("edges"),
        [subject]
    );
}

/// A guest call through each memory row is refused as before: a non-finite
/// number never reaches the gate, and a refused write is the typed `failed`
/// answer and replay row it always was.
#[cfg(feature = "code-sandbox-wasmtime")]
#[test]
fn a_guest_call_through_a_memory_row_is_refused_as_before() {
    let (_dir, vault) = open_test_vault();
    let subject = seed_person(&vault, 0xB2);
    let claim = entity(0xC3);
    let program = format!(
        "const subject = '{subject}'; const out = {{}}; \
         try {{ await self.memory.put_claim({{id: '{claim}', subject, predicate: 'p.q', value: 1, \
           confidence: NaN}}); out.nan = 'written'; }} catch (error) {{ out.nan = 'refused'; }} \
         try {{ await self.memory.put_edge({{src: '{claim}', kind: 'about', tgt: subject, \
           weight: Infinity}}); out.infinite = 'written'; }} catch (error) {{ out.infinite = 'refused'; }} \
         try {{ await self.memory.put_edge({{src: subject, kind: 'same_as', tgt: subject, \
           weight: 0}}); out.sameAs = 'written'; }} catch (error) {{ out.sameAs = String(error); }} \
         finish(JSON.stringify(out));",
        subject = subject.to_hex(),
        claim = claim.to_hex(),
    );
    let (answer, rows) = run_program(&vault, 0xE2, &program);
    let answer: serde_json::Value = serde_json::from_str(&answer).expect("guest answer");
    assert_eq!(answer["nan"], "refused", "{answer}");
    assert_eq!(answer["infinite"], "refused", "{answer}");
    let same_as = answer["sameAs"].as_str().expect("refusal text");
    assert!(same_as.contains(r#""failed":true"#), "{same_as}");
    assert_eq!(rows, ["self.memory.put_edge failed"]);
    assert!(vault.get_claim(&claim).expect("read").is_none());
    assert!(
        vault
            .targets(&subject, EdgeKind::SameAs, None)
            .expect("edges")
            .is_empty()
    );
}

/// A memory row's input is closed, as every row's is: a field it does not
/// list is refused before the gate, never dropped and written.
#[cfg(feature = "code-sandbox-wasmtime")]
#[test]
fn a_memory_row_refuses_a_field_its_input_does_not_list() {
    let (_dir, vault) = open_test_vault();
    let subject = seed_person(&vault, 0xB3);
    let claim = entity(0xC4);
    let program = format!(
        "try {{ await self.memory.put_claim({{id: '{claim}', subject: '{subject}', \
           predicate: 'profile.favorite_drink', value: 'tea', source: 'user_stated'}}); \
           finish('written'); }} catch (error) {{ finish('refused'); }}",
        subject = subject.to_hex(),
        claim = claim.to_hex(),
    );
    let (answer, rows) = run_program(&vault, 0xE3, &program);
    assert_eq!(answer, "refused");
    assert!(rows.is_empty(), "{rows:?}");
    assert!(vault.get_claim(&claim).expect("read").is_none());
}
