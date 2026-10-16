//! The decision read against an in-process llama.cpp: the joint marginals
//! checked against idle-fold test 5's own `read_probs` (run5b.py) on a fixed
//! answer, the measured request, and each per-call check refusing typed.
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use axum::{Json, Router, extract::State, routing::post};
use oneiron::llm::{
    BudgetLease, FatalLlmError, LabelReadFailure, LabelReadRequest, LabelReadResponse,
    LabelReadout, LabelSet, LlmError, LlmResult,
};
use oneiron::{BudgetExhaustionPolicy, BudgetGuard};
use serde_json::{Value as JsonValue, json};

use super::{DecisionReadDoor, bind};
use crate::config::models::ModelsConfig;

const LETTERS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr";
/// Test 5's served ids for its 44 labels, and its end token.
const EOS: u64 = 248_046;
fn label_id(index: usize) -> u64 {
    if index < 26 { 32 + index } else { 38 + index }
        .try_into()
        .unwrap()
}

/// The oracle: a fixed answer's label log-probabilities, and what test 5's
/// `read_probs` reads from it (oracle.json, made by make_oracle.py in the
/// lane's notes from run5b.py verbatim): the eleven options' marginals,
/// P(more thinking) and P(ask a person).
const LOGPROBS: [f64; 44] = [
    -12.172438, -6.31854, -4.904042, -8.380125, -9.938511, -11.61359, -4.307121, -0.936296,
    -6.788816, -6.736755, -13.272936, -4.042798, -2.880816, -5.401722, -3.511436, -5.18851,
    -13.158016, -13.955786, -1.771448, -7.532282, -6.281553, -4.898358, -0.950735, -9.071524,
    -8.596731, -12.349047, -5.277443, -9.242812, -7.138269, -10.828787, -4.337081, -7.493423,
    -6.383213, -9.70257, -3.600599, -3.530531, -10.547529, -2.258815, -6.611109, -3.224016,
    -1.833307, -3.57962, -8.483073, -7.501708,
];
const PRIMARY: [f64; 11] = [
    0.056433601550806824,
    0.25507978683914173,
    0.012491409017492374,
    0.060393067353579535,
    0.10730324413598537,
    0.24897588366033815,
    0.003390512962566954,
    0.009084430197355343,
    0.03669383308096691,
    0.09159113678506065,
    0.11856309441670619,
];
const THINK: f64 = 0.4490676214600979;
const PERSON: f64 = 0.7173702497252611;

/// A llama.cpp server's `/tokenize` and `/completion`: labels tokenize to
/// test 5's ids, and each completion takes the next queued answer.
#[derive(Default)]
struct Fake {
    answers: Mutex<VecDeque<JsonValue>>,
    requests: Mutex<Vec<JsonValue>>,
    /// A verbalizer the tokenizer splits in two.
    split: Option<String>,
}

async fn tokenize(State(fake): State<Arc<Fake>>, Json(body): Json<JsonValue>) -> Json<JsonValue> {
    let content = body["content"].as_str().unwrap();
    let tokens = if content == "<|im_end|>" && body["parse_special"] == true {
        json!([EOS])
    } else if fake.split.as_deref() == Some(content) {
        json!([1, 2])
    } else {
        let index = LETTERS.find(content).unwrap();
        json!([{"id": label_id(index), "piece": content}])
    };
    Json(json!({ "tokens": tokens }))
}

async fn completion(State(fake): State<Arc<Fake>>, Json(body): Json<JsonValue>) -> Json<JsonValue> {
    fake.requests.lock().unwrap().push(body);
    Json(fake.answers.lock().unwrap().pop_front().unwrap())
}

/// Serves `fake` on loopback; its base URL ends in `/v1`, as a chat
/// provider's does, and the read still reaches the native root.
async fn serve(fake: Arc<Fake>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = Router::new()
        .route("/tokenize", post(tokenize))
        .route("/completion", post(completion))
        .with_state(fake);
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    format!("http://{addr}/v1")
}

/// Writes a host package's recipe over `tokens` labels into `dir/package`.
fn package(dir: &std::path::Path, tokens: usize) {
    let package = dir.join("package");
    std::fs::create_dir_all(&package).unwrap();
    std::fs::write(
        package.join("read.txt"),
        "{state.head}\n(1) {question} (2) {paired} (3) {person}\n{labels}\n{state.dynamic}<|im_end|>\nJoint label:",
    )
    .unwrap();
    let verbalizers: Vec<String> = LETTERS
        .chars()
        .take(tokens)
        .map(|letter| format!("\"{letter}\""))
        .collect();
    std::fs::write(
        package.join("recipe.toml"),
        format!(
            "format = 1\ntemplate = \"read.txt\"\nrow = \"{{token}}: {{label}}; more thinking {{think}}\"\nrow_person = \"{{token}}: {{label}}; more thinking {{think}}; ask a person {{person}}\"\nyes = \"yes\"\nno = \"no\"\ntokens = [{}]\neos = \"<|im_end|>\"\nn_probs = 262144\n[probe]\npaired = \"Think?\"\nperson = \"Person?\"\n",
            verbalizers.join(", ")
        ),
    )
    .unwrap();
}

/// `[models]` reading with `dir`'s package, its path relative to `dir`.
fn models(dir: &std::path::Path, base_url: &str) -> anyhow::Result<ModelsConfig> {
    ModelsConfig::from_toml(
        &format!(
            "[providers.house]\nkind = \"local-openai-compat\"\nbase_url = \"{base_url}\"\nrevision = \"q4km\"\n[roles.local_reasoner]\nmodel = \"house:qwen3.8-27b\"\n[decision_read]\nrecipe = \"package/recipe.toml\"\n"
        ),
        Some(dir),
    )
}

fn config(dir: &std::path::Path, base_url: &str, tokens: usize) -> ModelsConfig {
    package(dir, tokens);
    models(dir, base_url).unwrap()
}

fn lease() -> BudgetLease {
    BudgetGuard::with_reserve_units("read", 1_000_000, 1, BudgetExhaustionPolicy::Suspend)
        .admit()
        .unwrap()
        .lease
}

/// One read through `door`, off the runtime as a host makes it.
async fn read(
    door: &DecisionReadDoor,
    options: Option<Vec<String>>,
    person: bool,
) -> LlmResult<LabelReadResponse> {
    let reader = door.reader();
    tokio::task::spawn_blocking(move || {
        let state = json!({"head": "HEAD", "dynamic": "DYNAMIC"});
        let labels = match &options {
            Some(options) => LabelSet::Choice(options),
            None => LabelSet::Noul,
        };
        reader.read(
            &LabelReadRequest {
                state: &state,
                primary: LabelReadout {
                    text: "When?",
                    labels,
                },
                paired: "Think?",
                person: person.then_some("Person?"),
                work_until: None,
            },
            &lease(),
        )
    })
    .await
    .unwrap()
}

/// llama.cpp's answer to a read: no text, the forced end, one row of
/// `(id, logprob)` entries around a distractor.
fn answer(entries: &[(u64, f64)]) -> JsonValue {
    let mut top: Vec<JsonValue> =
        vec![json!({"id": EOS, "token": "<|im_end|>", "logprob": -0.0001})];
    top.extend(
        entries
            .iter()
            .map(|(id, logprob)| json!({"id": id, "token": "?", "logprob": logprob})),
    );
    top.push(json!({"id": 90_000, "token": "x", "logprob": -20.0}));
    json!({
        "content": "",
        "stop_type": "eos",
        "stopped_eos": true,
        "tokens_evaluated": 1234,
        "tokens_predicted": 1,
        "timings": {"prompt_ms": 120.5, "predicted_ms": 3.25},
        "completion_probabilities": [{"id": EOS, "logprob": -0.0001, "top_logprobs": top}],
    })
}

/// The oracle's answer, with two of the reference's own readings: an earlier
/// entry for A (the later one wins), and another id spelled "B" after B's
/// own (read by its text, it overwrites B).
fn oracle_answer() -> JsonValue {
    let mut entries = vec![(label_id(0), -50.0)];
    entries.extend(
        LOGPROBS
            .iter()
            .enumerate()
            .map(|(index, logprob)| (label_id(index), *logprob)),
    );
    let mut answer = answer(&entries);
    let top = answer["completion_probabilities"][0]["top_logprobs"]
        .as_array_mut()
        .unwrap();
    top.insert(
        top.len() - 1,
        json!({"id": 91_000, "token": "B", "logprob": -2.5}),
    );
    answer
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_is_test_five_s_one_pass_read_through_the_configured_recipe() {
    let fake = Arc::new(Fake::default());
    fake.answers.lock().unwrap().push_back(oracle_answer());
    let dir = tempfile::tempdir().unwrap();
    let config = config(dir.path(), &serve(Arc::clone(&fake)).await, 44);
    let door = bind(&config, tokio::runtime::Handle::current())
        .unwrap()
        .unwrap();
    let options: Vec<String> = (0..11).map(|bin| format!("bin {bin}")).collect();
    let read = read(&door, Some(options.clone()), true).await.unwrap();

    for (got, want) in read.primary.iter().zip(PRIMARY) {
        assert!((got - want).abs() < 1e-12, "{got} vs {want}");
    }
    assert!((read.paired_yes - THINK).abs() < 1e-12);
    assert!((read.person_yes.unwrap() - PERSON).abs() < 1e-12);
    assert_eq!((read.usage.input.total, read.usage.output.total), (1234, 1));
    let reader = door.reader();
    assert_eq!(reader.model(), "house/qwen3.8-27b@q4km");
    assert!(reader.revision().starts_with("q4km+recipe."));
    assert_eq!(door.person_threshold(), 0.9);

    // The measured request: one position, the end token forced, pre-sampler
    // probabilities over the vocabulary, nothing sampled or stopped early.
    let requests = fake.requests.lock().unwrap();
    let [request] = requests.as_slice() else {
        panic!("one completion per read");
    };
    assert_eq!(request["n_predict"], 1);
    assert_eq!(request["temperature"], 0.0);
    assert_eq!(request["cache_prompt"], true);
    assert_eq!(request["id_slot"], 0);
    assert_eq!(request["stop"], json!([]));
    assert_eq!(request["n_probs"], 262_144);
    assert_eq!(request["post_sampling_probs"], false);
    assert_eq!(request["logit_bias"], json!([[EOS, 1e9]]));
    assert_eq!(
        request["response_fields"],
        json!([
            "content",
            "completion_probabilities",
            "timings",
            "tokens_evaluated",
            "tokens_predicted",
            "stop_type",
            "stopped_eos"
        ])
    );
    let prompt = request["prompt"].as_str().unwrap();
    // The probe reserves the prompt it sends, byte for byte, and the position read.
    let state = json!({"head": "HEAD", "dynamic": "DYNAMIC"});
    let reserve = door.reserve(&LabelReadRequest {
        state: &state,
        primary: LabelReadout {
            text: "When?",
            labels: LabelSet::Choice(&options),
        },
        paired: "Think?",
        person: Some("Person?"),
        work_until: None,
    });
    assert_eq!(reserve, Ok(prompt.len() as u64 + 1));
    assert!(prompt.starts_with("HEAD\n(1) When? (2) Think? (3) Person?\nA: bin 0; more thinking no; ask a person no\nB: bin 0; more thinking yes; ask a person no\nC: bin 0; more thinking no; ask a person yes\n"));
    assert!(prompt.contains(
        "\nr: bin 10; more thinking yes; ask a person yes\nDYNAMIC<|im_end|>\nJoint label:"
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_read_check_refuses_typed_and_none_reads_as_zero() {
    // A yes/no read without the person question: four labels, A to D.
    let four =
        |logprob: f64| -> Vec<(u64, f64)> { (0..4).map(|i| (label_id(i), logprob)).collect() };
    let mut emitted = answer(&four(-1.0));
    emitted["content"] = json!("A");
    let mut not_eos = answer(&four(-1.0));
    not_eos["stop_type"] = json!("limit");
    not_eos["stopped_eos"] = json!(false);
    let missing = answer(&four(-1.0)[..3]);
    let mut two_rows = answer(&four(-1.0));
    let row = two_rows["completion_probabilities"][0].clone();
    two_rows["completion_probabilities"] = json!([row.clone(), row]);
    // No text check without a text field, and no charge without the counts.
    let mut no_content = answer(&four(-1.0));
    no_content.as_object_mut().unwrap().remove("content");
    let mut no_usage = answer(&four(-1.0));
    no_usage.as_object_mut().unwrap().remove("tokens_evaluated");
    // The reference's own leniency: whitespace is no text, `stopped_eos` alone
    // is the stop, and the older schema reads by token text and probability.
    let older = json!({
        "content": " \n",
        "stopped_eos": true,
        "tokens_evaluated": 9,
        "tokens_predicted": 0,
        "completion_probabilities": [{"probs": [
            {"tok_str": "A", "prob": 0.4},
            {"tok_str": "B", "prob": 0.2},
            {"tok_str": "C", "prob": 0.3},
            {"tok_str": "D", "prob": 0.1},
        ]}],
    });
    let fake = Arc::new(Fake::default());
    fake.answers.lock().unwrap().extend([
        emitted, not_eos, missing, two_rows, no_content, no_usage, older,
    ]);
    let dir = tempfile::tempdir().unwrap();
    let config = config(dir.path(), &serve(Arc::clone(&fake)).await, 44);
    let door = bind(&config, tokio::runtime::Handle::current())
        .unwrap()
        .unwrap();
    for failure in [
        LabelReadFailure::EmittedText,
        LabelReadFailure::NotEosStop,
        LabelReadFailure::MissingLabels,
        LabelReadFailure::Malformed,
        LabelReadFailure::Malformed,
        LabelReadFailure::Malformed,
    ] {
        assert_eq!(
            read(&door, None, false).await,
            Err(LlmError::Fatal(FatalLlmError::LabelRead(failure)))
        );
    }
    let read = read(&door, None, false).await.unwrap();
    // Yes = A + B, P(more thinking) = B + D.
    assert!((read.primary[0] - 0.6).abs() < 1e-12 && (read.primary[1] - 0.4).abs() < 1e-12);
    assert!((read.paired_yes - 0.3).abs() < 1e-12);
    assert_eq!(read.person_yes, None);
    // The forced end costs its position even when the answer reports none.
    assert_eq!(read.usage.output.total, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recipe_the_served_tokenizer_cannot_read_refuses_every_read() {
    // A verbalizer of two tokens cannot be read at one position.
    let fake = Arc::new(Fake {
        split: Some("C".to_owned()),
        ..Fake::default()
    });
    let dir = tempfile::tempdir().unwrap();
    let config = config(dir.path(), &serve(Arc::clone(&fake)).await, 44);
    let door = bind(&config, tokio::runtime::Handle::current())
        .unwrap()
        .unwrap();
    assert_eq!(
        read(&door, None, false).await,
        Err(LlmError::Fatal(FatalLlmError::InvalidRequest))
    );
    // More joint labels than the recipe has tokens: 23 options with the person
    // question need 92.
    let options: Vec<String> = (0..23).map(|bin| format!("bin {bin}")).collect();
    assert_eq!(
        read(&door, Some(options), true).await,
        Err(LlmError::Fatal(FatalLlmError::InvalidRequest))
    );
    assert!(fake.requests.lock().unwrap().is_empty(), "nothing was read");
}

#[test]
fn a_recipe_that_cannot_render_a_read_fails_the_config() {
    let dir = tempfile::tempdir().unwrap();
    let base_url = "http://127.0.0.1:1";
    // Too few labels for one yes/no read.
    package(dir.path(), 3);
    let error = models(dir.path(), base_url).unwrap_err();
    assert!(error.to_string().contains("at least 4 distinct"), "{error}");
    // A placeholder the recipe does not define.
    package(dir.path(), 44);
    let recipe = dir.path().join("package/recipe.toml");
    let text = std::fs::read_to_string(&recipe).unwrap().replace(
        "{label}; more thinking {think}\"\n",
        "{label}; {thought}\"\n",
    );
    std::fs::write(&recipe, text).unwrap();
    let error = models(dir.path(), base_url).unwrap_err();
    assert!(
        error.to_string().contains("unknown placeholder {thought}"),
        "{error}"
    );
    // A probe that asks the person question reads at least eight labels.
    package(dir.path(), 6);
    let error = models(dir.path(), base_url).unwrap_err();
    assert!(error.to_string().contains("at least 8 tokens"), "{error}");
}
