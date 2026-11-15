//! Judged answers (ASK L9-36-ACCURACY = C, its second column): one pinned
//! reader answers each asked question from the texts the system returned for
//! it, and one pinned judge grades that answer against the gold `answer`.
//! Every type is judged: an `unanswerable` question is answered correctly
//! when the reader abstains, and an unchecked-support question is graded
//! against its `answer` like any other. A failed recall answers nothing, so
//! its row is incorrect.
//!
//! Both models sit behind OpenAI-compatible endpoints (`--reader` and
//! `--judge`, each `<base-url>,<model>`), with one key read from
//! `--model-key-file` as `load dream` reads it. The key goes to those
//! endpoints only, never to the report or a log. The judging runs after a
//! system has answered every question, so no model call sits between two
//! timed recalls.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use super::super::dream::setup;
use super::corpus::{Life, Question};
use super::report::{System, add_judged};
use super::say;

/// The reader's instruction, sent byte for byte as its system message.
const READER_INSTRUCTION: &str = "You answer a question about a person from the memories \
a memory system returned for it. Use only those memories. Reply with the answer alone, in as \
few words as the answer needs. If the memories do not hold the answer, reply with exactly: unknown";

/// The judge's instruction, sent byte for byte as its system message.
const JUDGE_INSTRUCTION: &str = "You grade an answer to a question against the gold answer. \
The answer is correct when it states what the gold answer states, in any wording or language. \
It is incorrect when it states something else, adds a conflicting detail, or gives no answer. \
Reply with exactly one word: correct or incorrect.";

/// The reader's reply when the memories do not hold the answer.
const ABSTAIN: &str = "unknown";

const READER_MAX_TOKENS: u32 = 200;
const JUDGE_MAX_TOKENS: u32 = 16;

/// One `--reader` or `--judge`: an OpenAI-compatible endpoint, whose base
/// URL ends where `/chat/completions` follows, and the model it serves.
pub(super) struct Endpoint {
    pub(super) base_url: String,
    pub(super) model: String,
}

/// Parses `<base-url>,<model>`.
pub(super) fn endpoint(flag: &str, value: &str) -> Result<Endpoint, String> {
    let shape = || format!("{flag} is <base-url>,<model>");
    let (base_url, model) = value.rsplit_once(',').ok_or_else(shape)?;
    if model.trim().is_empty() || reqwest::Url::parse(base_url).is_err() {
        return Err(shape());
    }
    Ok(Endpoint {
        base_url: base_url.to_owned(),
        model: model.trim().to_owned(),
    })
}

/// `--reader`, `--judge` and `--model-key-file`, as parsed.
pub(super) struct Judging {
    pub(super) reader: Endpoint,
    pub(super) judge: Endpoint,
    pub(super) key_file: PathBuf,
}

/// What the report pins of one model.
#[derive(Serialize)]
pub(super) struct Pin {
    base_url: String,
    model: String,
    /// The `model` the endpoint's preflight reply named.
    reply_model: String,
    /// sha256 of the instruction sent as the system message, byte for byte.
    instruction_sha256: String,
    temperature: f64,
    max_tokens: u32,
}

/// The reader's and the judge's pins.
#[derive(Serialize)]
pub(super) struct Pins {
    reader: Pin,
    judge: Pin,
}

fn sha256(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `load dream`'s preflight of one endpoint: the model it answered as.
fn preflight(role: &str, endpoint: &Endpoint, key: &str) -> Result<String, String> {
    say(&format!("{role} preflight: {}", endpoint.model));
    setup::preflight(&endpoint.base_url, &endpoint.model, key)
        .map(|answer| answer.reply_model)
        .map_err(|e| format!("--{role}: {e}"))
}

/// Lower case, without surrounding whitespace, quotes, emphasis or a final
/// period or exclamation mark.
fn bare(reply: &str) -> String {
    reply
        .trim()
        .trim_matches(&['"', '\'', '`', '*', '.', '!'][..])
        .trim()
        .to_lowercase()
}

/// The judge's verdict: `correct` or `incorrect`, case and marks aside.
fn verdict(reply: &str) -> Option<bool> {
    match bare(reply).as_str() {
        "correct" => Some(true),
        "incorrect" => Some(false),
        _ => None,
    }
}

/// The reader's message: the system's items in rank order, each numbered
/// (an item's texts one per line), then the question.
fn reader_prompt(question: &str, texts: &[Vec<String>]) -> String {
    let mut prompt = String::from("Memories:\n");
    if texts.is_empty() {
        prompt.push_str("(none)\n");
    }
    for (rank, item) in texts.iter().enumerate() {
        let _ = writeln!(prompt, "[{}] {}", rank + 1, item.join("\n"));
    }
    let _ = write!(prompt, "\nQuestion: {question}");
    prompt
}

/// The judge's message.
fn judge_prompt(question: &str, gold: &str, answer: &str) -> String {
    format!("Question: {question}\nGold answer: {gold}\nAnswer: {answer}")
}

/// The reader and the judge, once both answered their preflight.
pub(super) struct Judge {
    http: reqwest::blocking::Client,
    key: String,
    reader: Endpoint,
    judge: Endpoint,
    reader_reply: String,
    judge_reply: String,
}

impl Judge {
    /// Reads the key and checks that each endpoint answers as its model,
    /// before any store is opened.
    pub(super) fn start(judging: Judging) -> Result<Self, String> {
        let key = setup::read_key(&judging.key_file)?;
        let reader_reply = preflight("reader", &judging.reader, &key)?;
        let judge_reply = preflight("judge", &judging.judge, &key)?;
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(120))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("model client: {e}"))?;
        Ok(Self {
            http,
            key,
            reader: judging.reader,
            judge: judging.judge,
            reader_reply,
            judge_reply,
        })
    }

    /// What the report pins of both models.
    pub(super) fn pins(&self) -> Pins {
        let pin = |endpoint: &Endpoint, reply: &str, instruction: &str, max_tokens| Pin {
            base_url: endpoint.base_url.clone(),
            model: endpoint.model.clone(),
            reply_model: reply.to_owned(),
            instruction_sha256: sha256(instruction),
            temperature: 0.0,
            max_tokens,
        };
        Pins {
            reader: pin(
                &self.reader,
                &self.reader_reply,
                READER_INSTRUCTION,
                READER_MAX_TOKENS,
            ),
            judge: pin(
                &self.judge,
                &self.judge_reply,
                JUDGE_INSTRUCTION,
                JUDGE_MAX_TOKENS,
            ),
        }
    }

    /// One chat completion at temperature 0: the reply's text, trimmed. An
    /// error names the status or the transport failure, never a body (a
    /// gateway's message can echo part of the key).
    fn chat(
        &self,
        endpoint: &Endpoint,
        instruction: &str,
        prompt: String,
        max_tokens: u32,
    ) -> Result<String, String> {
        let url = format!(
            "{}/chat/completions",
            endpoint.base_url.trim_end_matches('/')
        );
        let response = self
            .http
            .post(url)
            .bearer_auth(&self.key)
            .json(&json!({
                "model": endpoint.model,
                "messages": [
                    {"role": "system", "content": instruction},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.0,
                "max_tokens": max_tokens,
            }))
            .send()
            .map_err(|e| {
                if e.is_timeout() {
                    "timeout".to_owned()
                } else {
                    "transport".to_owned()
                }
            })?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!("answered {}", status.as_u16()));
        }
        let body = response.json::<Value>().map_err(|_| "json".to_owned())?;
        body["choices"][0]["message"]["content"]
            .as_str()
            .map(|text| text.trim().to_owned())
            .ok_or_else(|| "no message content".to_owned())
    }

    /// The reader's answer to `question` from `texts`, and whether it is
    /// correct.
    fn grade(&self, question: &Question, texts: &[Vec<String>]) -> Result<(String, bool), String> {
        let answer = self
            .chat(
                &self.reader,
                READER_INSTRUCTION,
                reader_prompt(&question.question, texts),
                READER_MAX_TOKENS,
            )
            .map_err(|e| format!("reader: {e}"))?;
        let abstained = bare(&answer) == ABSTAIN;
        let unanswerable = question.kind == "unanswerable";
        if unanswerable || abstained {
            // An abstention answers an unanswerable question and misses any other.
            return Ok((answer, unanswerable && abstained));
        }
        let gold = [question.answer.as_deref(), question.answer_span.as_deref()]
            .into_iter()
            .flatten()
            .find(|gold| !gold.trim().is_empty())
            .ok_or_else(|| "no gold answer".to_owned())?;
        let reply = self
            .chat(
                &self.judge,
                JUDGE_INSTRUCTION,
                judge_prompt(&question.question, gold, &answer),
                JUDGE_MAX_TOKENS,
            )
            .map_err(|e| format!("judge: {e}"))?;
        let correct =
            verdict(&reply).ok_or_else(|| "judge: the reply is not a verdict".to_owned())?;
        Ok((answer, correct))
    }

    /// Judges every row of `system` from the texts it returned, then adds the
    /// judged column to its grade summaries.
    pub(super) fn judge(&self, lives: &[Life], system: &mut System) {
        let questions = lives
            .iter()
            .flat_map(|life| {
                life.questions.iter().map(move |(set, question)| {
                    (
                        (life.key.clone(), set.name(), question.qid.clone()),
                        question,
                    )
                })
            })
            .collect::<BTreeMap<_, _>>();
        say(&format!(
            "{}: judge {} rows",
            system.name,
            system.rows.len()
        ));
        for row in &mut system.rows {
            let texts = std::mem::take(&mut row.texts);
            if row.error.is_some() {
                row.answer_correct = Some(false);
                continue;
            }
            let key = (row.life.clone(), row.set, row.qid.clone());
            let Some(question) = questions.get(&key) else {
                continue;
            };
            match self.grade(question, &texts) {
                Ok((answer, correct)) => {
                    row.reader_answer = Some(answer);
                    row.answer_correct = Some(correct);
                }
                Err(error) => row.answer_error = Some(error),
            }
        }
        add_judged(system);
        let errors = system
            .rows
            .iter()
            .filter(|row| row.answer_error.is_some())
            .count();
        say(&format!("{}: judged, {errors} model errors", system.name));
    }
}
