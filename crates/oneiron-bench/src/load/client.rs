//! One agent on the facade doors: its signed slip, a fresh holder proof per
//! request, and the three verbs the bench drives (witness, claim upsert, recall).

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use oneiron::authority::CapabilitySlip;
use serde_json::{Value, json};

use super::corpus::{Corpus, Record, Subject, tag_index};
use super::server::Credential;
use super::stats::Sample;

pub(super) struct Agent {
    http: reqwest::blocking::Client,
    base: String,
    bearer: String,
    slip: CapabilitySlip,
    key: SigningKey,
}

/// What a recall answered, beside its timing.
pub(super) struct Recalled {
    pub(super) sample: Sample,
    /// The tag index of each item, in rank order (`None` for an untagged item).
    pub(super) ranking: Vec<Option<usize>>,
}

fn decode_seed(hex: &str) -> Result<[u8; 32], String> {
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2).unwrap_or("zz"), 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|e| format!("binding key: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| "binding key is not 32 bytes".to_owned())
}

impl Agent {
    /// One client for every agent of a run: its pool keeps a connection per
    /// concurrent request, and each blocking client would add its own runtime.
    pub(super) fn http() -> Result<reqwest::blocking::Client, String> {
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(600))
            .pool_max_idle_per_host(512)
            .build()
            .map_err(|e| format!("http client: {e}"))
    }

    pub(super) fn new(
        http: &reqwest::blocking::Client,
        base: &str,
        credential: &Credential,
    ) -> Result<Self, String> {
        Ok(Self {
            http: http.clone(),
            base: base.to_owned(),
            bearer: format!("Bearer {}", credential.token),
            slip: CapabilitySlip::from_token(&credential.token)
                .map_err(|e| format!("slip: {e}"))?,
            key: SigningKey::from_bytes(&decode_seed(&credential.binding_key)?),
        })
    }

    /// POSTs `body` to a facade verb; the time covers the round trip only,
    /// not the holder proof made before it.
    fn post(&self, verb: &str, body: &Value) -> (f64, Result<Value, String>) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let proof = match oneiron::authority::holder_proof(&self.slip, &self.key, timestamp) {
            Ok(proof) => proof.to_string(),
            Err(e) => return (0.0, Err(format!("proof: {e}"))),
        };
        let started = Instant::now();
        let sent = self
            .http
            .post(format!("{}/v1/core/facade/{verb}", self.base))
            .header("authorization", &self.bearer)
            .header("x-oneiron-binding", proof)
            .json(body)
            .send();
        let answer = sent.map_err(|e| {
            if e.is_timeout() {
                "timeout".to_owned()
            } else {
                "transport".to_owned()
            }
        });
        let result = answer.and_then(|response| {
            let status = response.status();
            let text = response.text().map_err(|_| "body".to_owned())?;
            if status.is_success() {
                serde_json::from_str(&text).map_err(|_| "json".to_owned())
            } else {
                let code = serde_json::from_str::<Value>(&text)
                    .ok()
                    .and_then(|v| {
                        v["code"]
                            .as_str()
                            .or_else(|| v["error"]["code"].as_str())
                            .map(str::to_owned)
                    })
                    .unwrap_or_default();
                Err(format!("{} {code}", status.as_u16()).trim().to_owned())
            }
        });
        (started.elapsed().as_secs_f64() * 1000.0, result)
    }

    /// Writes one corpus record: a witnessed turn or an upserted claim.
    pub(super) fn write(&self, corpus: &Corpus, owner: &str, record: &Record) -> Sample {
        let body = match record {
            Record::Turn {
                conversation,
                messages,
                ..
            } => json!({
                "conversation_ref": corpus.conversation_ref(*conversation),
                "occurred_at": 1_791_500_000 + record.index() as u64,
                "messages": messages.iter().enumerate().map(|(order, content)| json!({
                    "author": "user",
                    "message_type": "text",
                    "content": content,
                    "is_visible": true,
                    "order": order,
                })).collect::<Vec<_>>(),
            }),
            Record::Claim {
                subject,
                predicate,
                value,
                ..
            } => json!({
                "predicate": predicate,
                "subject_ref": match subject {
                    Subject::Owner => owner.to_owned(),
                    Subject::Conversation(c) => corpus.conversation_ref(*c),
                },
                "value": value,
                "confidence": 0.9,
                "source": "user_stated",
            }),
        };
        let verb = match record {
            Record::Turn { .. } => "witness",
            Record::Claim { .. } => "claim_upsert",
        };
        let (ms, result) = self.post(verb, &body);
        Sample {
            ms,
            error: result.err(),
            partial: false,
            items: 1,
        }
    }

    /// One recall at `effort`; `deadline_ms` rides beside it when given.
    pub(super) fn recall(
        &self,
        query: &str,
        effort: &str,
        limit: usize,
        deadline_ms: Option<u64>,
    ) -> Recalled {
        let mut body = json!({"query": query, "effort": effort, "limit": limit});
        if let Some(deadline) = deadline_ms {
            body["deadline_ms"] = json!(deadline);
        }
        let (ms, result) = self.post("recall", &body);
        match result {
            Ok(pack) => {
                let items = pack["items"].as_array().cloned().unwrap_or_default();
                let ranking = items.iter().map(item_tag).collect::<Vec<_>>();
                Recalled {
                    sample: Sample {
                        ms,
                        error: None,
                        partial: pack["retrieval_meta"]["partial"].as_bool() == Some(true),
                        items: items.len(),
                    },
                    ranking,
                }
            }
            Err(error) => Recalled {
                sample: Sample {
                    ms,
                    error: Some(error),
                    partial: false,
                    items: 0,
                },
                ranking: Vec::new(),
            },
        }
    }
}

/// The record an item came from: its own text's tag, or for a turn the tag in
/// one of the messages it cites.
fn item_tag(item: &Value) -> Option<usize> {
    item["value_text"].as_str().and_then(tag_index).or_else(|| {
        item["cited_messages"]
            .as_array()?
            .iter()
            .find_map(|m| m["value_text"].as_str().and_then(tag_index))
    })
}
