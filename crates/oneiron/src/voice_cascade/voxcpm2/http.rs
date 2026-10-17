//! Loopback wire to a separately deployed, always-warm CUDA worker.
//! A FIFO sender never runs HTTP inside `TtsSeamClient::submit`. Neither
//! queue refuses work for room (Rule 5); the adapter paces its renders to
//! the serving policy's `max_queued_renders`.
//! Each render is one `ai.speech` call on the host's [`WireSeat`]: admitted
//! on its own permit, started at the rung's media gate before the reference
//! leaves for the worker, and settled on the characters it spoke.

use super::*;
use crate::llm::media::{AiOperation, MediaPart, MediaUsage, MediaVoice};
use crate::llm::run_admission::{WireCallError, WireSeat};
use reqwest::{Url, blocking::Client};
use serde_json::{Value, json};
use std::{
    io::Read,
    sync::{
        Arc,
        mpsc::{self, Receiver, Sender, TryRecvError},
    },
    thread,
    time::Duration,
};

pub enum VoxCpm2Event {
    Audio {
        generation: GenerationEpoch,
        submission: u64,
        chunk_index: u64,
        target: Box<RenderTarget>,
        bytes: Vec<u8>,
    },
    Failed {
        generation: GenerationEpoch,
        submission: u64,
    },
}
impl VoxCpm2Event {
    pub fn audio(&self) -> Option<VoxCpm2Audio<'_>> {
        if let Self::Audio {
            generation,
            submission,
            chunk_index,
            target,
            bytes,
        } = self
        {
            Some(VoxCpm2Audio {
                generation: *generation,
                submission: *submission,
                chunk_index: *chunk_index,
                target: *target.clone(),
                channels: 1,
                bytes,
            })
        } else {
            None
        }
    }
}

/// Single worker owns the request-scoped WAV. Connect outside a cascade lock.
/// Only loopback HTTP is accepted: a remote host needs a separately secured
/// tunnel/proxy, never a public raw reference-upload endpoint.
pub struct VoxCpm2HttpQueue {
    sender: Sender<VoxCpm2Work>,
    responses: Receiver<VoxCpm2Event>,
    warm: WarmTarget,
}

impl VoxCpm2HttpQueue {
    /// Connects to the worker at `base_url`; each render it sends is a call
    /// on `seat`, the host's rung for the worker. The reference clip is the
    /// person's raw voice, so a third party's rung refuses.
    pub fn connect(
        vault: Arc<Vault>,
        base_url: &str,
        bearer: &str,
        seat: WireSeat,
    ) -> Result<Self> {
        if seat.locality() == ModelLocality::ThirdParty {
            return Err(invalid("a voice reference never goes to a third party"));
        }
        if bearer.len() < 32
            || bearer.len() > 512
            || !bearer.is_ascii()
            || bearer.bytes().any(|b| b.is_ascii_control())
        {
            return Err(invalid("invalid worker credential"));
        }
        let base = Url::parse(base_url).map_err(|_| invalid("invalid worker URL"))?;
        if base.scheme() != "http"
            || base.host_str() != Some("127.0.0.1")
            || base.port().is_none()
            || base.path() != "/"
            || base.query().is_some()
            || base.fragment().is_some()
            || !base.username().is_empty()
            || base.password().is_some()
        {
            return Err(invalid("worker must be loopback HTTP with a port"));
        }
        let vault_limits = vault.voice_serving_limits(None)?;
        let client = Client::builder()
            // A loopback URL is not a loopback destination if env proxies apply.
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_millis(vault_limits.http_deadline_ms))
            .build()
            .map_err(|_| invalid("worker client unavailable"))?;
        let warm: WarmTarget = client
            .get(base.join("ready").map_err(|_| invalid("ready URL"))?)
            .bearer_auth(bearer)
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .and_then(reqwest::blocking::Response::json)
            .map_err(|_| invalid("worker is not ready"))?;
        warm.validate()?;
        if !vault_limits.within(warm.limits) {
            return Err(invalid("worker policy narrower than vault limits"));
        }
        let (sender, work) = mpsc::channel();
        let (results, responses) = mpsc::channel();
        let credential = bearer.to_owned();
        let render_url = base.join("render").map_err(|_| invalid("render URL"))?;
        thread::Builder::new()
            .name("voxcpm2-render".into())
            .spawn(move || {
                run_worker(vault, &seat, client, render_url, credential, work, results);
            })
            .map_err(|_| invalid("worker thread unavailable"))?;
        Ok(Self {
            sender,
            responses,
            warm,
        })
    }

    pub fn try_recv(&self) -> Result<Option<VoxCpm2Event>> {
        match self.responses.try_recv() {
            Ok(event) => Ok(Some(event)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(invalid("worker disconnected")),
        }
    }
}
impl VoxCpm2Queue for VoxCpm2HttpQueue {
    fn warm_target(&self) -> Result<WarmTarget> {
        Ok(self.warm.clone())
    }
    fn try_submit(&mut self, work: VoxCpm2Work) -> Result<()> {
        self.sender
            .send(work)
            .map_err(|_| invalid("worker disconnected"))
    }
}

/// The bank's revision of the identity's refs a render is fenced at, in hex.
fn reference_revision(fence: &VoiceRefFence) -> String {
    fence
        .incarnation
        .iter()
        .flatten()
        .chain(&fence.ref_digest)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn target_json(target: &RenderTarget) -> Value {
    let fence = &target.fence;
    let revision = reference_revision(fence);
    json!({"voice_id": target.voice_id, "owner": fence.owner.to_hex(),
        "register": target.register, "reference_revision": revision,
        "limits": target.limits,
        "warm": {"model": target.warm.model, "checkpoint": target.warm.checkpoint,
            "boot_id": target.warm.boot_id, "sample_rate": target.warm.sample_rate,
            "limits": target.warm.limits}})
}
fn render(
    client: &Client,
    url: &Url,
    credential: &str,
    target: &RenderTarget,
    ref_clip: &VoiceRegisterClip,
    text: &str,
) -> Result<Vec<u8>> {
    let header = serde_json::to_vec(&json!({"target": target_json(target), "text": text,
        "transcript": ref_clip.transcript}))
    .map_err(|_| invalid("request encoding"))?;
    if header.len() as u64 > target.limits.max_header_bytes {
        return Err(invalid("request metadata exceeds serving policy"));
    }
    let len: u32 = header
        .len()
        .try_into()
        .map_err(|_| invalid("request too large"))?;
    let mut body = Vec::with_capacity(4 + header.len() + ref_clip.audio.len());
    body.extend_from_slice(&len.to_be_bytes());
    body.extend_from_slice(&header);
    body.extend_from_slice(&ref_clip.audio);
    let mut response = client
        .post(url.clone())
        .timeout(Duration::from_millis(target.limits.http_deadline_ms))
        .header("Content-Type", "application/octet-stream")
        .bearer_auth(credential)
        .body(body)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|_| invalid("worker render failed"))?;
    let max_response = target.limits.max_pcm_bytes + target.limits.max_header_bytes + 4;
    if response.content_length().is_some_and(|n| n > max_response) {
        return Err(invalid("oversized worker response"));
    }
    let mut received = Vec::new();
    response
        .by_ref()
        .take(max_response + 1)
        .read_to_end(&mut received)
        .map_err(|_| invalid("worker response failed"))?;
    if received.len() as u64 > max_response || received.len() < 5 {
        return Err(invalid("invalid worker response size"));
    }
    let n = u32::from_be_bytes(received[..4].try_into().map_err(|_| invalid("header"))?) as usize;
    if n == 0 || n as u64 > target.limits.max_header_bytes || received.len() <= n + 4 {
        return Err(invalid("invalid worker metadata"));
    }
    let meta: Value = serde_json::from_slice(&received[4..4 + n])
        .map_err(|_| invalid("invalid worker metadata"))?;
    if meta["target"] != target_json(target)
        || meta["sample_rate"].as_u64() != Some(u64::from(target.warm.sample_rate))
        || meta["channels"].as_u64() != Some(1)
    {
        return Err(invalid("worker target mismatch"));
    }
    Ok(received.split_off(4 + n))
}

/// One render as one call on `seat`: its permit starts before the request
/// leaves, and an answer settles on the characters it spoke.
fn admitted_render(
    seat: &WireSeat,
    client: &Client,
    url: &Url,
    credential: &str,
    target: &RenderTarget,
    reference: &VoiceRegisterClip,
    text: &str,
) -> Result<Vec<u8>> {
    let request = seat.request(
        AiOperation::Speech,
        vec![MediaPart::Text {
            text: text.to_owned(),
        }],
        Some(MediaVoice::Reference {
            voice_id: target.voice_id.clone(),
            owner: target.fence.owner.to_hex(),
            register: reference.register.clone(),
            revision: reference_revision(&target.fence),
            media_type: reference.media_type.clone(),
            audio: reference.audio.clone(),
            transcript: reference.transcript.clone(),
        }),
    );
    seat.call(
        &request,
        || render(client, url, credential, target, reference, text),
        |_| MediaUsage {
            characters: u64::try_from(text.chars().count()).unwrap_or(u64::MAX),
            ..MediaUsage::default()
        },
    )
    .map_err(|error| match error {
        WireCallError::Refused(_) => invalid("run admission refused the render"),
        WireCallError::Failed(error) => error,
    })
}

fn run_worker(
    vault: Arc<Vault>,
    seat: &WireSeat,
    client: Client,
    url: Url,
    credential: String,
    work: Receiver<VoxCpm2Work>,
    results: Sender<VoxCpm2Event>,
) {
    let mut active: Option<(GenerationEpoch, RenderTarget)> = None;
    let mut chunk_index = 0;
    while let Ok(item) = work.recv() {
        match item.operation {
            VoxCpm2Operation::Start { target } => {
                active = Some((item.generation, *target));
                chunk_index = 0;
            }
            VoxCpm2Operation::Cancel => {
                active = None;
            }
            VoxCpm2Operation::Render { text } => {
                let event = match active.as_ref() {
                    Some((epoch, target)) if *epoch == item.generation => {
                        match target.with_current(&vault, |reference| {
                            admitted_render(
                                seat,
                                &client,
                                &url,
                                &credential,
                                target,
                                reference,
                                &text,
                            )
                        }) {
                            Ok(bytes) => {
                                let event = VoxCpm2Event::Audio {
                                    generation: item.generation,
                                    submission: item.sequence,
                                    chunk_index,
                                    target: Box::new(target.clone()),
                                    bytes,
                                };
                                chunk_index += 1;
                                event
                            }
                            Err(_) => {
                                active = None;
                                VoxCpm2Event::Failed {
                                    generation: item.generation,
                                    submission: item.sequence,
                                }
                            }
                        }
                    }
                    _ => VoxCpm2Event::Failed {
                        generation: item.generation,
                        submission: item.sequence,
                    },
                };
                // A stopped session (its queue dropped) must not hold this worker.
                if results.send(event).is_err() {
                    active = None;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
