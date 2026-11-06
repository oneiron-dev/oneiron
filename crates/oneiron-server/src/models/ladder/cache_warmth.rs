//! Prompt-cache warmth (FIX 6029): this runtime's own note, in memory, of
//! which reusable prefix each route still holds warm in its provider's
//! prompt cache. It is a hint for `auto`'s choice between a live fork and
//! the cheap writer, never proof that a provider will hit. A rung's answer
//! notes a prefix only on its provider's own usage (FIX 6493): the one
//! block its request marked, when the provider reports a cache write, from
//! the instant it was dispatched, for the lifetime its provider keeps that
//! tier ([`cache_profile`], the one table). A self agent's compaction
//! under a row on `auto` reads the note when its breakpoint captures the
//! live request, and again right before its live fork's first dispatch.
//! Nothing is kept in the vault or across a restart, and no key is read: a
//! route the table does not know, a T0 offer (FIX 6495), a rebuilt provider
//! client, or a prefix no answer showed written reads cold. Warmth never
//! depends on where the agent runs.
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Mutex, PoisonError, Weak};
use std::time::Instant;

use oneiron::code_run::{CacheBoundary, HOST_PROVIDER_OPTIONS, LiveForkRung, cache_boundaries};
use oneiron::llm::SingleRouteBackend;
use oneiron_llm_anthropic::{AnthropicCacheTier, AnthropicProviderOptions};

use super::*;

/// The Anthropic API's own Messages route: the one route whose prompt-cache
/// lifetimes the table knows (CALLS "FIX 6029 prompt-cache lifetimes"). A
/// compatible proxy at another origin is unknown, so cold.
const ANTHROPIC_ROUTE: (&str, &str) = ("anthropic-compat", "https://api.anthropic.com");

/// How long the Anthropic API keeps a marked prefix at its default tier.
const ANTHROPIC_FIVE_MINUTES: Duration = Duration::from_secs(300);

/// How long it keeps one a request asked to keep for the hour.
const ANTHROPIC_ONE_HOUR: Duration = Duration::from_secs(3600);

/// How many content blocks before a request's breakpoint the Anthropic API
/// looks back for a prefix it holds.
const ANTHROPIC_LOOKBACK_BLOCKS: usize = 20;

/// How a route keeps a marked prefix: for how long after the send that
/// marked it, and how many content blocks before a later request's
/// breakpoint its provider looks back for it.
#[derive(Clone, Copy)]
struct CacheProfile {
    lifetime: Duration,
    lookback: usize,
}

/// The one lifetime table: the profile `rung`'s route keeps `request`'s
/// marked prefixes by, at the tier the request asks for, read by the same
/// parser its wire marks with. `None`, so cold, for every route not in it
/// (an OpenAI-style, Gemini or DeepSeek route, a proxy) until a row is
/// added here, and for a tier the parser does not know.
///
/// `None` too for a T0 offer (FIX 6495), on a note and on a lookup alike.
/// Its binding names the key's record, never the key's rotation
/// generation, so a key rotated under the same name keeps its client and
/// would keep its notes. Its warmth is unknown. Its sends and a forced
/// live fork go on as before.
fn cache_profile(rung: &LadderRung, request: &LlmRequest) -> Option<CacheProfile> {
    let binding = &rung.offer.binding;
    if binding.custody == KeyCustody::T0 {
        return None;
    }
    let route = &binding.route;
    if (route.adapter(), route.origin()) != ANTHROPIC_ROUTE {
        return None;
    }
    let lifetime = match AnthropicProviderOptions::from_request(request)
        .ok()?
        .cache_tier()?
    {
        AnthropicCacheTier::FiveMinutes => ANTHROPIC_FIVE_MINUTES,
        AnthropicCacheTier::OneHour => ANTHROPIC_ONE_HOUR,
    };
    Some(CacheProfile {
        lifetime,
        lookback: ANTHROPIC_LOOKBACK_BLOCKS,
    })
}

/// One reusable prefix of a request as its rung sends it: the content block
/// of a non-system message it ends at, and its digest.
struct Prefix {
    message: usize,
    part: usize,
    digest: [u8; 32],
}

/// Every reusable prefix of `request`, shortest first (CALLS "FIX 6029
/// prefix digest"). Each digest covers, in the order the wire caches a
/// prefix, all that would change it: the model, the tools, the params, the
/// options but the host's own descriptor, the effort and the reply format,
/// every system block, then each message's role and parts through the block
/// it ends at. `None` when the request does not encode.
fn prefixes(request: &LlmRequest) -> Option<Vec<Prefix>> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron.cache_warmth.prefix.v1");
    let options: BTreeMap<&String, &JsonValue> = request
        .provider_options
        .iter()
        .filter(|(namespace, _)| namespace.as_str() != HOST_PROVIDER_OPTIONS)
        .collect();
    feed(
        &mut hasher,
        &(
            &request.model,
            &request.tools,
            &request.params,
            &options,
            &request.envelope.seat_effort,
            &request.envelope.response_format,
        ),
    )?;
    for message in &request.messages {
        if message.role == LlmMessageRole::System {
            for part in &message.content {
                feed(&mut hasher, part)?;
            }
        }
    }
    let mut prefixes = Vec::new();
    for (index, message) in request.messages.iter().enumerate() {
        if message.role == LlmMessageRole::System {
            continue;
        }
        feed(&mut hasher, &message.role)?;
        for (part, content) in message.content.iter().enumerate() {
            feed(&mut hasher, content)?;
            prefixes.push(Prefix {
                message: index,
                part,
                digest: *hasher.clone().finalize().as_bytes(),
            });
        }
    }
    Some(prefixes)
}

/// Feeds `value`'s JSON to `hasher`, its length first.
fn feed(hasher: &mut blake3::Hasher, value: &impl Serialize) -> Option<()> {
    let bytes = serde_json::to_vec(value).ok()?;
    hasher.update(&bytes.len().to_le_bytes());
    hasher.update(&bytes);
    Some(())
}

/// What one warm prefix is held under: the offer its rung serves (its route,
/// offer, credential binding name and catalog revision, by digest), the
/// wire model, the provider client it went out through (CALLS "FIX 6029
/// client generation": a rebuilt client is another one, so cold; no key is
/// read or hashed, and a T0 offer is never held, FIX 6495), and the
/// prefix's digest.
#[derive(Clone, PartialEq, Eq, Hash)]
struct WarmKey {
    offer: String,
    wire_model: String,
    client: usize,
    prefix: [u8; 32],
}

/// `rung`'s part of a key: `None` when its offer does not encode.
fn route_key(rung: &LadderRung) -> Option<impl Fn(&Prefix) -> WarmKey> {
    let offer = oneiron::code_run::live_fork_offer_digest(&rung.offer.binding)?;
    let wire_model = rung.wire_model.clone();
    let client = Arc::as_ptr(&rung.offer.backend).cast::<()>().addr();
    Some(move |prefix: &Prefix| WarmKey {
        offer: offer.clone(),
        wire_model: wire_model.clone(),
        client,
        prefix: prefix.digest,
    })
}

/// One answered send's note of a prefix: the instant it was dispatched, the
/// lifetime its tier keeps, the prefix's extent in the provider's own
/// tokens (FIX 6493), and the client it went out through, held weakly so
/// that client's place is never another's while the note stands.
struct Observation {
    client: Weak<dyn SingleRouteBackend>,
    sent: Instant,
    lifetime: Duration,
    #[expect(dead_code, reason = "a hit's refresh reads it (FIX 6494)")]
    tokens: u64,
}

impl Observation {
    fn warm(&self, now: Instant) -> bool {
        self.client.strong_count() > 0 && now.saturating_duration_since(self.sent) < self.lifetime
    }

    fn until(&self) -> Option<Instant> {
        self.sent.checked_add(self.lifetime)
    }
}

/// The warm prefixes one runtime's routes hold (FIX 6029): in memory only,
/// on the offer state every ladder of the runtime shares. Expired notes are
/// pruned whenever it is read or written.
#[derive(Default)]
pub(in crate::models) struct CacheWarmth(Mutex<HashMap<WarmKey, Observation>>);

impl CacheWarmth {
    fn note(&self, key: WarmKey, seen: Observation) {
        let now = Instant::now();
        let mut held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        held.retain(|_, seen| seen.warm(now));
        // A send that answers late never shortens a later one's note.
        if held
            .get(&key)
            .is_none_or(|prior| prior.until() < seen.until())
        {
            held.insert(key, seen);
        }
    }

    /// The first of `keys` still warm now.
    fn first_warm(&self, keys: impl IntoIterator<Item = WarmKey>) -> Option<WarmKey> {
        let now = Instant::now();
        let mut held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        held.retain(|_, seen| seen.warm(now));
        keys.into_iter().find(|key| held.contains_key(key))
    }

    fn warm(&self, key: &WarmKey) -> bool {
        self.first_warm([key.clone()]).is_some()
    }
}

/// The one prefix a send marked, as it went out (FIX 6493).
struct Marked {
    key: WarmKey,
    client: Weak<dyn SingleRouteBackend>,
    sent: Instant,
    lifetime: Duration,
}

/// What a rung's send notes as warm once it answers, taken right before its
/// bound request goes out, so its instant is no later than its dispatch.
pub(super) struct Sending(Option<Marked>);

impl Sending {
    /// `bound` as `rung` sends it: nothing on a route the table does not
    /// know, or for a request that does not mark exactly one message block.
    pub(super) fn of(rung: &LadderRung, bound: &LlmRequest) -> Self {
        Self(marked(rung, bound))
    }

    /// The rung answered with `usage`, the provider's own, before a receipt
    /// is stamped on it (FIX 6493). The one prefix its request marked is
    /// warm from its dispatch for the lifetime its tier keeps, whatever its
    /// settlement, only when the provider reports a cache write. Its extent
    /// is the tokens the provider read and wrote: the prefix through that
    /// one block. An answer with no cache write notes nothing.
    pub(super) fn answered(self, rests: &OfferCooldowns, usage: &LlmUsage) {
        let Some(marked) = self.0 else {
            return;
        };
        let input = &usage.input;
        if input.cache_write == 0 {
            return;
        }
        let seen = Observation {
            client: marked.client,
            sent: marked.sent,
            lifetime: marked.lifetime,
            tokens: input.cache_read.saturating_add(input.cache_write),
        };
        rests.warmth.note(marked.key, seen);
    }
}

/// `bound`'s one marked prefix as `rung` sends it (FIX 6493). A provider
/// reports one cache write for the whole send, and writes nothing for a
/// prefix shorter than its model's minimum, so a write names a prefix only
/// when the send marks one block. A request whose descriptor names more
/// than one, a tool's or a system block's included, or whose own options
/// carry a `cache_control`, notes nothing. Neither does one whose one block
/// is a tool's or a system block, which no prefix here ends at.
fn marked(rung: &LadderRung, bound: &LlmRequest) -> Option<Marked> {
    let sent = Instant::now();
    let profile = cache_profile(rung, bound)?;
    let CacheBoundary::Message { message, part } = sole_boundary(bound)? else {
        return None;
    };
    let key = route_key(rung)?;
    let prefix = prefixes(bound)?
        .into_iter()
        .find(|prefix| (prefix.message, prefix.part) == (message, part))?;
    Some(Marked {
        key: key(&prefix),
        client: Arc::downgrade(&rung.offer.backend),
        sent,
        lifetime: profile.lifetime,
    })
}

/// The one block `request` marks on its wire, when it marks exactly one
/// (FIX 6493): its descriptor names that one boundary alone, and its own
/// options carry no `cache_control`.
fn sole_boundary(request: &LlmRequest) -> Option<CacheBoundary> {
    if options_mark(request) {
        return None;
    }
    let boundaries: BTreeSet<CacheBoundary> = cache_boundaries(request).ok()?.into_iter().collect();
    let mut boundaries = boundaries.into_iter();
    match (boundaries.next(), boundaries.next()) {
        (Some(boundary), None) => Some(boundary),
        _ => None,
    }
}

/// Whether `request`'s own Anthropic options carry a `cache_control` at any
/// depth (FIX 6493). The wire sends those options as they are, so each is a
/// marker on a block the host's descriptor does not place.
fn options_mark(request: &LlmRequest) -> bool {
    AnthropicProviderOptions::from_request(request).is_ok_and(|options| {
        options
            .raw
            .iter()
            .any(|(key, value)| names_cache_control(key, value))
    })
}

fn names_cache_control(key: &str, value: &JsonValue) -> bool {
    key == "cache_control"
        || match value {
            JsonValue::Object(object) => object
                .iter()
                .any(|(key, inner)| names_cache_control(key, inner)),
            JsonValue::Array(items) => items.iter().any(|item| names_cache_control("", item)),
            _ => false,
        }
}

impl OfferLadder {
    /// Whether `request`, as `captured` sends it on this ladder, reuses a
    /// prefix this runtime's routes still hold warm (FIX 6029): one an
    /// answer showed written (FIX 6493), unexpired, through the same
    /// client, within the blocks its provider looks back from the request's
    /// end. False for a rung this ladder does not hold or a route the table
    /// does not know.
    pub(crate) fn live_prefix_warm(&self, captured: &LiveForkRung, request: &LlmRequest) -> bool {
        self.warm_key(captured, request).is_some()
    }

    fn warm_key(&self, captured: &LiveForkRung, request: &LlmRequest) -> Option<WarmKey> {
        let rung = self.rungs.iter().find(|rung| {
            rung.offer.binding == captured.offer && rung.wire_model == captured.wire_model
        })?;
        let profile = cache_profile(rung, request)?;
        let key = route_key(rung)?;
        let prefixes = prefixes(request)?;
        self.rests
            .warmth
            .first_warm(prefixes.iter().rev().take(profile.lookback).map(key))
    }

    /// The first live-fork send of a flight under a row on `auto` (FIX
    /// 6029), on this one picked rung: sent only while `prefix`, the live
    /// request it forks as `captured` sends it, is still warm. `Ok(None)`
    /// for every stop before the rung went out (a cold prefix, asked before
    /// the rung is admitted and again once it is; a rung that rests, has its
    /// probation request out or is held on the device; a refused admission;
    /// a gate that refused it unsent), its permit settled unstarted first,
    /// for nothing: the flight's cheap writer then writes as the agent. Once
    /// the rung went out, its failure is its own, never read as cold, and
    /// the call goes on as [`Self::generate_exact_within`] would.
    pub(crate) async fn generate_exact_while_warm(
        &self,
        run: &RunAdmission,
        request: LlmRequest,
        captured: &LiveForkRung,
        prefix: &LlmRequest,
    ) -> LlmResult<Option<LlmResponse>> {
        let [rung] = self.rungs.as_slice() else {
            return Ok(None);
        };
        if !self.picked || self.admits(&request).is_err() {
            return Ok(None);
        }
        let Some(key) = self.warm_key(captured, prefix) else {
            return Ok(None);
        };
        let warm = || self.rests.warmth.warm(&key);
        let routes = self.rests.world_routes(&request);
        let takes_now = self.route_admitted(&routes, 0)
            && self.kept_on_device(0, &request).is_none()
            && self
                .rests
                .resting(&rung.offer.binding, &rung.wire_model)
                .is_none()
            && self
                .rests
                .probing(&rung.offer.binding, &rung.wire_model)
                .is_none();
        if !takes_now || !warm() {
            return Ok(None);
        }
        // The run is live until this call ends: the host stays awake for it.
        let _awake = oneiron_vault_contract::host_adapters::run_awake();
        let rung_run = run.with_work_context({
            let mut context = run.work_context();
            context.physical = physical_for(&rung.offer.binding);
            context
        });
        let Ok((bound, permit)) = self.admit(&rung_run, rung, &request, None, false) else {
            return Ok(None);
        };
        // Admission can wait on the run's receipts: the prefix, the
        // world's order and the world are judged again right before the rung
        // is sent.
        if !warm() || !self.route_admitted(&routes, 0) || self.kept_on_device(0, &request).is_some()
        {
            settle_failed(permit);
            return Ok(None);
        }
        let mut walk = Walk::default();
        let Some(probe) = self.probe(0, &mut walk) else {
            settle_failed(permit);
            return Ok(None);
        };
        let gate = rung_run.gate(Arc::clone(&rung.offer.backend), &rung.offer.binding);
        let warmth = Sending::of(rung, &bound);
        match gate.generate(bound, permit.lease()).await {
            Ok(mut response) => {
                warmth.answered(&self.rests, &response.usage);
                self.rests.succeeded(&rung.offer.binding, &rung.wire_model);
                permit.settle(CallOutcome::Answered(&response.usage))?;
                response.usage = self.answered(0, &walk, response.usage);
                rung.note_answered(&request);
                Ok(Some(response))
            }
            Err(error) => {
                if !settle_failed(permit) {
                    // The gate refused it before it went out.
                    return Ok(None);
                }
                drop(probe);
                self.failed(0, error, true, &mut walk)?;
                let budget = Duration::from_secs(self.rests.max_wait_secs());
                self.generate_exact_within(run, request, None, &|| true, budget)
                    .await
                    .map(Some)
            }
        }
    }
}
