//! Shared provider HTTP client execution.

use super::*;

impl ProviderHttp {
    /// Builds the client. A configured `key_env` that is unset or empty is a
    /// refusal here, so a seat never runs half-authenticated.
    pub(in crate::models) fn new(
        provider: &ProviderConfig,
        style: KeyStyle,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            provider.siwc.is_none(),
            "SIWC credentials are served by the Responses backend only"
        );
        Self::build(provider, style, false)
    }

    /// Builds a client that never goes through an environment proxy: a
    /// loopback URL is only a loopback destination when no proxy applies.
    pub(in crate::models) fn direct(
        provider: &ProviderConfig,
        style: KeyStyle,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            provider.siwc.is_none(),
            "SIWC credentials are served by the Responses backend only"
        );
        Self::build(provider, style, true)
    }

    /// The Responses consumer supplies its sensitive credential per send.
    pub(in crate::models) fn siwc(provider: &ProviderConfig) -> anyhow::Result<Self> {
        anyhow::ensure!(
            provider.siwc.is_some()
                && provider.kind == crate::config::models::ProviderKind::OpenaiCompat
                && provider.base_url == oneiron::dispatch_byoa::SIWC_RESPONSES_BASE_URL
                && provider.key_env.is_none()
                && provider.key_secret.is_none()
                && provider.locality == oneiron::ModelLocality::ThirdParty
                && provider.responses_socket.is_none(),
            "SIWC credentials require the official Responses HTTP route and no other key source"
        );
        Self::build(provider, KeyStyle::Bearer, false)
    }

    pub(super) fn build(
        provider: &ProviderConfig,
        style: KeyStyle,
        direct: bool,
    ) -> anyhow::Result<Self> {
        let mut headers = reqwest::header::HeaderMap::new();
        for (name, value) in &provider.headers {
            headers.insert(
                reqwest::header::HeaderName::from_bytes(name.as_bytes())?,
                reqwest::header::HeaderValue::from_str(value)?,
            );
        }
        if let Some(env) = &provider.key_env {
            let key = std::env::var(env)
                .ok()
                .filter(|key| !key.trim().is_empty())
                .ok_or_else(|| anyhow::anyhow!("{env} is not set"))?;
            let (name, value) = match style {
                KeyStyle::Bearer => (reqwest::header::AUTHORIZATION, format!("Bearer {key}")),
                KeyStyle::ApiKeyHeader => {
                    (reqwest::header::HeaderName::from_static("x-api-key"), key)
                }
                KeyStyle::Named(name) => (reqwest::header::HeaderName::from_static(name), key),
            };
            let mut value = reqwest::header::HeaderValue::from_str(&value)?;
            value.set_sensitive(true);
            headers.insert(name, value);
        }
        // One request per call (`SingleSend`): a redirect is answered, never
        // followed, and nothing the upstream may have read is sent twice; a
        // request that never reached it goes once more on `fresh`, a client
        // that keeps no idle connection (FIX 7113). reqwest's default policy
        // would resend a request an HTTP/2 server refused at the protocol
        // level.
        let builder = || {
            let builder = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .connect_timeout(Duration::from_secs(provider.timeout_secs.min(30)))
                .timeout(Duration::from_secs(provider.timeout_secs));
            if direct { builder.no_proxy() } else { builder }
        };
        let client = builder().default_headers(headers.clone()).build()?;
        let fresh = builder()
            .default_headers(headers)
            .pool_max_idle_per_host(0)
            .build()?;
        let bare = builder().build()?;
        Ok(Self {
            client,
            fresh,
            bare,
            base_url: provider.base_url.clone(),
            compression: provider.request_compression.map(|compression| {
                Arc::new(Compressor {
                    compression,
                    on: AtomicBool::new(true),
                })
            }),
        })
    }

    /// Joins the base URL and a protocol path. A base that already ends in
    /// `/v1` absorbs the path's own `/v1`, so both spellings of a base work.
    pub(in crate::models) fn url(&self, path: &str) -> String {
        match (self.base_url.strip_suffix("/v1"), path.strip_prefix("/v1/")) {
            (Some(base), Some(rest)) => format!("{base}/v1/{rest}"),
            _ => format!("{}{path}", self.base_url),
        }
    }

    /// The server's own root: a base that ends in `/v1` drops it, so a
    /// llama.cpp native path (`/completion`) is reached under any prefix.
    pub(in crate::models) fn native(&self) -> Self {
        Self {
            client: self.client.clone(),
            fresh: self.fresh.clone(),
            bare: self.bare.clone(),
            base_url: self
                .base_url
                .strip_suffix("/v1")
                .unwrap_or(&self.base_url)
                .to_owned(),
            compression: self.compression.clone(),
        }
    }

    pub(super) fn request(
        &self,
        path: &str,
        headers: &BTreeMap<String, String>,
    ) -> reqwest::RequestBuilder {
        let mut request = self.client.post(self.url(path));
        if !headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case("content-type"))
        {
            request = request.header(reqwest::header::CONTENT_TYPE, "application/json");
        }
        for (name, value) in headers {
            request = request.header(name, value);
        }
        request
    }

    /// Posts `body` as JSON, compressed when this provider's route takes it
    /// (ARCH-0081 §6).
    pub(super) fn post(
        &self,
        path: &str,
        headers: &BTreeMap<String, String>,
        body: &JsonValue,
    ) -> Sending {
        let plain = serde_json::to_vec(body).unwrap_or_default();
        self.send_body(path, || self.request(path, headers), plain, None)
    }

    /// Sends `plain` on a request `request` builds, compressed when this
    /// provider's route takes it. A 400 or 415 to a compressed body is sent
    /// once more, plain, while `admission`, when there is one, still allows
    /// the upload, and otherwise stands; when the plain answer differs, the
    /// encoding was the cause and compression turns off for this process.
    /// Each send that never reached the upstream goes once more on a fresh
    /// connection ([`never_sent::send`]).
    pub(super) fn send_body(
        &self,
        path: &str,
        request: impl Fn() -> reqwest::RequestBuilder,
        plain: Vec<u8>,
        admission: Option<UploadAdmission>,
    ) -> Sending {
        let encoded = self.compression.as_ref().and_then(|compressor| {
            Some((Arc::clone(compressor), compressor.encode(path, &plain)?))
        });
        let Some((compressor, encoded)) = encoded else {
            return never_sent::send(&self.fresh, request().body(plain));
        };
        let (request, resend) = (request(), request());
        let fresh = self.fresh.clone();
        Box::pin(async move {
            let request = request
                .header(reqwest::header::CONTENT_ENCODING, compressor.token())
                .body(encoded);
            let response = never_sent::send(&fresh, request).await?;
            if !matches!(response.status().as_u16(), 400 | 415)
                || admission.is_some_and(|admits| !admits())
            {
                return Ok(response);
            }
            let refused = response.status();
            drop(response);
            let response = never_sent::send(&fresh, resend.body(plain)).await?;
            if response.status() != refused {
                compressor.on.store(false, Ordering::Relaxed);
                tracing::warn!(
                    status = refused.as_u16(),
                    codec = compressor.token(),
                    "a provider refused a compressed request body; sending plain from now on"
                );
            }
            Ok(response)
        })
    }

    /// [`Self::send_body`] with `release` invoked before every physical send,
    /// including a fresh-connection retry and a plain resend after 400/415.
    pub(super) fn send_body_released<'a>(
        &'a self,
        path: &'a str,
        request: impl Fn() -> reqwest::RequestBuilder + 'a,
        plain: Vec<u8>,
        release: DispatchRelease<'a>,
        lease: &'a BudgetLease,
    ) -> ReleaseSending<'a> {
        let encoded = self.compression.as_ref().and_then(|compressor| {
            Some((Arc::clone(compressor), compressor.encode(path, &plain)?))
        });
        let Some((compressor, encoded)) = encoded else {
            return never_sent::send_released(&self.fresh, request().body(plain), release, lease);
        };
        let (request, resend) = (request(), request());
        let fresh = self.fresh.clone();
        Box::pin(async move {
            let request = request
                .header(reqwest::header::CONTENT_ENCODING, compressor.token())
                .body(encoded);
            let response =
                never_sent::send_released(&fresh, request, release.clone(), lease).await?;
            if !matches!(response.status().as_u16(), 400 | 415) {
                return Ok(response);
            }
            let refused = response.status();
            drop(response);
            let response =
                never_sent::send_released(&fresh, resend.body(plain), release, lease).await?;
            if response.status() != refused {
                compressor.on.store(false, Ordering::Relaxed);
                tracing::warn!(
                    status = refused.as_u16(),
                    codec = compressor.token(),
                    "a provider refused a compressed request body; sending plain from now on"
                );
            }
            Ok(response)
        })
    }

    /// One JSON exchange at `path`, its reply read whole, however large
    /// (FIX 9321): no size refuses it, and only a real allocation failure
    /// ends the read.
    pub(in crate::models) async fn post_json(
        &self,
        path: &str,
        headers: &BTreeMap<String, String>,
        body: &JsonValue,
    ) -> Result<JsonReply, HttpFailure> {
        let response = self.post(path, headers, body).await?;
        let status = response.status().as_u16();
        let headers = reply_headers(&response);
        // The encoded bytes stay booked, inside a media call, until the
        // reply is parsed.
        let (bytes, _held) = read_whole(response).await?;
        json_reply(status, headers, &bytes)
    }

    /// [`Self::post_json`], with a reply bound of the caller's own protocol.
    pub(in crate::models) async fn post_json_within(
        &self,
        path: &str,
        headers: &BTreeMap<String, String>,
        body: &JsonValue,
        max_bytes: usize,
    ) -> Result<JsonReply, HttpFailure> {
        let response = self.post(path, headers, body).await?;
        let status = response.status().as_u16();
        let headers = reply_headers(&response);
        let bytes = bounded_body(response, max_bytes).await?;
        json_reply(status, headers, &bytes)
    }

    /// One media exchange at `path`, its reply body read whole, however
    /// large, on the media-reply line (FIX 8615). One request, as every
    /// exchange here; a JSON or octet body is compressed as
    /// [`Self::send_body`] says.
    pub(in crate::models) async fn send_media(
        &self,
        path: &str,
        send: MediaSend,
    ) -> Result<BytesReply, HttpFailure> {
        let response = self.media_response(path, send).await?;
        let status = response.status().as_u16();
        let headers = reply_headers(&response);
        let (body, held) = read_booked(response).await?;
        Ok(BytesReply {
            status,
            headers,
            body,
            held,
        })
    }

    /// Sends one released JSON exchange: every physical attempt re-checks
    /// the lease's release, and a refusal keeps its original model error.
    pub(in crate::models) async fn send_json_released(
        &self,
        path: &str,
        json: JsonValue,
        release: DispatchRelease<'_>,
        lease: &BudgetLease,
    ) -> Result<BytesReply, HttpReleaseError> {
        let plain = serde_json::to_vec(&json).unwrap_or_default();
        let url = self.url(path);
        let request = {
            let url = url.as_str();
            move || {
                self.client
                    .post(url)
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
            }
        };
        let response = self
            .send_body_released(path, request, plain, release, lease)
            .await?;
        let status = response.status().as_u16();
        let headers = reply_headers(&response);
        let (body, held) = read_booked(response)
            .await
            .map_err(HttpReleaseError::Transport)?;
        Ok(BytesReply {
            status,
            headers,
            body,
            held,
        })
    }

    /// [`Self::send_media`], its 2xx reply's body left for the caller to
    /// take as it arrives ([`MediaStream::chunk`]), never held whole here
    /// (FIX 6122). Any other status's body is read whole, as `send_media`
    /// reads it.
    pub(in crate::models) async fn send_media_streamed(
        &self,
        path: &str,
        send: MediaSend,
    ) -> Result<StreamedReply, HttpFailure> {
        let response = self.media_response(path, send).await?;
        if response.status().is_success() {
            return Ok(StreamedReply::Body(MediaStream(response)));
        }
        let status = response.status().as_u16();
        let headers = reply_headers(&response);
        let (body, held) = read_booked(response).await?;
        Ok(StreamedReply::Refused(BytesReply {
            status,
            headers,
            body,
            held,
        }))
    }

    /// Sends one media exchange at `path`: its answer, its body unread.
    pub(super) async fn media_response(
        &self,
        path: &str,
        send: MediaSend,
    ) -> Result<reqwest::Response, HttpFailure> {
        let url = self.url(path);
        let body = |content_type: &'static str| {
            let url = url.as_str();
            move || {
                self.client
                    .post(url)
                    .header(reqwest::header::CONTENT_TYPE, content_type)
            }
        };
        Ok(match send {
            MediaSend::Get => self.client.get(url.as_str()).send().await?,
            MediaSend::Delete => self.client.delete(url.as_str()).send().await?,
            MediaSend::Json(json) => {
                let plain = serde_json::to_vec(&json).unwrap_or_default();
                self.send_body(path, body("application/json"), plain, None)
                    .await?
            }
            MediaSend::Multipart(form) => {
                self.client
                    .post(url.as_str())
                    .multipart(form)
                    .send()
                    .await?
            }
            MediaSend::Octets(octets, admission) => {
                let send = body("application/octet-stream");
                self.send_body(path, send, octets, Some(admission)).await?
            }
        })
    }

    /// One GET of `path` at the server's own root (as [`Self::native`]
    /// joins it), its body read whole up to `max_bytes`. The path is the
    /// caller's, never a URL a reply named, so it stays on this origin; a
    /// redirect is answered, never followed, and nothing is sent twice.
    pub(in crate::models) async fn get_native_within(
        &self,
        path: &str,
        max_bytes: usize,
    ) -> Result<BytesReply, HttpFailure> {
        let response = self.client.get(self.native().url(path)).send().await?;
        let status = response.status().as_u16();
        let headers = reply_headers(&response);
        let body = bounded_body(response, max_bytes).await?;
        Ok(BytesReply {
            status,
            headers,
            body,
            held: ReplyBytes::default(),
        })
    }

    /// A file the provider named by its full URI, read whole, however
    /// large, on the media-reply line. The key goes only to the provider's own
    /// origin; one redirect from there is followed, without the key or any
    /// provider header when it leaves that origin (a clip served from
    /// storage).
    pub(in crate::models) async fn fetch_media(
        &self,
        uri: &str,
    ) -> Result<BytesReply, HttpFailure> {
        let origin = reqwest::Url::parse(&self.base_url)
            .map_err(|_| HttpFailure::Connection)?
            .origin();
        let target = reqwest::Url::parse(uri).map_err(|_| HttpFailure::Malformed)?;
        if target.origin() != origin {
            return Err(HttpFailure::Malformed);
        }
        let mut response = self.client.get(target.clone()).send().await?;
        if response.status().is_redirection() {
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|location| location.to_str().ok())
                .and_then(|location| target.join(location).ok())
                .filter(|location| location.scheme() == "https")
                .ok_or(HttpFailure::Malformed)?;
            let client = if location.origin() == origin {
                &self.client
            } else {
                &self.bare
            };
            response = client.get(location).send().await?;
        }
        let status = response.status().as_u16();
        let headers = reply_headers(&response);
        let (body, held) = read_booked(response).await?;
        Ok(BytesReply {
            status,
            headers,
            body,
            held,
        })
    }

    /// A per-send SIWC bearer never enters a public request envelope. The
    /// caller retains credential and cancellation checks through `release`.
    pub(in crate::models) async fn post_sse_released<'a>(
        &'a self,
        path: &'a str,
        authorization: reqwest::header::HeaderValue,
        plain: Vec<u8>,
        release: DispatchRelease<'a>,
        lease: &'a BudgetLease,
    ) -> Result<impl Stream<Item = Result<SseItem, HttpFailure>> + Send + 'static, HttpReleaseError>
    {
        let request = || {
            self.client
                .post(self.url(path))
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .header(reqwest::header::AUTHORIZATION, authorization.clone())
        };
        let response = self
            .send_body_released(path, request, plain, release, lease)
            .await?;
        // The old reader owns non-2xx status parsing and every SSE frame.
        let sending: Sending = Box::pin(std::future::ready(Ok(response)));
        Ok(futures_util::stream::unfold(
            SseState::Start(sending),
            next_sse,
        ))
    }

    /// Starts a streamed exchange. A non-2xx answer arrives as one
    /// [`SseItem::Status`], its body read whole however large (FIX 9321),
    /// or [`HttpFailure::OutOfMemory`] when that body could not be held; a
    /// 2xx answer as its events, in order.
    pub(in crate::models) fn post_sse(
        &self,
        path: &str,
        headers: &BTreeMap<String, String>,
        body: &JsonValue,
    ) -> impl Stream<Item = Result<SseItem, HttpFailure>> + Send + 'static {
        let sending = self.post(path, headers, body);
        futures_util::stream::unfold(SseState::Start(sending), next_sse)
    }
}
