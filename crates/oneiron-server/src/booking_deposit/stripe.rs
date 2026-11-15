//! The Stripe API calls a deposit needs, test mode only.
//!
//! One PaymentIntent per deposit: created with `capture_method=manual` at
//! checkout, captured at confirm, cancelled when its checkout window ends
//! unconfirmed, refunded on a cancel. Every call reads the owner's secret
//! key inside the custody door, refuses it there unless it is a test key,
//! and never lets it leave the door's closure. Every write carries the
//! caller's `Idempotency-Key`, so a retry is deduped by Stripe. A refund
//! also carries that key in its metadata and is looked up by it before any
//! new one is made, since Stripe keeps an idempotency key for a day only; a
//! refund counts once Stripe says it succeeded.

use std::collections::BTreeMap;
use std::io::Read;
use std::time::Duration;

use oneiron::Vault;
use oneiron::booking::DepositTerms;
use oneiron::booking::lifecycle::{
    DepositProviderFailure, DepositSettleMove, DepositSettleRequest, DepositSettlementPort,
};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::{DEPOSIT_EFFECTOR, STRIPE_PUBLISHABLE_KEY_NAME, STRIPE_SECRET_KEY_NAME};

/// Stripe's API origin.
pub(crate) const STRIPE_API_BASE: &str = "https://api.stripe.com";

/// The API version every request pins, so a dashboard upgrade never changes
/// a reply's shape under this code.
const STRIPE_API_VERSION: &str = "2024-06-20";

/// The largest Stripe reply read.
const MAX_STRIPE_REPLY_BYTES: u64 = 256 * 1024;

/// The longest Stripe object id accepted.
const MAX_STRIPE_ID_BYTES: usize = 255;

/// The refund metadata field that carries the settle move's idempotency
/// key, as the form names it and as the refund answers it.
const SETTLE_KEY_FORM_FIELD: &str = "metadata[oneiron_settle_key]";
const SETTLE_KEY_METADATA: &str = "oneiron_settle_key";

/// Why a deposit cannot use Stripe on this server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DepositSetupError {
    /// A live key: deposits run in test mode only until the owner says so.
    LiveKeyRefused,
    /// Not a Stripe test key of the expected kind.
    NotATestKey,
    /// The custody door refused or holds no such secret.
    Secret(String),
}

impl std::fmt::Display for DepositSetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LiveKeyRefused => {
                f.write_str("a live Stripe key is refused: booking deposits run in test mode only")
            }
            Self::NotATestKey => f.write_str("the stored Stripe key is not a test key"),
            Self::Secret(reason) => write!(f, "the Stripe secret is unavailable: {reason}"),
        }
    }
}

/// Whether `raw` is a Stripe test key with one of `test_prefixes`; a live
/// key of the same kind is refused by name.
fn test_key<'a>(
    raw: &'a [u8],
    test_prefixes: &[&str],
    live_prefixes: &[&str],
) -> Result<&'a str, DepositSetupError> {
    let key = std::str::from_utf8(raw)
        .map_err(|_| DepositSetupError::NotATestKey)?
        .trim();
    if live_prefixes.iter().any(|prefix| key.starts_with(prefix)) {
        return Err(DepositSetupError::LiveKeyRefused);
    }
    let printable = key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if !printable || !test_prefixes.iter().any(|prefix| key.starts_with(prefix)) {
        return Err(DepositSetupError::NotATestKey);
    }
    Ok(key)
}

/// A secret (`sk_test_`) or restricted (`rk_test_`) test key.
pub(crate) fn secret_test_key(raw: &[u8]) -> Result<&str, DepositSetupError> {
    test_key(raw, &["sk_test_", "rk_test_"], &["sk_live_", "rk_live_"])
}

/// A publishable test key (`pk_test_`).
pub(crate) fn publishable_test_key(raw: &[u8]) -> Result<&str, DepositSetupError> {
    test_key(raw, &["pk_test_"], &["pk_live_"])
}

/// Reads the owner's publishable test key, which the visitor's browser
/// needs beside the client secret. It is public by design, but kept in
/// custody beside the other two, so one owner act sets up deposits.
pub(crate) fn publishable_key(vault: &Vault) -> Result<String, DepositSetupError> {
    let mut key = None;
    vault
        .inject_secret_at_door(
            STRIPE_PUBLISHABLE_KEY_NAME,
            DEPOSIT_EFFECTOR,
            &mut |raw: &[u8]| {
                key = Some(publishable_test_key(raw).map(str::to_owned));
                Ok(())
            },
        )
        .map_err(|error| DepositSetupError::Secret(error.to_string()))?;
    key.unwrap_or(Err(DepositSetupError::NotATestKey))
}

/// Why one Stripe call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StripeCallError {
    /// The server cannot use Stripe at all.
    Setup(DepositSetupError),
    /// No reply: the network or a timeout. Worth another try.
    Transport(String),
    /// Stripe's own 5xx or 429. Worth another try.
    Unavailable { status: u16, message: String },
    /// Stripe refused the request (4xx): another try answers the same.
    Refused {
        status: u16,
        code: Option<String>,
        message: String,
    },
    /// A reply this code cannot read.
    Malformed(String),
}

impl std::fmt::Display for StripeCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Setup(error) => error.fmt(f),
            Self::Transport(reason) => write!(f, "Stripe could not be reached: {reason}"),
            Self::Unavailable { status, message } => {
                write!(f, "Stripe answered {status}: {message}")
            }
            Self::Refused {
                status,
                code,
                message,
            } => write!(
                f,
                "Stripe refused ({status} {}): {message}",
                code.as_deref().unwrap_or("no code")
            ),
            Self::Malformed(reason) => write!(f, "Stripe's reply is unreadable: {reason}"),
        }
    }
}

impl StripeCallError {
    /// The settle answer for this failure. A setup failure (the key withheld,
    /// missing or not a test key, or a live key refused) made no Stripe call,
    /// and it heals when the owner or the host fixes the key: the move stays
    /// owed and is asked again hourly, never failing for good (Muse Spark
    /// blind review of #8231, 16 Nov).
    fn into_failure(self) -> DepositProviderFailure {
        match self {
            Self::Setup(_) => DepositProviderFailure::Pending(self.to_string()),
            Self::Transport(_) | Self::Unavailable { .. } => {
                DepositProviderFailure::Transient(self.to_string())
            }
            Self::Refused { .. } | Self::Malformed(_) => {
                DepositProviderFailure::Permanent(self.to_string())
            }
        }
    }
}

#[derive(Deserialize)]
struct StripeErrorReply {
    error: StripeErrorBody,
}

#[derive(Deserialize)]
struct StripeErrorBody {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

/// The PaymentIntent fields a deposit reads.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct PaymentIntentView {
    pub id: String,
    pub status: String,
    #[serde(default)]
    pub amount_capturable: u64,
    /// What the payment has captured.
    #[serde(default)]
    pub amount_received: u64,
    pub currency: String,
    pub livemode: bool,
}

/// The Refund fields a deposit reads.
#[derive(Deserialize)]
struct RefundView {
    id: String,
    amount: u64,
    /// `pending`, `requires_action`, `succeeded`, `failed` or `canceled`.
    status: String,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
}

/// One page of a PaymentIntent's refunds.
#[derive(Deserialize)]
struct RefundList {
    data: Vec<RefundView>,
}

impl RefundView {
    /// What the deposit records of this refund: its amount once it
    /// succeeded; pending while Stripe still holds it; a failure for good
    /// once it failed or was cancelled.
    fn settled_amount(&self) -> Result<u64, DepositProviderFailure> {
        match self.status.as_str() {
            "succeeded" => Ok(self.amount),
            "pending" | "requires_action" => Err(DepositProviderFailure::Pending(format!(
                "Stripe holds refund {} {}",
                self.id, self.status
            ))),
            status => Err(DepositProviderFailure::Permanent(format!(
                "Stripe's refund {} is {status}",
                self.id
            ))),
        }
    }
}

/// A created PaymentIntent and the secret the visitor's Stripe.js confirms
/// the card under.
pub(crate) struct CreatedPayment {
    pub id: String,
    pub client_secret: Zeroizing<String>,
}

#[derive(Deserialize)]
struct CreatedPaymentReply {
    id: String,
    client_secret: String,
    livemode: bool,
}

/// One Stripe API origin, used through the owner's custody secret.
pub(crate) struct StripeClient<'v> {
    vault: &'v Vault,
    http: reqwest::blocking::Client,
    base: String,
}

impl<'v> StripeClient<'v> {
    /// A client for `base` (Stripe's origin in service, a loopback fake in
    /// the tests).
    pub(crate) fn new(vault: &'v Vault, base: &str) -> Result<Self, StripeCallError> {
        let http = reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|_| StripeCallError::Transport("the HTTP client is unavailable".to_owned()))?;
        Ok(Self {
            vault,
            http,
            base: base.trim_end_matches('/').to_owned(),
        })
    }

    /// One request with the owner's test key, read inside the custody door.
    fn call(
        &self,
        path: &str,
        form: Option<&[(&str, String)]>,
        idempotency_key: Option<&str>,
    ) -> Result<Zeroizing<Vec<u8>>, StripeCallError> {
        let url = format!("{}{path}", self.base);
        let mut outcome: Option<Result<Zeroizing<Vec<u8>>, StripeCallError>> = None;
        self.vault
            .inject_secret_at_door(
                STRIPE_SECRET_KEY_NAME,
                DEPOSIT_EFFECTOR,
                &mut |raw: &[u8]| {
                    outcome = Some(self.send(&url, raw, form, idempotency_key));
                    Ok(())
                },
            )
            .map_err(|error| {
                StripeCallError::Setup(DepositSetupError::Secret(error.to_string()))
            })?;
        outcome.unwrap_or_else(|| {
            Err(StripeCallError::Setup(DepositSetupError::Secret(
                "the custody door did not run".to_owned(),
            )))
        })
    }

    fn send(
        &self,
        url: &str,
        raw_key: &[u8],
        form: Option<&[(&str, String)]>,
        idempotency_key: Option<&str>,
    ) -> Result<Zeroizing<Vec<u8>>, StripeCallError> {
        let key = secret_test_key(raw_key).map_err(StripeCallError::Setup)?;
        let mut request = match form {
            Some(form) => self.http.post(url).form(form),
            None => self.http.get(url),
        }
        .bearer_auth(key)
        .header("Stripe-Version", STRIPE_API_VERSION);
        if let Some(idempotency_key) = idempotency_key {
            request = request.header("Idempotency-Key", idempotency_key);
        }
        let response = request
            .send()
            .map_err(|error| StripeCallError::Transport(error.without_url().to_string()))?;
        let status = response.status();
        let mut body = Zeroizing::new(Vec::new());
        response
            .take(MAX_STRIPE_REPLY_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|_| StripeCallError::Transport("the reply could not be read".to_owned()))?;
        if body.len() as u64 > MAX_STRIPE_REPLY_BYTES {
            return Err(StripeCallError::Malformed(
                "the reply exceeds its bound".to_owned(),
            ));
        }
        if status.is_success() {
            return Ok(body);
        }
        let reply: Option<StripeErrorReply> = serde_json::from_slice(&body).ok();
        let (code, message) = reply.map_or((None, None), |reply| {
            (reply.error.code, reply.error.message)
        });
        let message = message.unwrap_or_else(|| "no message".to_owned());
        if status.is_server_error() || status.as_u16() == 429 {
            return Err(StripeCallError::Unavailable {
                status: status.as_u16(),
                message,
            });
        }
        Err(StripeCallError::Refused {
            status: status.as_u16(),
            code,
            message,
        })
    }

    /// Creates the deposit's PaymentIntent for `terms`, card only, with
    /// manual capture: the card is authorized now and captured at confirm.
    pub(crate) fn create_deposit_payment(
        &self,
        terms: &DepositTerms,
        idempotency_key: &str,
    ) -> Result<CreatedPayment, StripeCallError> {
        let form = [
            ("amount", terms.amount_minor.to_string()),
            ("currency", terms.currency.clone()),
            ("capture_method", "manual".to_owned()),
            ("payment_method_types[]", "card".to_owned()),
            ("description", "Booking deposit".to_owned()),
        ];
        let body = self.call("/v1/payment_intents", Some(&form), Some(idempotency_key))?;
        let reply: CreatedPaymentReply = serde_json::from_slice(&body)
            .map_err(|_| StripeCallError::Malformed("no PaymentIntent in the reply".to_owned()))?;
        if reply.livemode {
            return Err(StripeCallError::Setup(DepositSetupError::LiveKeyRefused));
        }
        if !stripe_id(&reply.id) {
            return Err(StripeCallError::Malformed(
                "the PaymentIntent id is not an id".to_owned(),
            ));
        }
        Ok(CreatedPayment {
            id: reply.id,
            client_secret: Zeroizing::new(reply.client_secret),
        })
    }

    /// Reads one PaymentIntent.
    pub(crate) fn payment_intent(&self, id: &str) -> Result<PaymentIntentView, StripeCallError> {
        let path = payment_path(id, "")?;
        let body = self.call(&path, None, None)?;
        serde_json::from_slice(&body)
            .map_err(|_| StripeCallError::Malformed("no PaymentIntent in the reply".to_owned()))
    }

    /// The deposit's refund under the settle move's idempotency `key`: the
    /// one already made under it, found by its metadata, or else a new one.
    /// Stripe dedupes a repeated key for a day only, so a refund it holds
    /// pending longer is never made twice.
    fn refund_once(
        &self,
        payment_id: &str,
        amount_minor: u64,
        key: &str,
    ) -> Result<RefundView, StripeCallError> {
        payment_path(payment_id, "")?;
        let listed = self.call(
            &format!("/v1/refunds?payment_intent={payment_id}&limit=100"),
            None,
            None,
        )?;
        let listed: RefundList = serde_json::from_slice(&listed)
            .map_err(|_| StripeCallError::Malformed("no refund list in the reply".to_owned()))?;
        if let Some(made) = listed.data.into_iter().find(|refund| {
            refund.metadata.get(SETTLE_KEY_METADATA).map(String::as_str) == Some(key)
        }) {
            return Ok(made);
        }
        let body = self.call(
            "/v1/refunds",
            Some(&[
                ("payment_intent", payment_id.to_owned()),
                ("amount", amount_minor.to_string()),
                ("reason", "requested_by_customer".to_owned()),
                (SETTLE_KEY_FORM_FIELD, key.to_owned()),
            ]),
            Some(key),
        )?;
        serde_json::from_slice(&body)
            .map_err(|_| StripeCallError::Malformed("no refund in the reply".to_owned()))
    }

    /// Captures `amount_minor` of the authorization; the amount the payment
    /// has captured.
    fn capture(
        &self,
        payment_id: &str,
        amount_minor: u64,
        key: &str,
    ) -> Result<u64, StripeCallError> {
        let body = self.call(
            &payment_path(payment_id, "/capture")?,
            Some(&[("amount_to_capture", amount_minor.to_string())]),
            Some(key),
        )?;
        serde_json::from_slice::<PaymentIntentView>(&body)
            .map(|captured| captured.amount_received)
            .map_err(|_| StripeCallError::Malformed("no PaymentIntent in the reply".to_owned()))
    }

    /// Cancels the payment; nothing is captured.
    fn void(&self, payment_id: &str, key: &str) -> Result<u64, StripeCallError> {
        self.call(
            &payment_path(payment_id, "/cancel")?,
            Some(&[("cancellation_reason", "abandoned".to_owned())]),
            Some(key),
        )
        .map(|_| 0)
    }
}

/// The PaymentIntent states in which a refused capture stands done.
const CAPTURE_DONE: &[&str] = &["succeeded"];

/// The PaymentIntent states in which a refused void stands settled: cancelled,
/// or captured before the void, whose capture the deposit then owes back.
const VOID_DONE: &[&str] = &["canceled", "succeeded"];

impl DepositSettlementPort for StripeClient<'_> {
    fn settle(
        &mut self,
        request: &DepositSettleRequest<'_>,
    ) -> Result<u64, DepositProviderFailure> {
        let id = request.payment_id;
        let key = request.idempotency_key;
        // A capture or cancel that already happened (a lost reply, a
        // dashboard act) is refused by Stripe; the PaymentIntent's own state
        // says whether the move stands done, and what it captured. A void
        // refused because the payment was captured (a capture whose reply was
        // lost) answers that capture, which the deposit then owes back.
        let (moved, done) = match request.movement {
            DepositSettleMove::Refund { amount_minor } => {
                return self
                    .refund_once(id, amount_minor, key)
                    .map_err(StripeCallError::into_failure)?
                    .settled_amount();
            }
            DepositSettleMove::Capture { amount_minor } => {
                (self.capture(id, amount_minor, key), CAPTURE_DONE)
            }
            DepositSettleMove::Void => (self.void(id, key), VOID_DONE),
        };
        match moved {
            Ok(moved) => Ok(moved),
            Err(error @ StripeCallError::Refused { .. }) => match self.payment_intent(id) {
                Ok(intent) if done.contains(&intent.status.as_str()) => Ok(intent.amount_received),
                // The read that would say whether the move stands done failed
                // for now: the row runs again, never failing for good on an
                // outage (Muse review of the money fixes, 15 Nov); a setup
                // failure waits hourly for the key.
                Err(
                    read @ (StripeCallError::Transport(_)
                    | StripeCallError::Unavailable { .. }
                    | StripeCallError::Setup(_)),
                ) => Err(read.into_failure()),
                _ => Err(error.into_failure()),
            },
            Err(error) => Err(error.into_failure()),
        }
    }
}

/// Whether `id` is a Stripe object id: letters, digits and underscores.
pub(crate) fn stripe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_STRIPE_ID_BYTES
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// The API path of one PaymentIntent, refusing an id that could leave it.
fn payment_path(id: &str, suffix: &str) -> Result<String, StripeCallError> {
    if !id.starts_with("pi_") || !stripe_id(id) {
        return Err(StripeCallError::Malformed(
            "the deposit's payment id is not a PaymentIntent id".to_owned(),
        ));
    }
    Ok(format!("/v1/payment_intents/{id}{suffix}"))
}
