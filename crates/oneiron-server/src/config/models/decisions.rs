//! `[models.decisions]`: the host's own typed questions and the System One
//! seat on its decision ladder.
//!
//! The ladder is built once at serve start from what `[models]` already
//! binds: the rule table first, the house model's decision read
//! (`[models.decision_read]`) on the escalation rung, and the vault owner's
//! ask queue last. These rows add the System One seat and the big model, and
//! word the host's own questions; a question with no wording is not asked, and its hook stays
//! unbound. No question text lives in the server.
use std::time::Duration;

use oneiron::llm::manifest::ModelRole;
use serde::Deserialize;

/// A seat pick's anytime budget when the file names none.
const DEFAULT_SEAT_BUDGET_MS: u64 = 2_000;
/// One image pick's anytime budget when the file names none.
const DEFAULT_IMAGE_PICK_BUDGET_MS: u64 = 1_000;
/// The longest booking free text the parse reads when the file names none:
/// the engine's own ceiling.
const DEFAULT_BOOKING_PARSE_INPUT_BYTES: usize = 4096;
/// One registration's whole slate-drafting budget when the file names none.
const DEFAULT_CONNECTOR_SLATE_BUDGET_MS: u64 = 30_000;
/// One imported topic's sensitivity read budget when the file names none.
const DEFAULT_IMPORT_AUDIENCE_BUDGET_MS: u64 = 30_000;

/// `[models.decisions]` as written.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DecisionsFile {
    /// The write gate's auto check: allow or hold.
    auto_check: Option<String>,
    seat: Option<SeatPickFile>,
    system_one: Option<SystemOneFile>,
    big: Option<BigFile>,
    image_pick: Option<ImagePickFile>,
    booking_parse: Option<BookingParseFile>,
    connector_slate: Option<ConnectorSlateFile>,
    import_audience: Option<ImportAudienceFile>,
}

/// `[models.decisions.import_audience]`: the two questions an imported topic is asked
/// with (OF-492). The sensitivity read goes up to the Big rung; a sensitive or unsure
/// topic asks the owner who may see its later imports. Without it, no topic is asked
/// and every import stays private.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportAudienceFile {
    /// "Is this imported topic sensitive?"
    sensitive_wording: String,
    /// "Who may see what later imports say about this topic?"
    audience_wording: String,
    budget_ms: Option<u64>,
}

/// `[models.decisions.connector_slate]`: the per-row question a connector
/// registration's grant slate is drafted with (OF-189), asked up to the Big
/// rung. Without it, the rule rung drafts every row from the owner's past
/// rulings.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectorSlateFile {
    /// "What should this connector tool's setting be?"
    wording: String,
    budget_ms: Option<u64>,
}

/// `[models.decisions.booking_parse]`: the cheap seat a booking page's free
/// text is parsed on (ONE-1816), through a seat `[models]` already fills.
/// Without it, free text is refused.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct BookingParseFile {
    /// The seat whose model parses.
    role: ModelRole,
    max_input_bytes: Option<usize>,
}

/// `[models.decisions.seat]`: the code-mode seat pick.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct SeatPickFile {
    /// The model-description facet a run's candidates are described under.
    facet: String,
    /// Which candidate the seat pins.
    model: String,
    /// Which of the chosen model's efforts it runs at.
    effort: String,
    budget_ms: Option<u64>,
}

/// `[models.decisions.image_pick]`: the fast per-image pick (OF-329), asked
/// for each image a hydrate would serve in full to a model that reads images.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImagePickFile {
    /// "Does this task need this image in full?"
    wording: String,
    budget_ms: Option<u64>,
}

/// `[models.decisions.system_one]`: the remote System One seat.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct SystemOneFile {
    /// Ends `/v1/systemone`; HTTPS, or HTTP on loopback.
    endpoint: String,
    /// The environment variable holding the seat's bearer token.
    key_env: String,
    model: String,
    version: String,
    /// Owner opt-in for unit state to leave a non-hosted vault.
    remote_opt_in: Option<bool>,
    budget_units: Option<u64>,
}

/// `[models.decisions.big]`: the big model on the Big rung, through a seat
/// `[models]` already fills.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct BigFile {
    /// The seat whose model answers; the generative reasoner when unset.
    role: Option<ModelRole>,
    /// The revision the rung's pin names.
    version: String,
    /// The host's framing of every question: the call's system message.
    wording: String,
    /// How the model is asked to reply: `json` (the default) or `lines`.
    reply: Option<BigReply>,
    budget_units: Option<u64>,
}

/// How the big model writes its answer and its probability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BigReply {
    /// One JSON object: `{"answer", "probability"}`.
    Json,
    /// Two lines: `answer: ...` and `probability: ...`.
    Lines,
}

/// The resolved section.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DecisionsSettings {
    /// The auto check's wording; `None` leaves the checker unbound.
    pub auto_check: Option<String>,
    pub seat: Option<SeatPickSettings>,
    pub system_one: Option<SystemOneSettings>,
    pub big: Option<BigSettings>,
    pub image_pick: Option<ImagePickSettings>,
    pub booking_parse: Option<BookingParseSettings>,
    pub connector_slate: Option<ConnectorSlateSettings>,
    pub import_audience: Option<ImportAudienceSettings>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportAudienceSettings {
    pub sensitive_wording: String,
    pub audience_wording: String,
    /// One topic's sensitivity read budget; a read past it asks the owner.
    pub budget: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectorSlateSettings {
    pub wording: String,
    /// One registration's whole drafting budget; a row past it keeps its
    /// rule draft.
    pub budget: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BookingParseSettings {
    pub role: ModelRole,
    /// The longest free text one parse reads, at most 4096 bytes.
    pub max_input_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImagePickSettings {
    pub wording: String,
    /// Each image's anytime budget.
    pub budget: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BigSettings {
    pub role: ModelRole,
    pub version: String,
    pub wording: String,
    pub reply: BigReply,
    /// The rung's own meter; the raw routes' units when unset.
    pub budget_units: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeatPickSettings {
    pub facet: String,
    pub model_wording: String,
    pub effort_wording: String,
    pub budget: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemOneSettings {
    pub endpoint: String,
    pub key_env: String,
    pub model: String,
    pub version: String,
    pub remote_opt_in: bool,
    /// The seat's own meter; the raw routes' units when unset.
    pub budget_units: Option<u64>,
}

impl DecisionsFile {
    pub(super) fn resolve(self) -> anyhow::Result<DecisionsSettings> {
        let filled = |field: &str, value: String| {
            if value.trim().is_empty() {
                anyhow::bail!("models.decisions.{field} must not be blank");
            }
            Ok(value)
        };
        let auto_check = self
            .auto_check
            .map(|wording| filled("auto_check", wording))
            .transpose()?;
        let seat = self
            .seat
            .map(|seat| -> anyhow::Result<_> {
                Ok(SeatPickSettings {
                    facet: filled("seat.facet", seat.facet)?,
                    model_wording: filled("seat.model", seat.model)?,
                    effort_wording: filled("seat.effort", seat.effort)?,
                    budget: Duration::from_millis(
                        match seat.budget_ms.unwrap_or(DEFAULT_SEAT_BUDGET_MS) {
                            0 => anyhow::bail!("models.decisions.seat.budget_ms must be above 0"),
                            ms => ms,
                        },
                    ),
                })
            })
            .transpose()?;
        let system_one = self
            .system_one
            .map(|seat| -> anyhow::Result<_> {
                if seat.budget_units == Some(0) {
                    anyhow::bail!("models budget units must be greater than zero");
                }
                Ok(SystemOneSettings {
                    endpoint: filled("system_one.endpoint", seat.endpoint)?,
                    key_env: filled("system_one.key_env", seat.key_env)?,
                    model: filled("system_one.model", seat.model)?,
                    version: filled("system_one.version", seat.version)?,
                    remote_opt_in: seat.remote_opt_in.unwrap_or(false),
                    budget_units: seat.budget_units,
                })
            })
            .transpose()?;
        let big = self
            .big
            .map(|big| -> anyhow::Result<_> {
                if big.budget_units == Some(0) {
                    anyhow::bail!("models budget units must be greater than zero");
                }
                Ok(BigSettings {
                    role: big.role.unwrap_or(ModelRole::GenerativeReasoner),
                    version: filled("big.version", big.version)?,
                    wording: filled("big.wording", big.wording)?,
                    reply: big.reply.unwrap_or(BigReply::Json),
                    budget_units: big.budget_units,
                })
            })
            .transpose()?;
        let image_pick = self
            .image_pick
            .map(|pick| -> anyhow::Result<_> {
                Ok(ImagePickSettings {
                    wording: filled("image_pick.wording", pick.wording)?,
                    budget: Duration::from_millis(
                        match pick.budget_ms.unwrap_or(DEFAULT_IMAGE_PICK_BUDGET_MS) {
                            0 => anyhow::bail!(
                                "models.decisions.image_pick.budget_ms must be above 0"
                            ),
                            ms => ms,
                        },
                    ),
                })
            })
            .transpose()?;
        let booking_parse = self
            .booking_parse
            .map(|parse| -> anyhow::Result<_> {
                Ok(BookingParseSettings {
                    role: parse.role,
                    max_input_bytes: match parse
                        .max_input_bytes
                        .unwrap_or(DEFAULT_BOOKING_PARSE_INPUT_BYTES)
                    {
                        bytes @ 1..=DEFAULT_BOOKING_PARSE_INPUT_BYTES => bytes,
                        _ => anyhow::bail!(
                            "models.decisions.booking_parse.max_input_bytes must be within 1..=4096"
                        ),
                    },
                })
            })
            .transpose()?;
        let connector_slate = self
            .connector_slate
            .map(|slate| -> anyhow::Result<_> {
                Ok(ConnectorSlateSettings {
                    wording: filled("connector_slate.wording", slate.wording)?,
                    budget: Duration::from_millis(
                        match slate.budget_ms.unwrap_or(DEFAULT_CONNECTOR_SLATE_BUDGET_MS) {
                            0 => anyhow::bail!(
                                "models.decisions.connector_slate.budget_ms must be above 0"
                            ),
                            ms => ms,
                        },
                    ),
                })
            })
            .transpose()?;
        let import_audience = self
            .import_audience
            .map(|audience| -> anyhow::Result<_> {
                Ok(ImportAudienceSettings {
                    sensitive_wording: filled(
                        "import_audience.sensitive_wording",
                        audience.sensitive_wording,
                    )?,
                    audience_wording: filled(
                        "import_audience.audience_wording",
                        audience.audience_wording,
                    )?,
                    budget: Duration::from_millis(
                        match audience
                            .budget_ms
                            .unwrap_or(DEFAULT_IMPORT_AUDIENCE_BUDGET_MS)
                        {
                            0 => anyhow::bail!(
                                "models.decisions.import_audience.budget_ms must be above 0"
                            ),
                            ms => ms,
                        },
                    ),
                })
            })
            .transpose()?;
        Ok(DecisionsSettings {
            auto_check,
            seat,
            system_one,
            big,
            image_pick,
            booking_parse,
            connector_slate,
            import_audience,
        })
    }
}
