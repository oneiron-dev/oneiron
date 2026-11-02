use super::*;
use crate::HandleRetention;
use serde::{Deserialize, Serialize};

/// How the host starts desktop guests. Its bounds are the host's manifest rows.
#[derive(Clone, Debug)]
pub struct DesktopGuest {
    pub runtime: PathBuf,
    pub image: String,
    pub limits: GuestLimits,
    /// The longest `wait_for` one call holds the run for.
    pub wait_cap: Duration,
    /// The press each effect class runs under, from the vault's grants.
    pub policy: SendPolicy,
}

/// Who has a desktop session (CUA-001): its agent, its agent waiting on the
/// person it asked, or a person driving it. `by` is the person's id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Takeover {
    Agent,
    Waiting {
        reason: String,
        asked_at_ms: u64,
    },
    Held {
        by: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        asked: Option<String>,
        taken_at_ms: u64,
        inputs: u64,
    },
}

/// A takeover the desktop's end cut short: still asked, or still held with
/// its inputs so far, when the run's desktop went away. Its receipt keeps
/// this, as a returned takeover's keeps its [`TakeoverRecord`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbandonedTakeover {
    #[serde(flatten)]
    pub state: Takeover,
    pub ended_at_ms: u64,
}

/// One input from the person who holds the desktop, at the pixels of the
/// whole-display screen they were last shown.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PersonInput {
    Click {
        x: u32,
        y: u32,
        #[serde(default)]
        button: Option<String>,
        #[serde(default)]
        count: Option<u32>,
    },
    Type {
        text: String,
    },
    Key {
        key: String,
    },
    Hotkey {
        keys: Vec<String>,
    },
    Scroll {
        x: u32,
        y: u32,
        direction: String,
        #[serde(default)]
        amount: Option<u32>,
    },
}

impl DesktopSession {
    /// The engine selects and proves a backend before attaching the
    /// desktop, as it does for a browser. The answers the session holds are
    /// charged to the host memory floor through `retention` (FIX 11579).
    pub fn attach(
        config: &DesktopGuest,
        transport: SessionTransport,
        retention: Box<dyn HandleRetention>,
    ) -> Result<Self, BrowserError> {
        if transport.manifest.fence_unproven || transport.manifest.fence_proof.is_none() {
            return Err(BrowserError::Unavailable(
                "desktop session fence unproven".to_owned(),
            ));
        }
        let SessionTransport {
            reader,
            writer,
            manifest,
            lease,
        } = transport;
        // The guest's display and accessibility bus come up before its
        // driver answers.
        let mcp = Mcp::attach(reader, writer, Instant::now() + LAUNCH)?;
        let token = session_token();
        Ok(Self {
            mcp,
            guest: lease,
            manifest,
            policy: config.policy.clone(),
            presses: PressBook::new(config.policy.clone()),
            press_holds: super::press_holds::PressHolds::default(),
            unread: None,
            input_sent: false,
            receipts: Vec::new(),
            receipt_seq: 0,
            decider: None,
            field_writer: None,
            provenance: None,
            receipt_sink: None,
            window: None,
            seq: 0,
            captures: Captures::new(&token),
            token,
            media: VecDeque::new(),
            pages: Observations::charged(retention),
            wait_cap: config.wait_cap,
            takeover: Takeover::Agent,
            returned: None,
            switched: None,
            secrets: Secrets::default(),
            typed: HashMap::new(),
            polling: false,
            view: None,
        })
    }

    /// Gives the session the host's secret custody (FIX 8028): the secrets
    /// its reads find from now on become handles bound to its run, and a
    /// type or expect may name them.
    pub fn set_secret_custody(&mut self, custody: Arc<dyn SecretCustody>) {
        self.secrets.install(custody);
    }

    /// Gives the session's batches the host's routine decider.
    pub fn set_decider(&mut self, decider: Box<dyn RoutineDecider>) {
        self.decider = Some(decider);
    }

    /// Gives the session's batches the host's writer of a Fill's text (FIX
    /// 8899): a desktop Fill that reaches generation asks it, as a browser
    /// session's does, under the same strict denial.
    pub fn set_field_writer(&mut self, writer: Box<dyn FieldWriter>) {
        self.field_writer = Some(writer);
    }

    /// Gives the session the host's keeper of receipt screenshots.
    pub fn set_receipt_sink(&mut self, sink: Box<dyn ReceiptEvidenceSink>) {
        self.receipt_sink = Some(sink);
    }

    /// Gives the session the host's live read of the vault's grants: each
    /// classified send reads them again, as a browser session's do (FIX
    /// 4613, 12133).
    pub fn set_press_grants(&mut self, grants: Box<dyn PressGrants>) {
        self.presses.set_live(grants);
    }

    /// Sets the press each effect class runs under, as the vault's grants
    /// stand now: a desktop that outlives one door of its run takes the
    /// next door's policy. The sends a batch press already paid stay paid:
    /// a door that binds the session again never refills them, as a
    /// browser session's stay paid (FIX 4615, 12133).
    pub fn set_policy(&mut self, policy: SendPolicy) {
        self.presses.set_granted(policy);
        self.policy = self.presses.policy();
    }

    /// What the guest's container proved, for the run's receipt.
    #[must_use]
    pub fn manifest(&self) -> &SessionManifest {
        &self.manifest
    }

    /// The PNG bytes of a screenshot this session took, while it holds them.
    #[must_use]
    pub fn image(&self, image: &str) -> Option<&[u8]> {
        self.media
            .iter()
            .rev()
            .find(|held| held.image == image)
            .map(|held| held.png.as_slice())
    }

    /// Every effect this session receipted, in order.
    #[must_use]
    pub fn receipts(&self) -> &[EffectReceipt] {
        &self.receipts
    }

    #[must_use]
    pub fn abandoned(&self) -> bool {
        self.guest.abandoned()
    }

    /// Who has the desktop now.
    #[must_use]
    pub fn takeover(&self) -> &Takeover {
        &self.takeover
    }

    /// Person `by` takes the desktop, asked or not. The caller holds the
    /// session, so the agent's call in flight has ended; its next one
    /// refuses until `by` hands the desktop back. Taking it again is a no-op.
    pub fn take_over(&mut self, by: &str) -> Result<&Takeover, BrowserError> {
        self.guest_up()?;
        let asked = match &self.takeover {
            Takeover::Agent => None,
            Takeover::Waiting { reason, .. } => Some(reason.clone()),
            Takeover::Held { by: holder, .. } if holder == by => return Ok(&self.takeover),
            Takeover::Held { .. } => return Err(BrowserError::TakenOver("held".to_owned())),
        };
        self.takeover = Takeover::Held {
            by: by.to_owned(),
            asked,
            taken_at_ms: now_ms(),
            inputs: 0,
        };
        Ok(&self.takeover)
    }

    /// The whole display as a PNG for the person: unmasked, never held in
    /// the session's images and never a receipt.
    pub fn person_screen(&mut self) -> Result<Vec<u8>, BrowserError> {
        self.guest_up()?;
        self.tool("get_desktop_state", json!({}))?
            .images
            .into_iter()
            .next()
            .ok_or_else(|| {
                BrowserError::Protocol("get_desktop_state sent no screenshot".to_owned())
            })
    }

    /// One input from `by`, who must hold the desktop, at the display's
    /// pixels; it counts toward the takeover's record. No press gates it:
    /// the person's own input is their press.
    pub fn person_input(&mut self, by: &str, input: PersonInput) -> Result<u64, BrowserError> {
        self.guest_up()?;
        match &self.takeover {
            Takeover::Held { by: holder, .. } if holder == by => {}
            Takeover::Held { .. } => return Err(BrowserError::TakenOver("held".to_owned())),
            Takeover::Agent | Takeover::Waiting { .. } => {
                return Err(BrowserError::Input(
                    "take the desktop over first".to_owned(),
                ));
            }
        }
        let desktop = json!({"kind": "desktop", "display_id": "primary"});
        let (name, arguments) = match input {
            PersonInput::Click {
                x,
                y,
                button,
                count,
            } => {
                let mut arguments = json!({"target": desktop, "x": x, "y": y});
                if let Some(button) = button {
                    arguments["button"] = Value::from(button);
                }
                if let Some(count) = count {
                    arguments["count"] = Value::from(count);
                }
                ("click", arguments)
            }
            PersonInput::Type { text } => ("type_text", json!({"target": desktop, "text": text})),
            PersonInput::Key { key } => ("press_key", json!({"target": desktop, "key": key})),
            PersonInput::Hotkey { keys } => ("hotkey", json!({"target": desktop, "keys": keys})),
            PersonInput::Scroll {
                x,
                y,
                direction,
                amount,
            } => {
                let mut arguments =
                    json!({"target": desktop, "x": x, "y": y, "direction": direction});
                if let Some(amount) = amount {
                    arguments["amount"] = Value::from(amount);
                }
                ("scroll", arguments)
            }
        };
        self.input(name, arguments)
            .map_err(|error| refusal(error, None))?;
        let Takeover::Held { inputs, .. } = &mut self.takeover else {
            return Err(BrowserError::GuestLost);
        };
        *inputs += 1;
        Ok(*inputs)
    }

    /// `by` hands the desktop back, from holding it or from the agent's ask
    /// it never took: the agent's next call reads the window in front, and
    /// its next answer carries this record once.
    pub fn hand_back(&mut self, by: &str) -> Result<TakeoverRecord, BrowserError> {
        let returned_at_ms = now_ms();
        let record = match &self.takeover {
            Takeover::Held {
                by: holder,
                asked,
                taken_at_ms,
                inputs,
            } if holder == by => TakeoverRecord {
                by: by.to_owned(),
                asked: asked.clone(),
                taken_at_ms: *taken_at_ms,
                returned_at_ms,
                inputs: *inputs,
                refusal: None,
            },
            Takeover::Held { .. } => return Err(BrowserError::TakenOver("held".to_owned())),
            Takeover::Waiting { reason, .. } => TakeoverRecord {
                by: by.to_owned(),
                asked: Some(reason.clone()),
                taken_at_ms: returned_at_ms,
                returned_at_ms,
                inputs: 0,
                refusal: None,
            },
            Takeover::Agent => {
                return Err(BrowserError::Input("the agent has the desktop".to_owned()));
            }
        };
        self.takeover = Takeover::Agent;
        self.window = None;
        self.switched = None;
        self.returned = Some(record.clone());
        Ok(record)
    }

    /// The takeover that ended since the agent's last answer, once.
    pub fn take_returned(&mut self) -> Option<TakeoverRecord> {
        self.returned.take()
    }

    /// The agent's move to another window since its last answer, once: an
    /// act opened a window in front, or the window it read was gone and the
    /// session gave way to the one in front. The host's door names it on
    /// that answer as `switched`.
    pub fn take_switched(&mut self) -> Option<WindowSwitch> {
        self.switched.take()
    }

    /// Ends a takeover still asked or held as the desktop goes away, with
    /// what it held so far; `None` while the agent has the desktop.
    pub fn abandon_takeover(&mut self) -> Option<AbandonedTakeover> {
        match std::mem::replace(&mut self.takeover, Takeover::Agent) {
            Takeover::Agent => None,
            state => Some(AbandonedTakeover {
                state,
                ended_at_ms: now_ms(),
            }),
        }
    }
}
