//! The guided setup as GenUI cards (OF-378), composed from the existing
//! closed atom kit: a checklist of accounts and connections, one permission
//! review per connection with an allow toggle per permission (like an app
//! install), the risks in plain words, and each connection's check beside
//! its Gate receipts. Every node carries fallback text, a surface without an
//! atom lowers it to that text, and [`PackSetupView::text`] is the whole
//! setup for a surface with no cards at all.
//!
//! A credential is never typed into a card: its button asks the host to open
//! the owner secrets form, the value goes to the secrets door, and
//! `secret_stored` pins the record it made. Toggles change card `$state`
//! only; the host validates an action event through the lens mediation frame
//! before it reads the toggles back with [`PackSetupView::card_action`].

use super::invalid;
use super::setup::{PackSetupConnection, PackSetupRisk};
use super::setup_session::{
    PackSetupAnswer, PackSetupCheck, PackSetupConnectionState, PackSetupView,
};
use super::PackInstallStatus;
use crate::error::Result;
use crate::lens::{
    ButtonControl, CollectionAtom, GeneratedLens, GeneratedUiActionDeclaration,
    GeneratedUiActionTier, GeneratedUiCard, GeneratedUiStateSnapshot, LedgerCell, LedgerRowAtom,
    LensAtom, LensAtomId, LensNode, LensRenderId, LensStatus, LensText, LensTextSpan,
    MetaLineAtom, ReceiptAtom, SealAtom, SealLevel, SectionAtom, SelfUiAction,
    SelfUiActionId, SelfUiBindableProperty, SelfUiBinding, SelfUiControl, SelfUiControlId,
    SelfUiStateKey, SelfUiStateValue, StatusDotAtom, TextBlockAtom, ToggleControl,
};

/// Lens text stays under the kit's own bound.
const MAX_CARD_TEXT_BYTES: usize = 16 * 1024 - 1;

/// What one card action asks the host to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackSetupCardAction {
    /// Hand this answer to `answer_pack_setup`.
    Answer(PackSetupAnswer),
    /// Run the connection's check.
    Verify { connection: String },
    /// Open the owner secrets form for this name, bound for read to this
    /// effector. The value goes to the secrets door, never to the card.
    StoreSecret {
        connection: String,
        secret: String,
        effector: String,
    },
}

impl PackSetupView {
    /// The setup's cards: checklist, one review per connection, risks, and
    /// checks with receipts.
    pub fn cards(&self) -> Result<Vec<GeneratedUiCard>> {
        let mut cards = vec![self.checklist_card()?];
        for (index, (connection, state)) in self
            .setup
            .connections
            .iter()
            .zip(&self.connections)
            .enumerate()
        {
            cards.push(self.review_card(index, connection, state)?);
        }
        cards.push(self.risks_card()?);
        cards.push(self.checks_card()?);
        Ok(cards)
    }

    /// Reads one card action back into what the host does next. The toggles
    /// in `state` are the owner's choices on the review card.
    pub fn card_action(
        &self,
        action_id: &str,
        state: &GeneratedUiStateSnapshot,
    ) -> Result<PackSetupCardAction> {
        let unknown = || invalid("unknown setup card action");
        let (kind, rest) = action_id.split_once('.').ok_or_else(unknown)?;
        let mut parts = rest.split('.');
        let index = position(parts.next(), 'c').ok_or_else(unknown)?;
        let connection = self.setup.connections.get(index).ok_or_else(unknown)?;
        match kind {
            "grant" => {
                let mut permissions = Vec::new();
                for (permission_index, permission) in connection.permissions.iter().enumerate() {
                    match state.get(&SelfUiStateKey::new(allow_key(index, permission_index))?) {
                        Some(SelfUiStateValue::Bool(true)) => {
                            permissions.push(permission.id.clone());
                        }
                        Some(SelfUiStateValue::Bool(false)) | None => {}
                        Some(_) => return Err(invalid("an allow toggle holds a non-toggle value")),
                    }
                }
                Ok(PackSetupCardAction::Answer(PackSetupAnswer::Allow {
                    connection: connection.id.clone(),
                    permissions,
                }))
            }
            "verify" => Ok(PackSetupCardAction::Verify {
                connection: connection.id.clone(),
            }),
            "secret" => {
                let secret = position(parts.next(), 's')
                    .and_then(|secret| connection.secrets.get(secret))
                    .ok_or_else(unknown)?;
                Ok(PackSetupCardAction::StoreSecret {
                    connection: connection.id.clone(),
                    secret: secret.name.clone(),
                    effector: secret.effector.clone(),
                })
            }
            "allow" => Err(invalid("an allow toggle changes card state only")),
            _ => Err(unknown()),
        }
    }

    /// The whole setup as plain text.
    #[must_use]
    pub fn text(&self) -> String {
        let mut out = format!(
            "# Set up {} {}\n\n{}\n",
            self.pack_name,
            self.version,
            status_line(self.status)
        );
        if !self.setup.accounts.is_empty() {
            out.push_str("\n## Accounts you need\n");
            for account in &self.setup.accounts {
                out.push_str(&format!("- {}", account.label));
                if let Some(link) = &account.sign_up {
                    out.push_str(&format!(" (sign up at {link})"));
                }
                if let Some(note) = &account.note {
                    out.push_str(&format!(". {note}"));
                }
                out.push('\n');
            }
        }
        for (connection, state) in self.setup.connections.iter().zip(&self.connections) {
            out.push_str(&format!(
                "\n## {} ({})\nNext: {}\n\nPermissions it asks for:\n",
                connection.label,
                connection.auth.label(),
                next_step(connection, state)
            ));
            for (permission, granted) in connection.permissions.iter().zip(&state.permissions) {
                out.push_str(&format!(
                    "- [{}] {} ({} risk{}). It can {}. What could go wrong: {}\n",
                    if granted.granted { "allowed" } else { "not allowed" },
                    permission.scope.as_deref().unwrap_or(&permission.id),
                    permission.level.as_str(),
                    if permission.optional { ", optional" } else { "" },
                    lowercase_first(&permission.what),
                    permission.risk
                ));
            }
            if !connection.secrets.is_empty() {
                out.push_str(
                    "\nCredentials. Store each through the owner secrets form, never in chat:\n",
                );
                for (secret, stored) in connection.secrets.iter().zip(&state.secrets) {
                    out.push_str(&format!(
                        "- {} under the name {}, bound for read to {} ({})",
                        secret.label,
                        secret.name,
                        secret.effector,
                        if stored.stored { "stored" } else { "missing" }
                    ));
                    if let Some(hint) = &secret.hint {
                        out.push_str(&format!(". {hint}"));
                    }
                    out.push('\n');
                }
            }
            out.push_str(&format!("\nCheck: {}\n", check_line(&state.check)));
        }
        out.push_str("\n## What could go wrong\n");
        for line in self.risk_lines() {
            out.push_str(&format!("- {line}\n"));
        }
        out.push_str(&format!("\n## How to set it up\n\n{}\n", self.instructions));
        out
    }

    fn checklist_card(&self) -> Result<GeneratedUiCard> {
        let title = format!("Set up {}", self.pack_name);
        let mut root = sheet("checklist", &title, Vec::new(), &title)?;
        root.children.push(text_block(
            "checklist-status",
            &format!("{} {}. {}", self.pack_name, self.version, status_line(self.status)),
        )?);
        if !self.setup.accounts.is_empty() {
            let mut rows = Vec::new();
            let mut fallback = String::from("Accounts you need:");
            for account in &self.setup.accounts {
                let mut serving = self
                    .setup
                    .connections
                    .iter()
                    .zip(&self.connections)
                    .filter(|(connection, _)| {
                        connection.account.as_deref() == Some(account.id.as_str())
                    })
                    .peekable();
                let ready = serving.peek().is_some() && serving.all(|(_, state)| state.ready);
                let sign_up = account.sign_up.as_deref().unwrap_or("Use one you already hold");
                rows.push(LedgerRowAtom {
                    cells: vec![cell("Account", &account.label)?, cell("Sign up", sign_up)?],
                    status: Some(dot(
                        if ready { LensStatus::Complete } else { LensStatus::Proposed },
                        if ready { "Connected" } else { "Needed" },
                    )?),
                    seal: None,
                });
                fallback.push_str(&format!(" {} ({sign_up});", account.label));
            }
            root.children
                .push(sheet("checklist-accounts", "Accounts you need", rows, &fallback)?);
        }
        let mut rows = Vec::new();
        let mut fallback = String::from("Connections:");
        for (connection, state) in self.setup.connections.iter().zip(&self.connections) {
            let next = next_step(connection, state);
            rows.push(LedgerRowAtom {
                cells: vec![
                    cell("Connection", &connection.label)?,
                    cell("Sign-in", connection.auth.label())?,
                    cell("Next", &next)?,
                ],
                status: Some(dot(connection_status(state), &next)?),
                seal: None,
            });
            fallback.push_str(&format!(" {}: {next};", connection.label));
        }
        if !rows.is_empty() {
            root.children
                .push(sheet("checklist-connections", "Connections", rows, &fallback)?);
        }
        let lines = self
            .instructions
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(lens_text)
            .collect::<Result<Vec<_>>>()?;
        root.children.push(LensNode::with_fallback_text(
            atom_id("checklist-instructions")?,
            LensAtom::DossierSection(SectionAtom {
                title: lens_text("How to set it up")?,
                lines,
            }),
            lens_text(&self.instructions)?,
        ));
        card(self, "checklist", root, Vec::new(), GeneratedUiStateSnapshot::default())
    }

    fn review_card(
        &self,
        index: usize,
        connection: &PackSetupConnection,
        state: &PackSetupConnectionState,
    ) -> Result<GeneratedUiCard> {
        let title = format!("{} wants to connect {}", self.pack_name, connection.label);
        let mut rows = Vec::new();
        for (permission, granted) in connection.permissions.iter().zip(&state.permissions) {
            rows.push(LedgerRowAtom {
                cells: vec![
                    cell(
                        "Permission",
                        permission.scope.as_deref().unwrap_or(&permission.id),
                    )?,
                    cell("What it can do", &permission.what)?,
                    cell(
                        "Risk",
                        &format!("{} risk. {}", permission.level.as_str(), permission.risk),
                    )?,
                ],
                status: Some(dot(
                    if granted.granted { LensStatus::Approved } else { LensStatus::Proposed },
                    if granted.granted {
                        "Allowed"
                    } else if permission.optional {
                        "Optional"
                    } else {
                        "Required"
                    },
                )?),
                seal: None,
            });
        }
        let mut root = sheet(&format!("review-c{index}"), &title, rows, &title)?;
        let mut sign_in = format!("Signs in with: {}.", connection.auth.label());
        if let Some(account) = connection
            .account
            .as_deref()
            .and_then(|id| self.setup.accounts.iter().find(|account| account.id == id))
        {
            sign_in.push_str(&format!(" Account: {}.", account.label));
        }
        root.children
            .push(text_block(&format!("review-c{index}-sign-in"), &sign_in)?);
        let mut actions = Vec::new();
        let mut values = Vec::new();
        for (permission_index, (permission, granted)) in connection
            .permissions
            .iter()
            .zip(&state.permissions)
            .enumerate()
        {
            let id = allow_key(index, permission_index);
            let checked = granted.granted || !permission.optional;
            let mut node = control(
                &id,
                SelfUiControl::Toggle(ToggleControl {
                    id: SelfUiControlId::new(id.clone())?,
                    label: lens_text(format!("Allow: {}", permission.what))?,
                    checked,
                    action: action(&id)?,
                }),
                &format!(
                    "Allow {}: {}",
                    permission.scope.as_deref().unwrap_or(&permission.id),
                    permission.what
                ),
            )?;
            node.state_bindings.push(SelfUiBinding {
                state_key: SelfUiStateKey::new(id.clone())?,
                property: SelfUiBindableProperty::Checked,
            });
            root.children.push(node);
            actions.push(declare(&id, GeneratedUiActionTier::Local)?);
            values.push((SelfUiStateKey::new(id)?, SelfUiStateValue::Bool(checked)));
        }
        for (secret_index, (secret, stored)) in connection
            .secrets
            .iter()
            .zip(&state.secrets)
            .enumerate()
        {
            let id = format!("secret.c{index}.s{secret_index}");
            let label = if stored.stored {
                format!("Replace {} in the secrets form", secret.label)
            } else {
                format!("Store {} in the secrets form", secret.label)
            };
            let mut fallback = format!(
                "Store {} through the owner secrets form under the name {}, bound for read to {}. Never paste it into chat.",
                secret.label, secret.name, secret.effector
            );
            if let Some(hint) = &secret.hint {
                fallback.push_str(&format!(" {hint}"));
            }
            root.children.push(button(&id, &label, &fallback)?);
            actions.push(declare(&id, GeneratedUiActionTier::DeterministicTool)?);
        }
        let grant = format!("grant.c{index}");
        root.children.push(button(
            &grant,
            "Allow selected permissions",
            "Allow the permissions you ticked; each one gets a Gate receipt.",
        )?);
        actions.push(declare(&grant, GeneratedUiActionTier::DeterministicTool)?);
        let verify = format!("verify.c{index}");
        root.children.push(button(
            &verify,
            "Check the connection",
            "Check the connection with the provider before the pack uses it.",
        )?);
        actions.push(declare(&verify, GeneratedUiActionTier::DeterministicTool)?);
        card(
            self,
            &format!("c{index}"),
            root,
            actions,
            values.into_iter().collect(),
        )
    }

    fn risks_card(&self) -> Result<GeneratedUiCard> {
        let lines = self
            .risk_lines()
            .into_iter()
            .map(lens_text)
            .collect::<Result<Vec<_>>>()?;
        let fallback = self.risk_lines().join(" ");
        let root = LensNode::with_fallback_text(
            atom_id("risks")?,
            LensAtom::Charter(SectionAtom {
                title: lens_text("What could go wrong")?,
                lines,
            }),
            lens_text(fallback)?,
        );
        card(self, "risks", root, Vec::new(), GeneratedUiStateSnapshot::default())
    }

    fn checks_card(&self) -> Result<GeneratedUiCard> {
        let mut rows = Vec::new();
        let mut fallback = String::from("Connection checks:");
        for (connection, state) in self.setup.connections.iter().zip(&self.connections) {
            let account = match &state.check {
                PackSetupCheck::Verified { account, .. } => account.clone(),
                _ => "Not checked".to_owned(),
            };
            let result = check_line(&state.check);
            rows.push(LedgerRowAtom {
                cells: vec![
                    cell("Connection", &connection.label)?,
                    cell("Account", &account)?,
                    cell("Result", &result)?,
                ],
                status: Some(dot(check_status(&state.check), &result)?),
                seal: None,
            });
            fallback.push_str(&format!(" {}: {result};", connection.label));
        }
        let mut root = sheet("checks", "Connection checks", rows, &fallback)?;
        for (index, (connection, state)) in self
            .setup
            .connections
            .iter()
            .zip(&self.connections)
            .enumerate()
        {
            let mut lines = Vec::new();
            for granted in state.permissions.iter().filter(|permission| permission.granted) {
                lines.push(MetaLineAtom {
                    label: lens_text(&granted.id)?,
                    value: lens_text(format!(
                        "allowed, Gate decision {}",
                        granted.decision_id.as_deref().unwrap_or("unknown")
                    ))?,
                });
            }
            if lines.is_empty() {
                continue;
            }
            let title = format!("Grant receipts: {}", connection.label);
            root.children.push(LensNode::with_fallback_text(
                atom_id(&format!("checks-receipts-c{index}"))?,
                LensAtom::Receipt(ReceiptAtom {
                    title: lens_text(&title)?,
                    lines,
                    seal: Some(SealAtom {
                        level: SealLevel::Authority,
                        label: lens_text("Gate receipt")?,
                    }),
                }),
                lens_text(title)?,
            ));
        }
        card(self, "checks", root, Vec::new(), GeneratedUiStateSnapshot::default())
    }

    /// Every risk in plain words, the highest first, then every power the
    /// pack asks for that its setup does not explain.
    fn risk_lines(&self) -> Vec<String> {
        let mut risks: Vec<(PackSetupRisk, String)> = Vec::new();
        for connection in &self.setup.connections {
            for permission in &connection.permissions {
                risks.push((
                    permission.level,
                    format!(
                        "{} risk. {} can {}. {}",
                        capitalized(permission.level.as_str()),
                        connection.label,
                        lowercase_first(&permission.what),
                        permission.risk
                    ),
                ));
            }
        }
        risks.sort_by_key(|(level, _)| std::cmp::Reverse(*level));
        let mut lines: Vec<String> = risks.into_iter().map(|(_, line)| line).collect();
        for grant in &self.permissions.grants {
            if self.setup.connections_for_grant(grant).next().is_none() {
                lines.push(format!(
                    "Unexplained. The pack asks for {grant} and its setup does not say why."
                ));
            }
        }
        let also = [
            ("Wakes on", &self.permissions.wakes),
            ("Hooks", &self.permissions.hooks),
            ("Organs", &self.permissions.organs),
            ("Board verbs", &self.permissions.section_verbs),
        ];
        for (what, powers) in also {
            if !powers.is_empty() {
                lines.push(format!("It also asks for {what}: {}.", powers.join(", ")));
            }
        }
        for skill in &self.permissions.bundled_skills {
            let needs: Vec<String> = [
                ("programs", &skill.bins),
                ("environment", &skill.env),
                ("MCP servers", &skill.mcp),
                ("tools", &skill.allowed_tools),
            ]
            .into_iter()
            .filter(|(_, items)| !items.is_empty())
            .map(|(what, items)| format!("{what} {}", items.join(", ")))
            .collect();
            if !needs.is_empty() {
                lines.push(format!(
                    "Its skill {} needs {}.",
                    skill.skill_id,
                    needs.join("; ")
                ));
            }
        }
        if lines.is_empty() {
            lines.push("Nothing this pack asks for carries a declared risk.".to_owned());
        }
        lines
    }
}

fn card(
    view: &PackSetupView,
    name: &str,
    root: LensNode,
    actions: Vec<GeneratedUiActionDeclaration>,
    state: GeneratedUiStateSnapshot,
) -> Result<GeneratedUiCard> {
    GeneratedUiCard::interactive(
        LensRenderId::new(format!("pack-setup.{}.{name}", view.session_id))?,
        GeneratedLens::new(root)?,
        actions,
        state,
    )
}

fn sheet(id: &str, title: &str, rows: Vec<LedgerRowAtom>, fallback: &str) -> Result<LensNode> {
    Ok(LensNode::with_fallback_text(
        atom_id(id)?,
        LensAtom::Sheet(CollectionAtom {
            title: lens_text(title)?,
            rows,
        }),
        lens_text(fallback)?,
    ))
}

fn text_block(id: &str, text: &str) -> Result<LensNode> {
    Ok(LensNode::with_fallback_text(
        atom_id(id)?,
        LensAtom::TextBlock(TextBlockAtom {
            spans: vec![LensTextSpan::Literal(lens_text(text)?)],
        }),
        lens_text(text)?,
    ))
}

fn control(id: &str, control: SelfUiControl, fallback: &str) -> Result<LensNode> {
    Ok(LensNode::with_fallback_text(
        atom_id(id)?,
        LensAtom::SelfUi(control),
        lens_text(fallback)?,
    ))
}

fn button(id: &str, label: &str, fallback: &str) -> Result<LensNode> {
    control(
        id,
        SelfUiControl::Button(ButtonControl {
            id: SelfUiControlId::new(id)?,
            label: lens_text(label)?,
            action: action(id)?,
        }),
        fallback,
    )
}

fn action(id: &str) -> Result<SelfUiAction> {
    Ok(SelfUiAction {
        command: SelfUiActionId::new(id)?,
        args: Vec::new(),
    })
}

fn declare(id: &str, tier: GeneratedUiActionTier) -> Result<GeneratedUiActionDeclaration> {
    Ok(GeneratedUiActionDeclaration {
        element_id: atom_id(id)?,
        action_id: SelfUiActionId::new(id)?,
        tier,
        action: action(id)?,
    })
}

fn cell(label: &str, value: &str) -> Result<LedgerCell> {
    Ok(LedgerCell {
        label: lens_text(label)?,
        value: lens_text(value)?,
    })
}

fn dot(status: LensStatus, label: &str) -> Result<StatusDotAtom> {
    Ok(StatusDotAtom {
        status,
        label: Some(lens_text(label)?),
    })
}

fn atom_id(id: &str) -> Result<LensAtomId> {
    LensAtomId::new(id)
}

/// Bounded, never blank: a node's fallback text is required.
fn lens_text(value: impl AsRef<str>) -> Result<LensText> {
    let value = value.as_ref().trim();
    if value.is_empty() {
        return LensText::new("none");
    }
    let mut cut = value.len().min(MAX_CARD_TEXT_BYTES);
    while !value.is_char_boundary(cut) {
        cut -= 1;
    }
    LensText::new(&value[..cut])
}

fn allow_key(connection: usize, permission: usize) -> String {
    format!("allow.c{connection}.p{permission}")
}

/// `c3` read as 3, for the given leading letter.
fn position(part: Option<&str>, letter: char) -> Option<usize> {
    part?.strip_prefix(letter)?.parse().ok()
}

fn status_line(status: PackInstallStatus) -> &'static str {
    match status {
        PackInstallStatus::Active => "Installed and active.",
        PackInstallStatus::Candidate => {
            "Not active yet: it waits for its qualification. You can set it up now."
        }
    }
}

fn next_step(connection: &PackSetupConnection, state: &PackSetupConnectionState) -> String {
    let allowed = connection.required().all(|required| {
        state
            .permissions
            .iter()
            .any(|permission| permission.id == required.id && permission.granted)
    });
    if !allowed {
        return "Review and allow its permissions".to_owned();
    }
    if !state.secrets.iter().all(|secret| secret.stored) {
        return "Store its credentials in the secrets form".to_owned();
    }
    match &state.check {
        PackSetupCheck::Unchecked => "Check the connection".to_owned(),
        PackSetupCheck::Verified { .. } => "Ready".to_owned(),
        PackSetupCheck::Failed { reason, .. } => format!("Fix it and check again: {reason}"),
        PackSetupCheck::Stale { .. } => "Something changed since its check; check it again".to_owned(),
    }
}

fn connection_status(state: &PackSetupConnectionState) -> LensStatus {
    match &state.check {
        _ if state.ready => LensStatus::Complete,
        PackSetupCheck::Failed { .. } => LensStatus::Rejected,
        PackSetupCheck::Stale { .. } => LensStatus::Stale,
        _ if state.permissions.iter().any(|permission| permission.granted)
            || state.secrets.iter().any(|secret| secret.stored) =>
        {
            LensStatus::Running
        }
        _ => LensStatus::Proposed,
    }
}

fn check_status(check: &PackSetupCheck) -> LensStatus {
    match check {
        PackSetupCheck::Unchecked => LensStatus::Missing,
        PackSetupCheck::Verified { .. } => LensStatus::Complete,
        PackSetupCheck::Failed { .. } => LensStatus::Rejected,
        PackSetupCheck::Stale { .. } => LensStatus::Stale,
    }
}

fn check_line(check: &PackSetupCheck) -> String {
    match check {
        PackSetupCheck::Unchecked => "not checked yet".to_owned(),
        PackSetupCheck::Verified { account, .. } => format!("verified as {account}"),
        PackSetupCheck::Failed { reason, .. } => format!("failed: {reason}"),
        PackSetupCheck::Stale { .. } => "stale: something changed since its check".to_owned(),
    }
}

fn capitalized(word: &str) -> String {
    let mut chars = word.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

fn lowercase_first(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_lowercase().chain(chars).collect()
    })
}
