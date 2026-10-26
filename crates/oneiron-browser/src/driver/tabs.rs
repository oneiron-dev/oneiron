use super::*;

impl CdpDriver {
    /// Opens one blank page in the guest, which runs it on `engine`, and
    /// attaches to it. With the host's proxy, every page the guest opens
    /// after it (a popup, a tab a link opens) reaches the network only
    /// through the proxy, as it does. The live-handle registry is charged
    /// through `retention`; the secrets its reads find are held through
    /// the session's `secrets`.
    pub(crate) fn attach(
        pipe: Pipe,
        engine: BrowserEngine,
        wait_cap: Duration,
        retention: Box<dyn HandleRetention>,
        secrets: Secrets,
    ) -> Result<Self, BrowserError> {
        let ignored = page_targets(&pipe)?
            .iter()
            .map(target_id)
            .filter(|id| !id.is_empty())
            .collect();
        let created = pipe.call(
            None,
            "Target.createTarget",
            json!({"url": "about:blank"}),
            Instant::now() + CALL,
        )?;
        let target = str_field(&created, "targetId")?;
        let session = attach_tab(&pipe, &target, engine)?;
        let token = session_token();
        let driver = Self {
            pipe,
            engine,
            session: session.clone(),
            target: target.clone(),
            tabs: vec![Tab {
                target: target.clone(),
                session,
                opener: None,
            }],
            ignored,
            seq: 0,
            media: VecDeque::new(),
            captures: Captures::new(&token),
            pages: Observations::default(),
            handles: Handles::new(token, retention),
            wait_cap,
            switched: None,
            agent_known: HashSet::from([target.clone()]),
            secrets,
            typed: HashMap::new(),
            secret_nodes: Vec::new(),
            held_closed: Vec::new(),
            sent: false,
        };
        if driver.pipe.mediated() {
            let deadline = Instant::now() + CALL;
            driver.pipe.claim_network(&target);
            crate::cdp::enable_network(&driver.pipe, &driver.session, deadline)?;
            if driver.follows_pages() {
                crate::cdp::follow_pages(&driver.pipe, deadline)?;
            }
        }
        Ok(driver)
    }

    /// The tabs as they are now, each tab or popup opened since followed
    /// and each closed one dropped. With `front_new`, a tab found opened
    /// comes to the front, as a browser shows a popup; a front tab that
    /// closed gives way to the tab that opened it, else the newest left,
    /// and with none left a blank one opens.
    pub(crate) fn tabs(&mut self, front_new: bool) -> Result<Vec<BrowserTab>, BrowserError> {
        let pages = page_targets(&self.pipe)?;
        let open: HashSet<String> = pages.iter().map(target_id).collect();
        let front_opener = self
            .tabs
            .iter()
            .find(|tab| tab.target == self.target)
            .and_then(|tab| tab.opener.clone());
        // A closed tab's page drops what the pipe kept of it (FIX 6767), and
        // its snapshots once another tab is in front (FIX 6891).
        let pipe = &self.pipe;
        let mut closed = Vec::new();
        self.tabs.retain(|tab| {
            let kept = open.contains(&tab.target);
            if !kept {
                pipe.forget_page(&tab.session);
                closed.push(tab.target.clone());
            }
            kept
        });
        // A closed tab's bindings go too; its handles' records stay (FIX 6158).
        for tab in &closed {
            self.handles.forget_tab(tab);
        }
        let mut opened = None;
        for info in &pages {
            let id = target_id(info);
            if id.is_empty()
                || self.ignored.contains(&id)
                || self.tabs.iter().any(|tab| tab.target == id)
            {
                continue;
            }
            self.chromium_only("a second tab")?;
            let session = attach_tab(&self.pipe, &id, self.engine)?;
            let opener = info
                .get("openerId")
                .and_then(Value::as_str)
                .map(str::to_owned);
            self.tabs.push(Tab {
                target: id.clone(),
                session,
                opener,
            });
            opened = Some(id);
        }
        let front_gone = !self.tabs.iter().any(|tab| tab.target == self.target);
        let next = match opened {
            Some(id) if front_new => Some(id),
            _ if front_gone => front_opener
                .filter(|opener| self.tabs.iter().any(|tab| &tab.target == opener))
                .or_else(|| self.tabs.last().map(|tab| tab.target.clone())),
            _ => None,
        };
        match next {
            Some(id) => self.bring_to_front(&id)?,
            None if self.tabs.is_empty() => self.open_tab()?,
            None => {}
        }
        self.drop_closed(&closed);
        Ok(self
            .tabs
            .iter()
            .map(|tab| {
                let info = pages.iter().find(|info| target_id(info) == tab.target);
                let field = |name: &str| {
                    info.and_then(|info| info.get(name))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned()
                };
                BrowserTab {
                    tab: tab.target.clone(),
                    url: field("url"),
                    title: field("title"),
                    front: tab.target == self.target,
                }
            })
            .collect())
    }

    /// Follows the tabs for the agent's verbs (CUA-001): a front tab that
    /// closed gives way, as [`Self::tabs`] has it, and the newest tab opened
    /// since the agent's last look comes to the front, as a browser shows a
    /// popup. A move to another tab is kept for the agent's next answer;
    /// moves before that answer join into one, from the tab the agent drove
    /// last it was told. Answers why the front moved, if it did.
    pub(crate) fn follow(&mut self) -> Result<Option<TabSwitchCause>, BrowserError> {
        let from = self.target.clone();
        let tabs = self.tabs(false)?;
        let opened = tabs
            .iter()
            .rev()
            .find(|tab| !self.agent_known.contains(&tab.tab))
            .map(|tab| tab.tab.clone());
        self.agent_known = tabs.iter().map(|tab| tab.tab.clone()).collect();
        if let Some(opened) = &opened {
            self.bring_to_front(opened)?;
        }
        if self.target == from {
            return Ok(None);
        }
        let why = if tabs.iter().any(|tab| tab.tab == from) {
            TabSwitchCause::Opened
        } else {
            TabSwitchCause::Closed
        };
        let (url, title) = tabs
            .into_iter()
            .find(|tab| tab.tab == self.target)
            .map_or_else(
                || (String::new(), String::new()),
                |tab| (tab.url, tab.title),
            );
        let from = self.switched.take().map_or(from, |earlier| earlier.from);
        if from != self.target {
            self.switched = Some(TabSwitch {
                tab: self.target.clone(),
                url,
                title,
                from,
                why,
            });
        }
        Ok(Some(why))
    }

    /// The agent's move to another tab since its last answer, once.
    pub(crate) fn take_switched(&mut self) -> Option<TabSwitch> {
        self.switched.take()
    }

    /// The agent takes the tabs as they stand, as a person hands the
    /// browser back: none of them counts as opened for its next verb.
    pub(crate) fn know_tabs(&mut self) {
        self.agent_known = self.tabs.iter().map(|tab| tab.target.clone()).collect();
        self.switched = None;
    }

    /// Brings followed tab `target` to the front.
    pub(crate) fn bring_to_front(&mut self, target: &str) -> Result<(), BrowserError> {
        let session = self
            .tabs
            .iter()
            .find(|tab| tab.target == target)
            .map(|tab| tab.session.clone())
            .ok_or_else(|| BrowserError::Input(format!("{target} is no tab of this browser")))?;
        self.pipe.call(
            None,
            "Target.activateTarget",
            json!({"targetId": target}),
            Instant::now() + CALL,
        )?;
        if self.target != target {
            self.target = target.to_owned();
            self.session = session;
            // The observations held were of the other tab.
            self.forget_observations();
        }
        Ok(())
    }

    /// Opens a blank tab in front, once every tab closed.
    fn open_tab(&mut self) -> Result<(), BrowserError> {
        self.chromium_only("a new tab once every tab closed")?;
        let created = self.pipe.call(
            None,
            "Target.createTarget",
            json!({"url": "about:blank"}),
            Instant::now() + CALL,
        )?;
        let target = str_field(&created, "targetId")?;
        let session = attach_tab(&self.pipe, &target, self.engine)?;
        self.tabs.push(Tab {
            target: target.clone(),
            session,
            opener: None,
        });
        self.bring_to_front(&target)
    }
}
