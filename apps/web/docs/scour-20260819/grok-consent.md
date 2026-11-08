I'll search X and the web for practitioner evidence on agent approval fatigue, permission-prompt design, and standing-grant review screens. Loading the research skill first so the search is scoped the way you asked.The question is a live-signal sweep, not a deep-research packet. I'll search X and the web in parallel across approval fatigue, allow-once vs always-allow, TCC-style critiques, and grant-review UIs.Strong signal on Claude Code fatigue and Anthropic’s auto-mode paper. Next I’ll pull the primary sources and look for Cursor, Codex, Grok Bot, computer-use, and grant-review designs.Official numbers and product posts are in. Next I’ll pull the Reddit/forum threads, the TCC GitHub issue, grant-revoke papers, and more X posts on allow-once vs always-allow.I have the Cowork revoke gap and the official 93% figure. Next I’ll pull Cursor/Codex forum threads, the 97% claim, and any praised grant-review screens.I have enough primary sources to write the brief. Two extra pages will pin down Grok Bot and the lattice/consent paper, then I’ll synthesize.**Approval fatigue is a measured security failure, not a taste complaint.** Anthropic’s own numbers say humans approve 93–97% of Claude Code permission prompts and catch dangerous commands 13.6% of the time (≈5% after 50+ prompts). The same pattern shows up independently in Cursor, Codex, HN, GitHub, and vendor blogs. Users praise *scoped* standing grants (session / workspace / command family), not a binary “once vs forever.” Dedicated agent grant-review/revoke screens that people actually praise are almost nonexistent.

---

## 1. People complaining that agents ask too often

### Consensus (3+ independent): Claude Code is the canonical case

Anthropic named the problem and measured it:

| Claim | Source | Date |
|---|---|---|
| Users approve **93%** of permission prompts | [Anthropic engineering: auto mode](https://www.anthropic.com/engineering/claude-code-auto-mode) | 25 Mar 2026 |
| Users approve **97%** of prompts; plan-mode rejection is **39%**; per-prompt rejection is **3%** | [claude.com auto-mode default](https://claude.com/blog/auto-mode-default-in-claude-code) | 7 Aug 2026 |
| 1,053 paid testers: humans caught **13.6%** of planted dangerous commands; auto mode **89%**. Humans drop from ~17% early to **~5% after 50+ prompts** | Same Anthropic post; [TechCrunch](https://techcrunch.com/2026/08/09/anthropic-is-turning-claude-codes-auto-mode-on-by-default/) | Aug 2026 |
| **49.5%** of CLI users have a Bash allow-rule; **5%** allow any shell; **62%** used `bypassPermissions` or “don’t ask again” on Bash; **25%** of sessions start in bypass | Anthropic default-mode post | Jun 2026 snapshot |
| Gusto adopted auto mode specifically to end “permission fatigue that was pushing engineers toward bypassing permissions” | Same post | Aug 2026 |

Practitioners independently say the same thing:

- **@levelsio** (13 Jan 2026): “stop asking me every time… Even with [accept edits on] it still asks me permission 1000 times per day… I just want you to run… And no I don't feel like running it with `--dangerously-skip-permissions`.” ~2k likes. [x.com/levelsio/status/2011129631001170244](https://x.com/levelsio/status/2011129631001170244)
- **@trq212** (Thariq, Claude Code, 13 Jan 2026), reply: “yeah this is a p0 for us… **permission fatigue actually makes Claude Code less secure** since people stop paying attention.” [x.com/trq212/status/2011207386229260599](https://x.com/trq212/status/2011207386229260599)
- **@ryanbeck111** (9 Apr 2026): “It would be reckless to dangerously skip permissions… that's why I make it ask me first and then rapidly click ‘always allow’ on everything without reading it first.” [x.com/ryanbeck111/status/2042288227680186557](https://x.com/ryanbeck111/status/2042288227680186557)
- **@zodchiii** (29 Apr 2026): “click allow 30 times per session… don't even read what you're approving.” [x.com/zodchiii/status/2049489654370459704](https://x.com/zodchiii/status/2049489654370459704)
- **@ura_yaeri** (13 Aug 2026): Japanese user: endlessly forced to hit 常に許可 (“always allow”) — “マジでダルイ.” [x.com/ura_yaeri/status/2087817087100354821](https://x.com/ura_yaeri/status/2087817087100354821)
- **@error_imateapot** (23 Jul 2026): Claude asked five times for “don’t ask again” on the **exact same command**. [x.com/error_imateapot/status/2080300280197927409](https://x.com/error_imateapot/status/2080300280197927409)
- GitHub **#11380** (10 Nov 2025): “continually asks… even after selecting yes, always allow.” [github.com/anthropics/claude-code/issues/11380](https://github.com/anthropics/claude-code/issues/11380)
- Reddit r/ClaudeCode: “every 15 seconds it stops to ask me things I already agreed.” [reddit.com/r/ClaudeCode/comments/1r92dpu](https://www.reddit.com/r/ClaudeCode/comments/1r92dpu/how_can_i_stop_getting_way_too_many_permission/)
- Test Double (Joé Dupuis, 7 Apr 2026): “Permission fatigue is real. There’s no point to having permissions if we don’t read them.” [testdouble.com/insights/get-in-the-box…](https://testdouble.com/insights/get-in-the-box-illustrated-permissions-guide-to-make-claude-chill)
- HN on auto-mode default (10 Aug 2026, 313 comments): **hkchad** — alias for `--dangerously-skip-permissions` after a week of “constant y, y, y… felt like Homer Simpson running the nuke plant”; **danielbln** — “I just cannot approve seven trillion approval prompts and stay sane”; **matheusmoreira** — “Alarm fatigue will quickly destroy any and all ‘meticulously approve every little command’ workflows”; **paul_h** — “massively imperfect 1-approve-once and 2-approve-forever.” [news.ycombinator.com/item?id=49239021](https://news.ycombinator.com/item?id=49239021)

**@bcherny** (7 Aug 2026): “The team and I use Auto mode exclusively… I couldn't imagine going back to permission prompts!” [x.com/bcherny/status/2085807103382519872](https://x.com/bcherny/status/2085807103382519872)

That is vendor + users + HN + GitHub + Reddit. **Consensus.**

### Consensus: Cursor — auto-run still nags; users want in-prompt scope

Independent threads, not one loud account:

- Forum: “Agent Mode keeps asking approval for changes” (5 Dec 2025) and “asking for approval at each code change” (10 Jan 2026). Staff workaround: turn off *External file edit protection*. [forum.cursor.com/t/145341](https://forum.cursor.com/t/agent-mode-keeps-asking-approval-for-changes/145341), [forum.cursor.com/t/148476](https://forum.cursor.com/t/cursor-agent-asking-for-approval-at-each-code-change/148476)
- Forum: agent preemptively uses `required_permissions: ["all"]` instead of sandbox auto-run (22 May 2026). [forum.cursor.com/t/161271](https://forum.cursor.com/t/agent-preemptively-uses-required-permissions-all-instead-of-auto-running-in-sandbox-allowlist-with-sandbox/161271)
- **Abhijith_Yatnam** (19 Jun 2026) + staff **Dean Rie**: IDE prompt today is only **Run-once / Allowlist global / Skip**. Users want workspace / session / this-tool / this-MCP-server. Staff: “not available yet… on our radar.” [forum.cursor.com/t/163631](https://forum.cursor.com/t/granular-approval-options-for-terminal-commands-and-mcp-tool-calls/163631)
- r/cursor: “How bad is always saying always allow? I have no idea what the stuff they are asking means.” [reddit.com/r/cursor/comments/1v97cvq](https://www.reddit.com/r/cursor/comments/1v97cvq/how_bad_is_always_saying_always_allow/)
- r/cursor sidebar chatter (mid-Aug 2026): Cursor keeps asking “Always run” `git status`/`cd` over and over.

**Consensus on the complaint.** The praised *fix* is not “always allow everything”; it is **scope in the prompt itself**.

### Consensus (smaller n, still 3+): Codex — “Approve for me” is the praised middle; the ask-every-time mode is hated

- **@antonpme** (10 Jul 2026): a Codex popup “every half hour or hour… ruining the entire experience.” [x.com/antonpme/status/2075494772597301693](https://x.com/antonpme/status/2075494772597301693)
- **@BitBullish** (15 Aug 2026): skip-permission on, still “hit approve 20 times during a 2 hour run… the dumbest experience of my life.” [x.com/BitBullish/status/2088606040891769097](https://x.com/BitBullish/status/2088606040891769097)
- **@abdcyln** (13 Aug 2026): forgot “Approve for me”; Codex “asks constantly… even after I've changed the settings.” Mid-run flip does not take effect until the next prompt. [x.com/abdcyln/status/2087723044370313310](https://x.com/abdcyln/status/2087723044370313310)
- **@markvalorian** (12 Aug 2026): permission system is “a huge point of friction”; “Approve for me” is billed while Claude auto mode is free; cannot retune mid-turn. [x.com/markvalorian/status/2087557841863184747](https://x.com/markvalorian/status/2087557841863184747)
- **@reach_vb** (OpenAI, 8 Jun 2026): “Do yourself a favor and switch to ‘Approve for me’… approving each tool call isn't the way… godsend for long running tasks.” [x.com/reach_vb/status/2064044955421769755](https://x.com/reach_vb/status/2064044955421769755)
- **@Allamay_Shi** (7 Aug 2026): “non-stop ‘Allow once’ or ‘Allow for this session’ prompts… when you come back, job is stuck.” [x.com/Allamay_Shi/status/2085700427845107731](https://x.com/Allamay_Shi/status/2085700427845107731)
- Official docs: “The sandbox **reduces approval fatigue**.” Modes: Ask for approval / Approve for me / Full access. “Choose the **narrowest scope** that lets the task continue.” [learn.chatgpt.com/docs/sandboxing](https://learn.chatgpt.com/docs/sandboxing)

**Consensus:** per-call ask is unusable for long runs; users want a live reviewer *or* a sandbox that swallows routine work. Mid-run policy changes that do not apply immediately are a separate, repeated complaint.

### Grok Bot — thin on *prompt* fatigue; thicker on *wrong* or *missing* gates

**Nothing found** as a 3+ independent corpus of “Grok Bot asks me to approve too often.” What exists:

- Official line: bots “only check in when approval is needed”; local computer access “defaults to requiring approval every time” (@grok, 13 Aug 2026). [x.com/grok/status/2087755437068165617](https://x.com/grok/status/2087755437068165617)
- **@petecallaghans** (18 Aug 2026): opposite failure — “those other bots are doing things I didn't approve.” [x.com/petecallaghans/status/2089762470239866950](https://x.com/petecallaghans/status/2089762470239866950)
- **@petergyang** (18 Aug 2026): Marie Kondo bot prompt explicitly “Do not move, delete, unsubscribe, or cancel anything without my approval.” [x.com/petergyang/status/2089724101070086482](https://x.com/petergyang/status/2089724101070086482)
- **@ssbrouhard** (13 Aug 2026): Telegram path for Grok permissions is **Approve once / Deny** only — “No permanent ‘always allow’ shortcut.” [x.com/ssbrouhard/status/2087743825531772989](https://x.com/ssbrouhard/status/2087743825531772989)
- Sugra (vendor, not practitioner): “If the approval gate is a modal that appears forty times a day, it will be clicked through by Thursday.” [sugra.systems/blog/welcome-grok-bot](https://sugra.systems/blog/welcome-grok-bot)

Treat Grok Bot as **anecdote + product copy**, not a fatigue consensus.

### Computer-use / Operator / ChatGPT agent — thin on click-fatigue; strong on *missing* consent

**Nothing found** as a dense 2025–26 practitioner corpus of “Operator / computer-use asks me every click.” The evidence that *does* exist cuts the other way:

- OpenAI (Jul 2025 launch): “trained to explicitly ask… before actions with real-world consequences, like making a purchase.” [news.ycombinator.com/item?id=44595492](https://news.ycombinator.com/item?id=44595492)
- Michael & Roesner, UW (arXiv:2607.13718v2, 20 Jul 2026): ChatGPT **chat** requires approval for every permissioned action with **no “always allow”**; ChatGPT **agent mode** then does Gmail etc. in the remote browser with **no permission policy at all**. [arxiv.org/html/2607.13718v2](https://arxiv.org/html/2607.13718v2)
- Codex computer-use: CAPTCHA is **always-confirm**, even if pre-approved (@grok, 13 Aug 2026). [x.com/grok/status/2087908286121083173](https://x.com/grok/status/2087908286121083173)
- **@CarlRothman** (17 Aug 2026): Grok Build spontaneously requested Photos / email / calendar; macOS TCC was “the entire security model.” [x.com/CarlRothman/status/2089470501835960419](https://x.com/CarlRothman/status/2089470501835960419)

**Consensus only on this:** computer-use either over-asks on a few hard-coded actions (CAPTCHA, purchases) or **under-asks** by leaving the VM/browser unconstrained. Not the Claude-style “30 allows per session” pattern.

---

## 2. “Allow once vs always allow” grammars people actually praise

### Consensus: a two-button once/forever prompt is the *problem*, not the solution

Independent critiques of tool-level toggles:

- Anthropic itself: people click through; **plan approval** (39% reject) is the dialogue they actually read.
- [arXiv:2605.11360](https://arxiv.org/html/2605.11360v1) (12 May 2026): “Always Allow” on an MCP tool “silently authorizes all future emails with arbitrary recipients.”
- Blake Crosley (18 May 2026): sticky `always_approve` for `shell` / `send_email` / `deploy` is unsafe; safer bound is **run + resource + pattern + expiry**. [blakecrosley.com/blog/ai-agent-approval-prompts-not-authorization](https://blakecrosley.com/blog/ai-agent-approval-prompts-not-authorization)
- Curity (20 Aug 2025): persist-once consent is the wrong default for agents; prefer **time-limited / per-transaction**, with a duration picker. [curity.io/blog/user-consent-best-practices-in-the-age-of-ai-agents](https://curity.io/blog/user-consent-best-practices-in-the-age-of-ai-agents/)
- OWASP Agentic Top 10 ASI09 (9 Dec 2025): polished explanations talk operators into harmful approvals. Cited in Crosley.

### Grammars that *do* get praise (or at least repeated as a rule of thumb)

| Grammar | Who | Status |
|---|---|---|
| **Read-only = Always Allow; write/deploy/send/spend = Allow Once every time** | @elizondogabriel, 10 Aug 2026 | Anecdote, but matches Curity/Crosley/Auth0 |
| **Yes / Yes this session / No** (Claude default card) | Claude Code UI; GitHub #11380 shows the third option as “No, and tell Claude what to do differently” | Shipped; users still complain it doesn’t *stick* |
| **Ask / Allow / Deny configured once** (settings.json / `/permissions`) | @adocomplete, 5 Jan 2026; @zodchiii; Test Double “Allow it / Kill it / Push it” | Consensus among power users: **pre-configure, don’t click** |
| **Run-once / Allowlist this workspace / Allowlist global / This session / This MCP tool / This MCP server** | Cursor FR + staff, Jun 2026 | User-requested; **not shipped in IDE prompt** |
| **Ask for approval / Approve for me / Full access**, plus sandbox `workspace-write` | Codex official + @reach_vb | Consensus *among Codex users who found it* |
| **Deny / Allow once / Always allow; unanswered = deny, never approve** | @jordankdalton / Tackle, 14 Aug 2026 | Anecdote (product pitch) |
| **Approve once / Deny only — no Always Allow** | @ssbrouhard on Grok-via-Telegram | Anecdote; opposite of Claude’s “always” escape hatch |
| **Approve a summary of proposed actions, not each command** | HN Retr0id + bradfa, 10 Aug 2026 | Anecdote, high-signal; matches Anthropic’s plan-vs-prompt data |

**@adocomplete** (5 Jan 2026): “3 permission tiers… Configure once. Never click ‘allow’ on npm test again.” [x.com/adocomplete/status/2008228756629172667](https://x.com/adocomplete/status/2008228756629172667)

Test Double’s flywheel is the most concrete praised *practice*: every prompt is **Allow (write a standing rule) / Kill (give the agent a sandboxed alternative) / Push (move the ask to start or end of the task)** — never “just click yes.”

---

## 3. macOS TCC-style prompt-fatigue applied to agents

### Consensus: TCC *is* the agent permission UI on Mac, and it is a bad one for versioned CLIs

- Claude Code **#63130** (28 May 2026) + four prior locked issues (#27322, #36675, #36832, #41297): each versioned binary (`2.1.153`) is a new TCC identity; popup says the version number, not “Claude Code”; prior grants die on update; sometimes asks for Apple Music. [github.com/anthropics/claude-code/issues/63130](https://github.com/anthropics/claude-code/issues/63130)
- **@CarlRothman** (17 Aug 2026): Grok Build → Terminal → Photos/Mail/Calendar TCC. “Most people hit Approve out of habit.”
- **@altryne** (13 Aug 2026): “the mac approval didn't show up and the agent said he can't do things, but I already approved the ‘always’ button.” [x.com/altryne/status/2087696636084363534](https://x.com/altryne/status/2087696636084363534)
- HN **shelled** (10 Aug 2026): macOS Privacy & Security is “so badly implemented and poorly shown” that OpenCode appears under Full Disk Access *and* Files & Folders with contradictory toggles.
- **@rusabuilds** (14 Aug 2026): “tccutil resets by service, not by app… there is no single place to see what you actually granted. the sprawl is the design.” [x.com/rusabuilds/status/2088235437349323113](https://x.com/rusabuilds/status/2088235437349323113)
- Mysk (23 Jul 2026): TCC dialogs should show **signing identity** and warn if it changed — because users cannot tell which binary they are blessing. [x.com/mysk_co/status/2080370107310538983](https://x.com/mysk_co/status/2080370107310538983)
- Classic security writeups still cited in 2025–26: SentinelOne (TCC “OK” click-through grants Finder automation / FDA); [wts.dev CVE-2025-31250](https://wts.dev/posts/tcc-who/) (spoofed consent prompt as another app).

**Consensus, applied to agents:** a system dialog that names the *host binary* (“Terminal”, “2.1.153”, “node”), offers Allow/Don’t Allow, and stores the grant with no in-app ledger, **is the same fatigue machine as Claude’s allow-once card** — plus identity confusion.

### Anecdote (high-signal): treat the machine as an employee device, not a TCC target

**@kunchenguid** (29 Jul 2026): disable agent permission checks; isolate secrets behind a human-gated vault; wipe/repro the box. “I would never tell [an employee] to ask me for approval each time they wanted to run a shell command.” [x.com/kunchenguid/status/2082316720086405524](https://x.com/kunchenguid/status/2082316720086405524)

That is the HN/VM/devcontainer camp in one post. It is a *containment* strategy, not a consent-card design.

---

## 4. Standing-grant review / revoke screens people praise

**Nothing found:** a widely praised, shipped *agent* “grants registry” that practitioners point at and say “copy this.”

What exists, labeled honestly:

| Surface | Verdict |
|---|---|
| **GitHub OAuth consent + app review/revoke** | Curity (20 Aug 2025) explicitly holds it up as a well-designed consent screen (who / to what / what data / how long) and says users must be able to browse and revoke. Closest praised *analog*. |
| **Claude `/permissions` + settings.json allow/ask/deny** | Praised as *escape from clicking*, not as a review UI. Boris: if auto mode blocks wrongly, “just run /permissions to tune.” No one is raving about the *screen*. |
| **Cursor Settings allowlist + `.cursor/cli.json`** | Staff-documented; users still want the same scopes **on the prompt**. Not praised as a registry. |
| **Auth0 Token Vault + CIBA + RAR** | Vendor design: revoke a connection, kill in-flight tokens, show “refund $2,000 to Jane Doe for order #12345” not “approve billing.” [auth0.com/blog/why-ai-agents-need-their-own-permission-model](https://auth0.com/blog/why-ai-agents-need-their-own-permission-model/) (1 Jun 2026). Practitioner praise: **nothing found**. |
| **Claude Cowork** | **Anti-pattern.** UW walkthrough (May–Jun 2026): once a folder grant exists, **the user cannot revoke it in-app**. Old sessions keep the grant if reopened. Only OS TCC or uninstall. Warning text that “a new task removes the permission” is **false**. |
| **macOS Privacy & Security** | The default standing-grant ledger for local agents. Practitioners **criticize** it (identity, sprawl, no single view). |
| **OpenAI Agents SDK `always_approve` / `always_reject` on `RunState`** | Runtime primitive, not a review screen. Crosley: every sticky grant needs **scope + expiry + revoke**. |

UW paper (21 systems + 5 commercial agents): literature rarely lets users **edit or revoke after grant**; commercial agents are better at continuous control but then drown users in HITL, which is the privacy-fatigue path. That is the academic confirmation of the product hole.

---

## 5. Cross-cutting consensus (safe to design against)

1. **A prompt that fires dozens of times is not a control.** Anthropic 93/97%, 13.6%→5% catch rate, Gusto’s “fatigue → bypass,” Thariq’s “less secure,” Crosley, Curity, Test Double, HN alarm-fatigue comments.
2. **Humans read plans, not tool calls.** 39% plan reject vs 3% prompt reject. HN Retr0id independently wants “approve summaries of proposed actions.”
3. **Always-allow at tool granularity is how people nuke themselves.** MCP “Always Allow” = all future emails; `Bash(python:*)` ≈ any code; Cursor `required_permissions: ["all"]`.
4. **Sandbox (or VM) + rare high-stakes card** is the praised *system*, not a prettier modal. Codex docs, Test Double, HN container/VM chorus, Anthropic auto-mode as a replacement for `--dangerously-skip-permissions`.
5. **Grants that cannot be listed, scoped, expired, or revoked are consent theater.** Cowork; TCC-per-version; Codex mid-run setting changes ignored; Claude “always allow” that doesn’t stick (#11380).

---

## 6. Five lessons for a consent-gate card + grants registry

- **Card = one commit-point, not one tool call.** Show actor, action, resource, blast radius, evidence, duration, rollback. Offer **Allow once / Allow this run / Allow this workspace + this command-or-tool family / Deny + reason**. Default unanswered to **deny**. Do not ship a lone “Always allow this tool.” That is the grammar users both mash and later regret.

- **Risk-split the verbs on the card.** Auto-allow (or sandbox-allow) reads, searches, in-repo edits. Force a card for write-outside-workspace, network egress, send, spend, deploy, delete, credential use. Match Elizondo / Curity / Auth0 / Anthropic hard-denies. If the card fires more than a handful of times per task, the classifier/sandbox failed — don’t make the user the backstop.

- **Standing grants are objects with a registry row, not a remembered click.** Every Always/session/workspace grant must appear in a single list: who, what, resource pattern, created-from-which-card, expiry, last used, revoke. If it is not on that list, it is not granted. Cowork and versioned-TCC are the cautionary tales.

- **Identity on the card must be the agent, not the host binary.** Never “Terminal would like to access Photos.” Name the agent, the run, and the signing/workspace identity. Warn if the identity changed since last grant (Mysk). A grant to `claude 2.1.153` that dies on `2.1.154` is why people start clicking blind.

- **Revoke is a first-class button, and mid-run policy changes take effect immediately.** Registry revoke must kill in-flight tokens and pause the run (Auth0 Token Vault shape). Flipping Ask ↔ Approve-for-me / shrinking a grant must apply to the *current* turn — Codex users called out the opposite as a product miss. Show last-used and unused grants so review is possible without waiting for the next scary prompt.
