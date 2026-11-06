# Grok Bot — product study for design
**Subject:** GROK BOT by xAI / SpaceXAI (`x.ai/bot`). Tagline: *“AI teammates you can give real work to. Bots can sign in to your tools, use them just like you do, and come back with finished work.”*  
**Study date:** 7 Sep 2026. Facts first. Each fact has a source URL and a date. Unverified claims are marked.

---

## 1. What it is

| Fact | Source | Date |
|---|---|---|
| Grok Bot is a **named-agent desktop/mobile app**, not Grok chat. Pitch: always-on AI teammates with **their own cloud computer**, who sign into the user’s apps and return **finished work**, interrupting only for approval. | [x.ai/bot](https://x.ai/bot); [Introducing Grok Bot](https://x.ai/news/introducing-grok-bot) | Product page live 7 Sep 2026; launch post **11 Aug 2026** |
| **Launch:** public early beta **11 August 2026**. First joint SpaceXAI + Cursor shipment after the reported Cursor acquisition. | [x.ai/news/introducing-grok-bot](https://x.ai/news/introducing-grok-bot); [9to5Mac](https://9to5mac.com/2026/08/11/grok-bot-is-an-all-new-iphone-and-mac-app-from-spacexai-and-cursor/) | 11 Aug 2026 |
| **Platforms at launch:** dedicated **macOS** app (Apple silicon + Intel) and **iOS**; **Windows** desktop also shipped; **Linux** mentioned in launch coverage; **Android “coming soon.”** iPad was **not** in the launch-day Apple set. | [9to5Mac 11 Aug](https://9to5mac.com/2026/08/11/grok-bot-is-an-all-new-iphone-and-mac-app-from-spacexai-and-cursor/); [iGeeksBlog](https://www.igeeksblog.com/grok-bot-macos-ios-launch/) | 11–12 Aug 2026 |
| **Platforms now (early Sep):** official page still leads with **macOS + iOS** (“desk and pocket”). **Android** reached Play **2 Sep 2026**. **iPad** reported **4 Sep 2026**. Downloads are served from Cursor’s updater (`api2.cursor.sh` … `grok-bot-…`). | [x.ai/bot](https://x.ai/bot); [CellCog](https://cellcog.ai/blog/what-is-grok-bot/); [9to5Mac 4 Sep](https://9to5mac.com/2026/09/04/spacexai-expands-grok-bot-to-ipad-as-access-expands-to-cheaper-plans/) | 2–7 Sep 2026 |
| **No standalone SKU.** Access is **bundled** into Cursor and SuperGrok plans. Official price ladder on the product page: **Cursor Pro $20/mo**, Pro+, Ultra; **SuperGrok $30/mo**, Plus, Heavy; **Cursor Teams Standard $40/seat/mo**, Premium. Ultra advertises **extended token limits**; Premium adds **SAML/OIDC SSO**. Weekly Grok Bot usage is included; overage is billed. | [x.ai/bot](https://x.ai/bot) Pricing | fetched 7 Sep 2026 |
| **Launch-day access was narrower in press** (SuperGrok Heavy / Cursor Ultra / Teams Premium, ~$120–$300). The **launch post itself** already listed SuperGrok + Cursor Pro families. By late August / early September, **Cursor Pro ($20)** is a documented entry, and **enterprise** opened **3 Sep 2026** (two free weeks for Grok/Cursor Enterprise, activate in admin dashboard; list price unpublished). | [9to5Mac 11 Aug](https://9to5mac.com/2026/08/11/grok-bot-is-an-all-new-iphone-and-mac-app-from-spacexai-and-cursor/); [launch post](https://x.ai/news/introducing-grok-bot); [Grok Bot for Enterprise](https://x.ai/news/grok-bot-for-enterprise); [9to5Mac 4 Sep](https://9to5mac.com/2026/09/04/spacexai-expands-grok-bot-to-ipad-as-access-expands-to-cheaper-plans/) | 11 Aug – 4 Sep 2026 |
| **Who it is for:** anyone who can message a coworker — PMs, GTM, designers (official “guides”), sales, ops, finance, engineering. Internally it ran sales outbound, campaigns, office ops, and bug work. It is **not** a coding IDE; Cursor remains the code surface. SuperGrok marketing frames it as “an AI that works like a teammate. Not a chatbot.” | [launch post](https://x.ai/news/introducing-grok-bot); [x.ai/bot](https://x.ai/bot); [grok.com/supergrok/grokbot](https://grok.com/supergrok/grokbot) | 11–29 Aug 2026 |

**Audience, in one line:** paid Cursor/Grok subscribers who want **standing digital employees**, not a better chat box.

---

## 2. The interaction model (chat + group chat)

This is an **iMessage/Slack-shaped messenger**, not a canvas or a DAG builder.

### Sidebar of named Bots
Each Bot is a **durable teammate**: name, job, own conversation, working context over time ([docs: Create and manage Bots](https://docs.x.ai/grok-bot/bots), undated on fetch; use-cases gallery dated **11 Aug 2026**).

Official job chips on the product page: **Sales Outbound, Talent Scout, Paid Media, Expense Manager, Product Performance, Bug Reproduction, Account Health, Chief of Staff** ([x.ai/bot](https://x.ai/bot), 7 Sep 2026).

| Named role | What official copy says it owns | Source / date |
|---|---|---|
| **Sales Outbound** | Overnight pipeline: research accounts, score contacts, draft email + LinkedIn, **leave a review list** — “Nothing goes out until you've had a look” in the demo write-up. | [x.ai/bot](https://x.ai/bot); [use-cases](https://x.ai/docs/grok-bot/use-cases) 11 Aug 2026 |
| **Talent Scout** | Sourcing, candidate research, outreach drafts, scheduling prep. | same use-cases page, 11 Aug 2026 |
| **Expense Manager** | Named as a “good job” in the Bots doc (narrow ownership). | [docs.x.ai/grok-bot/bots](https://docs.x.ai/grok-bot/bots) |
| **Account Manager / Account Health** | Landing-page memory example is labeled **“Updated memory for Account Manager.”** Use-case **Account Health** owns a watch list; **never contact a customer or change an account without approval.** | [x.ai/bot](https://x.ai/bot); [use-cases](https://x.ai/docs/grok-bot/use-cases) 11 Aug 2026 |
| **Inbox** | Not a gallery chip. Launch post describes a **chief of staff on top** and specialists for **“inbox management, expenses, recruiting, bug fixes, or operations.”** | [launch post](https://x.ai/news/introducing-grok-bot) 11 Aug 2026 |
| **Chief / Chief of Staff** | Owns a **source-linked digest of what changed and what needs attention.** Connect Slack, email, calendar, notes. Internally: “a chief of staff sits on top, with a specialist for each lane… so you’re not the middleman.” | [use-cases](https://x.ai/docs/grok-bot/use-cases) 11 Aug 2026; [launch post](https://x.ai/news/introducing-grok-bot) |

Sidebar mechanics ([Bots doc](https://docs.x.ai/grok-bot/bots)): **Pin** active Bots; **Hide from sidebar** (does **not** pause routines); **Show hidden chats**; **Duplicate** (copies profile, skills, routines, avatar — **not** history/memory/attachments); cap **50 Bots + group chats combined**.

### Group chats (e.g. “Offsite crew”)
Official flow ([Message and collaborate](https://docs.x.ai/grok-bot/chat-and-collaboration)):

1. **New** in the sidebar.  
2. In **New chat**, select **two to six Bots**.  
3. Open the group, **edit the generated name**.  
4. Describe the shared outcome and who owns the next step.  
On phone: **+ → New Group Chat**. Membership is editable.

**I did not find the exact string “Offsite crew” in official docs.** What is documented: groups get a **generated, editable name**; the Bots doc’s example is a **“Website Launch”** group (coordinator + content editor + analytics reviewer). Treat “Offsite crew” as the **pattern** (a named room of specialists), not a confirmed first-party template.

Landing-page group choreography: *Asking Research… / Looping in Comms… / Sending to Chief… / Pinging Travel…* ([x.ai/bot](https://x.ai/bot)).

### How a Bot reports work
The transcript is the status board. It shows **tool activity, computer use, created files, questions, and approval requests** next to normal messages ([chat doc](https://docs.x.ai/grok-bot/chat-and-collaboration)). Bots are supposed to **return with finished work** or an approval, not a draft-in-chat as the end state ([launch post](https://x.ai/news/introducing-grok-bot), 11 Aug 2026). Users are told to ask for **evidence: links, screenshots, or a short action log**.

Sales demo: “52 accounts pulled, 36 drafts queued, **zero sent**” ([squad.so write-up of the launch demo](https://squad.so/resources/grok-bot-examples), 4 Sep 2026 — secondary; matches official “review list” copy).

### How tasks are assigned inside a chat
- **1:1:** open the Bot in the sidebar, type. Paste text/links/images, attach files.  
- **Group:** write normally and let Bots decide who answers, **or `@` a Bot** when one owner should take it. Mention several Bots only when each is needed. **`@everyone`** is documented and labeled “sparingly.”  
- **Kickoff pattern from docs:** `@Researcher gather… @Writer turn findings into a draft. @Reviewer check… Do not publish anything.`  
- **Handoffs:** a Bot can **async-message another Bot**; the receiver wakes, works, may reply later; you see the handoff in the conversation.  
- **Redirect:** a new DM from you **beats background work**. **“Stop now”** ends the current turn; it does **not** undo completed actions.  
- **Threads** for feedback on one result/approval; **reactions** for ack — docs say a reaction **must not** carry a safety-critical decision.

### Mentions
Type **`@`** to mention a **Bot, group, routine, or connector**. Type **`/`** to reference a saved **skill** ([chat doc](https://docs.x.ai/grok-bot/chat-and-collaboration); [skills/routines](https://docs.x.ai/grok-bot/skills-routines-and-automations) via search index, retrieved 7 Sep 2026).

### The Chief role
Two layers:

1. **Product role (Chief of Staff):** a Bot whose job is **coordination and digest**, not a special runtime. Same object type as Sales Outbound.  
2. **Org pattern:** people create Chief **first**, then specialists. Launch copy: one Bot “to manage the others.” Users on X: *“create CHIEF first”* (@MarikWeb3, 7 Sep 2026); *“Chief, 相当于项目经理”* (@Reimagine2026, 7 Sep 2026); SpaceXAI engineer Lauren Tan described a **Chief of Staff + 3 managers + 11 workers** (@0xCodez, 1 Sep 2026).

Chief is **social architecture**, not a different engine.

---

## 3. How a Bot is created and set up

**Hybrid: form + chat + templates. Chat is how you teach; a form is how you name the employee.**

### Exact documented create steps
From [Create and manage Bots](https://docs.x.ai/grok-bot/bots):

1. **New** in the sidebar, or `Cmd/Ctrl+N`.  
2. In **New chat**, select **Create new agent**.  
3. App opens a Bot named **New Agent**.  
4. **Bot actions → Edit Profile** → **name, title, description, avatar**.  
5. Start a conversation with a **concrete task**.

Existing Bots can **suggest or create** a focused Bot. Cap: **50** Bots + groups.

Secondary setup guide (19 Aug 2026, [The Tech Archive](https://aitecharchive.com/articles/how-to-use-grok-bot-complete-setup-guide-2026), cites x.ai/bot): pick a suggested teammate from **“Meet a future teammate”** or **Create your own**; give (1) a short name, (2) one primary job, (3) a description of how it should work. Vendor rule: **one Bot, one job**.

### What the user configures

| Surface | What you set | How | Source |
|---|---|---|---|
| **Profile** | Name, title, description, avatar | Form: Edit Profile | Bots doc |
| **Job / approval boundary** | Operational description, including “never send without approval” | Form **and** chat. Docs: **description = durable rules**; **message = this task** | Bots doc |
| **Tools / plugins** | Gmail, Calendar, Drive, Slack, GitHub, Notion, Salesforce, Outlook, Teams, SharePoint, OneDrive (list as of Aug 2026 guide) | **Settings → Plugins → Add** (OAuth marketplace). Connectors are **account-wide, not per-Bot** | [Tech Archive 19 Aug](https://aitecharchive.com/articles/how-to-use-grok-bot-complete-setup-guide-2026); community SETUP.md |
| **Sign-ins (no API)** | Browser sessions on the **shared cloud computer** | “Log Grok Bot in once”; computer-use into sites with no MCP | [x.ai/bot](https://x.ai/bot); launch post 11 Aug |
| **Schedule** | Routines (cron-like, some event triggers) | **Ask the owning Bot in chat**; then inspect in **View conversation details → Routines** (enable/pause/test/edit/history). Timezone: **Settings → Agent timezone** | [skills/routines doc](https://docs.x.ai/grok-bot/skills-routines-and-automations) |
| **Skills** | Reusable how-to | Do a task well → *“Save this as a skill named …”*; invoke with `/`; enable per Bot under **Settings → Plugins → Yours** | same |
| **Permissions / local machine** | Whether the Bot may run on **your** Mac/Windows | **Settings → General → Agent → Execution on Local Computer**: Ask every time (default) / always / never | [Approvals, security, and privacy](https://docs.x.ai/grok-bot/approvals-security-and-privacy) ~2 Sep 2026 |
| **Voice** | **Not documented as a Grok Bot config.** SuperGrok marketing lists Voice for **Grok chat**, not Bot. | — | [grok.com SuperGrok](https://grok.com/supergrok/grokbot) 29 Aug 2026 |
| **Templates / gallery** | 56 example roles across functions; community “installer” prompts paste into chat | Official use-cases + third-party botteams | [use-cases](https://x.ai/docs/grok-bot/use-cases) 11 Aug 2026; [github.com/ellelion/botteams](https://github.com/ellelion/botteams) |

**Vendor doctrine (use-cases, 11 Aug 2026):** run one safe task → correct until reviewable → save a skill → test on a second input → **create a routine only when retries and failure cases are defined** → keep consequential external actions behind approval.

Launch post contrast: *“Other AI tools may ask you to set up workflows first. With Grok Bot, simply message a Bot.”* That is the **first-run** story. Recurring work still graduates into **skills + routines + a Routines panel**.

---

## 4. What runs beyond chat

| Capability | Fact | Source / date |
|---|---|---|
| **Scheduled / continuous** | Routines run on a schedule (and “where supported, after an event”). **Background routines run with the laptop closed.** Hiding a Bot does **not** pause routines. | skills/routines doc; Bots doc |
| **Always-on computer** | **One cloud computer per user**, shared by **all** of that user’s Bots. Browser + filesystem + terminal. Linux VM. Not on-prem, not BYO image. | launch post 11 Aug; [security FAQ](https://docs.x.ai/grok-bot/security-faq) 3 Sep 2026 |
| **Tool sign-ins / where credentials live** | Plugins via **OAuth**. Computer-use logins live as **browser sessions on the shared VM** — available to **every Bot on that user**. WebAuthn is **forwarded to the member’s desktop**; docs recommend **passkeys in a password manager**. A masked secret store exists; it is **not** a general password manager; values are **excluded from the transcript and not shown to the model**. Isolation = **separate Cursor user**, not a second Bot. | [approvals/security](https://docs.x.ai/grok-bot/approvals-security-and-privacy) ~2 Sep; [identity and access](https://docs.x.ai/grok-bot/identity-and-access) 3 Sep; security FAQ 3 Sep |
| **Computer-use** | First-class. Sites with **no API/MCP**. Transcript shows computer-use. Enterprise **Auto Review** can allow / require approval / deny shell, plugins, computer-use, automation writes, Cloud Agent / subagent launches. It does **not** review every side effect (memory writes, most settings). | chat doc; security FAQ 3 Sep |
| **Approvals / consent** | Product promise: come back when approval is needed. Per-Bot **description boundaries**. Local-computer default **Ask every time**. Group threads for one approval. Enterprise Auto Review. Demo: drafts queue, nothing sends. | launch 11 Aug; chat + approvals docs |
| **Memory** | Per-Bot: stable preferences, important facts, summaries. **Not** a source of truth — keep changing facts in the system of record. Bots have **separate conversations** but **share the computer**, and pass context via DMs, groups, and files. Landing page: “Noted for next time… Updated memory for Account Manager.” Duplicate does **not** copy memory. | Bots doc; [x.ai/bot](https://x.ai/bot) |
| **Teach by watching** | “Ask a Bot to follow along as you complete a workflow once. It saves it as a routine.” | [x.ai/bot](https://x.ai/bot); launch 11 Aug |
| **Share** | Public share link → preview on x.ai → **Add to Grok Bot**. Copies config (identity, description, skills, routines). **Does not copy computer, logins, or history.** Link is public. | Bots doc |
| **Search / command palette** | Jump Bots/groups, messages, files, links, routines, settings. Availability “can vary during rollout.” | chat doc |

### Progressive disclosure: chat is primary, **not** the only surface

Documented **non-chat surfaces**:

- Sidebar roster (pin/hide)  
- **Edit Profile** form  
- **Settings → Plugins** marketplace  
- **Settings → General → Agent** (local execution)  
- **Settings → Agent timezone**  
- **View conversation details → Routines** (schedule, test, history)  
- Command palette / search  
- Computer viewer (“You’re in control / Working”) on the marketing page  
- Enterprise **admin dashboard** (access, network, audit) as of 3 Sep 2026  

So: **chat-first onboarding**, then **settings / profile / routines / admin** as the work becomes standing. That is progressive disclosure, not chat-only. What is *missing* vs a workflow product: no visual DAG editor, no first-class approval **inbox** in the docs I fetched (approvals live **in the transcript**).

---

## 5. What early users praise and complain about (X + reviews)

### Praise (handles + dates)

| Who | When | What they said |
|---|---|---|
| **Mo Bitar**, [atmoio.substack.com](https://atmoio.substack.com/p/i-went-in-ready-to-hate-grok-bot) | **25 Aug 2026** | Went in ready to hate it; now runs **eight** assistants. The jump is “from **iMessage to Slack**”: one contact → a **team**. Computer-use replaces MCP plumbing. |
| **@joelau2023** (Joel Walters) | **7 Sep 2026** | “My chief of staff just made a new agent. TikTok specialist… once a day… I post manually. Mind blown.” |
| **@Reimagine2026** | **7 Sep 2026** | Chief = PM; other Bots = module leads; user only talks to the manager. Solves **lost context across sessions**. |
| **@MarikWeb3** | **7 Sep 2026** (and 5 Sep article) | Playbook: install → **create CHIEF first** → other job titles → watch one real task → Telegram brief at 07:00 → **schedule last**. |
| **@GergelyOrosz** | **7 Sep 2026** | Gold-rush category now: **“Chief of AI” agents (Grok Bot clones).** |
| **Lauren Tan** (SpaceXAI / ex-Cursor), quoted by **@0xCodez** | **1 Sep 2026** | “Most powerful agentic tool we have ever shipped, **but only 1% of users use it correctly.**” She runs **15+** agents: Chief + 3 managers + 11 workers. |
| Internal quotes in launch post | **11 Aug 2026** | Roman: “90% vs 100% done.” Fiona: “like bringing on a coworker. No automations to set up.” Bennett: “2–3x more efficient.” Emma: stopped micromanaging after they asked why she kept asking questions. |

### Complaints / failure modes

| Who | When | What |
|---|---|---|
| **@Robokoch56** (Alexander Koch) | **7 Sep 2026** | Tried to let a Bot post on Kleinanzeigen; **Chief reported the cloud box IP is Cloudflare-blocked**. Asks if German sites fail generally. |
| **Continuum review** [continuumcode.ai](https://continuumcode.ai/guides/grok-bot-review/) | **22 Aug 2026** | Best first-run in the category; **do not point it at anything regulated.** Launch-week: Bots **loop talking to each other** before stopping. Shared-machine + Cursor dependency “will not change.” Verdict: try if you already pay; don’t buy a plan *for* it. |
| **@0xCodez / Lauren Tan** | **1 Sep 2026** | Power is real; **almost nobody sets it up as a team.** Closing the laptop = unused product. |
| **Cortex Gateway** (IT/auditor note) | **17 Aug 2026** | Sign-ins from a **US datacenter VM outside device-trust**; promised audit view “doesn’t exist yet” *at that date* (enterprise audit shipped **3 Sep** — later than this piece). Killing a computer **keeps durable disk**. Downstream systems **cannot tell employee from Bot**. |

### What reviewers **call** it
- **“iMessage to Slack” / Slack-for-a-team-of-bots** — Mo Bitar, 25 Aug 2026.  
- **“iMessage-style AI system that displays agents as teammates”** — [9to5Mac](https://9to5mac.com/2026/09/04/spacexai-expands-grok-bot-to-ipad-as-access-expands-to-cheaper-plans/), 4 Sep 2026.  
- **“Chief of AI” agents** — Gergely Orosz, 7 Sep 2026.  
- **“An AI that works like a teammate. Not a chatbot.”** — SuperGrok marketing, 29 Aug 2026.

**“Normie tier”:** I searched X and the web for that phrase tied to Grok Bot and **did not find a sourced use**. Do not treat it as a known nickname.

---

## 6. Known limits

| Limit | Fact | Source / date |
|---|---|---|
| **Platforms** | Dedicated apps; **not** grok.com chat. iPad late; Android 2 Sep. Linux is coverage-only (terminal), not on the current download hero. **No on-prem / no customer image.** | [x.ai/bot](https://x.ai/bot); security FAQ **3 Sep 2026** |
| **Roster** | **50** Bots + group chats combined. Groups **2–6** Bots. | Bots + chat docs |
| **Computer isolation** | **All Bots of one user share one computer and its logins/files.** Per-Bot is not a security boundary. Hide ≠ pause. Delete Bot ≠ wipe computer files. | Bots doc; approvals doc; security FAQ 3 Sep |
| **IdP / device trust** | Bot computer is **unmanaged Linux**; **Okta FastPass / MDM / compliant-device rules fail** in the computer browser. Admins must add a **scoped exception**. Grok Bot **sign-in** still uses Cursor SSO on the **member’s** device. | [identity and access](https://docs.x.ai/grok-bot/identity-and-access) **3 Sep 2026** |
| **Data residency** | Computers run **in the United States today**. Written residency = talk to account team. | security FAQ **3 Sep 2026** |
| **Privacy mode** | **Requires data storage; Legacy Privacy Mode not supported.** Training opt-out follows Cursor account settings. | approvals/security ~2 Sep 2026 |
| **Enterprise controls (since 3 Sep)** | Access, network, audit; Auto Review; admin can terminate a member’s computer (disk kept, next session is a fresh VM on that disk). Pricing unpublished. Two-week free window for existing Enterprise. | [Grok Bot for Enterprise](https://x.ai/news/grok-bot-for-enterprise) 3 Sep; security FAQ |
| **API** | **No first-party Grok Bot product API** in official docs fetched. xAI API is the **model** API; Enterprise FAQ even **forbids using the xAI API to run a competing service**. Community directories (botteams) are unofficial. | [x.ai/legal/faq-enterprise](https://x.ai/legal/faq-enterprise/); docs.x.ai grok-bot set |
| **Computer-use in the wild** | Datacenter IPs get **blocked** (Cloudflare / classifieds). | @Robokoch56, 7 Sep 2026 |
| **Bot-to-bot media** | Group handoff messages are **text-only**; send images in a **direct** Bot-to-Bot message if the teammate must inspect them. | chat doc |
| **Search** | Cross-conversation search “can vary during rollout.” | chat doc |
| **Voice / per-Bot credentials / EU region / on-prem** | Not offered as of these docs. | — |

---

## 10-line designer summary (one minute)

1. Grok Bot is a **messenger of named employees**, each with a job, not a single omni-chat.  
2. First-run is **New → Create agent → Edit Profile → give it a task** — form for identity, chat for work.  
3. The sidebar is an **org chart** (Chief, Sales Outbound, Talent Scout, Expense…); groups are **named rooms of 2–6 Bots**.  
4. Assign with **`@Bot`**; invoke skills with **`/`**; the transcript is the **status + approval surface**.  
5. Standing work **graduates** from chat → **skill → routine → Routines panel** (true progressive disclosure).  
6. Power is a **shared cloud computer** (browser/FS/terminal) that signs into real tools, including no-API sites.  
7. **Consent is copy + interrupts**, not a vault: “never send without approval” lives in the description; sends still happen in the thread.  
8. Memory is **per-Bot narrative**; **credentials are not** — every Bot on the user shares logins.  
9. People love **Chief + specialists** and hate **IP blocks, agent loops, and treating it like ChatGPT**.  
10. Enterprise (US-only VM, Cursor SSO, Auto Review) arrived **3 Sep 2026**; there is **no Bot API**.

## One-line verdict for Oneiron

**Steal** the named-role sidebar, group-chat as visible handoff, chat-first teaching that **opens** a profile/routines/settings layer, and an explicit **Chief** coordinator; **avoid** pooling every agent onto one credentialed computer, burying consent only in chat transcripts, and shipping computer-use from a shared US IP with no per-agent vault or inbox of pending gates.
