# Product study: SQUAD (`squad.so`)

**Audience:** design team. **Method:** first-party pages and docs, plus public X. **Retrieved:** 7 Sep 2026. **Not used:** local skills, subagents. **Confusion to avoid:** this is **not** Squads Protocol (`squads.xyz`, Solana multisig, $5.7M round). That is a different company.

**Source reliability:** Squad’s own site and docs are primary. Their Grok Bot comparison pages are commercially interested. X quotes are attributed. Where two first-party pages disagree, both are listed.

---

## 1. What it is

| Fact | Source | Date |
|---|---|---|
| **Product:** “AI teammates that connect to all your tools, understand your context, and take action to get your work done on schedule.” Bring-your-own ChatGPT / Claude / SuperGrok (and more). | [squad.so](https://squad.so/) | Fetched 7 Sep 2026 |
| **Legal/org name in schema:** Organization “Squad”; also MissionControlHQ, MCHQ, Mission Control HQ, Mission Control. | Homepage JSON-LD | Fetched 7 Sep 2026 |
| **Former name:** MissionControlHQ until **August 2026**, then Squad. Same product, same team. | [squad.so FAQ](https://squad.so/) (“Weren’t you called MissionControlHQ?”) | Fetched 7 Sep 2026 |
| **Founding date in schema:** 2026. | Homepage JSON-LD `foundingDate` | Fetched 7 Sep 2026 |
| **Founders in schema:** **Bhanu Teja Pachipulusu** (X `@pbteja1998`, GitHub `pbteja1998`); **Sai Dheeraj Pachipulusu**; **Thibault Louis-Lucas** (Tibo). | Homepage JSON-LD `founder` | Fetched 7 Sep 2026 |
| Bhanu is presented as founder of Squad (formerly MissionControlHQ) and of SiteGPT. | [squad.so/resources/grok-bot-alternative](https://squad.so/resources/grok-bot-alternative) author block | Article 19 Aug 2026; modified 6 Sep 2026 |
| Tibo: co-founder credit on homepage; previously sold Tweet Hunter / Taplio (self-described “$10m”); co-founder of Revid.ai, Outrank.so, PostSyncer. | [squad.so](https://squad.so/) testimonial; [X bio @tibo_maker](https://x.com/tibo_maker) | Fetched 7 Sep 2026 |
| **How Tibo joined:** paying MissionControlHQ user since **May 2026**; “partnering up with them on distribution and product”; rename to Squad because “MissionControlHQ described the dashboard. Squad describes the thing a user actually wants.” | [@tibo_maker thread](https://x.com/tibo_maker/status/2095449430619009085) | 3 Sep 2026 |
| Bhanu and Dheeraj “bootstrapped SiteGPT before this.” | Same Tibo thread | 3 Sep 2026 |
| **Funding:** no public equity round, Crunchbase-style raise, or investor list found for Squad.so / MissionControlHQ in this pass. Treat as **bootstrapped / indie** unless a later filing appears. Do not use Squads Labs’ $5.7M (that is `squads.xyz`). | Search + first-party pages; contrast [squads.xyz blog](https://squads.xyz/blog/squads-labs-raises-strategic-round) | Round post 14 Apr 2026; Squad.so pages fetched 7 Sep 2026 |
| **Public Squad.so launch / rebrand:** Tibo, “I’m going against Grok Bot / excited to announce squad.so” — 1,401 likes, ~747k views. | [X 2095449430619009085](https://x.com/tibo_maker/status/2095449430619009085) | 3 Sep 2026 |
| Tibo’s claim of prior art: “a few weeks ago xAI shipped Grok Bot… that’s the architecture @pbteja1998 has been building for a year with his brother @saidheeraj_96, as MissionControlHQ.” | Same thread, follow-up tweet | 3 Sep 2026 |
| **Grok Bot launch (category comparator):** 11 Aug 2026, early beta. | [The Verge](https://www.theverge.com/ai-artificial-intelligence/978666/spacexai-grok-bot-ai-agent-beta-launch); Squad’s own recap | Verge 12 Aug 2026; Squad article 19 Aug 2026 |
| **Who it is for (stated):** non-coders who can brief a new hire; founders / operators / SMBs. Homepage logos include Animoca Brands, Tavus, Pepper Content, Revid.ai, Outrank, SiteGPT, clinics, agencies. Testimonials include 12- and 17-agent workspaces. | [squad.so](https://squad.so/) | Fetched 7 Sep 2026 |
| **Pricing:** **$99/month** flat, 7-day money-back, cancel anytime. Plus the customer’s own AI plan (ChatGPT **$100–$200/mo recommended**). No per-task AI markup from Squad. | [squad.so](https://squad.so/), [squad.so/pricing](https://squad.so/pricing) | Fetched 7 Sep 2026 |
| Optional extras: research-tool **credits** (1,000 free/month, then **$5 / 5,000**); extra agent email inboxes **$10/month each**. | Homepage FAQ; [docs/costs-credits](https://squad.so/resources/docs/costs-credits) | Fetched 7 Sep 2026 |
| All-in they advertise: **$199–$299/mo** (Squad + recommended ChatGPT). | [why-missioncontrolhq](https://squad.so/resources/why-missioncontrolhq) | Page dated 11 Jul 2026; prices “as of August 2026” |
| **Unlimited named teammates** on the $99 plan. | Homepage pricing block | Fetched 7 Sep 2026 |
| **Platforms (homepage footer):** Web; **iOS, iPad, Mac, Android = “coming soon.”** Talk channels listed: Web, Telegram, Slack, Discord, Email. | [squad.so](https://squad.so/) | Fetched 7 Sep 2026 |
| **Platforms (docs FAQ, conflicting):** “the Squad (formerly MissionControlHQ) iOS app is on the App Store.” Telegram optional; Discord via Settings. | [docs/faq](https://squad.so/resources/docs/faq) | Updated 6 Sep 2026 |
| Contacts: `support@squad.so`; older docs still say `support@missioncontrolhq.ai`. | Homepage JSON-LD; [docs/provisioning](https://squad.so/resources/docs/provisioning) | Provisioning updated 5 Sep 2026 |
| Social: [x.com/squad_so_](https://x.com/squad_so_), LinkedIn company/squad-so. | Homepage JSON-LD `sameAs` | Fetched 7 Sep 2026 |

---

## 2. The interaction model

This is a **named-roster + group chat + mission board**, not chat-only.

### Sidebar of named agents

Homepage demo workspace “Harbor & Pine” shows **YOUR SQUAD** with named roles and live status:

- **Atlas** — routing the morning’s work (lead)
- **Tessa** — overdue invoices
- **June** — drafting overnight client emails
- **Milo** — content calendar submitted for review
- **Ray** — vendor quotes

Each row shows a working count. Source: [squad.so](https://squad.so/) live demo chrome, fetched 7 Sep 2026.

Docs: left sidebar holds the **squad roster**, then **group chats** under it, Squad channel pinned first. Source: [docs/chat-squad](https://squad.so/resources/docs/chat-squad), modified 20 Aug 2026.

### Group chats and the Squad channel

| Behavior | Source | Date |
|---|---|---|
| Talk to **one agent, a group, or the whole squad**. | Docs index + chat-squad | Modified 20 Aug 2026 |
| Start a group from any agent’s composer via **Group**, or @mention someone into a 1:1 — it becomes a group and **keeps recent history**; both threads stay linked. | [chat-squad](https://squad.so/resources/docs/chat-squad) | 20 Aug 2026 |
| **📣 Squad channel:** one message to every active agent; @mention narrows it. Bell shows who was reached. | Same | 20 Aug 2026 |
| In a multi-agent group, **only @mentioned agents must answer**; others may stay silent. | Same | 20 Aug 2026 |
| Agents **DM each other**. Those DMs appear under **Agent conversations** (one row per pair). You can open and type in. | Same | 20 Aug 2026 |
| Archive groups (not the Squad channel). Rename with pencil. | Same | 20 Aug 2026 |
| Every user message starts a **thread**. Threads can be named. | Same | 20 Aug 2026 |
| Rule of thumb in docs: **direction → chat; decisions → tickets; announcements → Squad channel.** Standing policy → docs, because “chat scrolls away.” | Same | 20 Aug 2026 |
| Pinned conversation panel docks on the right across screens. | Same | 20 Aug 2026 |
| `#` links a doc (agent reads it). File attach in composer. Mentions highlight only if they resolve. | Same | 20 Aug 2026 |

Homepage also labels a **GROUP CHATS** block: “Squad chat” and “Fall promo war room.” Source: [squad.so](https://squad.so/).

### Mentions and task assignment inside chat

| Behavior | Source | Date |
|---|---|---|
| “An @-mention in squad chat **triggers the mentioned agent’s run**. So do schedules and inbound email.” | [why-missioncontrolhq](https://squad.so/resources/why-missioncontrolhq) | 11 Jul 2026 |
| Composer highlights real @mentions by full name. | [chat-squad](https://squad.so/resources/docs/chat-squad) | 20 Aug 2026 |
| Mission cards have **Chat about it** — opens chat with that mission attached as context. Board has a Chat tab. | Same | 20 Aug 2026 |
| Day-in-the-life: user dumps three jobs; **Jarvis** (lead) splits to Tessa / June / Milo. | [squad.so](https://squad.so/) | Fetched 7 Sep 2026 |
| Tibo: “you don’t manage your AI teammates, your Chief does… it routes it to the right teammate. if the job needs someone new, it spins another teammate up.” | [X thread](https://x.com/tibo_maker/status/2095449430619009085) | 3 Sep 2026 |

Work also assigns **outside** chat: mission board queues (“Queued for Milo”), schedules, inbound agent email.

### How finished work is reported

Not “the bot pings you in a DM and that’s the product.” Several surfaces:

| Surface | What the user sees | Source | Date |
|---|---|---|---|
| **Mission board** | Columns: Backlog / Needs you (blocked) / In flight / Done. Cards show owner, recency, chat count, tags. Demo: “4 done today, 1 need you.” | [squad.so](https://squad.so/); [docs/missions-board](https://squad.so/resources/docs/missions-board) | Fetched 7 Sep 2026 |
| **Status on the agent row** | “Content calendar submitted for review”; “Drafting replies…” | Homepage demo | 7 Sep 2026 |
| **Tickets / “Needs you”** | Approval cards: draft email, Approve and send / Edit. “My Tickets.” | Homepage; [docs/tickets](https://squad.so/resources/docs/tickets) | 7 Sep 2026 |
| **Chat replies** | “answers, links to docs they wrote, cards for emails they drafted.” | [chat-squad](https://squad.so/resources/docs/chat-squad) | 20 Aug 2026 |
| **Docs library** | Deliverables as living documents. | Homepage; [docs/docs-guide](https://squad.so/resources/docs/docs-guide) | Docs index fetched 7 Sep 2026 |
| **Agent inbox** | Work arriving at 7:00 AM; per-agent addresses. | Homepage | 7 Sep 2026 |
| **End-of-day digest** | “One end-of-day digest” from Squad/Sana. | Homepage “One day with Squad” | 7 Sep 2026 |
| **Runs / activity log** | Every execution: trigger, duration, token cost, tools touched. “Receipts.” | [docs/runs-guide](https://squad.so/resources/docs/runs-guide); homepage “Receipts” | Docs index 7 Sep 2026 |
| **Status timeline per agent** | Called out vs Grok Bot scrollback. | [grok-bot-alternative](https://squad.so/resources/grok-bot-alternative) | Updated 5–6 Sep 2026 |

### Lead / manager agent

Yes, first-class.

- Docs call it **Lead Agent** / **AI Chief of Staff**. Onboarding is a conversation with it. [docs/talk-to-your-lead](https://squad.so/resources/docs/talk-to-your-lead), modified 20 Aug 2026.
- [docs/meet-squad](https://squad.so/resources/docs/meet-squad) (index blurb): “the lead agent that coordinates, the specialists that own lanes.”
- Demo name **Atlas** (“Routing the morning’s work”). Narrative names **Jarvis**. Customer quote: “I named him Jerry.”
- Lead **designs the roster**, **creates specialists**, **sets first tasks**, **routes**, **can spin up a new teammate**, **reports what’s running / done / needs you**.
- Grok Bot comparison: Grok Bot gives an empty sidebar you fill; Squad’s lead interviews you and proposes named roles. [grok-bot-alternative](https://squad.so/resources/grok-bot-alternative), 19 Aug / 6 Sep 2026.

---

## 3. How an agent is created and set up

**Primary path: conversation with the Lead, not a blank form.** Templates exist as use-case starters, not as the first-run org chart.

### Documented steps

**A. Before chat**

1. **Connect an AI provider** on the setup page (ChatGPT recommended; also Claude, Claude Code, Grok/SuperGrok, Gemini, Copilot, Kimi, MiniMax, Z.AI, Qwen Cloud, OpenRouter, Cloudflare Workers AI, OpenCode). No token markup. [docs/connect-your-ai](https://squad.so/resources/docs/connect-your-ai), updated **6 Sep 2026**.
2. **Provisioning (~5 min)** after credentials: workspace → install agent runtime (2–3 min) → connect provider → add channels/memory/usage tracking → start agents → workspace defaults → security checkpoint. [docs/provisioning](https://squad.so/resources/docs/provisioning), updated **5 Sep 2026**.
3. Success screen: remaining provider connect (if needed) + dashboard button.

**B. Onboarding chat (required)**

“Your squad isn’t ready until you complete onboarding: a ~10 minute conversation.” [provisioning](https://squad.so/resources/docs/provisioning), 5 Sep 2026.

[Talk to Your Lead](https://squad.so/resources/docs/talk-to-your-lead) (modified 20 Aug 2026) lists exact Lead moves:

1. Introduce themselves; ask what to call you  
2. Learn company, customers, goals  
3. What’s eating your time  
4. **Design the squad**; you choose names and themes  
5. **Create specialist agents**  
6. **Set up initial tasks** so work starts immediately  

Duration: **10–15 minutes**. After that, Lead creates specialists, **sets schedules**, creates tasks, “starts working immediately.” Then you monitor on the dashboard.

Sample: Lead proposes a content specialist from a “content is eating my time” answer — **role design is conversational**, not a checkbox matrix.

Homepage FAQ: “Your AI Chief of Staff learns your business and designs the squad with you. You can hire, rename or retire AI teammates whenever you like.” Fetched 7 Sep 2026.

**C. Teaching a job after hire (demo, homepage)**

“Teach a task”: name it → **drive the agent’s browser once while it watches** → it writes an SOP/skill → you edit/approve. “Clicks and typed values are captured. Passwords and one-time codes never are.” Guardrails (e.g. “Over $500 needs your yes”) are in the generated skill. Fetched 7 Sep 2026.

**D. Use-case starters (not first-run roster)**

Homepage “Create your own” plus featured jobs (invoice chaser, inbox triage, weekly report, cold outreach, Shopify issues, support, meeting notes, release QA, competitor watch, personal bookings). These are **job shapes**, not a template gallery of personality bots. Fetched 7 Sep 2026.

### What is configured (tools, sign-ins, schedule, permissions, voice)

| Config | How / where | Source | Date |
|---|---|---|---|
| **Model** | Workspace default; **per agent** and **per schedule** override; ordered **fallback models** | [docs/tokens-models](https://squad.so/resources/docs/tokens-models) | Updated 6 Sep 2026 |
| **AI accounts** | Settings → AI Tokens; stack multiple accounts; priority = fallback chain; sync banner if creds haven’t reached every agent | Same | 6 Sep 2026 |
| **Tools / integrations** | 70+ apps; **any MCP server** (paste URL or JSON); 53 research/scrape tools on by default | [squad.so](https://squad.so/) | 7 Sep 2026 |
| **Sign-ins** | Each teammate: **own browser profile**, own logins/files by default; can share a login when told | Homepage; Tibo thread | 7 Sep / 3 Sep 2026 |
| **Connection scopes** | Per teammate: read-only vs read+write vs none, without re-auth | Homepage; grok-bot-alternative | 7 Sep / 6 Sep 2026 |
| **Secrets** | Vault on the squad’s dedicated computer; read at runtime; **never shown in thread**; “write-only (readable by tools, never displayed back)” | Homepage FAQ; [docs/safety-control](https://squad.so/resources/docs/safety-control) | 7 Sep 2026 |
| **Schedule** | Recurring jobs, heartbeats, stagger, timeouts; Lead sets initial ones | [docs/schedules-heartbeats](https://squad.so/resources/docs/schedules-heartbeats); talk-to-your-lead | Docs index 7 Sep 2026 |
| **Email** | Per-agent inbox/address; $10/mo add-on; allow/block lists; send caps; draft/escalation states | Homepage; [docs/email-guide](https://squad.so/resources/docs/email-guide); costs-credits | 7 Sep 2026 |
| **Caps** | Daily send caps; credit auto-recharge max; schedule timeouts — platform-enforced | [safety-control](https://squad.so/resources/docs/safety-control) | Fetched 7 Sep 2026 |
| **Telegram / Discord** | Optional, Settings; never required at setup. Discord: DMs from allowed people + @mention in server | [docs](https://squad.so/resources/docs); FAQ 6 Sep 2026 | |
| **Skills** | Procedures packaged once, tagged into a **squad-wide** library (not per-agent scoped) | [docs/skills-guide](https://squad.so/resources/docs/skills-guide); grok-bot-alternative | 6 Sep 2026 |
| **Voice (speech)** | **Not documented** as a setup field (no TTS/voice ID in homepage, connect-your-ai, talk-to-your-lead, or docs index). “Voice” on-site means writing voice / SOP tone. | Docs index + homepage | 7 Sep 2026 |
| **Personality / name / theme** | Chosen with Lead during onboarding; hire/fire anytime | talk-to-your-lead; homepage | 20 Aug / 7 Sep 2026 |

Exact Grok connect steps (example of a sign-in, not a form-built agent): Settings → AI Tokens → Sign in with Grok → approve code on grok.com. [connect-your-ai](https://squad.so/resources/docs/connect-your-ai), 6 Sep 2026.

---

## 4. What runs beyond chat

**Chat is the briefing surface. It is not the only surface.** Progressive disclosure is real: onboarding is chat; ongoing work is **board + tickets + runs + docs + settings**.

| Capability | Detail | Source | Date |
|---|---|---|---|
| **Scheduled / continuous** | “Do agents work while I’m offline? Yes — schedules, heartbeats, and email handling run around the clock.” | [docs/faq](https://squad.so/resources/docs/faq) | 6 Sep 2026 |
| **Computer-use** | Dedicated **cloud computer** per squad; **separate browser profile per teammate**; agents sign into sites; “Take over her screen and do the task once while she watches.” | Homepage | 7 Sep 2026 |
| **Credentials** | Vault on that computer, “rather than in a shared database.” Keys not pasted in chat. | Homepage FAQ | 7 Sep 2026 |
| **Approvals / consent** | Outbound (customer/vendor/team) waits for yes. Draft-for-review **enforced at send time**, not honor-system. Tickets block spend/customers/direction. **Pause always works** (platform stop). Trust ladder: draft everything week one → auto-handle earned categories → keep tickets for money and customers. “Nothing graduates itself.” | Homepage; [safety-control](https://squad.so/resources/docs/safety-control) | 7 Sep 2026 |
| **Memory** | “Shared context graph and memory from every conversation and every app.” Docs page: inspect, correct, wipe; memory vs docs. | Homepage; [docs/memory-guide](https://squad.so/resources/docs/memory-guide) | Index fetched 7 Sep 2026 |
| **Workflows** | Describe a multi-step job once (changelog → rewrite → draft email, hold for yes). Skills from recordings. Playbooks (support autopilot, inbox zero, content engine, Monday report, etc.). | Homepage; docs playbooks | 7 Sep 2026 |
| **Automation surfaces besides chat** | Mission board, schedules, email inboxes, Telegram, Discord, Slack, tickets, Cmd+K palette, notifications (Settings → Notifications), Billing/credits, AI Tokens, Integrations & secrets. | Docs index | 7 Sep 2026 |
| **Team visibility** | Board/threads/run log in shared workspace; **read-only share link** for clients. Human teammates message via **Telegram allowlist**, not a full multi-seat console. | Homepage FAQ; [docs/public-team](https://squad.so/resources/docs/public-team) | 7 Sep 2026 |
| **Isolation** | “Dedicated, isolated workspace on its own computer.” Per-agent browsers. | Homepage FAQ | 7 Sep 2026 |
| **Self-host** | “Talk to us. Self-hosted and isolated deployments are handled case by case.” | Homepage FAQ | 7 Sep 2026 |
| **Export on cancel** | “SOPs and run history are yours to export.” | Homepage FAQ | 7 Sep 2026 |

**Progressive disclosure (design-relevant):**  
Setup → provisioning spinner → **Lead chat** (creates the org) → **dashboard** (board, tickets, feed). Chat panel **docks** while you move across screens. Settings exist for tokens, Telegram, Discord, notifications, integrations. This is **chat-first operations**, not chat-only.

---

## 5. Versus Grok Bot, and what X says (including “copycat”)

### Feature-by-feature (Grok Bot facts from xAI + Verge; Squad from first-party)

Grok Bot launched **11 Aug 2026** in early beta: named “AI teammates,” shared cloud computer, sign into tools, come back when done or when approval is needed, bots message each other, group chat, one bot can manage others. Desktop + iOS for SuperGrok Heavy / Cursor Ultra / Cursor Teams Premium; teams/enterprise waitlist. [The Verge, 12 Aug 2026](https://www.theverge.com/ai-artificial-intelligence/978666/spacexai-grok-bot-ai-agent-beta-launch).

xAI FAQ (quoted by Squad, fetched 19 Aug 2026; security docs re-checked 3 Sep 2026): **every bot shares one cloud computer**; isolation is **per user, not per bot**; “Do not use separate Bots as a security boundary.” [x.ai/bot](https://x.ai/bot), [docs.x.ai/grok-bot/approvals-security-and-privacy](https://docs.x.ai/grok-bot/approvals-security-and-privacy).

| | **Grok Bot** | **Squad** |
|---|---|---|
| **Pitch** | Named AI teammates + group chat + cloud PC | Same shape, plus board/tickets/lead-designed roster |
| **Entry price** | Included with Cursor Ultra **$200/mo** or SuperGrok Heavy **$300/mo**; Premium Teams **$120/seat**; free tier to start (xAI, as of 19 Aug 2026) | **$99/mo** + your AI plan (**~$199–299** all-in) |
| **Model** | xAI models only, bundled | BYO, 13 providers **including Grok**; per-agent model |
| **At quota** | Wait for reset or per-token overage | Stack accounts / fallback chain mid-task |
| **Roster design** | You fill an empty sidebar (templates exist in Grok Bot: copy a bot in one tap — [Hangar](https://hangar.grok.me/learn), 28 Aug 2026) | Lead interviews you (~10 min) and **proposes** named roles |
| **Lead / chief** | You typically create a Chief of Agents first (xAI / Hangar practice) | **Built-in** Lead / Chief of Staff |
| **Work surface** | Chat threads, group chats | Chat **plus** mission board, tickets, per-agent timeline, docs, runs |
| **Group chat** | Yes; one review said routines could not be saved from group chats | Yes; Squad channel + agent-to-agent DMs visible |
| **Mentions** | Bots in a thread pass work | @mention **starts a run**; also schedules + email |
| **Computer** | **One shared** machine for all bots | One machine **per customer**; **browser per agent** by default |
| **Sign-in model** | One sign-in inherited by every bot | Separate logins by default; share optionally |
| **Email to an agent** | Not a documented trigger (Slack/Git/Teams/Linear/Sentry/PagerDuty + schedules, per Squad’s Aug 2026 reading of xAI) | Per-agent inbox, **$10/mo** |
| **Approvals** | Per-action on sends/posts (xAI) | Board-level ticket queue, send caps, draft-for-review **at send time** |
| **Secrets** | Shared-machine logins | Vault; never in thread |
| **Skills scope** | Shared across bots | Library also **squad-wide** (same limitation) |
| **Cost receipts** | Not per-agent (Squad’s claim) | Per-run model/token ledger |
| **Share with a human** | — | Read-only dashboard link |
| **Setup time** | Near-zero if you already pay for Ultra/Heavy | Connect AI (~credential) + 5 min provision + 10–15 min Lead chat |
| **Who ships first (claimed)** | Public product 11 Aug 2026 | Tibo: architecture built “for a year”; he paid from **May 2026**; public **Squad** name 3 Sep 2026 |

Independent-ish recap (commercially picks Squad): Northbound Studio, **4 Sep 2026** — “Until August 2026 it was MissionControlHQ. Same product.” [northboundstudio.io/en/blog/squad-so-review](https://northboundstudio.io/en/blog/squad-so-review).

### What X users actually said

**The launch frame is competitive, not “we copied them.”** Tibo opened with **“I'm going against Grok Bot”** (3 Sep 2026, [2095449430619009085](https://x.com/tibo_maker/status/2095449430619009085)), then argued MCHQ **predated** Grok Bot.

**Similarity, not theft — quoted:**

> “haven't used it but i believe @squad_so_ is similar to grok bot. created by @tibo_maker / @pbteja1998”  
> — **@Imbkr** (Karthik Bonthu), 3 Sep 2026, [2095573276491669520](https://x.com/Imbkr/status/2095573276491669520)

> “I am going to test @squad_so_ first / Hopefully the will build something similar to Grok Bot that is LLM agnostic.”  
> — **@ninan99**, 5 Sep 2026, [2096079457530618056](https://x.com/ninan99/status/2096079457530618056)

> “always have the guts to go against the giants! this is amazing, was about to go for grok bot now i changed my mind lol ! lets go https://squad.so”  
> — **@joemyoya**, 4 Sep 2026, [2095823119491465590](https://x.com/joemyoya/status/2095823119491465590)

> “Grok Bot, now https://Squad.so Ai never stops, truly lol !”  
> — **@luisguimontmota**, quoting Tibo, 3 Sep 2026, [2095650241357730039](https://x.com/luisguimontmota/status/2095650241357730039)

**Copycat accusation: not found as a high-engagement pile-on in this pass.** Searches for copycat / clone / ripoff / carbon copy against `squad.so` / `@squad_so_` returned:

- People building **other** “Grok Bot clones” (e.g. **@jamesvanderhaak**, 7 Sep 2026, open-source “Botex”; **@LLMpsycho**, 7 Sep 2026, “I've been running a Grok Bot clone”).
- No viral post in this sample that says “Squad stole Grok Bot’s UI.”

**Design takeaway on the accusation:** the **IA is the same category object** (sidebar of named agents, group chat, chief of staff, computer-use, come back with finished work). Timeline: **MCHQ product claimed from ~2025–May 2026; Grok Bot public 11 Aug 2026; Squad rebrand and “going against Grok Bot” marketing 3 Sep 2026.** So: **parallel category + opportunistic rename**, not a documented clone of a prior public Grok Bot. The **homepage chrome after 3 Sep** (named roster, group chats, “submitted for review”) is visually in the same family as Grok Bot’s sidebar-of-roles. Treat “copycat” as **market talk about the interaction model**, not as a sourced IP claim.

Grok Bot shared-computer criticism on X (context for why Squad hammers per-agent browsers), verified by Squad 3 Sep 2026: [@nykdotdev](https://x.com/nykdotdev/status/2094659114248843377), [@xoleeep](https://x.com/xoleeep/status/2094819850484891868), [@Argona0x](https://x.com/Argona0x/status/2089005278758912413), [@MAXdeg0](https://x.com/MAXdeg0/status/2090852404157637036).

---

## 6. Known limits

| Limit | Evidence | Date |
|---|---|---|
| **No public API in docs.** Docs index has setup, board, chat, email, MCP, tokens — **no API reference**. | [squad.so/resources/docs](https://squad.so/resources/docs) | Fetched 7 Sep 2026 |
| Extensibility path is **MCP** (“paste a hosted URL or the JSON”) and a **partners** program (Tibo: 20% affiliate for a year at squad.so/partners). | Homepage; Tibo thread; X @grok reply 4 Sep 2026 | 3–7 Sep 2026 |
| **Not open-source.** Product is hosted. Open pieces are **customer-side**: BYO open models (Kimi, GLM, Qwen, Llama via Workers AI / OpenRouter), MCP, and a **SKILL.md**-style skills library (portability claimed in their Grok comparison). | Homepage; grok-bot-alternative | 6–7 Sep 2026 |
| **Platforms:** Web is real. iOS **contradicted** (FAQ: on App Store, 6 Sep 2026; homepage footer: “coming soon,” 7 Sep 2026). iPad/Mac/Android coming soon. Telegram/Discord/Slack/email as doors. | FAQ vs homepage | 6–7 Sep 2026 |
| **Enterprise controls are thin.** No SSO / SCIM / per-seat admin console in public pricing. Multi-human access = Telegram allowlist + **read-only** share link. Self-host “case by case.” Contrast: Grok Bot Premium Teams lists SSO (per Squad’s 19 Aug reading of xAI). | [docs/public-team](https://squad.so/resources/docs/public-team); homepage FAQ | 7 Sep 2026 |
| **Skills are squad-wide**, not a security boundary. | grok-bot-alternative | 6 Sep 2026 |
| **Email inboxes cost extra** ($10/mo each). | Homepage | 7 Sep 2026 |
| **$20 ChatGPT is explicitly too small** for squad workloads. | why-missioncontrolhq; tokens docs | Aug–Sep 2026 |
| Provisioning can hang on “Installing AI tools”; support still `@missioncontrolhq.ai` in that doc. | [provisioning](https://squad.so/resources/docs/provisioning) | 5 Sep 2026 |
| Customer exit quote on Claude Max blocking (reliability/vendor risk): Dan Thompson, Sterling Gap, “with them blocking Claude Max… it made more sense financially.” | Homepage testimonials | Fetched 7 Sep 2026 |
| **Voice agents:** not a documented product surface. | Docs index | 7 Sep 2026 |
| **No free trial** — 7-day money-back after payment. | Homepage FAQ | 7 Sep 2026 |

---

## 10-line summary (one minute)

1. **Squad is a $99/mo hosted “AI teammates” ops layer** (ex-MissionControlHQ, renamed Aug 2026; public “vs Grok Bot” push 3 Sep 2026) from Bhanu + Dheeraj Pachipulusu and Tibo; bootstrapped as far as public record goes.  
2. **You bring the brain** (ChatGPT/Claude/Grok/etc., stack + fallback); Squad sells coordination, a cloud PC, and a board.  
3. **IA:** left roster of named agents + group chats + 📣 Squad channel; work lives on a **mission board** with tickets, not only in scrollback.  
4. **Lead / Chief of Staff is the product:** it interviews you, names the team, routes, and can hire. You do not start from a blank form.  
5. **Create-by-chat, tighten-by-settings:** 5 min provision → 10–15 min Lead chat → later record-a-task, scopes, schedules, models. No voice-ID setup.  
6. **Finished work returns as cards, docs, Done columns, 7am inbox, and a digest** — plus a run ledger.  
7. **Consent is a ticket queue + send-time draft gate + daily caps + pause**, not a prompt that says “please don’t send.”  
8. **Memory is a context graph across chat + apps;** secrets sit in a vault on an isolated machine; each agent gets its own browser.  
9. **Versus Grok Bot:** same teammate metaphor; Squad adds BYO models, per-agent browsers, email inboxes, board/tickets; Grok Bot wins on zero setup and a shared machine if you already pay Ultra/Heavy.  
10. **Limits:** no public API, weak multi-seat/enterprise, skills not scoped, iOS messaging inconsistent, chat-first but **not** chat-only.

## Verdict for Oneiron

**Steal the Lead-interviewed roster, mission board + ticket consent gates, per-agent browser/scope, vault-not-chat secrets, and “finished work as a card/inbox not a speech bubble”; avoid cloning the Grok-like sidebar-as-the-whole-product, the chat-only org chart, squad-wide unscoped skills, and a rename-to-match-the-lab go-to-market.**
