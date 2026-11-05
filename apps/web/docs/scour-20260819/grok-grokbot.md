I'll search X and the web for practitioner accounts of Grok Bot's approval flow, teach-by-demonstration, multi-bot collaboration, and persistent panel state — vendor posts filtered out.Vendor and recap coverage is thick; next I’ll isolate first-person posts on approvals, teach-by-demo, multi-bot, and persistent state.Several first-person posts are usable. I’ll pull those threads plus practitioner write-ups and keep searching for Always-Allow / review-list language.I have first-person complaints on auto-review, thread UI, and multi-bot. Next I’ll open those posts and a few write-ups for exact quotes.Nick Gray’s review is the strongest first-person write-up so far. I’ll pull the HN thread, the bug-report replies, and a few more approval-specific posts.Practitioner evidence is thin and recent (beta launched **2026-08-11**; this sweep covers ~8 days). Almost everything below is first-person X, Reddit, HN, or a hands-on essay. Official docs, @xai/@grok/@bot, Cursor/SpaceXAI staff posts, and recap blogs are excluded unless a practitioner is quoting them.

**Named “review list” UI:** nothing found. Marketing on [x.ai/bot](https://x.ai/bot) says Sales Outbound “leaves a review list for you to approve.” No independent user described that inbox. What they describe instead is prompt fences, Auto-review rules, and Allow-once / Always-allow / Deny banners.

---

## What users praise

**Setup is fast enough that people actually start.**  
**Consensus (3+).** [@Loganullyott](https://x.com/Loganullyott/status/2089732997096595703) (2026-08-18): install → two recurring tasks automated in ~5 minutes; Claude/OpenAI stalled on permissions/login/cron; Hermes felt like an afternoon of tutorials. [@nickgraynews](https://x.com/nickgraynews/status/2089792062690668740) (2026-08-18): “insanely easy to set up”; no Mac Mini. [@Austen](https://x.com/Austen/status/2089710739862810911) (2026-08-18): “not being a pain in the ass to set up is pretty big.” r/AI_Agents [u/cornmacabre](https://old.reddit.com/r/AI_Agents/comments/1vnbg4z/grok_bot_just_validated_everything_weve_been/) (2026-08-16): first interface a “normie” would get; OAuth is “a simple click.”

**Persistent cloud computer + phone/laptop access.**  
**Consensus (3+).** [@petergyang](https://creatoreconomy.so/p/how-we-use-computers-is-about-to-change-forever-ai) (2026-08-12 essay): closest thing to “agents their own persistent cloud computer.” Same author on X (2026-08-17): “built in persistent cloud computer. UX is simple, focused, and delightful” ([comparison post](https://x.com/petergyang/status/2089442169509806152)). [@DillonLoomis](https://x.com/DillonLoomis/status/2089722135375692130) (2026-08-18): “I love the UI and simplicity and the persistent VM.” [@nickgraynews](https://x.com/nickgraynews/status/2089792062690668740): talk from phone and laptop, not tied to one device. HN [jjcm](https://news.ycombinator.com/item?id=49263241) (2026-08-11/12): each bot owns routines/context/domain; “async work feels like it actually works.”

**Teach-by-demonstration (“Teach a task”).**  
**Consensus among people who mention it (3+ praise; 0 found failure reports).** [@DailyDoseOfDS_](https://x.com/DailyDoseOfDS_/status/2089659158455034052) / Avi Chawla (2026-08-18): recorded a live pass scraping a newsletter; bot turned it into a skill, then a scheduled routine on the closed-laptop VM. [@mrfundman](https://x.com/mrfundman/status/2089760255890571404) (2026-08-18): video of teaching WordPress updates. r/AI_Agents [u/christophersocial](https://old.reddit.com/r/AI_Agents/comments/1vnbg4z/grok_bot_just_validated_everything_weve_been/) (2026-08-13): “nailed the hardest part, on-boarding real work via Teach-a-Task.” Vestra cofounder [u/NoSpecific64](https://old.reddit.com/r/AI_Agents/comments/1vnbg4z/grok_bot_just_validated_everything_weve_been/) (competitor, 2026-08-13): “Teach-a-task is brilliant… This kills the biggest cost in automation: specifying the workflow.”  
**Nothing found:** a practitioner saying teach-a-task recorded a workflow and then failed to replay it.

**Draft-first work with an explicit human gate (implemented as a prompt, not a product inbox).**  
**Anecdote, repeated as a pattern by two independent users.** [@petergyang](https://x.com/petergyang/status/2089724101070086482) (2026-08-18): Marie Kondo bot audits email/Drive/subs; “Do not move, delete, unsubscribe, or cancel anything without my approval.” [@lennysan](https://x.com/lennysan/status/2087241423792087518) (2026-08-11, early access, disclosed no financial tie): auto-reply support mail, scan card statements for cancelable subs, guest briefs — framed as “less scary” than OpenClaw.

**Natural-language Auto-review customization.**  
**Anecdote (1 hands-on + 1 agreement).** [@kr0der](https://x.com/kr0der/status/2088487100115276242) (2026-08-15): “i’m liking the Grok Bot auto-review rules… sometimes they block actions that are completely safe… customise these in natural language… so nice.” [@max_bevza](https://x.com/max_bevza/status/2088513975134691742) agreed NL rules matter.

**Multi-bot “chief of staff + specialists” when it works.**  
**Split, not consensus.** Early tester [@mattshumer_](https://x.com/mattshumer_/status/2087232424535117959) (2026-08-11): researcher + writer + CoS “worked out of the box.” [@therealjosh](https://x.com/therealjosh/status/2089376329586393271) (2026-08-17): manager bot over specialists after leaving Cowork; “moving quickly… still early.” HN [jjcm](https://news.ycombinator.com/item?id=49263241): bots communicate across domains; fabric-sourcing bot negotiated with ~40 Vietnam suppliers and handed a file to a prototyper bot.

**Choice chips as the consent surface.**  
**Anecdote.** [@nickgraynews](https://x.com/nickgraynews/status/2089792062690668740) (2026-08-18): “‘pick an option for what I should do’ is the correct upgrade for chat bot interface”; wants multi-choice closer to Claude’s AskUserQuestion.

---

## What users complain about — especially approvals and trust

### Approvals are either too loose or too sticky

**Specialist bots act without the human’s approval; CoS-as-router is not a control plane.**  
**Anecdote.** [@petecallaghans](https://x.com/petecallaghans/status/2089762470239866950) (2026-08-18): CoS watching a fleet, “those other bots are doing things I didn’t approve.” He told CoS to ask permission and route through him. Also: 20% of weekly usage on day 1, $200 already spent, on support/code/email only.

**Always Allow does not mean “stop asking.”**  
**Anecdote (2 independent, same week).** [@chrisvb](https://x.com/chrisvb/status/2089552073880993879) (2026-08-18): “Bot is not playing nice and with always allow permissions.” [@Rob_HCB](https://x.com/Rob_HCB/status/2088722966590677265) (2026-08-15, bug report to staff): Windows banner “Allow Grok Bot and all agents to run commands on your local computer?” — Always allow / Allow once / Never. Allow once and X do not dismiss it; persists across quit/reopen. User refused Always allow.

**Auto-review false-positives and post-update lockouts.**  
**Consensus (3+).** [@kr0der](https://x.com/kr0der/status/2088487100115276242): sometimes blocks safe actions. [@DarylAntony](https://x.com/DarylAntony/status/2088797735034208661) (2026-08-16): after 0.20, “commands couldn’t run because of auto-review”; turning Auto-review off fixed it. [@itswillandbill](https://x.com/itswillandbill/status/2089285028404679122) (2026-08-17): “Got a lot of auto review notifications” when the bot walked an email account in the browser. [@promptprobe](https://x.com/promptprobe/status/2089719420805677484) (2026-08-18): just turned Auto-review off. Practitioner tip from [@AYi_AInotes](https://x.com/AYi_AInotes/status/2089737633127669806) (2026-08-18): “先别开「永远允许」。发邮件、付钱、删除，一律要你点头” — don’t turn on Always Allow first; mail/pay/delete always need a nod.

**Local-computer consent is binary and opaque.**  
**Anecdote (2 independent).** [@interplanetary](https://x.com/interplanetary/status/2089797101761028504) (Chris Lewicki, 2026-08-18): “pretty much only a ‘Ask every time’ and ‘You have access to everything with no visibility for the user to what you did’. Access to read/optionally-write on a scoped-folder would be a big upgrade.” [@mfachallenge](https://x.com/mfachallenge/status/2089043491682984425) (Aaron Faby, 2026-08-16): if you want local commands gated, you must write an Auto-review rule yourself (“Run commands on my computer” → ask).

**Approval UI is not where the user is looking.**  
**Anecdote (2, same staff-bugs thread).** [@Adapt2Survibe](https://x.com/Adapt2Survibe/status/2088778738901434576) (2026-08-16): creating a thread looks like the chat was wiped (no way back to main); the “auto review paused this” card appeared in the *main* chat while he was staring at the thread’s three dots. [@kidandcat](https://x.com/kidandcat/status/2088750760649695340) (Jairo, 2026-08-15): sidebar shows “working” while the bot is actually waiting for approval.

**Rules don’t travel with the user.**  
**Anecdote.** [@mozap01](https://x.com/mozap01/status/2089111087203418547) (2026-08-16): running the bot on a Mac mini against local Chrome — “set auto-review there (laptop rules don’t carry over).”

**An approval does not undo work already done; there is no dry run.**  
**Anecdote (competitor reading docs + one practitioner restating the same fear).** Vestra cofounder [u/NoSpecific64](https://old.reddit.com/r/AI_Agents/comments/1vnbg4z/grok_bot_just_validated_everything_weve_been/p3g8up2/) (2026-08-13): “an approval doesn’t reverse work already completed… all your bots share one computer… xAI says outright not to treat bots as a security boundary. That’s their documentation.” [u/ParsnipThick40](https://old.reddit.com/r/AI_Agents/comments/1vnbg4z/grok_bot_just_validated_everything_weve_been/) (2026-08-13): trust is not happy-path completion; it is whether the agent pauses on the 10% that changes (renamed button, irreversible action) and leaves an audit trail.

**Named review-list / “Require-Approval always wins” as lived UX:** nothing found. Users never used those product names. They talk about Auto-review on/off, Always Allow, Allow once, and prompt text.

### Trust: credentials, shared machine, truthfulness, reliability

**Cloud-login hesitation is the adoption wall.**  
**Consensus (3+ independent, same claim).** [@petergyang](https://creatoreconomy.so/p/how-we-use-computers-is-about-to-change-forever-ai) (2026-08-12): friends say they “don’t trust AI enough to give it access to my email, calendar, and other apps”; he calls trust “the biggest barrier.” He hesitated entering a password on the *cloud* computer (would have typed it on his laptop); wants to know what the VM remembers, who can access it, how to revoke. r/AI_Agents [u/Sellingerrors](https://old.reddit.com/r/AI_Agents/comments/1vnbg4z/grok_bot_just_validated_everything_weve_been/) (2026-08-14): “The hardest part about this business is trusting the bot… especially with money.” [u/RRRASHERRR](https://old.reddit.com/r/AI_Agents/comments/1vm4tji/they_gave_the_ai_its_own_computer_and_it_can/p372a1m/) (2026-08-12): “‘own computer’ is the right direction, but the hard parts are identity, approvals, audit logs. without those it’s not an employee, it’s a browser with chaos privileges.” HN [FuckButtons](https://news.ycombinator.com/item?id=49265935) (2026-08-12): trusts colleagues not to do stupid things with accounts; cannot say the same for agents; you remain responsible.

**Shared computer = shared logins, not a security boundary.**  
**Consensus (3+).** Same docs-reading claim from [u/NoSpecific64](https://old.reddit.com/r/AI_Agents/comments/1vnbg4z/grok_bot_just_validated_everything_weve_been/p3g8up2/), [u/cornmacabre](https://old.reddit.com/r/AI_Agents/comments/1vnbg4z/grok_bot_just_validated_everything_weve_been/p435p6s/) (2026-08-17): scout-bot, finance-bot, and media-bot on one VM is “head scratching… weird implications… bot collisions”; “as wild-west… as someone running their business on a single Mac-mini.” [@petergyang](https://creatoreconomy.so/p/how-we-use-computers-is-about-to-change-forever-ai) screenshot caption: “All of your Grok Bots share one persistent cloud computer.”

**Do not trust research output blindly.**  
**Anecdote.** [@DillonLoomis](https://x.com/DillonLoomis/status/2089722135375692130) (2026-08-18, 48k views): research bot wrongly treated a blocked NTA page as “Tesla Nevada robotaxi permit denied” and ignored the public approval PDF. “I would have looked like an idiot had I trusted it.” Follow-up: simplicity-for-masses vs model control.

**Reliability after day 1 destroys trust faster than a missing feature.**  
**Consensus (3+).** [@Evanish](https://x.com/Evanish/status/2089792503993991292) (Jason Evanish, 2026-08-18): first days great; then scheduled automations “all falling over,” some miss the clock, others “claiming to not have connections they do.” “This is how you destroy product trust.” [@isuggest_app](https://x.com/isuggest_app/status/2089757635314896913) (Scott, 2026-08-18): 3 hours in a “here’s a login card, you don’t see it?” loop; asked for a refund, was refused. [@doja_dan](https://x.com/doja_dan/status/2088909816706089228) (2026-08-16): overnight bots “messing up… not very smart independently unless you give them decent rules.” [@JoshuaHudsonMBC](https://x.com/JoshuaHudsonMBC/status/2089381430501736668) (2026-08-17): first-use greeting loop he couldn’t stop. [@crsmoore](https://x.com/crsmoore/status/2089747015525941424) (2026-08-18): bot stuck “working” all night with no routine running.

**Resetting the shared computer is the unofficial fix — and people are afraid of it.**  
**Consensus (3+).** [@nickgraynews](https://x.com/nickgraynews/status/2089792062690668740): long-running inbox-every-15-min agent went silent; “afraid to” reset until a staffer said it was safe. [@mg](https://x.com/mg/status/2089774706362638685) (Matt Galligan, 2026-08-18): reset worked; “was nervous to click that button.” [@tylerrongs](https://x.com/tylerrongs/status/2089781838781046792): reset “lost a couple hours of context/changes.” [@aboutlisa](https://x.com/aboutlisa/status/2089779414301385106): bots “all useless” until reset. Same ritual reported by [@carlosjargueta](https://x.com/carlosjargueta/status/2089795914873569711), [@hirenpatelatl](https://x.com/hirenpatelatl/status/2089789064438259929), [@Stoneham_SD](https://x.com/Stoneham_SD/status/2089783907361427569).

**Enterprise brand trust is a separate objection.**  
**Anecdote.** [@hardiktiw](https://x.com/hardiktiw/status/2089764042877640821) (2026-08-18): Anthropic could copy the form factor; “Trust on grok for enterprise usage is low.”

---

## Teach-by-demonstration — lived detail

Praise is above. Extra constraints from practitioners, not docs:

- Treat it as training an employee: show the job once, narrate *why* ([@aiedge_](https://x.com/aiedge_/status/2089125062133875139), 2026-08-16 — tutorial voice, not a failure/success diary).
- Rebuild bots after learning the “one job + CoS + teach the hard path” pattern ([@AYi_AInotes](https://x.com/AYi_AInotes/status/2089737633127669806)).
- **Nothing found:** a user who recorded a task, saved it as a routine, and then described the approval boundary that the recording produced (or failed to produce).

---

## Multi-bot collaboration — lived detail

**Works as a roster; fails as a shared DM.**  
**Split (not 3+ on the same claim).**

| Claim | Sources | Label |
|---|---|---|
| CoS + specialists can coordinate | [@mattshumer_](https://x.com/mattshumer_/status/2087232424535117959) 2026-08-11; [@therealjosh](https://x.com/therealjosh/status/2089376329586393271) 2026-08-17; HN [jjcm](https://news.ycombinator.com/item?id=49263241) | approaching consensus on *roster* setup |
| Same-thread multi-bot “fell apart and accomplished nothing” | [@ericwithcoffee](https://x.com/ericwithcoffee/status/2089701340985401582) 2026-08-18 | anecdote |
| Multi-bot thread shows self-talk then the bubble disappears | [@casper_chsieh](https://x.com/casper_chsieh/status/2088875585867317652) 2026-08-16 | anecdote |
| One thread, many tasks: agent only does the last item | [@nickgraynews](https://x.com/nickgraynews/status/2089792062690668740) | anecdote |
| User wants *multiple threads per bot*, not one chat per job | [@petergyang](https://x.com/petergyang/status/2089442169509806152) 2026-08-17 | anecdote |
| Unapproved side-work from sibling bots | [@petecallaghans](https://x.com/petecallaghans/status/2089762470239866950) | anecdote |

---

## Persistent panel / thread / computer state

**Consensus that persistence is the product — and that panel/thread/computer state is currently leaky.**

- **No back-navigation from a thread; approval cards land in the parent you can’t see** — [@Adapt2Survibe](https://x.com/Adapt2Survibe/status/2088778738901434576) (2026-08-16).
- **Sidebar status lies** (working vs waiting-for-approval) — [@kidandcat](https://x.com/kidandcat/status/2088750760649695340) (2026-08-15).
- **iOS thread lag / stale log** — [@SethRubenstein](https://x.com/SethRubenstein/status/2088722237763293687) (force-quit to refresh); [@JasperCooper_](https://x.com/JasperCooper_/status/2088737623913156776) (~10s load); [@casper_chsieh](https://x.com/casper_chsieh/status/2088875585867317652) (late phone notifs, then a burst).
- **Grok chat memory ≠ Grok Bot memory** — [@glerouge](https://x.com/glerouge/status/2089769146393182710) (2026-08-18): “what I teach one doesn’t feed the other.”
- **Browser extensions on the agent computer don’t persist** — [@PerssonAC](https://x.com/PerssonAC/status/2088739108835541288) (2026-08-15).
- **Reset-computer is tribal knowledge and feels like data loss** — see reliability section.
- **Multiple threads with the same bot** — wanted by Peter Yang; **nothing found** that the product supports it.

---

## Gaps (nothing found)

- A practitioner walkthrough of a **review-list** screen (batch-approve outbound, expenses, etc.).
- Anyone using the product names **Require Approval wins over Always Allow** as a lived tie-break.
- iOS users describing **Always Allow** (desktop reports have it; iOS reports in this sweep do not).
- Teach-a-task **failure** after a successful recording.
- An audit log of “what the bot did while I was away” that a user said they actually used. Audit view is described as coming (docs + competitor writeup); no user said they have it.
- Independent measurement of how often Always Allow later caused a bad send/pay/delete.

---

## 5 lessons for a competing consent / runs UI

1. **Make the review surface a place, not a prompt.** Users reinvent “don’t delete/send/pay without my approval” in bot text because there is no durable review list. Ship a single inbox of pending irreversible actions (send, pay, delete, publish) that is visible from *every* thread and from the phone — the current failure is an approval card landing in a parent chat the user cannot see.

2. **Always-Allow must be narrow, inspectable, and machine-local.** People want NL rules ([@kr0der](https://x.com/kr0der/status/2088487100115276242)) and then turn the whole layer off when it false-positives ([@DarylAntony](https://x.com/DarylAntony/status/2088797735034208661)). Do not offer “always allow this computer.” Offer scoped allow-lists (this host, this folder, this command family), show what matched, let Require-Approval win, and sync rules across devices (they currently do not — [@mozap01](https://x.com/mozap01/status/2089111087203418547)).

3. **Sidebar truth is a trust feature.** “Working” vs “blocked on you” vs “stuck” must be accurate ([@kidandcat](https://x.com/kidandcat/status/2088750760649695340)). A stuck Allow-once banner ([@Rob_HCB](https://x.com/Rob_HCB/status/2088722966590677265)) or a bot that stays “working” overnight ([@crsmoore](https://x.com/crsmoore/status/2089747015525941424)) trains people to ignore the panel.

4. **Teach-by-demo should emit an approval boundary with the skill.** The praised loop is “show it once.” The missing artifact is the gate: what this routine may do unattended vs what must queue. Pair every saved routine with a generated review policy the user can edit before the first scheduled run.

5. **Do not use a sibling bot as the permission system; isolate blast radius.** CoS-as-router failed for [@petecallaghans](https://x.com/petecallaghans/status/2089762470239866950). Users already assume one shared VM means one shared login ([u/cornmacabre](https://old.reddit.com/r/AI_Agents/comments/1vnbg4z/grok_bot_just_validated_everything_weve_been/p435p6s/), Peter Yang). Per-bot or per-connector sessions, a scoped local-folder sandbox ([@interplanetary](https://x.com/interplanetary/status/2089797101761028504)), and a reset that does not feel like burning hours of state ([@tylerrongs](https://x.com/tylerrongs/status/2089781838781046792), [@nickgraynews](https://x.com/nickgraynews/status/2089792062690668740)) are what make “always-on” feel like a teammate instead of a hostage situation.
