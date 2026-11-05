I’ll search X and the web for practitioner takes on toast vs inline-settle outcome UX, then sort what’s anecdote versus repeated across independent sources.The first pass found strong design-system writing but little product-specific praise. Next I’ll pull the primary essays and hunt X for Linear, Superhuman, Things, and undo-snackbar complaints.The GitHub Primer docs and a few product-specific threads look like the best remaining sources. I’ll pull those plus targeted X searches for Linear, Superhuman, Things, and undo-snackbar complaints.I have the design-system case against toasts. Next I’ll search X more narrowly and pull Linear, Superhuman, Things, and Gmail undo-send threads so product opinions aren’t just inferred from guidelines.Keyword search on X is noisy because “toast” is food. I’ll switch to quoted UX terms, fetch high-signal posts, and keep hunting product-specific Linear / Superhuman / Things takes.Found a Linear CPO post and several high-signal X posts. I’ll fetch those threads plus more targeted product searches.I have Linear’s own CPO on toast policy. Next I’ll fetch that conversation, Superhuman/Things product threads, Gmail undo-send user complaints, and the remaining primary essays.I’ve got a few high-signal X posts. I’ll pull more primary essays and Reddit/HN/user-complaint sources, plus Superhuman help docs and Things logbook undo patterns.I’ll pull the remaining primary sources: Vitaly Friedman, Gmail undo-send user threads, Superhuman undo docs, Linear undo/toast, and a few more practitioner essays.I’ll pull a few remaining primary pages: Gmail undo-send user threads, Superhuman undo behavior, Linear forum posts, and GitHub/WordPress snackbar issues.



I have enough primary sources to write a careful report. I’ll grab Linear’s official undo/archive docs and one more Superhuman undo-send source so product claims stay cited.




I have enough to write a careful, citation-heavy report. I'll also fetch WordPress Gutenberg snackbar issue and Adam Silver's original tweet if possible, plus Linear's toast-on-mutations quote more carefully.

Let me also get the WordPress Gutenberg snackbar WCAG issue and maybe Scott O'Hara / Adrian Roselli as accessibility practitioners.

I think I have a solid picture. Let me write the report now.

Structure:
1. Bottom line / what the record actually shows
2. Consensus clusters (3+ independent)
3. Product-specific: Linear, Superhuman, Things — thin record
4. Toast fatigue / disappearing undo
5. Outcomes you cannot find afterwards
6. Counter-opinions
7. 5 bullets: what practitioners actually reward

Be honest about "nothing found" for Linear/Superhuman/Things practitioner praise of toast-free inline-settle.

Findings:

- GitHub Primer officially recommends against toasts; success should be self-evident in the UI (creating an issue → seeing it in the list). Secondary feedback should persist (banners). This is institutional, not a random tweet.
- Adam Silver (Mar 15, 2020): snackbars disappear, rush users, Gmail undo-send snackbar changes state 3 times; recommend persistent message at point of action or status area (Google Docs).
- Max Schmitt (Jul 17, 2024): toasts appear far from attention; Gmail archive toast redundant if list updates; better: mutate the object in place. HN 702 pts / 385 comments.
- Jakob Nielsen (Mar 25, 2024): toasts combine disruption + anxiety-inducing disappearance; "boring UX is better UX" = put info where user is already looking.
- Vitaly Friedman (Jun 17, 2025): 8 usability issues; prefer inline status change; don't use toasts for errors/critical details.
- NN/g Maria Rosala (Nov 29, 2020): Google Drive undo snackbar only lasts a few seconds — users must know they want undo and act quickly.
- Devon Govett @devongovett (Nov 15, 2025): GitHub removing toasts; better patterns are inline confirmation/errors. 735 likes.
- Manuel Simoni @msimoni (Jan 21, 2026): toast is one of the worst UI inventions — in the way when you don't need it, gone when you need it. 635 likes.
- HN GitHub thread: yencabulator — toasts stay just long enough to realize there was Undo, then gone; quamserena — Google Calendar toast fatigue on every action.

This is CONSENSUS among UX practitioners / a11y specialists / HN power users: auto-dismiss + far-from-action + undo-only-in-toast is bad.

- Linear: Jori Lallo (CPO) Aug 15, 2023: "We try to show a toast on most mutations but not for Inbox archive as it's so common action. But we do support Cmd+z to undo." That's the opposite of toast-free praise — they toast most mutations, suppress toast on high-frequency archive, rely on Cmd+Z. Official docs: Cmd+Z + 30-day Recently deleted archive. NOTHING FOUND praising Linear specifically for toast-free inline-settle. Emil Kowalski (Linear DE) literally built a famous toast library (Sonner).
- Superhuman: Help docs still use a "send toast" with Undo for Quick Reply (30s iOS / 20s Android). Desktop has Z for undo. One Reddit user (biggy, Mar 2024) called the undo popup "handy." NOTHING FOUND praising Superhuman for being toast-free. Superhuman uses toasts + keyboard undo.
- Things 3: Completions go to Logbook (durable archive), Mac Trash + Cmd+Z, iOS shake-to-undo last delete. Official FAQ. This IS an inline-settle / durable-destination pattern. BUT I found almost no practitioner commentary framing Things as "toast-free outcome UX." Support docs and feature writeups exist; praise is about minimalism generally, not specifically anti-toast. Label: thin record on the specific claim. Users praise Logbook as a findable history of completions, which is adjacent.

- Gmail undo-send: praised as a concept (delay-before-send), criticized as snackbar UX. Adam Silver documents 3-state flicker. Jon Lopkin (UX Collective, Jun 1, 2020) notes 5-second window causes time-induced stress. Google Community: clicking "View message" dismisses undo. @vasuman (Feb 10, 2026): navigating away can fail to send / lose draft. @alexngsx (May 7, 2026): "most users never see it because the toast disappears too fast." Thunderbird Android #10557 (Feb 18, 2026): undo snackbar 0.5–1s. NN/g on Google Drive. Chromium issue: missed undo close-tabs snackbar.
- Consensus: undo that lives only in a timed snackbar is widely hated.

- GitHub Primer: auto-dismiss + important info = no way to review.
- HN TeMPOraL: wants action log, not ephemeral pokes.
- d0gsg0w00f / davidsgk: toast + notification tray / history.
- Figma export errors in toast (Reddit EmbarrassedLeader684): miss the error, can't find what happened.
- Primer: "Toasts that both display important information and automatically dismiss themselves may create a situation where a user is given important information, but then has no way to go back and review."

- lolinder on HN: redundancy is a feature; standardized toast + undo saves misclicks; inline-only forces users to learn many "it's done" signals.
- JamesSwift: optimistic archive + toast + undo is faster than confirm dialogs.
- treflop: for grade-D apps, redundant toast is the only confirmation you can trust.
- Reddit thatgibbyguy / CreepyBird4678: toasts needed for async backend confirmation.
- Some designers: toasts fine for non-critical transient; problem is misuse.
- Superhuman/Gmail users still praise undo-send as a life-saver (the delay), even while criticizing the chrome.

What practitioners actually reward:
1. The object itself changes in place (list item gone, button becomes Saved, issue appears in list) — success is self-evident.
2. Undo that is not time-boxed to a disappearing corner: Cmd/Ctrl+Z, Trash/Logbook/Recently deleted, or persistent until next action / until dismissed.
3. A durable place to find the outcome later (archive, sent folder, activity log, logbook) — not only a toast you missed.
4. Feedback at the point of action, not the opposite corner of a large display; especially for errors.
5. Silence on high-frequency, reversible actions (Linear inbox archive, Things complete → Logbook) plus a reliable backstop; toast spam on every mutation is punished (Google Calendar, LinkedIn).

I'll write this cleanly with citations.**Practitioners do not reward “toast-free” as a brand. They reward outcomes that stay in the object, undo that is not a timed corner, and a place you can find the result later.** Toast/snackbar popups are the pattern they punish when those three are missing.

I searched X (keyword + semantic), the web, HN, Reddit, GitHub issues, and product docs. The record is thick among UX/a11y practitioners and power users. It is **thin-to-empty** for people praising Linear, Superhuman, or Things *specifically* as toast-free inline-settle products. Those apps are cited below as they actually work, not as a fan consensus.

---

## Consensus (3+ independent sources)

### 1. Auto-dismiss + far-from-action is the core failure
Independent essays and a large HN thread say the same thing: a toast is in the way when you do not need it, and gone when you do.

| Source | Date | Claim |
|---|---|---|
| [Adam Silver](https://adamsilver.io/blog/the-problem-with-toast-messages-and-what-to-do-instead/) | 15 Mar 2020 | Snackbars rush users, disappear, fail keyboard/magnifier users. Gmail’s send snackbar flips through three states in seconds. Prefer a persistent message where the user is looking, or a status area like Google Docs. |
| [Max Schmitt, *Toasts are Bad UX*](https://maxschmitt.me/posts/toasts-bad-ux) | 17 Jul 2024 | Toasts land far from attention. Gmail archive toast is redundant once the row leaves the list. Better: mutate the control in place (loading → done). |
| [HN on Schmitt](https://news.ycombinator.com/item?id=41298794) | 20 Aug 2024 | 702 points, 385 comments. Repeated: periphery flashes, undo vanishes, magnifier users never see the corner. |
| [Jakob Nielsen](https://jakobnielsenphd.substack.com/p/ux-roundup-20240325) | 25 Mar 2024 | Toasts mix disruption with “anxiety-introducing disappearance.” Important info belongs at the focus point and should stay until dismissed. “Boring UX is better UX.” |
| [Vitaly Friedman](https://www.linkedin.com/pulse/toasts-snackbars-ux-guidelines-vitaly-friedman-6peze) | 17 Jun 2025 | Eight issues: too short, far from the action, blocks chrome, no keyboard focus. Prefer inline status change; do not put errors or critical detail in a toast. |
| [@msimoni](https://x.com/msimoni/status/2014036429639209245) | 21 Jan 2026 | “The toast is certainly one of the worst UI inventions ever. By introducing time as a factor, it's in the way when you don't need it, and gone when you need it.” 635 likes. |

**Label: consensus** among UX writers, a11y people, and HN/X practitioners.

### 2. GitHub’s ban is the strongest institutional vote for “settle in the object”
[Primer, *Accessible notifications and messages*](https://primer.style/accessibility/patterns/accessible-notifications-and-messages/) (current docs; HN discussion ~Dec 2025, [item 46196831](https://news.ycombinator.com/item?id=46196831)):

- Toasts are **not recommended**.
- Direct actions should be self-evident: create an issue → it appears in the list. A success toast can *reduce* trust.
- Complex/bulk work gets **persistent** banners or progressive disclosure, not auto-dismiss.
- Timed toasts risk WCAG 2.2.1 (timing), 1.3.2 (sequence), 2.1.1 (keyboard), 4.1.3 (status). They also sit outside magnifier viewports and leave **no way to review** what just happened.

X: [@devongovett, 15 Nov 2025](https://x.com/devongovett/status/1989749188318658979) — “There are often better patterns like inline confirmation/errors.” 735 likes. Follow-up 18 Apr 2026: “success messages are mostly unnecessary because their action is self evident.”

r/UXDesign (26 Nov 2025, [192 upvotes](https://old.reddit.com/r/UXDesign/comments/1p7fph6/github_retiring_toasts_from_their_design_system/)): teams report they investigated toasts and chose “nope”; LinkedIn’s stacking non-dismissing toasts are the hated opposite. Split: some want auto-dismiss settings, not a ban.

**Label: consensus that success should live in the object.** Not consensus that every toast must be banned (see counter-cluster).

### 3. Undo that only exists inside a disappearing snackbar is widely hated
| Source | Date | Claim |
|---|---|---|
| [NN/g, Maria Rosala](https://www.nngroup.com/articles/user-control-and-freedom/) | 29 Nov 2020 | Google Drive rename snackbar lasts a few seconds. Users must already know they want undo and act immediately. |
| Adam Silver (above) | 2020 | Gmail: Sending → Sent+Undo → Undo vanishes after ~5s → bar dies at ~10s. Erratic, almost unclickable Cancel. |
| Jon Lopkin, UX Collective | 1 Jun 2020 | [Gmail undo-send](https://uxdesign.cc/an-underrated-ux-gmails-undo-send-d2a1ff04251f): the *idea* is praised; the 5-second snackbar “could cause additional time-induced stress.” |
| [Google Community](https://support.google.com/mail/thread/5183254) | 30 Apr 2019 | Clicking “View message” (the thing you do to *check* the send) kills Undo. |
| [@vasuman](https://x.com/vasuman/status/2021296283584254161) | 10 Feb 2026 | Undo-send is a delay, not a recall. Navigate away and the send can fail silently / vanish from drafts. “You have to babysit a sent email for 30 seconds.” 39 likes, 10 replies. |
| [@alexngsx](https://x.com/alexngsx/status/2052371197044936755) | 7 May 2026 | “most users never see it because the toast disappears too fast.” |
| [Thunderbird Android #10557](https://github.com/thunderbird/thunderbird-android/issues/10557) | 18 Feb 2026 | Swipe-delete undo snackbar lasts ~0.5–1s; “nearly impossible” to catch. |
| HN [@yencabulator](https://news.ycombinator.com/item?id=46246221) | Dec 2025 | Favorite failure: toast lasts just long enough to *see* Undo, then it is gone. |

**Label: consensus** on “undo must outlive the snackbar.” The *delay-before-send* idea is still liked; the chrome is not.

### 4. Toast fatigue / every-action confirmation
- HN [@quamserena](https://news.ycombinator.com/item?id=46197976) (Dec 2025): Google Calendar fires a toast on every little action; they fly in/out too fast to click, too slow when you batch-create events.
- r/UXDesign: LinkedIn connection/job-saved toasts stack and force close-after-close ([thread](https://old.reddit.com/r/UXDesign/comments/1ex5co1/toasts_are_bad_ux/), Aug 2024; same complaint in the Nov 2025 GitHub thread).
- Primer: overuse trains banner-blindness.

**Label: consensus** that high-frequency success toasts are noise.

### 5. Outcomes you cannot find afterwards
- Primer: important + auto-dismiss = no review path.
- HN TeMPOraL ([20 Aug 2024](https://news.ycombinator.com/item?id=41301979)): wants an **action log** (timestamped, with Undo/View still attached), not ephemeral pokes. Others: toast + history tray.
- r/UXDesign: Figma export *errors* in a timed bottom toast — miss it on a large screen, then you cannot tell whether the file exported or failed ([EmbarrassedLeader684](https://old.reddit.com/r/UXDesign/comments/1p7fph6/github_retiring_toasts_from_their_design_system/), Nov 2025).

**Label: consensus** that if the message matters, it needs a durable home.

---

## Product-specific: Linear, Superhuman, Things

### Linear — **nothing found** praising toast-free inline-settle
What exists is the opposite of a toast-free brand, plus a durable backstop:

- [@jorilallo](https://x.com/jorilallo/status/1691307206375845889) (Linear CPO, 15 Aug 2023): “We try to show a toast on most mutations but not for Inbox archive as it’s so common action. But we do support Cmd+z to undo.”
- [Linear docs](https://linear.app/docs/delete-archive-issues): accidental delete → `Cmd/Ctrl+Z`; after that, **Recently deleted** for 30 days, then gone. Archives are a real place (`G` then `X`).
- Linear design engineer Emil Kowalski is known for [Sonner](https://sonner.emilkowal.ski/), a toast library — HN even cites it as a *good* toast+history implementation.

So Linear’s practitioner-visible policy is: **toast most mutations, suppress toast on the highest-frequency archive, always keep Cmd+Z + a 30-day archive.** That is “don’t toast the boring action,” not “toast-free product.”

### Superhuman — **nothing found** praising toast-free outcomes
They still ship toasts and treat undo as a first-class shortcut:

- [Help: Quick Reply](https://help.superhuman.com/hc/en-us/articles/46005712692877-Reply-to-Email-on-Mobile): undo a send from “the send toast” (iOS 30s / Android 20s).
- Desktop: `Z` = Undo; Instant Send is `Cmd+Shift+Z` ([shortcut lists](https://usethekeyboard.com/superhuman/)).
- r/SuperhumanEmail ([Mar 2024](https://old.reddit.com/r/SuperhumanEmail/comments/1b4395v/getting_into_the_keyboard_shortcut_flow_it_is_not/)): user **biggy** calls the undo popup “handy” after accidental delete. Anecdote, not a toast-free manifesto.

### Things — adjacent pattern, **thin** on the toast debate
[Cultured Code FAQ](https://culturedcode.com/things/support/articles/2967034/) and [Logbook docs](https://culturedcode.com/things/support/articles/4001304/):

- Complete → item leaves Today and lives in **Logbook** (searchable, kept indefinitely).
- Mac delete → Trash + `Cmd+Z`.
- iOS delete is multi-step; last delete is shake-to-undo *immediately*.

That *is* inline-settle + durable destination. I did **not** find a cluster of practitioners saying “Things is great because it has no toasts.” Praise I found is generic minimalism / calendar quiet, not outcome chrome.

---

## Counter-cluster (also real; do not flatten)

Not everyone wants toasts gone.

- HN **lolinder** (20 Aug 2024): redundancy is a feature. A standard toast+undo names *what* happened (archive vs delete) when the list just “loses a row.” Inline-only forces many local dialects of “done.”
- HN **JamesSwift / abirch**: optimistic remove + toast + undo is faster and less anxious than “are you sure?”
- HN **treflop**: most apps are “grade D”; a redundant toast is the only confirmation you can trust.
- r/UXDesign **thatgibbyguy / CreepyBird4678** (Aug 2024): toasts exist for *async* backend confirmation while the user keeps working. Schmitt’s Gmail example is called “hugely problematic” because people do not track inventory of a long list.
- Some a11y-adjacent designers: auto-dismiss is the bug; a persistent, swipe-to-dismiss bar is fine.

**Label: consensus that *misused* toasts are bad. Contested that the component should be banned.** GitHub’s ban is influential, not unanimous.

---

## X specifically

High-signal practitioner posts exist (`@msimoni`, `@devongovett`, Linear’s `@jorilallo`). Broader keyword search is polluted by food (“toast”) and is not a useful corpus. I did **not** find an X groundswell of people naming Linear / Superhuman / Things as toast-free outcome UX. **Nothing found** there beyond the cites above.

---

## Five things practitioners actually reward

1. **The object settles.** The row leaves, the issue appears, the button becomes “Saved,” the invoice “Send” becomes “Paid.” GitHub Primer, Schmitt, Friedman, Govett: if success is visible in the thing you touched, a toast is noise and can even reduce trust.

2. **Undo that is not a timed corner.** `Cmd/Ctrl+Z` (Linear, Things Mac), `Z` (Superhuman), Trash / Recently deleted / Logbook, or a bar that stays until the next action or explicit dismiss. NN/g, Silver, Thunderbird #10557, `@yencabulator`: an Undo that dies with the snackbar is a trap.

3. **A place to find it later.** Sent folder, archive, Logbook, 30-day recently deleted, activity log. Primer + HN action-log comments: if you miss the flash, the outcome must still be retrievable. Gmail’s worst cases are when navigating away both kills Undo *and* leaves you unsure whether send happened (`@vasuman`).

4. **Feedback at the point of action — especially errors.** Corner toasts on large / magnified / multi-monitor setups are routinely missed (Silver, Nielsen, Primer, Figma export anecdote). Errors next to the control; success as state change; async completion as a persistent banner or inbox, not a 3-second corner.

5. **Silence on high-frequency reversible actions, plus a backstop.** Linear’s own CPO: no toast on inbox archive because it is too common; Cmd+Z still works. Calendar/LinkedIn-style toast-per-click is the pattern people name when they say they are fatigued. Practitioners reward *confidence without ceremony*, not a popup that narrates every keystroke.
