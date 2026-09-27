# ONE-1502: outbound connector adapter SOWs

These are nine independently cuttable host-adapter work orders. OF-327 owns the
engine manifest, gate, frozen intent, retry class and receipt. ONE-D2 owns actor
registration and SurfaceEvent; ONE-D3 owns the provider transports. The core
`OutboundExecutionSink` is the handoff, **not** proof that a provider transport
exists. The core fixture at `outbound::tests::connector_qualification` probes the
handoff with a fake transport. Each SOW closes only when the adapter runs the
same probes with a real provider sandbox/credential, using a caller-owned vault
and never placing credentials in that vault.

## Shared acceptance for every adapter

- Map the *frozen* intent and content reference to the declared channel call.
  Bind the chosen connector and target to the actor's exact grant. Reject
  unsupported verbs, expired or missing opt-in, missing permission and
  out-of-scope channels before crossing the wire. Never silently no-op.
- Run ARCH-0028 qualification: replay the same key (one remote effect), timeout
  after the wire may have started (same end state, or `uncertain` with no
  automatic resend), scope escape (zero calls), and injection resistance (an
  inbound message cannot author a send). Check trace, provenance and budget.
- Probe a closed delivery window: interrupt degrades to the configured ambient
  destination or is held for that window, **never silently dropped**. Record
  the actual result in the receipt; a provider ACK does not prove human display.
- Probe capability vs permission twice: a declared policy-risk verb is held
  with a visible proposal under a normal grant; a distinct owner-authorized
  grant for that channel and verb lets the same kind of effect execute.
- A definite pre-wire error can retry on the same frozen intent. A timeout
  after an emulated/unknown-key crossing cannot auto-retry. A native key must
  be stable over retry, provider accepted, and bound to frozen bytes. Honor
  provider retry-after and settle metered budget only on confirmed delivery.

## LINE

Calls: `reply_message` with live reply token, `push_message` and reviewed
`narrowcast`. Push/narrowcast bind `X-Line-Retry-Key` to a stable provider-valid
key; qualify actual retry behavior and push quota/plan before dispatch. Reply
and mixed-mode compatibility `send` are non-native until split by mode. A
push must not spend free reply quota. On quota/permission failure hold with
reason; degrade an interrupt to an allowed ambient path, never turn a failed
push into an unauthorized reply.

## Telegram

Bot-token rail, chat `/start`/membership and target-chat permissions. Send
message/media through queue-emulated dedupe; `setMessageReaction` and
bot-authored edits have distinct target/window rules. A transport timeout is
uncertain: no blind second `sendMessage`. Probe per-chat and group rate limits,
retry-after, muted ambient alternative and an out-of-chat scope escape.

## Slack — `workspace_bot`

Official bot-token rail with first-class bot identity and native DM to the
owner's user; OAuth scopes and channel membership are permissions, not API
capabilities. `chat.postMessage` has no provider-wide retry key: queue dedupe
and ambiguous-timeout hold. Keep persona attribution dependent on
`chat:write.customize`; message metadata needs an app-level token. Probe
workspace/channel escape, method/channel rate limits and quiet-window ambient
thread/DM behavior. Do not substitute a user impersonation token.

## Discord — `workspace_bot`

Official, per-owner-minted bot token with first-class workspace identity;
DM-your-own-user is native. `create_message` uses a frozen nonce with
`enforce_nonce=true`; verify provider acceptance and replay, not just a
locally repeated value. Channel permissions and shared-guild/DM visibility
are separate from `Send Messages`. Message Content Intent is a configuration
and annual-review concern above 10k unique users. Policy item 21 forbids
training on message content, not witnessing into the user's own vault. Cold or
bulk marketing DM uses the distinct `cold_dm` policy-risk verb and must be
proposal-gated, not hard-vetoed. Ordinary `send` is for opted-in contacts.

## APNs push

App topic, entitlement, device token and user notification opt-in are separate
permission checks. `apns-id` is tracking-only, **not** a dedupe key. Use
queue-emulated retry policy and never resend an uncertain push. Enforce the
actual `time-sensitive → active → passive` downgrade at the sink, never claim
`critical` entitlement or that an APNs ACK means the alert surfaced through
Focus. Probe expired tokens and an ungranted topic/device.

## iMessage — Messages for Business (`imessage_mfb`)

This is one of TWO iMessage rails. An Apple-registered MSP mediates a verified
business identity. Support replies in an active conversation, opt-in proactive
notifications and iOS Business Updates `invite` to an explicitly supplied
recipient; never cold-message strangers. The send UUID must be derived as a
valid, stable provider UUID from the frozen key and confirmed by the MSP;
`invite` has no assumed native retry guarantee. Qualify MSP approval, window,
live-human escalation, AI disclosure and recipient opt-in; on missing review
hold rather than falling through to bridge transport.

## iMessage — hardware bridge (`imessage_bridge`)

Dedicated number and host-device consent; `send` may cold-initiate within
provider/per-line caps, unlike MfB. Disclose unofficial `policy_risk` on the
proposal and let a per-channel owner grant authorize it. Queue-emulated
at-most-once on uncertain transport, with no false provider dedupe. Probe caps,
kill-switch/device availability, OS file access for media and scope to the
specific line. A missing bridge degrades to a consented alternate/hold, never
secretly sends through MfB.

## Email

Choose a *provider rail*, not a generic `email` retry guarantee:
`email_resend` binds Resend's `Idempotency-Key`; `email_ses` and
`email_postmark` use queue dedupe (no native key). SMTP/generic `email` remains a conservative legacy entry. Its historical
`replace_idempotent` claim describes the logical superseding-message shape,
not a provider guarantee. Do not route an ambiguous generic replacement to a
keyless provider; qualification must prove a native key or revise the claim
when the generic compatibility path is retired. A superseding email is a new
send, not an in-place edit. Verify sender domain, recipient consent, headers,
provider rate/quotas, bounce/retry-after and correct receipt state. Probe
provider switch under one logical intent: never replay an SES send via Resend.

## Voice

Real telephony provider call, not joining a voice room. Validate E.164,
recipient consent, jurisdiction, recording disclosure, provider approval and
per-recipient scope before dialing. Queue dedupe can prevent two *local*
attempts but cannot prove a timeout did not ring the phone: hold for reconcile
instead of redial. A quiet-window call becomes a consented chat/message or a
queued morning call; test both the alternate's grant and the original receipt.
