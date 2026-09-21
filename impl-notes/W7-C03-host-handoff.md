# W7-C03 production host and cloud handoff

Owner scope ruling: 2026-09-19 recovery continuation. The engine work continues to completion. Cloud delivery and supplied production credentials are deployment handoffs, not engine blockers. No cloud implementation is claimed by the engine fixtures.

## First-party mail: steps 9–16

Target repository: `oneiron-cloud`, design entry `mail/DESIGN.md`. Target service directory: `control-plane/convex/mail/`; inbound route registration belongs in `control-plane/convex/http.ts`. File names within `mail/` are for the cloud implementer to choose, not assertions that those files already exist.

1. Package embedded **Stalwart >=0.16.0**, with a pinned release and image/binary digest in the ARCH-0053 pack. Support `SelfRun` and `CloudRun`. Use its JMAP management API, not the removed REST admin API. This is a first-party organ, not a SaaS inbox integration.
2. Implement `oneiron::channel_identity_provider::native_mail::NativeMailHost`: `provision(&ProvisionIntent, NativeMailRunMode)` consumes an already admitted ExternalEffect intent and returns a durable provider mailbox id. Keep identity-id idempotency, provision domains/accounts with JMAP, and maintain the mailbox/message store, In-Reply-To/References threading, and reply extraction there.
3. Implement `verify_webhook(original_bytes, headers)` with Svix verification before parsing. Register the Convex HTTP route to pass verified bytes into `NativeMailAdapter::accept_webhook`. That adapter performs canonical identity parsing and the existing durable quarantine/admission handoff. Do not expose the semantic `parse_inbound` helper as a bypass of signature verification. Preserve provider-event idempotency; sender text remains untrusted and does not become instructions.
4. Fulfill admitted send intents through Stalwart, recording provider enqueue receipts separately from delivery/bounce receipts. Connect the existing outbound intent ledger to the cloud delivery worker; a queued intent is not a delivered message. E-sign send/remind uses the same rail and cannot bypass recipient-count admission.
5. Implement per-identity side-domain allocation, never-crown policy, burnt-domain isolation, DNS publication and reconciliation. Reuse the cloud `edge/` single-credential Cloudflare/reconcile pattern. Domain authorization stays in that service; the Rust adapter's syntax validation is not a substitute for the never-crown policy.
6. Implement customer BYO `_oneiron.<domain>` NS delegation and the paste-record fallback. Publish the delegated DKIM `_domainkey`, `_acme-challenge`, and SPF include records with observed DNS verification and retry state. Do not treat a submitted domain as proof of ownership.
7. **MAIL-11 remains an unavailable restricted Track-B annex.** The handoff must supply the approved DKIM key custody, generation, rotation, signing and destruction design. Neither the engine adapter nor this ticket invents replacement cryptography. Public DNS keys are not custody of the private signing keys.

The Rust adapter and mode/admission tests are in `crates/oneiron/src/channel_identity_provider/native_mail.rs`. Fulfillment credentials, MTA processes, DNS zones and cloud databases are not created by these tests.

## E-sign production signing and scheduling

- The host supplies a configured `oneiron_seal::PdfSealEngine` and `PadesProfile`, including its production signing identity, trust material and any required TSA/network configuration. Test-generated identities are only fixtures and must not become production defaults.
- A worker leases `ESIGN_SEAL_ATTEMPT_KIND` records through the normal attempt queue and calls `Vault::seal_esign_attempt(attempt, engine, profile, canonical_url)`. The immutable original is prepared outside the writer lock; both backend self-verification and independent verification must pass before atomic artifact/status/audit publication. On failure the host uses the queue's retry/lease policy, not a direct terminal-status write.
- The host issues the HTTPS canonical signing/certificate capability URL. It must use the document's intended capability, not a deployment placeholder. Capabilities stay in browser fragments/POST bodies and are hashed at rest; request logging must not record those secrets.
- Schedule `Vault::sweep_esign_seals(documents, now)` every 15 minutes, with batches of at most 100 document ids. It only repairs ready triggers aged 15 minutes through 6 hours. The host enumerates its document workload and supplies wall-clock seconds.
- Schedule expiry calls through `Vault::expire_esign_document`. VOIDED and EXPIRED remain unsealed; neither is sent to the seal worker. The HTTP loader's expiry refusal is not itself a claim that a sweep already ran.
- Owner reseal uses `Vault::request_esign_reseal` with a live owner-tier standing grant, owner decision and full audit context. It is not a direct worker invocation under an arbitrary actor.
- Public HTTP signing requires real peer transport information. The standalone listener installs ConnectInfo; any managed listener must do the same before mounting this route. A caller-controlled forwarding header is not authenticated IP evidence. A reverse-proxy deployment must make an explicit trusted peer/audit integration, not silently trust X-Forwarded-For.

## Other host loops

The engine exposes durable Wave planner application/ready-set dispatch and Linear push outbox/pull cursor doors. A deployment supplies planner/model selection, Linear credentials, polling cadence and delivery execution. Cleanup retention remains an engine cron arm with owner-controlled policy; owner bulk purge is never scheduled. OF-445's memory proxy is still explicitly POST-ENGINE by its own contract.
