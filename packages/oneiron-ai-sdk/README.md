# Memory Wire for the Vercel AI SDK

A tool pack over the shipped `oneiron` handle. The host chooses the vault and
actor. Tools cannot open vaults, change identity, or make raw HTTP writes.
Typed errors and receipts pass through unchanged. This package never creates an
engine lease.

The `recall` tool's `effort` field does not work yet. Its schema offers
`minimal`, `standard` and `deep`, but the engine accepts only `light`,
`medium`, `high`, `xhigh`, `max` and `call`. Every value the schema allows is
refused with a typed bad-request error. A call that leaves `effort` unset runs
at the default, `medium`.

```sh
npm install oneiron @oneiron/ai-sdk ai @ai-sdk/openai
```

```js
import { generateText, stepCountIs } from "ai"
import { openai } from "@ai-sdk/openai"
import { Oneiron } from "oneiron"
import { memoryTools } from "@oneiron/ai-sdk"

const memory = Oneiron.open()
const result = await generateText({
  model: openai("gpt-4.1-mini"),
  tools: memoryTools(memory),
  stopWhen: stepCountIs(3),
  prompt: "Recall what I prefer when travelling. Do not invent missing memories.",
})
console.log(result.text)
```

Set `OPENAI_API_KEY` for this sample. Replace `Oneiron.open()` with
`Oneiron.connect(process.env.ONEIRON_URL, process.env.ONEIRON_KEY)` for a server.
No model or provider dependency is bundled into the adapter.

## Native integration proof

After building `packages/oneiron`, run `bun install --frozen-lockfile` and
`bun run test:native` here. This executes the real `generateText` tool loop in Node, the shipped SDK runtime,
against an actual native vault. A deterministic AI SDK model supplies tool
calls, so the test needs no external provider key. Memory, schemas, tool dispatch,
recall and receipts are not mocked.
