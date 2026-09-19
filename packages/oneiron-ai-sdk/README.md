# Memory Wire for the Vercel AI SDK

A tool pack over the shipped `oneiron` handle. The host chooses the vault and
actor. Tools cannot open vaults, change identity, or make raw HTTP writes.
Typed errors and receipts pass through unchanged. `deep` recall still requires
an engine lease; this package never creates one.

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
