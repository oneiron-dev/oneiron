/** Memory Wire tool adapters. All effects are calls on the supplied SDK handle. */
import { jsonSchema, tool } from "ai"

const schema = (properties, required = []) => jsonSchema({
  type: "object", properties, required, additionalProperties: false,
})

/** The host constructs the actor-bound handle once; tools cannot rebind it. */
export function memoryTools(memory) {
  return {
    witness: tool({
      description: "Witness a conversational turn in memory. Returns a write receipt.",
      inputSchema: schema({
        conversationRef: { type: "string" },
        turnRef: { type: "string" },
        occurredAt: { type: "integer", minimum: 0 },
        messages: { type: "array", minItems: 1, items: {
          type: "object", additionalProperties: false,
          properties: {
            id: { type: "string" },
            author: { type: "string", enum: ["user", "companion", "system"] },
            messageType: { type: "string" }, content: { type: "string" },
            metadata: { type: "object", additionalProperties: true },
            isVisible: { type: "boolean" }, order: { type: "integer", minimum: 0 },
          }, required: ["author", "messageType", "content", "order"],
        } },
      }, ["conversationRef", "messages"]),
      execute: (input) => memory.witness(input),
    }),
    recall: tool({
      description: "Recall scoped memory. Values and scope are resolved by the engine now.",
      inputSchema: schema({
        query: { type: "string" },
        options: { type: "object", additionalProperties: false, properties: {
          effort: { type: "string", enum: ["minimal", "standard", "deep"] },
          limit: { type: "integer", minimum: 0 },
          format: { type: "string", enum: ["json", "yaml", "toon", "md", "txt"] },
          scope: { type: "object", additionalProperties: false, properties: {
            worldRef: { type: "string" }, facet: { type: "string" },
          } },
        } },
      }, ["query"]),
      execute: ({ query, options }) => memory.recall(query, options),
    }),
    receipts: tool({
      description: "Read memory governance receipts, newest first.",
      inputSchema: schema({ limit: { type: "integer", minimum: 0 } }),
      execute: ({ limit }) => memory.receipts(limit),
    }),
  }
}
