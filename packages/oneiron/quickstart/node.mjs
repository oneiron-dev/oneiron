import { Oneiron } from "oneiron"

const memory = Oneiron.open()

const witnessed = memory.witness({
  conversationRef: "11111111111111111111111111111111",
  messages: [{
    author: "user",
    messageType: "dialogue",
    content: "I prefer a window seat when I fly.",
    order: 0,
  }],
})

const claimed = memory.claimUpsert({
  id: "22222222222222222222222222222222",
  predicate: "preference.travel.seat",
  subjectRef: witnessed.turnShortId,
  value: { seat: "window" },
  confidence: 1,
  source: "user_stated",
})
const recalled = memory.recall("window seat")
const receipts = memory.receipts()

console.log(JSON.stringify({ witnessed, claimed, recalled, receipts }, null, 2))
