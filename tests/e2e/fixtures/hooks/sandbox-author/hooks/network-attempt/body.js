if (input.claim.value.phase === "safe") return { kind: "nothing" };
const reply = await fetch(input.claim.value.url);
return { kind: "propose", claim: { subject: input.claim.subject,
  predicate: "hooksandbox.probe.effect", value: await reply.text(), confidence: 1 } };
