if (input.claim.value.phase === "safe") return { kind: "nothing" };
const file = require("fs").readFileSync(input.claim.value.path, "utf8");
return { kind: "propose", claim: { subject: input.claim.subject,
  predicate: "hooksandbox.probe.effect", value: file, confidence: 1 } };
