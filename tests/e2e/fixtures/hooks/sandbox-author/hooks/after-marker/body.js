if (input.args.predicate !== "hooksandbox.probe.pending") return { kind: "continue" };
return { kind: "propose", claim: { subject: input.args.subject_ref,
  predicate: "hooksandbox.probe.effect", confidence: 1,
  value: { marker: "violet-after-answer", invocation: input.args.value.invocation } } };
