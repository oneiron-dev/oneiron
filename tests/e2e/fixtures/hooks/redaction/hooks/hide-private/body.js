if (input.args.predicate !== "local.hooks.profile") return { kind: "continue" };
return { kind: "redact", paths: ["/value/*/value/private", "/value/*/claim/label"] };
