// Generated from code-run.wit; do not edit.
declare namespace OneironCodeRun {
  interface TimeRange { start: number; end: number; }
  interface SearchInput { query: string; limit?: number | undefined; }
  interface ClaimInput { id: string; predicate: string; subject: unknown; value: unknown; confidence?: number | undefined; occurred?: OneironCodeRun.TimeRange | undefined; learnedAt?: number | undefined; }
  interface SearchOutput { results: unknown[]; }
  interface ClaimOutput { id: string; }
  interface EdgeOutput { src: string; kind: string; tgt: string; }
  interface WaitOutput { waitId: string; }
  interface SpeechOutput { order: number; isVisible: boolean; }
  interface SupersedeInput { newId: string; oldId: string; now: number; }
  interface EdgeInput { src: string; kind: string; tgt: string; weight?: number | undefined; }
  interface PromptInput { prompt: string; }
  interface TextInput { text: string; }
  interface CredentialInput { operation: string; credentialHandle: string; args: unknown; }
  interface FileProposal { path: string; bytes: Uint8Array; }
  interface StepResult { resultJson: string; proposals: Array<OneironCodeRun.ProposalDelta>; }
  type ProposalDelta = { tag: "file-write"; val: OneironCodeRun.FileProposal } | { tag: "claim-candidate"; val: OneironCodeRun.ClaimInput };
}
declare namespace sandbox {
  namespace fs {
    function read_file(path: string): Promise<Uint8Array>;
  }
  namespace credential {
    function call(input: OneironCodeRun.CredentialInput): Promise<string>;
  }
}
declare namespace oneiron {
  namespace clock {
    function now_unix_ms(): number;
  }
  namespace random {
    function bytes(length: number): Uint8Array;
  }
}
declare namespace self {
  namespace memory {
    function search(input: OneironCodeRun.SearchInput): Promise<OneironCodeRun.SearchOutput>;
    function put_claim(input: OneironCodeRun.ClaimInput): Promise<OneironCodeRun.ClaimOutput>;
    function supersede_claim(input: OneironCodeRun.SupersedeInput): Promise<OneironCodeRun.ClaimOutput>;
    function put_edge(input: OneironCodeRun.EdgeInput): Promise<OneironCodeRun.EdgeOutput>;
  }
  function ask_human(input: OneironCodeRun.PromptInput): Promise<OneironCodeRun.WaitOutput>;
  function askHuman(input: OneironCodeRun.PromptInput): Promise<OneironCodeRun.WaitOutput>;
  function speak(input: OneironCodeRun.TextInput): Promise<OneironCodeRun.SpeechOutput>;
  function think(input: OneironCodeRun.TextInput): Promise<OneironCodeRun.SpeechOutput>;
  function express(input: OneironCodeRun.TextInput): Promise<OneironCodeRun.SpeechOutput>;
}
