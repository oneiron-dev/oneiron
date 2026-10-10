import assert from 'node:assert/strict';
import { createHostSdk } from '../../crates/oneiron/wit/generated/code-run.mjs';

const calls = [];
const sdk = createHostSdk({
  'ask': input => ({waitId: input.prompt}),
  // self.memory's rows, the run's own memory rows among them, ride these two.
  'verb-names': () => ['put_claim', 'search'],
  'verb-call': (verb, input) => { calls.push({verb, input}); return JSON.stringify({id: JSON.parse(input).id}); },
  'json-validate': (schema, value) => { calls.push({schema, value}); return true; },
  'clock-now-unix-ms': () => 1234,
  'random-bytes': length => new Uint8Array(length).fill(7),
});
assert.equal(sdk.self.memory, undefined);
assert.deepEqual(sdk.self.verbs.names(), ['put_claim', 'search']);
assert.equal(await sdk.self.verbs.call('put_claim', {id:'id', subject:'s', value:{text:'hello'}}), '{"id":"id"}');
assert.deepEqual(calls[0], {verb:'put_claim', input:'{"id":"id","subject":"s","value":{"text":"hello"}}'});
assert.deepEqual(await sdk.ask({prompt:'hello'}), {waitId:'hello'});
assert.equal(sdk.self.ask_human, undefined);
assert.equal(sdk.self.askHuman, undefined);

assert.equal(await sdk.self.json.validate({type:'integer'}, 7), true);
assert.deepEqual(calls.at(-1), {schema:'{"type":"integer"}', value:'7'});

assert.equal(sdk.oneiron.clock.now_unix_ms(), 1234);
assert.deepEqual(sdk.oneiron.random.bytes(3), new Uint8Array([7,7,7]));
assert.throws(() => sdk.oneiron.random.bytes(-1), RangeError);
const foreign = createHostSdk({'clock-now-unix-ms': () => 99});
assert.equal(foreign.self, undefined);
assert.equal(foreign.ask, undefined);
assert.equal(foreign.oneiron.clock.now_unix_ms(), 99);
console.log('WIT guest SDK adaptation: passed');
