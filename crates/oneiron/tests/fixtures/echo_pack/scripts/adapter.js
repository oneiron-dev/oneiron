const bytes = await sandbox.fs.read_file('/mnt/workspace/scripts/input.json');
let text = ''; for (const byte of bytes) text += String.fromCharCode(byte);
const grant = packGrants.email;
await sandbox.credential.call({operation:'metadata', credentialHandle:grant.handle,
    args:{scheme:grant.scheme, host:grant.host}});
const output = JSON.stringify({
    inbound: [JSON.parse(text)],
    verbs: [{channel:'email', verb:'send', target:'recipient', content_ref:'artifact:1'}],
    events: [{event_id:'arrival-1', connector:'email', event_kind:'arrived',
        predicate:'email.message', payload:{id:'message-1'}}]
});
propose.file('/mnt/workspace/adapter-output.json', Array.from(output, c => c.charCodeAt(0)));
finish('ok');
